from contextlib import closing
from datetime import UTC, datetime, timedelta
from sqlite3 import OperationalError

import pytest

from app.audit.store import Database
from app.audit.verify import verify_file
from app.identity.lifecycle import Lifecycle, LifecycleError
from app.identity.lifecycle_models import (
    HR_GRANTS,
    Grants,
    Registration,
    ReviewDecision,
    State,
)


class MockProvider:
    def __init__(self):
        self.fail_rotation = False
        self.fail_revocation = False
        self.actual = None
        self.rotations = []
        self.disabled = []

    def rotate(self, client_id, operation_id):
        self.rotations.append((client_id, operation_id))
        if self.fail_rotation:
            raise RuntimeError("synthetic secret returned in provider diagnostic")
        return datetime.now(UTC) + timedelta(days=30)

    def disable(self, client_id, operation_id):
        self.disabled.append((client_id, operation_id))
        if self.fail_revocation:
            raise RuntimeError("synthetic secret returned in provider diagnostic")

    def permissions(self, client_id):
        return self.actual


@pytest.fixture
def storage(tmp_path):
    with closing(Database(str(tmp_path / "registry.sqlite3"))) as store:
        yield store


@pytest.fixture
def provider():
    return MockProvider()


@pytest.fixture
def lifecycle(storage, provider):
    return Lifecycle(storage, 30, provider)


def register(lifecycle, grants=None, expires_at=None):
    return lifecycle.register(Registration(
        id="demo-agent", client_id="demo-client", display_name="Demo Agent",
        approved=grants or Grants(), credential_expires_at=expires_at,
    ), "admin-sub", "correlation")


def test_registry_onboarding_is_minimal_unique_and_durable(tmp_path, storage, lifecycle):
    pending = register(lifecycle)
    assert pending.status == State.PENDING
    assert pending.assigned == pending.approved == Grants()
    assert pending.created_by == "admin-sub"
    assert pending.created_at.utcoffset() == timedelta(0)
    with pytest.raises(LifecycleError, match="agent_or_client_already_registered"):
        register(lifecycle)
    with pytest.raises(LifecycleError, match="agent_or_client_already_registered"):
        lifecycle.register(Registration(id="other", client_id=pending.client_id, display_name="Other"), "admin", "corr")
    with closing(Database(str(tmp_path / "registry.sqlite3"))) as reopened:
        assert Lifecycle(reopened, 30).details(pending.id) == pending
        assert reopened.verify().valid


def test_lifecycle_transitions_revoke_credentials_and_invalidate_generations(lifecycle):
    registered = register(lifecycle, HR_GRANTS)
    with pytest.raises(LifecycleError, match="agent_inactive"):
        lifecycle.check_hr(registered.client_id)
    with pytest.raises(LifecycleError, match="invalid_state_transition"):
        lifecycle.transition(registered.id, State.SUSPENDED, "incident", "admin", "correlation")
    active = lifecycle.transition(registered.id, State.ACTIVE, "approved_onboarding", "admin", "corr")
    assert lifecycle.check_hr(active.client_id, active.generation).status == State.ACTIVE
    lifecycle.transition(active.id, State.SUSPENDED, "incident", "admin", "corr")
    with pytest.raises(LifecycleError, match="agent_inactive"):
        lifecycle.check_hr(active.client_id, active.generation)
    lifecycle.transition(active.id, State.ACTIVE, "restored", "admin", "corr")
    with pytest.raises(LifecycleError, match="handoff_invalidated"):
        lifecycle.check_hr(active.client_id, active.generation)
    dead = lifecycle.transition(active.id, State.DEPROVISIONED, "retired", "admin", "corr")
    assert dead.credential.revoked_at is not None
    assert dead.assigned == Grants()
    assert dead.provider_revocation == "PENDING"
    with pytest.raises(LifecycleError, match="invalid_state_transition"):
        lifecycle.transition(dead.id, State.ACTIVE, "restored", "admin", "corr")


def test_rotation_request_and_confirmation_change_metadata_and_cut_off_stale_bearers(lifecycle, provider):
    old = register(lifecycle, HR_GRANTS)
    request = lifecycle.request_rotation(old.id, "admin", "corr")
    assert request.state == "PENDING"
    assert not provider.rotations
    assert lifecycle.details(old.id).credential.version == old.credential.version
    complete = lifecycle.apply_rotation(old.id, request.id, "admin", "corr")
    assert complete.state == "COMPLETED"
    assert provider.rotations == [(old.client_id, request.id)]
    new = lifecycle.transition(old.id, State.ACTIVE, "approved_onboarding", "admin", "corr").credential
    assert new.version != old.credential.version and new.rotated_at is not None and new.expires_at is not None
    cutoff = int(new.rotated_at.timestamp())
    for issued_at in (None, cutoff - 10, cutoff):
        with pytest.raises(LifecycleError, match="stale_agent_token"):
            lifecycle.check_hr(old.client_id, issued_at=issued_at, check_token=True)
    assert lifecycle.check_hr(old.client_id, issued_at=cutoff + 1, check_token=True).credential == new


def test_rotation_failure_preserves_metadata_and_sanitizes_diagnostics(lifecycle, storage, provider):
    old = register(lifecycle)
    rotation = lifecycle.request_rotation(old.id, "admin", "corr")
    provider.fail_rotation = True
    failed = lifecycle.apply_rotation(old.id, rotation.id, "admin", "corr")
    assert failed.state == "FAILED"
    assert lifecycle.details(old.id).credential == old.credential
    events = storage.events(100, 0, "rotation", old.id, None)
    assert [event.decision for event in events] == ["pending", "pending", "failure"]
    assert "synthetic secret" not in str(events)


def test_missing_provider_can_record_requests_but_cannot_claim_success(storage):
    lifecycle = Lifecycle(storage, 30)
    agent = register(lifecycle)
    rotation = lifecycle.request_rotation(agent.id, "admin", "corr")
    with pytest.raises(LifecycleError, match="provider_not_configured"):
        lifecycle.apply_rotation(agent.id, rotation.id, "admin", "corr")
    assert lifecycle.details(agent.id).rotation.state == "PENDING"
    lifecycle.transition(agent.id, State.DEPROVISIONED, "retired", "admin", "corr")
    with pytest.raises(LifecycleError, match="provider_not_configured"):
        lifecycle.revoke_provider(agent.id, "admin", "corr")


def test_provider_revocation_is_separate_from_local_deprovisioning(lifecycle, provider):
    agent = register(lifecycle)
    lifecycle.transition(agent.id, State.DEPROVISIONED, "retired", "admin", "corr")
    assert not provider.disabled
    provider.fail_revocation = True
    assert lifecycle.revoke_provider(agent.id, "admin", "corr").provider_revocation == "FAILED"
    provider.fail_revocation = False
    assert lifecycle.revoke_provider(agent.id, "admin", "corr").provider_revocation == "CONFIRMED"


def test_review_flags_excess_drift_lapsed_review_inactivity_and_expired_credentials(lifecycle, storage, provider):
    old = datetime.now(UTC) - timedelta(days=40)
    agent = register(lifecycle, HR_GRANTS, old)
    lifecycle.transition(agent.id, State.ACTIVE, "approved_onboarding", "admin", "corr")
    lifecycle.transition(agent.id, State.SUSPENDED, "incident", "admin", "corr")
    updated = lifecycle.details(agent.id)
    updated.created_at = old
    with storage.transaction() as db:
        db.execute("UPDATE agents SET document=? WHERE id=?", (updated.model_dump_json(), agent.id))
    provider.actual = HR_GRANTS.model_copy(update={"roles": frozenset({"hr_agent", "overbroad"})})
    review = lifecycle.create_review(agent.id, Grants(), "reviewer", "review-corr")
    assert set(review.findings) == {
        "excess_permissions", "permission_drift", "suspended_permissions", "review_due", "inactive", "credential_expired",
    }
    assert len(review.recommendations) == len(review.findings)
    assert lifecycle.details(agent.id).assigned == HR_GRANTS
    rejected = lifecycle.decide_review(agent.id, review.id, ReviewDecision(decision="REJECTED"), "admin", "corr")
    assert rejected.reviewer == "admin" and rejected.decided_at is not None
    assert lifecycle.details(agent.id).assigned == HR_GRANTS
    new_review = lifecycle.create_review(agent.id, Grants(), "reviewer", "review-corr")
    assert lifecycle.decide_review(
        agent.id, new_review.id, ReviewDecision(decision="APPROVED"), "admin", "corr",
    ).decision == "APPROVED"
    assert lifecycle.details(agent.id).assigned == Grants()
    assert len(storage.events(100, 0, "permissions_changed", agent.id, None)) == 1


def test_stale_review_cannot_restore_permissions_after_state_change(lifecycle):
    agent = register(lifecycle)
    review = lifecycle.create_review(agent.id, HR_GRANTS, "admin", "corr")
    lifecycle.transition(agent.id, State.ACTIVE, "approved_onboarding", "admin", "corr")
    with pytest.raises(LifecycleError, match="review_snapshot_changed"):
        lifecycle.decide_review(agent.id, review.id, ReviewDecision(decision="APPROVED"), "admin", "corr")
    assert lifecycle.details(agent.id).assigned == Grants()


@pytest.mark.parametrize("alteration", [
    "UPDATE audit_events SET document=replace(document, 'authenticated', 'modified') WHERE sequence=2",
    "DELETE FROM audit_events WHERE sequence=2",
    "DELETE FROM audit_events WHERE sequence=3",
    "UPDATE audit_events SET sequence=4 WHERE sequence=1",
])
def test_audit_chain_detects_modification_deletion_and_reordering(storage, alteration):
    for _ in range(3):
        storage.audit("human_auth", "callback", "success", "authenticated", "corr")
    assert storage.verify().valid
    with storage.transaction() as db:
        db.execute(alteration)
    assert not storage.verify().valid


def test_audit_only_retains_safe_identity_identifiers_and_provides_pagination(storage):
    storage.audit("agent_auth", "authenticate", "failure", "invalid_token", "correlation",
                  actor="Bearer synthetic.jwt.parts", agent="demo-agent")
    storage.audit("agent_auth", "authenticate", "success", "authenticated", "correlation", actor="actor-id")
    first, = storage.events(1, 0, "agent_auth", "demo-agent", "failure")
    second, = storage.events(1, first.sequence, "agent_auth", None, None)
    assert first.actor == "[redacted]" and second.actor == "actor-id"
    assert first.correlation_id == second.correlation_id == "correlation"
    assert second.previous_hash == first.event_hash
    assert "synthetic.jwt.parts" not in first.model_dump_json()
    assert storage.verify().valid


def test_offline_audit_verification_opens_existing_database_read_only(storage, tmp_path):
    storage.audit("human_auth", "authenticate", "success", "authenticated", "correlation")
    path = tmp_path / "registry.sqlite3"
    before = path.read_bytes()
    assert verify_file(path).records_checked == 1
    assert path.read_bytes() == before
    missing = tmp_path / "missing.sqlite3"
    with pytest.raises(OperationalError):
        verify_file(missing)
    assert not missing.exists()
