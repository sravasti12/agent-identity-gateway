import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

from app.audit.store import Database
from app.identity.lifecycle_models import (
    HR_GRANTS,
    Agent,
    Credential,
    Grants,
    Registration,
    Review,
    ReviewDecision,
    Rotation,
    State,
)

TRANSITIONS = {
    State.PENDING: {State.ACTIVE, State.DEPROVISIONED},
    State.ACTIVE: {State.SUSPENDED, State.DEPROVISIONED},
    State.SUSPENDED: {State.ACTIVE, State.DEPROVISIONED},
    State.DEPROVISIONED: set(),
}


class LifecycleError(RuntimeError):
    def __init__(self, status: int, code: str) -> None:
        self.status = status
        self.code = code
        self.agent_id: str | None = None
        super().__init__(code)


class AgentProvider(Protocol):
    """Administrative integration boundary. Only expiry and local operation IDs cross it."""

    def rotate(self, client_id: str, operation_id: str) -> datetime | None: ...
    def disable(self, client_id: str, operation_id: str) -> None: ...
    def permissions(self, client_id: str) -> Grants | None: ...


class Lifecycle:
    def __init__(self, storage: Database, review_days: int, provider: AgentProvider | None = None) -> None:
        self.storage = storage
        self.review_period = timedelta(days=review_days)
        self.provider = provider

    @staticmethod
    def _get(db: sqlite3.Connection, agent_id: str) -> Agent:
        row = db.execute("SELECT document FROM agents WHERE id=?", (agent_id,)).fetchone()
        if row is None:
            raise LifecycleError(404, "agent_not_found")
        return Agent.model_validate_json(row["document"])

    @staticmethod
    def _save(db: sqlite3.Connection, agent: Agent) -> None:
        agent.updated_at = datetime.now(UTC)
        db.execute("UPDATE agents SET document=? WHERE id=?", (agent.model_dump_json(), agent.id))

    def register(self, request: Registration, actor: str, correlation: str) -> Agent:
        if not request.approved.within(HR_GRANTS):
            raise LifecycleError(422, "permissions_outside_catalog")
        now = datetime.now(UTC)
        agent = Agent(
            id=request.id, client_id=request.client_id, display_name=request.display_name,
            description=request.description, assigned=request.approved, approved=request.approved,
            created_by=actor, created_at=now, updated_at=now,
            credential=Credential(
                version=uuid4().hex, created_at=now, expires_at=request.credential_expires_at,
            ),
        )
        with self.storage.transaction() as db:
            try:
                db.execute("INSERT INTO agents VALUES (?, ?, ?)", (agent.id, agent.client_id, agent.model_dump_json()))
            except sqlite3.IntegrityError:
                raise LifecycleError(409, "agent_or_client_already_registered") from None
            self.storage.audit("agent_onboarded", "register", "success", "registered", correlation,
                               actor=actor, agent=agent.id, resource=f"credential:{agent.credential.version}", db=db)
        return agent

    def details(self, agent_id: str) -> Agent:
        with self.storage.transaction() as db:
            return self._get(db, agent_id)

    def list_agents(self, limit: int, after: str) -> list[Agent]:
        with self.storage.transaction() as db:
            rows = db.execute("SELECT document FROM agents WHERE id>? ORDER BY id LIMIT ?", (after, limit))
            return [Agent.model_validate_json(row["document"]) for row in rows]

    def transition(self, agent_id: str, target: State, reason: str, actor: str, correlation: str) -> Agent:
        with self.storage.transaction() as db:
            agent = self._get(db, agent_id)
            if target not in TRANSITIONS[agent.status]:
                raise LifecycleError(409, "invalid_state_transition")
            agent.status = target
            agent.generation += 1
            agent.state_reason = reason
            agent.state_changed_by = actor
            if target == State.DEPROVISIONED:
                agent.credential.revoked_at = datetime.now(UTC)
                agent.assigned = Grants()
                agent.provider_revocation = "PENDING"
            self._save(db, agent)
            self.storage.audit("agent_state", target.lower(), "success", reason, correlation,
                               actor=actor, agent=agent.id, db=db)
            return agent

    @staticmethod
    def _check_credential(agent: Agent, issued_at: object, *, check_token: bool) -> None:
        if agent.status != State.ACTIVE or agent.credential.revoked_at is not None:
            raise LifecycleError(403, "agent_inactive")
        if agent.rotation is not None and agent.rotation.state == "RUNNING":
            raise LifecycleError(403, "rotation_in_progress")
        if agent.credential.expires_at is not None and agent.credential.expires_at <= datetime.now(UTC):
            raise LifecycleError(403, "credential_expired")
        rotated = agent.credential.rotated_at
        if check_token and rotated is not None and (type(issued_at) is not int or issued_at <= int(rotated.timestamp())):
            raise LifecycleError(403, "stale_agent_token")

    def check_registered_bearer(self, client_id: str, issued_at: object) -> Agent | None:
        with self.storage.transaction() as db:
            row = db.execute("SELECT document FROM agents WHERE client_id=?", (client_id,)).fetchone()
            if row is None:
                return None  # Keep the credential probe available for onboarding.
            agent = Agent.model_validate_json(row["document"])
            try:
                self._check_credential(agent, issued_at, check_token=True)
            except LifecycleError as error:
                error.agent_id = agent.id
                raise
            return agent

    def _check_hr(
        self, db: sqlite3.Connection, client_id: str, generation: int | None, issued_at: object, *,
        check_token: bool,
    ) -> Agent:
        row = db.execute("SELECT document FROM agents WHERE client_id=?", (client_id,)).fetchone()
        if row is None:
            raise LifecycleError(403, "agent_not_registered")
        agent = Agent.model_validate_json(row["document"])
        try:
            self._check_credential(agent, issued_at, check_token=check_token)
            if generation is not None and agent.generation != generation:
                raise LifecycleError(403, "handoff_invalidated")
            if (
                not agent.approved.within(HR_GRANTS) or not agent.assigned.within(agent.approved)
                or not HR_GRANTS.within(agent.assigned)
            ):
                raise LifecycleError(403, "registry_permission_denied")
        except LifecycleError as error:
            error.agent_id = agent.id
            raise
        return agent

    def check_hr(
        self, client_id: str, generation: int | None = None, issued_at: object = None, *, check_token: bool = False,
    ) -> Agent:
        with self.storage.transaction() as db:
            return self._check_hr(db, client_id, generation, issued_at, check_token=check_token)

    def record_invocation(
        self, client_id: str, generation: int, issued_at: object, expires_at: int,
        actor: str, subject: str, correlation: str,
    ) -> None:
        with self.storage.transaction() as db:
            agent = self._check_hr(db, client_id, generation, issued_at, check_token=True)
            if expires_at <= datetime.now(UTC).timestamp():
                raise LifecycleError(403, "delegation_expired")
            agent.last_access_at = datetime.now(UTC)
            self._save(db, agent)
            self.storage.audit("mcp_invocation", "read_hr_team", "allow", "authorized", correlation,
                               actor=actor, subject=subject, agent=agent.id,
                               resource="hr_team/demo-team", scope="hr_team_read", db=db)

    def request_rotation(self, agent_id: str, actor: str, correlation: str) -> Rotation:
        with self.storage.transaction() as db:
            agent = self._get(db, agent_id)
            if agent.status == State.DEPROVISIONED or (
                agent.rotation and agent.rotation.state in ("PENDING", "RUNNING")
            ):
                raise LifecycleError(409, "rotation_unavailable")
            rotation = Rotation(id=uuid4().hex, requested_by=actor, requested_at=datetime.now(UTC))
            agent.rotation = rotation
            self._save(db, agent)
            self.storage.audit("rotation", "request", "pending", "provider_not_executed", correlation,
                               actor=actor, agent=agent.id, resource=f"rotation:{rotation.id}", db=db)
            return rotation

    def apply_rotation(self, agent_id: str, rotation_id: str, actor: str, correlation: str) -> Rotation:
        provider = self.provider
        if provider is None:
            raise LifecycleError(503, "provider_not_configured")
        with self.storage.transaction() as db:
            agent = self._get(db, agent_id)
            rotation = agent.rotation
            if agent.status == State.DEPROVISIONED or rotation is None or rotation.id != rotation_id:
                raise LifecycleError(409, "rotation_unavailable")
            if rotation.state != "PENDING":
                raise LifecycleError(409, "rotation_already_processed")
            rotation.state = "RUNNING"
            # Stop existing handoffs before starting an external, non-transactional operation.
            agent.generation += 1
            self._save(db, agent)
            self.storage.audit("rotation", "apply", "pending", "provider_started", correlation,
                               actor=actor, agent=agent.id, db=db)
        try:
            expiry = provider.rotate(agent.client_id, rotation.id)
            if expiry is not None and (expiry.utcoffset() is None or expiry <= datetime.now(UTC)):
                raise ValueError("invalid provider expiry")
            confirmed = True
        except Exception:  # noqa: BLE001 - isolate provider failures without logging their payloads.
            expiry = None
            confirmed = False
        with self.storage.transaction() as db:
            current = self._get(db, agent_id)
            active_rotation = current.rotation
            if active_rotation is None or active_rotation.id != rotation_id or active_rotation.state != "RUNNING":
                raise LifecycleError(409, "rotation_state_changed")
            now = datetime.now(UTC)
            success = confirmed and current.status != State.DEPROVISIONED
            active_rotation.state = "COMPLETED" if success else "FAILED"
            active_rotation.finished_at = now
            if success:
                current.credential = Credential(version=uuid4().hex, created_at=now, rotated_at=now, expires_at=expiry)
            self._save(db, current)
            self.storage.audit("rotation", "apply", "success" if success else "failure",
                               "provider_confirmed" if success else "rotation_not_confirmed", correlation,
                               actor=actor, agent=current.id,
                               resource=f"credential:{current.credential.version}" if success else f"rotation:{rotation_id}",
                               db=db)
            return active_rotation

    def revoke_provider(self, agent_id: str, actor: str, correlation: str) -> Agent:
        provider = self.provider
        if provider is None:
            raise LifecycleError(503, "provider_not_configured")
        with self.storage.transaction() as db:
            agent = self._get(db, agent_id)
            if agent.status != State.DEPROVISIONED or agent.provider_revocation not in ("PENDING", "FAILED"):
                raise LifecycleError(409, "provider_revocation_unavailable")
            if agent.rotation is not None and agent.rotation.state == "RUNNING":
                raise LifecycleError(409, "rotation_in_progress")
            agent.provider_revocation = "RUNNING"
            self._save(db, agent)
            self.storage.audit("provider_revocation", "disable", "pending", "provider_started", correlation,
                               actor=actor, agent=agent.id, db=db)
        try:
            provider.disable(agent.client_id, f"deprovision:{agent.id}")
            confirmed = True
        except Exception:  # noqa: BLE001 - isolate provider failures without logging their payloads.
            confirmed = False
        with self.storage.transaction() as db:
            current = self._get(db, agent_id)
            current.provider_revocation = "CONFIRMED" if confirmed else "FAILED"
            self._save(db, current)
            self.storage.audit("provider_revocation", "disable", "success" if confirmed else "failure",
                               "provider_confirmed" if confirmed else "revocation_not_confirmed", correlation,
                               actor=actor, agent=current.id, db=db)
            return current

    def create_review(self, agent_id: str, proposed: Grants | None, actor: str, correlation: str) -> Review:
        if proposed is not None and not proposed.within(HR_GRANTS):
            raise LifecycleError(422, "permissions_outside_catalog")
        baseline = self.details(agent_id)
        try:
            observed = self.provider.permissions(baseline.client_id) if self.provider is not None else None
        except Exception:  # noqa: BLE001 - isolate provider failures without logging their payloads.
            raise LifecycleError(502, "provider_observation_failed") from None
        with self.storage.transaction() as db:
            agent = self._get(db, agent_id)
            if agent.generation != baseline.generation:
                raise LifecycleError(409, "review_snapshot_changed")
            now = datetime.now(UTC)
            actual = observed if observed is not None else agent.assigned
            issues = {
                "excess_permissions": (not actual.within(agent.approved), "Review grants and propose a reduced set"),
                "permission_drift": (actual != agent.approved or agent.assigned != agent.approved,
                                     "Reconcile assigned permissions with approvals"),
                "suspended_permissions": (agent.status == State.SUSPENDED and actual != Grants(),
                                          "Consider removing retained permissions"),
                "review_due": (now - (agent.last_review_at or agent.created_at) >= self.review_period,
                               "Review access against current responsibilities"),
                "inactive": (now - (agent.last_access_at or agent.created_at) >= self.review_period,
                             "Confirm whether continued access is needed"),
                "credential_expired": (agent.credential.expires_at is not None and agent.credential.expires_at <= now,
                                       "Review credential rotation or deprovisioning"),
            }
            review = Review(
                id=uuid4().hex, agent_id=agent.id, agent_generation=agent.generation, created_at=now,
                created_by=actor, assigned=agent.assigned, approved=agent.approved, observed=observed,
                proposed=proposed, findings=tuple(key for key, (flag, _) in issues.items() if flag),
                recommendations=tuple(message for flag, message in issues.values() if flag),
            )
            db.execute("INSERT INTO reviews VALUES (?, ?, ?)", (review.id, agent.id, review.model_dump_json()))
            self.storage.audit("access_review", "create", "pending", "review_created", correlation,
                               actor=actor, agent=agent.id, db=db)
            return review

    def reviews(self, agent_id: str, limit: int, after: str) -> list[Review]:
        with self.storage.transaction() as db:
            self._get(db, agent_id)
            rows = db.execute(
                "SELECT document FROM reviews WHERE agent_id=? AND id>? ORDER BY id LIMIT ?",
                (agent_id, after, limit),
            )
            return [Review.model_validate_json(row["document"]) for row in rows]

    def decide_review(self, agent_id: str, review_id: str, decision: ReviewDecision, actor: str, correlation: str) -> Review:
        with self.storage.transaction() as db:
            agent = self._get(db, agent_id)
            row = db.execute("SELECT document FROM reviews WHERE id=? AND agent_id=?", (review_id, agent_id)).fetchone()
            if row is None:
                raise LifecycleError(404, "review_not_found")
            review = Review.model_validate_json(row["document"])
            if review.decision != "PENDING":
                raise LifecycleError(409, "review_already_decided")
            if decision.decision == "APPROVED" and review.agent_generation != agent.generation:
                raise LifecycleError(409, "review_snapshot_changed")
            now = datetime.now(UTC)
            review.decision = decision.decision
            review.reviewer = actor
            review.decided_at = now
            agent.last_review_at = now
            if review.decision == "APPROVED" and review.proposed is not None:
                if agent.status == State.DEPROVISIONED:
                    raise LifecycleError(409, "deprovisioned_agent")
                agent.approved = review.proposed
                agent.assigned = review.proposed
                agent.generation += 1
                self.storage.audit("permissions_changed", "apply_review", "success", "review_approved", correlation,
                                   actor=actor, agent=agent.id, db=db)
            self._save(db, agent)
            db.execute("UPDATE reviews SET document=? WHERE id=?", (review.model_dump_json(), review.id))
            self.storage.audit("access_review", "decide", "success", review.decision.lower(), correlation,
                               actor=actor, agent=agent.id, db=db)
            return review
