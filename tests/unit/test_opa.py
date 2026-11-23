import json
from datetime import UTC, datetime
from time import time

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from app.authorization.delegated import (
    DECISION_PATH,
    OPAAuthorizer,
    PolicyDenied,
    PolicyUnavailable,
)
from app.identity.delegation import DelegatedIdentity
from app.identity.lifecycle_models import HR_GRANTS, Agent, Credential, State
from app.identity.tokens import User
from config.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,
        keycloak_issuer="https://idp.test/realms/test",
        keycloak_client_id="human-client",
        keycloak_client_secret=SecretStr("synthetic-secret"),
        keycloak_redirect_uri="https://gateway.test/auth/callback",
        keycloak_api_audience="example-api",
        keycloak_hr_agent_client_id="example-client",
        keycloak_hr_agent_client_secret=SecretStr("synthetic-agent-secret"),
        opa_url="https://opa.test/",
    )


@pytest.fixture
def identity() -> DelegatedIdentity:
    return DelegatedIdentity(
        subject=User(subject="human-id", username="test-human", realm_roles=("hr_manager",)),
        actor=User(subject="actor-id", username="test-agent", realm_roles=("hr_agent",)),
        actor_client="example-client", audience="example-api", granted_scopes=frozenset({"hr_team_read"}),
        expires_at=int(time()) + 100,
    )


@pytest.fixture
def agent() -> Agent:
    now = datetime.now(UTC)
    return Agent(
        id="example-agent", client_id="example-client", display_name="Example", description="",
        status=State.ACTIVE, assigned=HR_GRANTS, approved=HR_GRANTS, created_by="fixture-admin",
        created_at=now, updated_at=now, credential=Credential(version="metadata-version", created_at=now),
    )


def test_posts_only_verified_identity_and_server_context(settings, identity, agent):
    grants = {"roles": ["hr_agent"], "tools": ["read_hr_team"], "resources": ["hr_team/demo-team"],
              "scopes": ["hr_team_read"]}
    def respond(request):
        assert str(request.url) == f"https://opa.test{DECISION_PATH}"
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        assert json.loads(request.content) == {"input": {
            "human": {"subject": "human-id", "roles": ["hr_manager"]},
            "actor": {"subject": "actor-id", "roles": ["hr_agent"], "client_id": "example-client"},
            "delegation": {"audience": "example-api", "expires_at": identity.expires_at, "scopes": ["hr_team_read"]},
            "request": {"tool": "read_hr_team", "resource": {"type": "hr_team", "id": "demo-team"}},
            "context": {"expected_audience": "example-api", "allowed_agent_client": "example-client"},
            "governance": {"status": "ACTIVE", "client_id": "example-client", "assigned": grants, "approved": grants},
        }}
        return httpx.Response(200, json={"result": {"allow": True}})

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        OPAAuthorizer(client, settings).authorize_team_read(identity, agent)


@pytest.mark.parametrize(("status", "body"), [
    (200, b"{}"),
    (200, b""),
    (200, b"not json"),
    (200, b'{"result": true}'),
    (200, b'{"result":{"allow":"true"}}'),
    (200, b'{"result":{"allow":1}}'),
    (200, b'{"result":{"allow":true,"reason":"unexpected"}}'),
    (200, b'{"result":{"allow":false,"allow":true}}'),
    (200, b'{"result":{"allow":true},"unexpected":1}'),
    (200, b"x" * 4097),
    (200, b"[" * 1500 + b"]" * 1500),
    (302, b'{"result":{"allow":true}}'),
    (503, b'{"result":{"allow":true}}'),
])
def test_opa_response_fails_closed(settings, identity, agent, status, body):
    def respond(request):
        assert request.url.host == "opa.test"
        return httpx.Response(status, content=body, headers={"Location": "https://unrelated.test/"})

    with (
        httpx.Client(transport=httpx.MockTransport(respond), follow_redirects=True) as client,
        pytest.raises(PolicyUnavailable),
    ):
        OPAAuthorizer(client, settings).authorize_team_read(identity, agent)


@pytest.mark.parametrize("transport_error", [httpx.ReadTimeout, httpx.ConnectError])
def test_opa_network_failure_has_sanitized_error(settings, identity, agent, transport_error):
    def respond(request):
        raise transport_error("private diagnostic", request=request)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client, pytest.raises(PolicyUnavailable) as caught:
        OPAAuthorizer(client, settings).authorize_team_read(identity, agent)
    assert "private diagnostic" not in str(caught.value)


def test_valid_opa_denial_raises_policy_denied(settings, identity, agent):
    with httpx.Client(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={"result": {"allow": False}}),
    )) as client, pytest.raises(PolicyDenied):
        OPAAuthorizer(client, settings).authorize_team_read(identity, agent)


def test_never_uses_allow_returned_after_expiration(settings, identity, agent, monkeypatch):
    clock = iter([identity.expires_at - 1, identity.expires_at])
    monkeypatch.setattr("app.authorization.delegated.time", lambda: next(clock))
    with httpx.Client(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={"result": {"allow": True}}),
    )) as client, pytest.raises(PolicyDenied):
        OPAAuthorizer(client, settings).authorize_team_read(identity, agent)


@pytest.mark.parametrize("url", ["http://opa.test", "https://user:credential@opa.test", "https://opa.test/a"])
def test_opa_url_rejects_insecure_or_ambiguous_urls(settings, url):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{**settings.model_dump(), "opa_url": url})
