import logging
import os
import socket
import subprocess
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic, sleep, time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from test_lifecycle import MockProvider

from app.authorization.delegated import DECISION_PATH
from app.gateway.main import create_app
from app.identity.delegation import (
    ACCESS_TOKEN_TYPE,
    EXCHANGE_GRANT,
    TOOL_SCOPE,
    DelegationDenied,
    DelegationService,
    ExchangeLifetimeError,
    ExchangeRejected,
    InvalidExchangeResponse,
)
from app.identity.lifecycle_models import HR_GRANTS, Registration, State
from app.identity.sessions import HANDOFF_TTL, SESSION_COOKIE, SESSION_TTL
from app.identity.tokens import (
    InvalidToken,
    KeycloakUnavailable,
    TokenVerifier,
    WrongAgentIdentity,
)
from config.settings import Settings

CLIENT = "test-agent"
HUMAN = "test-human"
AUDIENCE = "test-api"
ACTOR_SUBJECT = "agent-subject"
SUBJECT = "human-subject"


@pytest.fixture
def settings():
    return Settings(
        _env_file=None,
        gateway_database=":memory:",
        keycloak_issuer="https://idp.test/realms/test",
        keycloak_client_id=HUMAN,
        keycloak_client_secret="mock-human-secret",
        keycloak_redirect_uri="https://gateway.test/auth/callback",
        keycloak_api_audience=AUDIENCE,
        keycloak_hr_agent_client_id=CLIENT,
        keycloak_hr_agent_client_secret="mock-agent-secret",
        delegation_enabled=True,
    )


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class Provider:
    def __init__(self, settings, key):
        self.settings = settings
        self.key = key
        self.exchanges = []
        self.exchange_status = 200
        self.override_exchange = None
        self.output_claims = {}
        self.human_claims = {}
        self.nonce = ""

    def sign(self, **kwargs):
        body = {
            "iss": self.settings.keycloak_issuer, "typ": "Bearer",
            "iat": int(time()), "exp": int(time()) + 200, "aud": AUDIENCE,
            "sub": SUBJECT, "preferred_username": "test-user",
            "realm_access": {"roles": ["hr_manager"]},
        }
        body.update(kwargs)
        return jwt.encode(body, self.key, algorithm="RS256", headers={"kid": "fixture-key"})

    def human(self, **kwargs):
        claims = {
            "azp": HUMAN, "aud": [AUDIENCE, CLIENT],
            "sid": "fixture-browser-session",
            "scope": f"openid profile {TOOL_SCOPE} delegation:client:{CLIENT}",
            "may_act": {"sub": ACTOR_SUBJECT, "client_id": CLIENT},
        }
        claims.update(self.human_claims)
        claims.update(kwargs)
        return self.sign(**claims)

    def actor(self, **kwargs):
        claims = {
            "azp": CLIENT, "sub": ACTOR_SUBJECT, "preferred_username": f"service-account-{CLIENT}",
            "realm_access": {"roles": ["hr_agent"]},
        }
        claims.update(kwargs)
        return self.sign(**claims)

    def respond(self, request):
        if request.url.path.endswith("/certs"):
            key = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
            return httpx.Response(200, json={"keys": [dict(key, kid="fixture-key")]})
        assert request.url.path.endswith("/token")
        form = {key: value[0] for key, value in parse_qs(request.content.decode()).items()}
        if form["grant_type"] == "authorization_code":
            return httpx.Response(200, json={
                "id_token": self.sign(typ="ID", aud=HUMAN, nonce=self.nonce,
                                      sub=self.human_claims.get("sub", SUBJECT)),
                "access_token": self.human(),
            })
        self.exchanges.append(form)
        if self.override_exchange is not None:
            return self.override_exchange
        if self.exchange_status != 200:
            return httpx.Response(self.exchange_status, json={"error_description": "internal provider details"})
        claims = {
            "azp": CLIENT, "act": {"sub": ACTOR_SUBJECT, "client_id": CLIENT},
            "scope": TOOL_SCOPE, "exp": int(time()) + 100,
        }
        claims.update(self.output_claims)
        return httpx.Response(200, json={
            "access_token": self.sign(**claims), "expires_in": 100, "token_type": "Bearer",
            "issued_token_type": ACCESS_TOKEN_TYPE,
        })


@pytest.fixture
def provider(settings, key):
    return Provider(settings, key)


@pytest.fixture
def service(settings, provider):
    with httpx.Client(transport=httpx.MockTransport(provider.respond)) as client:
        yield DelegationService(settings, client, TokenVerifier(settings, client))


@pytest.fixture
def opa_decision():
    return {"result": {"allow": True}}


@pytest.fixture
def gateway(settings, provider, opa_decision):
    def respond(request):
        assert request.url.path == DECISION_PATH
        return httpx.Response(200, json=opa_decision)

    with TestClient(
        create_app(
            settings, transport=httpx.MockTransport(provider.respond),
            opa_transport=httpx.MockTransport(respond),
        ),
        base_url="https://gateway.test", follow_redirects=False,
    ) as client:
        seed_agent(client)
        yield client


def seed_agent(client):
    lifecycle = client.app.state.lifecycle
    lifecycle.register(
        Registration(id="fixture-agent", client_id=CLIENT, display_name="Fixture agent", approved=HR_GRANTS),
        "fixture-admin", "fixture-correlation",
    )
    return lifecycle.transition("fixture-agent", State.ACTIVE, "approved_onboarding", "fixture-admin", "fixture-correlation")


@pytest.fixture(scope="module")
def opa_server():
    binary = os.environ.get("OPA_TEST_BINARY")
    if not binary:
        pytest.skip("Set OPA_TEST_BINARY to run the real OPA integration")
    with socket.socket() as server_socket:
        server_socket.bind(("127.0.0.1", 0))
        port = server_socket.getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    policy_dir = Path(__file__).resolve().parents[2] / "policies"
    with subprocess.Popen(
        [
            binary, "run", "--server", f"--addr=127.0.0.1:{port}", "--authorization=basic",
            "--skip-version-check", str(policy_dir / "authorization.rego"),
            str(policy_dir / "api_authorization.rego"),
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    ) as process:
        try:
            with httpx.Client(base_url=base_url, trust_env=False, timeout=0.2) as http:
                deadline = monotonic() + 6
                while monotonic() < deadline and process.poll() is None:
                    try:
                        if http.get("/health").status_code == 200:
                            break
                    except httpx.RequestError:
                        pass
                    sleep(0.05)
                else:
                    pytest.fail("OPA did not become healthy")
                assert http.get("/v1/policies").status_code in (401, 403)
            yield base_url
        finally:
            process.terminate()


def test_exchange_validates_and_downscopes(service, provider):
    actor, human = provider.actor(), provider.human()
    identity = service.exchange(human, actor)
    assert identity.actor.subject == ACTOR_SUBJECT
    assert identity.subject.subject == SUBJECT
    assert identity.audience == AUDIENCE
    assert identity.granted_scopes == {TOOL_SCOPE}
    assert provider.exchanges == [{
        "grant_type": EXCHANGE_GRANT, "client_id": CLIENT, "client_secret": "mock-agent-secret",
        "actor_token": actor, "subject_token": human, "actor_token_type": ACCESS_TOKEN_TYPE,
        "subject_token_type": ACCESS_TOKEN_TYPE, "requested_token_type": ACCESS_TOKEN_TYPE,
        "scope": TOOL_SCOPE, "audience": AUDIENCE,
    }]
    assert "access_token" not in identity.model_dump()


@pytest.mark.parametrize(("claims", "error"), [
    ({"exp": 1}, InvalidToken),
    ({"aud": ["wrong", CLIENT]}, InvalidToken),
    ({"aud": AUDIENCE}, DelegationDenied),
    ({"iss": "https://untrusted.test"}, InvalidToken),
    ({"may_act": None}, DelegationDenied),
    ({"may_act": {"sub": "unrelated", "client_id": CLIENT}}, DelegationDenied),
    ({"scope": f"openid delegation:client:{CLIENT}"}, DelegationDenied),
    ({"azp": "unrelated-client"}, InvalidToken),
])
def test_rejects_bad_subject_before_exchange(service, provider, claims, error):
    with pytest.raises(error):
        service.exchange(provider.human(**claims), provider.actor())
    assert not provider.exchanges


def test_rejects_invalid_subject_signature(service, provider, settings):
    forged = Provider(settings, rsa.generate_private_key(public_exponent=65537, key_size=2048)).human()
    with pytest.raises(InvalidToken):
        service.exchange(forged, provider.actor())
    assert not provider.exchanges


def test_rejects_an_unauthorized_requesting_client(service, provider):
    with pytest.raises(WrongAgentIdentity):
        service.exchange(provider.human(), provider.actor(azp="wrong"))
    assert not provider.exchanges


@pytest.mark.parametrize(("status", "error"), [
    (401, ExchangeRejected), (403, DelegationDenied), (400, DelegationDenied),
    (429, KeycloakUnavailable), (503, KeycloakUnavailable),
])
def test_provider_failures_are_sanitized(service, provider, status, error):
    provider.exchange_status = status
    with pytest.raises(error) as exc:
        service.exchange(provider.human(), provider.actor())
    assert "internal provider details" not in str(exc.value)


@pytest.mark.parametrize("response", [httpx.Response(200, text="not JSON"), httpx.Response(200, json={})])
def test_malformed_exchange_response(service, provider, response):
    provider.override_exchange = response
    with pytest.raises(InvalidExchangeResponse):
        service.exchange(provider.human(), provider.actor())


@pytest.mark.parametrize(("claims", "error"), [
    ({"aud": "wrong"}, InvalidExchangeResponse),
    ({"aud": [AUDIENCE, "another-api"]}, InvalidExchangeResponse),
    ({"exp": 1}, InvalidExchangeResponse),
    ({"act": {"sub": "unrelated", "client_id": CLIENT}}, InvalidExchangeResponse),
    ({"act": {"sub": ACTOR_SUBJECT, "client_id": "unrelated-client"}}, InvalidExchangeResponse),
    ({"azp": "unrelated-client"}, InvalidExchangeResponse),
    ({"sub": "unrelated-human"}, InvalidExchangeResponse),
    ({"scope": "profile"}, DelegationDenied),
    ({"scope": f"{TOOL_SCOPE} hr_team_write"}, DelegationDenied),
    ({"realm_access": {"roles": ["hr_manager", "admin"]}}, InvalidExchangeResponse),
])
def test_rejects_unusable_or_overprivileged_output(service, provider, claims, error):
    provider.output_claims.update(claims)
    with pytest.raises(error):
        service.exchange(provider.human(), provider.actor())


def start_delegated_login(gateway, provider):
    start = gateway.get("/auth/login?delegate=true")
    assert start.status_code == 303
    query = parse_qs(urlsplit(start.headers["location"]).query)
    assert set(query["scope"][0].split()) == {"openid", "profile", TOOL_SCOPE, f"delegation:client:{CLIENT}"}
    provider.nonce = query["nonce"][0]
    return gateway.get("/auth/callback", params={"code": "mock-code", "state": query["state"][0]})


def handoff(gateway, provider):
    assert start_delegated_login(gateway, provider).status_code == 303
    assert gateway.post("/auth/delegation", headers={"Origin": "https://other.test"}).status_code == 403
    result = gateway.post("/auth/delegation", headers={"Origin": "https://gateway.test"})
    assert result.status_code == 200
    return result.json()["handoff"]


def tool(gateway, code, token=None, name="read_hr_team"):
    headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = gateway.post("/mcp", headers=headers, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": {"handoff": code}},
    })
    assert response.status_code == 200, response.text
    return response.json()


def test_independent_browser_sessions_keep_handoffs_and_expiry_separate(gateway, provider, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("app.identity.sessions.monotonic", lambda: clock[0])
    other_subject = "second-human-subject"
    with closing(TestClient(gateway.app, base_url="https://gateway.test", follow_redirects=False)) as other:
        first = handoff(gateway, provider)
        clock[0] += 1
        provider.human_claims["sub"] = other_subject
        second = handoff(other, provider)
        assert gateway.cookies[SESSION_COOKIE] != other.cookies[SESSION_COOKIE]
        assert first != second
        origin = {"Origin": "https://gateway.test"}
        assert gateway.post("/auth/delegation", headers=origin).json()["handoff"] == first
        assert other.post("/auth/delegation", headers=origin).json()["handoff"] == second
        assert gateway.get("/auth/me").json()["subject"] == SUBJECT
        assert other.get("/auth/me").json()["subject"] == other_subject
        bearer = provider.actor()
        assert tool(gateway, first, bearer)["result"]["structuredContent"]["subject"] == SUBJECT
        provider.output_claims["sub"] = other_subject
        assert tool(other, second, bearer)["result"]["structuredContent"]["subject"] == other_subject
        clock[0] += SESSION_TTL - 1
        assert gateway.get("/auth/me").status_code == 401
        assert other.get("/auth/me").json()["subject"] == other_subject


def test_other_registered_agent_cannot_use_configured_agents_handoff(gateway, provider, monkeypatch):
    lifecycle = gateway.app.state.lifecycle
    other_client = "second-workload"
    lifecycle.register(
        Registration(id="second-agent", client_id=other_client, display_name="Second agent"),
        "fixture-admin", "fixture-correlation",
    )
    code = handoff(gateway, provider)
    other_bearer = provider.actor(azp=other_client, sub="second-workload-subject",
                                  preferred_username=f"service-account-{other_client}")

    def reject_execution(_identity):
        pytest.fail("Tool executed for a different workload client")

    with monkeypatch.context() as patch:
        patch.setattr("app.tools.mcp_server.team_read_result", reject_execution)
        assert tool(gateway, code, other_bearer)["result"]["isError"]
    assert not provider.exchanges
    denial, = gateway.app.state.storage.events(20, 0, "mcp_invocation", None, "deny")
    assert denial.reason_code == "authorization"
    assert tool(gateway, code, provider.actor())["result"]["structuredContent"]["actor"] == ACTOR_SUBJECT


def test_mcp_checks_bearer_and_consumes_handoff_once(gateway, provider):
    code = handoff(gateway, provider)
    assert tool(gateway, code)["result"]["isError"]
    assert tool(gateway, code, provider.actor(azp="wrong"))["result"]["isError"]
    assert tool(gateway, code, provider.actor(sub="wrong"))["result"]["isError"]
    assert not provider.exchanges
    token = provider.actor()
    result = tool(gateway, code, token)["result"]
    assert not result.get("isError", False)
    assert result["structuredContent"] == {
        "subject": SUBJECT, "actor": ACTOR_SUBJECT, "actor_client": CLIENT, "audience": AUDIENCE,
    }
    assert tool(gateway, code, token)["result"]["isError"]
    assert len(provider.exchanges) == 1


def admin_headers(provider):
    return {"Authorization": f"Bearer {provider.human(realm_access={'roles': ['gateway_admin']})}"}


def test_human_bearer_is_rejected_at_both_agent_boundaries(gateway, provider, monkeypatch, caplog):
    code = handoff(gateway, provider)
    bearer = provider.human()
    diagnostic = gateway.get("/agent/me", headers={"Authorization": f"Bearer {bearer}"})
    assert diagnostic.status_code == 403

    def reject_execution(_identity):
        pytest.fail("Tool executed with a human bearer")

    with monkeypatch.context() as patch:
        patch.setattr("app.tools.mcp_server.team_read_result", reject_execution)
        response = tool(gateway, code, bearer)
    assert response["result"]["isError"]
    assert not provider.exchanges
    storage = gateway.app.state.storage
    auth = storage.events(20, 0, "agent_auth", None, "failure")
    assert any(event.reason_code == "wrong_identity" and
               event.correlation_id == diagnostic.headers["X-Correlation-ID"] for event in auth)
    denial, = storage.events(20, 0, "mcp_invocation", None, "deny")
    assert denial.reason_code == "authorization"
    assert any(event.correlation_id == denial.correlation_id for event in auth)
    assert all(value not in str((diagnostic.text, response, caplog.text, auth, denial))
               for value in (bearer, code))
    assert not tool(gateway, code, provider.actor())["result"].get("isError")


@pytest.mark.parametrize("cookie", [None, "synthetic-unknown-session"], ids=["missing", "unknown"])
def test_handoff_claim_requires_a_live_browser_session(gateway, provider, cookie, caplog):
    headers = {"Origin": "https://gateway.test"}
    if cookie is not None:
        headers["Cookie"] = f"{SESSION_COOKIE}={cookie}"
    response = gateway.post("/auth/delegation", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Browser session required"}
    event, = gateway.app.state.storage.events(20, 0, "delegation_rejected", None, None)
    assert (event.decision, event.reason_code) == ("deny", "session_missing")
    assert event.correlation_id == response.headers["X-Correlation-ID"]
    assert not provider.exchanges
    if cookie is not None:
        assert cookie not in str((response.text, caplog.text, event))
    assert handoff(gateway, provider)


@pytest.mark.parametrize("provider_fails", [False, True], ids=["confirmed", "failed"])
def test_mock_rotation_controls_mcp_bearer_cutoff_and_handoff_generation(
    gateway, provider, provider_fails, monkeypatch, caplog,
):
    cutoff = int(time()) - 10

    class RotationClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(cutoff, tz or UTC)

    monkeypatch.setattr("app.identity.lifecycle.datetime", RotationClock)
    state = gateway.app.state
    mock = MockProvider()
    mock.fail_rotation = provider_fails
    state.lifecycle.provider = mock
    old = provider.actor(iat=cutoff - 1)
    assert not tool(gateway, handoff(gateway, provider), old)["result"].get("isError")
    rotation = state.lifecycle.request_rotation("fixture-agent", "fixture-admin", "rotation-correlation")
    assert rotation.state == "PENDING" and not mock.rotations
    assert not tool(gateway, handoff(gateway, provider), old)["result"].get("isError")
    previous_handoff = handoff(gateway, provider)
    result = state.lifecycle.apply_rotation("fixture-agent", rotation.id, "fixture-admin", "rotation-correlation")
    assert result.state == ("FAILED" if provider_fails else "COMPLETED")
    assert mock.rotations == [(CLIENT, rotation.id)]
    accepted = old if provider_fails else provider.actor(iat=cutoff + 1)
    attempts = [(previous_handoff, accepted)]
    if not provider_fails:
        attempts.append((handoff(gateway, provider), old))

    def reject_execution(_identity):
        pytest.fail("Tool executed with an invalidated handoff or stale bearer")

    exchanges = len(provider.exchanges)
    with monkeypatch.context() as patch:
        patch.setattr("app.tools.mcp_server.team_read_result", reject_execution)
        for code, bearer in attempts:
            response = tool(gateway, code, bearer)
            assert response["result"]["isError"]
            assert all(value not in str((response, caplog.text)) for value in (code, bearer))
    assert len(provider.exchanges) == exchanges
    denials = state.storage.events(20, 0, "mcp_invocation", None, "deny")
    assert len(denials) == len(attempts)
    assert all(value.correlation_id for value in denials)
    if not provider_fails:
        assert any(value.reason_code == "stale_agent_token" for value in denials)
    events = state.storage.events(100, 0, None, None, None)
    assert all(value not in str((events, caplog.text)) for value in (
        old, accepted, previous_handoff, "synthetic secret returned in provider diagnostic",
    ))
    assert not tool(gateway, handoff(gateway, provider), accepted)["result"].get("isError")


def test_mcp_rejects_handoff_at_expiry(gateway, provider, monkeypatch, caplog):
    clock = [100.0]
    monkeypatch.setattr("app.identity.sessions.monotonic", lambda: clock[0])
    code = handoff(gateway, provider)
    bearer = provider.actor()
    clock[0] += HANDOFF_TTL

    def reject_execution(_identity):
        pytest.fail("Tool executed with an expired handoff")

    with monkeypatch.context() as patch:
        patch.setattr("app.tools.mcp_server.team_read_result", reject_execution)
        response = tool(gateway, code, bearer)
    assert response["result"]["isError"]
    assert not provider.exchanges
    event, = gateway.app.state.storage.events(20, 0, "mcp_invocation", None, None)
    assert (event.decision, event.reason_code) == ("deny", "authorization")
    assert all(value not in str((response, caplog.text, event)) for value in (code, bearer))
    assert not tool(gateway, handoff(gateway, provider), bearer)["result"].get("isError")


def test_governance_http_onboarding_and_audit_require_verified_admin(gateway, provider):
    body = {"id": "new-agent", "client_id": "new-client", "display_name": "New agent"}
    ordinary = {"Authorization": f"Bearer {provider.human()}"}
    workload = provider.actor(realm_access={"roles": ["hr_agent", "gateway_admin"]})
    assert gateway.post("/admin/agents", json=body).status_code == 401
    assert gateway.post("/admin/agents", headers=ordinary, json=body).status_code == 403
    assert gateway.post("/admin/agents", headers={"Authorization": f"Bearer {workload}"}, json=body).status_code == 401
    headers = admin_headers(provider)
    rejected = gateway.post("/admin/agents", headers=headers, json={**body, "client_secret": "sensitive-fixture"})
    assert rejected.status_code == 422 and "sensitive-fixture" not in rejected.text
    created = gateway.post("/admin/agents", headers={**headers, "X-Correlation-ID": "untrusted"}, json=body)
    assert created.status_code == 201
    assert created.json()["status"] == "PENDING"
    assert not any(created.json()["assigned"].values())
    assert gateway.post("/admin/agents", headers=headers, json=body).status_code == 409
    assert gateway.get("/admin/agents/new-agent", headers=headers).json()["created_by"] == SUBJECT
    assert gateway.get("/admin/agents", headers=headers, params={"after": "fixture-agent", "limit": 1}).json()[0]["id"] == body["id"]
    assert gateway.get("/admin/audit", headers=ordinary).status_code == 403
    events = gateway.get("/admin/audit", headers=headers, params={
        "agent": body["id"], "event_type": "agent_onboarded", "limit": 1,
    }).json()
    assert len(events) == 1 and events[0]["correlation_id"] == created.headers["X-Correlation-ID"]
    assert events[0]["correlation_id"] != "untrusted"
    assert gateway.get("/admin/audit/integrity", headers=headers).json()["valid"]


@pytest.mark.parametrize("target", ["SUSPENDED", "DEPROVISIONED"])
def test_inactive_agent_cannot_use_pending_handoff_or_administer_itself(gateway, provider, target):
    code = handoff(gateway, provider)
    actor = provider.actor(realm_access={"roles": ["hr_agent", "gateway_admin"]})
    workload = {"Authorization": f"Bearer {actor}"}
    ordinary = {"Authorization": f"Bearer {provider.human()}"}
    path = "/admin/agents/fixture-agent/state"
    payload = {"reason": "incident"}
    assert gateway.post(f"{path}/{target}", headers=ordinary, json=payload).status_code == 403
    changed = gateway.post(f"{path}/{target}", headers=admin_headers(provider), json=payload)
    assert changed.status_code == 200 and changed.json()["status"] == target
    assert gateway.post(f"{path}/ACTIVE", headers=workload, json={"reason": "restored"}).status_code == 401
    assert gateway.get("/agent/me", headers=workload).status_code == 403
    assert gateway.get("/auth/login?delegate=true").status_code == 403
    assert tool(gateway, code, actor)["result"]["isError"]
    if target == "SUSPENDED":
        assert gateway.post(
            f"{path}/ACTIVE", headers=admin_headers(provider), json={"reason": "restored"},
        ).status_code == 200
        assert tool(gateway, code, actor)["result"]["isError"]
    assert not provider.exchanges


@pytest.mark.parametrize("target", [State.SUSPENDED, State.DEPROVISIONED])
def test_revocation_between_opa_and_local_execution_prevents_invocation(gateway, provider, monkeypatch, target, caplog):
    code = handoff(gateway, provider)
    state = gateway.app.state
    authorize = state.authorizer.authorize_team_read

    def allow_then_revoke(identity, agent):
        authorize(identity, agent)
        state.lifecycle.transition(agent.id, target, "incident", "fixture-admin", "fixture-correlation")

    def reject_execution(_identity):
        pytest.fail("Tool executed after local deprovisioning")

    monkeypatch.setattr(state.authorizer, "authorize_team_read", allow_then_revoke)
    monkeypatch.setattr("app.tools.mcp_server.team_read_result", reject_execution)
    bearer = provider.actor()
    response = tool(gateway, code, bearer)
    assert response["result"]["isError"]
    assert len(provider.exchanges) == 1
    assert state.storage.events(20, 0, "opa_decision", "fixture-agent", "allow")
    assert not state.storage.events(20, 0, "mcp_invocation", "fixture-agent", "allow")
    event, = state.storage.events(20, 0, "mcp_invocation", "fixture-agent", "deny")
    assert all(value not in str((response, caplog.text, event)) for value in (code, bearer))


def test_workload_cannot_decide_reviews_and_approved_revocation_changes_permissions(gateway, provider):
    path = "/admin/agents/fixture-agent/reviews"
    headers = admin_headers(provider)
    review = gateway.post(path, headers=headers, json={"proposed": {}})
    assert review.status_code == 201
    decision = f"{path}/{review.json()['id']}/decision"
    assert gateway.post(
        decision, headers={"Authorization": f"Bearer {provider.actor()}"},
        json={"decision": "APPROVED"},
    ).status_code == 401
    assert gateway.post(
        decision, headers={"Authorization": f"Bearer {provider.human()}"},
        json={"decision": "APPROVED"},
    ).status_code == 403
    applied = gateway.post(decision, headers=headers, json={"decision": "APPROVED"})
    assert applied.status_code == 200 and applied.json()["decision"] == "APPROVED"
    assert gateway.get("/auth/login?delegate=true").status_code == 403


def test_successful_tool_writes_correlated_credential_free_audit(gateway, provider):
    code = handoff(gateway, provider)
    bearer = provider.actor()
    assert not tool(gateway, code, bearer)["result"].get("isError")
    events = gateway.app.state.storage.events(100, 0, None, None, None)
    invoked = next(event for event in events if event.event_type == "mcp_invocation")
    assert {event.event_type for event in events if event.correlation_id == invoked.correlation_id} == {
        "agent_auth", "delegation_accepted", "exchange", "opa_decision", "mcp_invocation",
    }
    assert any(event.event_type == "delegation_created" for event in events)
    assert all(value not in str(events) for value in (code, bearer, "mock-agent-secret", "Authorization:"))
    assert gateway.app.state.lifecycle.details("fixture-agent").last_access_at is not None


@pytest.mark.parametrize("opa_payload", [{"result": {"allow": False}}, {}, {"result": {"allow": "true"}}])
def test_mcp_never_executes_tool_without_explicit_opa_allow(
    gateway, provider, opa_decision, opa_payload, monkeypatch,
):
    opa_decision.clear()
    opa_decision.update(opa_payload)

    def reject_execution(_identity):
        pytest.fail("Tool was executed without explicit OPA allow")

    monkeypatch.setattr("app.tools.mcp_server.team_read_result", reject_execution)
    code = handoff(gateway, provider)
    actor = provider.actor()
    assert tool(gateway, code, actor)["result"]["isError"]
    assert tool(gateway, code, actor)["result"]["isError"]
    assert len(provider.exchanges) == 1


@pytest.mark.parametrize("failure", [httpx.ConnectError, httpx.ReadTimeout], ids=["offline", "timeout"])
def test_mcp_audits_opa_transport_failure_without_executing_tool(
    settings, provider, failure, monkeypatch, caplog,
):
    diagnostic = "synthetic private policy diagnostic"

    def unavailable(request):
        assert request.url.path == DECISION_PATH
        raise failure(diagnostic, request=request)

    def reject_execution(_identity):
        pytest.fail("Tool executed after a policy transport failure")

    monkeypatch.setattr("app.tools.mcp_server.team_read_result", reject_execution)
    with TestClient(
        create_app(settings, transport=httpx.MockTransport(provider.respond),
                   opa_transport=httpx.MockTransport(unavailable)),
        base_url="https://gateway.test", follow_redirects=False,
    ) as gateway:
        seed_agent(gateway)
        code = handoff(gateway, provider)
        bearer = provider.actor()
        response = tool(gateway, code, bearer)
        assert response["result"]["isError"]
        storage = gateway.app.state.storage
        invocation, = storage.events(20, 0, "mcp_invocation", "fixture-agent", None)
        policy, = storage.events(20, 0, "opa_decision", "fixture-agent", None)
        assert (invocation.decision, invocation.reason_code) == ("deny", "policy_unavailable")
        assert (policy.decision, policy.reason_code) == ("deny", "unavailable_or_invalid")
        assert invocation.correlation_id == policy.correlation_id
        assert all(value not in str((response, caplog.text, invocation, policy))
                   for value in (diagnostic, code, bearer))


def test_mcp_runtime_uses_real_opa_policy(settings, provider, opa_server):
    settings.opa_url = opa_server
    with TestClient(
        create_app(settings, transport=httpx.MockTransport(provider.respond)),
        base_url="https://gateway.test", follow_redirects=False,
    ) as gateway:
        seed_agent(gateway)
        actor = provider.actor()
        allowed = tool(gateway, handoff(gateway, provider), actor)["result"]
        assert not allowed.get("isError", False)
        assert allowed["structuredContent"]["subject"] == SUBJECT
        provider.output_claims["realm_access"] = {"roles": []}
        denied = tool(gateway, handoff(gateway, provider), actor)["result"]
        assert denied["isError"]
        assert len(provider.exchanges) == 2


def test_mcp_denies_missing_hr_authority_and_unknown_tool(gateway, provider):
    provider.human_claims["realm_access"] = {"roles": ["employee"]}
    provider.output_claims["realm_access"] = {"roles": ["employee"]}
    code = handoff(gateway, provider)
    token = provider.actor()
    unknown = tool(gateway, code, token, name="write_hr_team")
    assert "error" in unknown or unknown["result"]["isError"]
    assert not provider.exchanges
    assert tool(gateway, code, token)["result"]["isError"]
    assert not provider.exchanges


def test_mcp_denies_wrong_audience_and_expired_actor(gateway, provider):
    code = handoff(gateway, provider)
    for token in (provider.actor(aud="unrelated-api"), provider.actor(exp=1)):
        assert tool(gateway, code, token)["result"]["isError"]
    assert not provider.exchanges


def test_mcp_denies_untrusted_host(gateway):
    response = gateway.post("/mcp", headers={
        "Host": "untrusted.test", "Accept": "application/json, text/event-stream",
    }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 421


def test_mcp_provider_errors_do_not_echo_credentials(gateway, provider):
    code = handoff(gateway, provider)
    provider.exchange_status = 503
    token = provider.actor()
    response = str(tool(gateway, code, token))
    assert "Identity provider unavailable" in response
    assert all(value not in response for value in (code, token, "mock-agent-secret", "internal provider details"))
    assert tool(gateway, code, token)["result"]["isError"]


def test_declined_consent_does_not_create_handoff(gateway, provider):
    provider.human_claims["may_act"] = None
    assert start_delegated_login(gateway, provider).status_code == 403
    assert gateway.post("/auth/delegation", headers={"Origin": "https://gateway.test"}).status_code == 401


def test_delegated_token_cannot_be_used_as_direct_human_bearer(gateway, provider):
    token = provider.human(act={"sub": ACTOR_SUBJECT, "client_id": CLIENT})
    assert gateway.get("/hr/team", headers={"Authorization": f"Bearer {token}"}).status_code == 401


@pytest.mark.parametrize(("path", "role"), [("/hr/team", "hr_manager"), ("/employee/me", "employee")])
def test_direct_routes_require_human_token_class(gateway, provider, path, role):
    roles = {"roles": [role]}
    rejected = [
        provider.actor(realm_access=roles),
        provider.human(azp="unrelated-client", realm_access=roles),
        provider.human(act={"sub": ACTOR_SUBJECT}, realm_access=roles),
        provider.human(exp=1, realm_access=roles),
        provider.human(aud="wrong-api", realm_access=roles),
        provider.human(client_id=HUMAN, preferred_username="ordinary-looking-name", realm_access=roles),
        provider.human(sid=None, realm_access=roles),
    ]
    for token in rejected:
        assert gateway.get(path, headers={"Authorization": f"Bearer {token}"}).status_code == 401

    valid = provider.human(preferred_username="service-account-looking-user", realm_access=roles)
    assert gateway.get(path, headers={"Authorization": f"Bearer {valid}"}).status_code == 200


@pytest.mark.parametrize(("subject_lifetime", "actor_lifetime"), [(100, 200), (200, 100)])
def test_exchange_accepts_expiration_at_shortest_input(service, provider, subject_lifetime, actor_lifetime):
    now = int(time())
    expiry = now + min(subject_lifetime, actor_lifetime)
    provider.output_claims["exp"] = expiry
    assert service.exchange(
        provider.human(exp=now + subject_lifetime), provider.actor(exp=now + actor_lifetime),
    ).expires_at == expiry


@pytest.mark.parametrize(("subject_lifetime", "actor_lifetime", "output_lifetime", "reason"), [
    (90, 200, 100, "subject_expiry_exceeded"),
    (200, 90, 100, "actor_expiry_exceeded"),
    (200, 200, -1, "response_expired"),
    (600, 600, 500, "max_lifetime_exceeded"),
])
def test_exchange_rejects_invalid_lifetimes(service, provider, subject_lifetime, actor_lifetime, output_lifetime, reason):
    now = int(time())
    provider.output_claims["exp"] = now + output_lifetime
    with pytest.raises(ExchangeLifetimeError, match=f"^{reason}$"):
        service.exchange(
            provider.human(exp=now + subject_lifetime), provider.actor(exp=now + actor_lifetime),
        )


@pytest.mark.parametrize("lifetime", [0, 301])
def test_rejects_invalid_reported_lifetime(service, provider, lifetime):
    provider.override_exchange = httpx.Response(200, json={
        "access_token": "opaque-fixture-value", "expires_in": lifetime,
        "token_type": "Bearer", "issued_token_type": ACCESS_TOKEN_TYPE,
    })
    with pytest.raises(ExchangeLifetimeError, match="^invalid_reported_lifetime$"):
        service.exchange(provider.human(), provider.actor())


def test_invalid_actor_signature_and_identical_subject_are_denied(service, provider, settings):
    forged_actor = Provider(settings, rsa.generate_private_key(public_exponent=65537, key_size=2048)).actor()
    with pytest.raises(InvalidToken):
        service.exchange(provider.human(), forged_actor)
    with pytest.raises(DelegationDenied):
        service.exchange(provider.human(sub=ACTOR_SUBJECT), provider.actor())
    assert not provider.exchanges


@pytest.mark.parametrize("roles", [
    {"test-api": {"roles": ["manage"]}},
    {"unrelated": {"roles": ["read"]}},
    {"unrelated": {"roles": "read"}},
])
def test_rejects_added_or_malformed_client_roles(service, provider, roles):
    provider.output_claims["resource_access"] = roles
    with pytest.raises(InvalidExchangeResponse):
        service.exchange(
            provider.human(resource_access={"test-api": {"roles": ["read"]}}), provider.actor(),
        )


def test_preserves_existing_client_roles_without_using_them_for_policy(service, provider):
    roles = {"test-api": {"roles": ["read"]}}
    provider.output_claims["resource_access"] = roles
    assert service.exchange(provider.human(resource_access=roles), provider.actor()).granted_scopes == {TOOL_SCOPE}


def test_mcp_debug_logs_are_credential_free_and_preserve_security_events(gateway, provider, caplog):
    caplog.set_level(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger="mcp.server.lowlevel.server")
    code = handoff(gateway, provider)
    bearer = provider.actor()
    unauthorized = provider.actor(realm_access={"roles": ["employee"]})
    malformed = gateway.post("/mcp", headers={
        "Accept": "application/json, text/event-stream", "Authorization": f"Bearer {bearer}",
    }, json={"jsonrpc": "2.0", "id": 1, "method": "invalid", "params": {"handoff": code}})
    assert "error" in malformed.json()
    assert tool(gateway, code, unauthorized)["result"]["isError"]
    assert not provider.exchanges
    provider.output_claims["exp"] = 1
    assert tool(gateway, code, bearer)["result"]["isError"]
    assert "reason=authorization" in caplog.text
    assert "reason=response_expired" in caplog.text
    assert "Received message:" not in caplog.text
    assert all(value not in caplog.text for value in (
        code, bearer, unauthorized, "Authorization:", "mock-agent-secret",
    ))
