from time import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.gateway.main import create_app
from app.identity.delegation import (
    ACCESS_TOKEN_TYPE,
    EXCHANGE_GRANT,
    TOOL_SCOPE,
    DelegationDenied,
    DelegationService,
    ExchangeRejected,
    InvalidExchangeResponse,
)
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
                "id_token": self.sign(typ="ID", aud=HUMAN, nonce=self.nonce),
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
def gateway(settings, provider):
    with TestClient(
        create_app(settings, transport=httpx.MockTransport(provider.respond)),
        base_url="https://gateway.test", follow_redirects=False,
    ) as client:
        yield client


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
    ({"azp": "unrelated-client"}, DelegationDenied),
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
    token = provider.sign(act={"sub": ACTOR_SUBJECT, "client_id": CLIENT})
    assert gateway.get("/hr/team", headers={"Authorization": f"Bearer {token}"}).status_code == 401
