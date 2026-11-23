from concurrent.futures import ThreadPoolExecutor
from time import time
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.gateway.main import create_app
from app.identity import agent_tokens
from app.identity.agent_tokens import AgentCredentialsRejected, AgentTokenService, InvalidAgentTokenResponse
from app.identity.tokens import KeycloakUnavailable, TokenVerifier
from config.settings import Settings


CLIENT_ID = "test-hr-agent"
FIXTURE_SECRET = "mock-agent-secret"
SUBJECT = "test-service-account-subject"


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def settings(monkeypatch):
    monkeypatch.setenv("KEYCLOAK_HR_AGENT_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("KEYCLOAK_HR_AGENT_CLIENT_SECRET", FIXTURE_SECRET)
    return Settings(
        _env_file=None,
        keycloak_issuer="https://keycloak.test/realms/test",
        keycloak_api_audience="test-api",
        keycloak_client_id="human-client",
        keycloak_client_secret="mock-human-secret",
        keycloak_redirect_uri="https://gateway.test/auth/callback",
    )


class KeycloakStub:
    def __init__(self, settings, key):
        self.settings = settings
        self.key = key
        self.exchanges = 0
        self.response = None
        self.claims = {}
        self.expires_in = 300

    def token(self, **overrides):
        claims = {
            "iss": self.settings.keycloak_issuer,
            "aud": self.settings.keycloak_api_audience,
            "sub": SUBJECT,
            "preferred_username": f"service-account-{CLIENT_ID}",
            "azp": CLIENT_ID,
            "realm_access": {"roles": ["hr_agent"]},
            "typ": "Bearer",
            "exp": int(time()) + 300,
        }
        claims.update(overrides)
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "test-key"})

    def respond(self, request):
        base = f"{self.settings.keycloak_issuer}/protocol/openid-connect"
        if request.url == f"{base}/certs":
            assert request.method == "GET"
            key = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
            return httpx.Response(200, json={"keys": [dict(key, kid="test-key", use="sig")]})
        assert request.url == f"{base}/token"
        assert request.method == "POST"
        assert parse_qs(request.content.decode()) == {
            "grant_type": ["client_credentials"],
            "client_id": [CLIENT_ID],
            "client_secret": [FIXTURE_SECRET],
        }
        self.exchanges += 1
        if isinstance(self.response, httpx.HTTPError):
            raise self.response
        if self.response is not None:
            return self.response
        return httpx.Response(200, json={
            "access_token": self.token(**self.claims), "expires_in": self.expires_in, "token_type": "Bearer",
        })


@pytest.fixture
def keycloak(settings, key):
    return KeycloakStub(settings, key)


@pytest.fixture
def service(settings, keycloak):
    with httpx.Client(transport=httpx.MockTransport(keycloak.respond)) as http:
        yield AgentTokenService(settings, http, TokenVerifier(settings, http))


@pytest.fixture
def gateway(settings, keycloak):
    with TestClient(create_app(settings, transport=httpx.MockTransport(keycloak.respond))) as client:
        yield client


def test_agent_settings_load_environment(settings, monkeypatch):
    assert settings.keycloak_hr_agent_client_id == CLIENT_ID
    assert settings.keycloak_hr_agent_client_secret.get_secret_value() == FIXTURE_SECRET
    assert FIXTURE_SECRET not in repr(settings)
    monkeypatch.setenv("KEYCLOAK_HR_AGENT_CLIENT_SECRET", " ")
    with pytest.raises(ValidationError, match="Configure both HR agent"):
        Settings(_env_file=None, **settings.model_dump(exclude={"keycloak_hr_agent_client_secret"}))


def test_exchange_and_concurrent_cache_reuse(service, keycloak):
    with ThreadPoolExecutor(max_workers=4) as executor:
        tokens = list(executor.map(lambda _: service.get_token(), range(8)))
    issued = tokens[0]
    assert issued.identity.subject == SUBJECT
    assert issued.identity.realm_roles == ("hr_agent",)
    assert issued.access_token not in repr(issued)
    assert all(token is issued for token in tokens)
    assert keycloak.exchanges == 1


def test_refresh_before_expiry_and_after_expired_cache(service, keycloak, monkeypatch):
    clock = 100.0
    monkeypatch.setattr(agent_tokens, "monotonic", lambda: clock)
    keycloak.expires_in = 10
    initial = service.get_token()
    clock = 108.0
    assert service.get_token() is initial
    clock = 109.0
    refreshed = service.get_token()
    assert refreshed is not initial
    clock = 120.0
    assert service.get_token() is not refreshed
    assert keycloak.exchanges == 3


def test_jwt_expiry_caps_cache_and_failed_refresh_does_not_return_stale(service, keycloak, monkeypatch):
    wall_clock = int(time())
    monkeypatch.setattr(agent_tokens, "time", lambda: wall_clock)
    keycloak.claims["exp"] = wall_clock + 10
    service.get_token()
    wall_clock += 10
    keycloak.response = httpx.Response(503)
    with pytest.raises(KeycloakUnavailable):
        service.get_token()
    assert keycloak.exchanges == 2


@pytest.mark.parametrize(("response", "error"), [
    (httpx.Response(401, json={"error": "invalid_client"}), AgentCredentialsRejected),
    (httpx.Response(400, json={"error": "invalid_client"}), AgentCredentialsRejected),
    (httpx.Response(503), KeycloakUnavailable),
    (httpx.ReadTimeout("mock timeout"), KeycloakUnavailable),
    (httpx.Response(200, text="not json"), InvalidAgentTokenResponse),
    (httpx.Response(200, json=[]), InvalidAgentTokenResponse),
    (httpx.Response(200, json={"expires_in": 300, "token_type": "Bearer"}), InvalidAgentTokenResponse),
    (httpx.Response(200, json={"access_token": "placeholder", "expires_in": True, "token_type": "Bearer"}), InvalidAgentTokenResponse),
    (httpx.Response(200, json={"access_token": "placeholder", "expires_in": 300, "token_type": "Basic"}), InvalidAgentTokenResponse),
])
def test_safe_exchange_errors(service, keycloak, response, error):
    keycloak.response = response
    with pytest.raises(error):
        service.get_token()


@pytest.mark.parametrize("claims", [
    {"iss": "https://wrong.test"},
    {"aud": "wrong-api"},
    {"exp": 1},
    {"azp": "other-client"},
    {"preferred_username": "human-user"},
    {"realm_access": {"roles": ["employee"]}},
])
def test_refuses_to_cache_invalid_service_identity(service, keycloak, claims):
    keycloak.claims.update(claims)
    with pytest.raises(InvalidAgentTokenResponse):
        service.get_token()


def test_refuses_to_cache_token_signed_by_another_key(service, keycloak):
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = KeycloakStub(keycloak.settings, other_key).token()
    keycloak.response = httpx.Response(200, json={
        "access_token": token, "expires_in": 300, "token_type": "Bearer",
    })
    with pytest.raises(InvalidAgentTokenResponse):
        service.get_token()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_diagnostic_requires_agent_bearer_and_preserves_human_role_checks(gateway, keycloak):
    assert gateway.get("/agent/me").status_code == 401
    assert gateway.get("/agent/me", headers=bearer("invalid")).status_code == 401
    human = keycloak.token(azp="human-client", preferred_username="priya")
    assert gateway.get("/agent/me", headers=bearer(human)).status_code == 403
    assert keycloak.exchanges == 0
    token = keycloak.token()
    response = gateway.get("/agent/me", headers=bearer(token))
    assert response.status_code == 200
    assert response.json() == {
        "subject": SUBJECT, "username": f"service-account-{CLIENT_ID}", "realm_roles": ["hr_agent"],
    }
    assert response.headers["cache-control"] == "no-store"
    for path in ("/hr/team", "/employee/me"):
        assert gateway.get(path, headers=bearer(token)).status_code == 403
    assert keycloak.exchanges == 1


def test_diagnostic_requires_matching_service_subject(gateway, keycloak):
    other_subject = keycloak.token(sub="unrelated-subject")
    assert gateway.get("/agent/me", headers=bearer(other_subject)).status_code == 403


@pytest.mark.parametrize(("status", "expected"), [(401, 502), (503, 503)])
def test_diagnostic_hides_provider_error(gateway, keycloak, status, expected):
    keycloak.response = httpx.Response(status, json={"error_description": "internal details"})
    response = gateway.get("/agent/me", headers=bearer(keycloak.token()))
    assert response.status_code == expected
    assert "internal details" not in response.text
