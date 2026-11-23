import base64
import hashlib
from collections.abc import Iterator
from time import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.gateway.main import create_app
from config.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,
        gateway_database=":memory:",
        keycloak_issuer="https://keycloak.test/realms/test",
        keycloak_client_id="test-client",
        keycloak_client_secret="fixture-secret",
        keycloak_redirect_uri="https://gateway.test/auth/callback",
        keycloak_api_audience="test-api",
    )


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class MockKeycloak:
    def __init__(self, settings: Settings, key: rsa.RSAPrivateKey) -> None:
        self.settings = settings
        self.key = key
        self.nonce = ""
        self.id_claims: dict[str, str] = {}
        self.token_status = 200
        self.jwks_calls = 0
        self.exchange: dict[str, list[str]] = {}

    def token(self, **overrides) -> str:
        claims = {
            "iss": self.settings.keycloak_issuer,
            "aud": self.settings.keycloak_api_audience,
            "sub": "test-subject",
            "preferred_username": "test-user",
            "azp": self.settings.keycloak_client_id,
            "sid": "fixture-browser-session",
            "realm_access": {"roles": ["employee"]},
            "typ": "Bearer",
            "iat": int(time()),
            "exp": int(time()) + 300,
        }
        claims.update(overrides)
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "test-key"})

    def respond(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/certs"):
            assert request.method == "GET"
            self.jwks_calls += 1
            key = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
            return httpx.Response(200, json={"keys": [dict(key, kid="test-key", use="sig")]})
        assert request.url.path.endswith("/token")
        assert request.method == "POST"
        self.exchange = parse_qs(request.content.decode())
        if self.token_status != 200:
            return httpx.Response(self.token_status, json={"error_description": "private detail"})
        access_token = self.token()
        digest = hashlib.sha256(access_token.encode("ascii")).digest()
        id_claims = {
            "aud": self.settings.keycloak_client_id,
            "nonce": self.nonce,
            "typ": "ID",
            "at_hash": base64.urlsafe_b64encode(digest[:16]).decode("ascii").rstrip("="),
        }
        id_claims.update(self.id_claims)
        return httpx.Response(200, json={
            "access_token": access_token,
            "id_token": self.token(**id_claims),
            "refresh_token": "fixture-refresh-token",
        })


@pytest.fixture
def gateway(settings: Settings, signing_key: rsa.RSAPrivateKey) -> Iterator[tuple[TestClient, MockKeycloak]]:
    keycloak = MockKeycloak(settings, signing_key)
    app = create_app(settings, transport=httpx.MockTransport(keycloak.respond))
    with TestClient(app, base_url="https://gateway.test", follow_redirects=False) as client:
        yield client, keycloak


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("claims", [
    {"exp": 1},
    {"iss": "https://untrusted.test"},
    {"aud": "wrong-api"},
    {"typ": "ID"},
    {"realm_access": {"roles": "employee"}},
    {"exp": "invalid"},
])
def test_rejects_invalid_claims(gateway, claims):
    client, keycloak = gateway
    assert client.get("/auth/me", headers=bearer(keycloak.token(**claims))).status_code == 401


def test_rejects_invalid_signature(gateway):
    client, keycloak = gateway
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = MockKeycloak(keycloak.settings, other_key).token()
    assert client.get("/auth/me", headers=bearer(forged)).status_code == 401


def test_rejects_unpermitted_algorithm(gateway):
    client, keycloak = gateway
    token = jwt.encode({"sub": "test"}, "x" * 32, algorithm="HS256", headers={"kid": "test-key"})
    assert client.get("/auth/me", headers=bearer(token)).status_code == 401
    assert keycloak.jwks_calls == 0


@pytest.mark.parametrize("path", ["/auth/me", "/hr/team", "/employee/me"])
def test_missing_authentication(gateway, path):
    client, _ = gateway
    response = client.get(path)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(("role", "hr_status", "employee_status"), [
    ("employee", 403, 200),
    ("hr_manager", 200, 403),
    ("other", 403, 403),
])
def test_role_authorization_and_jwks_cache(gateway, role, hr_status, employee_status):
    client, keycloak = gateway
    headers = bearer(keycloak.token(realm_access={"roles": [role]}))
    assert client.get("/hr/team", headers=headers).status_code == hr_status
    assert client.get("/employee/me", headers=headers).status_code == employee_status
    assert client.get("/auth/me", headers=headers).json() == {
        "subject": "test-subject", "username": "test-user", "realm_roles": [role],
    }
    assert keycloak.jwks_calls == 1


def start_login(client: TestClient) -> dict[str, str]:
    response = client.get("/auth/login")
    assert response.status_code == 303
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "Secure" in response.headers["set-cookie"]
    return {key: values[0] for key, values in parse_qs(urlsplit(response.headers["location"]).query).items()}


def test_login_uses_pkce_and_keeps_tokens_server_side(gateway):
    client, keycloak = gateway
    login = start_login(client)
    keycloak.nonce = login["nonce"]
    callback = {"code": "fixture-code", "state": login["state"], "iss": keycloak.settings.keycloak_issuer}
    response = client.get("/auth/callback", params=callback)
    assert response.status_code == 303
    assert response.headers["location"] == "/auth/me"
    assert response.headers["cache-control"] == "no-store"
    session = client.cookies["gateway_session"]
    assert len(session) == 43
    assert session != login["state"]
    assert "fixture-secret" not in str(response.headers)
    assert "fixture-refresh-token" not in str(response.headers)
    assert response.content == b""
    verifier = keycloak.exchange["code_verifier"][0]
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert login["code_challenge_method"] == "S256"
    assert login["code_challenge"] == expected
    assert keycloak.exchange["grant_type"] == ["authorization_code"]
    assert keycloak.exchange["client_secret"] == ["fixture-secret"]
    assert keycloak.exchange["redirect_uri"] == [keycloak.settings.keycloak_redirect_uri]
    assert client.get("/auth/me").json()["username"] == "test-user"
    assert client.get("/employee/me").status_code == 200
    assert client.get("/hr/team").status_code == 403
    assert client.get("/auth/me", headers=bearer("bad-token")).status_code == 401
    client.cookies.set("gateway_login", login["state"], domain="gateway.test", path="/auth/callback")
    assert client.get("/auth/callback", params=callback).status_code == 400


@pytest.mark.parametrize("failure", [
    "state", "nonce", "token_hash", "id_token_type", "provider_error", "issuer", "exchange",
])
def test_login_failures(gateway, failure):
    client, keycloak = gateway
    login = start_login(client)
    keycloak.nonce = login["nonce"]
    params = {"state": login["state"], "code": "fixture-code"}
    expected = 400
    if failure == "state":
        params["state"] = "wrong-state"
    elif failure == "nonce":
        keycloak.nonce = "wrong-nonce"
        expected = 401
    elif failure == "token_hash":
        keycloak.id_claims["at_hash"] = "wrong-hash"
        expected = 401
    elif failure == "id_token_type":
        keycloak.id_claims["typ"] = "Bearer"
        expected = 401
    elif failure == "provider_error":
        params.update(error="access_denied", error_description="private detail")
    elif failure == "issuer":
        params["iss"] = "https://untrusted.test"
    else:
        keycloak.token_status = 503
        expected = 503
    response = client.get("/auth/callback", params=params)
    assert response.status_code == expected
    assert "private detail" not in response.text
    assert "gateway_session" not in client.cookies
    if expected == 400:
        assert not keycloak.exchange
