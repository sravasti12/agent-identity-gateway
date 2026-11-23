from dataclasses import dataclass, field
from threading import Lock
from time import monotonic, time

import httpx

from app.identity.tokens import InvalidToken, KeycloakUnavailable, TokenVerifier, User, WrongAgentIdentity
from config.settings import Settings


MAX_CACHE_SECONDS = 3600


class AgentCredentialsRejected(RuntimeError):
    pass


class InvalidAgentTokenResponse(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentToken:
    access_token: str = field(repr=False)
    identity: User
    expires_at: int
    refresh_at: float


class AgentTokenService:
    def __init__(self, settings: Settings, http: httpx.Client, verifier: TokenVerifier) -> None:
        self.client_id = settings.keycloak_hr_agent_client_id
        self.client_secret = settings.keycloak_hr_agent_client_secret
        self.token_url = f"{settings.keycloak_issuer}/protocol/openid-connect/token"
        self.http = http
        self.verifier = verifier
        self._cached: AgentToken | None = None
        self._lock = Lock()

    def get_token(self) -> AgentToken:
        with self._lock:
            cached = self._cached
            if cached is not None and monotonic() < cached.refresh_at and time() < cached.expires_at:
                return cached
            self._cached = self._request_token()
            return self._cached

    def _request_token(self) -> AgentToken:
        if self.client_id is None or self.client_secret is None:
            raise AgentCredentialsRejected
        started = monotonic()
        try:
            response = self.http.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret.get_secret_value(),
                },
                timeout=5.0,
                follow_redirects=False,
            )
            if response.status_code in (401, 403):
                raise AgentCredentialsRejected
            if response.status_code == 400:
                body = response.json()
                if isinstance(body, dict) and body.get("error") in ("invalid_client", "unauthorized_client"):
                    raise AgentCredentialsRejected
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPError:
            raise KeycloakUnavailable from None
        except ValueError:
            raise InvalidAgentTokenResponse from None

        if not isinstance(body, dict):
            raise InvalidAgentTokenResponse
        token = body.get("access_token")
        token_type = body.get("token_type")
        expires_in = body.get("expires_in")
        if (
            not isinstance(token, str)
            or not token
            or not isinstance(token_type, str)
            or token_type.lower() != "bearer"
            or type(expires_in) is not int
            or expires_in <= 0
        ):
            raise InvalidAgentTokenResponse
        try:
            identity, jwt_expiry = self.verifier.access_agent(token, self.client_id)
        except (InvalidToken, WrongAgentIdentity):
            raise InvalidAgentTokenResponse from None
        now = monotonic()
        wall_now = time()
        jwt_deadline = min(jwt_expiry, int(wall_now) + MAX_CACHE_SECONDS + 1)
        remaining = min(min(expires_in, MAX_CACHE_SECONDS) - (now - started), jwt_deadline - wall_now)
        if remaining <= 0:
            raise InvalidAgentTokenResponse
        refresh_at = now + remaining - min(30.0, remaining * 0.1)
        return AgentToken(token, identity, jwt_expiry, refresh_at)
