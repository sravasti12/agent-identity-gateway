from time import time
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.identity.tokens import InvalidToken, KeycloakUnavailable, TokenVerifier, User
from config.settings import Settings

ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
TOOL_SCOPE = "hr_team_read"
OIDC_SCOPES = frozenset({"openid", "profile", "email"})
MAX_DELEGATED_SECONDS = 300


class DelegationDenied(ValueError):
    pass


class ExchangeRejected(RuntimeError):
    pass


class InvalidExchangeResponse(RuntimeError):
    pass


class ExchangeResponse(BaseModel):
    model_config = ConfigDict(strict=True, hide_input_in_errors=True)

    access_token: str = Field(min_length=1, repr=False, exclude=True)
    token_type: str
    issued_token_type: Literal["urn:ietf:params:oauth:token-type:access_token"]
    expires_in: int = Field(gt=0, le=MAX_DELEGATED_SECONDS)
    refresh_token: None = None


class DelegatedIdentity(BaseModel):
    subject: User
    actor: User
    actor_client: str
    audience: str
    granted_scopes: frozenset[str]
    expires_at: int


def authorization_scopes(claims: dict[str, Any]) -> frozenset[str]:
    scope = claims.get("scope")
    if not isinstance(scope, str):
        raise DelegationDenied
    return frozenset(scope.split())


def delegation_scope(client_id: str) -> str:
    return f"delegation:client:{client_id}"


class DelegationService:
    def __init__(self, settings: Settings, http: httpx.Client, verifier: TokenVerifier) -> None:
        self.settings = settings
        self.http = http
        self.verifier = verifier

    def verify_subject(self, token: str, actor_subject: str | None = None) -> tuple[User, dict[str, Any]]:
        subject, claims = self.verifier.access_identity(token)
        client_id = self.settings.keycloak_hr_agent_client_id
        audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        actor = claims.get("may_act")
        if (
            not self.settings.delegation_enabled or client_id is None
            or claims.get("azp") != self.settings.keycloak_client_id
            or subject.username.startswith("service-account-")
            or "act" in claims or type(claims["exp"]) is not int
            or client_id not in audiences
            or not isinstance(actor, dict)
            or actor.get("client_id") != client_id
            or not isinstance(actor.get("sub"), str) or not actor["sub"]
            or actor["sub"] == subject.subject or "act" in actor
            or actor.get("iss", self.settings.keycloak_issuer) != self.settings.keycloak_issuer
            or (actor_subject is not None and actor["sub"] != actor_subject)
            or not {TOOL_SCOPE, delegation_scope(client_id)} <= authorization_scopes(claims)
        ):
            raise DelegationDenied
        return subject, claims

    def exchange(self, subject_token: str, actor_token: str) -> DelegatedIdentity:
        settings = self.settings
        client_id = settings.keycloak_hr_agent_client_id
        secret = settings.keycloak_hr_agent_client_secret
        if not settings.delegation_enabled or client_id is None or secret is None:
            raise DelegationDenied
        actor, actor_exp = self.verifier.access_agent(actor_token, client_id)
        subject, source = self.verify_subject(subject_token, actor.subject)
        try:
            response = self.http.post(
                f"{settings.keycloak_issuer}/protocol/openid-connect/token",
                data={
                    "grant_type": EXCHANGE_GRANT,
                    "client_id": client_id,
                    "client_secret": secret.get_secret_value(),
                    "subject_token": subject_token,
                    "subject_token_type": ACCESS_TOKEN_TYPE,
                    "actor_token": actor_token,
                    "actor_token_type": ACCESS_TOKEN_TYPE,
                    "requested_token_type": ACCESS_TOKEN_TYPE,
                    "audience": settings.keycloak_api_audience,
                    "scope": TOOL_SCOPE,
                },
                timeout=5.0,
                follow_redirects=False,
            )
        except httpx.HTTPError:
            raise KeycloakUnavailable from None
        if response.status_code >= 500 or response.status_code == 429:
            raise KeycloakUnavailable
        if response.status_code == 401:
            raise ExchangeRejected
        if response.status_code in (400, 403):
            raise DelegationDenied
        if response.status_code != 200:
            raise InvalidExchangeResponse

        try:
            result = ExchangeResponse.model_validate_json(response.content)
            delegated, claims = self.verifier.access_identity(result.access_token)
        except (ValidationError, InvalidToken):
            raise InvalidExchangeResponse from None
        expiry = claims["exp"]
        now = time()
        audience = settings.keycloak_api_audience
        act = claims.get("act")
        if (
            result.token_type.lower() != "bearer"
            or claims.get("azp") != client_id or claims["aud"] not in (audience, [audience])
            or delegated.subject != subject.subject or delegated.username != subject.username
            or not isinstance(act, dict)
            or act.get("sub") != actor.subject or act.get("client_id") != client_id
            or act.get("iss", settings.keycloak_issuer) != settings.keycloak_issuer
            or "act" in act or "may_act" in claims
            or type(expiry) is not int or not now < expiry <= min(source["exp"], actor_exp, now + MAX_DELEGATED_SECONDS)
            or not set(delegated.realm_roles) <= set(subject.realm_roles)
        ):
            raise InvalidExchangeResponse
        granted = authorization_scopes(claims)
        if (
            TOOL_SCOPE not in granted
            or not granted <= (OIDC_SCOPES | {TOOL_SCOPE})
            or not granted <= authorization_scopes(source)
        ):
            raise DelegationDenied
        return DelegatedIdentity(
            subject=delegated, actor=actor, actor_client=client_id,
            audience=audience, granted_scopes=granted, expires_at=expiry,
        )
