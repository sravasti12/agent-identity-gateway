from threading import Lock
from time import monotonic
from typing import Any

import httpx
import jwt
from pydantic import BaseModel

from config.settings import Settings


class InvalidToken(ValueError):
    pass


class KeycloakUnavailable(RuntimeError):
    pass


class WrongAgentIdentity(ValueError):
    pass


class User(BaseModel):
    subject: str
    username: str
    realm_roles: tuple[str, ...]


class TokenVerifier:
    def __init__(self, settings: Settings, http: httpx.Client) -> None:
        self.settings = settings
        self.http = http
        self.keys: dict[str, jwt.PyJWK] = {}
        self.expires_at = 0.0
        self.retry_at = 0.0
        self.lock = Lock()

    def _key(self, kid: str) -> jwt.PyJWK:
        with self.lock:
            now = monotonic()
            fresh = now < self.expires_at
            if fresh and kid in self.keys:
                return self.keys[kid]
            if now >= self.retry_at:
                self.retry_at = now + 10
                try:
                    response = self.http.get(
                        f"{self.settings.keycloak_issuer}/protocol/openid-connect/certs"
                    )
                    response.raise_for_status()
                    document = response.json()
                    keys = {}
                    for entry in document["keys"]:
                        if (
                            entry.get("kty") == "RSA"
                            and entry.get("use") in (None, "sig")
                            and entry.get("alg") in (None, "RS256")
                            and isinstance(entry.get("kid"), str)
                        ):
                            keys[entry["kid"]] = jwt.PyJWK.from_dict(entry, algorithm="RS256")
                except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError, jwt.PyJWTError):
                    if not fresh:
                        raise KeycloakUnavailable from None
                else:
                    self.keys = keys
                    self.expires_at = monotonic() + 300
                    fresh = True
            if not fresh:
                raise KeycloakUnavailable
            if kid not in self.keys:
                raise InvalidToken
            return self.keys[kid]

    def decode(self, token: str, audience: str, required: list[str]) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if header.get("alg") != "RS256" or not isinstance(kid, str) or not kid:
                raise InvalidToken
            key = self._key(kid)
            return jwt.decode(
                token,
                key=key.key,
                algorithms=["RS256"],
                issuer=self.settings.keycloak_issuer,
                audience=audience,
                options={"require": ["iss", "aud", "exp", "sub", *required]},
            )
        except (jwt.PyJWTError, TypeError, ValueError, OverflowError):
            raise InvalidToken from None

    def access_user(self, token: str) -> User:
        user, _ = self._access_identity(token)
        return user

    def access_agent(self, token: str, client_id: str) -> tuple[User, int]:
        user, claims = self._access_identity(token)
        if type(claims["exp"]) is not int:
            raise InvalidToken
        if (
            claims.get("azp") != client_id
            or user.username != f"service-account-{client_id}"
            or "hr_agent" not in user.realm_roles
        ):
            raise WrongAgentIdentity
        return user, claims["exp"]

    def _access_identity(self, token: str) -> tuple[User, dict[str, Any]]:
        claims = self.decode(token, self.settings.keycloak_api_audience, ["preferred_username"])
        realm = claims.get("realm_access", {})
        roles = realm.get("roles", []) if isinstance(realm, dict) else None
        username = claims["preferred_username"]
        if (
            claims.get("typ") != "Bearer"
            or not claims["sub"]
            or not isinstance(username, str)
            or not username
            or not isinstance(roles, list)
            or not all(isinstance(role, str) for role in roles)
        ):
            raise InvalidToken
        user = User(subject=claims["sub"], username=username, realm_roles=tuple(roles))
        return user, claims
