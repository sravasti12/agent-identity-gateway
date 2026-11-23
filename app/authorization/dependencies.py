from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request

from app.identity.sessions import SESSION_COOKIE
from app.identity.tokens import InvalidToken, KeycloakUnavailable, User


def authenticated_user(request: Request) -> User:
    app = request.app.state
    correlation = request.state.correlation_id
    authorization = request.headers.get("Authorization")
    if authorization is None:
        session = app.sessions.get(request.cookies.get(SESSION_COOKIE, ""))
        token = session.token if session is not None else None
    else:
        scheme, _, credentials = authorization.partition(" ")
        token = credentials if scheme.lower() == "bearer" else None
    unauthorized = HTTPException(
        status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        app.storage.audit("human_auth", "authenticate", "failure", "missing_human_credential", correlation)
        raise unauthorized
    try:
        user, _ = app.verifier.access_human(token)
    except InvalidToken:
        app.storage.audit("human_auth", "authenticate", "failure", "invalid_human_credential", correlation)
        raise unauthorized from None
    except KeycloakUnavailable:
        app.storage.audit("human_auth", "authenticate", "failure", "identity_provider_unavailable", correlation)
        raise HTTPException(503, "Identity provider unavailable") from None
    app.storage.audit("human_auth", "authenticate", "success", "authenticated", correlation, actor=user.subject)
    return user


CurrentUser = Annotated[User, Depends(authenticated_user)]


def require_role(role: str) -> Callable[[User], User]:
    def authorized(user: CurrentUser) -> User:
        if role not in user.realm_roles:
            raise HTTPException(403, "Insufficient permissions")
        return user

    return authorized
