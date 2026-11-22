from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request

from app.identity.sessions import SESSION_COOKIE
from app.identity.tokens import InvalidToken, KeycloakUnavailable, User


def authenticated_user(request: Request) -> User:
    app = request.app.state
    authorization = request.headers.get("Authorization")
    if authorization is None:
        token = app.sessions.get(request.cookies.get(SESSION_COOKIE, ""))
    else:
        scheme, _, credentials = authorization.partition(" ")
        token = credentials if scheme.lower() == "bearer" else None
    unauthorized = HTTPException(
        status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise unauthorized
    try:
        return app.verifier.access_user(token)
    except InvalidToken:
        raise unauthorized from None
    except KeycloakUnavailable:
        raise HTTPException(503, "Identity provider unavailable") from None


CurrentUser = Annotated[User, Depends(authenticated_user)]


def require_role(role: str) -> Callable[[User], User]:
    def authorized(user: CurrentUser) -> User:
        if role not in user.realm_roles:
            raise HTTPException(403, "Insufficient permissions")
        return user

    return authorized
