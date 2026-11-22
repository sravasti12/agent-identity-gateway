from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, Request, Response
from pydantic import ValidationError

from app.authorization.dependencies import CurrentUser, require_role
from app.identity.routes import PRIVATE_HEADERS, router
from app.identity.sessions import LOGIN_TTL, SESSION_TTL, ExpiringStore, LoginAttempt
from app.identity.tokens import TokenVerifier, User
from config.settings import Settings


def create_app(
    settings: Settings | None = None, *, transport: httpx.BaseTransport | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            app.state.settings = settings if settings is not None else Settings()
        except ValidationError as error:
            fields = ", ".join(str(issue["loc"][0]) for issue in error.errors())
            raise RuntimeError(f"Missing or invalid gateway configuration: {fields}") from None
        app.state.login_attempts = ExpiringStore[LoginAttempt](LOGIN_TTL)
        app.state.sessions = ExpiringStore[str](SESSION_TTL)
        with httpx.Client(timeout=5.0, transport=transport, trust_env=False) as http:
            app.state.http = http
            app.state.verifier = TokenVerifier(app.state.settings, http)
            yield

    app = FastAPI(title="Agent Identity Gateway", lifespan=lifespan)
    app.include_router(router)

    @app.middleware("http")
    async def private_responses(
        request: Request, call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers.update(PRIVATE_HEADERS)
        return response

    @app.get("/auth/me")
    def me(user: CurrentUser) -> User:
        return user

    @app.get("/hr/team")
    def hr_team(user: Annotated[User, Depends(require_role("hr_manager"))]) -> User:
        return user

    @app.get("/employee/me")
    def employee_me(user: Annotated[User, Depends(require_role("employee"))]) -> User:
        return user

    return app


app = create_app()
