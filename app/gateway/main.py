from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Annotated
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, FastAPI, Request, Response
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import ValidationError

from app.authorization.dependencies import CurrentUser, require_role
from app.identity.agent_routes import router as agent_router
from app.identity.agent_tokens import AgentTokenService
from app.identity.delegation import DelegationService
from app.identity.routes import PRIVATE_HEADERS, router
from app.identity.sessions import (
    HANDOFF_TTL,
    LOGIN_TTL,
    SESSION_TTL,
    BrowserSession,
    ExpiringStore,
    LoginAttempt,
)
from app.identity.tokens import TokenVerifier, User
from app.tools.mcp_server import create_mcp
from config.settings import Settings


def create_app(
    settings: Settings | None = None, *, transport: httpx.BaseTransport | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            app.state.settings = settings if settings is not None else Settings()  # type: ignore[call-arg]
        except ValidationError as error:
            fields = ", ".join(
                str(issue["loc"][0]) if issue["loc"] else "HR agent credentials"
                for issue in error.errors(include_input=False)
            )
            raise RuntimeError(f"Missing or invalid gateway configuration: {fields}") from None
        callback_url = urlsplit(app.state.settings.keycloak_redirect_uri)
        transport_security = mcp.settings.transport_security
        if transport_security is None:
            raise RuntimeError("MCP transport security is required")
        transport_security.allowed_hosts = [callback_url.netloc]
        transport_security.allowed_origins = [f"{callback_url.scheme}://{callback_url.netloc}"]
        app.state.login_attempts = ExpiringStore[LoginAttempt](LOGIN_TTL)
        app.state.sessions = ExpiringStore[BrowserSession](SESSION_TTL)
        app.state.handoffs = ExpiringStore[str](HANDOFF_TTL)
        with httpx.Client(timeout=5.0, transport=transport, trust_env=False) as http:
            app.state.http = http
            app.state.verifier = TokenVerifier(app.state.settings, http)
            app.state.agent_tokens = AgentTokenService(app.state.settings, http, app.state.verifier)
            app.state.delegation = DelegationService(app.state.settings, http, app.state.verifier)
            async with mcp.session_manager.run():
                yield

    app = FastAPI(title="Agent Identity Gateway", lifespan=lifespan)
    app.include_router(router)
    app.include_router(agent_router)

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

    mcp = create_mcp(app.state, TransportSecuritySettings())
    app.mount("/", mcp.streamable_http_app())
    return app


app = create_app()
