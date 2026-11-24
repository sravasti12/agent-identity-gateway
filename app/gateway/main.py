from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, closing
from sqlite3 import Error as SQLiteError
from typing import Annotated
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import ValidationError

from app.audit.store import Database
from app.authorization.delegated import OPAAuthorizer
from app.authorization.dependencies import CurrentUser, require_role
from app.identity.agent_routes import router as agent_router
from app.identity.agent_tokens import AgentTokenService
from app.identity.delegation import DelegationService
from app.identity.lifecycle import AgentProvider, Lifecycle, LifecycleError
from app.identity.lifecycle_routes import router as lifecycle_router
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
    opa_transport: httpx.BaseTransport | None = None,
    agent_provider: AgentProvider | None = None,
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
        with (
            closing(Database(app.state.settings.gateway_database)) as storage,
            httpx.Client(timeout=5.0, transport=transport, trust_env=False) as http,
            httpx.Client(timeout=2.0, transport=opa_transport, trust_env=False) as opa_http,
        ):
            app.state.http = http
            app.state.opa_http = opa_http
            app.state.storage = storage
            app.state.lifecycle = Lifecycle(storage, app.state.settings.access_review_days, agent_provider)
            app.state.verifier = TokenVerifier(app.state.settings, http)
            app.state.agent_tokens = AgentTokenService(app.state.settings, http, app.state.verifier)
            app.state.delegation = DelegationService(app.state.settings, http, app.state.verifier)
            app.state.authorizer = OPAAuthorizer(opa_http, app.state.settings)
            async with mcp.session_manager.run():
                yield

    app = FastAPI(title="Agent Identity Gateway", lifespan=lifespan)
    app.include_router(router)
    app.include_router(agent_router)
    app.include_router(lifecycle_router)

    @app.exception_handler(LifecycleError)
    async def lifecycle_error(_request: Request, error: LifecycleError) -> Response:
        return JSONResponse({"detail": error.code}, error.status)

    @app.exception_handler(RequestValidationError)
    async def private_validation(request: Request, error: RequestValidationError) -> Response:
        if request.url.path.startswith("/admin/"):
            return JSONResponse({"detail": "invalid_governance_request"}, 422)
        return await request_validation_exception_handler(request, error)

    @app.middleware("http")
    async def private_responses(
        request: Request, call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request.state.correlation_id = uuid4().hex
        response = await call_next(request)
        response.headers.update(PRIVATE_HEADERS)
        response.headers["X-Correlation-ID"] = request.state.correlation_id
        return response

    @app.get("/auth/me")
    def me(user: CurrentUser) -> User:
        return user

    @app.get("/health/live", include_in_schema=False)
    def live() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/health/ready", include_in_schema=False)
    def ready() -> JSONResponse:
        state = app.state
        issuer = state.settings.keycloak_issuer
        checks = {"database": False, "identity_provider": False}
        try:
            with state.storage.lock:
                checks["database"] = state.storage.connection.execute(
                    "SELECT 1 FROM audit_head WHERE singleton=1"
                ).fetchone() is not None
        except SQLiteError:
            pass
        try:
            response = state.http.get(f"{issuer.rstrip('/')}/.well-known/openid-configuration", timeout=2.0)
            metadata = response.json() if response.status_code == 200 else None
            checks["identity_provider"] = isinstance(metadata, dict) and metadata.get("issuer") == issuer
        except (httpx.HTTPError, ValueError):
            pass
        if state.settings.delegation_enabled:
            checks["policy_engine"] = False
            try:
                checks["policy_engine"] = state.opa_http.get(
                    f"{state.settings.opa_url}/health?bundles", timeout=2.0,
                ).status_code == 200
            except httpx.HTTPError:
                pass
        available = all(checks.values())
        return JSONResponse({"status": "ready" if available else "unavailable", "checks": checks},
                            status_code=200 if available else 503)

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
