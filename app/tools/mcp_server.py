import logging
from typing import Annotated

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import State
from starlette.requests import Request

from app.authorization.delegated import authorize_team_read
from app.identity.delegation import (
    DelegationDenied,
    ExchangeLifetimeError,
    ExchangeRejected,
    InvalidExchangeResponse,
)
from app.identity.tokens import (
    ExpiredToken,
    InvalidToken,
    KeycloakUnavailable,
    WrongAgentIdentity,
)

logger = logging.getLogger(__name__)


def suppress_sdk_request_log(_record: logging.LogRecord) -> bool:
    # The SDK can log decoded JSON-RPC messages or transport errors containing request data.
    return False


def suppress_sdk_root_request_log(record: logging.LogRecord) -> bool:
    # Some SDK session errors use logging.warning()/debug() on the root logger.
    source = record.pathname.replace("\\", "/").casefold()
    return not source.endswith(("/mcp/shared/session.py", "/mcp/server/sse.py"))


class TeamReadResult(BaseModel):
    subject: str
    actor: str
    actor_client: str
    audience: str


def read_team(state: State, authorization: str, handoff: str) -> TeamReadResult:
    if not state.settings.delegation_enabled:
        raise ToolError("Delegation unavailable")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        logger.info("mcp.team_read.denied reason=missing_bearer")
        raise ToolError("Agent bearer authentication required")
    try:
        actor, _ = state.verifier.access_agent(token, state.settings.keycloak_hr_agent_client_id)
        if len(handoff) != 43:
            raise DelegationDenied
        handle = state.handoffs.get(handoff)
        session = state.sessions.get(handle) if handle is not None else None
        if session is None:
            raise DelegationDenied
        subject, _ = state.delegation.verify_subject(session.token, actor.subject)
        if "hr_manager" not in subject.realm_roles:
            raise DelegationDenied
        if state.handoffs.get(handoff, consume=True) != handle:
            raise DelegationDenied
        identity = state.delegation.exchange(session.token, token)
        authorize_team_read(identity, state.settings.keycloak_api_audience)
    except ExpiredToken:
        logger.info("mcp.team_read.denied reason=input_expired")
        raise ToolError("Delegation input expired") from None
    except (InvalidToken, WrongAgentIdentity, DelegationDenied):
        logger.info("mcp.team_read.denied reason=authorization")
        raise ToolError("Delegated tool authorization denied") from None
    except KeycloakUnavailable:
        logger.warning("mcp.team_read.denied reason=provider_unavailable")
        raise ToolError("Identity provider unavailable") from None
    except ExchangeLifetimeError as error:
        logger.info("mcp.team_read.denied reason=%s", str(error))
        raise ToolError("Delegated credential lifetime invalid") from None
    except (ExchangeRejected, InvalidExchangeResponse):
        logger.warning("mcp.team_read.denied reason=exchange_failed")
        raise ToolError("Delegated credentials unavailable") from None
    logger.info("mcp.team_read.allowed")
    return TeamReadResult(
        subject=identity.subject.subject, actor=identity.actor.subject,
        actor_client=identity.actor_client, audience=identity.audience,
    )


def create_mcp(state: State, transport_security: TransportSecuritySettings) -> FastMCP:
    logging.getLogger().addFilter(suppress_sdk_root_request_log)
    for sdk_logger in (
        "mcp.server.lowlevel.server",
        "mcp.server.fastmcp.server",
        "mcp.server.streamable_http",
        "mcp.server.streamable_http_manager",
        "mcp.server.transport_security",
        "mcp.shared.session",
    ):
        logging.getLogger(sdk_logger).addFilter(suppress_sdk_request_log)
    server = FastMCP(
        "Agent Identity Gateway", stateless_http=True, json_response=True,
        transport_security=transport_security,
    )

    @server.tool()
    async def read_hr_team(
        handoff: Annotated[str, Field(description="One-use browser delegation handoff")],
        ctx: Context,
    ) -> TeamReadResult:
        """Verify permission for an HR team read and return the authorized identities."""
        request = ctx.request_context.request
        if not isinstance(request, Request):
            raise ToolError("Authenticated HTTP transport required")
        return await run_in_threadpool(read_team, state, request.headers.get("Authorization", ""), handoff)

    return server
