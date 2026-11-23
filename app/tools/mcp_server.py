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
    ExchangeRejected,
    InvalidExchangeResponse,
)
from app.identity.tokens import InvalidToken, KeycloakUnavailable, WrongAgentIdentity


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
    except (InvalidToken, WrongAgentIdentity, DelegationDenied):
        raise ToolError("Delegated tool authorization denied") from None
    except KeycloakUnavailable:
        raise ToolError("Identity provider unavailable") from None
    except (ExchangeRejected, InvalidExchangeResponse):
        raise ToolError("Delegated credentials unavailable") from None
    return TeamReadResult(
        subject=identity.subject.subject, actor=identity.actor.subject,
        actor_client=identity.actor_client, audience=identity.audience,
    )


def create_mcp(state: State, transport_security: TransportSecuritySettings) -> FastMCP:
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
