import logging
from typing import Annotated

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import State
from starlette.requests import Request

from app.audit.store import Decision, EventType
from app.authorization.delegated import PolicyDenied, PolicyUnavailable
from app.identity.delegation import (
    DelegatedIdentity,
    DelegationDenied,
    ExchangeLifetimeError,
    ExchangeRejected,
    InvalidExchangeResponse,
)
from app.identity.lifecycle import LifecycleError
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


def read_team(state: State, authorization: str, handoff: str, correlation_id: str) -> TeamReadResult:
    actor_id: str | None = None
    subject_id: str | None = None
    agent_id: str | None = None

    def audit(event: EventType, decision: Decision, reason: str) -> None:
        state.storage.audit(
            event, "read_hr_team", decision, reason, correlation_id,
            actor=actor_id, subject=subject_id, agent=agent_id, resource="hr_team/demo-team", scope="hr_team_read",
        )

    if not state.settings.delegation_enabled:
        audit("mcp_invocation", "deny", "delegation_disabled")
        raise ToolError("Delegation unavailable")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        audit("agent_auth", "failure", "missing_bearer")
        audit("mcp_invocation", "deny", "missing_bearer")
        logger.info("mcp.team_read.denied reason=missing_bearer")
        raise ToolError("Agent bearer authentication required")
    try:
        client_id = state.settings.keycloak_hr_agent_client_id
        actor, actor_claims = state.verifier.agent_identity(token, client_id)
        actor_id = actor.subject
        audit("agent_auth", "success", "authenticated")
        if len(handoff) != 43:
            raise DelegationDenied
        handle = state.handoffs.get(handoff)
        session = state.sessions.get(handle) if handle is not None else None
        if session is None:
            raise DelegationDenied
        subject, _ = state.delegation.verify_subject(session.token, actor.subject)
        subject_id = subject.subject
        if "hr_manager" not in subject.realm_roles:
            raise DelegationDenied
        agent = state.lifecycle.check_hr(
            client_id, session.agent_generation, actor_claims.get("iat"), check_token=True,
        )
        agent_id = agent.id
        if state.handoffs.get(handoff, consume=True) != handle:
            raise DelegationDenied
        audit("delegation_accepted", "success", "handoff_consumed")
        try:
            identity = state.delegation.exchange(session.token, token)
        except (InvalidToken, WrongAgentIdentity, DelegationDenied, KeycloakUnavailable,
                ExchangeRejected, InvalidExchangeResponse) as error:
            reason = str(error) if isinstance(error, ExchangeLifetimeError) else "exchange_denied"
            audit("exchange", "failure", reason)
            raise
        audit("exchange", "success", "verified")
        try:
            state.authorizer.authorize_team_read(identity, agent)
        except (PolicyDenied, PolicyUnavailable) as error:
            audit("opa_decision", "deny", "unavailable_or_invalid" if isinstance(error, PolicyUnavailable) else "denied")
            raise
        audit("opa_decision", "allow", "allowed")
        state.lifecycle.record_invocation(
            client_id, agent.generation, actor_claims.get("iat"), identity.expires_at,
            identity.actor.subject, identity.subject.subject, correlation_id,
        )
    except ExpiredToken:
        if actor_id is None:
            audit("agent_auth", "failure", "input_expired")
        audit("delegation_rejected", "deny", "input_expired")
        audit("mcp_invocation", "deny", "input_expired")
        logger.info("mcp.team_read.denied reason=input_expired")
        raise ToolError("Delegation input expired") from None
    except (InvalidToken, WrongAgentIdentity, DelegationDenied, PolicyDenied):
        if actor_id is None:
            audit("agent_auth", "failure", "authorization")
        audit("delegation_rejected", "deny", "authorization")
        audit("mcp_invocation", "deny", "authorization")
        logger.info("mcp.team_read.denied reason=authorization")
        raise ToolError("Delegated tool authorization denied") from None
    except PolicyUnavailable:
        audit("delegation_rejected", "deny", "policy_unavailable")
        audit("mcp_invocation", "deny", "policy_unavailable")
        logger.warning("mcp.team_read.denied reason=policy_unavailable")
        raise ToolError("Delegated tool authorization unavailable") from None
    except KeycloakUnavailable:
        if actor_id is None:
            audit("agent_auth", "failure", "provider_unavailable")
        audit("delegation_rejected", "deny", "provider_unavailable")
        audit("mcp_invocation", "deny", "provider_unavailable")
        logger.warning("mcp.team_read.denied reason=provider_unavailable")
        raise ToolError("Identity provider unavailable") from None
    except ExchangeLifetimeError as error:
        audit("delegation_rejected", "deny", str(error))
        audit("mcp_invocation", "deny", str(error))
        logger.info("mcp.team_read.denied reason=%s", str(error))
        raise ToolError("Delegated credential lifetime invalid") from None
    except (ExchangeRejected, InvalidExchangeResponse):
        audit("delegation_rejected", "deny", "exchange_failed")
        audit("mcp_invocation", "deny", "exchange_failed")
        logger.warning("mcp.team_read.denied reason=exchange_failed")
        raise ToolError("Delegated credentials unavailable") from None
    except LifecycleError as error:
        agent_id = error.agent_id or agent_id
        audit("delegation_rejected", "deny", error.code)
        audit("mcp_invocation", "deny", error.code)
        raise ToolError("Delegated tool authorization denied") from None
    logger.info("mcp.team_read.allowed")
    return team_read_result(identity)


def team_read_result(identity: DelegatedIdentity) -> TeamReadResult:
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
        return await run_in_threadpool(
            read_team, state, request.headers.get("Authorization", ""), handoff, request.state.correlation_id,
        )

    return server
