from fastapi import APIRouter, HTTPException, Request

from app.identity.agent_tokens import (
    AgentCredentialsRejected,
    AgentTokenService,
    InvalidAgentTokenResponse,
)
from app.identity.lifecycle import LifecycleError
from app.identity.tokens import (
    InvalidToken,
    KeycloakUnavailable,
    TokenVerifier,
    User,
    WrongAgentIdentity,
)

router = APIRouter(prefix="/agent", tags=["agent"])


@router.get("/me")
def agent_me(request: Request) -> User:
    audit = request.app.state.storage.audit
    correlation = request.state.correlation_id
    unauthorized = HTTPException(401, "Agent bearer authentication required", {"WWW-Authenticate": "Bearer"})
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        audit("agent_auth", "agent_diagnostic", "failure", "missing_bearer", correlation)
        raise unauthorized

    service: AgentTokenService = request.app.state.agent_tokens
    verifier: TokenVerifier = request.app.state.verifier
    if service.client_id is None:
        audit("agent_auth", "agent_diagnostic", "failure", "agent_not_configured", correlation)
        raise HTTPException(503, "Agent authentication unavailable")

    try:
        caller, claims = verifier.agent_identity(token, service.client_id)
        request.app.state.lifecycle.check_registered_bearer(service.client_id, claims.get("iat"))
        issued = service.get_token()
    except LifecycleError as error:
        audit("agent_auth", "agent_diagnostic", "deny", error.code, correlation,
              actor=caller.subject, agent=error.agent_id)
        raise
    except InvalidToken:
        audit("agent_auth", "agent_diagnostic", "failure", "invalid_token", correlation)
        raise unauthorized from None
    except WrongAgentIdentity:
        audit("agent_auth", "agent_diagnostic", "failure", "wrong_identity", correlation)
        raise HTTPException(403, "Agent identity required") from None
    except KeycloakUnavailable:
        audit("agent_auth", "agent_diagnostic", "failure", "identity_provider_unavailable", correlation)
        raise HTTPException(503, "Identity provider unavailable") from None
    except (AgentCredentialsRejected, InvalidAgentTokenResponse):
        audit("agent_auth", "agent_diagnostic", "failure", "provider_rejected", correlation)
        raise HTTPException(502, "Agent token acquisition failed") from None

    if caller.subject != issued.identity.subject:
        audit("agent_auth", "agent_diagnostic", "failure", "subject_mismatch", correlation, actor=caller.subject)
        raise HTTPException(403, "Agent identity required")
    audit("agent_auth", "agent_diagnostic", "success", "authenticated", correlation, actor=caller.subject)
    return issued.identity
