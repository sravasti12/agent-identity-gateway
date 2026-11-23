from fastapi import APIRouter, HTTPException, Request

from app.identity.agent_tokens import AgentCredentialsRejected, AgentTokenService, InvalidAgentTokenResponse
from app.identity.tokens import InvalidToken, KeycloakUnavailable, TokenVerifier, User, WrongAgentIdentity


router = APIRouter(prefix="/agent", tags=["agent"])


@router.get("/me")
def agent_me(request: Request) -> User:
    unauthorized = HTTPException(401, "Agent bearer authentication required", {"WWW-Authenticate": "Bearer"})
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise unauthorized

    service: AgentTokenService = request.app.state.agent_tokens
    verifier: TokenVerifier = request.app.state.verifier
    if service.client_id is None:
        raise HTTPException(503, "Agent authentication unavailable")

    try:
        caller, _ = verifier.access_agent(token, service.client_id)
        issued = service.get_token()
    except InvalidToken:
        raise unauthorized from None
    except WrongAgentIdentity:
        raise HTTPException(403, "Agent identity required") from None
    except KeycloakUnavailable:
        raise HTTPException(503, "Identity provider unavailable") from None
    except (AgentCredentialsRejected, InvalidAgentTokenResponse):
        raise HTTPException(502, "Agent token acquisition failed") from None

    if caller.subject != issued.identity.subject:
        raise HTTPException(403, "Agent identity required")
    return issued.identity
