from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.audit.store import AuditRecord, ChainResult, Decision, EventType
from app.identity.lifecycle import LifecycleError
from app.identity.lifecycle_models import (
    Agent,
    Registration,
    Review,
    ReviewDecision,
    ReviewRequest,
    Rotation,
    State,
    StateChange,
)
from app.identity.tokens import InvalidToken, KeycloakUnavailable, User

router = APIRouter(prefix="/admin", tags=["identity governance"])
Limit = Annotated[int, Query(ge=1, le=100)]


def administrator(request: Request) -> User:
    state = request.app.state
    correlation = request.state.correlation_id
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    try:
        if scheme.lower() != "bearer" or not token:
            raise InvalidToken
        user, _ = state.verifier.access_human(token)
    except InvalidToken:
        state.storage.audit("human_auth", "governance", "failure", "invalid_admin_bearer", correlation)
        raise HTTPException(401, "Human bearer authentication required", {"WWW-Authenticate": "Bearer"}) from None
    except KeycloakUnavailable:
        state.storage.audit("human_auth", "governance", "failure", "identity_provider_unavailable", correlation)
        raise HTTPException(503, "Identity provider unavailable") from None
    if "gateway_admin" not in user.realm_roles:
        state.storage.audit("human_auth", "governance", "deny", "admin_role_required", correlation, actor=user.subject)
        raise HTTPException(403, "Administrator role required")
    if request.method != "GET":
        state.storage.audit("human_auth", "governance", "success", "admin_authenticated", correlation,
                            actor=user.subject)
    return user


Admin = Annotated[User, Depends(administrator)]


@router.post("/agents", status_code=201)
def register(body: Registration, request: Request, admin: Admin) -> Agent:
    if body.client_id == request.app.state.settings.keycloak_client_id:
        raise LifecycleError(422, "human_client_cannot_be_registered")
    return request.app.state.lifecycle.register(body, admin.subject, request.state.correlation_id)


@router.get("/agents")
def list_agents(request: Request, admin: Admin, limit: Limit = 50, after: str = "") -> list[Agent]:
    return request.app.state.lifecycle.list_agents(limit, after)


@router.get("/agents/{agent_id}")
def agent_details(agent_id: str, request: Request, admin: Admin) -> Agent:
    return request.app.state.lifecycle.details(agent_id)


@router.post("/agents/{agent_id}/state/{target}")
def change_state(agent_id: str, target: State, body: StateChange, request: Request, admin: Admin) -> Agent:
    return request.app.state.lifecycle.transition(
        agent_id, target, body.reason, admin.subject, request.state.correlation_id,
    )


@router.post("/agents/{agent_id}/rotations", status_code=202)
def request_rotation(agent_id: str, request: Request, admin: Admin) -> Rotation:
    return request.app.state.lifecycle.request_rotation(agent_id, admin.subject, request.state.correlation_id)


@router.post("/agents/{agent_id}/rotations/{rotation_id}/apply")
def apply_rotation(agent_id: str, rotation_id: str, request: Request, admin: Admin) -> Rotation:
    return request.app.state.lifecycle.apply_rotation(agent_id, rotation_id, admin.subject, request.state.correlation_id)


@router.post("/agents/{agent_id}/provider-revocation")
def revoke_provider(agent_id: str, request: Request, admin: Admin) -> Agent:
    return request.app.state.lifecycle.revoke_provider(agent_id, admin.subject, request.state.correlation_id)


@router.post("/agents/{agent_id}/reviews", status_code=201)
def create_review(agent_id: str, body: ReviewRequest, request: Request, admin: Admin) -> Review:
    return request.app.state.lifecycle.create_review(agent_id, body.proposed, admin.subject, request.state.correlation_id)


@router.get("/agents/{agent_id}/reviews")
def list_reviews(agent_id: str, request: Request, admin: Admin, limit: Limit = 50, after: str = "") -> list[Review]:
    return request.app.state.lifecycle.reviews(agent_id, limit, after)


@router.post("/agents/{agent_id}/reviews/{review_id}/decision")
def decide_review(agent_id: str, review_id: str, body: ReviewDecision, request: Request, admin: Admin) -> Review:
    return request.app.state.lifecycle.decide_review(
        agent_id, review_id, body, admin.subject, request.state.correlation_id,
    )


@router.get("/audit")
def audit_events(
    request: Request, admin: Admin, limit: Limit = 50, after: Annotated[int, Query(ge=0)] = 0,
    event_type: EventType | None = None, agent: str | None = None, decision: Decision | None = None,
) -> list[AuditRecord]:
    return request.app.state.storage.events(limit, after, event_type, agent, decision)


@router.get("/audit/integrity")
def audit_integrity(request: Request, admin: Admin) -> ChainResult:
    return request.app.state.storage.verify()
