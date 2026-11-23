from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

AgentKey = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")]
GrantName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_:/-]{1,100}$")]


class State(StrEnum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DEPROVISIONED = "DEPROVISIONED"


class Grants(BaseModel):
    model_config = ConfigDict(extra="forbid")

    roles: frozenset[GrantName] = Field(default_factory=frozenset, max_length=16)
    tools: frozenset[GrantName] = Field(default_factory=frozenset, max_length=16)
    resources: frozenset[GrantName] = Field(default_factory=frozenset, max_length=16)
    scopes: frozenset[GrantName] = Field(default_factory=frozenset, max_length=16)

    def within(self, upper: "Grants") -> bool:
        return (
            self.roles <= upper.roles and self.tools <= upper.tools
            and self.resources <= upper.resources and self.scopes <= upper.scopes
        )


HR_GRANTS = Grants(
    roles=frozenset({"hr_agent"}), tools=frozenset({"read_hr_team"}),
    resources=frozenset({"hr_team/demo-team"}), scopes=frozenset({"hr_team_read"}),
)


class Registration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: AgentKey
    client_id: AgentKey
    display_name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    approved: Grants = Field(default_factory=Grants)
    credential_expires_at: AwareDatetime | None = None


class Credential(BaseModel):
    version: str
    created_at: datetime
    rotated_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None


class Rotation(BaseModel):
    id: str
    requested_by: str
    requested_at: datetime
    state: Literal["PENDING", "RUNNING", "FAILED", "COMPLETED"] = "PENDING"
    finished_at: datetime | None = None


class Agent(BaseModel):
    id: str
    client_id: str
    display_name: str
    description: str
    status: State = State.PENDING
    assigned: Grants
    approved: Grants
    created_by: str
    created_at: datetime
    updated_at: datetime
    last_access_at: datetime | None = None
    last_review_at: datetime | None = None
    credential: Credential
    rotation: Rotation | None = None
    generation: int = 0
    state_reason: str = "registered"
    state_changed_by: str | None = None
    provider_revocation: Literal["NOT_REQUESTED", "PENDING", "RUNNING", "FAILED", "CONFIRMED"] = "NOT_REQUESTED"


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposed: Grants | None = None


class ReviewDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["APPROVED", "REJECTED"]


class StateChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: Literal["approved_onboarding", "security_review", "incident", "retired", "restored"]


class Review(BaseModel):
    id: str
    agent_id: str
    agent_generation: int
    created_at: datetime
    created_by: str
    assigned: Grants
    approved: Grants
    observed: Grants | None = None
    proposed: Grants | None = None
    findings: tuple[str, ...]
    recommendations: tuple[str, ...]
    decision: Literal["PENDING", "APPROVED", "REJECTED"] = "PENDING"
    reviewer: str | None = None
    decided_at: datetime | None = None
