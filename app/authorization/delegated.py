import json
from time import time

import httpx

from app.identity.delegation import DelegatedIdentity
from app.identity.lifecycle_models import Agent
from config.settings import Settings

DECISION_PATH = "/v1/data/agent_gateway/authorization/decision"
MAX_DECISION_BYTES = 4096


class PolicyDenied(ValueError):
    pass


class PolicyUnavailable(RuntimeError):
    pass


def unique_object(items: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(items)
    if len(result) != len(items):
        raise ValueError("Duplicate policy response key")
    return result


class OPAAuthorizer:
    def __init__(self, http: httpx.Client, settings: Settings) -> None:
        self.http = http
        self.settings = settings

    def authorize_team_read(self, identity: DelegatedIdentity, agent: Agent) -> None:
        if time() >= identity.expires_at:
            raise PolicyDenied
        # Identity has already passed JWT, subject and actor binding checks.
        policy_input = {
            "human": {"subject": identity.subject.subject, "roles": list(identity.subject.realm_roles)},
            "actor": {
                "subject": identity.actor.subject,
                "roles": list(identity.actor.realm_roles),
                "client_id": identity.actor_client,
            },
            "delegation": {
                "audience": identity.audience,
                "expires_at": identity.expires_at,
                "scopes": sorted(identity.granted_scopes),
            },
            "request": {"tool": "read_hr_team", "resource": {"type": "hr_team", "id": "demo-team"}},
            "governance": {
                "status": agent.status.value,
                "client_id": agent.client_id,
                "assigned": {key: sorted(value) for key, value in agent.assigned.model_dump().items()},
                "approved": {key: sorted(value) for key, value in agent.approved.model_dump().items()},
            },
            "context": {
                "expected_audience": self.settings.keycloak_api_audience,
                "allowed_agent_client": self.settings.keycloak_hr_agent_client_id,
            },
        }
        try:
            with self.http.stream(
                "POST", f"{self.settings.opa_url}{DECISION_PATH}", json={"input": policy_input},
                follow_redirects=False, headers={"Accept-Encoding": "identity"},
            ) as response:
                if response.status_code != 200:
                    raise PolicyUnavailable
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise PolicyUnavailable
                body = bytearray()
                for chunk in response.iter_bytes():
                    if len(body) + len(chunk) > MAX_DECISION_BYTES:
                        raise PolicyUnavailable
                    body.extend(chunk)
            payload = json.loads(body, object_pairs_hook=unique_object)
        except (httpx.HTTPError, ValueError, RecursionError):
            raise PolicyUnavailable from None
        if not isinstance(payload, dict) or set(payload) != {"result"}:
            raise PolicyUnavailable
        result = payload["result"]
        if not isinstance(result, dict) or set(result) != {"allow"} or type(result["allow"]) is not bool:
            raise PolicyUnavailable
        if not result["allow"] or time() >= identity.expires_at:
            raise PolicyDenied
