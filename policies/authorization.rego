package agent_gateway.authorization

import rego.v1

default allow := false

decision := {"allow": allow}

allowed_scopes := {"hr_team_read", "openid", "profile", "email"}
registry_catalog := {
    "roles": ["hr_agent"],
    "tools": ["read_hr_team"],
    "resources": ["hr_team/demo-team"],
    "scopes": ["hr_team_read"],
}

within_approval(assigned, approved) if {
    every field in {"roles", "tools", "resources", "scopes"} {
        is_array(assigned[field])
        is_array(approved[field])
        every grant in assigned[field] {
            grant in approved[field]
        }
    }
}

allow if {
    is_string(input.human.subject)
    input.human.subject != ""
    is_string(input.actor.subject)
    input.actor.subject != ""
    input.human.subject != input.actor.subject
    is_array(input.human.roles)
    "hr_manager" in input.human.roles
    is_array(input.actor.roles)
    "hr_agent" in input.actor.roles
    is_string(input.context.allowed_agent_client)
    input.context.allowed_agent_client != ""
    input.actor.client_id == input.context.allowed_agent_client
    input.governance.status == "ACTIVE"
    input.governance.client_id == input.actor.client_id
    within_approval(input.governance.assigned, input.governance.approved)
    within_approval(input.governance.approved, registry_catalog)
    "hr_agent" in input.governance.assigned.roles
    "read_hr_team" in input.governance.assigned.tools
    "hr_team/demo-team" in input.governance.assigned.resources
    "hr_team_read" in input.governance.assigned.scopes

    input.request.tool == "read_hr_team"
    input.request.resource == {"type": "hr_team", "id": "demo-team"}
    is_string(input.context.expected_audience)
    input.context.expected_audience != ""
    input.delegation.audience == input.context.expected_audience
    is_array(input.delegation.scopes)
    "hr_team_read" in input.delegation.scopes
    every scope in input.delegation.scopes {
        scope in allowed_scopes
    }
    is_number(input.delegation.expires_at)
    input.delegation.expires_at * 1000000000 > time.now_ns()
}
