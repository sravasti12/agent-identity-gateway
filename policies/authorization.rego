package agent_gateway.authorization

import rego.v1

default allow := false

decision := {"allow": allow}

allowed_scopes := {"hr_team_read", "openid", "profile", "email"}

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
