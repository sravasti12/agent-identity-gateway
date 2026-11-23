package agent_gateway.authorization_test

import rego.v1
import data.agent_gateway.authorization

valid_input := {
    "human": {"subject": "example-user", "roles": ["hr_manager"]},
    "actor": {"subject": "example-workload", "roles": ["hr_agent"], "client_id": "example-client"},
    "delegation": {"audience": "example-api", "expires_at": 200, "scopes": ["hr_team_read", "profile"]},
    "request": {"tool": "read_hr_team", "resource": {"type": "hr_team", "id": "demo-team"}},
    "governance": {
        "status": "ACTIVE",
        "client_id": "example-client",
        "assigned": authorization.registry_catalog,
        "approved": authorization.registry_catalog,
    },
    "context": {"expected_audience": "example-api", "allowed_agent_client": "example-client"},
}

test_allow_valid_delegate if {
    authorization.decision == {"allow": true} with input as valid_input with time.now_ns as 100000000000
}

test_deny_invalid_authorization_input[name] if {
    some name, change in {
        "human_role": {"op": "replace", "path": "/human/roles", "value": ["employee"]},
        "actor_role": {"op": "replace", "path": "/actor/roles", "value": ["hr_manager"]},
        "actor_client": {"op": "replace", "path": "/actor/client_id", "value": "unrelated"},
        "actor_subject": {"op": "replace", "path": "/actor/subject", "value": "example-user"},
        "missing_subject": {"op": "remove", "path": "/human/subject"},
        "tool": {"op": "replace", "path": "/request/tool", "value": "write_hr_team"},
        "resource": {"op": "replace", "path": "/request/resource/id", "value": "other-team"},
        "audience": {"op": "replace", "path": "/delegation/audience", "value": "unrelated"},
        "scope": {"op": "replace", "path": "/delegation/scopes", "value": ["profile"]},
        "extra_scope": {"op": "add", "path": "/delegation/scopes/-", "value": "hr_team_write"},
        "expiry": {"op": "replace", "path": "/delegation/expires_at", "value": 100},
        "expiry_type": {"op": "replace", "path": "/delegation/expires_at", "value": "200"},
        "pending_agent": {"op": "replace", "path": "/governance/status", "value": "PENDING"},
        "suspended_agent": {"op": "replace", "path": "/governance/status", "value": "SUSPENDED"},
        "deprovisioned_agent": {"op": "replace", "path": "/governance/status", "value": "DEPROVISIONED"},
        "unbound_registry": {"op": "replace", "path": "/governance/client_id", "value": "other-client"},
        "assignment_drift": {"op": "add", "path": "/governance/assigned/scopes/-", "value": "hr_team_write"},
        "unapproved_resource": {"op": "replace", "path": "/governance/approved/resources", "value": []},
        "unknown_registry": {"op": "remove", "path": "/governance"},
    }
    invalid_input := json.patch(valid_input, [change])
    authorization.decision == {"allow": false} with input as invalid_input with time.now_ns as 100000000000
}

test_default_deny if {
    authorization.decision == {"allow": false} with input as {}
}

test_api_exposes_only_health_and_decisions if {
    data.system.authz.allow with input as {"method": "GET", "path": ["health"]}
    data.system.authz.allow with input as {
        "method": "POST", "path": ["v1", "data", "agent_gateway", "authorization", "decision"],
    }
    not data.system.authz.allow with input as {"method": "GET", "path": ["v1", "policies"]}
    not data.system.authz.allow with input as {"method": "PUT", "path": ["v1", "policies", "example"]}
    not data.system.authz.allow with input as {"method": "PUT", "path": ["v1", "data", "example"]}
}
