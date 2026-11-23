import pytest
import z3

from verification.delegation_invariants import DelegationModel


def test_authorized_delegation_has_a_witness():
    model = DelegationModel()
    solver = z3.Solver()
    solver.add(model.allowed(), model.subject == 1, model.caller_actor == 2)
    solver.add(model.subject_permissions == 3, model.actor_permissions == 1, model.delegated_permissions == 1)
    assert solver.check() == z3.sat


@pytest.mark.parametrize("violation", [
    lambda m: m.delegated_permissions & ~m.subject_permissions != 0,
    lambda m: m.delegated_audience != m.api_audience,
    lambda m: m.delegated_permissions & m.tool_permission == 0,
    lambda m: m.delegated_subject != m.subject,
    lambda m: m.caller_actor != m.allowed_actor,
    lambda m: m.delegated_actor != m.caller_actor,
    lambda m: z3.Not(m.actor_authorized),
    lambda m: m.delegated_permissions & ~m.actor_permissions != 0,
    lambda m: z3.Not(m.unexpired),
    lambda m: z3.Not(m.actor_signature_valid),
    lambda m: z3.Not(m.subject_signature_valid),
    lambda m: z3.Not(m.delegated_signature_valid),
    lambda m: m.caller_actor == m.subject,
    lambda m: z3.Not(m.actor_has_hr_agent),
    lambda m: z3.Not(m.subject_has_hr_manager),
    lambda m: z3.Not(m.delegated_subject_has_hr_manager),
    lambda m: z3.Not(m.tool_is_hr_team_read),
    lambda m: z3.Not(m.resource_is_demo_team),
    lambda m: z3.Not(m.policy_response_valid),
    lambda m: z3.Not(m.policy_allows),
])
def test_delegation_invariants(violation):
    model = DelegationModel()
    solver = z3.Solver()
    solver.add(model.allowed(), violation(model))
    assert solver.check() == z3.unsat
