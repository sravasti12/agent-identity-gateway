from dataclasses import dataclass

import z3  # type: ignore[import-untyped]


@dataclass(frozen=True)
class DelegationModel:
    """A finite abstraction of one gateway authorization decision."""

    actor_authorized = z3.Bool("actor_authorized")
    subject_signature_valid = z3.Bool("subject_signature_valid")
    actor_signature_valid = z3.Bool("actor_signature_valid")
    delegated_signature_valid = z3.Bool("delegated_signature_valid")
    subject_has_hr_manager = z3.Bool("subject_has_hr_manager")
    delegated_subject_has_hr_manager = z3.Bool("delegated_subject_has_hr_manager")
    actor_has_hr_agent = z3.Bool("actor_has_hr_agent")
    unexpired = z3.Bool("unexpired")
    subject = z3.Int("subject")
    delegated_subject = z3.Int("delegated_subject")
    allowed_actor = z3.Int("allowed_actor")
    caller_actor = z3.Int("caller_actor")
    delegated_actor = z3.Int("delegated_actor")
    api_audience = z3.Int("api_audience")
    delegated_audience = z3.Int("delegated_audience")
    subject_permissions = z3.BitVec("subject_permissions", 4)
    actor_permissions = z3.BitVec("actor_permissions", 4)
    delegated_permissions = z3.BitVec("delegated_permissions", 4)
    tool_permission = z3.BitVecVal(1, 4)

    def allowed(self):
        return z3.And(
            self.actor_authorized,
            self.subject_signature_valid,
            self.actor_signature_valid,
            self.delegated_signature_valid,
            self.subject_has_hr_manager,
            self.delegated_subject_has_hr_manager,
            self.actor_has_hr_agent,
            self.actor_permissions == z3.If(self.actor_has_hr_agent, self.tool_permission, z3.BitVecVal(0, 4)),
            self.unexpired,
            self.delegated_subject == self.subject,
            self.caller_actor == self.allowed_actor,
            self.delegated_actor == self.caller_actor,
            self.caller_actor != self.subject,
            self.delegated_audience == self.api_audience,
            self.delegated_permissions & ~self.subject_permissions == 0,
            self.delegated_permissions & ~self.actor_permissions == 0,
            self.delegated_permissions & self.tool_permission == self.tool_permission,
        )
