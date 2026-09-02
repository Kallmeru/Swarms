"""The decision function. One place, one answer, one reason.

Every privileged call in the system arrives here and leaves with a `Decision`
that says allow, deny, or needs-a-human, plus the evidence behind it. The
rules are fixed; the actions they apply to come from the operator's policy.

    1. Known action.    An action the policy does not declare is denied.
    2. Known principal. A principal the policy does not declare holds nothing.
    3. Authority.       The principal must hold the action's capability, and
                        the run's ceiling must still allow it.
    4. Grounding.       Every control argument must trace to trusted data.
    5. Approval.        Actions marked require_approval need a human, even
                        when 1-4 pass.

Rule 4 is the one that earns its keep. An email whose *body* quotes an
untrusted document is ordinary work and is allowed. An email whose
*recipient* came from that document is the attack and is refused. A defense
that blocked both would have a perfect containment rate and no users.

No model call, no classifier, no pattern list. A dictionary lookup and a
label comparison, so the answer does not depend on how the attack was worded
and cannot be argued with.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from swarms import capability as capability_module
from swarms.capability import Capability
from swarms.config import ActionSpec, Policy
from swarms.taint import TaintLabel, TaintedValue


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class Rule(str, Enum):
    UNKNOWN_ACTION = "unknown_action"
    UNKNOWN_PRINCIPAL = "unknown_principal"
    CAPABILITY = "capability"
    RUN_AUTHORITY = "run_authority"
    GROUNDING = "grounding"
    APPROVAL = "approval"
    OBSERVE_ONLY = "observe_only"
    PERMITTED = "permitted"


@dataclass(frozen=True)
class Decision:
    effect: Effect
    rule: Rule
    reason: str
    action: str
    principal: str = ""
    offending_arg: str | None = None
    offending_span: str | None = None
    offending_provenance: tuple[str, ...] = ()
    arg_labels: dict[str, str] = field(default_factory=dict)
    enforced: bool = True

    @property
    def allowed(self) -> bool:
        """True when the call may proceed. Observe-only mode reports the
        decision it would have made and still returns True, which is what
        makes it safe to run against real traffic."""
        return self.effect is Effect.ALLOW or not self.enforced

    @property
    def needs_approval(self) -> bool:
        return self.effect is Effect.REQUIRE_APPROVAL and self.enforced

    def to_dict(self) -> dict:
        return {
            "effect": self.effect.value,
            "rule": self.rule.value,
            "reason": self.reason,
            "action": self.action,
            "principal": self.principal,
            "allowed": self.allowed,
            "enforced": self.enforced,
            "offending_arg": self.offending_arg,
            "offending_span": self.offending_span,
            "offending_provenance": list(self.offending_provenance),
            "arg_labels": dict(self.arg_labels),
        }


class PolicyDenied(PermissionError):
    """Raised by the SDK when a guarded call is refused. Carries the decision
    so a caller can log or surface the reason rather than a bare failure."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(decision.reason)


class ApprovalRequired(PolicyDenied):
    """Raised when a call is otherwise permitted but the policy wants a human.
    `approval_id` is the handle to resolve it with."""

    def __init__(self, decision: Decision, approval_id: str):
        self.approval_id = approval_id
        super().__init__(decision)


# ---------------------------------------------------------------------------
# Taint inspection
# ---------------------------------------------------------------------------

def is_untrusted(value: Any) -> bool:
    """Whether a value carries untrusted taint anywhere inside it.

    Recurses, because arguments are rarely flat: a recipient list, a dict of
    headers, a list of attachment records. A top-level-only check passes
    `to=[ok@corp, attacker@evil]` straight through.
    """
    if isinstance(value, TaintedValue):
        return value.label is TaintLabel.UNTRUSTED
    if isinstance(value, dict):
        return any(is_untrusted(v) for v in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(is_untrusted(v) for v in value)
    return False


def first_untrusted(value: Any) -> TaintedValue | None:
    """The specific tainted value behind a denial, so the audit record can
    quote it instead of saying "something in here was untrusted"."""
    if isinstance(value, TaintedValue):
        return value if value.label is TaintLabel.UNTRUSTED else None
    children: tuple = ()
    if isinstance(value, dict):
        children = tuple(value.values())
    elif isinstance(value, (list, tuple, set, frozenset)):
        children = tuple(value)
    for child in children:
        found = first_untrusted(child)
        if found is not None:
            return found
    return None


def label_of(value: Any) -> str:
    return "UNTRUSTED" if is_untrusted(value) else "TRUSTED"


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

def authorize(
    action: str,
    args: dict,
    principal: str,
    policy: Policy,
    held: Capability | None = None,
) -> Decision:
    """Decide one privileged call.

    `held` defaults to whatever the policy grants the principal. It is a
    parameter so a caller that has already attenuated authority (a gateway
    honoring a scoped token, say) can pass the narrowed set rather than have
    it silently widened back to the principal's full grant.
    """
    enforced = capability_module.enforcing()
    labels = {k: label_of(v) for k, v in args.items()}

    def decide(effect: Effect, rule: Rule, reason: str, **extra) -> Decision:
        return Decision(
            effect=effect, rule=rule, reason=reason, action=action, principal=principal,
            arg_labels=labels, enforced=enforced, **extra,
        )

    # 1. Known action.
    spec: ActionSpec | None = policy.action(action)
    if spec is None:
        if policy.unknown_action == "allow":
            return decide(Effect.ALLOW, Rule.UNKNOWN_ACTION,
                          f"action '{action}' is not in the policy; defaults.unknown_action is 'allow'")
        return decide(Effect.DENY, Rule.UNKNOWN_ACTION,
                      f"action '{action}' is not declared in policy '{policy.name}', denying by default. "
                      f"Add it under actions: if it should be callable.")

    # 2. Known principal.
    if not policy.knows_principal(principal) and policy.unknown_principal == "deny":
        return decide(Effect.DENY, Rule.UNKNOWN_PRINCIPAL,
                      f"principal '{principal}' is not declared in policy '{policy.name}', so it holds "
                      f"no capabilities")

    # 3. Authority.
    granted = held if held is not None else Capability.of(policy.capabilities_of(principal))
    if not granted.allows(spec.capability):
        return decide(Effect.DENY, Rule.CAPABILITY,
                      f"principal '{principal}' does not hold '{spec.capability}', which "
                      f"'{action}' requires")

    ceiling = capability_module.run_authority()
    if ceiling is not None and not ceiling.allows(spec.capability):
        return decide(Effect.DENY, Rule.RUN_AUTHORITY,
                      f"this run was not authorized for '{spec.capability}'; the request that started it "
                      f"never asked for '{action}'")

    # 4. Grounding.
    for arg in spec.control_args:
        if arg in args and is_untrusted(args[arg]):
            tainted = first_untrusted(args[arg])
            span = str(tainted.value) if tainted else str(args[arg])
            trail = tuple(tainted.provenance) if tainted and tainted.provenance else ("unknown origin",)
            return decide(
                Effect.DENY, Rule.GROUNDING,
                f"control argument '{arg}' of '{action}' traces to untrusted content "
                f"({' -> '.join(trail)}); content that was read cannot decide what a privileged "
                f"action targets",
                offending_arg=arg, offending_span=span, offending_provenance=trail,
            )

    # 5. Approval.
    if spec.require_approval:
        return decide(Effect.REQUIRE_APPROVAL, Rule.APPROVAL,
                      f"'{action}' is marked require_approval; a human has to confirm it")

    if not enforced:
        return decide(Effect.ALLOW, Rule.OBSERVE_ONLY,
                      "permitted (engine is in observe-only mode, nothing would have been blocked)")

    return decide(Effect.ALLOW, Rule.PERMITTED,
                  f"'{principal}' holds '{spec.capability}' and every control argument of '{action}' "
                  f"is grounded in trusted provenance")


def explain(action: str, args: dict, principal: str, policy: Policy) -> dict:
    """Decision plus the context behind it, for the console and the API. Runs
    the same code path as authorize(), so what is displayed is what was
    enforced."""
    decision = authorize(action, args, principal, policy)
    spec = policy.action(action)
    return {
        **decision.to_dict(),
        "control_args": list(spec.control_args) if spec else [],
        "data_args": list(spec.data_args) if spec else [],
        "required_capability": spec.capability if spec else None,
        "principal_capabilities": sorted(policy.capabilities_of(principal)),
        "policy": policy.name,
    }
