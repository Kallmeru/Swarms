"""Policy engine: the one place a privileged action is allowed or denied.

Two rules, checked in order, both deterministic and both pure code. No model
call, no classifier, no pattern list, nothing that an attacker can rephrase
their way around:

  1. **Authority.** The agent must hold the capability for this action, and
     the run's task must authorize it. Unknown actions are denied.
  2. **Grounding.** Every *control* argument of the action must be TRUSTED.
     A control argument is one that decides what the action does to the
     world: who an email goes to, which command runs, which path is written.

Rule 2 is the important half, and the split is what makes the system usable
rather than merely safe. An email whose *body* quotes an untrusted document
is normal work and is allowed. An email whose *recipient* came from that
document is the attack, and is refused. A defense that blocked both would
have a perfect containment rate and no users.
"""
from __future__ import annotations

from typing import Any, NamedTuple

from core import capability as capability_module
from core.capability import Capability
from core.taint import TaintedValue, TaintLabel

# action -> argument names that steer the action's effect on the world.
# Anything not listed is a data argument and may legitimately carry
# untrusted content.
#
# ponytail: control-argument grounding does not stop exfiltration *through*
# a data argument (untrusted body sent to a trusted recipient). Closing that
# needs a read-label on the destination as well, i.e. full information-flow
# control; documented in README under "Known limits".
CONTROL_ARGS: dict[str, tuple[str, ...]] = {
    "send_email": ("to", "cc", "bcc", "recipient", "attachments"),
    "execute": ("command", "argv", "cmd"),
    "write_file": ("path", "filename"),
}


class Decision(NamedTuple):
    """Unpacks as the 4-tuple the rest of the project already destructures,
    while giving new code readable attribute access."""

    allowed: bool
    reason: str
    offending_arg: str | None
    offending_span: str | None

    @property
    def rule(self) -> str:
        return "allow" if self.allowed else "deny"


def _is_untrusted(value: Any) -> bool:
    """Whether a value carries untrusted taint anywhere inside it.

    Recurses through containers because arguments are rarely flat: a
    `send_email` call takes `to` as a list, `attachments` as a list of dicts,
    and a check that only looked at the top level would miss every one of
    them.
    """
    if isinstance(value, TaintedValue):
        return value.label is TaintLabel.UNTRUSTED
    if isinstance(value, dict):
        return any(_is_untrusted(v) for v in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_is_untrusted(v) for v in value)
    return False  # a bare literal came from our own code, not the outside


def _first_untrusted(value: Any) -> TaintedValue | None:
    """The specific tainted value that caused a denial, so the event log can
    quote it instead of saying "something in here was untrusted"."""
    if isinstance(value, TaintedValue):
        return value if value.label is TaintLabel.UNTRUSTED else None
    children: tuple = ()
    if isinstance(value, dict):
        children = tuple(value.values())
    elif isinstance(value, (list, tuple, set, frozenset)):
        children = tuple(value)
    for child in children:
        found = _first_untrusted(child)
        if found is not None:
            return found
    return None


def control_args(action: str) -> tuple[str, ...]:
    return CONTROL_ARGS.get(action, ())


def authorize(action: str, args: dict, capability: Capability) -> Decision:
    """Decide a single privileged action.

    Reads the shield flag and run authority through the module rather than by
    value, so a run that changes them mid-process (the benchmark flips the
    shield between passes) is actually reflected here; a `from ... import
    SHIELD` would freeze the value at import time.
    """
    if not capability_module.shield_enabled():
        return Decision(True, "shield disabled (unprotected baseline)", None, None)

    # Rule 0: an action nobody has written a policy for is not allowed to
    # execute by default. New verbs arrive denied, not permitted.
    if action not in capability_module.ACTION_FIELDS:
        return Decision(False, f"unknown action '{action}': no policy defines it, denying by default", None, None)

    # Rule 1: authority. Held by the agent, and authorized for this task.
    if not capability.allows(action):
        return Decision(
            False,
            f"agent lacks capability for '{action}' (never granted, or attenuated at a trust boundary)",
            None,
            None,
        )
    if not capability_module.run_authority().allows(action):
        return Decision(
            False,
            f"this task does not authorize '{action}', the human's request never asked for it",
            None,
            None,
        )

    # Rule 2: grounding. Control arguments must trace to trusted data.
    for name in control_args(action):
        if name in args and _is_untrusted(args[name]):
            tainted = _first_untrusted(args[name])
            span = str(tainted.value) if tainted else str(args[name])
            trail = " -> ".join(tainted.provenance) if tainted and tainted.provenance else "unknown origin"
            return Decision(
                False,
                (
                    f"control argument '{name}' traces to untrusted content ({trail}); "
                    f"content that was read cannot decide who a privileged action targets"
                ),
                name,
                span,
            )

    return Decision(True, "all control arguments grounded in trusted provenance", None, None)


def explain(action: str, args: dict, capability: Capability) -> dict:
    """Decision plus the evidence behind it, for the API and the UI. Same
    code path as authorize(), so what gets displayed is what got enforced."""
    decision = authorize(action, args, capability)
    return {
        "action": action,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "offending_arg": decision.offending_arg,
        "offending_span": decision.offending_span,
        "shield": capability_module.shield_enabled(),
        "agent_capability": capability.to_dict(),
        "run_authority": capability_module.run_authority().to_dict(),
        "control_args": list(control_args(action)),
        "arg_labels": {
            k: ("UNTRUSTED" if _is_untrusted(v) else "TRUSTED") for k, v in args.items()
        },
    }
