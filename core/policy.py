import core.capability as capability_module
from core.taint import TaintedValue, TaintLabel
from core.capability import Capability


def _is_untrusted(value) -> bool:
    """
    Recursively checks whether a value contains untrusted taint.
    Supports:
    - TaintedValue
    - dict
    - list/tuple
    - raw values (always trusted)
    """
    if isinstance(value, TaintedValue):
        return value.label == TaintLabel.UNTRUSTED

    if isinstance(value, dict):
        return any(_is_untrusted(v) for v in value.values())

    if isinstance(value, (list, tuple)):
        return any(_is_untrusted(v) for v in value)

    return False  # raw values are trusted unless wrapped


def _find_offending(args: dict):
    """Find the first top-level arg that carries untrusted taint, and its
    raw value, so the caller has something concrete to log/display.
    Returns (key, value) or (None, None)."""
    for key, value in args.items():
        if _is_untrusted(value):
            span = value.value if isinstance(value, TaintedValue) else value
            return key, span
    return None, None


def authorize(action: str, args: dict, capability: Capability):
    """
    Decides whether a privileged action is allowed.
    Returns (allowed, reason, offending_arg, offending_span), not just a
    bool, the last three are what the event log and the frontend need to
    explain *why* something was blocked.

    Reads capability_module.SHIELD_ENABLED live (not imported by name) so
    that toggling it between benchmark runs (core.capability.set_shield_enabled)
    actually takes effect here, an `from core.capability import SHIELD_ENABLED`
    would freeze the value at import time instead.
    """
    if not capability_module.SHIELD_ENABLED:
        return True, "shield disabled (baseline/demo mode)", None, None

    # 1. Capability check (does the agent have permission?)
    if action == "send_email" and not capability.can_email:
        return False, "agent lacks capability for 'send_email' (dropped at an earlier boundary)", None, None

    if action == "execute" and not capability.can_execute:
        return False, "agent lacks capability for 'execute' (dropped at an earlier boundary)", None, None

    if action == "write_file" and not capability.can_write_file:
        return False, "agent lacks capability for 'write_file' (dropped at an earlier boundary)", None, None

    # 2. Taint check (are control arguments trusted?)
    if _is_untrusted(args):
        offending_arg, offending_span = _find_offending(args)
        reason = (
            f"control argument '{offending_arg}' traces to untrusted content, "
            f"an instruction derived from untrusted content cannot authorize a privileged action"
        )
        return False, reason, offending_arg, offending_span

    # If all checks pass → allow
    return True, "all control arguments grounded in trusted provenance", None, None
