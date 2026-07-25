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


def authorize(action: str, args: dict, capability: Capability) -> bool:
    """
    Pure function: decides whether a privileged action is allowed.
    """

    # 1. Capability check (does the agent have permission?)
    if action == "send_email" and not capability.can_email:
        return False

    if action == "execute" and not capability.can_execute:
        return False

    if action == "write_file" and not capability.can_write_file:
        return False

    # 2. Taint check (are control arguments trusted?)
    if _is_untrusted(args):
        return False

    # If all checks pass → allow
    return True
