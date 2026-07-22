from core.taint import TaintedValue, TaintLabel
from core.capability import Capability


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
    for key, value in args.items():
        if isinstance(value, TaintedValue):
            if value.label == TaintLabel.UNTRUSTED:
                return False

    # If all checks pass → allow
    return True
