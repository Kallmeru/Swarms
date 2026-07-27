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


def authorize(action: str, args: dict, capability: Capability):
    """
    Pure function: decides whether a privileged action is allowed.
    Returns a structured verdict object required by the frontend:
    {
        "allowed": bool,
        "reason": str or None,
        "offending_span": str or None
    }
    """

    # -----------------------------
    # 1. Capability check
    # -----------------------------
    if action == "send_email" and not capability.can_email:
        return {
            "allowed": False,
            "reason": "missing_capability",
            "offending_span": None,
        }

    if action == "execute" and not capability.can_execute:
        return {
            "allowed": False,
            "reason": "missing_capability",
            "offending_span": None,
        }

    if action == "write_file" and not capability.can_write_file:
        return {
            "allowed": False,
            "reason": "missing_capability",
            "offending_span": None,
        }

    # -----------------------------
    # 2. Taint check
    # -----------------------------
    if _is_untrusted(args):
        # Extract the actual tainted text for frontend display
        offending_span = None

        # Try to extract a meaningful string
        for v in args.values():
            if isinstance(v, TaintedValue):
                offending_span = v.value
                break

        # Fallback: stringify entire args
        if offending_span is None:
            offending_span = str(args)

        return {
            "allowed": False,
            "reason": "untrusted_input",
            "offending_span": offending_span,
        }

    # -----------------------------
    # All checks passed → allow
    # -----------------------------
    return {
        "allowed": True,
        "reason": None,
        "offending_span": None,
    }
