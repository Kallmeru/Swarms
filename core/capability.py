# -----------------------------------------
# Global shield toggle
# When True  → capability attenuation ON
# When False → capability attenuation OFF
# -----------------------------------------
SHIELD_ENABLED = True


class Capability:
    def __init__(self, can_email=False, can_execute=False, can_write_file=False):
        self.can_email = can_email
        self.can_execute = can_execute
        self.can_write_file = can_write_file

    def to_dict(self):
        """Serialize capability for logging/UI."""
        return {
            "can_email": self.can_email,
            "can_execute": self.can_execute,
            "can_write_file": self.can_write_file,
        }


def set_shield_enabled(value: bool) -> None:
    """Flip the global shield toggle. Call this before a run rather than
    setting the module attribute directly, so there's one obvious place
    this happens (needed to run 60 attacks x on/off in one process without
    each callsite reaching into another module's internals)."""
    global SHIELD_ENABLED
    SHIELD_ENABLED = value


def drop_capability(cap: Capability) -> Capability:
    """
    Capability attenuation at agent boundaries.
    - If SHIELD_ENABLED is True → drop all privileged capabilities.
    - If SHIELD_ENABLED is False → keep original capability (worm succeeds).
    """

    # NEW: shield OFF → do NOT drop capability
    if not SHIELD_ENABLED:
        return cap

    # Shield ON → drop everything (original behavior)
    return Capability(
        can_email=False,
        can_execute=False,
        can_write_file=False,
    )
