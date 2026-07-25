class Capability:
    def __init__(self, can_email=False, can_execute=False, can_write_file=False):
        self.can_email = can_email
        self.can_execute = can_execute
        self.can_write_file = can_write_file


def drop_capability(cap: Capability) -> Capability:
    """
    Pure function: attenuate capability at an agent boundary.
    For now, we drop all privileged actions.
    """
    return Capability(
        can_email=False,
        can_execute=False,
        can_write_file=False,
    )
