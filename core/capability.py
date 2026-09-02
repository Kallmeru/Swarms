"""Capability model: what an agent is allowed to do, and how that shrinks.

Authority in this system is granted by the human, once, and only ever gets
smaller. It is never carried by data, never inferred from what a document
asks for, and never restored. Two consequences worth stating plainly:

  * An agent cannot gain an authority by being handed data that requests it.
    That is the escalation path a poisoned document tries to walk.
  * A run declares up front which actions the human's task authorizes. An
    agent that holds `send_email` in general still cannot send during a task
    that was only authorized to summarize.

Run state (shield mode and run authority) lives in `contextvars`, not module
globals. That is not a style preference: the API server runs many pipelines
at once, and a module global would let one request's shield setting leak into
another's, silently disabling the defense under load.
"""
from __future__ import annotations

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterable, Iterator

# action name -> the Capability field that authorizes it. Adding an action
# means adding a line here and a control-argument spec in policy.py; an
# action in neither is denied, which is the correct default for a new verb
# nobody has thought about yet.
ACTION_FIELDS: dict[str, str] = {
    "send_email": "can_email",
    "execute": "can_execute",
    "write_file": "can_write_file",
}


@dataclass(frozen=True)
class Capability:
    """An immutable set of granted actions.

    Frozen because attenuation must produce a new value rather than mutate a
    shared one: two agents holding the same Capability object, where one
    handoff mutates it, is a defense that silently stops applying.
    """

    can_email: bool = False
    can_execute: bool = False
    can_write_file: bool = False

    # -- set-like view -------------------------------------------------------

    @property
    def granted(self) -> frozenset[str]:
        return frozenset(a for a, f in ACTION_FIELDS.items() if getattr(self, f))

    @classmethod
    def of(cls, actions: Iterable[str]) -> "Capability":
        actions = set(actions)
        unknown = actions - set(ACTION_FIELDS)
        if unknown:
            raise ValueError(f"unknown action(s): {sorted(unknown)}")
        return cls(**{f: (a in actions) for a, f in ACTION_FIELDS.items()})

    @classmethod
    def all(cls) -> "Capability":
        return cls.of(ACTION_FIELDS)

    @classmethod
    def none(cls) -> "Capability":
        return cls()

    def allows(self, action: str) -> bool:
        """Unknown actions are denied. Fail closed."""
        field = ACTION_FIELDS.get(action)
        return bool(field) and getattr(self, field)

    def intersect(self, other: "Capability") -> "Capability":
        return Capability.of(self.granted & other.granted)

    def to_dict(self) -> dict:
        return {f: getattr(self, f) for f in ACTION_FIELDS.values()}

    def __str__(self) -> str:
        return "{" + ", ".join(sorted(self.granted)) + "}" if self.granted else "{}"


NOTHING = Capability.none()

# ---------------------------------------------------------------------------
# Per-run state. contextvars, so concurrent runs in one process (the API
# server) cannot see or clobber each other's settings.
# ---------------------------------------------------------------------------

_shield: contextvars.ContextVar[bool] = contextvars.ContextVar("swarms_shield", default=True)
_authority: contextvars.ContextVar[Capability] = contextvars.ContextVar(
    "swarms_run_authority", default=Capability.all()
)


def shield_enabled() -> bool:
    """True when enforcement is on. False is the unprotected baseline the
    benchmark measures against, not a production mode."""
    return _shield.get()


def set_shield_enabled(value: bool) -> None:
    _shield.set(bool(value))


def run_authority() -> Capability:
    """Actions the human's task authorizes for this run. Defaults to all, so
    code that never declares an authority behaves as before."""
    return _authority.get()


def set_run_authority(cap: Capability) -> None:
    _authority.set(cap)


@contextmanager
def run_policy(shield: bool = True, authority: Capability | None = None) -> Iterator[None]:
    """Scope shield mode and run authority to a block, restoring both after.

    Use this rather than the setters wherever a run can be nested or
    concurrent: the tokens make the restore exact even if the body raises.
    """
    tokens = [_shield.set(bool(shield))]
    if authority is not None:
        tokens.append(_authority.set(authority))
    try:
        yield
    finally:
        for var, token in zip((_shield, _authority), tokens):
            var.reset(token)


def attenuate(cap: Capability) -> Capability:
    """Capability as it survives a trust boundary.

    Shield on: the receiver keeps only what it was granted *and* what this
    run's task authorizes. Monotonically shrinking, so no sequence of
    handoffs can hand an agent an authority nobody gave it.

    Shield off: unchanged. That is the vulnerable baseline, where authority
    rides along with the data and a document that asks for email gets it.
    """
    if not shield_enabled():
        return cap
    return cap.intersect(run_authority())


def drop_capability(cap: Capability) -> Capability:
    """Total attenuation: strip everything. Kept as the explicit name for
    boundaries that should delegate no authority at all (an agent handing
    off to a fully untrusted third party)."""
    return cap if not shield_enabled() else NOTHING
