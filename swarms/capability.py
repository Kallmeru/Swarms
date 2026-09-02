"""Capability model: what a principal may do, and how that shrinks.

Authority is granted by the operator's policy, once, and only ever gets
smaller. It is never carried by data, never inferred from what a document
asks for, and never restored.

Capabilities are dotted names (`email.send`, `payments.charge`, `db.read`)
rather than a fixed set of flags, because the actions worth guarding differ
per deployment and a product cannot ship the list. Grants may use wildcards
(`email.*`); requirements never do.

Run state lives in `contextvars`. That is not a style preference: the gateway
serves many pipelines at once, and a module global would let one request's
enforcement settings leak into another's, silently disabling the defense
under exactly the load where it matters.
"""
from __future__ import annotations

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Iterable, Iterator


@dataclass(frozen=True)
class Capability:
    """An immutable set of granted capability names.

    Frozen because attenuation has to produce a new value rather than mutate
    a shared one: two principals holding the same object, where one boundary
    crossing mutates it, is a defense that silently stops applying.
    """

    grants: frozenset[str] = frozenset()

    @classmethod
    def of(cls, names: Iterable[str] | None = None) -> "Capability":
        return cls(frozenset(names or ()))

    @classmethod
    def none(cls) -> "Capability":
        return cls(frozenset())

    def allows(self, required: str) -> bool:
        """Whether this set covers a required capability.

        `fnmatchcase`, not `fnmatch`: the latter lowercases patterns on
        Windows, and a capability check whose result depends on the host
        operating system is not a check.
        """
        if not required:
            return False
        return any(g == required or fnmatchcase(required, g) for g in self.grants)

    def intersect(self, other: "Capability") -> "Capability":
        """Attenuation. Wildcards on either side are resolved by keeping only
        grants the other side also covers, so `email.*` ∩ `email.send` is
        `email.send` rather than the empty set."""
        kept = {g for g in self.grants if other.allows(g)}
        kept |= {g for g in other.grants if self.allows(g)}
        return Capability(frozenset(kept))

    def __or__(self, other: "Capability") -> "Capability":
        return Capability(self.grants | other.grants)

    def __bool__(self) -> bool:
        return bool(self.grants)

    def to_list(self) -> list[str]:
        return sorted(self.grants)

    def __str__(self) -> str:
        return "{" + ", ".join(sorted(self.grants)) + "}"


NOTHING = Capability.none()

# ---------------------------------------------------------------------------
# Per-run state.
# ---------------------------------------------------------------------------

_enforcing: contextvars.ContextVar[bool] = contextvars.ContextVar("swarms_enforcing", default=True)
_authority: contextvars.ContextVar[Capability | None] = contextvars.ContextVar("swarms_authority", default=None)


def enforcing() -> bool:
    """False puts the engine in observe-only mode: decisions are still
    computed and recorded, nothing is blocked. That exists so a team can
    measure what a policy *would* have done against real traffic before
    turning it on, which is the only responsible way to deploy one."""
    return _enforcing.get()


def set_enforcing(value: bool) -> None:
    _enforcing.set(bool(value))


def run_authority() -> Capability | None:
    """The ceiling for this run, set from the caller's request rather than
    the policy: a task that only asked for a summary should not be able to
    send mail even if the principal generally may. None means no additional
    ceiling beyond what the principal holds."""
    return _authority.get()


def set_run_authority(cap: Capability | None) -> None:
    _authority.set(cap)


@contextmanager
def run_policy(enforce: bool = True, authority: Capability | None = None) -> Iterator[None]:
    """Scope enforcement mode and run authority, restoring both on exit even
    if the body raises."""
    tokens = [(_enforcing, _enforcing.set(bool(enforce))), (_authority, _authority.set(authority))]
    try:
        yield
    finally:
        for var, token in reversed(tokens):
            var.reset(token)


def attenuate(held: Capability) -> Capability:
    """Authority as it survives a trust boundary: what the principal holds,
    narrowed to what this run was authorized to do. Monotonically shrinking,
    so no sequence of handoffs ends with more authority than was granted."""
    ceiling = run_authority()
    return held if ceiling is None else held.intersect(ceiling)
