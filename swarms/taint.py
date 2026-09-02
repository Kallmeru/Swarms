"""Taint model: every value that moves through the swarm carries a label.

`TRUSTED` means the value traces back to the human operator's own task.
`UNTRUSTED` means it traces, however indirectly, to content the system read
from the outside world. The label is attached at the boundary where data
enters and it only ever travels in one direction: anything derived from an
untrusted value is itself untrusted. There is no sanitizer, no classifier,
and no way for content to talk its way back up to TRUSTED, which is the
whole point, that path is exactly what prompt injection attacks.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Iterable, Sequence


class TaintLabel(Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"

    @property
    def wire(self) -> str:
        """Uppercase form used in the event log and by the frontend."""
        return self.value.upper()


class TaintedValue:
    """A value plus its trust label and the provenance chain that earned it.

    Provenance is kept because a block is only useful if it can say *why*:
    "this recipient came from tool:read_document, not from your task" is an
    actionable message, "blocked" is not.
    """

    __slots__ = ("value", "label", "provenance")

    def __init__(self, value: Any, label: TaintLabel, provenance: Sequence[str] | None = None):
        if not isinstance(label, TaintLabel):
            raise TypeError(f"label must be a TaintLabel, got {type(label).__name__}")
        self.value = value
        self.label = label
        self.provenance = list(provenance or [])

    # -- construction helpers ------------------------------------------------

    @classmethod
    def trusted(cls, value: Any, origin: str = "user_task") -> "TaintedValue":
        return cls(value, TaintLabel.TRUSTED, [origin])

    @classmethod
    def untrusted(cls, value: Any, origin: str) -> "TaintedValue":
        return cls(value, TaintLabel.UNTRUSTED, [origin])

    def derive(self, value: Any, tag: str) -> "TaintedValue":
        """A new value computed from this one. Keeps the label, extends the
        chain. This is the single operation agents should use, so that
        propagation is a property of the type rather than of every caller
        remembering to do it."""
        return TaintedValue(value, self.label, self.provenance + [tag])

    # -- predicates ----------------------------------------------------------

    @property
    def is_trusted(self) -> bool:
        return self.label is TaintLabel.TRUSTED

    @property
    def is_untrusted(self) -> bool:
        return self.label is TaintLabel.UNTRUSTED

    def stamp(self, tag: str) -> "TaintedValue":
        """Append a provenance tag in place. Returns self so it chains."""
        self.provenance.append(tag)
        return self

    def to_dict(self) -> dict:
        return {"value": self.value, "label": self.label.value, "provenance": list(self.provenance)}

    def __repr__(self) -> str:
        preview = str(self.value)
        if len(preview) > 60:
            preview = preview[:57] + "..."
        return f"<TaintedValue {self.label.value} {preview!r} via {'->'.join(self.provenance) or 'unknown'}>"


# ---------------------------------------------------------------------------
# Pure propagation functions. Deterministic, no I/O, no model call. This is
# the entire "cost" of the defense on the hot path.
# ---------------------------------------------------------------------------

def propagate_label(*labels: TaintLabel) -> TaintLabel:
    """Join on the trust lattice: one untrusted input taints the result.

    Variadic because real derivations combine more than two inputs (a draft
    built from a task, a summary and a template); folding pairwise in every
    caller is how a label gets dropped by accident.
    """
    return TaintLabel.UNTRUSTED if any(l is TaintLabel.UNTRUSTED for l in labels) else TaintLabel.TRUSTED


def combine_provenance(*chains: Iterable[str]) -> list[str]:
    """Merge provenance chains, preserving order and dropping repeats, so a
    value that passed through the same tool twice does not read as two
    separate origins."""
    seen: dict[str, None] = {}
    for chain in chains:
        for tag in chain:
            seen.setdefault(tag, None)
    return list(seen)


def combine(*values: TaintedValue, joiner: str = "") -> TaintedValue:
    """Merge N tainted values into one. The result is untrusted if any input
    was, which is the rule that makes "summarize the poisoned doc into a
    clean-looking report" not launder the taint."""
    if not values:
        raise ValueError("combine() needs at least one value")
    return TaintedValue(
        joiner.join(str(v.value) for v in values),
        propagate_label(*(v.label for v in values)),
        combine_provenance(*(v.provenance for v in values)),
    )


def combine_values(a: TaintedValue, b: TaintedValue) -> TaintedValue:
    """Two-argument form of combine(), kept because it is the name the rest
    of the project and the integration doc already use."""
    return combine(a, b)


def wrap_raw(value: Any, agent_name: str) -> TaintedValue:
    """Wrap an agent's plain (unlabeled) return value.

    Fails closed: anything an agent hands back without a label is treated as
    untrusted. An agent that wants to assert trust has to say so explicitly.
    """
    return TaintedValue.untrusted(value, f"output_of:{agent_name}")


def label_of(value: Any) -> TaintLabel:
    """Label of any value, labeled or not. Bare Python values are trusted:
    they are literals from our own code, not content from outside."""
    return value.label if isinstance(value, TaintedValue) else TaintLabel.TRUSTED
