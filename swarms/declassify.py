"""Declassifiers: the sanctioned way an untrusted value may still be used.

Grounding refuses a control argument that traces to content the agent read.
That is correct and it is also, on its own, too strict to deploy. The case
that breaks it is ordinary: *reply to the customer who emailed us*. The
address genuinely comes from untrusted input, and refusing it forever does
not make the system secure, it makes it unused, and an unused control gets
switched off.

A declassifier is an operator-authored rule that says which untrusted values
are nonetheless acceptable *for a named argument of a named action*. The
decision to declassify comes from the policy file, never from the content, so
an attacker who controls the document still cannot widen what is allowed.

Two kinds, deliberately:

    allowlist   the value must be a member of a set the operator wrote down.
                Strong: the set is configuration, so an injected value can
                only get through by already being something you approved.

    pattern     the value must fully match a regular expression. Weaker, and
                honest about it: a pattern is only as good as its author. It
                exists because the real-world rule is usually "any address
                inside our own domain", which is a meaningful containment
                boundary (it stops exfiltration to an attacker's mailbox)
                even though it is not an exhaustive list.

Every declassification is recorded on the decision and in the audit trail, so
"why was this allowed" has an answer that names the rule that allowed it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


class DeclassifierError(ValueError):
    """A declassifier that cannot be built. Raised while loading policy."""


@dataclass(frozen=True)
class Declassifier:
    kind: str           # "allowlist" | "pattern"
    ref: str            # value-set name, or the pattern source
    _regex: re.Pattern | None = None

    def describe(self) -> str:
        return f"{self.kind}:{self.ref}"

    def permits(self, value: Any, value_sets: dict[str, frozenset[str]]) -> bool:
        text = value if isinstance(value, str) else str(value)

        if self.kind == "allowlist":
            members = value_sets.get(self.ref)
            if members is None:
                # A missing set denies rather than permits. A typo in a set
                # name must not silently turn into "allow anything".
                return False
            return text.strip().casefold() in members

        if self.kind == "pattern":
            # fullmatch, never search: `^...$` is easy to forget and a
            # partial match would let "attacker@evil.example?x=@corp.example"
            # satisfy a rule meant to pin the whole address.
            return bool(self._regex and self._regex.fullmatch(text.strip()))

        return False

    def to_dict(self) -> dict:
        return {"kind": self.kind, "ref": self.ref}

    @classmethod
    def from_spec(cls, raw: Any, *, where: str) -> "Declassifier":
        if not isinstance(raw, dict) or len(raw) != 1:
            raise DeclassifierError(
                f"{where}: each declassifier is a single-key mapping, "
                f"'allowlist: <set name>' or 'pattern: <regex>', got {raw!r}"
            )
        kind, ref = next(iter(raw.items()))
        if kind not in ("allowlist", "pattern"):
            raise DeclassifierError(f"{where}: unknown declassifier {kind!r}, expected 'allowlist' or 'pattern'")
        if not isinstance(ref, str) or not ref:
            raise DeclassifierError(f"{where}: {kind} needs a non-empty string value")

        compiled = None
        if kind == "pattern":
            try:
                compiled = re.compile(ref)
            except re.error as exc:
                raise DeclassifierError(f"{where}: invalid regular expression {ref!r}: {exc}") from exc
        return cls(kind=kind, ref=ref, _regex=compiled)


def normalize_value_sets(raw: Any) -> dict[str, frozenset[str]]:
    """Value sets from the policy file, case-folded once at load time.

    Folding here rather than per comparison means an operator writing
    `Boss@Corp.example` and a model emitting `boss@corp.example` agree,
    without every call site remembering to normalize.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise DeclassifierError("value_sets must be a mapping of name -> list of values")

    sets: dict[str, frozenset[str]] = {}
    for name, members in raw.items():
        if isinstance(members, str) or not hasattr(members, "__iter__"):
            raise DeclassifierError(f"value_sets.{name}: expected a list of values, got {members!r}")
        sets[name] = frozenset(str(m).strip().casefold() for m in members)
    return sets


def parse_declassify(raw: Any, *, action: str, control_args: tuple[str, ...]) -> dict[str, tuple[Declassifier, ...]]:
    """Parse an action's `declassify:` block into arg -> rules."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise DeclassifierError(f"action {action!r}: declassify must map an argument name to a list of rules")

    parsed: dict[str, tuple[Declassifier, ...]] = {}
    for arg, rules in raw.items():
        if arg not in control_args:
            # Declassifying a data argument is meaningless: data arguments
            # were never checked. Saying so loudly beats leaving the operator
            # believing a rule is doing something.
            raise DeclassifierError(
                f"action {action!r}: declassify names {arg!r}, which is not one of its control_args "
                f"{list(control_args)}. Only control arguments are ever refused, so only they can be "
                f"declassified."
            )
        if isinstance(rules, dict):
            rules = [rules]
        if not isinstance(rules, list) or not rules:
            raise DeclassifierError(f"action {action!r}: declassify.{arg} must be a non-empty list of rules")
        parsed[arg] = tuple(
            Declassifier.from_spec(r, where=f"action {action!r} declassify.{arg}") for r in rules
        )
    return parsed
