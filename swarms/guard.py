"""The developer-facing API.

    from swarms import Guard

    guard = Guard.from_file("swarms.yaml")

    @guard.tool("send_email", principal="mailer")
    def send_email(to: str, subject: str, body: str) -> None:
        smtp.send(to, subject, body)

    with guard.session(user="alice") as s:
        page = s.ingest(requests.get(url).text, source=f"web:{url}")
        to   = s.trust("boss@corp.example", source="user_request")
        send_email(to=to, subject="Summary", body=page)   # checked, then run

Two calls carry the whole contract. `ingest()` marks everything that came
from outside the trust boundary. `trust()` marks what the human actually
asked for. Everything else is inferred.

**Recovering provenance from model output.** In a real agent the model does
not hand back labeled objects, it hands back JSON: `{"to": "a@b.com"}`. So
`Session.tool_call()` classifies each value by asking where that text could
have come from. If it appears in ingested content, it is untrusted, and the
audit record names the source it appeared in. If it exactly matches something
the human trusted, it is trusted. If it is neither, it is untrusted, because
a recipient that appears in no document and in no request is not a value
anybody chose. That path is fail-closed on purpose and separately from the
decorator path, where an argument the developer's own code constructed is
trusted by construction.
"""
from __future__ import annotations

import functools
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from swarms.capability import Capability, run_policy
from swarms.config import Policy
from swarms.policy import (
    ApprovalRequired,
    Decision,
    Effect,
    PolicyDenied,
    authorize,
    explain,
)
from swarms.store import AuditStore
from swarms.taint import TaintedValue, TaintLabel

# Characters that exist in payloads only to break naive matching. Stripped
# from both sides before comparison, so "atta​cker@evil" in a document
# still matches "attacker@evil" coming back from the model.
_ZERO_WIDTH = dict.fromkeys((0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF))


def _normalize(text: str) -> str:
    return " ".join(text.translate(_ZERO_WIDTH).lower().split())


@dataclass
class IngestedSource:
    """One piece of content that entered the session from outside."""

    source: str
    text: str
    normalized: str = field(default="", repr=False)
    ingested_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self.normalized = _normalize(self.text)


class Session:
    """One unit of agent work, and the trust context around it.

    A session is cheap and short-lived: one user request, one pipeline run,
    one conversation turn. Its whole job is to remember what came from
    outside and what the human asked for, so a decision later can tell them
    apart.
    """

    def __init__(
        self,
        guard: "Guard",
        principal: str,
        session_id: str | None = None,
        user: str = "",
        authority: Capability | None = None,
        metadata: dict | None = None,
    ):
        self.guard = guard
        self.principal = principal
        self.id = session_id or uuid.uuid4().hex
        self.user = user
        self.authority = authority
        self.metadata = dict(metadata or {})
        self.sources: list[IngestedSource] = []
        self._trusted: dict[str, str] = {}   # normalized value -> source
        self.decisions: list[Decision] = []

    # -- marking data --------------------------------------------------------

    def ingest(self, text: str, source: str) -> TaintedValue:
        """Register content that came from outside and get it back labeled.

        Call this on every tool result, retrieved document, web page, email
        body, and message from another agent. It is the load-bearing call:
        content that is never ingested cannot be recognized later, so an
        un-instrumented source is a hole in the model, exactly as it is in
        any other taint system.
        """
        if not isinstance(text, str):
            text = str(text)
        self.sources.append(IngestedSource(source=source, text=text))
        return TaintedValue.untrusted(text, f"ingest:{source}")

    def trust(self, value: Any, source: str = "user_request") -> TaintedValue:
        """Mark a value the human actually supplied.

        Explicit trust wins over appearing in untrusted content: if the user
        said "send it to boss@corp.example" and a poisoned document happens
        to mention the same address, the user's request is still what
        authorized it.
        """
        text = value if isinstance(value, str) else str(value)
        self._trusted[_normalize(text)] = source
        return TaintedValue.trusted(value, source)

    # -- recovering provenance ----------------------------------------------

    def classify(self, value: Any, *, unlabeled: str | None = None) -> TaintedValue:
        """Label a raw value by working out where it could have come from.

        `unlabeled` decides the verdict for a value that matches nothing:
        "untrusted" for anything a model produced, "trusted" for a value the
        developer's own code constructed. Callers pass it explicitly rather
        than sharing one default, because those two cases genuinely differ.
        """
        if isinstance(value, TaintedValue):
            return value
        if isinstance(value, dict):
            return TaintedValue(
                {k: self.classify(v, unlabeled=unlabeled) for k, v in value.items()},
                self._container_label(value.values(), unlabeled),
                ["container"],
            )
        if isinstance(value, (list, tuple)):
            return TaintedValue(
                [self.classify(v, unlabeled=unlabeled) for v in value],
                self._container_label(value, unlabeled),
                ["container"],
            )

        fallback = unlabeled or self.guard.policy.unlabeled_value
        text = value if isinstance(value, str) else str(value)
        needle = _normalize(text)

        if not needle:
            return TaintedValue(value, TaintLabel.TRUSTED, ["empty"])

        # 1. The human named it.
        if needle in self._trusted:
            return TaintedValue(value, TaintLabel.TRUSTED, [f"user:{self._trusted[needle]}"])

        # 2. It appears in something we read. Short values are excluded
        #    because a two-character match against a page of prose is a
        #    coincidence, not provenance.
        if len(needle) >= self.guard.policy.min_match_length:
            for src in self.sources:
                if needle in src.normalized:
                    return TaintedValue(value, TaintLabel.UNTRUSTED, [f"ingest:{src.source}"])

        # 3. Nothing accounts for it.
        label = TaintLabel.TRUSTED if fallback == "trusted" else TaintLabel.UNTRUSTED
        return TaintedValue(value, label, ["unattributed"])

    def _container_label(self, values, unlabeled: str | None) -> TaintLabel:
        return (TaintLabel.UNTRUSTED
                if any(self.classify(v, unlabeled=unlabeled).is_untrusted for v in values)
                else TaintLabel.TRUSTED)

    # -- decisions -----------------------------------------------------------

    def check(self, action: str, args: dict, *, unlabeled: str | None = None) -> Decision:
        """Decide a call without performing it. Records to the audit log."""
        labeled = {k: self.classify(v, unlabeled=unlabeled) for k, v in args.items()}
        started = time.perf_counter()
        with run_policy(enforce=self.guard.enforcing, authority=self.authority):
            decision = authorize(action, labeled, self.principal, self.guard.policy)
        latency_us = int((time.perf_counter() - started) * 1_000_000)

        self.decisions.append(decision)
        self.guard._record(decision, self.id, latency_us, {
            "policy": self.guard.policy.name, "user": self.user, **self.metadata,
        })
        return decision

    def call(self, action: str, fn: Callable, /, *, approval_id: str | None = None, **args) -> Any:
        """Authorize, then perform. The tool is not looked up until the
        decision is made, so a denied call has no window in which the side
        effect has started and the check has not finished."""
        decision = self.check(action, args)
        plain = _unwrap(args)

        if decision.needs_approval:
            if approval_id is None:
                approval = self.guard.store.open_approval(
                    self.id, self.principal, action, plain, decision.reason)
                raise ApprovalRequired(decision, approval.id)
            # Spending the approval is the check: it succeeds only for this
            # action, with these argument values, exactly once.
            spent, why = self.guard.store.consume_approval(approval_id, action, plain)
            if not spent:
                raise PolicyDenied(_with_reason(decision, f"approval rejected: {why}"))
        elif not decision.allowed:
            raise PolicyDenied(decision)

        return fn(**plain)

    def tool_call(self, name: str, arguments: dict, *, approval_id: str | None = None) -> Decision:
        """Decide a tool call emitted by a model.

        Fail-closed: an argument that matches neither ingested content nor
        anything the human trusted is treated as untrusted, because a value
        that appears in no document and in no request is not one anybody
        chose.
        """
        return self.check(name, arguments, unlabeled="untrusted")

    def explain(self, action: str, args: dict) -> dict:
        with run_policy(enforce=self.guard.enforcing, authority=self.authority):
            return explain(action, {k: self.classify(v) for k, v in args.items()},
                           self.principal, self.guard.policy)

    def to_dict(self) -> dict:
        return {
            "session_id": self.id, "principal": self.principal, "user": self.user,
            "sources": [{"source": s.source, "chars": len(s.text)} for s in self.sources],
            "trusted_values": len(self._trusted),
            "decisions": len(self.decisions),
        }


class Guard:
    """Holds the policy and the audit store, and hands out sessions."""

    def __init__(
        self,
        policy: Policy | None = None,
        store: AuditStore | None = None,
        enforce: bool = True,
    ):
        self.policy = policy or Policy.discover()
        self.store = store if store is not None else AuditStore(_default_db_path())
        # False is observe-only: decisions are computed and recorded, nothing
        # is blocked. Deploy that way first, read the audit log, then enforce.
        self.enforcing = enforce

    # -- construction --------------------------------------------------------

    @classmethod
    def from_file(cls, path: str, db: str | None = None, enforce: bool = True) -> "Guard":
        return cls(Policy.load(path), AuditStore(db or _default_db_path()), enforce=enforce)

    @classmethod
    def from_dict(cls, raw: dict, db: str | None = None, enforce: bool = True) -> "Guard":
        return cls(Policy.from_dict(raw), AuditStore(db or _default_db_path()), enforce=enforce)

    # -- sessions ------------------------------------------------------------

    def session(
        self,
        principal: str = "",
        user: str = "",
        authority: list[str] | Capability | None = None,
        session_id: str | None = None,
        **metadata,
    ) -> Session:
        """A session for one unit of work.

        `authority` is the ceiling this particular request asked for. A task
        that only asked for a summary passes `[]`, and no amount of injected
        text can make it send mail, even if the principal generally may.
        """
        if isinstance(authority, list):
            authority = Capability.of(authority)
        return Session(self, principal or _sole_principal(self.policy), session_id,
                       user=user, authority=authority, metadata=metadata)

    @contextmanager
    def session_scope(self, principal: str = "", **kwargs) -> Iterator[Session]:
        session = self.session(principal, **kwargs)
        try:
            yield session
        finally:
            pass  # sessions hold no external resources; the audit log is already durable

    # -- decorators ----------------------------------------------------------

    def tool(self, action: str, principal: str | None = None) -> Callable:
        """Wrap a function so every call is decided first.

        The wrapped function takes an optional `session=` keyword. Without
        one it gets a fresh single-use session, which means no ingested
        content and therefore nothing to trace against, so use that only for
        tools that never see model-derived arguments.
        """
        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args, session: Session | None = None, approval_id: str | None = None, **kwargs):
                if args:
                    raise TypeError(
                        f"{fn.__name__}() guarded by swarms must be called with keyword arguments: "
                        "the policy names control arguments by name, and positional values cannot "
                        "be matched to them."
                    )
                active = session or self.session(principal or fn.__name__)
                return active.call(action, fn, approval_id=approval_id, **kwargs)
            wrapper.__swarms_action__ = action  # type: ignore[attr-defined]
            return wrapper
        return decorator

    # -- approvals -----------------------------------------------------------

    def approve(self, approval_id: str, by: str, note: str = ""):
        return self.store.resolve_approval(approval_id, True, by, note)

    def deny(self, approval_id: str, by: str, note: str = ""):
        return self.store.resolve_approval(approval_id, False, by, note)

    # -- misc ----------------------------------------------------------------

    def _record(self, decision: Decision, session_id: str, latency_us: int, metadata: dict) -> None:
        try:
            self.store.record(decision, session_id, latency_us, metadata)
        except Exception:  # pragma: no cover - audit must never break the call path
            # A failing audit write must not turn an allowed action into an
            # exception in the caller's application. It is logged and dropped;
            # the decision itself already happened.
            import logging
            logging.getLogger("swarms").exception("audit write failed for %s", decision.action)

    def reload(self, path: str | None = None) -> Policy:
        """Re-read the policy from disk. Returns the new policy, or raises and
        leaves the old one in place: a bad edit must not disarm the gateway."""
        source = path or self.policy.source_path
        if not source:
            raise ValueError("this policy was not loaded from a file, nothing to reload")
        self.policy = Policy.load(source)
        return self.policy


def _with_reason(decision: Decision, reason: str) -> Decision:
    """A copy of a decision carrying a more specific reason. Decisions are
    frozen so the recorded one and the raised one cannot drift apart."""
    from dataclasses import replace
    return replace(decision, effect=Effect.DENY, reason=reason)


def _unwrap(value: Any) -> Any:
    """Strip labels before handing arguments to the real tool. Recurses,
    because arguments nest and a top-level-only unwrap leaves TaintedValue
    objects that a tool cannot use and json cannot serialize."""
    if isinstance(value, TaintedValue):
        return _unwrap(value.value)
    if isinstance(value, dict):
        return {k: _unwrap(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_unwrap(v) for v in value]
    return value


def _sole_principal(policy: Policy) -> str:
    """If the policy declares exactly one principal, use it rather than making
    every call site repeat the name."""
    if len(policy.principals) == 1:
        return next(iter(policy.principals))
    return "unknown"


def _default_db_path() -> str:
    import os
    return os.environ.get("SWARMS_DB", "swarms.db")
