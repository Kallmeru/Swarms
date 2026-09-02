"""SWARMS — policy enforcement for AI agent tool calls.

Agents read things. Some of what they read is written by someone who wants
them to act on it. SWARMS is the layer that decides whether a tool call is
allowed to happen, based on where its arguments came from rather than on how
they are phrased.

    from swarms import Guard

    guard = Guard.from_file("swarms.yaml")

    @guard.tool("send_email", principal="agent3_emailer")
    def send_email(to, subject, body): ...

    with guard.session_scope("agent3_emailer", user="alice") as s:
        page = s.ingest(fetch(url), source=f"web:{url}")
        to   = s.trust("boss@corp.example")
        send_email(to=to, subject="Summary", body=page, session=s)

The enforcement path is a dictionary lookup and a label comparison. No model
call, no classifier, no pattern list, so a decision costs microseconds and
does not depend on recognizing an attack.
"""
from swarms.capability import Capability, attenuate, enforcing, run_policy
from swarms.config import ActionSpec, Policy, PolicyError, Principal
from swarms.guard import Guard, Session
from swarms.policy import (
    ApprovalRequired,
    Decision,
    Effect,
    PolicyDenied,
    Rule,
    authorize,
    explain,
)
from swarms.store import AuditStore
from swarms.taint import TaintedValue, TaintLabel

__version__ = "2.0.0"

__all__ = [
    "ActionSpec", "ApprovalRequired", "AuditStore", "Capability", "Decision",
    "Effect", "Guard", "Policy", "PolicyDenied", "PolicyError", "Principal",
    "Rule", "Session", "TaintLabel", "TaintedValue", "attenuate", "authorize",
    "enforcing", "explain", "run_policy", "__version__",
]
