"""The tools the swarm can actually call.

`send_email` writes to an in-process outbox and never opens an SMTP socket.
That is a safety property, not a shortcut: this repo runs attack payloads
whose entire goal is to get mail sent to an attacker-controlled address, and
a demo that could really send is one misconfigured environment variable away
from doing the attacker's work for them. The outbox is what the benchmark and
the UI read to prove an action executed.
"""
from __future__ import annotations

import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# Deliberately permissive rather than RFC-strict. An ASCII-only pattern
# silently skips internationalized domains, which means a homoglyph address
# would read as "no recipient found" and the attack would look contained when
# it simply was not seen. Over-matching here is safe: whatever is extracted
# still carries the untrusted label and still faces the policy engine.
EMAIL_RE = re.compile(r"[^\s<>@,;:\"'()\[\]{}]+@[^\s<>@,;:\"'()\[\]{}]+")
_TRAILING_PUNCT = ".,;:!?)]}>\"'-"
# Zero-width characters are stripped before matching: they exist in payloads
# purely to break naive parsing, and an address parser that falls for them
# under-reports the attack surface.
_ZERO_WIDTH = dict.fromkeys((0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF))

MAX_DOCUMENT_CHARS = 20_000


@dataclass
class SentEmail:
    to: str
    subject: str
    body: str
    sent_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    # Carried on the record itself, not just returned from send(), so anything
    # that reads the outbox later still sees that nothing left the process.
    delivered: bool = False


class Outbox:
    """Thread-safe because the API server runs pipelines concurrently and a
    plain list append plus read is not atomic across the two operations the
    benchmark does (send, then count)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sent: list[SentEmail] = []

    def send(self, to: str, subject: str = "", body: str = "") -> dict:
        mail = SentEmail(to=str(to), subject=str(subject), body=str(body))
        with self._lock:
            self._sent.append(mail)
        return {"recorded": True, **asdict(mail)}

    def all(self) -> list[dict]:
        with self._lock:
            return [asdict(m) for m in self._sent]

    def clear(self) -> None:
        with self._lock:
            self._sent.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._sent)


def make_tools(outbox: Outbox) -> dict:
    """Tool table handed to the emailer's AgentRuntime. Bound to a specific
    outbox so each run can assert on its own sends instead of sharing one
    global that every other test has already written to."""
    return {"send_email": outbox.send}


def read_document(text: str) -> str:
    """Ingest external content.

    Truncates rather than trusting the caller's length, because this is the
    system's outermost trust boundary: everything past this point is labeled
    UNTRUSTED, but an unbounded string still costs memory and model tokens
    before any labeling helps.
    """
    if not isinstance(text, str):
        raise TypeError("document must be text")
    return text[:MAX_DOCUMENT_CHARS]


def find_email_addresses(text: str) -> list[str]:
    """Every address appearing in a piece of content, first occurrence order.

    This is the naive extraction a real agent does when told "email the
    relevant party", and the exact behavior an injected document exploits.
    Keeping it honest and unfiltered is deliberate: SWARMS does not defend by
    being clever about which address looks suspicious, it defends by refusing
    to let an address that came from content steer a privileged action.
    """
    seen: dict[str, None] = {}
    for match in EMAIL_RE.findall((text or "").translate(_ZERO_WIDTH)):
        addr = match.rstrip(_TRAILING_PUNCT)
        local, _, domain = addr.partition("@")
        if local and "." in domain:
            seen.setdefault(addr, None)
    return list(seen)
