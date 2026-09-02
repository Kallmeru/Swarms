"""Structured event log: the single wire format core/ speaks to everything else.

One JSON object per event, in order, matching docs/swarms-integration-schema.md.
The benchmark reads it, the API returns it, the frontend animates it.

Run state is a `contextvars.ContextVar`, so several pipelines running at once
in one process (which is exactly what the API server does) each collect their
own events. With a module global, two concurrent requests interleave into one
list and both get a garbled trace.

Events are collected in memory by default and only written to
`runs/<run_id>/events.jsonl` when a run explicitly asks to persist. A server
that wrote a file per request would grow without bound for output nobody
reads.
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

log = logging.getLogger("swarms.events")

RUNS_ROOT = os.environ.get("SWARMS_RUNS_DIR", "runs")


@dataclass
class Run:
    run_id: str
    events: list[dict] = field(default_factory=list)
    path: str | None = None
    counter: int = 0


_run: contextvars.ContextVar[Run | None] = contextvars.ContextVar("swarms_run", default=None)


def _open_run(run_id: str | None, persist: bool, root: str) -> Run:
    run_id = run_id or str(uuid.uuid4())
    path = None
    if persist:
        run_dir = os.path.join(root, run_id)
        os.makedirs(run_dir, exist_ok=True)
        path = os.path.join(run_dir, "events.jsonl")
        # Truncate: re-running the same attack must replace its trace, not
        # append onto the previous one and double every count downstream.
        open(path, "w", encoding="utf-8").close()
    return Run(run_id=run_id, path=path)


@contextmanager
def run_context(run_id: str | None = None, persist: bool = False, root: str = RUNS_ROOT) -> Iterator[Run]:
    """Scope a run. Yields the Run, whose `.events` is the collected trace."""
    run = _open_run(run_id, persist, root)
    token = _run.set(run)
    try:
        yield run
    finally:
        _run.reset(token)


def set_current_run(run_id: str | None = None, persist: bool = True, root: str = RUNS_ROOT) -> str:
    """Non-scoped form, for scripts that run one pipeline start to finish
    (Demo.py, the CLI benchmark). Prefer run_context() anywhere that a run
    can be nested or concurrent."""
    run = _open_run(run_id, persist, root)
    _run.set(run)
    return run.run_id


def current_run() -> Run:
    """The active run, starting an unnamed in-memory one if nothing set it,
    so a stray log_event() call never raises in the middle of a request."""
    run = _run.get()
    if run is None:
        run = _open_run(None, persist=False, root=RUNS_ROOT)
        _run.set(run)
    return run


def current_events() -> list[dict]:
    return list(current_run().events)


def events_path() -> str | None:
    return current_run().path


def log_event(event_type: str, data: dict) -> dict:
    """Record one event. `agent` is hoisted out of `data` to the envelope
    because that is where every consumer looks for it."""
    run = current_run()
    run.counter += 1
    event = {
        "event_id": f"evt_{run.counter:04d}",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "run_id": run.run_id,
        "type": event_type,
        "agent": data.get("agent"),
        "data": data,
    }
    run.events.append(event)

    if run.path:
        with open(run.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")

    # Debug-level, not print(): a library that writes to stdout unasked
    # corrupts any caller that emits JSON or CSV on the same stream.
    if log.isEnabledFor(logging.DEBUG):
        log.debug("%s", json.dumps(event, default=str))
    return event


# ---------------------------------------------------------------------------
# Named helpers. Thin wrappers so call sites read as intent rather than as a
# string literal, and so the field names for each event type live in exactly
# one place.
# ---------------------------------------------------------------------------

def log_boundary(from_agent: str, to_agent: str, value: Any) -> dict:
    return log_event("AGENT_HANDOFF", {
        "agent": from_agent,
        "to": to_agent,
        "data_label": value.label.wire,
        "data_preview": str(value.value)[:200],
        "provenance": list(value.provenance),
    })


def log_capability_drop(agent: str, before, after) -> dict:
    return log_event("CAPABILITY_ATTENUATED", {
        "agent": agent,
        "before": before.to_dict(),
        "after": after.to_dict(),
        "removed": sorted(before.granted - after.granted),
    })


def log_blocked_action(agent: str, action: str, reason: str, offending_arg=None, offending_span=None) -> dict:
    return log_event("ACTION_BLOCKED", {
        "agent": agent, "action": action, "reason": reason,
        "offending_arg": offending_arg, "offending_span": offending_span,
    })


def log_allowed_action(agent: str, action: str, reason: str) -> dict:
    return log_event("ACTION_ALLOWED", {"agent": agent, "action": action, "reason": reason})
