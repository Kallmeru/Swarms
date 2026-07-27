import os
import json
import time
import uuid


# ---------------------------------------------------------
# Per-run event log. set_current_run() must be called before running any
# agent for a given attack + shield mode, so that each attack's events end
# up in their own file instead of all runs sharing one file for the whole
# process (which is what happens if the run id is only picked once, at
# import time).
# ---------------------------------------------------------
_state = {"run_id": None}


def set_current_run(run_id: str = None) -> str:
    """Start a fresh run. If run_id is omitted, generates one. Clears any
    prior log for this run_id, so re-running the same attack doesn't
    silently append onto a previous run's events."""
    run_id = run_id or str(uuid.uuid4())
    _state["run_id"] = run_id
    run_dir = os.path.join("runs", run_id)
    os.makedirs(run_dir, exist_ok=True)
    open(os.path.join(run_dir, "events.jsonl"), "w").close()
    return run_id


def _current_run_id() -> str:
    # falls back to auto-starting a run rather than raising, so anything
    # that forgets to call set_current_run() still works, just without the
    # per-attack separation that benchmark/run_benchmark.py relies on
    if _state["run_id"] is None:
        set_current_run()
    return _state["run_id"]


def log_event(event_type: str, data: dict):
    """Generic event logger used by all core components. Writes one JSON
    line to runs/<run_id>/events.jsonl, this is the file
    benchmark/run_benchmark.py and the frontend both read. `agent` is
    hoisted to the top level of the event (not just inside `data`), the
    frontend matches on evt.agent directly."""
    run_id = _current_run_id()
    event = {
        "timestamp": time.time(),
        "run_id": run_id,
        "type": event_type,
        "agent": data.get("agent"),
        "data": data,
    }

    # Terminal output
    print(json.dumps(event))

    # Write to events.jsonl
    event_file = os.path.join("runs", run_id, "events.jsonl")
    with open(event_file, "a") as f:
        f.write(json.dumps(event) + "\n")


# ---------------------------------------------------------
# Kept for anything that still calls these directly. runtime.py no longer
# does (it calls log_event with the wire-format type and fields itself),
# but these still work standalone if something else needs them.
# ---------------------------------------------------------

def log_boundary(from_agent: str, to_agent: str, value):
    """Logs taint + provenance when crossing agent boundaries."""
    log_event("AGENT_HANDOFF", {
        "agent": from_agent,
        "to": to_agent,
        "data_label": value.label.value.upper(),
        "provenance": value.provenance,
    })


def log_capability_drop(from_agent: str, to_agent: str, old_cap, new_cap):
    """Logs capability attenuation at boundaries."""
    log_event("CAPABILITY_DROP", {
        "agent": from_agent,
        "to": to_agent,
        "old": old_cap.to_dict(),
        "new": new_cap.to_dict(),
    })


def log_blocked_action(agent: str, action: str, reason: str = None, offending_arg=None, offending_span=None):
    """Logs when a privileged action is blocked."""
    log_event("ACTION_BLOCKED", {
        "agent": agent,
        "action": action,
        "reason": reason,
        "offending_arg": offending_arg,
        "offending_span": offending_span,
    })


def log_allowed_action(agent: str, action: str, reason: str = None):
    """Logs when a privileged action is allowed."""
    log_event("ACTION_ALLOWED", {
        "agent": agent,
        "action": action,
        "reason": reason,
    })
