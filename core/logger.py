import os
import json
import time
import uuid


# ---------------------------------------------------------
# Create a unique run_id for every execution of the program
# ---------------------------------------------------------
RUN_ID = str(uuid.uuid4())
RUN_DIR = os.path.join("runs", RUN_ID)
os.makedirs(RUN_DIR, exist_ok=True)

EVENT_FILE = os.path.join(RUN_DIR, "events.jsonl")


def _ts():
    return time.time()


def log_event(event_type: str, data: dict):
    """Generic event logger used by all core components."""
    event = {
        "timestamp": _ts(),
        "type": event_type,
        "data": data
    }

    # Terminal output
    print(json.dumps(event))

    # Write to events.jsonl
    with open(EVENT_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


# ---------------------------------------------------------
# WIRE-FORMAT EVENT NAMES (Fix #3)
# ---------------------------------------------------------

def log_boundary(from_agent: str, to_agent: str, value):
    """Logs taint + provenance when crossing agent boundaries."""
    log_event("AGENT_HANDOFF", {
        "from": from_agent,
        "to": to_agent,
        "value_label": value.label.value,
        "provenance": value.provenance
    })


def log_capability_drop(from_agent: str, to_agent: str, old_cap, new_cap):
    """Logs capability attenuation at boundaries."""
    log_event("CAPABILITY_DROP", {
        "from": from_agent,
        "to": to_agent,
        "old": old_cap.to_dict(),
        "new": new_cap.to_dict()
    })


def log_blocked_action(agent: str, action: str, args=None):
    """Logs when a privileged action is blocked."""
    log_event("ACTION_BLOCKED", {
        "agent": agent,
        "action": action,
        "args": args
    })


def log_allowed_action(agent: str, action: str):
    """Logs when a privileged action is allowed."""
    log_event("ACTION_ALLOWED", {
        "agent": agent,
        "action": action
    })
