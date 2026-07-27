import os
import json
import time
import uuid

# These are set per attack, not at import time
RUN_ID = None
RUN_DIR = None
EVENT_FILE = None


def init_run():
    """Call once per attack/demo to initialize a fresh run."""
    global RUN_ID, RUN_DIR, EVENT_FILE
    RUN_ID = str(uuid.uuid4())
    RUN_DIR = os.path.join("runs", RUN_ID)
    os.makedirs(RUN_DIR, exist_ok=True)
    EVENT_FILE = os.path.join(RUN_DIR, "events.jsonl")


def _ts():
    return time.time()


def log_event(event_type: str, data: dict, agent: str = None):
    """Generic event logger used by all core components."""
    event = {
        "event_id": str(uuid.uuid4()),
        "run_id": RUN_ID,
        "timestamp": _ts(),
        "type": event_type,
        "agent": agent,
        "data": data
    }

    print(json.dumps(event))

    with open(EVENT_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


def log_boundary(from_agent: str, to_agent: str, value):
    log_event(
        "AGENT_HANDOFF",
        {
            "from": from_agent,
            "to": to_agent,
            "value_label": value.label.value,
            "provenance": value.provenance
        },
        agent=from_agent
    )


def log_capability_drop(from_agent: str, to_agent: str, old_cap, new_cap):
    log_event(
        "CAPABILITY_DROP",
        {
            "from": from_agent,
            "to": to_agent,
            "old": old_cap.to_dict(),
            "new": new_cap.to_dict()
        },
        agent=from_agent
    )


def log_blocked_action(agent: str, action: str, args=None):
    log_event(
        "ACTION_BLOCKED",
        {
            "action": action,
            "args": args
        },
        agent=agent
    )


def log_allowed_action(agent: str, action: str):
    log_event(
        "ACTION_ALLOWED",
        {
            "action": action
        },
        agent=agent
    )
