import json
import time

def _ts():
    return time.time()

def log_event(event_type: str, data: dict):
    """Generic event logger used by all core components."""
    event = {
        "timestamp": _ts(),
        "type": event_type,
        "data": data
    }
    print(json.dumps(event))

def log_boundary(from_agent: str, to_agent: str, value):
    """Logs taint + provenance when crossing agent boundaries."""
    log_event("boundary_cross", {
        "from": from_agent,
        "to": to_agent,
        "value_label": value.label.value,
        "provenance": value.provenance
    })

def log_capability_drop(from_agent: str, to_agent: str, old_cap, new_cap):
    """Logs capability attenuation at boundaries."""
    log_event("capability_drop", {
        "from": from_agent,
        "to": to_agent,
        "old": old_cap.to_dict(),
        "new": new_cap.to_dict()
    })

def log_blocked_action(agent: str, action: str, args=None):
    """Logs when a privileged action is blocked."""
    log_event("privileged_action_blocked", {
        "agent": agent,
        "action": action,
        "args": args
    })

def log_allowed_action(agent: str, action: str):
    """Logs when a privileged action is allowed."""
    log_event("privileged_action_allowed", {
        "agent": agent,
        "action": action
    })
