def log_taint_propagation(a, b, result):
    log_event("taint_propagation", {
        "a_label": a.label.value,
        "b_label": b.label.value,
        "result_label": result.label.value,
        "a_provenance": a.provenance,
        "b_provenance": b.provenance,
        "result_provenance": result.provenance
    })


def log_capability_drop(agent_from, agent_to, old_cap, new_cap):
    log_event("capability_drop", {
        "from": agent_from,
        "to": agent_to,
        "old_capability": {
            "can_email": old_cap.can_email,
            "can_execute": old_cap.can_execute,
            "can_write_file": old_cap.can_write_file
        },
        "new_capability": {
            "can_email": new_cap.can_email,
            "can_execute": new_cap.can_execute,
            "can_write_file": new_cap.can_write_file
        }
    })


def log_boundary(agent_from, agent_to, value):
    log_event("boundary_cross", {
        "from": agent_from,
        "to": agent_to,
        "value_label": value.label.value,
        "provenance": value.provenance
    })


def log_blocked_action(agent, action, args):
    log_event("privileged_action_blocked", {
        "agent": agent,
        "action": action,
        "args": {k: getattr(v, "value", v) for k, v in args.items()}
    })


def log_allowed_action(agent, action):
    log_event("privileged_action_allowed", {
        "agent": agent,
        "action": action
    })
