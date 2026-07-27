from core.taint import TaintedValue, TaintLabel
from core.capability import Capability, drop_capability
from core.policy import authorize
from core.logger import (
    log_event,
    log_boundary,
    log_capability_drop,
    log_blocked_action,
    log_allowed_action,
)

# ---------------------------------------------------------
# Global shield toggle (ON = containment, OFF = worm escapes)
# ---------------------------------------------------------
SHIELD_ON = True

# ---------------------------------------------------------
# Map internal agent names → frontend agent IDs
# ---------------------------------------------------------
AGENT_NAME_MAP = {
    "Reader": "agent1_reader",
    "Analyst": "agent2_analyst",
    "Emailer": "agent3_emailer",
}


class AgentRuntime:
    def __init__(self, agent_fn, capability: Capability, agent_name: str):
        self.agent_fn = agent_fn
        self.capability = capability
        self.agent_name = AGENT_NAME_MAP[agent_name]

    def run(self, input_value: TaintedValue) -> TaintedValue:
        log_event("AGENT_START", {"agent": self.agent_name}, agent=self.agent_name)

        output = self.agent_fn(input_value)

        if not isinstance(output, TaintedValue):
            output = TaintedValue(
                value=output,
                label=TaintLabel.UNTRUSTED,
                provenance=[f"output_of:{self.agent_name}"],
            )

        log_event(
            "AGENT_END",
            {
                "agent": self.agent_name,
                "output_label": output.label.value,
            },
            agent=self.agent_name,
        )

        return output

    def handoff(self, next_runtime, value: TaintedValue) -> TaintedValue:
        log_boundary(self.agent_name, next_runtime.agent_name, value)

        old_cap = next_runtime.capability

        # ---------------------------------------------------------
        # SHIELD LOGIC: Only drop capability when SHIELD_ON = True
        # ---------------------------------------------------------
        if SHIELD_ON:
            new_cap = drop_capability(next_runtime.capability)

            log_capability_drop(
                self.agent_name,
                next_runtime.agent_name,
                old_cap,
                new_cap
            )

            next_runtime.capability = new_cap

        # If SHIELD_OFF → no capability drop
        return next_runtime.run(value)

    def privileged_action(self, action: str, args: dict):
        verdict = authorize(action, args, self.capability)

        normalized_args = {
            k: getattr(v, "value", v) for k, v in args.items()
        }

        if not verdict["allowed"]:
            log_blocked_action(
                agent=self.agent_name,
                action=action,
                args={
                    "normalized_args": normalized_args,
                    "reason": verdict["reason"],
                    "offending_span": verdict["offending_span"],
                }
            )
            return False

        log_allowed_action(self.agent_name, action)
        return True
