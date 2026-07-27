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


class AgentRuntime:
    def __init__(self, agent_fn, capability: Capability, agent_name: str):
        self.agent_fn = agent_fn
        self.capability = capability
        self.agent_name = agent_name

    def run(self, input_value: TaintedValue) -> TaintedValue:
        """
        Runs the agent with taint-aware input and wraps output.
        """
        # Wire-format event name
        log_event("AGENT_START", {"agent": self.agent_name})

        output = self.agent_fn(input_value)

        # If agent returns raw text, wrap it as UNTRUSTED
        if not isinstance(output, TaintedValue):
            output = TaintedValue(
                value=output,
                label=TaintLabel.UNTRUSTED,
                provenance=[f"output_of:{self.agent_name}"],
            )

        # Wire-format event name
        log_event(
            "AGENT_END",
            {
                "agent": self.agent_name,
                "output_label": output.label.value,
            },
        )

        return output

    def handoff(self, next_runtime, value: TaintedValue) -> TaintedValue:
        """
        Passes tainted value to the next agent.
        Drops capability at boundary and logs attenuation.
        """
        # Wire-format boundary event
        log_boundary(self.agent_name, next_runtime.agent_name, value)

        # Capability drop
        old_cap = next_runtime.capability
        new_cap = drop_capability(next_runtime.capability)

        # Wire-format capability drop event
        log_capability_drop(self.agent_name, next_runtime.agent_name, old_cap, new_cap)

        # Apply dropped capability to next runtime
        next_runtime.capability = new_cap

        return next_runtime.run(value)

    def privileged_action(self, action: str, args: dict):
        """
        Attempts a privileged action (email, execute, write file).
        Enforces taint + capability rules.
        """
        allowed = authorize(action, args, self.capability)

        if not allowed:
            # Normalize args for logging (unwrap TaintedValue.value if present)
            normalized_args = {
                k: getattr(v, "value", v) for k, v in args.items()
            }

            # Wire-format blocked action event
            log_blocked_action(
                agent=self.agent_name,
                action=action,
                args={
                    "normalized_args": normalized_args,
                    "reason": "untrusted_input",
                    "offending_span": normalized_args,
                }
            )
            return False

        # Wire-format allowed action event
        log_allowed_action(self.agent_name, action)

        # In real system, you'd call the actual action here.
        return True
