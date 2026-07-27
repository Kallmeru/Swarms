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
        log_event("agent_run_start", {"agent": self.agent_name})

        output = self.agent_fn(input_value)

        # If agent returns raw text, wrap it as UNTRUSTED
        if not isinstance(output, TaintedValue):
            output = TaintedValue(
                value=output,
                label=TaintLabel.UNTRUSTED,
                provenance=[f"output_of:{self.agent_name}"],
            )

        log_event(
            "agent_run_end",
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
        # Log boundary with provenance
        log_boundary(self.agent_name, next_runtime.agent_name, value)

        # Log capability drop
        old_cap = next_runtime.capability
        new_cap = drop_capability(next_runtime.capability)
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
            log_blocked_action(self.agent_name, action, normalized_args)
            return False

        log_allowed_action(self.agent_name, action)

        # In real system, you'd call the actual action here.
        return True
