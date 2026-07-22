from core.taint import TaintedValue, TaintLabel, combine_values
from core.capability import Capability, drop_capability
from core.policy import authorize
from core.logger import log_event


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

        # Run the agent
        output = self.agent_fn(input_value)

        # If agent returns raw text, wrap it as UNTRUSTED
        if not isinstance(output, TaintedValue):
            output = TaintedValue(
                value=output,
                label=TaintLabel.UNTRUSTED,
                provenance=[f"output_of:{self.agent_name}"]
            )

        log_event("agent_run_end", {
            "agent": self.agent_name,
            "output_label": output.label.value
        })

        return output

    def handoff(self, next_runtime, value: TaintedValue) -> TaintedValue:
        """
        Passes tainted value to the next agent.
        Drops capability at boundary.
        """
        log_event("boundary_cross", {
            "from": self.agent_name,
            "to": next_runtime.agent_name,
            "value_label": value.label.value
        })

        # Drop capability at boundary
        next_runtime.capability = drop_capability(next_runtime.capability)

        return next_runtime.run(value)

    def privileged_action(self, action: str, args: dict):
        """
        Attempts a privileged action (email, execute, write file).
        Enforces taint + capability rules.
        """
        allowed = authorize(action, args, self.capability)

        if not allowed:
            log_event("privileged_action_blocked", {
                "agent": self.agent_name,
                "action": action,
                "args": {k: getattr(v, "value", v) for k, v in args.items()}
            })
            return False

        log_event("privileged_action_allowed", {
            "agent": self.agent_name,
            "action": action
        })

        # In real system, you'd call the actual action here.
        return True
