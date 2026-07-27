from core.taint import TaintedValue, TaintLabel
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
        log_event("AGENT_START", {
            "agent": self.agent_name,
            "inputs": [{"label": input_value.label.value.upper()}],
        })

        output = self.agent_fn(input_value)

        # If agent returns raw text, wrap it as UNTRUSTED
        if not isinstance(output, TaintedValue):
            output = TaintedValue(
                value=output,
                label=TaintLabel.UNTRUSTED,
                provenance=[f"output_of:{self.agent_name}"],
            )

        log_event("AGENT_END", {
            "agent": self.agent_name,
            "output_label": output.label.value.upper(),
            "output_preview": str(output.value)[:200],
        })

        return output

    def handoff(self, next_runtime, value: TaintedValue) -> TaintedValue:
        """
        Passes tainted value to the next agent.
        Drops capability at boundary (unless the shield is off) and logs
        the crossing.
        """
        next_runtime.capability = drop_capability(next_runtime.capability)

        log_event("AGENT_HANDOFF", {
            "agent": self.agent_name,
            "data_label": value.label.value.upper(),
            "data_preview": str(value.value)[:200],
        })

        return next_runtime.run(value)

    def privileged_action(self, action: str, args: dict):
        """
        Attempts a privileged action (email, execute, write file).
        Enforces taint + capability rules.
        """
        allowed, reason, offending_arg, offending_span = authorize(action, args, self.capability)

        if not allowed:
            log_event("ACTION_BLOCKED", {
                "agent": self.agent_name,
                "action": action,
                "reason": reason,
                "offending_arg": offending_arg,
                "offending_span": offending_span,
            })
            return False

        log_event("ACTION_ALLOWED", {
            "agent": self.agent_name,
            "action": action,
            "reason": reason,
        })

        # In real system, you'd call the actual action here.
        return True
