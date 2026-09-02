"""Agent runtime: the wrapper every agent runs inside.

It does four things and nothing else: label what goes in, label what comes
out, attenuate authority when work crosses to the next agent, and route every
privileged action through the policy engine before any tool actually runs.

The agent function itself is ordinary code (or an LLM call) and is trusted to
do none of this. That separation is the design: enforcement cannot be talked
out of by the content an agent read, because the content never reaches the
enforcement path, only the data path.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping

from core.capability import Capability, attenuate
from core.logger import log_event
from core.policy import authorize
from core.taint import TaintedValue, wrap_raw

AgentFn = Callable[[TaintedValue], Any]
Tool = Callable[..., Any]


class AgentRuntime:
    def __init__(
        self,
        agent_fn: AgentFn,
        capability: Capability,
        agent_name: str,
        tools: Mapping[str, Tool] | None = None,
    ):
        self.agent_fn = agent_fn
        self.capability = capability
        self.agent_name = agent_name
        # Real callables, invoked only after the policy engine allows the
        # action. Absent tool -> the action is logged as allowed but nothing
        # executes, which is the right behavior for a benchmark run.
        self.tools: dict[str, Tool] = dict(tools or {})

    def run(self, input_value: TaintedValue) -> TaintedValue:
        log_event("AGENT_START", {
            "agent": self.agent_name,
            "inputs": [{"label": input_value.label.wire}],
            "capability": self.capability.to_dict(),
        })

        output = self.agent_fn(input_value)
        if not isinstance(output, TaintedValue):
            # Fails closed: an agent that returns bare text gets the
            # untrusted label, never the benefit of the doubt.
            output = wrap_raw(output, self.agent_name)

        log_event("AGENT_END", {
            "agent": self.agent_name,
            "output_label": output.label.wire,
            "output_preview": str(output.value)[:200],
        })
        return output

    def handoff(self, next_runtime: "AgentRuntime", value: TaintedValue) -> TaintedValue:
        """Hand data to the next agent. Data crosses; authority does not.

        The receiver's capability is re-derived at the boundary rather than
        carried, so no chain of handoffs can end with an agent holding more
        than the human granted it for this task.
        """
        before = next_runtime.capability
        after = attenuate(before)
        next_runtime.capability = after

        if before.granted != after.granted:
            log_event("CAPABILITY_ATTENUATED", {
                "agent": next_runtime.agent_name,
                "before": before.to_dict(),
                "after": after.to_dict(),
                "removed": sorted(before.granted - after.granted),
            })

        log_event("AGENT_HANDOFF", {
            "agent": self.agent_name,
            "to": next_runtime.agent_name,
            "data_label": value.label.wire,
            "data_preview": str(value.value)[:200],
            "provenance": list(value.provenance),
        })
        return next_runtime.run(value)

    def privileged_action(self, action: str, args: dict) -> bool:
        """Attempt a privileged action. Returns whether it executed.

        The policy check happens before the tool is looked up, so a denied
        action never touches the tool at all: there is no window where the
        side effect has started and the check has not finished.
        """
        decision = authorize(action, args, self.capability)

        if not decision.allowed:
            log_event("ACTION_BLOCKED", {
                "agent": self.agent_name,
                "action": action,
                "reason": decision.reason,
                "offending_arg": decision.offending_arg,
                "offending_span": decision.offending_span,
                "args": _unwrap(args),
            })
            return False

        tool = self.tools.get(action)
        result = None
        if tool is not None:
            result = tool(**_unwrap(args))

        log_event("ACTION_ALLOWED", {
            "agent": self.agent_name,
            "action": action,
            "reason": decision.reason,
            "args": _unwrap(args),
            "executed": tool is not None,
            "result": result,
        })
        return True


def _unwrap(value: Any) -> Any:
    """Strip labels for handing to a tool or writing to the log. Recurses,
    because arguments nest (a list of recipients, a dict of headers) and a
    top-level-only unwrap leaves TaintedValue objects that a tool cannot use
    and json cannot serialize."""
    if isinstance(value, TaintedValue):
        return _unwrap(value.value)
    if isinstance(value, dict):
        return {k: _unwrap(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_unwrap(v) for v in value]
    return value
