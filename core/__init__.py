"""SWARMS security kernel.

Deterministic, dependency-free (apart from the optional LLM client), and the
only part of the project that decides whether a privileged action happens.

    from core import AgentRuntime, Capability, TaintedValue, TaintLabel, run_policy
"""
from core.capability import Capability, attenuate, run_authority, run_policy, shield_enabled
from core.logger import current_events, log_event, run_context
from core.policy import Decision, authorize, explain
from core.runtime import AgentRuntime
from core.taint import TaintedValue, TaintLabel, combine, propagate_label

__version__ = "1.0.0"

__all__ = [
    "AgentRuntime", "Capability", "Decision", "TaintLabel", "TaintedValue",
    "attenuate", "authorize", "combine", "current_events", "explain",
    "log_event", "propagate_label", "run_authority", "run_context",
    "run_policy", "shield_enabled", "__version__",
]
