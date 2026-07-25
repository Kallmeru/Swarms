📘 TRIPWIRE v2 — Core Security Engine
Taint Tracking • Capability Attenuation • Policy Enforcement • Agent Runtime • Structured Logging
This branch (Paru-(Core)) contains the security kernel for TRIPWIRE v2 — the deterministic enforcement layer that prevents worm propagation across multi‑agent LLM systems.

This core is ~300–400 lines of pure Python and implements:

Taint Model

Capability Model

Policy Engine

Agent Runtime Wrapper

Structured Event Logging

Benchmark Hooks

This is the foundation of the entire project.

core/
│
├── taint.py          # Taint labels, TaintedValue, provenance merging
├── capability.py     # Agent capabilities + attenuation at boundaries
├── policy.py         # Privileged action authorization rules
├── runtime.py        # Agent wrapper: taint, capability, policy, logging
├── logger.py         # Structured JSON logs + benchmark hooks
│
demo_test.py          # Fake agent chain test (for teammates)
README.md             # This file
🧠 Architecture Overview
1. Taint Model (taint.py)
Tracks trustworthiness of data as it flows through agents.

TaintLabel — TRUSTED / UNTRUSTED

TaintedValue — wraps all data

combine_values() — merges taint + provenance

All agent inputs/outputs are wrapped in TaintedValue.

2. Capability Model (capability.py)
Defines what each agent is allowed to do.

Capabilities include:

can_email

can_execute

can_write_file

Capabilities drop at every agent boundary, preventing worm escalation.

3. Policy Engine (policy.py)
Blocks privileged actions when:

the agent lacks capability

the action uses UNTRUSTED data

This is the worm‑killing rule.

4. Agent Runtime (runtime.py)
The “mini‑OS” each agent runs inside.

Responsibilities:

wrap inputs

wrap outputs

drop capability at boundaries

enforce privileged actions

log everything

track provenance

Teammates will use this wrapper for all agents.

5. Event Logger (logger.py)
Produces structured JSON logs for:

graph UI

worm propagation animation

debugging

benchmark replay

Includes hooks:

log_taint_propagation

log_capability_drop

log_boundary

log_blocked_action

log_allowed_action



