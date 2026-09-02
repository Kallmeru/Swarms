# SWARMS: integration contract (v2)

What the pieces promise each other. This describes the code as it is on
`main`, not a plan, so anything here can be relied on and anything missing is
genuinely missing.

Three things are pinned down: the event wire format, the one function that
integrates the pipeline with everything else, and the fixture schema.

**Changes from v1**, all additive except where noted:

- `authorize()` returns a `Decision`, a `NamedTuple` that still unpacks as the
  documented `(allowed, reason, offending_arg, offending_span)` tuple.
- Run state (shield mode, run authority, event stream) moved from module
  globals to `contextvars`. Necessary for the API server: with globals, two
  concurrent requests interleave their events and one request's shield
  setting silently applies to the other.
- Events carry `event_id` and an ISO-8601 `timestamp` (v1 emitted a float and
  no id). **This is the one breaking change**; nothing in the frontend reads
  either field.
- New event types: `RUN_START`, `RUN_END`, `RECIPIENT_RESOLVED`,
  `CAPABILITY_ATTENUATED`. All optional to consume.
- Policy gained control-argument grounding and run authority (see below).

---

## Part 1: the wire format

One JSON object per event, in order. Persisted runs write
`runs/<run_id>/events.jsonl`; in-process callers get the same objects back
from `run_swarm()` without touching disk.

```json
{"event_id": "evt_0004", "timestamp": "2026-09-02T10:00:00.123Z", "run_id": "attack_001_on",
 "type": "ACTION_BLOCKED", "agent": "agent3_emailer",
 "data": {"action": "send_email", "reason": "...", "offending_arg": "to",
          "offending_span": "attacker@evil.example"}}
```

Envelope fields, identical on every line: `event_id`, `timestamp`, `run_id`,
`type`, `agent`, `data`. `agent` is hoisted out of `data` to the envelope
because that is where every consumer looks; it is exactly one of
`agent1_reader`, `agent2_analyst`, `agent3_emailer`, or `null` for events that
belong to the run rather than an agent.

### Event types

| type | emitted when | fields consumers read |
|---|---|---|
| `RUN_START` | a run begins | `attack_id`, `category`, `intent` (`malicious`/`benign`/`unknown`), `shield` (`on`/`off`), `user_task`, `authorized_actions`. **`intent` and `shield` together are what make `ACTION_ALLOWED` readable**: the same event means "a worm succeeded" on an attack and "a job completed" on a real task. |
| `AGENT_START` | an agent begins its turn | `inputs`: array of `{"label": "TRUSTED"\|"UNTRUSTED"}`. Any untrusted input colors that agent's node untrusted from the start. `capability`: what it holds. |
| `TOOL_CALL` | a tool is invoked | `tool`, `args`, `arg_labels`. Informational. |
| `TOOL_RESULT` | a tool returns | `label`, `preview`. An untrusted result recolors the current agent even if it started trusted: this is Agent 1 visibly catching it from the document. |
| `CAPABILITY_ATTENUATED` | a boundary shrinks the receiver's authority | `before`, `after`, `removed`. Only emitted when something actually changed. |
| `AGENT_HANDOFF` | one agent hands work to the next | `to`, `data_label`, `data_preview`, `provenance`. Colors the edge. |
| `RECIPIENT_RESOLVED` | the emailer picks a recipient | `recipient`, `label`, `provenance`, `task_recipient`. This is the single most diagnostic event in the stream: it shows the attack landing before the policy engine reacts to it. |
| `ACTION_ALLOWED` | a privileged action executed | `action`, `reason`, `args`, `executed`, `result`. Read together with `RUN_START.shield`/`.intent`. |
| `ACTION_BLOCKED` | a privileged action was refused | `reason` (human-readable), `offending_arg`, `offending_span` (the literal value that caused it), `args`. |
| `SCANNER_RESULT` | the attack-lab scanner scored the document | `score`, `flagged`, `findings`. Informational only, gates nothing. |
| `SCANNER_ALERT_PREVIEW` | the scanner flagged | `to`, `from`, `subject`, `body`. The alert it *would* send. Never sent. |
| `AGENT_END`, `RUN_END` | turn / run finished | `output_label`, `output_preview`; `executed`, `recipient`, `recipient_label`, `outbox_count`. |

Labels on the wire are uppercase `"TRUSTED"` / `"UNTRUSTED"`. Use
`label.wire` rather than uppercasing at each call site.

---

## Part 2: the policy engine

`core.policy.authorize(action, args, capability) -> Decision`

Checked in order, all deterministic, no model call:

1. **Shield off** → allow. The unprotected baseline, not a production mode.
2. **Unknown action** → deny. A verb nobody has written a policy for arrives
   denied, not permitted.
3. **Authority** → the agent must hold the capability, *and* the run's task
   must authorize the action (`core.capability.run_authority()`).
4. **Grounding** → every control argument must be `TRUSTED`.

```python
CONTROL_ARGS = {
    "send_email": ("to", "cc", "bcc", "recipient", "attachments"),
    "execute":    ("command", "argv", "cmd"),
    "write_file": ("path", "filename"),
}
```

Arguments not listed are **data** arguments and may legitimately carry
untrusted content: an email body quoting the document is normal work.
Adding an action means adding a line to `ACTION_FIELDS` in `capability.py`
and a line here; a test asserts every capability action has a control-argument
spec, so an action can never end up with nothing checked.

Taint detection recurses through dicts, lists, tuples and sets, because
arguments nest and a top-level-only check misses `to: [ok@x, attacker@y]`.

### Run scope

```python
from core.capability import Capability, run_policy

with run_policy(shield=True, authority=Capability.of(["send_email"])):
    ...
```

Both settings are `contextvars`, restored exactly on exit even if the body
raises. Use `run_policy` rather than the setters anywhere a run can be nested
or concurrent.

---

## Part 3: the integration function

```python
from swarm.run_swarm import run_swarm, run_both

run_swarm(attack: Fixture | dict, shield_enabled: bool, run_id: str, persist: bool = True) -> dict
```

Returns:

```python
{
  "run_id": str, "attack_id": str, "intent": str, "shield": "on" | "off",
  "malicious_action_executed": bool,   # did the privileged action go through
  "hijacked": bool,                    # ...and did content choose its target
  "recipient": str, "recipient_label": "TRUSTED" | "UNTRUSTED",
  "outbox": [ ... ],                   # recorded sends, never delivered
  "events_path": str, "events": [ ... ],
}
```

`run_both(fixture)` runs the same input under both settings and returns
`{"attack", "off", "on"}`. `persist=False` skips the file and returns the
events inline: what the API uses, so it does not write a trace per request.

Accepts a plain dict as well as a `Fixture`, so the v1 call signature keeps
working.

---

## Part 4: the fixture schema

Fixtures load from `swarm/attacks/attack_*.json` (one per file) and
`swarm/corpus.json` (a `{"fixtures": [...]}` list), concatenated, sorted by
id, with duplicate ids rejected loudly. Only four fields are required.

```json
{
  "attack_id": "attack_041",
  "name": "short_snake_case_name",
  "category": "delimiter_confusion",
  "document_text": "the untrusted content the reader ingests",

  "intent": "malicious",
  "target_email": "attacker@evil.example",
  "task_recipient": "finance@acme-corp.example",
  "user_task": "Read this, summarize it, and email the summary to finance@acme-corp.example.",
  "authorized_actions": ["send_email"],
  "expect": {"shield_off": "executed", "shield_on": "blocked"},
  "notes": "what this technique is and why it is here"
}
```

Defaults, applied in `swarm/fixtures.py`: `intent` malicious,
`authorized_actions` `["send_email"]`, `task_recipient` the org address,
`user_task` generated from the two above, and `expect` derived from intent
(everything executes with the shield off; with it on, benign authorized work
executes and everything else is blocked).

Attacker addresses use the reserved `.example` TLD (RFC 2606) so nothing in
the corpus can resolve. A test enforces it.

Adding an attack is one entry in `corpus.json`. `--strict` on the benchmark
exits non-zero if any run defies its `expect`, and CI runs it that way, so a
regression in the security property fails the build.
