# SWARMS

**Policy enforcement for AI agent tool calls.**

```bash
pip install swarms-guard
```

Agents read things. Some of what they read is written by someone who wants
them to act on it. SWARMS decides whether a tool call is allowed to happen
based on **where its arguments came from**, not on how they are phrased.

```python
from swarms import Guard

guard = Guard.from_file("swarms.yaml")

@guard.tool("send_email", principal="assistant")
def send_email(to, subject, body):
    smtp.send(to, subject, body)

with guard.session_scope("assistant", user="alice") as s:
    page = s.ingest(fetch(url), source=f"web:{url}")   # untrusted, whatever it says
    to   = s.trust("boss@corp.example")                # the human's choice

    send_email(to=to, subject="Summary", body=page, session=s)
```

That call goes through. The body quotes a page nobody vetted, which is normal
work. Change `to` to an address that came out of the page and it is refused,
with the argument named and the value quoted:

```
PolicyDenied: control argument 'to' of 'send_email' traces to untrusted content
(ingest:web:example.com/invoice); content that was read cannot decide what a
privileged action targets
```

## Why not just detect bad prompts

Because detection has to recognise an attack to stop one, and phrasing is
free. Against the 40-technique corpus in this repo, the regex scanner
bundled here catches **8%**. Refusing arguments that cannot be traced to the
human catches **100%**, without recognising anything.

The engine is a dictionary lookup and a label comparison. No model call, no
classifier, no pattern list. A decision costs **~3µs**; the full guarded call
including the durable audit write is **~100µs**, about 10,000/sec on one
thread. Fast enough that there is never a reason to sample or to skip it
under load.

## The rules

Five checks, in order, all deterministic:

| | |
|---|---|
| **Known action** | An action your policy does not declare is denied. |
| **Known principal** | A principal it does not declare holds nothing, so a typo fails safe. |
| **Authority** | The principal must hold the action's capability, and this task's ceiling must still allow it. |
| **Grounding** | Every *control* argument must trace back to the human. |
| **Approval** | Actions you mark `require_approval` need a person, even when the rest passes. |

**Grounding is the one that earns its keep.** You name, per action, the
arguments that decide what it does to the world. Everything else is a data
argument and may carry untrusted content freely. An email body quoting a
scraped page is fine; an email *recipient* taken from that page is the
attack. Blocking both would score 100% on containment and be useless.

## The policy is a file you own

```yaml
# swarms.yaml
actions:
  send_email:
    capability: email.send
    control_args: [to, cc, bcc]        # must trace to the human
    data_args: [subject, body]         # may quote anything

  charge_card:
    capability: payments.charge
    control_args: [customer_id, amount, currency]
    require_approval: true

principals:
  assistant:
    capabilities: [email.send]
  billing:
    capabilities: [payments.charge]
```

It is load-bearing, not decoration. Delete `to` from `control_args` and
`swarms redteam` drops from 100% containment to 5% on the same corpus.

```bash
swarms init            # write a starter policy
swarms policy check    # validate and lint it
swarms redteam         # run 40 attacks and 8 benign controls against it
```

## Validate your own configuration

`swarms redteam` runs a corpus of prompt-injection attacks and legitimate
control tasks through a deliberately gullible agent pipeline that calls your
real policy.

```
  policy              default
  fixtures            48  (40 attacks, 8 benign controls)

  containment         40/40 attacks refused  (100.0%)
  utility retained    7/7 legitimate tasks completed  (100.0%)
  false positives     0

  refused by rule     {'grounding': 38, 'run_authority': 2}
  regex scanner       would have flagged 3/40  (8% recall)
  wall clock          0.02s
```

Both numbers, always, because either alone is trivial to fake. A policy that
denies everything contains 100% and ships nothing. `--strict` exits non-zero
on any failure, so this belongs in CI.

The corpus covers 15 technique families: direct override, multi-hop redirect,
worm self-propagation, credential and PII exfiltration, HTML/SVG/markdown
injection, base64/hex/ROT13 encoding, zero-width and homoglyph obfuscation,
delimiter confusion, forged tool-call JSON, citation laundering, social
engineering, shell injection, fake policy override, and unauthorized-action
attempts. Attacker addresses use reserved TLDs, so nothing in it can resolve.

## Recovering provenance from model output

A model does not hand back labeled objects. It hands back JSON:

```json
{"name": "send_email", "arguments": {"to": "attacker@evil.example"}}
```

`Session.tool_call()` works out where each value could have come from: it
matches against everything the session ingested (zero-width and case
normalised, so obfuscation does not defeat it) and against what the human
trusted. A value that matches neither is treated as untrusted, because a
recipient that appears in no document and in no request is not one anybody
chose.

```python
decision = session.tool_call(call["name"], call["arguments"])
if decision.allowed:
    TOOLS[call["name"]](**call["arguments"])
else:
    # hand decision.reason back to the model and let it try again
```

See [`examples/tool_calling_loop.py`](examples/tool_calling_loop.py).

**This is the contract to get right:** call `ingest()` on every tool result,
retrieved document, web page and message from another agent. Content that is
never ingested cannot be recognised later. An un-instrumented source is a
hole in the model, exactly as it is in any taint system.

## Gateway and console

For non-Python stacks, or when you want the audit trail and approval queue:

```bash
swarms keygen
SWARMS_API_KEYS=swk_...:alice:admin swarms serve
```

```bash
curl -X POST localhost:8000/v1/authorize -H "Authorization: Bearer $KEY" \
  -H 'content-type: application/json' -d '{
    "session_id": "...", "action": "send_email",
    "arguments": {"to": "attacker@evil.example"}
  }'
```

| | |
|---|---|
| `POST /v1/sessions` | open a session for one unit of work |
| `POST /v1/sessions/{id}/ingest` | register content that came from outside |
| `POST /v1/sessions/{id}/trust` | register a value the human supplied |
| `POST /v1/authorize` | decide a tool call |
| `GET /api/decisions` `/api/stats` | the audit trail |
| `GET /api/approvals` | the approval queue |
| `GET /metrics` | Prometheus |
| `GET /docs` | OpenAPI |

The console at `/` is the operator surface: live decision stream with full
provenance, audit search, the approval queue, the loaded policy, red-team
results, and a simulator for checking a call against a rule before you ship
it. No build step, no CDN — it works on an air-gapped install.

API keys have three roles: `viewer` reads, `service` decides and records,
`admin` also resolves approvals and reloads policy. With none configured the
gateway runs open, warns loudly, reports `auth: disabled`, and **refuses to
start** when `SWARMS_ENV=production`.

## Human approval

Actions marked `require_approval` raise `ApprovalRequired` with an id.

```python
try:
    charge_card(customer_id=cid, amount=amt, session=s)
except ApprovalRequired as e:
    # someone resolves it in the console, or via the API
    charge_card(..., approval_id=e.approval_id, session=s)
```

An approval is bound to the exact arguments it was granted for and can be
spent **once**. Approving a $1 charge does not authorize a $10,000 one, and
the same id cannot be replayed or used on a different action. Unanswered
requests expire.

## Deploying it

```bash
docker build -t swarms .          # build runs policy check + redteam --strict
docker run -p 8000:8000 -v swarms-data:/data \
  -e SWARMS_ENV=production -e SWARMS_API_KEYS=swk_...:svc:service swarms
```

Roll it out in observe-only first (`swarms serve --observe`, or
`SWARMS_ENFORCE=0`). Decisions are computed and recorded; nothing is blocked.
Read the audit log, fix what the policy gets wrong on your traffic, then
enforce.

## Known limits

- **Grounding control arguments does not stop exfiltration through a data
  argument.** An untrusted body sent to a trusted recipient is permitted by
  design. Closing that needs a read-label on the destination too, i.e. full
  information-flow control.
- **Enforcement is at the tool boundary.** A side effect that never goes
  through `Guard` is outside the model, the same way an OS cannot protect a
  process talking straight to hardware.
- **Provenance depends on `ingest()`.** Content you never register cannot be
  attributed. This is the usage contract, and it is where a deployment most
  often goes wrong.
- **The corpus is 40 hand-written attacks.** A floor, not a proof, and not a
  red-team campaign.
- **Server-side sessions are per-worker.** Run one worker, or add session
  affinity. `SessionRegistry` is the swap point.
- **Audit throughput is bounded by SQLite's commit**, roughly 10k decisions
  per second per process. Well above agent workloads, which are gated on
  model latency, but it is the first thing to move if you outgrow it.

## Layout

```
swarms/
  config.py      policy loading, validation, linting
  policy.py      the decision function, and a reason for every verdict
  capability.py  capability sets, wildcards, per-run scope (contextvars)
  taint.py       labels, propagation, provenance chains
  guard.py       the SDK: Guard, Session, @guard.tool
  store.py       SQLite audit trail and approval queue
  llm.py         optional real-model backend
  cli.py         swarms init / serve / policy / redteam / audit / keygen
  server/        FastAPI gateway, API-key auth
  detect/        advisory content scanner, gates nothing
  redteam/       the corpus, the vulnerable pipeline, the suite
web/             the operator console
examples/        runnable integrations
tests/           98 tests
```

## Running the tests

```bash
pip install -e ".[server,llm,dev]"
python -m pytest tests
python examples/quickstart.py
swarms redteam --strict
```

## Team

- **Paru** ([@Kallmeru](https://github.com/Kallmeru)) — security kernel: the taint model, capability model and policy engine.
- **Ablaze** ([@Ablaze005](https://github.com/Ablaze005)) — content scanner and sanitizer (`swarms/detect/`), the advisory signal reported alongside every decision.
- **Dipesh** ([@dipeshrayg](https://github.com/dipeshrayg)) — SDK, gateway, console, attack corpus, red-team runner, packaging.

Apache-2.0.
