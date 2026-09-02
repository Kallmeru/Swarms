# Architecture

How the pieces fit, and why each boundary is where it is. Read this before
changing anything in `swarms/policy.py` or `swarms/capability.py`.

```
   your application
        │
        ├── @guard.tool(...)  ─────┐          Python: in-process, ~100µs
        │                          │
   other stacks                    ▼
        └── POST /v1/authorize ─► Guard ─► Session ─► policy.authorize()
                                    │         │              │
                                    │         │         swarms.yaml
                                    │         │        (config.py)
                                    │    provenance
                                    │    (taint.py)
                                    ▼
                              AuditStore (SQLite)
                              decisions + approvals
```

## The decision is the product

Everything else exists to get a correct answer out of
`swarms.policy.authorize()` and to record it. That function is pure: it takes
an action, arguments, a principal and a policy, and returns a `Decision`. It
does no I/O, calls no model, and reads no file. Three consequences worth
keeping:

- **It is fast enough to be unconditional.** ~3µs for the decision, ~100µs
  for the whole guarded call once the audit row is committed. There is never
  a reason to sample or to skip the check under load.
- **It is testable without mocks.** Every rule in `tests/test_policy.py` is a
  direct call.
- **It cannot be talked out of an answer.** Content reaches the *data* path
  and never the decision path.

## The five rules

In order, and the order matters.

1. **Known action.** Not in the policy → denied. New tools arrive inert.
2. **Known principal.** Not in the policy → holds nothing. A typo in a
   principal name fails safe instead of inheriting authority.
3. **Authority.** The principal holds the action's capability, and the run's
   ceiling still allows it. Capabilities are dotted names with wildcard
   grants (`email.*`); requirements never use wildcards.
4. **Grounding.** Every control argument must be TRUSTED.
5. **Approval.** `require_approval` actions need a human.

Grounding runs *after* authority so a call that was never permitted does not
leak which arguments would have been checked. Approval runs last so nobody is
paged to approve a call that is already invalid.

## Where labels come from

Two ways, and the difference matters.

**Explicit.** `session.ingest(text, source=...)` returns an UNTRUSTED value
and registers the text. `session.trust(value)` returns a TRUSTED one. Values
carried through your own code keep their labels; `TaintedValue.derive()`
propagates label and provenance together, so a summary of a poisoned document
is still untrusted however clean it reads.

**Recovered.** Model output arrives as plain JSON with no labels, so
`Session.classify()` reconstructs provenance:

1. exact match against a trusted value → TRUSTED (the human named it, and
   that beats the same string appearing in a document)
2. substring match against ingested content → UNTRUSTED, naming the source
3. neither → the caller's fallback

Matching is normalised for case, whitespace and zero-width characters, and
values shorter than `min_match_length` are skipped: a two-character hit
against a page of prose is a coincidence, not provenance.

The fallback differs by path on purpose. `tool_call()` (model output) falls
back to **untrusted**: a value in no document and no request is not one
anybody chose. The `@guard.tool` decorator falls back to
`defaults.unlabeled_value` (trusted by default): an argument the developer's
own code constructed is not laundered content. Set it to `untrusted` for a
high-assurance deployment where every control value must be explicitly
grounded.

## Run state is contextvars, not globals

`swarms/capability.py` keeps enforcement mode and the run ceiling in
`contextvars`. This is not a style choice. The gateway serves many pipelines
at once; with module globals, one request turning enforcement off disables it
for every request in flight, and every response still looks plausible. That
failure is silent, which is the worst kind to ship in a security control.
`tests/test_policy.py::test_concurrent_runs_keep_their_own_enforcement_setting`
runs 100 interleaved decisions and asserts each saw its own setting.

## Audit is durable and out of the call path

`AuditStore` is SQLite in WAL mode with a connection per thread. Decisions and
approvals are rows, not log lines, because the questions asked months later
("what did we decide", "who approved this") are queries.

A failing audit write is logged and dropped rather than raised: logging is not
allowed to turn a permitted action into an exception in someone's
application. The decision already happened; losing the record of it is bad,
breaking the caller is worse.

Approvals are bound to an argument fingerprint and spent with a guarded
`UPDATE`, so concurrent workers cannot both win and an approval for one set of
arguments cannot be replayed against another.

## Enforce vs observe

`enforcing = False` computes and records every decision and blocks nothing.
`Decision.allowed` returns True while `Decision.effect` still says DENY, so
the audit log shows exactly what would have been refused. This is the only
responsible way to introduce a policy to live traffic.

## What is deliberately not here

- **No inline sanitizer on the decision path.** `swarms/detect/` scores text
  and is reported alongside a decision, but never gates one. Detection has to
  recognise an attack to stop it.
- **No model in the enforcement path.** Adding one would reintroduce the
  failure mode the design exists to avoid, and cost four orders of magnitude
  in latency.
- **No implicit trust escalation.** There is no path from UNTRUSTED back to
  TRUSTED. Any such path is exactly what prompt injection attacks.

## Extending it

**A new action:** add it to `swarms.yaml` with a capability and its control
arguments, grant the capability to a principal, run `swarms policy check`,
then `swarms redteam` to confirm you did not widen anything.

**A new storage backend:** reimplement `AuditStore`'s eight methods. Nothing
else touches the database.

**Shared sessions across workers:** reimplement `SessionRegistry`'s four
methods against Redis. Nothing else touches session state.

**A new corpus fixture:** one entry in `swarms/redteam/corpus.json`. Only
`attack_id`, `name`, `category` and `document_text` are required; the loader
supplies the rest.
