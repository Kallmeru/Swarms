# SWARMS — status check and team directions

Read after all three branches had real content: `main` (merged frontend + core fixes), `Paru-(Core)`, and `Ablaze-(Agents)` (fresh manual upload). This reconciles what's actually built against what the demo needs, and gives each person a concrete next step.

## 🚨 Urgent, before anything else in this doc

`Ablaze-(Agents)` has a real `.env` file committed, with live credentials, in a **public** GitHub repo:

```
GEMINI_API_KEY=AQ.Ab8RN6L5jeprR64EkIQP04Tr4lHMMKt-IXt2JTvt-Ea292vBIA
ALERT_SMTP_USER=ablaze123pariyar@gmail.com
ALERT_SMTP_PASS=kyjcxyxaxfripyrv        <- looks like a Gmail app password
ALERT_TO=ablazepariyar2@gmail.com
ALERT_FROM=ablaze123pariyar@gmail.com
```

This is not the earlier empty-`.env` false alarm from a few days ago — these are real values, currently reachable by anyone on the internet.

**Do this now, not after reading the rest of this doc:**
1. Revoke/rotate the Gemini API key.
2. Change the Gmail account password and revoke that app password (Google Account → Security → App passwords).
3. Only after that: fix the branch. Deleting `.env` in a new commit does **not** remove it from git history — it's still fetchable from every clone and from GitHub's own commit view. A full history rewrite (`git filter-repo` or BFG) is a separate decision the team should make together, don't do it solo, but it doesn't matter until the credentials themselves are rotated, so rotation comes first.
4. `Ablaze-(Agents)`'s `.gitignore` is also corrupted (looks like it was saved with the wrong encoding — it's literally garbled bytes, not text), so it was never actually excluding `.env` in the first place. Needs to be recreated as plain text.

## Current state, branch by branch

### `main` (the live baseline)
- `core/`: taint tracking + capability attenuation + policy engine. Shield on/off toggle works end to end (verified by running `Demo.py`).
- `web/`: full SWARMS OS frontend, live at kallmeru.github.io/Swarms/, mobile-responsive, sound effects.
- `benchmark/run_benchmark.py`: written and tested, but it calls `swarm.run_swarm.run_swarm(attack, shield_enabled, run_id)` — **that module doesn't exist anywhere, on any branch.** This is the single biggest gap: nothing currently produces real benchmark data.
- Only 2 attacks have real event data (`web/data/attack_001/002_*.json`); `benchmark_summary.json` is explicitly a placeholder ("Placeholder from the 2 sample attacks bundled for frontend development").

### `Paru-(Core)`
- Hasn't pulled `main` since commit `24d4868` — that's before `web/`, `benchmark/`, and `docs/` existed. It's missing all three entirely.
- Independently re-solved the exact same shield-toggle bug that got fixed on `main`, but with an **incompatible** shape:
  - `authorize()` returns a dict `{allowed, reason, offending_span}` vs. main's tuple `(allowed, reason, offending_arg, offending_span)`.
  - Toggle mechanism: a module-level `runtime.SHIELD_ON` meant to be poked directly (`core.runtime.SHIELD_ON = False`) vs. main's `set_shield_enabled()` setter.
  - Logging: `logger.init_run()` always mints a random UUID with no way to pass a specific run id, vs. main's `set_current_run(run_id)`. `benchmark/run_benchmark.py`'s whole contract depends on controlling the run id for file naming — Paru's version as-is can't satisfy that.
  - `Demo.py` on this branch was rewritten back to a single shield-off-only manual script, no on/off comparison assertion.
- Also has `core/__pycache__/*.pyc` committed (compiled bytecode, shouldn't be tracked).
- None of this is "wrong", it's a second, independent solution to the same problem, but it means merging either direction will conflict across every file in `core/` plus `Demo.py`. Someone needs to pick one and reconcile, not just merge.

### `Ablaze-(Agents)`
- Built a prompt-injection **scanner + sanitizer + Gemini client + SMTP email alerting** system: regex-weighted scoring (`scanner_rules.py`), text sanitization (`sanitizers.py`), an LLM wrapper (`llm_client.py`), an alert emailer (`agents.py`). Reasonably solid code on its own terms.
- But it's a genuinely different architecture from the rest of the project. No `TaintedValue`, no `Capability`, no `agent1_reader`/`agent2_analyst`/`agent3_emailer`, no `run_swarm()` — it doesn't plug into `core/`, `web/`, or `benchmark/` at all as committed.
- The branch itself is also missing `core/`, `web/`, `benchmark/`, `docs/` entirely — same as Paru's branch, never synced with `main`.

## Directions

### Paru — Core
1. Pull `main` into `Paru-(Core)` first. You're missing the entire frontend and benchmark script right now.
2. Reconcile the two shield-toggle fixes — recommend keeping main's version since it's the one already wired end-to-end to `web/` and `benchmark/run_benchmark.py` and verified working; port over anything from your version you prefer (e.g. the dict-shaped verdict is arguably cleaner), but pick one shape and update `Demo.py` to match it, not both.
3. Once reconciled, build the actual missing piece: `swarm/run_swarm.py`, the one function `benchmark/run_benchmark.py` has been waiting on:
   `run_swarm(attack, shield_enabled, run_id) -> {"run_id", "malicious_action_executed", "events_path"}`. This is what unblocks real benchmark data across the full attack set instead of 2 hand-placed samples.
4. Add `__pycache__/` to `.gitignore` and untrack the `.pyc` files already committed.

### Ablaze — Agents / Attack Lab
1. Rotate the leaked credentials — see the urgent section at the top, do this before anything else.
2. Recreate `.gitignore` as plain text (the current one is corrupted) and make sure it actually excludes `.env` and `__pycache__/`.
3. The scanner/sanitizer/alerting work is solid but isn't on the critical path for the demo. What's actually needed: the **attack scenarios** (`swarm/attacks/attack_*.json` fixtures, poisoned documents with a directive for the worm to try) that `benchmark/run_benchmark.py` loops over, and ideally the reader/analyst/emailer agent functions themselves for Paru's `core/` to wrap.
4. Worth a short conversation with Paru about whether the scanner is meant to replace or supplement taint tracking — right now they're two disconnected security concepts in one demo. Better to settle that before more code goes into either.

### Dipesh — Front-End (me)
1. Nothing urgent — live site works, mobile-responsive, sound effects fixed.
2. Once `swarm/run_swarm.py` exists and the benchmark script can run for real, regenerate `web/data/*.json` from actual results instead of the 2 placeholder attacks.
3. Blocked on Paru/Ablaze for that; picking this back up once it's ready.
