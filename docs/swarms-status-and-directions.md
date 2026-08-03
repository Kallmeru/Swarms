# SWARMS — final status before Tech Fest

**Update: PR #13 and #14 are merged into `main`.** The real 8-attack benchmark, mobile fixes, and sound effects are all live. This doc's newest addition is below: Ablaze's scanner work is now properly integrated with safe credential handling.

**Second update: the scanner core is now wired live into the demo**, not just sitting in the repo. `swarm/agents.py`'s reader step calls `attack_lab.scanner_rules.scan_text` on every attack document and the frontend shows the score next to the graphs. Every mention below of "not wired into the live demo path" refers only to the *optional* LLM-rewrite feature and the real SMTP send, which still need real external credentials and stay disconnected on purpose. See `docs/tech-fest-briefing.md` for how to talk about this.

**Third update: the alert email is now shown too, as a preview.** When a document is flagged, the demo shows exactly what `ScannerAgent.send_alert()` would have emailed, real subject and body built from the actual attack, using safe placeholder addresses (`security@example.com` / `swarms@example.com`, from `attack_lab.config.Config()`'s defaults since no real `.env` exists in the deploy environment). Clearly labeled "preview, not sent". It can't actually send: the live site is static, there's no backend to receive a "run attack" request and open an SMTP connection when a judge clicks the button, and Ablaze's real credentials are the ones that leaked (still unconfirmed whether they've been rotated), so nothing here depends on them.

## `attack_lab/` — Ablaze's scanner, integrated safely

Brought Ablaze's prompt-injection scanner/sanitizer/alerting code into `main` as its own `attack_lab/` package, alongside `swarm/` and `core/`, still deliberately *not* wired into the live demo path (see below for why). What changed from the original branch:

- **The leaked `.env` was never brought over.** Only the code came in. Added `.env.example` at the project root instead, real values, no secrets, ever.
- **Replaced `test_env.py`**, which printed the raw API key and SMTP user to stdout (that's a second, independent secrets-hygiene problem beyond the committed `.env`, printing to a terminal or CI log is its own leak vector). New version (`attack_lab/check_env.py`) reports which vars are set as booleans only, never the values.
- **Added `attack_lab/test_scanner.py`**, a real self-check that runs the scanner and sanitizer against a known-malicious string and a benign one, with zero API key or network dependency, `python -m attack_lab.test_scanner`. This is genuinely working code today, not blocked on any credential.
- **Added a root `requirements.txt`** so `python-dotenv`, `requests`, etc. are installable in one place.
- Main's `.gitignore` already correctly excludes `.env` and `__pycache__/` (this repo's root `.gitignore` was never the corrupted one, only Ablaze's own branch copy was), so nothing needed fixing there.

**What I still cannot do**: rotate the actual leaked Gemini key and Gmail app password. That requires logging into Ablaze's Google account, which I don't have and shouldn't have. The credentials are still live until Ablaze does that, this integration protects `main` from ever containing them and gives everyone a safe way to run the scanner with their own key, but it doesn't revoke the old one. Please confirm that's been done.

**Why this still isn't wired into the live demo**: the scanner/sanitizer core (regex-based, `scan_text` + `basic_sanitize`) has zero external dependency and could be wired in safely. The optional LLM-rewrite and email-alert features need a real Gemini key and real SMTP credentials respectively, either one being slow, rate-limited, or down during a live presentation would break the demo. Keeping it as a standalone, presentable-on-its-own module (with a passing offline self-check) is the safer call for tech fest day. Wiring the regex-only scanner in as a non-blocking, informational overlay is a reasonable next step, just not one to make hours before presenting.

## What got built in this pass (closes the last real gap)

- **`swarm/` package now exists**: `swarm/agents.py` (reader/analyst/emailer functions), `swarm/run_swarm.py` (the exact `run_swarm(attack, shield_enabled, run_id)` function `benchmark/run_benchmark.py` was always waiting on), and 8 attack fixtures in `swarm/attacks/` covering direct override, multi-hop redirect, credential exfiltration, HTML/script injection, base64 obfuscation, role override, shell command injection, and a fake system message.
- **`benchmark/run_benchmark.py` actually run for real**: 8/8 attacks succeed with the shield off, 0/8 succeed with it on. `benchmark/results.csv` and every `web/data/*.json` file (16 event logs + `manifest.json` + `benchmark_summary.json`) are now real generated output, not the 2 hand-placed samples.
- **`Demo.py` consolidated** to call `swarm.run_swarm` instead of duplicating the agent logic inline, one source of truth now.
- **Frontend polish**: fixed the "placeholder numbers" copy under the benchmark chart (now describes the real run), fixed a blank `Offending value: ""` line that showed up once real data replaced the hand-written mock events, verified all 8 attacks play back correctly end to end (graphs, status, reason panel, sounds) with zero console errors.
- Built on top of `core/`, exactly as it already is on `main` — nothing in `core/` was touched. The shield toggle, taint tracking, and capability attenuation are all Paru's already-verified code, unchanged.

## What still needs a human, not more code

1. **Still urgent**: rotate the leaked Gemini API key and Gmail app password from `Ablaze-(Agents)`'s `.env` (flagged in the previous status doc). I have not touched that branch, I can't rotate credentials that aren't mine, and I'm not force-pushing over someone else's branch. Please confirm this actually happened.
2. **`Paru-(Core)` branch**: still diverged (dict-based `authorize()`, different logger API, missing `web/`/`benchmark/`/`docs/`). I did *not* merge it or touch it — the `swarm/` layer above is built entirely on the version of `core/` already on `main`, which is Paru's own original fix, already verified and live. Recommendation: Paru should pull `main` going forward rather than trying to merge the old branch state back in; there's nothing left to reconcile if the old branch is just abandoned in favor of `main`.
3. **Ablaze's scanner/sanitizer/alerting code** now lives at `attack_lab/` on `main`, properly integrated with safe credential handling (see the section above). Still *deliberately not wired into the live demo path*: the optional LLM-rewrite and email-alert features depend on a live Gemini API call and a real SMTP send, both are things that can fail, lag, or hang during a live presentation. Worth mentioning verbally as a second layer the team explored, not something to run on stage.
4. `core/llm_client.py` is intentionally still a stub. Nothing in the demo path calls out to an LLM or any external API, on purpose: the whole thing is deterministic and works with no network dependency, so nothing can flake during the presentation.

## This needs a merge before any of it is live

Everything above is on a branch (PR incoming). The live site at kallmeru.github.io/Swarms/ won't show any of this, the real 8-attack benchmark, the fixed copy, none of it, until that PR is merged. This is the one remaining step between now and a presentable live demo.

## What to actually present

- Open the live site, walk through the SWARMS OS desktop concept, open `invoice_final.pdf`, pick any of the 8 attacks from the wheel, hit Run Attack, watch shield-off succeed and shield-on get contained side by side.
- The benchmark chart: 100% shield-off success vs. 0% shield-on success across 8 distinctly-styled attack techniques. Clean, strong headline number for a demo.
- If asked what else was explored: Ablaze's scanner + alerting prototype is a good talking point for "what's next," not part of the live path today.

## Directions, updated

- **Paru**: nothing blocking. Pull `main` when you get a chance to see the `swarm/` layer sitting on top of your `core/`. A richer directive-tracking event on intermediate handoffs (matching the very first mock schema this project sketched) would be a nice post-tech-fest polish item, not needed for the demo to work today.
- **Ablaze**: rotate the credentials, that's the one open item with your name on it.
- **Dipesh (me)**: done for now, watching for anything that comes up before presentation time.
