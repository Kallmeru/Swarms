# Operator console

The frontend for the SWARMS gateway. Vanilla JS and CSS, no build step and no
CDN, because this is a self-hosted security tool and an air-gapped or
CSP-restricted install has to work.

Served by the gateway at `/`:

```bash
swarms serve
```

- `index.html` — structure
- `console.css` — styles
- `console.js` — everything else
- `data/redteam.json` — written by `swarms redteam --web-dir web/data`, read by the Red team view

## Views

| | |
|---|---|
| **Overview** | Decision volume, refusal rate, decision latency, pending approvals, why calls were refused, per-action breakdown. Warns when the gateway is unauthenticated or in observe-only mode. |
| **Decisions** | The audit trail, filterable by effect, action, principal and free text. Click a row for the full provenance chain and argument labels. |
| **Approvals** | The queue for `require_approval` actions. Approve or deny with attribution. |
| **Policy** | The loaded policy: every action with its control and data arguments, every principal with its capabilities, lint advisories, and a reload button. |
| **Red team** | The last suite result: containment, utility retained, false positives, per-category, and every fixture with the reason it was refused. |
| **Simulator** | Check a call against the live policy without performing it. Paste content, set arguments, see the decision and where each value traced to. |

Everything comes from the gateway's own API, so what the console shows is the
state the engine is actually in, not a copy of it.

## Authentication

When the gateway has API keys configured, the console asks for one and keeps
it in `localStorage`. Use the **Key** button in the top bar to set or change
it. A `viewer` key is enough for everything except approvals and policy
reload.
