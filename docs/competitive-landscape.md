# Where SWARMS sits

A survey of what else defends agent tool calls, what each approach actually
does, and which of their working principles SWARMS adopts. Written to be
useful when deciding *not* to use SWARMS, so the weaknesses are here too.

Sources are linked inline. Figures attributed to other products are their
published claims, not our measurements. The only numbers we measured are
labelled as ours.

---

## The four categories

### 1. Detection — classify the text, block what looks malicious

**Lakera Guard, Protect AI LLM Guard, Meta PromptGuard / Llama Guard, Rebuff,
Vigil, AWS Bedrock Guardrails, Azure Prompt Shields, Google Model Armor.**

A classifier or pattern set inspects prompts and tool outputs and scores them.
LLM Guard ships [30+ input/output scanners](https://dev.to/agdex_ai/best-ai-agent-security-guardrails-tools-in-2026-llm-guard-vs-nemo-vs-guardrails-ai-5e5d);
Bedrock Guardrails offers six pre-trained harmful-content classifiers with
tunable thresholds.

**The structural problem.** Detection must recognise an attack to stop one,
and phrasing is unbounded. Giskard's 2026 survey puts it plainly: prompt
injection prevention is
[an unwinnable arms race, with even the best-defended models bypassed a
meaningful fraction of the time](https://www.giskard.ai/knowledge/ai-guardrails-comparison-2026).

**What we take from it.** Detection is genuinely useful as *telemetry*, and
the same survey notes most production agents run two or three of these
layered. SWARMS keeps a scanner in the box for exactly that — advisory,
never gating. Against our own 40-technique corpus the bundled regex scanner
flags **8%** while grounding refuses **100%**. That 8% is our own naive
scanner, not a commercial product; treat it as a floor for the category, not
as a score for anyone's vendor.

### 2. Policy engines — authorize the call by identity and resource

**AWS Cedar (in Bedrock AgentCore Policy, GA March 2026), Open Policy Agent /
Rego, Oso, Cerbos, Amazon Verified Permissions.**

This is the closest category commercially, and the most credible. Cedar sits
in the agent's Gateway and
[evaluates every tool call automatically](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/),
with default-deny, forbid-over-permit and order-independent evaluation.
Reported as [42–60× faster than Rego](https://www.osohq.com/learn/opa-vs-cedar-vs-zanzibar),
which also notes Rego's learning curve sits closer to Datalog than to YAML.

**The structural gap.** These engines decide on identity, action and resource
attributes. They do not track where an argument's *value* came from. A review
of AgentCore states the limitation directly: the policy layer
[enforces boundaries on what tools the agent can call, not what reasoning
leads it to call them](https://clawaws.com/blog/agentcore-policy-review/).
An agent holding a legitimate `email.send` grant, talked by a web page into
sending to the page's chosen address, satisfies every identity-based rule.
That is the confused-deputy problem, and it is the one SWARMS is for.

**What we take from it.** Nearly all of the shape: default-deny, declarative
configuration the operator owns, decisions as versioned auditable code, an
independent audit trail. These are settled good ideas and SWARMS implements
them rather than inventing alternatives.

**These are complements, not substitutes.** Cedar answers "may this identity
call this tool"; SWARMS answers "may this *value* steer it". Run both.

### 3. Architectural isolation — separate the trusted plan from untrusted data

**Google DeepMind CaMeL; the Dual-LLM pattern.**

The research ancestor of this project and the most rigorous work in the
space. CaMeL splits a Privileged LLM (plans from the trusted user query) from
a Quarantined LLM (handles untrusted data, no tool access), with a custom
interpreter tracking provenance and enforcing capabilities before each tool
call. It reports
[77% of tasks solved with provable security](https://simonwillison.net/2025/Apr/11/camel/).

**Why it has not shipped widely.** A retrospective ten months on found
[convincing real-world implementations remain limited](https://neuraltrust.ai/blog/camel-prompt-injection),
with the industry still relying largely on reactive defenses. The barriers
are practical: you must restructure your agent around the P-LLM/Q-LLM/
interpreter quartet — it is not plug-and-play — and the reported task
completion drops from 84% to 77%.

**What we take from it, and what we change.** The core idea is CaMeL's and we
say so: authority comes from the user's request, and data that was merely
read cannot become a command. What SWARMS changes is the delivery. There is
no rewrite: you add a decorator, or you point an MCP client at a gateway and
change nothing at all. The utility cost differs too, because only *control*
arguments are checked — an email body may quote a poisoned page freely. On
our corpus that is 100% containment with 0 false positives across 8 benign
control tasks (ours, measured, `swarms redteam`).

Note the asymmetry honestly: CaMeL's 77% is on a general agent benchmark
(AgentDojo) against an adaptive attacker. Ours is on a corpus we wrote. They
are not comparable numbers, and ours is the easier test.

### 4. MCP gateways — authenticate and route tool traffic

**Bifrost (Maxim AI), Docker MCP Gateway, Obot, Natoma, and the MCP spec's
own authorization section.**

MCP's authorization framework is OAuth 2.1-based and, by design,
[specifies how a server may authenticate a client, not which tools a given
identity should see or whether a call should execute](https://www.getmaxim.ai/articles/top-5-mcp-gateways-for-securing-agent-tool-access-in-2026/).
The exposure is not theoretical: Knostic scanned for public MCP servers and
found 1,862, with every one of the 119 sampled returning a full internal tool
listing to an unauthenticated request.

**What we take from it.** The deployment shape. A gateway is where an
enterprise can insert a control without touching agent code, so SWARMS ships
one (`swarms serve --mcp-upstream`). It targets MCP revision
[2026-07-28](https://blog.modelcontextprotocol.io/posts/2026-07-28/):
stateless request/response, `Mcp-Method` and `Mcp-Name` headers so a gateway
can authorize without parsing bodies, and Multi Round-Trip Requests, which we
use for human approval.

---

## The comparison

| | Detection | Cedar / OPA | CaMeL | MCP gateways | **SWARMS** |
|---|---|---|---|---|---|
| Stops an attack it has never seen | ✗ | ✓ | ✓ | n/a | ✓ |
| Knows where an argument's value came from | ✗ | ✗ | ✓ | ✗ | ✓ |
| Blocks a legitimately-granted tool being redirected | ✗ | ✗ | ✓ | ✗ | ✓ |
| Works without restructuring the agent | ✓ | ✓ | ✗ | ✓ | ✓ |
| Zero model calls on the enforcement path | ✗ | ✓ | ✗ | ✓ | ✓ |
| Human approval bound to specific arguments | ✗ | ✗ | ✗ | partial | ✓ |
| Mature, vendor-supported, broad deployment | ✓ | ✓ | ✗ | ✓ | ✗ |

The last row is the honest one. Cedar has AWS behind it. SWARMS does not.

---

## The claim, stated narrowly

> Provenance-aware authorization at the tool-call boundary, deployable
> without restructuring the agent, with the utility cost measured rather
> than assumed.

Each clause is doing work. *Provenance-aware* is what Cedar and OPA lack.
*Without restructuring* is what stopped CaMeL. *Utility measured* is the part
most security tools skip, and it is why the corpus carries 8 benign control
tasks whose false-positive rate is reported next to the containment rate — a
system that refuses everything scores 100% on containment and is worthless.

Academic work has converged on the same design: a 2026 survey describes
labelling values with provenance and raising a violation when a tool call's
arguments trace to an untrusted source, and notes this runtime taint tracking
for agent pipelines is
[at proposed status, with empirical validation requiring an agent-pipeline
fixture not yet constructed](https://arxiv.org/pdf/2604.18248). That fixture
is `swarms/redteam/` — 48 fixtures, 40 attacks across 15 technique families,
8 benign controls, reproducible with one command.

---

## Where SWARMS is weaker

Stated because a buyer will find these anyway.

- **`ingest()` is load-bearing.** Content that never enters the session
  cannot be recognised later. In SDK mode an uninstrumented source is a hole.
  The MCP gateway closes this for traffic it relays, which is why it is the
  recommended deployment.
- **Provenance is recovered by matching, not by dataflow.** We compare values
  against ingested text rather than tracking them through the model, because
  nothing survives a round trip through an LLM's weights. A value the model
  paraphrases (`"the address is a@b.com"` → `a.b@company.com`) is not matched.
  CaMeL's interpreter does not have this weakness; it pays for that with the
  rewrite.
- **Control-argument grounding does not stop exfiltration through a data
  argument.** An untrusted body sent to a trusted recipient is allowed by
  design. Closing that needs a read-label on the destination — full
  information-flow control — which we have not built.
- **One project, no vendor.** No SOC 2, no support contract, no 24/7.
- **SQLite audit store.** Right for a sidecar; a shared store is a rewrite of
  one class, but it is a rewrite.

## Reproducing our numbers

```bash
pip install swarms-guard
swarms redteam            # containment, utility, false positives, scanner recall
```

Nothing in that path calls a network service, so it produces the same figures
on your machine as on ours.
