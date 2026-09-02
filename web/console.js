// SWARMS operator console.
//
// Reads the gateway's own API, so everything shown here is the state the
// engine is actually in. No build step and no CDN: this is a self-hosted
// security tool, and an offline or CSP-restricted install has to work.

const $ = (id) => document.getElementById(id);
const KEY_STORAGE = "swarms.apiKey";

const state = {
  view: "overview",
  health: null,
  policy: null,
  redteam: null,
  autoTimer: null,
};

// ---------- transport ----------

function apiKey() {
  try { return localStorage.getItem(KEY_STORAGE) || ""; } catch { return ""; }
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  const key = apiKey();
  if (key) headers["Authorization"] = `Bearer ${key}`;

  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    promptForKey("This gateway requires an API key.");
    throw new Error("unauthorized");
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try { const body = await res.json(); detail = body.detail || detail; } catch { /* not json */ }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return res.headers.get("content-type")?.includes("json") ? res.json() : res.text();
}

function promptForKey(message = "API key for this gateway:") {
  const current = apiKey();
  const next = window.prompt(message, current);
  if (next === null) return;
  try { localStorage.setItem(KEY_STORAGE, next.trim()); } catch { /* private mode */ }
  refresh();
}

// ---------- helpers ----------

function esc(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
}

const EFFECT_PILL = { allow: "pill-ok", deny: "pill-bad", require_approval: "pill-warn" };
const pill = (text, cls) => `<span class="pill ${cls}">${esc(text)}</span>`;
const effectPill = (effect) => pill(effect, EFFECT_PILL[effect] || "pill-dim");

function shortTime(iso) {
  if (!iso) return "—";
  return iso.replace("T", " ").replace("Z", "").slice(0, 19);
}

function tile(value, label, sub = "", cls = "") {
  return `<div class="tile ${cls}"><div class="v">${esc(value)}</div>
          <div class="k">${esc(label)}</div>${sub ? `<div class="sub">${esc(sub)}</div>` : ""}</div>`;
}

function bars(rows, cls = "") {
  const max = Math.max(1, ...rows.map(r => r[1]));
  return rows.map(([label, n, hint]) => `
    <div class="bar-row">
      <span title="${esc(label)}">${esc(label)}</span>
      <span class="bar-track"><span class="bar-fill ${cls}" style="width:${(n / max) * 100}%"></span></span>
      <span class="n">${esc(hint ?? n)}</span>
    </div>`).join("");
}

function empty(colspan, text) {
  return `<tr><td class="empty" colspan="${colspan}">${esc(text)}</td></tr>`;
}

// ---------- navigation ----------

const TITLES = {
  overview: "Overview", decisions: "Decisions", approvals: "Approvals",
  policy: "Policy", redteam: "Red team", simulate: "Policy simulator",
};

function show(view) {
  state.view = view;
  document.querySelectorAll(".view").forEach(el => el.classList.toggle("active", el.id === `view-${view}`));
  document.querySelectorAll("#nav button").forEach(b =>
    b.setAttribute("aria-current", String(b.dataset.view === view)));
  $("viewTitle").textContent = TITLES[view] || view;
  refresh();
}

$("nav").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-view]");
  if (btn) show(btn.dataset.view);
});
$("refreshBtn").addEventListener("click", () => refresh());
$("keyBtn").addEventListener("click", () => promptForKey());
$("drawerClose").addEventListener("click", () => $("drawer").classList.remove("open"));
document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("drawer").classList.remove("open"); });

// ---------- health ----------

async function loadHealth() {
  const h = await api("api/health");
  state.health = h;
  $("footVersion").textContent = h.version;
  $("footAuth").textContent = h.auth;
  $("footSessions").textContent = h.open_sessions;
  $("footLlm").textContent = h.llm?.enabled ? `${h.llm.provider}:${h.llm.model}` : "deterministic";
  $("brandPolicy").textContent = `policy: ${h.policy.name}`;

  const badge = $("modeBadge");
  badge.textContent = h.enforcing ? "ENFORCING" : "OBSERVE ONLY";
  badge.className = `pill ${h.enforcing ? "pill-ok" : "pill-warn"}`;
  badge.title = h.enforcing
    ? "Decisions are enforced: denied calls do not happen."
    : "Decisions are computed and recorded, but nothing is blocked.";
  return h;
}

// ---------- overview ----------

async function loadOverview() {
  const stats = await api("api/stats?hours=24");
  const h = state.health || {};

  const banner = $("overviewBanner");
  const notes = [];
  if (h.enforcing === false) {
    notes.push("<b>Observe-only.</b> Decisions are being recorded but nothing is blocked. " +
               "Start with <code>swarms serve</code> (no <code>--observe</code>) to enforce.");
  }
  if (h.auth === "disabled") {
    notes.push("<b>No API key configured.</b> Every endpoint on this gateway is open. " +
               "Set <code>SWARMS_API_KEYS</code> before exposing it.");
  }
  banner.innerHTML = notes.join("<br>");
  banner.className = notes.length ? "banner bad" : "banner";

  $("overviewTiles").innerHTML = [
    tile(stats.total, "decisions, 24h"),
    tile(stats.denied, "refused", `${(stats.deny_rate * 100).toFixed(1)}% of calls`, stats.denied ? "bad" : ""),
    tile(`${stats.avg_latency_us.toFixed(0)}µs`, "avg decision", `max ${stats.max_latency_us}µs`, "good"),
    tile(stats.pending_approvals, "awaiting approval", "", stats.pending_approvals ? "warn" : ""),
  ].join("");

  const ruleRows = Object.entries(stats.denials_by_rule);
  $("ruleBars").innerHTML = ruleRows.length
    ? bars(ruleRows, "bad")
    : `<div class="mono-dim">Nothing refused in the last 24 hours.</div>`;

  $("actionRows").innerHTML = stats.by_action.length
    ? stats.by_action.map(a => `<tr>
        <td>${esc(a.action)}</td><td class="num">${a.total}</td><td class="num">${a.denied}</td>
        <td>${a.total ? ((a.denied / a.total) * 100).toFixed(0) : 0}%</td></tr>`).join("")
    : empty(4, "No decisions recorded yet. Point an agent at the gateway, or use the simulator.");

  $("approvalBadge").textContent = stats.pending_approvals || "";
}

// ---------- decisions ----------

function decisionFilters() {
  const params = new URLSearchParams({ limit: "200" });
  for (const [key, id] of [["effect", "fEffect"], ["action", "fAction"],
                           ["principal", "fPrincipal"], ["search", "fSearch"]]) {
    const value = $(id).value.trim();
    if (value) params.set(key, value);
  }
  return params;
}

async function loadDecisions() {
  const { decisions } = await api(`api/decisions?${decisionFilters()}`);
  $("decisionRows").innerHTML = decisions.length
    ? decisions.map((d, i) => `<tr class="clickable" data-i="${i}">
        <td class="mono-dim">${esc(shortTime(d.ts))}</td>
        <td>${effectPill(d.effect)}</td>
        <td>${esc(d.action)}</td>
        <td class="mono-dim">${esc(d.principal || "—")}</td>
        <td class="mono-dim">${esc(d.rule)}</td>
        <td class="wrap">${esc(d.reason)}</td>
        <td class="num mono-dim">${d.latency_us}</td></tr>`).join("")
    : empty(7, "No decisions match these filters.");

  $("decisionRows").onclick = (e) => {
    const row = e.target.closest("tr[data-i]");
    if (row) openDecision(decisions[Number(row.dataset.i)]);
  };
}

function openDecision(d) {
  $("drawerTitle").innerHTML = `${effectPill(d.effect)} ${esc(d.action)}`;
  const labels = Object.entries(d.arg_labels || {});
  $("drawerBody").innerHTML = `
    <dl class="kv">
      <dt>Time</dt><dd>${esc(d.ts)}</dd>
      <dt>Rule</dt><dd>${esc(d.rule)}</dd>
      <dt>Principal</dt><dd>${esc(d.principal || "—")}</dd>
      <dt>Session</dt><dd class="mono-dim">${esc(d.session_id || "—")}</dd>
      <dt>Enforced</dt><dd>${d.enforced ? "yes" : "no (observe-only)"}</dd>
      <dt>Latency</dt><dd>${d.latency_us}µs</dd>
    </dl>
    <h2>Reason</h2>
    <div class="code">${esc(d.reason)}</div>
    ${d.offending_span ? `
      <h2>Offending value</h2>
      <div class="code">${esc(d.offending_arg)} = ${esc(d.offending_span)}</div>` : ""}
    ${(d.provenance || []).length ? `
      <h2>Where it came from</h2>
      <ul class="trail">${d.provenance.map(p => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}
    ${labels.length ? `
      <h2>Argument labels</h2>
      <dl class="kv">${labels.map(([k, v]) =>
        `<dt>${esc(k)}</dt><dd>${pill(v, v === "UNTRUSTED" ? "pill-warn" : "pill-ok")}</dd>`).join("")}</dl>` : ""}`;
  $("drawer").classList.add("open");
}

["applyFilters"].forEach(id => $(id).addEventListener("click", () => loadDecisions()));
$("clearFilters").addEventListener("click", () => {
  ["fEffect", "fAction", "fPrincipal", "fSearch"].forEach(id => { $(id).value = ""; });
  loadDecisions();
});
$("fSearch").addEventListener("keydown", (e) => { if (e.key === "Enter") loadDecisions(); });
$("fAuto").addEventListener("change", scheduleAuto);

function scheduleAuto() {
  clearInterval(state.autoTimer);
  const ms = Number($("fAuto").value);
  if (ms) state.autoTimer = setInterval(() => { if (state.view === "decisions") loadDecisions(); }, ms);
}

// ---------- approvals ----------

async function loadApprovals() {
  const [pending, resolved] = await Promise.all([
    api("api/approvals?status=pending"),
    api("api/approvals?status=approved"),
  ]);

  $("approvalRows").innerHTML = pending.approvals.length
    ? pending.approvals.map(a => `<tr>
        <td class="mono-dim">${esc(shortTime(a.ts))}</td>
        <td>${esc(a.action)}</td>
        <td class="mono-dim">${esc(a.principal)}</td>
        <td class="wrap"><code>${esc(JSON.stringify(a.args))}</code></td>
        <td class="wrap mono-dim">${esc(a.reason)}</td>
        <td style="white-space:nowrap">
          <button class="btn btn-sm btn-ok" data-approve="${esc(a.id)}">Approve</button>
          <button class="btn btn-sm btn-bad" data-deny="${esc(a.id)}">Deny</button>
        </td></tr>`).join("")
    : empty(6, "Nothing is waiting for a human.");

  $("resolvedRows").innerHTML = resolved.approvals.length
    ? resolved.approvals.map(a => `<tr>
        <td class="mono-dim">${esc(shortTime(a.ts))}</td>
        <td>${esc(a.action)}</td>
        <td>${pill(a.status, a.status === "approved" ? "pill-ok" : "pill-dim")}</td>
        <td class="mono-dim">${esc(a.resolved_by || "—")}</td>
        <td class="wrap mono-dim">${esc(a.note || "")}</td></tr>`).join("")
    : empty(5, "Nothing resolved yet.");
}

$("approvalRows").addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-approve],[data-deny]");
  if (!btn) return;
  const approved = btn.hasAttribute("data-approve");
  const id = btn.dataset.approve || btn.dataset.deny;
  const by = window.prompt(`${approved ? "Approve" : "Deny"} as (your name or email):`, "");
  if (!by) return;
  const note = window.prompt("Note (optional):", "") || "";
  btn.disabled = true;
  try {
    await api(`api/approvals/${id}`, { method: "POST", body: JSON.stringify({ approved, by, note }) });
    await loadApprovals();
    await loadOverview();
  } catch (err) {
    alert(`Could not resolve: ${err.message}`);
    btn.disabled = false;
  }
});

// ---------- policy ----------

async function loadPolicy() {
  const p = await api("api/policy");
  state.policy = p;
  $("policyPath").textContent = p.source_path || "(built-in default policy)";

  const lint = $("policyLint");
  lint.innerHTML = p.lint.length
    ? `<b>${p.lint.length} advisory:</b><br>` + p.lint.map(esc).join("<br>")
    : "";
  lint.className = p.lint.length ? "banner" : "banner";

  $("actionCards").innerHTML = Object.values(p.actions).map(a => `
    <div class="card">
      <h4>${esc(a.name)} ${a.require_approval ? pill("approval", "pill-warn") : ""}</h4>
      <div class="desc">${esc(a.description || "")}</div>
      <div class="row"><span>capability</span><code>${esc(a.capability)}</code></div>
      <div class="row"><span>control args</span>${
        a.control_args.length
          ? a.control_args.map(x => `<span class="tag control">${esc(x)}</span>`).join("")
          : `<span class="pill pill-bad">none — nothing is grounded</span>`}</div>
      <div class="row"><span>data args</span>${
        a.data_args.map(x => `<span class="tag data">${esc(x)}</span>`).join("") || "<span class='mono-dim'>—</span>"}</div>
    </div>`).join("");

  $("principalCards").innerHTML = Object.values(p.principals).map(pr => `
    <div class="card">
      <h4>${esc(pr.name)}</h4>
      <div class="desc">${esc(pr.description || "")}</div>
      <div class="row">${
        pr.capabilities.length
          ? pr.capabilities.map(c => `<span class="tag ${c.includes("*") ? "control" : "data"}">${esc(c)}</span>`).join("")
          : `<span class="pill pill-dim">no authority</span>`}</div>
    </div>`).join("");

  populateSimulator(p);
}

$("reloadPolicyBtn").addEventListener("click", async (e) => {
  e.target.disabled = true;
  try {
    const out = await api("api/policy/reload", { method: "POST" });
    await loadPolicy();
    alert(`Reloaded '${out.policy}': ${out.actions} actions.`);
  } catch (err) {
    alert(`Reload refused, the running policy is unchanged:\n\n${err.message}`);
  } finally {
    e.target.disabled = false;
  }
});

// ---------- red team ----------

async function loadRedteam() {
  let report;
  try {
    report = await api("api/redteam");
  } catch {
    $("redteamBanner").className = "banner";
    $("redteamBanner").innerHTML =
      "No report yet. Run the suite below, or from a shell with <code>swarms redteam --web-dir web/data</code>.";
    $("redteamTiles").innerHTML = "";
    $("categoryBars").innerHTML = "";
    $("redteamRows").innerHTML = empty(6, "No results.");
    return;
  }
  state.redteam = report;
  renderRedteam(report);
}

function renderRedteam(report) {
  const s = report.summary;
  $("redteamMeta").textContent = `${s.generated_at} · policy '${s.policy}' · ${s.duration_seconds}s`;

  const failed = s.failures.length > 0;
  $("redteamBanner").className = `banner ${failed ? "bad" : "ok"}`;
  $("redteamBanner").innerHTML = failed
    ? `<b>${s.failures.length} failure(s).</b> ` + s.failures.map(f =>
        `${esc(f.attack_id)} (${esc(f.kind)})`).join(", ")
    : `<b>This policy holds.</b> Every attack in the corpus was refused and every legitimate task
       still completed. The regex scanner alone would have caught
       ${s.scanner_would_flag}/${s.total_attacks}, which is the argument for not relying on detection.`;

  $("redteamTiles").innerHTML = [
    tile(`${(s.containment_rate * 100).toFixed(0)}%`, "attacks refused",
         `${s.total_attacks - s.attacks_through_protected}/${s.total_attacks}`,
         s.containment_rate === 1 ? "good" : "bad"),
    tile(`${(s.utility_retained * 100).toFixed(0)}%`, "legitimate work still runs",
         `${s.benign_completed}/${s.benign_authorized}`, s.utility_retained === 1 ? "good" : "bad"),
    tile(s.false_positives, "false positives", "", s.false_positives ? "bad" : "good"),
    tile(`${(s.scanner_recall * 100).toFixed(0)}%`, "regex scanner recall", "for comparison", "warn"),
  ].join("");

  // "as expected" rather than "contained": refusing is the right outcome for
  // an attack and the wrong one for a legitimate task.
  const cats = Object.entries(s.by_category)
    .map(([name, c]) => [name, c.as_expected, `${c.as_expected}/${c.total}`]);
  $("categoryBars").innerHTML = bars(cats, "ok");

  $("redteamRows").innerHTML = report.results.map((r, i) => `
    <tr class="clickable" data-i="${i}">
      <td class="mono-dim">${esc(r.attack_id)}</td>
      <td>${esc(r.name)}</td>
      <td class="mono-dim">${esc(r.category)}</td>
      <td>${r.unprotected.executed ? pill("landed", "pill-bad") : pill("no-op", "pill-dim")}</td>
      <td>${r.protected.executed
            ? pill(r.intent === "benign" ? "completed" : "GOT THROUGH", r.intent === "benign" ? "pill-ok" : "pill-bad")
            : pill("refused", "pill-ok")}</td>
      <td class="wrap mono-dim">${esc(r.protected.rule)}</td></tr>`).join("");

  $("redteamRows").onclick = (e) => {
    const row = e.target.closest("tr[data-i]");
    if (row) openFixture(report.results[Number(row.dataset.i)]);
  };
}

function openFixture(r) {
  $("drawerTitle").innerHTML = `${esc(r.attack_id)} <span class="mono-dim">${esc(r.category)}</span>`;
  $("drawerBody").innerHTML = `
    <dl class="kv">
      <dt>Technique</dt><dd>${esc(r.name)}</dd>
      <dt>Intent</dt><dd>${esc(r.intent)}</dd>
      <dt>Unprotected</dt><dd>${r.unprotected.executed
        ? `sent to <code>${esc(r.unprotected.recipient)}</code> ${pill(r.unprotected.label, "pill-warn")}`
        : "did not fire"}</dd>
      <dt>Enforced</dt><dd>${r.protected.executed
        ? pill("allowed", r.intent === "benign" ? "pill-ok" : "pill-bad")
        : pill("refused", "pill-ok")}</dd>
    </dl>
    <h2>Document the agent read</h2>
    <div class="code">${esc(r.document_text)}</div>
    <h2>Decision</h2>
    <div class="code">${esc(r.protected.reason)}</div>
    ${r.protected.offending_span ? `
      <h2>Offending value</h2>
      <div class="code">${esc(r.protected.offending_arg)} = ${esc(r.protected.offending_span)}</div>` : ""}
    ${(r.protected.provenance || []).length ? `
      <h2>Where the recipient came from</h2>
      <ul class="trail">${r.protected.provenance.map(p => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}
    <h2>Regex scanner, for comparison</h2>
    <div class="code">score ${r.scanner.score} · ${
      r.scanner.findings.length ? esc(r.scanner.findings.join(", ")) : "no rule matched"}</div>
    ${r.notes ? `<h2>Notes</h2><div class="mono-dim">${esc(r.notes)}</div>` : ""}`;
  $("drawer").classList.add("open");
}

$("runRedteamBtn").addEventListener("click", async (e) => {
  e.target.disabled = true;
  e.target.textContent = "Running…";
  try {
    await api("api/redteam/run", { method: "POST" });
    await loadRedteam();
  } catch (err) {
    alert(`Could not run the suite: ${err.message}`);
  } finally {
    e.target.disabled = false;
    e.target.textContent = "Run suite against this policy";
  }
});

// ---------- simulator ----------

function populateSimulator(policy) {
  const principalSel = $("simPrincipal");
  const actionSel = $("simAction");
  if (principalSel.options.length && actionSel.options.length) return; // already built

  principalSel.innerHTML = Object.keys(policy.principals)
    .map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join("");
  actionSel.innerHTML = Object.keys(policy.actions)
    .map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join("");

  const preferred = { principal: "agent3_emailer", action: "send_email" };
  if (policy.principals[preferred.principal]) principalSel.value = preferred.principal;
  if (policy.actions[preferred.action]) actionSel.value = preferred.action;

  actionSel.addEventListener("change", renderSimArgs);
  renderSimArgs();
}

function renderSimArgs() {
  const action = state.policy?.actions?.[$("simAction").value];
  if (!action) { $("simArgs").innerHTML = ""; return; }
  const rows = [
    ...action.control_args.map(a => [a, true]),
    ...action.data_args.map(a => [a, false]),
  ];
  $("simArgs").innerHTML = rows.map(([name, isControl]) => `
    <div class="arg-row">
      <span class="${isControl ? "tag control" : "tag data"}" title="${
        isControl ? "Control argument: must trace to trusted data" : "Data argument: may carry untrusted content"
      }">${esc(name)}</span>
      <input type="text" data-arg="${esc(name)}" placeholder="${isControl ? "value that steers the action" : "content"}">
    </div>`).join("");
}

$("simFill").addEventListener("click", () => {
  // Pull the first address out of the pasted content, which is what a
  // cooperative agent would do with it. Saves retyping it into the argument.
  const match = $("simContent").value.match(/[^\s<>@,;:"'()[\]{}]+@[^\s<>@,;:"'()[\]{}]+\.[^\s<>@,;:"'()[\]{}]{2,}/);
  const first = document.querySelector("#simArgs input[data-arg]");
  if (match && first) first.value = match[0].replace(/[.,;:!?)\]}>'"]+$/, "");
  const body = document.querySelector('#simArgs input[data-arg="body"]');
  if (body) body.value = $("simContent").value.slice(0, 200);
});

$("simRun").addEventListener("click", async (e) => {
  const out = $("simResult");
  e.target.disabled = true;
  out.innerHTML = `<div class="mono-dim">Checking…</div>`;
  try {
    const authority = $("simAuthority").value.trim();
    const session = await api("v1/sessions", {
      method: "POST",
      body: JSON.stringify({
        principal: $("simPrincipal").value,
        user: "console",
        authority: authority ? authority.split(",").map(s => s.trim()).filter(Boolean) : null,
      }),
    });

    const content = $("simContent").value.trim();
    if (content) {
      await api(`v1/sessions/${session.session_id}/ingest`, {
        method: "POST",
        body: JSON.stringify({ content, source: "console:pasted_content" }),
      });
    }
    for (const line of $("simTrusted").value.split("\n").map(s => s.trim()).filter(Boolean)) {
      await api(`v1/sessions/${session.session_id}/trust`, {
        method: "POST", body: JSON.stringify({ value: line, source: "console:human_supplied" }),
      });
    }

    const args = {};
    document.querySelectorAll("#simArgs input[data-arg]").forEach(i => {
      if (i.value.trim()) args[i.dataset.arg] = i.value;
    });

    const decision = await api("v1/authorize", {
      method: "POST",
      body: JSON.stringify({
        session_id: session.session_id,
        action: $("simAction").value,
        arguments: args,
        from_model: true,
      }),
    });
    await api(`v1/sessions/${session.session_id}`, { method: "DELETE" }).catch(() => {});

    out.innerHTML = renderSimDecision(decision);
    loadOverview().catch(() => {});
  } catch (err) {
    out.innerHTML = `<div class="banner bad">${esc(err.message)}</div>`;
  } finally {
    e.target.disabled = false;
  }
});

function renderSimDecision(d) {
  const labels = Object.entries(d.arg_labels || {});
  return `
    <div class="banner ${d.allowed ? "ok" : "bad"}">
      ${effectPill(d.effect)} <b>${d.allowed ? "would proceed" : "would be refused"}</b>
      &nbsp;<span class="mono-dim">rule: ${esc(d.rule)}</span>
    </div>
    <div class="code">${esc(d.reason)}</div>
    ${d.offending_span ? `
      <h2>Offending value</h2>
      <div class="code">${esc(d.offending_arg)} = ${esc(d.offending_span)}</div>` : ""}
    ${(d.offending_provenance || []).length ? `
      <h2>Traced to</h2>
      <ul class="trail">${d.offending_provenance.map(p => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}
    ${labels.length ? `
      <h2>Argument labels</h2>
      <dl class="kv">${labels.map(([k, v]) =>
        `<dt>${esc(k)}</dt><dd>${pill(v, v === "UNTRUSTED" ? "pill-warn" : "pill-ok")}</dd>`).join("")}</dl>` : ""}
    ${d.note ? `<div class="mono-dim">${esc(d.note)}</div>` : ""}`;
}

// ---------- refresh ----------

const LOADERS = {
  overview: loadOverview, decisions: loadDecisions, approvals: loadApprovals,
  policy: loadPolicy, redteam: loadRedteam, simulate: async () => { if (!state.policy) await loadPolicy(); },
};

async function refresh() {
  try {
    await loadHealth();
    await (LOADERS[state.view] || (() => {}))();
    $("lastRefresh").textContent = new Date().toLocaleTimeString([], { hour12: false });
  } catch (err) {
    if (err.message !== "unauthorized") console.error(err);
  }
}

refresh();
scheduleAuto();
setInterval(() => { if (state.view === "overview") loadOverview().catch(() => {}); }, 15000);
