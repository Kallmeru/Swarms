// SWARMS frontend.
//
// Runs in one of two modes and figures out which on its own:
//
//   LIVE    a backend answered /api/health, so every run is executed on
//           demand by the real pipeline, including on text a visitor types.
//   REPLAY  no backend (the static GitHub Pages build), so it animates the
//           traces benchmark/run_benchmark.py wrote into web/data/.
//
// The event format is identical either way, which is the only reason one set
// of rendering code can serve both.

const NODES = [
  { id: 'doc',    label: 'Poisoned\nDocument', shape: 'box' },
  { id: 'agent1', label: 'Agent 1\nReader',    shape: 'ellipse' },
  { id: 'agent2', label: 'Agent 2\nAnalyst',   shape: 'ellipse' },
  { id: 'agent3', label: 'Agent 3\nEmailer',   shape: 'ellipse' },
  { id: 'action', label: 'Send Email\nAction', shape: 'box' },
];
const EDGES = [
  { id: 'e_doc_a1', from: 'doc',    to: 'agent1' },
  { id: 'e_a1_a2',  from: 'agent1', to: 'agent2' },
  { id: 'e_a2_a3',  from: 'agent2', to: 'agent3' },
  { id: 'e_a3_act', from: 'agent3', to: 'action' },
];
const NEUTRAL = '#6B5F50', TRUSTED = '#6FA184', UNTRUSTED = '#D3A24E', BLOCKED = '#D6543F';
const CREAM = '#F3E7D3';

const AGENT_TO_NODE = { agent1_reader: 'agent1', agent2_analyst: 'agent2', agent3_emailer: 'agent3' };
const AGENT_TO_HANDOFF_EDGE = { agent1_reader: 'e_a1_a2', agent2_analyst: 'e_a2_a3' };

const $ = (id) => document.getElementById(id);

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : str;
  return div.innerHTML;
}

// ---------- transport ----------

const API = { live: false, health: null };

async function detectBackend() {
  try {
    const res = await fetch('api/health', { cache: 'no-store' });
    if (!res.ok) throw new Error(res.status);
    API.health = await res.json();
    API.live = true;
  } catch {
    API.live = false;
    // The failed probe above shows up in devtools as a 404. Say why, so
    // anyone who opens the console on the static build sees a deliberate
    // feature check rather than a broken request.
    console.info('SWARMS: no backend at /api/health, running in REPLAY mode. The 404 above is that check. Run `python -m server` for live mode.');
  }
  renderMode();
  return API.live;
}

function renderMode() {
  const badge = $('modeBadge');
  if (!badge) return;
  if (API.live) {
    const llm = API.health && API.health.llm && API.health.llm.enabled
      ? `${API.health.llm.provider}:${API.health.llm.model}`
      : 'deterministic agents';
    badge.textContent = 'ENGINE: LIVE';
    badge.title = `Runs are executed on request by the real pipeline (${llm}).`;
    badge.classList.add('mode-live');
  } else {
    badge.textContent = 'ENGINE: REPLAY';
    badge.title = 'No backend reachable, animating traces recorded by benchmark/run_benchmark.py.';
    badge.classList.remove('mode-live');
  }
  document.querySelectorAll('[data-requires-live]').forEach(el => {
    el.classList.toggle('needs-backend', !API.live);
    el.querySelectorAll('button, textarea, input').forEach(c => { c.disabled = !API.live; });
  });
}

async function postRun(body) {
  const res = await fetch('api/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch { /* body was not json */ }
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
  }
  return res.json();
}

async function loadManifest() {
  if (API.live) {
    const data = await (await fetch('api/attacks')).json();
    return data.fixtures;
  }
  const res = await fetch('data/manifest.json');
  if (!res.ok) throw new Error(`manifest.json: ${res.status}`);
  return res.json();
}

// Static replay reads the two recorded traces; live mode executes both runs
// server-side. Same shape out either way so nothing downstream branches.
async function runAttack(attackId) {
  if (API.live) return postRun({ attack_id: attackId });
  const [off, on] = await Promise.all(['off', 'on'].map(mode =>
    fetch(`data/${attackId}_${mode}.json`).then(r => {
      if (!r.ok) throw new Error(`${attackId}_${mode}.json: ${r.status}`);
      return r.json();
    })));
  return { off: { events: off }, on: { events: on } };
}

// ---------- graph ----------

function makeGraph(containerId) {
  const container = $(containerId);
  const nodes = new vis.DataSet(NODES.map(n => ({ ...n, color: { background: '#241D16', border: NEUTRAL, highlight: { background: '#241D16', border: NEUTRAL } } })));
  const edges = new vis.DataSet(EDGES.map(e => ({ ...e, color: NEUTRAL, width: 2, arrows: 'to' })));
  const network = new vis.Network(container, { nodes, edges }, {
    physics: false,
    layout: { hierarchical: { direction: 'LR', sortMethod: 'directed', nodeSpacing: 120, levelSeparation: 120 } },
    nodes: { font: { size: 11, face: 'ui-monospace, "SF Mono", monospace', color: CREAM }, borderWidth: 1.5, shapeProperties: { borderRadius: 6 } },
    edges: { smooth: { type: 'cubicBezier', roundness: 0.35 } },
    interaction: { dragNodes: false, zoomView: false },
  });
  return { network, nodes, edges };
}

function nodeColor(borderColor) {
  return { background: '#241D16', border: borderColor, highlight: { background: '#241D16', border: borderColor } };
}

function resetGraph(graph) {
  NODES.forEach(n => graph.nodes.update({ id: n.id, color: nodeColor(NEUTRAL), borderWidth: 1.5 }));
  EDGES.forEach(e => graph.edges.update({ id: e.id, color: NEUTRAL, width: 2, dashes: false }));
}

// ---------- event rendering ----------

// A running trace next to the graph. The graph shows what happened, this
// shows what the engine said while it happened, which is what anyone
// evaluating a security tool actually wants to read.
function trace(ctx, text, kind) {
  if (!ctx.traceEl) return;
  const li = document.createElement('li');
  li.className = `trace-line${kind ? ' trace-' + kind : ''}`;
  li.textContent = text;
  ctx.traceEl.appendChild(li);
  ctx.traceEl.scrollTop = ctx.traceEl.scrollHeight;
}

function applyEvent(evt, graph, ctx) {
  const nodeId = AGENT_TO_NODE[evt.agent];
  const d = evt.data || {};

  switch (evt.type) {
    case 'RUN_START':
      // Live runs declare intent and shield mode up front, which is what
      // lets "the action executed" be read correctly: the same event means
      // a worm succeeded on an attack and a job completed on a real task.
      ctx.intent = d.intent || ctx.intent;
      ctx.shield = d.shield || ctx.shield;
      trace(ctx, `run ${d.attack_id} | shield ${ctx.shield} | authorized: ${(d.authorized_actions || []).join(', ') || 'nothing'}`);
      break;

    case 'AGENT_START': {
      if (!nodeId) break;
      const untrusted = (d.inputs || []).some(i => i.label === 'UNTRUSTED');
      graph.nodes.update({ id: nodeId, color: nodeColor(untrusted ? UNTRUSTED : TRUSTED), borderWidth: 2.5 });
      trace(ctx, `${evt.agent} starts, input ${untrusted ? 'UNTRUSTED' : 'TRUSTED'}`);
      break;
    }

    case 'TOOL_RESULT':
      // An agent that reads untrusted output is contaminated for the rest of
      // its turn even if it began from a trusted instruction. This is Agent 1
      // visibly catching it from the document.
      if (nodeId && d.label === 'UNTRUSTED') {
        graph.nodes.update({ id: nodeId, color: nodeColor(UNTRUSTED), borderWidth: 2.5 });
        trace(ctx, `${evt.agent} read ${d.tool} -> UNTRUSTED`, 'warn');
      }
      break;

    case 'CAPABILITY_ATTENUATED':
      trace(ctx, `capability stripped at boundary: ${(d.removed || []).join(', ')} removed from ${d.agent}`, 'warn');
      break;

    case 'AGENT_HANDOFF': {
      const edgeId = AGENT_TO_HANDOFF_EDGE[evt.agent];
      if (!edgeId) break;
      if (d.directive_requested && !d.directive_allowed) {
        graph.edges.update({ id: edgeId, color: BLOCKED, width: 3, dashes: [6, 4] });
        const label = edgeId === 'e_a1_a2' ? 'Agent 1 to Agent 2' : 'Agent 2 to Agent 3';
        contained(ctx, `at ${label}`, d.reason, d.directive_requested, 'Poisoned instruction');
      } else {
        graph.edges.update({ id: edgeId, color: d.data_label === 'UNTRUSTED' ? UNTRUSTED : TRUSTED, width: 3 });
        trace(ctx, `${evt.agent} -> ${d.to}: data crosses as ${d.data_label}, authority does not`);
      }
      break;
    }

    case 'RECIPIENT_RESOLVED':
      ctx.recipient = d;
      trace(ctx,
        `recipient resolved: ${d.recipient} [${d.label}] via ${(d.provenance || []).join(' -> ')}`,
        d.label === 'UNTRUSTED' ? 'warn' : null);
      renderRecipient(ctx);
      break;

    case 'ACTION_ALLOWED': {
      if (d.action !== 'send_email') break;
      const worm = ctx.shield === 'off' && ctx.intent !== 'benign';
      graph.edges.update({ id: 'e_a3_act', color: worm ? BLOCKED : TRUSTED, width: 4 });
      graph.nodes.update({ id: 'action', color: nodeColor(worm ? BLOCKED : TRUSTED), borderWidth: 2.5 });
      if (worm) {
        ctx.statusEl.innerHTML = '<b>WORM SUCCEEDED</b>: the injected instruction chose the recipient, and the mail went out.';
        ctx.statusEl.className = 'status leaked';
        trace(ctx, `ACTION_ALLOWED send_email -> ${(d.args || {}).to} (no enforcement)`, 'bad');
        if (window.SwarmsSound) SwarmsSound.playWormSucceeded();
      } else {
        ctx.statusEl.innerHTML = '<span class="seal-badge">&#10003;</span><b>DELIVERED</b>: legitimate task completed.';
        ctx.statusEl.className = 'status delivered';
        trace(ctx, `ACTION_ALLOWED send_email -> ${(d.args || {}).to} (${d.reason})`, 'good');
      }
      break;
    }

    case 'ACTION_BLOCKED':
      graph.edges.update({ id: 'e_a3_act', color: BLOCKED, width: 3, dashes: [6, 4] });
      contained(ctx, 'at the privileged action', d.reason, d.offending_span, 'Offending value');
      trace(ctx, `ACTION_BLOCKED ${d.action}: ${d.reason}`, 'good');
      break;

    // Ablaze's regex scanner, scoring the same document independently. It
    // never gates anything. It is shown because it sometimes misses attacks
    // that containment still stops, which is the argument against building a
    // defense out of detection.
    case 'SCANNER_RESULT': {
      const panel = $('scanner-panel');
      if (!panel) break;
      const verdict = d.flagged
        ? '<span class="scanner-flagged">FLAGGED</span>'
        : '<span class="scanner-clear">not flagged</span>';
      const matched = (d.findings || []).length
        ? ` &middot; matched: ${d.findings.map(escapeHtml).join(', ')}`
        : ' &middot; no rule matched';
      panel.innerHTML = `<b>Attack-lab scanner:</b> score ${Math.round(d.score * 100)}% &middot; ${verdict}${matched}`;
      break;
    }

    case 'SCANNER_ALERT_PREVIEW': {
      const el = $('alert-preview');
      if (!el) break;
      el.innerHTML =
        '<div class="alert-preview-header">Alert email &mdash; preview, not sent</div>' +
        `<div class="alert-preview-meta"><b>To:</b> ${escapeHtml(d.to)}<br><b>From:</b> ${escapeHtml(d.from)}<br><b>Subject:</b> ${escapeHtml(d.subject)}</div>` +
        `<div class="alert-preview-body">${escapeHtml(d.body)}</div>`;
      break;
    }
  }
}

function contained(ctx, where, reason, span, spanLabel) {
  ctx.statusEl.innerHTML = `<span class="seal-badge">&#10003;</span><b>CONTAINED</b> ${where}`;
  ctx.statusEl.className = 'status blocked';
  const reasonEl = $('reason-panel');
  if (reasonEl) {
    reasonEl.innerHTML = `<b>Reason:</b> ${escapeHtml(reason || '')}` +
      (span ? `<br><b>${spanLabel}:</b> "<i>${escapeHtml(span)}</i>"` : '');
  }
  if (window.SwarmsSound) SwarmsSound.playContained();
}

function renderRecipient(ctx) {
  const el = $(`recipient-${ctx.shield}`);
  if (!el || !ctx.recipient) return;
  const r = ctx.recipient;
  el.innerHTML = `<span class="chip chip-${r.label === 'UNTRUSTED' ? 'untrusted' : 'trusted'}">${r.label}</span>` +
    `<code>${escapeHtml(r.recipient)}</code>`;
}

async function playSequence(events, graph, statusEl, traceEl, shield, intent, delayMs) {
  const ctx = { statusEl, traceEl, shield, intent, recipient: null };
  resetGraph(graph);
  statusEl.innerHTML = '';
  statusEl.className = 'status';
  if (traceEl) traceEl.innerHTML = '';
  const recipientEl = $(`recipient-${shield}`);
  if (recipientEl) recipientEl.innerHTML = '';
  // the document is always the untrusted seed
  graph.nodes.update({ id: 'doc', color: nodeColor(UNTRUSTED), borderWidth: 2.5 });

  for (const evt of events) {
    await new Promise(r => setTimeout(r, delayMs));
    try {
      applyEvent(evt, graph, ctx);
    } catch (err) {
      console.error('failed to apply event', evt, err);
    }
  }
}

// ---------- controls ----------

const graphOff = makeGraph('graph-off');
const graphOn = makeGraph('graph-on');
const loadErrorEl = $('loadError');
let manifest = [];

function selectedFixture() {
  const id = $('attackPicker').value;
  return manifest.find(a => a.attack_id === id) || {};
}

function showPayload() {
  const el = $('payload-panel');
  const fixture = selectedFixture();
  if (!el || !fixture.document_text) { if (el) el.innerHTML = ''; return; }
  el.innerHTML =
    `<div class="payload-task"><b>Human's task:</b> ${escapeHtml(fixture.user_task || '')}</div>` +
    `<div class="payload-doc"><b>Document the reader ingests:</b><br>${escapeHtml(fixture.document_text)}</div>` +
    (fixture.notes ? `<div class="payload-note">${escapeHtml(fixture.notes)}</div>` : '');
}

async function play(source) {
  loadErrorEl.textContent = '';
  const reasonEl = $('reason-panel');
  if (reasonEl) reasonEl.innerHTML = '';
  ['scanner-panel', 'alert-preview'].forEach(id => { const el = $(id); if (el) el.innerHTML = ''; });
  if (window.SwarmsSound) SwarmsSound.playAttackStart();

  const btn = $('playBtn');
  btn.disabled = true;
  btn.textContent = 'Running...';
  try {
    const result = await source();
    const intent = (result.attack && result.attack.intent) || selectedFixture().intent || 'malicious';
    await Promise.all([
      playSequence(result.off.events, graphOff, $('status-off'), $('trace-off'), 'off', intent, 500),
      playSequence(result.on.events, graphOn, $('status-on'), $('trace-on'), 'on', intent, 500),
    ]);
  } catch (err) {
    loadErrorEl.textContent = `Run failed: ${err.message}`;
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Attack';
  }
}

$('playBtn').onclick = () => play(() => runAttack($('attackPicker').value));

// ---------- live console: run the pipeline on text the visitor supplies ----------

const consoleForm = $('consoleForm');
if (consoleForm) {
  consoleForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const out = $('consoleResult');
    const btn = $('consoleRun');
    out.innerHTML = '<div class="console-pending">Running both pipelines...</div>';
    btn.disabled = true;
    try {
      const result = await postRun({
        document_text: $('consoleDoc').value,
        user_task: $('consoleTask').value || undefined,
        task_recipient: $('consoleRecipient').value,
        authorize_send: $('consoleAuthorize').checked,
      });
      out.innerHTML = renderConsoleResult(result);
      if (window.SwarmsSound) SwarmsSound.playContained();
    } catch (err) {
      out.innerHTML = `<div class="console-error">${escapeHtml(err.message)}</div>`;
    } finally {
      btn.disabled = false;
    }
  });
}

function renderConsoleResult(result) {
  const row = (mode) => {
    const r = result[mode];
    const blocked = (r.events.find(e => e.type === 'ACTION_BLOCKED') || {}).data || {};
    const executed = r.malicious_action_executed;
    const verdict = executed
      ? `<span class="chip chip-untrusted">SENT</span>`
      : `<span class="chip chip-trusted">BLOCKED</span>`;
    return `<div class="console-row">
      <div class="console-row-head">Shield ${mode.toUpperCase()} ${verdict}</div>
      <div class="console-kv"><span>recipient</span><code>${escapeHtml(r.recipient)}</code>
        <span class="chip chip-${r.recipient_label === 'UNTRUSTED' ? 'untrusted' : 'trusted'}">${r.recipient_label}</span></div>
      ${blocked.reason ? `<div class="console-kv"><span>reason</span><em>${escapeHtml(blocked.reason)}</em></div>` : ''}
      ${blocked.offending_span ? `<div class="console-kv"><span>offending</span><code>${escapeHtml(blocked.offending_span)}</code></div>` : ''}
      <div class="console-kv"><span>outbox</span><code>${r.outbox.length} recorded, 0 delivered</code></div>
    </div>`;
  };
  const hijacked = result.off.recipient_label === 'UNTRUSTED';
  return `<div class="console-verdict">${hijacked
    ? 'Your text hijacked the unprotected pipeline. Under the shield it did not.'
    : 'Your text did not redirect the unprotected pipeline, so both runs behaved the same.'}</div>`
    + row('off') + row('on');
}

// ---------- startup ----------

detectBackend()
  .then(loadManifest)
  .then(list => {
    manifest = list;
    const sel = $('attackPicker');
    list.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a.attack_id;
      opt.textContent = `${a.attack_id}: ${a.name} (${a.category})`;
      sel.appendChild(opt);
    });

    // Visual attack picker: a curved wheel kept in sync with the real
    // <select> above (attackPicker stays the source of truth playBtn reads
    // from, and the fully accessible fallback for keyboard/screen readers).
    const wheelEl = $('attackWheel');
    if (wheelEl && list.length && typeof initOptionWheel === 'function') {
      const wheel = initOptionWheel(wheelEl, list.map(a => a.attack_id), {
        onChange: (index) => {
          sel.value = list[index].attack_id;
          sel.dispatchEvent(new Event('change'));
        },
      });
      sel.addEventListener('change', () => {
        const index = list.findIndex(a => a.attack_id === sel.value);
        if (index >= 0) wheel.select(index);
      });
    }
    sel.addEventListener('change', showPayload);
    showPayload();
  })
  .catch(err => { loadErrorEl.textContent = `Could not load the attack list: ${err.message}`; });

// Constructing Chart.js against a canvas that's still display:none (the
// window hasn't been opened yet) leaves it permanently stuck at 0x0, even a
// later resize() can't recover it, only building a fresh instance does. So
// this waits for the data AND builds the chart lazily on first open instead
// of at page load.
let benchmarkChart = null;
let benchmarkSummary = null;

fetch('data/benchmark_summary.json')
  .then(r => r.json())
  .then(summary => { benchmarkSummary = summary; renderBenchmarkStats(); ensureBenchmarkChart(); })
  .catch(err => { loadErrorEl.textContent = `Could not load benchmark_summary.json: ${err.message}`; });

function renderBenchmarkStats() {
  const el = $('benchmarkStats');
  if (!el || !benchmarkSummary) return;
  const s = benchmarkSummary;
  el.innerHTML = [
    ['attacks contained', `${s.total_attacks - s.attacks_succeeded_shield_on}/${s.total_attacks}`],
    ['benign tasks still completed', `${s.benign_completed_shield_on}/${s.benign_authorized}`],
    ['false positives', String(s.false_positives)],
    ['wall clock', `${s.duration_seconds}s for ${s.total_fixtures * 2} runs`],
  ].map(([k, v]) => `<div class="bm-stat"><span>${k}</span><b>${escapeHtml(v)}</b></div>`).join('');
}

function ensureBenchmarkChart() {
  if (benchmarkChart || !benchmarkSummary) return;
  const canvas = $('benchmarkChart');
  if (canvas.getBoundingClientRect().width === 0) return; // still hidden, openWindow() calls this again once it's visible
  const s = benchmarkSummary;
  benchmarkChart = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: ['Attacks succeed\nshield OFF', 'Attacks succeed\nshield ON', 'Benign work\ncompletes, shield ON'],
      datasets: [{
        label: `n=${s.total_attacks} attacks, ${s.benign_authorized} benign`,
        data: [
          s.shield_off_success_rate * 100,
          s.shield_on_success_rate * 100,
          (s.utility_retained !== undefined ? s.utility_retained : 1) * 100,
        ],
        backgroundColor: [BLOCKED, TRUSTED, TRUSTED],
        borderRadius: 4,
      }],
    },
    options: {
      scales: {
        y: { beginAtZero: true, max: 100, ticks: { callback: v => v + '%', color: '#A0917E' }, grid: { color: 'rgba(243,231,211,0.12)' } },
        x: { ticks: { color: '#A0917E', font: { size: 9 } }, grid: { display: false } },
      },
      plugins: { legend: { display: false } },
    },
  });
}

// ---------- menu bar clock ----------

function tickClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString([], { hour12: false });
}
tickClock();
setInterval(tickClock, 1000);

// ---------- sound effects: taps/clicks and the mute toggle ----------

if (window.SwarmsSound) {
  document.addEventListener('click', e => {
    if (e.target.closest('.cursor-target, .dot-close')) SwarmsSound.playClick();
  });

  const soundToggle = document.getElementById('soundToggle');
  const refreshSoundIcon = () => {
    soundToggle.textContent = SwarmsSound.isMuted() ? '\u{1F507}' : '\u{1F50A}';
    soundToggle.setAttribute('aria-label', SwarmsSound.isMuted() ? 'Unmute sound effects' : 'Mute sound effects');
  };
  soundToggle.addEventListener('click', () => { SwarmsSound.setMuted(!SwarmsSound.isMuted()); refreshSoundIcon(); });
  refreshSoundIcon();
}

// ---------- homepage effects: dot field, target cursor, decrypt text ----------

const dotFieldEl = document.getElementById('dotField');
if (dotFieldEl && typeof initDotField === 'function') initDotField(dotFieldEl);

if (typeof initTargetCursor === 'function') initTargetCursor('.cursor-target');

let conceptDecrypts = null;
if (typeof makeDecryptText === 'function') {
  const brandTextEl = document.getElementById('brandText');
  if (brandTextEl) makeDecryptText(brandTextEl, { trigger: 'hover', speed: 30 });

  // first two paragraphs only, the third has an inline <b> tag that a plain
  // textContent rebuild would flatten
  conceptDecrypts = Array.from(document.querySelectorAll('#win-concept .window-body p:not(:last-child)'))
    .map(p => makeDecryptText(p, { trigger: 'manual' }));
}

// ---------- window manager ----------

const isDesktopMode = () => window.matchMedia('(min-width: 780px)').matches;
let zTop = 20;

// clamp a window's CSS-derived position (percentage lefts like win-attack's
// 26% plus a fixed width can hang off the right edge on narrower desktop
// widths, e.g. 780-865px) so it always stays fully on screen
function clampToViewport(rect, offset) {
  return {
    left: Math.max(8, Math.min(rect.left + offset, window.innerWidth - rect.width - 8)),
    top: Math.max(8, Math.min(rect.top + offset, window.innerHeight - rect.height - 8)),
  };
}

// invoice_final.pdf is open by default so a desktop visitor sees the demo
// immediately. On a phone a window covers the whole screen, so open by
// default there would hide the icon grid before anyone knows it exists,
// closer to a phone's own "home screen of icons" habit than a page.
const winAttackDefault = document.getElementById('win-attack');
if (!isDesktopMode()) {
  winAttackDefault.classList.remove('open');
} else {
  const { left, top } = clampToViewport(winAttackDefault.getBoundingClientRect(), 0);
  winAttackDefault.style.left = `${left}px`;
  winAttackDefault.style.top = `${top}px`;
  winAttackDefault.dataset.positioned = 'true';
}

function bringToFront(win) {
  zTop += 1;
  win.style.zIndex = zTop;
}

function openWindow(id) {
  const win = document.getElementById(id);
  if (!win) return;
  const openCount = document.querySelectorAll('.window.open').length;
  win.classList.add('open');
  if (isDesktopMode() && !win.dataset.positioned) {
    // measured after adding 'open': a display:none rect is always zero,
    // which would collapse every window's first-open position to the corner
    const rect = win.getBoundingClientRect();
    const { left, top } = clampToViewport(rect, openCount * 24);
    win.style.left = `${left}px`;
    win.style.top = `${top}px`;
    win.dataset.positioned = 'true';
  }
  bringToFront(win);
  if (id === 'win-attack') {
    graphOff.network.redraw();
    graphOn.network.redraw();
  }
  if (id === 'win-benchmark') {
    ensureBenchmarkChart();
  }
  if (id === 'win-concept' && conceptDecrypts) {
    conceptDecrypts.forEach(d => d.play());
  }
  updateTaskbarState();
}

function closeWindow(id) {
  const win = document.getElementById(id);
  if (!win) return;
  win.classList.remove('open');
  updateTaskbarState();
}

function toggleWindow(id) {
  const win = document.getElementById(id);
  if (!win) return;
  if (win.classList.contains('open')) closeWindow(id);
  else openWindow(id);
}

function updateTaskbarState() {
  document.querySelectorAll('.taskbar-links [data-window]').forEach(btn => {
    const win = document.getElementById(btn.dataset.window);
    btn.classList.toggle('active', !!(win && win.classList.contains('open')));
  });
}

document.querySelectorAll('.taskbar-links [data-window]').forEach(btn => {
  btn.addEventListener('click', () => toggleWindow(btn.dataset.window));
});
document.querySelectorAll('.taskbar-links [data-href]').forEach(btn => {
  btn.addEventListener('click', () => window.open(btn.dataset.href, '_blank', 'noopener'));
});
document.querySelectorAll('.window .dot-close').forEach(btn => {
  btn.addEventListener('click', () => closeWindow(btn.closest('.window').id));
});
document.querySelectorAll('.window').forEach(win => {
  win.addEventListener('mousedown', () => bringToFront(win));
});

updateTaskbarState();

// Drag helper shared by windows and icons. Uses plain mouse events (not
// Pointer Events / setPointerCapture) and listens for move/up on `document`
// rather than the dragged element, because once the cursor moves fast enough
// to leave the element's bounds mid-drag, an element-scoped listener stops
// receiving events and the drag appears to "let go" early. preventDefault on
// mousedown is what stops the browser from starting a text-selection drag
// instead of handing the gesture to us.
function makeDraggable(handleEl, moveEl, { onStart, getBounds } = {}) {
  let dragging = false, startX = 0, startY = 0, startLeft = 0, startTop = 0, maxLeft = Infinity, maxTop = Infinity;

  handleEl.addEventListener('mousedown', e => {
    if (e.button !== 0) return;
    if (onStart && onStart(e) === false) return;
    dragging = true;
    e.preventDefault();
    startX = e.clientX; startY = e.clientY;
    const rect = moveEl.getBoundingClientRect();
    const bounds = getBounds ? getBounds() : { left: 0, top: 0, width: window.innerWidth, height: window.innerHeight };
    startLeft = rect.left - bounds.left;
    startTop = rect.top - bounds.top;
    maxLeft = bounds.width - rect.width;
    maxTop = bounds.height - rect.height;
    moveEl.classList.add('dragging');
  });
  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    moveEl.style.left = `${Math.max(0, Math.min(maxLeft, startLeft + (e.clientX - startX)))}px`;
    moveEl.style.top = `${Math.max(0, Math.min(maxTop, startTop + (e.clientY - startY)))}px`;
  });
  document.addEventListener('mouseup', () => {
    dragging = false;
    moveEl.classList.remove('dragging');
  });
}

// dragging a window by its title bar (desktop only, windows are position:fixed
// so left/top are already viewport-relative and need no parent-offset math)
document.querySelectorAll('.window-titlebar').forEach(bar => {
  const win = bar.closest('.window');
  makeDraggable(bar, win, {
    onStart: e => {
      if (!isDesktopMode() || e.target.closest('.dot')) return false;
      win.dataset.positioned = 'true';
      bringToFront(win);
    },
  });
});

// ---------- desktop icons: draggable on desktop, tap-to-open on mobile ----------

const desktopEl = document.getElementById('desktop');

document.querySelectorAll('.icon').forEach(icon => {
  const activate = () => {
    if (icon.dataset.window) openWindow(icon.dataset.window);
    else if (icon.dataset.href) window.open(icon.dataset.href, '_blank', 'noopener');
  };

  icon.addEventListener('dblclick', activate);
  icon.addEventListener('click', () => { if (!isDesktopMode()) activate(); });
  icon.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); }
  });

  makeDraggable(icon, icon, {
    onStart: () => isDesktopMode(),
    getBounds: () => desktopEl.getBoundingClientRect(),
  });
});

// entering or leaving desktop mode: clear inline positions so the
// stylesheet's own layout for that mode (grid on mobile, floating on desktop)
// takes back over cleanly instead of fighting leftover drag positions
let wasDesktop = isDesktopMode();
window.addEventListener('resize', () => {
  const nowDesktop = isDesktopMode();
  if (nowDesktop === wasDesktop) return;
  wasDesktop = nowDesktop;
  if (nowDesktop) return;
  document.querySelectorAll('.icon').forEach(i => { i.style.left = ''; i.style.top = ''; });
  document.querySelectorAll('.window').forEach(w => {
    w.style.left = ''; w.style.top = ''; delete w.dataset.positioned;
  });
});
