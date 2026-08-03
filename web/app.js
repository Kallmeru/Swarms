// SWARMS frontend. Reads pre-generated event JSON (see web/data/) and
// animates the swarm graph inside the invoice_final.pdf window. No backend
// calls of its own: benchmark/run_benchmark.py (core + attack-lab branches)
// is the only thing that writes into web/data/.

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

function makeGraph(containerId) {
  const container = document.getElementById(containerId);
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

function applyEvent(evt, graph, statusEl, reasonEl) {
  const nodeId = AGENT_TO_NODE[evt.agent];

  if (evt.type === 'AGENT_START' && nodeId) {
    const isUntrusted = (evt.data.inputs || []).some(i => i.label === 'UNTRUSTED');
    graph.nodes.update({ id: nodeId, color: nodeColor(isUntrusted ? UNTRUSTED : TRUSTED), borderWidth: 2.5 });
  }

  // an agent that reads untrusted tool output is contaminated for the rest of its turn,
  // even if it started from a trusted instruction (e.g. Agent 1 reading a poisoned doc)
  if (evt.type === 'TOOL_RESULT' && nodeId && evt.data.label === 'UNTRUSTED') {
    graph.nodes.update({ id: nodeId, color: nodeColor(UNTRUSTED), borderWidth: 2.5 });
  }

  if (evt.type === 'AGENT_HANDOFF') {
    const edgeId = AGENT_TO_HANDOFF_EDGE[evt.agent];
    if (!edgeId) return; // agent3_emailer has no outgoing agent-to-agent handoff edge
    if (evt.data.directive_requested && !evt.data.directive_allowed) {
      graph.edges.update({ id: edgeId, color: BLOCKED, width: 3, dashes: [6, 4] });
      const label = edgeId === 'e_a1_a2' ? 'Agent 1 to Agent 2' : 'Agent 2 to Agent 3';
      statusEl.innerHTML = `<span class="seal-badge">&#10003;</span><b>CONTAINED</b> at ${label}`;
      statusEl.className = 'status blocked';
      reasonEl.innerHTML = `<b>Reason:</b> ${evt.data.reason}<br><b>Poisoned instruction:</b> "<i>${escapeHtml(evt.data.directive_requested)}</i>"`;
      if (window.SwarmsSound) SwarmsSound.playContained();
    } else {
      const color = evt.data.data_label === 'UNTRUSTED' ? UNTRUSTED : TRUSTED;
      graph.edges.update({ id: edgeId, color, width: 3 });
    }
  }

  if (evt.type === 'ACTION_ALLOWED' && evt.agent === 'agent3_emailer' && evt.data.action === 'send_email') {
    graph.edges.update({ id: 'e_a3_act', color: BLOCKED, width: 4 });
    graph.nodes.update({ id: 'action', color: nodeColor(BLOCKED), borderWidth: 2.5 });
    statusEl.innerHTML = `<b>WORM SUCCEEDED</b>: malicious email sent.`;
    statusEl.className = 'status leaked';
    if (window.SwarmsSound) SwarmsSound.playWormSucceeded();
  }

  if (evt.type === 'ACTION_BLOCKED') {
    graph.edges.update({ id: 'e_a3_act', color: BLOCKED, width: 3, dashes: [6, 4] });
    statusEl.innerHTML = `<span class="seal-badge">&#10003;</span><b>CONTAINED</b> at final action`;
    statusEl.className = 'status blocked';
    reasonEl.innerHTML = `<b>Reason:</b> ${evt.data.reason}` +
      (evt.data.offending_span ? `<br><b>Offending value:</b> "<i>${escapeHtml(evt.data.offending_span)}</i>"` : '');
    if (window.SwarmsSound) SwarmsSound.playContained();
  }

  // Ablaze's regex-weighted scanner, a second, independent signal on the
  // same document. Purely informational: it doesn't affect containment,
  // that's still entirely the capability model's job, and it fires
  // identically from both the shield-off and shield-on event streams since
  // it scores the same document either way, whichever arrives first wins,
  // that's fine since the content is the same.
  if (evt.type === 'SCANNER_RESULT') {
    const panel = document.getElementById('scanner-panel');
    if (panel) {
      const pct = Math.round(evt.data.score * 100);
      const verdict = evt.data.flagged
        ? '<span class="scanner-flagged">FLAGGED</span>'
        : '<span class="scanner-clear">not flagged</span>';
      const matches = evt.data.findings.length ? ` &middot; matched: ${evt.data.findings.map(escapeHtml).join(', ')}` : ' &middot; no rule matched';
      panel.innerHTML = `<b>Attack-lab scanner:</b> score ${pct}% &middot; ${verdict}${matches}`;
    }
  }

  // What Ablaze's ScannerAgent.send_alert() would have emailed for this
  // flagged attack, real subject/body, real attack details, but never
  // actually sent: the live site is static (no backend to send from when a
  // visitor clicks Run Attack), and using real SMTP credentials in a public
  // demo isn't something to depend on. Same fires-from-both-streams note as
  // SCANNER_RESULT above applies here.
  if (evt.type === 'SCANNER_ALERT_PREVIEW') {
    const el = document.getElementById('alert-preview');
    if (el) {
      el.innerHTML = `<div class="alert-preview-header">Alert email &mdash; preview, not sent</div>` +
        `<div class="alert-preview-meta"><b>To:</b> ${escapeHtml(evt.data.to)}<br><b>From:</b> ${escapeHtml(evt.data.from)}<br><b>Subject:</b> ${escapeHtml(evt.data.subject)}</div>` +
        `<div class="alert-preview-body">${escapeHtml(evt.data.body)}</div>`;
    }
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

async function playSequence(events, graph, statusEl, reasonEl, delayMs) {
  resetGraph(graph);
  statusEl.innerHTML = '';
  statusEl.className = 'status';
  graph.nodes.update({ id: 'doc', color: nodeColor(UNTRUSTED), borderWidth: 2.5 }); // the document is always the untrusted seed
  for (const evt of events) {
    await new Promise(r => setTimeout(r, delayMs));
    try {
      applyEvent(evt, graph, statusEl, reasonEl);
    } catch (err) {
      console.error('failed to apply event', evt, err);
    }
  }
}

const graphOff = makeGraph('graph-off');
const graphOn = makeGraph('graph-on');
const loadErrorEl = document.getElementById('loadError');

async function loadAttack(attackId) {
  const [offEvents, onEvents] = await Promise.all([
    fetch(`data/${attackId}_off.json`).then(r => { if (!r.ok) throw new Error(`${attackId}_off.json: ${r.status}`); return r.json(); }),
    fetch(`data/${attackId}_on.json`).then(r => { if (!r.ok) throw new Error(`${attackId}_on.json: ${r.status}`); return r.json(); }),
  ]);
  return { offEvents, onEvents };
}

document.getElementById('playBtn').onclick = async () => {
  if (window.SwarmsSound) SwarmsSound.playAttackStart();
  const attackId = document.getElementById('attackPicker').value;
  loadErrorEl.textContent = '';
  const reasonEl = document.getElementById('reason-panel');
  reasonEl.innerHTML = '';
  document.getElementById('scanner-panel').innerHTML = '';
  document.getElementById('alert-preview').innerHTML = '';
  try {
    const { offEvents, onEvents } = await loadAttack(attackId);
    playSequence(offEvents, graphOff, document.getElementById('status-off'), reasonEl, 650);
    playSequence(onEvents, graphOn, document.getElementById('status-on'), reasonEl, 650);
  } catch (err) {
    loadErrorEl.textContent = `Could not load attack data: ${err.message}`;
    console.error(err);
  }
};

fetch('data/manifest.json')
  .then(r => r.json())
  .then(list => {
    const sel = document.getElementById('attackPicker');
    list.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a.attack_id;
      opt.textContent = `${a.attack_id}: ${a.name} (${a.category})`;
      sel.appendChild(opt);
    });

    // Visual attack picker: a curved wheel kept in sync with the real
    // <select> above (attackPicker stays the source of truth playBtn reads
    // from, and the fully accessible fallback for keyboard/screen readers).
    const wheelEl = document.getElementById('attackWheel');
    if (wheelEl && list.length && typeof initOptionWheel === 'function') {
      const labels = list.map(a => a.attack_id);
      const wheel = initOptionWheel(wheelEl, labels, {
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
  })
  .catch(err => { loadErrorEl.textContent = `Could not load manifest.json: ${err.message}`; });

// Constructing Chart.js against a canvas that's still display:none (the
// window hasn't been opened yet) leaves it permanently stuck at 0x0, even a
// later resize() can't recover it, only building a fresh instance does. So
// this waits for the data AND builds the chart lazily on first open instead
// of at page load.
let benchmarkChart = null;
let benchmarkSummary = null;
fetch('data/benchmark_summary.json')
  .then(r => r.json())
  .then(summary => { benchmarkSummary = summary; ensureBenchmarkChart(); })
  .catch(err => { loadErrorEl.textContent = `Could not load benchmark_summary.json: ${err.message}`; });

function ensureBenchmarkChart() {
  if (benchmarkChart || !benchmarkSummary) return;
  const canvas = document.getElementById('benchmarkChart');
  if (canvas.getBoundingClientRect().width === 0) return; // still hidden, openWindow() will call this again once it's actually visible
  benchmarkChart = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: ['Shield OFF', 'Shield ON'],
      datasets: [{
        label: `Malicious action success rate (n=${benchmarkSummary.total_attacks})`,
        data: [benchmarkSummary.shield_off_success_rate * 100, benchmarkSummary.shield_on_success_rate * 100],
        backgroundColor: [BLOCKED, TRUSTED],
        borderRadius: 4,
      }],
    },
    options: {
      scales: {
        y: { beginAtZero: true, max: 100, ticks: { callback: v => v + '%', color: '#A0917E' }, grid: { color: 'rgba(243,231,211,0.12)' } },
        x: { ticks: { color: '#A0917E' }, grid: { display: false } },
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
