// TRIPWIRE v2 frontend. Reads pre-generated event JSON (see web/data/) and
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
  }

  if (evt.type === 'ACTION_BLOCKED') {
    graph.edges.update({ id: 'e_a3_act', color: BLOCKED, width: 3, dashes: [6, 4] });
    statusEl.innerHTML = `<span class="seal-badge">&#10003;</span><b>CONTAINED</b> at final action`;
    statusEl.className = 'status blocked';
    reasonEl.innerHTML = `<b>Reason:</b> ${evt.data.reason}<br><b>Offending value:</b> "<i>${escapeHtml(evt.data.offending_span || '')}</i>"`;
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
  const attackId = document.getElementById('attackPicker').value;
  loadErrorEl.textContent = '';
  const reasonEl = document.getElementById('reason-panel');
  reasonEl.innerHTML = '';
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
  })
  .catch(err => { loadErrorEl.textContent = `Could not load manifest.json: ${err.message}`; });

fetch('data/benchmark_summary.json')
  .then(r => r.json())
  .then(summary => {
    new Chart(document.getElementById('benchmarkChart'), {
      type: 'bar',
      data: {
        labels: ['Shield OFF', 'Shield ON'],
        datasets: [{
          label: `Malicious action success rate (n=${summary.total_attacks})`,
          data: [summary.shield_off_success_rate * 100, summary.shield_on_success_rate * 100],
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
  })
  .catch(err => { loadErrorEl.textContent = `Could not load benchmark_summary.json: ${err.message}`; });

// ---------- menu bar clock ----------

function tickClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString([], { hour12: false });
}
tickClock();
setInterval(tickClock, 1000);

// ---------- window manager ----------

const isDesktopMode = () => window.matchMedia('(min-width: 780px)').matches;
let zTop = 20;

// invoice_final.pdf is open by default so a desktop visitor sees the demo
// immediately. On a phone a window covers the whole screen, so open by
// default there would hide the icon grid before anyone knows it exists,
// closer to a phone's own "home screen of icons" habit than a page.
if (!isDesktopMode()) {
  document.getElementById('win-attack').classList.remove('open');
}

function bringToFront(win) {
  zTop += 1;
  win.style.zIndex = zTop;
}

function openWindow(id) {
  const win = document.getElementById(id);
  if (!win) return;
  if (isDesktopMode() && !win.dataset.positioned) {
    const openCount = document.querySelectorAll('.window.open').length;
    const rect = win.getBoundingClientRect();
    win.style.left = `${rect.left + openCount * 24}px`;
    win.style.top = `${rect.top + openCount * 24}px`;
    win.dataset.positioned = 'true';
  }
  win.classList.add('open');
  bringToFront(win);
  if (id === 'win-attack') {
    graphOff.network.redraw();
    graphOn.network.redraw();
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
  let dragging = false, startX = 0, startY = 0, startLeft = 0, startTop = 0;

  handleEl.addEventListener('mousedown', e => {
    if (e.button !== 0) return;
    if (onStart && onStart(e) === false) return;
    dragging = true;
    e.preventDefault();
    startX = e.clientX; startY = e.clientY;
    const rect = moveEl.getBoundingClientRect();
    const bounds = getBounds ? getBounds() : { left: 0, top: 0 };
    startLeft = rect.left - bounds.left;
    startTop = rect.top - bounds.top;
    moveEl.classList.add('dragging');
  });
  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    moveEl.style.left = `${Math.max(0, startLeft + (e.clientX - startX))}px`;
    moveEl.style.top = `${Math.max(0, startTop + (e.clientY - startY))}px`;
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
