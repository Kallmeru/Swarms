// TRIPWIRE v2 frontend — reads pre-generated event JSON (see web/data/) and
// animates the swarm graph. No backend calls of its own: benchmark/run_benchmark.py
// (owned by the core + attack-lab branches) is the only thing that writes into web/data/.
// Schema for every file here is documented in person3-frontend-visualization.md.

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
const NEUTRAL = '#9aa0a6', TRUSTED = '#2ecc71', UNTRUSTED = '#e67e22', BLOCKED = '#e74c3c';

const AGENT_TO_NODE = { agent1_reader: 'agent1', agent2_analyst: 'agent2', agent3_emailer: 'agent3' };
const AGENT_TO_HANDOFF_EDGE = { agent1_reader: 'e_a1_a2', agent2_analyst: 'e_a2_a3' };

function makeGraph(containerId) {
  const container = document.getElementById(containerId);
  const nodes = new vis.DataSet(NODES.map(n => ({ ...n, color: NEUTRAL })));
  const edges = new vis.DataSet(EDGES.map(e => ({ ...e, color: NEUTRAL, width: 2, arrows: 'to' })));
  const network = new vis.Network(container, { nodes, edges }, {
    physics: false,
    layout: { hierarchical: { direction: 'LR', sortMethod: 'directed', nodeSpacing: 160, levelSeparation: 160 } },
    nodes: { font: { size: 14, multi: false } },
    interaction: { dragNodes: false, zoomView: false },
  });
  return { network, nodes, edges };
}

function resetGraph(graph) {
  NODES.forEach(n => graph.nodes.update({ id: n.id, color: NEUTRAL }));
  EDGES.forEach(e => graph.edges.update({ id: e.id, color: NEUTRAL, width: 2, dashes: false }));
}

function applyEvent(evt, graph, statusEl, reasonEl) {
  const nodeId = AGENT_TO_NODE[evt.agent];

  if (evt.type === 'AGENT_START' && nodeId) {
    const isUntrusted = (evt.data.inputs || []).some(i => i.label === 'UNTRUSTED');
    graph.nodes.update({ id: nodeId, color: isUntrusted ? UNTRUSTED : TRUSTED });
  }

  // an agent that reads untrusted tool output is contaminated for the rest of its turn,
  // even if it started from a trusted instruction (e.g. Agent 1 reading a poisoned doc)
  if (evt.type === 'TOOL_RESULT' && nodeId && evt.data.label === 'UNTRUSTED') {
    graph.nodes.update({ id: nodeId, color: UNTRUSTED });
  }

  if (evt.type === 'AGENT_HANDOFF') {
    const edgeId = AGENT_TO_HANDOFF_EDGE[evt.agent];
    if (!edgeId) return; // agent3_emailer has no outgoing agent-to-agent handoff edge
    if (evt.data.directive_requested && !evt.data.directive_allowed) {
      graph.edges.update({ id: edgeId, color: BLOCKED, width: 5, dashes: true });
      const label = edgeId === 'e_a1_a2' ? 'Agent 1 → Agent 2' : 'Agent 2 → Agent 3';
      statusEl.innerHTML = `<b>CONTAINED</b> at ${label}`;
      statusEl.className = 'status blocked';
      reasonEl.innerHTML = `<b>Reason:</b> ${evt.data.reason}<br><b>Poisoned instruction:</b> "<i>${escapeHtml(evt.data.directive_requested)}</i>"`;
    } else {
      const color = evt.data.data_label === 'UNTRUSTED' ? UNTRUSTED : TRUSTED;
      graph.edges.update({ id: edgeId, color, width: 4 });
    }
  }

  if (evt.type === 'ACTION_ALLOWED' && evt.agent === 'agent3_emailer' && evt.data.action === 'send_email') {
    graph.edges.update({ id: 'e_a3_act', color: UNTRUSTED, width: 6 });
    graph.nodes.update({ id: 'action', color: UNTRUSTED });
    statusEl.innerHTML = `<b>WORM SUCCEEDED</b> — malicious email sent.`;
    statusEl.className = 'status leaked';
  }

  if (evt.type === 'ACTION_BLOCKED') {
    graph.edges.update({ id: 'e_a3_act', color: BLOCKED, dashes: true });
    statusEl.innerHTML = `<b>CONTAINED</b> at final action.`;
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
  graph.nodes.update({ id: 'doc', color: UNTRUSTED }); // the document is always the untrusted seed
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
      opt.textContent = `${a.attack_id} — ${a.name} (${a.category})`;
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
          backgroundColor: [UNTRUSTED, TRUSTED],
        }],
      },
      options: {
        scales: { y: { beginAtZero: true, max: 100, ticks: { callback: v => v + '%' } } },
        plugins: { legend: { display: false } },
      },
    });
  })
  .catch(err => { loadErrorEl.textContent = `Could not load benchmark_summary.json: ${err.message}`; });
