// SWARMS dashboard: project overview and the entry point into the OS demo
// (os.html). Reuses effects.js's dot field, decrypt text and target cursor
// for visual consistency with the OS page; nothing from app.js applies here
// (that file assumes the OS page's windows, graphs and attack picker exist).

const dotFieldEl = document.getElementById('dotField');
if (dotFieldEl && typeof initDotField === 'function') initDotField(dotFieldEl);

if (typeof initTargetCursor === 'function') initTargetCursor('.cursor-target');

if (typeof makeDecryptText === 'function') {
  const brandTextEl = document.getElementById('brandText');
  if (brandTextEl) makeDecryptText(brandTextEl, { trigger: 'hover', speed: 30 });
}

const pct = (v) => `${Math.round((v || 0) * 100)}%`;
const set = (id, text) => { const el = document.getElementById(id); if (el) el.textContent = text; };

// Prefers the live API so the dashboard reflects the running build, falls
// back to the file the benchmark wrote so the static GitHub Pages deploy
// shows the same numbers.
fetch('api/benchmark', { cache: 'no-store' })
  .then(r => (r.ok ? r.json() : Promise.reject(r.status)))
  .catch(() => fetch('data/benchmark_summary.json').then(r => r.json()))
  .then(summary => {
    set('statTotal', summary.total_attacks);
    set('statOff', pct(summary.shield_off_success_rate));
    set('statOn', pct(summary.shield_on_success_rate));
    // utility_retained is absent from benchmark output predating benign
    // controls; hide the tile rather than print a confident zero.
    if (summary.utility_retained === undefined) {
      const tile = document.getElementById('statUtility');
      if (tile && tile.parentElement) tile.parentElement.style.display = 'none';
    } else {
      set('statUtility', pct(summary.utility_retained));
    }

    const benign = summary.total_benign ? `, plus ${summary.total_benign} benign control tasks` : '';
    set('statsNote',
      `Measured by python -m benchmark.run_benchmark over ${summary.total_fixtures || summary.total_attacks} fixtures${benign}. ` +
      `${summary.false_positives === undefined ? '' : `False positives: ${summary.false_positives}. `}` +
      `Every attack is run twice through the real pipeline, once unprotected and once protected.`);
  })
  .catch(() => {
    const section = document.getElementById('statsSection');
    if (section) section.style.display = 'none';
  });
