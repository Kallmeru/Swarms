// SWARMS dashboard: project overview and the entry point into the OS demo
// (os.html). Reuses effects.js's dot field, decrypt text, and target cursor
// for visual consistency with the OS page; nothing from app.js is relevant
// here (that file assumes the OS page's windows/graphs/attack picker exist).

const dotFieldEl = document.getElementById('dotField');
if (dotFieldEl && typeof initDotField === 'function') initDotField(dotFieldEl);

if (typeof initTargetCursor === 'function') initTargetCursor('.cursor-target');

if (typeof makeDecryptText === 'function') {
  const brandTextEl = document.getElementById('brandText');
  if (brandTextEl) makeDecryptText(brandTextEl, { trigger: 'hover', speed: 30 });
}

fetch('data/benchmark_summary.json')
  .then(r => r.json())
  .then(summary => {
    document.getElementById('statTotal').textContent = summary.total_attacks;
    document.getElementById('statOff').textContent = `${Math.round(summary.shield_off_success_rate * 100)}%`;
    document.getElementById('statOn').textContent = `${Math.round(summary.shield_on_success_rate * 100)}%`;
  })
  .catch(() => {
    document.getElementById('statsSection').style.display = 'none';
  });
