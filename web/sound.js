// SWARMS UI sound effects: short tones synthesized with the Web Audio API,
// no audio files to host or license. Browsers block audio before a user
// gesture, so the AudioContext is created lazily on first use rather than
// at page load.

(function () {
  const MUTE_KEY = 'swarms-sound-muted';
  let ctx = null;
  let muted = localStorage.getItem(MUTE_KEY) === '1';

  function getCtx() {
    if (!ctx) ctx = new (window.AudioContext || window.webkitAudioContext)();
    if (ctx.state === 'suspended') ctx.resume();
    return ctx;
  }

  function tone(freq, duration, { type = 'sine', gain = 0.06, sweepTo = null } = {}) {
    if (muted) return;
    const audio = getCtx();
    const osc = audio.createOscillator();
    const g = audio.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, audio.currentTime);
    if (sweepTo) osc.frequency.exponentialRampToValueAtTime(sweepTo, audio.currentTime + duration);
    g.gain.setValueAtTime(gain, audio.currentTime);
    g.gain.exponentialRampToValueAtTime(0.0001, audio.currentTime + duration);
    osc.connect(g).connect(audio.destination);
    osc.start();
    osc.stop(audio.currentTime + duration);
  }

  window.SwarmsSound = {
    playClick() { tone(1100, 0.05, { type: 'square', gain: 0.05 }); },
    playTick() { tone(900, 0.03, { type: 'sine', gain: 0.03 }); },
    playAttackStart() { tone(220, 0.16, { type: 'sawtooth', gain: 0.06, sweepTo: 560 }); },
    playContained() {
      tone(660, 0.09, { type: 'sine', gain: 0.06 });
      setTimeout(() => tone(880, 0.12, { type: 'sine', gain: 0.06 }), 90);
    },
    playWormSucceeded() { tone(320, 0.3, { type: 'sawtooth', gain: 0.08, sweepTo: 140 }); },
    isMuted: () => muted,
    setMuted(value) {
      muted = value;
      localStorage.setItem(MUTE_KEY, value ? '1' : '0');
    },
  };
})();
