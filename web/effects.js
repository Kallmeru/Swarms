// Homepage animation effects: an animated dot-grid background, a
// decrypt-style text reveal, and a bracket cursor that locks onto
// interactive elements. Ported from React + GSAP components to plain
// canvas/DOM + CSS transitions, this site has no build step and no other
// framework, adding one for three small effects would be the wrong trade.
// All three respect prefers-reduced-motion.

// ---------- dot field: animated background, cursor bulges the grid ----------

function initDotField(container, options = {}) {
  const opts = Object.assign({
    dotRadius: 1.3,
    dotSpacing: 15,
    cursorRadius: 230,
    bulgeStrength: 42,
    glowRadius: 150,
    gradientFrom: 'rgba(243, 231, 211, 0.14)',
    gradientTo: 'rgba(214, 84, 63, 0.10)',
    glowColor: '#D6543F',
  }, options);

  const TWO_PI = Math.PI * 2;
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  container.classList.add('dot-field-container');
  const canvas = document.createElement('canvas');
  canvas.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;';
  container.appendChild(canvas);

  const svgNS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(svgNS, 'svg');
  svg.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;pointer-events:none;';
  const glowId = `dot-field-glow-${Math.random().toString(36).slice(2, 9)}`;
  const defs = document.createElementNS(svgNS, 'defs');
  const grad = document.createElementNS(svgNS, 'radialGradient');
  grad.setAttribute('id', glowId);
  const stop1 = document.createElementNS(svgNS, 'stop');
  stop1.setAttribute('offset', '0%');
  stop1.setAttribute('stop-color', opts.glowColor);
  const stop2 = document.createElementNS(svgNS, 'stop');
  stop2.setAttribute('offset', '100%');
  stop2.setAttribute('stop-color', 'transparent');
  grad.appendChild(stop1);
  grad.appendChild(stop2);
  defs.appendChild(grad);
  const glowCircle = document.createElementNS(svgNS, 'circle');
  glowCircle.setAttribute('cx', '-9999');
  glowCircle.setAttribute('cy', '-9999');
  glowCircle.setAttribute('r', String(opts.glowRadius));
  glowCircle.setAttribute('fill', `url(#${glowId})`);
  glowCircle.style.opacity = '0';
  svg.appendChild(defs);
  svg.appendChild(glowCircle);
  container.appendChild(svg);

  const ctx = canvas.getContext('2d', { alpha: true });
  const dpr = Math.min(window.devicePixelRatio || 1, 2);

  let dots = [];
  let size = { w: 0, h: 0, offsetX: 0, offsetY: 0 };
  const mouse = { x: -9999, y: -9999, prevX: -9999, prevY: -9999, speed: 0 };
  let glowOpacity = 0;
  let engagement = 0;
  let raf = null;
  let frameCount = 0;
  let resizeTimer = null;

  function buildDots(w, h) {
    const step = opts.dotRadius + opts.dotSpacing;
    const cols = Math.floor(w / step);
    const rows = Math.floor(h / step);
    const padX = (w % step) / 2;
    const padY = (h % step) / 2;
    const next = new Array(Math.max(0, rows * cols));
    let idx = 0;
    for (let row = 0; row < rows; row++) {
      for (let col = 0; col < cols; col++) {
        const ax = padX + col * step + step / 2;
        const ay = padY + row * step + step / 2;
        next[idx++] = { ax, ay, sx: ax, sy: ay };
      }
    }
    dots = next;
  }

  function doResize() {
    const rect = container.getBoundingClientRect();
    const w = rect.width, h = rect.height;
    if (w <= 0 || h <= 0) return;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = `${w}px`;
    canvas.style.height = `${h}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    size = { w, h, offsetX: rect.left + window.scrollX, offsetY: rect.top + window.scrollY };
    buildDots(w, h);
  }

  function onResize() {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(doResize, 100);
  }

  function onMouseMove(e) {
    mouse.x = e.pageX - size.offsetX;
    mouse.y = e.pageY - size.offsetY;
  }

  const speedInterval = setInterval(() => {
    const dx = mouse.prevX - mouse.x;
    const dy = mouse.prevY - mouse.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    mouse.speed += (dist - mouse.speed) * 0.5;
    if (mouse.speed < 0.001) mouse.speed = 0;
    mouse.prevX = mouse.x;
    mouse.prevY = mouse.y;
  }, 20);

  function drawStatic() {
    ctx.clearRect(0, 0, size.w, size.h);
    const gradient = ctx.createLinearGradient(0, 0, size.w, size.h);
    gradient.addColorStop(0, opts.gradientFrom);
    gradient.addColorStop(1, opts.gradientTo);
    ctx.fillStyle = gradient;
    const rad = opts.dotRadius / 2;
    ctx.beginPath();
    for (const d of dots) {
      ctx.moveTo(d.ax + rad, d.ay);
      ctx.arc(d.ax, d.ay, rad, 0, TWO_PI);
    }
    ctx.fill();
  }

  function tick() {
    frameCount++;
    const len = dots.length;

    const targetEngagement = Math.min(mouse.speed / 5, 1);
    engagement += (targetEngagement - engagement) * 0.06;
    if (engagement < 0.001) engagement = 0;

    glowOpacity += (engagement - glowOpacity) * 0.08;
    glowCircle.setAttribute('cx', String(mouse.x));
    glowCircle.setAttribute('cy', String(mouse.y));
    glowCircle.style.opacity = String(glowOpacity);

    ctx.clearRect(0, 0, size.w, size.h);
    const gradient = ctx.createLinearGradient(0, 0, size.w, size.h);
    gradient.addColorStop(0, opts.gradientFrom);
    gradient.addColorStop(1, opts.gradientTo);
    ctx.fillStyle = gradient;

    const crSq = opts.cursorRadius * opts.cursorRadius;
    const rad = opts.dotRadius / 2;

    ctx.beginPath();
    for (let i = 0; i < len; i++) {
      const d = dots[i];
      const dx = mouse.x - d.ax;
      const dy = mouse.y - d.ay;
      const distSq = dx * dx + dy * dy;

      if (distSq < crSq && engagement > 0.01) {
        const dist = Math.sqrt(distSq);
        const t = 1 - dist / opts.cursorRadius;
        const push = t * t * opts.bulgeStrength * engagement;
        const angle = Math.atan2(dy, dx);
        d.sx += (d.ax - Math.cos(angle) * push - d.sx) * 0.15;
        d.sy += (d.ay - Math.sin(angle) * push - d.sy) * 0.15;
      } else {
        d.sx += (d.ax - d.sx) * 0.1;
        d.sy += (d.ay - d.sy) * 0.1;
      }

      ctx.moveTo(d.sx + rad, d.sy);
      ctx.arc(d.sx, d.sy, rad, 0, TWO_PI);
    }
    ctx.fill();

    raf = requestAnimationFrame(tick);
  }

  doResize();
  window.addEventListener('resize', onResize);

  if (reduceMotion) {
    drawStatic();
  } else {
    window.addEventListener('mousemove', onMouseMove, { passive: true });
    raf = requestAnimationFrame(tick);
  }

  return {
    destroy() {
      cancelAnimationFrame(raf);
      clearInterval(speedInterval);
      clearTimeout(resizeTimer);
      window.removeEventListener('resize', onResize);
      window.removeEventListener('mousemove', onMouseMove);
      canvas.remove();
      svg.remove();
    },
  };
}

// ---------- decrypt text: scrambles then reveals a string, left to right ----------

function makeDecryptText(el, options = {}) {
  const opts = Object.assign({
    speed: 35,
    characters: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!$%&*+=',
    trigger: 'manual', // 'manual' (call .play() yourself) or 'hover'
  }, options);

  const text = el.textContent;
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  el.textContent = '';
  el.classList.add('decrypt-text');

  // real text stays available to screen readers regardless of animation state
  const srOnly = document.createElement('span');
  srOnly.className = 'decrypt-sr-only';
  srOnly.textContent = text;
  el.appendChild(srOnly);

  const visible = document.createElement('span');
  visible.setAttribute('aria-hidden', 'true');
  el.appendChild(visible);

  const chars = text.split('').map(ch => {
    const span = document.createElement('span');
    span.textContent = ch;
    span.className = 'decrypt-char-revealed';
    visible.appendChild(span);
    return span;
  });

  let interval = null;
  let playing = false;

  function randomChar() {
    return opts.characters[Math.floor(Math.random() * opts.characters.length)];
  }

  function play() {
    if (playing || reduceMotion) return;
    playing = true;
    let revealed = 0;
    clearInterval(interval);
    interval = setInterval(() => {
      chars.forEach((span, i) => {
        if (text[i] === ' ') return;
        if (i < revealed) {
          span.textContent = text[i];
          span.className = 'decrypt-char-revealed';
        } else {
          span.textContent = randomChar();
          span.className = 'decrypt-char-encrypted';
        }
      });
      revealed++;
      if (revealed > text.length) {
        clearInterval(interval);
        chars.forEach((span, i) => { span.textContent = text[i]; span.className = 'decrypt-char-revealed'; });
        playing = false;
      }
    }, opts.speed);
  }

  if (opts.trigger === 'hover') {
    el.addEventListener('mouseenter', play);
  }

  return { play };
}

// ---------- target cursor: bracket cursor that locks onto .cursor-target elements ----------

function initTargetCursor(selector = '.cursor-target', options = {}) {
  const opts = Object.assign({ spinDuration: 2.6 }, options);
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const canHover = window.matchMedia('(hover: hover) and (pointer: fine)').matches;
  if (reduceMotion || !canHover) return null;

  const wrapper = document.createElement('div');
  wrapper.className = 'target-cursor-wrapper';
  wrapper.innerHTML =
    '<div class="target-cursor-dot"></div>' +
    '<div class="target-cursor-corner corner-tl"></div>' +
    '<div class="target-cursor-corner corner-tr"></div>' +
    '<div class="target-cursor-corner corner-br"></div>' +
    '<div class="target-cursor-corner corner-bl"></div>';
  document.body.appendChild(wrapper);
  const corners = wrapper.querySelectorAll('.target-cursor-corner');

  let spinDeg = 0;
  let locked = false;
  let raf = null;
  let lastTime = null;

  function idleCorners() {
    corners[0].style.transform = 'translate(-150%, -150%)';
    corners[1].style.transform = 'translate(50%, -150%)';
    corners[2].style.transform = 'translate(50%, 50%)';
    corners[3].style.transform = 'translate(-150%, 50%)';
  }
  idleCorners();

  function tick(now) {
    if (lastTime == null) lastTime = now;
    const dt = (now - lastTime) / 1000;
    lastTime = now;
    if (!locked) {
      spinDeg = (spinDeg + (360 / opts.spinDuration) * dt) % 360;
      wrapper.style.transform = `translate(-50%, -50%) rotate(${spinDeg}deg)`;
    }
    raf = requestAnimationFrame(tick);
  }
  raf = requestAnimationFrame(tick);

  function onMouseMove(e) {
    if (locked) return;
    wrapper.style.left = `${e.clientX}px`;
    wrapper.style.top = `${e.clientY}px`;
  }
  window.addEventListener('mousemove', onMouseMove, { passive: true });

  document.querySelectorAll(selector).forEach(target => {
    target.addEventListener('mouseenter', () => {
      locked = true;
      const rect = target.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      wrapper.style.transform = 'translate(-50%, -50%) rotate(0deg)';
      wrapper.style.left = `${cx}px`;
      wrapper.style.top = `${cy}px`;
      const halfW = rect.width / 2 + 6;
      const halfH = rect.height / 2 + 6;
      corners[0].style.transform = `translate(${-halfW - 6}px, ${-halfH - 6}px)`;
      corners[1].style.transform = `translate(${halfW - 6}px, ${-halfH - 6}px)`;
      corners[2].style.transform = `translate(${halfW - 6}px, ${halfH - 6}px)`;
      corners[3].style.transform = `translate(${-halfW - 6}px, ${halfH - 6}px)`;
    });
    target.addEventListener('mouseleave', () => {
      locked = false;
      idleCorners();
    });
  });

  return {
    destroy() {
      cancelAnimationFrame(raf);
      window.removeEventListener('mousemove', onMouseMove);
      wrapper.remove();
    },
  };
}

// ---------- option wheel: a curved, draggable list for picking one item ----------

function initOptionWheel(container, items, options = {}) {
  const opts = Object.assign({
    defaultSelected: 0,
    textColor: 'var(--ink-soft)',
    activeColor: 'var(--cream)',
    side: 'left',
    fontSize: 1.05,   // rem
    spacing: 1.7,
    curve: 1,
    tilt: 10,
    blur: 1.5,
    fade: 0.3,
    minOpacity: 0.15,
    smoothing: 160,
    inset: 14,
    onChange: null,
  }, options);

  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  container.classList.add('option-wheel');
  if (opts.side === 'right') container.classList.add('option-wheel--right');
  container.setAttribute('role', 'listbox');
  container.setAttribute('tabindex', '0');
  container.setAttribute('aria-label', 'Attack picker');
  container.style.setProperty('--ow-text-color', opts.textColor);
  container.style.setProperty('--ow-active-color', opts.activeColor);
  container.style.setProperty('--ow-font-size', `${opts.fontSize}rem`);
  container.style.setProperty('--ow-inset', `${opts.inset}px`);

  let dragMoved = false;

  const itemEls = items.map((label, i) => {
    const el = document.createElement('div');
    el.className = 'option-wheel__item';
    el.setAttribute('role', 'option');
    el.textContent = label;
    el.addEventListener('click', () => { if (!dragMoved) applyTarget(i, true); });
    container.appendChild(el);
    return el;
  });

  const remPx = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
  const rowH = Math.max(opts.fontSize * opts.spacing * remPx, 1);
  const mirror = opts.side === 'right' ? -1 : 1;
  const tiltRad = (opts.tilt * Math.PI) / 180;
  const R = tiltRad > 0.0005 ? rowH / tiltRad : 0;

  let pos = opts.defaultSelected;
  let target = opts.defaultSelected;
  let selected = opts.defaultSelected;
  let raf = null;
  let last = 0;

  function layout() {
    itemEls.forEach((el, i) => {
      const d = i - pos;
      const dist = Math.abs(d);
      let x = 0, y = d * rowH, rot = 0;
      if (R > 0) {
        const ang = Math.max(-Math.PI / 2, Math.min(Math.PI / 2, d * tiltRad));
        y = R * Math.sin(ang);
        x = -mirror * R * (1 - Math.cos(ang)) * opts.curve;
        rot = (mirror * ang * 180) / Math.PI;
      }
      el.style.transform = `translate(${x.toFixed(2)}px, calc(${y.toFixed(2)}px - 50%)) rotate(${rot.toFixed(3)}deg)`;
      el.style.opacity = String(Math.max(opts.minOpacity, 1 - dist * opts.fade));
      el.style.filter = opts.blur > 0 ? `blur(${(dist * opts.blur).toFixed(2)}px)` : 'none';
      el.style.setProperty('--ow-p', String(Math.max(0, 1 - Math.min(dist, 1))));
      el.classList.toggle('option-wheel__item--selected', i === selected);
      el.setAttribute('aria-selected', i === selected ? 'true' : 'false');
    });
  }

  function tick(now) {
    const dt = Math.min((now - last) / 1000, 0.05);
    last = now;
    const tau = Math.max(opts.smoothing, 1) / 1000;
    const k = 1 - Math.exp(-dt / tau);
    let next = pos + (target - pos) * k;
    const settled = Math.abs(target - next) < 0.001;
    pos = settled ? target : next;
    layout();
    raf = settled ? null : requestAnimationFrame(tick);
  }

  function startLoop() {
    if (raf != null) return;
    last = performance.now();
    raf = requestAnimationFrame(tick);
  }

  function applyTarget(value, snap) {
    let v = Math.min(Math.max(value, 0), items.length - 1);
    if (snap) v = Math.round(v);
    target = v;
    const idx = Math.round(v);
    if (idx !== selected) {
      selected = idx;
      if (opts.onChange) opts.onChange(idx, items[idx]);
    }
    if (reduceMotion) { pos = target; layout(); } else { startLoop(); }
  }

  let wheelTimer = null;
  container.addEventListener('wheel', e => {
    e.preventDefault();
    const delta = e.deltaMode === 1 ? e.deltaY * 24 : e.deltaY;
    const step = Math.max(-1, Math.min(1, delta / rowH));
    applyTarget(target + step, false);
    clearTimeout(wheelTimer);
    wheelTimer = setTimeout(() => applyTarget(target, true), 140);
  }, { passive: false });

  let drag = null;
  container.addEventListener('pointerdown', e => {
    drag = { y: e.clientY, start: target, id: e.pointerId };
    dragMoved = false;
  });
  container.addEventListener('pointermove', e => {
    if (!drag) return;
    const dy = e.clientY - drag.y;
    if (!dragMoved && Math.abs(dy) > 4) {
      dragMoved = true;
      container.setPointerCapture(drag.id);
      container.classList.add('option-wheel--dragging');
    }
    if (dragMoved) applyTarget(drag.start - dy / rowH, false);
  });
  function endDrag() {
    if (!drag) return;
    drag = null;
    container.classList.remove('option-wheel--dragging');
    if (dragMoved) applyTarget(target, true);
    setTimeout(() => { dragMoved = false; }, 0);
  }
  container.addEventListener('pointerup', endDrag);
  container.addEventListener('pointercancel', endDrag);

  container.addEventListener('keydown', e => {
    let delta = null;
    if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') delta = -1;
    else if (e.key === 'ArrowDown' || e.key === 'ArrowRight') delta = 1;
    if (delta == null) return;
    e.preventDefault();
    applyTarget(Math.round(target) + delta, true);
  });

  pos = opts.defaultSelected;
  target = opts.defaultSelected;
  selected = opts.defaultSelected;
  layout();

  return {
    select(index) {
      target = Math.min(Math.max(index, 0), items.length - 1);
      selected = Math.round(target);
      if (reduceMotion) { pos = target; layout(); } else { startLoop(); }
    },
    get selectedIndex() { return selected; },
  };
}
