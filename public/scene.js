'use strict';
// Original voxel "vault shield": true 3D rotation, back-face culling and painter's sort on a 2D canvas.
window.VaultScene = (() => {
  const SHAPE = ['111111111', '111222111', '111222111', '111121111', '111222111', '011111110', '001111100', '000111000', '000010000'];
  const FACES = [[[0,0,1],[[-1,-1,1],[1,-1,1],[1,1,1],[-1,1,1]]], [[0,0,-1],[[1,-1,-1],[-1,-1,-1],[-1,1,-1],[1,1,-1]]],
    [[1,0,0],[[1,-1,1],[1,-1,-1],[1,1,-1],[1,1,1]]], [[-1,0,0],[[-1,-1,-1],[-1,-1,1],[-1,1,1],[-1,1,-1]]],
    [[0,-1,0],[[-1,-1,-1],[1,-1,-1],[1,-1,1],[-1,-1,1]]], [[0,1,0],[[-1,1,1],[1,1,1],[1,1,-1],[-1,1,-1]]]];
  function mount(canvas) {
    const g = canvas.getContext('2d'), cubes = [];
    SHAPE.forEach((row, y) => [...row].forEach((c, x) => { if (c !== '0') cubes.push({ x: x - 4, y: y - 4, key: c === '2',
      sx: (Math.random() - .5) * 30, sy: -12 - Math.random() * 14, sz: (Math.random() - .5) * 24, delay: y * 70 + Math.random() * 250 }); }));
    const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
    let mx = 0, my = 0, start = performance.now(), raf = 0, visible = true;
    const move = e => { const r = canvas.getBoundingClientRect(); mx = (e.clientX - r.left) / r.width - .5; my = (e.clientY - r.top) / r.height - .5; };
    addEventListener('pointermove', move, { passive: true });
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting; if (visible && !raf) raf = requestAnimationFrame(draw); }); io.observe(canvas);
    function draw(now) {
      raf = 0;
      if (!canvas.isConnected) { removeEventListener('pointermove', move); io.disconnect(); return; }
      const dpr = Math.min(devicePixelRatio || 1, 2), w = canvas.clientWidth, h = canvas.clientHeight;
      if (canvas.width !== Math.round(w * dpr)) { canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr); }
      g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h);
      const t = calm ? 9000 : now - start, ry = (calm ? .5 : Math.sin(t / 2600) * .6) + mx * .7, rx = -.32 - my * .35;
      const cy = Math.cos(ry), sy = Math.sin(ry), cx = Math.cos(rx), sx = Math.sin(rx), unit = Math.min(w, h) / 13.5;
      const rot = (x, y, z) => { const X = x * cy + z * sy, Z = -x * sy + z * cy; return [X, y * cx - Z * sx, y * sx + Z * cx]; };
      const proj = ([x, y, z]) => { const p = 30 / (30 - z); return [w / 2 + x * unit * p, h / 2 + y * unit * p]; };
      // orbit ring and scan light
      for (let i = 0; i < 44; i++) { const a = i / 44 * Math.PI * 2 + t / 3800, p = rot(Math.cos(a) * 6.4, 1.6, Math.sin(a) * 6.4), [px, py] = proj(p);
        g.fillStyle = `rgba(${i % 11 ? '77,124,255' : '56,225,255'},${.18 + (p[2] + 6.4) / 20})`; g.fillRect(px - 2, py - 2, i % 11 ? 3 : 7, i % 11 ? 3 : 7); }
      const scan = calm ? 99 : ((t / 380) % 18) - 7, faces = [];
      for (const c of cubes) {
        const k = calm ? 1 : Math.min(1, Math.max(0, (t - c.delay) / 1100)), e = 1 - Math.pow(1 - k, 4);
        const bob = calm ? 0 : Math.sin(t / 700 + c.x * .7 + c.y * .5) * .09;
        const pos = [c.x + c.sx * (1 - e), c.y + c.sy * (1 - e) + bob, c.sz * (1 - e) + (c.key ? .55 : 0)];
        const lit = Math.max(0, 1 - Math.abs(c.y - scan) / 1.4);
        for (const [n, vs] of FACES) {
          const rn = rot(...n); if (rn[2] <= .02) continue;
          const pts = vs.map(v => rot(pos[0] + v[0] * .46, pos[1] + v[1] * .46, pos[2] + v[2] * .46));
          faces.push({ pts, z: pts.reduce((s, p) => s + p[2], 0), shade: .42 + .58 * Math.max(0, rn[2] * .65 - rn[1] * .6 + rn[0] * .25), key: c.key, lit, a: e });
        }
      }
      faces.sort((a, b) => a.z - b.z);
      for (const f of faces) {
        const base = f.key ? [56, 225, 255] : [38, 66, 140], s = f.key ? .65 + f.shade * .4 : f.shade * (1 + f.lit * .7);
        g.beginPath(); f.pts.forEach((p, i) => { const [x, y] = proj(p); i ? g.lineTo(x, y) : g.moveTo(x, y); }); g.closePath();
        g.fillStyle = `rgba(${base.map(v => Math.min(255, v * s) | 0)},${f.a})`; g.fill();
        g.strokeStyle = f.key ? `rgba(190,250,255,${f.a})` : `rgba(110,170,255,${(.28 + f.lit * .6) * f.a})`; g.lineWidth = 1; g.stroke();
      }
      if (!calm && visible) raf = requestAnimationFrame(draw);
    }
    raf = requestAnimationFrame(draw);
    if (calm) addEventListener('resize', () => requestAnimationFrame(draw), { passive: true });
  }
  return { mount };
})();
