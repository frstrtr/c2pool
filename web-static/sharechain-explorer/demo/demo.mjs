// Demo driver — synthetic sharechain against the real bundle.
// Proves the Explorer plugins compose end-to-end without a c2pool
// server. Deterministic under a seeded RNG so visual regression is
// stable.

import {
  Host,
  registerExplorerBaseline,
  computeGridLayout,
  createGridRenderer,
  cellAtPoint,
} from '../dist/sharechain-explorer.js';

// ── Deterministic RNG (mulberry32) ──────────────────────────────
function makeRng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6D2B79F5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rng = makeRng(42);

// ── Synthetic share generator ───────────────────────────────────
const ADDR_POOL = [
  'Xaaa111', 'Xbbb222', 'Xccc333', 'Xddd444', 'Xeee555',
  'Xfff666', 'Xggg777', 'Xhhh888', 'XmineXX', 'Xiii999',
];
const MY_ADDRESS = 'XmineXX';
const SHARE_VERSION = 36;

function synthesise(n) {
  const shares = [];
  for (let i = 0; i < n; i++) {
    const r = rng();
    let V = 36, dv = 36;
    if (r < 0.15) { V = 35; dv = 35; }          // legacy V35 only
    else if (r < 0.30) { V = 35; dv = 36; }     // signalling V36
    const stale = rng();
    const s = stale < 0.02 ? 2 : stale < 0.05 ? 1 : 0;
    const v = rng() < 0.03 ? 0 : 1;
    const feeRoll = rng();
    const base = {
      s, v, V, dv,
      m: ADDR_POOL[Math.floor(rng() * ADDR_POOL.length)],
    };
    shares.push(feeRoll < 0.01 ? { ...base, fee: 1 } : base);
  }
  return shares;
}

// ── Wire the Host + renderer ────────────────────────────────────
const host = new Host('explorer');
registerExplorerBaseline(host);
await host.init({ kind: 'explorer' });

const canvas = /** @type {HTMLCanvasElement} */ (document.getElementById('grid'));
const wrap   = document.getElementById('grid-wrap');
const stats  = document.getElementById('stats');
const addBtn = document.getElementById('add-share');
const rotBtn = document.getElementById('rotate-hover');
const rstBtn = document.getElementById('reset');

const renderer = createGridRenderer(canvas);
const userContext = { myAddress: MY_ADDRESS, shareVersion: SHARE_VERSION };

let shares = synthesise(4320);
let hoveredIndex = -1;

function paint() {
  const layout = computeGridLayout({
    shareCount: shares.length,
    containerWidth: wrap.clientWidth,
    cellSize: 10,
    gap: 1,
    marginLeft: 38,
    minHeight: 40,
  });
  renderer.paint({
    layout,
    shares,
    userContext,
    backgroundColor: '#0d0d1a',
    hoveredIndex: hoveredIndex >= 0 ? hoveredIndex : undefined,
  });
  stats.textContent = `${shares.length} shares — hover: ${hoveredIndex >= 0 ? '#' + hoveredIndex : '—'}`;
}

// Hit test on mouse move — uses the layout module's cellAtPoint.
canvas.addEventListener('mousemove', (ev) => {
  const rect = canvas.getBoundingClientRect();
  const x = ev.clientX - rect.left;
  const y = ev.clientY - rect.top;
  const layout = computeGridLayout({
    shareCount: shares.length,
    containerWidth: wrap.clientWidth,
    cellSize: 10,
    gap: 1,
    marginLeft: 38,
    minHeight: 40,
  });
  const idx = cellAtPoint(layout, x, y);
  const next = idx ?? -1;
  if (next !== hoveredIndex) {
    hoveredIndex = next;
    paint();
  }
});
canvas.addEventListener('mouseleave', () => {
  if (hoveredIndex !== -1) { hoveredIndex = -1; paint(); }
});

// Controls
addBtn.addEventListener('click', () => {
  const newShare = synthesise(1)[0];
  shares = [newShare, ...shares].slice(0, 4320);
  paint();
});
rotBtn.addEventListener('click', () => {
  hoveredIndex = (hoveredIndex + 1) % Math.min(shares.length, 100);
  paint();
});
rstBtn.addEventListener('click', () => {
  shares = synthesise(4320);
  hoveredIndex = -1;
  paint();
});

window.addEventListener('resize', () => paint());

paint();

// Expose for devtools poking.
window.__demo = { host, renderer, getShares: () => shares, paint };
