// ▣ off-chain block-share cells for the Fluid grid: the rows equal what
// the dashboard's "Blocks in Window" counts as off-chain (its own
// c2pWindowBlocks, run from dashboard.html), the cells are placed by
// timestamp, the hover text never says "block lost", the view draws them,
// and the dashboard wires them safely.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  offChainBlocks, withOffChainCells, offChainLines, isOffChainCell, mountSharechainGrid, createSelectionBus,
  createGridLayout, parseCssColor, OFF_CHAIN_FILL, FLAG_DIM, type BlockRow, type GridShare, type Ctx2D,
} from '../../src/scene/index.js';

const HTML = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
function section(name: string): string {
  const a = HTML.indexOf('// BEGIN ' + name);
  const b = HTML.indexOf('// END ' + name);
  assert.ok(a >= 0 && b > a, `${name} block present`);
  return HTML.slice(a, b);
}
// eslint-disable-next-line @typescript-eslint/no-implied-eval
const dash = new Function(`${section('c2pBlockMarks')}${section('c2pWindowBlocks')}\nreturn { c2pWindowBlocks };`)() as {
  c2pWindowBlocks(blocks: unknown, shares: unknown, set: unknown, sym: string): { offChain: number };
};

const H = (n: number) => `00000000000000${n.toString(16).padStart(50, 'a')}`;
const SHARES: GridShare[] = Array.from({ length: 20 }, (_, i) => ({ H: H(i), h: H(i).slice(0, 16), t: 2_000 - i * 10, m: i % 2 ? 'Xa' : 'Xb' }));
// one short-only share (no H) to exercise the short-hash match
SHARES.push({ h: 'shortonly0000001', t: 1_805 });

const BLOCKS: BlockRow[] = [
  { hash: 'blk1', share: H(3), ts: 1_970, chain: 'DASH', height: 100 },            // on-chain (full)
  { hash: 'blk2', share: 'feedfacefeedface' + 'b'.repeat(48), ts: 1_955, chain: 'DASH', height: 101, miner: 'Xa' }, // off-chain
  { hash: H(7), share: null, ts: 1_930, chain: 'DASH', height: 102 },              // on-chain via hash
  { hash: 'blk4', share: 'shortonly0000001' + 'c'.repeat(48), ts: 1_805, chain: 'DASH' }, // on-chain via short
  { hash: 'blk5', share: 'deadbeef' + 'd'.repeat(56), ts: 1_840, chain: 'DASH', height: 104, miner: 'Xb' }, // off-chain
  { hash: 'blk6', share: 'old' + 'e'.repeat(61), ts: 100, chain: 'DASH' },          // older than the window
  { hash: 'blk7', share: 'doge' + 'f'.repeat(60), ts: 1_990, chain: 'DOGE' },       // other coin
  { hash: 'blk2', share: 'feedfacefeedface' + 'b'.repeat(48), ts: 1_955, chain: 'DASH' }, // duplicate
];

test('parity: off-chain rows == what "Blocks in Window" counts as off-chain', () => {
  const rows = offChainBlocks(BLOCKS, SHARES, 'DASH');
  assert.deepEqual(rows.map((r) => r.hash), ['blk2', 'blk5']);
  assert.equal(rows.length, dash.c2pWindowBlocks(BLOCKS, SHARES, null, 'DASH').offChain);
  // and on a few variations
  for (const [blocks, sym] of [[BLOCKS.slice(0, 3), 'DASH'], [BLOCKS, 'dash'], [[], 'DASH'], [BLOCKS, 'DOGE']] as const) {
    assert.equal(offChainBlocks(blocks, SHARES, sym).length,
      dash.c2pWindowBlocks(blocks, SHARES, null, sym).offChain, `${blocks.length} rows, ${sym}`);
  }
  assert.deepEqual(offChainBlocks(null, SHARES, 'DASH'), []);
});

test('cells are placed by timestamp in the newest-first window', () => {
  const rows = offChainBlocks(BLOCKS, SHARES, 'DASH');
  const merged = withOffChainCells(SHARES, rows);
  assert.equal(merged.length, SHARES.length + 2);
  const ts = merged.map((s) => s.t ?? 0);
  assert.deepEqual(ts, [...ts].sort((a, b) => b - a), 'still newest first');
  const cell = merged.find(isOffChainCell)!;
  assert.equal(cell.H, `offchain:${BLOCKS[1]!.share}`);
  assert.equal(cell.m, 'Xa', 'the finder is the bus subject');
  assert.deepEqual(withOffChainCells(SHARES, []), SHARES);
});

test('hover text: block height and coin, the agreed wording, never "block lost"', () => {
  const lines = offChainLines({ height: 2573244, chain: 'DASH', miner: 'XoZc', ts: 1_000 }, 1_000 + 600);
  assert.equal(lines[0], '▣ solved block 2573244 (DASH)');
  assert.equal(lines[1], 'share not on the best sharechain — finder lost one share of PPLNS weight');
  assert.ok(lines.includes('finder XoZc'));
  assert.ok(lines.includes('10 min ago'));
  assert.ok(!lines.join(' ').toLowerCase().includes('block lost'));
});

function fakeDom() {
  const mk = (tag: string): Record<string, unknown> => ({
    tag, style: {}, children: [] as unknown[], parentNode: null, clientWidth: 600, clientHeight: 300,
    appendChild(c: { parentNode: unknown }) { c.parentNode = this; (this.children as unknown[]).push(c); return c; },
    insertBefore(c: { parentNode: unknown }) { c.parentNode = this; (this.children as unknown[]).push(c); return c; },
    removeChild(c: unknown) { const a = this.children as unknown[]; a.splice(a.indexOf(c), 1); return c; },
    addEventListener() {}, removeEventListener() {},
    getBoundingClientRect() { return { left: 0, top: 0, width: 600, height: 300 }; },
  });
  const doc = { defaultView: { addEventListener() {}, removeEventListener() {} }, createElement: mk };
  const container = mk('div');
  (container as { ownerDocument: unknown }).ownerDocument = doc;
  return container as unknown as HTMLElement;
}
function fakeCanvas(): HTMLCanvasElement {
  const noop = (): void => {};
  const ctx: Ctx2D = { fillStyle: '', strokeStyle: '', lineWidth: 1, font: '', textAlign: '', textBaseline: '',
    setTransform: noop, fillRect: noop, clearRect: noop, strokeRect: noop, fillText: noop,
    save: noop, restore: noop, beginPath: noop, rect: noop, clip: noop };
  return { width: 0, height: 0, style: { width: '', height: '' }, getContext: () => ctx } as unknown as HTMLCanvasElement;
}

test('the view draws ▣ cells, dims them with their finder, and relayouts when rows change', () => {
  let t = 0;
  const queue: Array<() => void> = [];
  const bus = createSelectionBus();
  const grid = mountSharechainGrid({
    container: fakeDom(), bus, colorOf: () => '#00e676',
    clock: () => t, scheduler: { request: (cb) => { queue.push(cb); return 1; }, cancel: () => {} },
    createSurface: fakeCanvas, devicePixelRatio: () => 1, nowSeconds: () => 2_000,
  });
  const settle = (): void => { for (let i = 0; i < 300 && queue.length; i++) { t += 16; queue.splice(0).forEach((cb) => cb()); } };
  const rows = offChainBlocks(BLOCKS, SHARES, 'DASH');
  grid.update(SHARES, { offChain: rows });
  settle();
  const cell = grid.scene.placed().find((p) => p.key === `offchain:${BLOCKS[1]!.share}`)!;
  assert.ok(cell, '▣ cell present');
  assert.ok(cell.w >= 8);
  assert.equal(cell.color, parseCssColor(OFF_CHAIN_FILL));
  bus.pin('Xb', 'pplns-treemap');
  assert.ok(grid.scene.placed().find((p) => p.key === cell.key)!.flags & FLAG_DIM, 'finder Xa dims when Xb is pinned');
  bus.pin(null, 'pplns-treemap');
  // same window and same rows → restyle only; new rows → relayout
  grid.update(SHARES, { offChain: rows });
  assert.equal(grid.scene.isAnimating(), false);
  grid.update(SHARES, { offChain: [] });
  assert.equal(grid.scene.isAnimating(), true, 'the ▣ cells leave');
  settle();
  assert.ok(!grid.scene.placed().some((p) => p.key.startsWith('offchain:')));
  grid.destroy();
});

test('hour axis rows follow the laid-out cells (window + ▣), not the window alone', () => {
  // Pick a window size where two extra ▣ cells change the grid geometry.
  const VP = { x: 0, y: 0, w: 600, h: 300 };
  const gl = createGridLayout();
  let n = 10;
  while (gl.metrics(n, VP).step === gl.metrics(n + 2, VP).step) n++;
  const g = gl.metrics(n + 2, VP);
  const now = 100_000;
  const shares: GridShare[] = Array.from({ length: n }, (_, i) => ({ H: H(i), t: now - i * 1_500, m: 'Xa' }));
  const rows: BlockRow[] = [
    { hash: 'b1', share: 'aa'.repeat(32), ts: now - 2_000, chain: 'DASH' },
    { hash: 'b2', share: 'bb'.repeat(32), ts: now - 9_000, chain: 'DASH' },
  ];
  const texts: Array<{ text: string; y: number }> = [];
  const recCanvas = (): HTMLCanvasElement => {
    const c = fakeCanvas() as unknown as { getContext: () => Ctx2D };
    const ctx = c.getContext();
    ctx.fillText = (text: string, _x: number, y: number) => { texts.push({ text, y }); };
    return c as unknown as HTMLCanvasElement;
  };
  let t = 0;
  const queue: Array<() => void> = [];
  const grid = mountSharechainGrid({
    container: fakeDom(), colorOf: () => '#00e676',
    clock: () => t, scheduler: { request: (cb) => { queue.push(cb); return 1; }, cancel: () => {} },
    createSurface: recCanvas, devicePixelRatio: () => 1, nowSeconds: () => now,
  });
  grid.update(shares, { offChain: rows });
  for (let i = 0; i < 300 && queue.length; i++) { t += 16; queue.splice(0).forEach((cb) => cb()); }
  const hours = texts.filter((x) => /^\d+h$/.test(x.text));
  assert.ok(hours.length >= 2, 'the axis has labels');
  const rowYs = new Set(grid.scene.placed().map((p) => p.y + g.step / 2));
  for (const l of hours) assert.ok(rowYs.has(l.y), `${l.text} at y=${l.y} sits on a laid-out row`);
  grid.destroy();
});

test('dashboard.html wires ▣ cells from the ledger, with a text-only tooltip', () => {
  const block = section('c2pFluidGrid');
  // the same symbol expression as the "Blocks in Window" panel (psym)
  assert.match(block, /offChain: f\.mod\.offChainBlocks\(window\.c2pRecentBlocks, defrag\.shares, ci\.symbol \|\| 'COIN'\)/);
  assert.match(HTML, /var psym = ci\.symbol \|\| 'COIN';/);
  const tip = block.slice(block.indexOf('function c2pOffChainTip'), block.indexOf('function c2pFluidMount'));
  assert.match(tip, /d\.textContent = line;/);
  assert.doesNotMatch(tip, /innerHTML/, 'server fields never go through innerHTML');
  assert.match(HTML, /window\.c2pRecentBlocks = blocks \|\| \[\];\s*\n\s*if \(window\.c2pFluidActive && typeof defrag\.render === 'function'\) defrag\.render\(\);/,
    'a /recent_blocks refresh re-renders Fluid');
  assert.match(block, /window\.c2pFluidActive = false;\s*\n\s*defrag\.render = classicRender;/, 'a failed load stops Fluid re-renders');
});
