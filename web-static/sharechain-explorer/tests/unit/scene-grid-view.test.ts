// "Fluid (experimental)" share-chain grid on the scene engine: keyed
// cells (a new tip slides every cell one slot, evicted shares leave),
// host colours and block marks, the hour axis, hover / click handed to
// the host, bus linking with the PPLNS treemap, and the dashboard wiring.
// Runs on a minimal fake DOM.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  mountSharechainGrid, createSelectionBus, parseCssColor, hourAxisLabels, rgba, BLOCK_MARK,
  FLAG_DIM, FLAG_MATCH, type Ctx2D, type GridShare,
} from '../../src/scene/index.js';

type Listener = (ev: Record<string, unknown>) => void;
class FakeEl {
  style: Record<string, string> = {};
  children: FakeEl[] = [];
  parentNode: FakeEl | null = null;
  listeners = new Map<string, Set<Listener>>();
  clientWidth = 600; clientHeight = 300;
  constructor(public tag: string, public ownerDocument: FakeDoc) {}
  appendChild(c: FakeEl) { c.parentNode = this; this.children.push(c); return c; }
  insertBefore(c: FakeEl, ref: FakeEl | null) { c.parentNode = this; const i = ref === null ? -1 : this.children.indexOf(ref); if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); return c; }
  removeChild(c: FakeEl) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); c.parentNode = null; return c; }
  addEventListener(t: string, f: Listener) { (this.listeners.get(t) ?? this.listeners.set(t, new Set()).get(t)!).add(f); }
  removeEventListener(t: string, f: Listener) { this.listeners.get(t)?.delete(f); }
  fire(t: string, ev: Record<string, unknown> = {}) { for (const f of this.listeners.get(t) ?? []) f(ev); }
  getBoundingClientRect() { return { left: 0, top: 0, width: this.clientWidth, height: this.clientHeight }; }
}
class FakeDoc {
  defaultView = { addEventListener() {}, removeEventListener() {} };
  createElement(tag: string) { return new FakeEl(tag, this); }
}
function fakeCanvas(): unknown {
  const noop = (): void => {};
  const ctx: Ctx2D = {
    fillStyle: '', strokeStyle: '', lineWidth: 1, font: '', textAlign: '', textBaseline: '',
    setTransform: noop, fillRect: noop, clearRect: noop, strokeRect: noop, fillText: noop,
    save: noop, restore: noop, beginPath: noop, rect: noop, clip: noop,
  };
  return { width: 0, height: 0, style: { width: '', height: '' }, getContext: () => ctx };
}

const share = (i: number, over: Partial<GridShare> = {}): GridShare =>
  ({ h: `h${i}`, H: `H${i.toString().padStart(4, '0')}`, m: i % 3 === 0 ? 'Xalice' : 'Xbob', t: 1_000_000 - i * 30, ...over });

function mount(opts: { blocks?: Set<string> } = {}) {
  const doc = new FakeDoc();
  const container = doc.createElement('div');
  let t = 0;
  const queue: Array<() => void> = [];
  const bus = createSelectionBus();
  const hovers: Array<GridShare | null> = [];
  const clicks: GridShare[] = [];
  const grid = mountSharechainGrid({
    container: container as unknown as HTMLElement,
    colorOf: (s) => (s.m === 'Xalice' ? '#00e676' : '#2e7d32'),
    blockKindOf: (s) => (opts.blocks?.has(s.H!) ? 'primary' : null),
    bus,
    onHover: (s) => hovers.push(s),
    onClick: (s) => clicks.push(s),
    clock: () => t,
    scheduler: { request: (cb) => { queue.push(cb); return 1; }, cancel: () => {} },
    createSurface: () => fakeCanvas() as HTMLCanvasElement,
    devicePixelRatio: () => 1,
    nowSeconds: () => 1_000_000,
  });
  const stage = container.children[0]!;
  const settle = (): void => { for (let i = 0; i < 400 && queue.length > 0; i++) { t += 16; queue.splice(0).forEach((cb) => cb()); } };
  const tile = (key: string) => grid.scene.placed().find((p) => p.key === key);
  const centre = (key: string) => { const p = tile(key)!; return { clientX: p.x + p.w / 2, clientY: p.y + p.h / 2 }; };
  return { grid, bus, stage, container, settle, tile, centre, hovers, clicks };
}

test('one cell per share, newest first, keyed by full hash', () => {
  const m = mount();
  const window1 = Array.from({ length: 40 }, (_, i) => share(i));
  m.grid.update(window1);
  m.settle();
  const placed = m.grid.scene.placed();
  assert.equal(placed.length, 40);
  const a = m.tile('H0000')!, b = m.tile('H0001')!;
  assert.equal(a.y, b.y);
  assert.ok(b.x > a.x, 'the second share sits right of the tip');
});

test('a new tip slides every cell one slot; the evicted share leaves', () => {
  const m = mount();
  const w = Array.from({ length: 40 }, (_, i) => share(i + 1));
  m.grid.update(w);
  m.settle();
  const before = new Map(m.grid.scene.placed().map((p) => [p.key, [p.x, p.y]]));
  const next = [share(0), ...w.slice(0, 39)];   // new tip, oldest (H0040) evicted
  m.grid.update(next);
  m.settle();
  const after = new Map(m.grid.scene.placed().map((p) => [p.key, [p.x, p.y]]));
  assert.ok(after.has('H0000'), 'the new tip entered');
  assert.ok(!after.has('H0040'), 'the evicted share left');
  // H0001 took the slot H0000 now has... each cell moved to its successor's old slot.
  for (let i = 1; i < 39; i++) {
    const k = `H${i.toString().padStart(4, '0')}`;
    const succ = `H${(i + 1).toString().padStart(4, '0')}`;
    assert.deepEqual(after.get(k), before.get(succ), `${k} moved one slot`);
  }
});

test('colours come from the host; block cells get the core colour and a ring outline', () => {
  const m = mount({ blocks: new Set(['H0003']) });
  m.grid.update(Array.from({ length: 10 }, (_, i) => share(i)));
  m.settle();
  assert.equal(m.tile('H0000')!.color, parseCssColor('#00e676'));
  assert.equal(m.tile('H0001')!.color, parseCssColor('#2e7d32'));
  const block = m.tile('H0003')!;
  assert.ok(block.w >= 8, 'fixture cells are big enough for the ring');
  assert.equal(block.color, parseCssColor(BLOCK_MARK.primary.core));
  assert.ok(block.flags & FLAG_MATCH);
});

test('bus: pinning a miner (or hovering it in the treemap) dims the other miners\' cells', () => {
  const m = mount();
  m.grid.update(Array.from({ length: 12 }, (_, i) => share(i)));
  m.settle();
  m.bus.pin('Xalice', 'pplns-treemap');
  assert.equal(m.tile('H0000')!.flags & FLAG_DIM, 0, 'Xalice stays bright');
  assert.ok(m.tile('H0001')!.flags & FLAG_DIM, 'Xbob dims');
  m.bus.pin(null, 'pplns-treemap');
  m.bus.hover('Xbob', 'pplns-treemap');
  assert.ok(m.tile('H0000')!.flags & FLAG_DIM);
  assert.equal(m.tile('H0001')!.flags & FLAG_DIM, 0);
});

test('hover publishes the miner and hands the share to the host; leave and click too', () => {
  const m = mount();
  m.grid.update(Array.from({ length: 12 }, (_, i) => share(i)));
  m.settle();
  m.stage.fire('mousemove', m.centre('H0001'));
  assert.equal(m.bus.get().hover, 'Xbob');
  assert.equal(m.bus.get().source, 'grid');
  assert.equal(m.hovers.at(-1)?.H, 'H0001');
  assert.equal(m.tile('H0000')!.flags & FLAG_DIM, 0, 'own hover does not dim the grid');
  m.stage.fire('mouseleave');
  assert.equal(m.bus.get().hover, null);
  assert.equal(m.hovers.at(-1), null);
  m.stage.fire('click', m.centre('H0002'));
  assert.equal(m.clicks.at(-1)?.H, 'H0002');
});

test('same window array again: restyle only, no relayout', () => {
  const m = mount();
  const w = Array.from({ length: 12 }, (_, i) => share(i));
  m.grid.update(w);
  m.settle();
  const before = m.grid.scene.placed();
  m.grid.update(w);
  assert.equal(m.grid.scene.isAnimating(), false);
  assert.deepEqual(m.grid.scene.placed().map((p) => [p.key, p.x]), before.map((p) => [p.key, p.x]));
});

test('destroy removes the stage and its listeners', () => {
  const m = mount();
  m.grid.update([share(0)]);
  m.grid.destroy();
  assert.equal(m.container.children.length, 0);
  assert.equal(m.stage.listeners.get('mousemove')?.size ?? 0, 0);
});

test('parseCssColor: hex, short hex, hex with alpha, rgb(a); null otherwise', () => {
  assert.equal(parseCssColor('#00e676'), rgba(0, 0xe6, 0x76));
  assert.equal(parseCssColor('#fff'), rgba(255, 255, 255));
  assert.equal(parseCssColor('#11223380'), rgba(0x11, 0x22, 0x33, 0x80));
  assert.equal(parseCssColor('rgb(1, 2, 3)'), rgba(1, 2, 3));
  assert.equal(parseCssColor('rgba(1,2,3,0.5)'), rgba(1, 2, 3, 128));
  assert.equal(parseCssColor('chartreuse'), null);
});

test('hour axis labels a row when its mean share age crosses into a new hour', () => {
  const shares: GridShare[] = Array.from({ length: 30 }, (_, i) => ({ t: 1_000_000 - i * 300 }));  // 5 min apart: rows 0,2,4 start hours 0,1,2
  const labels = hourAxisLabels(shares, { cols: 6, rows: 5, step: 10, marginLeft: 38 }, 1_000_000);
  assert.deepEqual(labels.map((l) => l.text), ['0h', '1h', '2h']);
  assert.ok(labels.every((l) => l.align === 'right' && l.x === 34));
});

test('dashboard.html: Fluid is opt-in, Classic the default, scene.js stamped, Classic restored on failure', () => {
  const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
  const a = html.indexOf('// BEGIN c2pFluidGrid');
  const b = html.indexOf('// END c2pFluidGrid');
  assert.ok(a > 0 && b > a);
  const block = html.slice(a, b);
  assert.match(block, /q\.get\('explorer-anim'\) === 'fluid' \? 'fluid' : 'classic'/);
  assert.match(block, /localStorage\.getItem\('c2p_explorer_anim'\) === 'fluid' \? 'fluid' : 'classic'/);
  assert.match(block, /import\('\.\/sharechain-explorer\/dist\/scene\.js\?v=[0-9a-f]{8}'\)/);
  assert.match(block, /if \(window\.__c2pBundledExplorer \|\| mode !== 'fluid'\) return;/, 'Classic unless opted in');
  assert.match(block, /defrag\.render = classicRender;/, 'a failed load restores Classic');
  assert.match(block, /colorOf: function\(s\) \{ return defrag\.getColor\(s\); \}/, 'Classic colours');
  assert.match(html, /var bus = window\.c2pSelectionBus \|\| mod\.createSelectionBus\(\);/, 'treemap and grid share one bus');
  assert.match(html, /id="anim-fluid"[^>]*>Fluid \(experimental\)</);
});
