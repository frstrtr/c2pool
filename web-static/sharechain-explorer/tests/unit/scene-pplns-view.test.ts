// PPLNS treemap view, DOM half: mount into a container, hover → tooltip
// and linked highlight, click → pin, Esc → unpin, click on "N others" →
// expand, the coin toggle re-weights the same keys, search dims, a
// linked view's hover highlights here, destroy cleans up. Runs against a
// minimal fake DOM (no browser).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  mountPplnsTreemap, createSelectionBus, FLAG_DIM, FLAG_PINNED, FLAG_SELECTED, DEFAULT_OTHERS_KEY,
  type Ctx2D, type PplnsSnapshot,
} from '../../src/scene/index.js';

type Listener = (ev: Record<string, unknown>) => void;

class FakeEl {
  style: Record<string, string> = {};
  children: FakeEl[] = [];
  parentNode: FakeEl | null = null;
  listeners = new Map<string, Set<Listener>>();
  className = ''; type = ''; textContent = ''; innerHTML = ''; value = ''; placeholder = '';
  clientWidth = 600; clientHeight = 300; offsetWidth = 200; offsetHeight = 80;
  constructor(public tag: string, public ownerDocument: FakeDoc) {}
  appendChild(c: FakeEl) { c.parentNode = this; this.children.push(c); return c; }
  insertBefore(c: FakeEl, ref: FakeEl | null) {
    c.parentNode = this;
    const i = ref === null ? -1 : this.children.indexOf(ref);
    if (i < 0) this.children.push(c); else this.children.splice(i, 0, c);
    return c;
  }
  removeChild(c: FakeEl) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); c.parentNode = null; return c; }
  addEventListener(type: string, fn: Listener) { (this.listeners.get(type) ?? this.listeners.set(type, new Set()).get(type)!).add(fn); }
  removeEventListener(type: string, fn: Listener) { this.listeners.get(type)?.delete(fn); }
  fire(type: string, ev: Record<string, unknown> = {}) { for (const fn of this.listeners.get(type) ?? []) fn(ev); }
  getBoundingClientRect() { return { left: 0, top: 0, width: this.clientWidth, height: this.clientHeight }; }
  count(): number { return this.children.reduce((n, c) => n + 1 + c.count(), 0); }
}

class FakeDoc {
  listeners = new Map<string, Set<Listener>>();
  defaultView = {
    innerWidth: 1280, innerHeight: 900, opened: [] as string[],
    addEventListener() {}, removeEventListener() {},
    open(u: string) { this.opened.push(u); },
  };
  createElement(tag: string) { return new FakeEl(tag, this); }
  addEventListener(type: string, fn: Listener) { (this.listeners.get(type) ?? this.listeners.set(type, new Set()).get(type)!).add(fn); }
  removeEventListener(type: string, fn: Listener) { this.listeners.get(type)?.delete(fn); }
  fire(type: string, ev: Record<string, unknown>) { for (const fn of this.listeners.get(type) ?? []) fn(ev); }
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

const SNAP: PplnsSnapshot = {
  payouts: {
    Lwhale: 5.0, Lmid: 1.5, Lthird: 0.8,
    ...Object.fromEntries(Array.from({ length: 6 }, (_, i) => [`Ltiny${i}`, 0.001])),
  },
  merged: {
    Lwhale: { amount: 5.0, merged: [{ symbol: 'DOGE', address: 'Dw', amount: 100, source: 'auto-convert' }] },
    Lmid: { amount: 1.5, merged: [{ symbol: 'DOGE', address: 'Dm', amount: 900, source: 'explicit' }] },
    Lthird: { amount: 0.8, merged: [{ symbol: 'DOGE', address: 'Dt', amount: 50, source: 'explicit' }] },
  },
};

function mount() {
  const doc = new FakeDoc();
  const container = doc.createElement('div');
  let t = 0;
  const queue: Array<() => void> = [];
  const bus = createSelectionBus();
  const opened: string[] = [];
  const view = mountPplnsTreemap({
    container: container as unknown as HTMLElement,
    symbol: 'LTC', mergedSymbol: 'DOGE', bus,
    addressUrl: (a) => `https://explorer.example/address/${a}`,
    open: (u) => opened.push(u),
    clock: () => t,
    scheduler: { request: (cb) => { queue.push(cb); return 1; }, cancel: () => {} },
    createSurface: () => fakeCanvas() as HTMLCanvasElement,
    devicePixelRatio: () => 1,
  });
  const root = container.children[0]!;
  const [bar, stage, tip] = root.children as [FakeEl, FakeEl, FakeEl];
  const settle = (): void => { for (let i = 0; i < 400 && queue.length > 0; i++) { t += 16; queue.splice(0).forEach((cb) => cb()); } };
  const centre = (key: string) => {
    const p = view.scene.placed().find((x) => x.key === key)!;
    return { clientX: p.x + p.w / 2, clientY: p.y + p.h / 2 };
  };
  const flags = (key: string) => view.scene.placed().find((x) => x.key === key)!.flags;
  return { doc, container, view, bus, bar, stage, tip, settle, centre, flags, opened };
}

test('mount: toolbar, stage and tooltip in the container; tiles after update', () => {
  const m = mount();
  assert.equal(m.container.children.length, 1);
  const labels = m.bar.children.map((c) => c.textContent);
  assert.ok(labels.includes('LTC') && labels.includes('DOGE'), 'coin toggle for a merged child');
  m.view.update(SNAP);
  m.settle();
  const keys = m.view.scene.placed().map((p) => p.key);
  assert.ok(keys.includes('Lwhale') && keys.includes(DEFAULT_OTHERS_KEY), keys.join(','));
});

test('hover shows the tooltip and highlights; leave clears', () => {
  const m = mount();
  m.view.update(SNAP);
  m.settle();
  m.stage.fire('mousemove', m.centre('Lmid'));
  assert.equal(m.bus.get().hover, 'Lmid');
  assert.equal(m.tip.style.display, 'block');
  assert.ok(m.tip.innerHTML.includes('Lmid'));
  assert.ok(m.flags('Lmid') & FLAG_SELECTED);
  m.stage.fire('mouseleave');
  assert.equal(m.bus.get().hover, null);
  assert.equal(m.tip.style.display, 'none');
});

test('click pins, Esc unpins; ctrl-click opens the address explorer', () => {
  const m = mount();
  m.view.update(SNAP);
  m.settle();
  m.stage.fire('click', m.centre('Lwhale'));
  assert.equal(m.bus.get().pinned, 'Lwhale');
  assert.ok(m.flags('Lwhale') & FLAG_PINNED);
  assert.ok(m.flags('Lmid') & FLAG_DIM);
  m.doc.fire('keydown', { key: 'Escape' });
  assert.equal(m.bus.get().pinned, null);
  m.stage.fire('click', { ...m.centre('Lmid'), ctrlKey: true });
  assert.deepEqual(m.opened, ['https://explorer.example/address/Lmid']);
  assert.equal(m.bus.get().pinned, null, 'ctrl-click does not pin');
});

test('click on "N others" lays the small miners out; Esc groups them again', () => {
  const m = mount();
  m.view.update(SNAP);
  m.settle();
  m.stage.fire('click', m.centre(DEFAULT_OTHERS_KEY));
  m.settle();
  const keys = m.view.scene.placed().map((p) => p.key);
  assert.ok(!keys.includes(DEFAULT_OTHERS_KEY));
  assert.ok(keys.includes('Ltiny0') && keys.includes('Ltiny5'));
  m.doc.fire('keydown', { key: 'Escape' });
  m.settle();
  assert.ok(m.view.scene.placed().some((p) => p.key === DEFAULT_OTHERS_KEY));
});

test('coin toggle: the same miners tween to their merged-child weights', () => {
  const m = mount();
  m.view.update(SNAP);
  m.settle();
  const parentArea = (k: string) => { const p = m.view.scene.placed().find((x) => x.key === k)!; return p.w * p.h; };
  assert.ok(parentArea('Lwhale') > parentArea('Lmid'));
  const dogeBtn = m.bar.children.find((c) => c.textContent === 'DOGE')!;
  dogeBtn.fire('click');
  m.settle();
  assert.ok(parentArea('Lmid') > parentArea('Lwhale'), 'DOGE weights: Lmid 900 > Lwhale 100');
  assert.ok(!m.view.scene.placed().some((p) => p.key.startsWith('Ltiny')), 'miners without a child share drop out');
});

test('search dims non-matching tiles; a linked view hover highlights here', () => {
  const m = mount();
  m.view.update(SNAP);
  m.settle();
  const input = m.bar.children.find((c) => c.tag === 'input')!;
  input.value = 'third';
  input.fire('input');
  assert.ok(m.flags('Lwhale') & FLAG_DIM);
  assert.ok(!(m.flags('Lthird') & FLAG_DIM));
  m.bus.search('', 'toolbar');
  m.bus.hover('Lwhale', 'grid');
  assert.ok(m.flags('Lwhale') & FLAG_SELECTED, 'linked hover');
});

test('log scale shows the non-proportional badge', () => {
  const m = mount();
  m.view.update(SNAP);
  m.view.setScale('log');
  const badge = m.bar.children.find((c) => c.textContent.includes('NOT proportional'))!;
  assert.equal(badge.style.display, 'inline');
  m.view.setScale('linear');
  assert.equal(badge.style.display, 'none');
});

test('destroy removes everything and its listeners', () => {
  const m = mount();
  m.view.update(SNAP);
  m.view.destroy();
  assert.equal(m.container.children.length, 0);
  assert.equal(m.doc.listeners.get('keydown')?.size ?? 0, 0);
  assert.equal(m.stage.listeners.get('mousemove')?.size ?? 0, 0);
});

test('dashboard.html: the view is opt-in, stamped, and the grid only dims when a miner is focused', async () => {
  const { readFileSync } = await import('node:fs');
  const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
  const a = html.indexOf('// BEGIN c2pPplnsView');
  const b = html.indexOf('// END c2pPplnsView');
  assert.ok(a > 0 && b > a, 'c2pPplnsView block present');
  const block = html.slice(a, b);
  assert.match(block, /q\.has\('pplns-view'\)/);
  assert.match(block, /localStorage\.getItem\('c2p_pplns_view'\) === '1'/);
  assert.match(block, /import\('\.\/sharechain-explorer\/dist\/scene\.js\?v=[0-9a-f]{8}'\)/);
  assert.match(block, /d3\.json\('\.\.\/current_payouts'/, 'weights from /current_payouts');
  assert.doesNotMatch(block, /block_value_miner/, 'never the projected block value as a denominator');
  assert.doesNotMatch(block, /my_address/, 'the owner is never inferred from my_address');
  assert.match(html, /function loadMainPPLNS\(_attempt\) \{\s*if \(c2pPplnsViewEnabled\(\)\) \{ loadPplnsView\(\); return; \}/);
  assert.match(html, /var dimCell = !!this\.focusMiner && share\.m !== this\.focusMiner;/);
});
