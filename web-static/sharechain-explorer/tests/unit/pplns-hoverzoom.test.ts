// Tests for Phase B #12 — PPLNS parsing, orchestrator PPLNS capture,
// hover-zoom paint program.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parsePPLNS,
  buildHoverZoomProgram,
  RealtimeOrchestrator,
  type ShareForClassify,
  type Transport,
  type TipEvent,
  type ExplorerError,
  type PaintCommand,
} from '../../src/explorer/index.js';

// ── parsePPLNS ──────────────────────────────────────────────────

test('parsePPLNS: empty input → empty output', () => {
  assert.deepEqual(parsePPLNS({}), []);
  assert.deepEqual(parsePPLNS(null), []);
  assert.deepEqual(parsePPLNS('string'), []);
  assert.deepEqual(parsePPLNS([]), []);
});

test('parsePPLNS: flat {addr: amount} shape', () => {
  const r = parsePPLNS({ Xa: 0.6, Xb: 0.3, Xc: 0.1 });
  assert.equal(r.length, 3);
  // Sort desc by amt
  assert.equal(r[0]?.addr, 'Xa');
  assert.equal(r[1]?.addr, 'Xb');
  assert.equal(r[2]?.addr, 'Xc');
  // pct sums to ~1
  const sum = r.reduce((a, e) => a + e.pct, 0);
  assert.ok(Math.abs(sum - 1) < 1e-9);
});

test('parsePPLNS: merged {addr: {amount, merged}} shape', () => {
  const r = parsePPLNS({
    Xa: { amount: 0.5, merged: [{ symbol: 'DOGE', amount: 100 }] },
    Xb: { amount: 0.5 },
  });
  assert.equal(r.length, 2);
  assert.equal(r[0]?.amt, 0.5);
  assert.equal(r[1]?.amt, 0.5);
});

test('parsePPLNS: filters zero/negative/NaN amounts', () => {
  const r = parsePPLNS({ Xa: 1, Xb: 0, Xc: -1, Xd: NaN, Xe: 2 });
  assert.deepEqual(r.map((e) => e.addr), ['Xe', 'Xa']);
});

test('parsePPLNS: tolerates objects without amount field', () => {
  const r = parsePPLNS({ Xa: { merged: [] }, Xb: 0.5 });
  // Xa counts as 0 → filtered; Xb survives.
  assert.deepEqual(r.map((e) => e.addr), ['Xb']);
});

// ── Orchestrator PPLNS capture ──────────────────────────────────

function sh(h: string, over: Partial<ShareForClassify> = {}): ShareForClassify {
  return { s: 0, v: 1, V: 36, dv: 36, m: 'Xother', ...over, h } as unknown as ShareForClassify;
}

interface MockT extends Transport {
  fireTip(ev: TipEvent): void;
}

function makeTransport(window: Record<string, unknown>, delta?: Record<string, unknown>): MockT {
  const subs: Array<{ onTip: (ev: TipEvent) => void; onRec?: () => void }> = [];
  return {
    kind: 'demo',
    fetchWindow: async () => window,
    fetchTip: async () => ({ hash: 'a'.repeat(16), height: 1 }),
    fetchDelta: async () => delta ?? { shares: [] },
    fetchStats: async () => ({}),
    fetchShareDetail: async () => ({}),
    negotiate: async () => ({ apiVersion: '1.0' }),
    fetchCurrentPayouts: async () => ({ miners: [] }),
    fetchMinerDetail: async () => ({}),
    subscribeStream(onTip, _onErr?: (err: ExplorerError) => void, onRec?: () => void) {
      const entry: typeof subs[number] = { onTip };
      if (onRec !== undefined) entry.onRec = onRec;
      subs.push(entry);
      return { unsubscribe() { subs.splice(subs.indexOf(entry), 1); } };
    },
    fireTip(ev) { for (const s of subs) s.onTip(ev); },
  };
}

test('orchestrator: captures pplns_current from /sharechain/window', async () => {
  const t = makeTransport({
    shares: [sh('a'), sh('b')],
    pplns_current: { Xa: 0.7, Xb: 0.3 },
  });
  const o = new RealtimeOrchestrator({
    transport: t,
    userContext: { shareVersion: 36 },
    containerWidth: () => 1000,
  });
  await o.start();
  const entries = o.getPPLNSForShare(undefined);
  assert.equal(entries.length, 2);
  assert.equal(entries[0]?.addr, 'Xa');
  await o.stop();
});

test('orchestrator: getPPLNSForShare exact match', async () => {
  const t = makeTransport({
    shares: [sh('a'), sh('b')],
    pplns_current: { Xfallback: 1 },
    pplns: { 'a': { Xexact: 1 } },
  });
  const o = new RealtimeOrchestrator({
    transport: t,
    userContext: { shareVersion: 36 },
    containerWidth: () => 1000,
  });
  await o.start();
  const entries = o.getPPLNSForShare('a');
  assert.equal(entries.length, 1);
  assert.equal(entries[0]?.addr, 'Xexact');
  await o.stop();
});

test('orchestrator: getPPLNSForShare walks backward for nearest cached', async () => {
  const t = makeTransport({
    shares: [sh('a'), sh('b'), sh('c'), sh('d')],
    pplns_current: { Xfallback: 1 },
    pplns: { 'a': { Xa: 1 } },  // only 'a' has cached data
  });
  const o = new RealtimeOrchestrator({
    transport: t,
    userContext: { shareVersion: 36 },
    containerWidth: () => 1000,
  });
  await o.start();
  // Looking up 'c' walks backward (toward newer — lower index) to find 'a'.
  const entries = o.getPPLNSForShare('c');
  assert.equal(entries.length, 1);
  assert.equal(entries[0]?.addr, 'Xa');
  await o.stop();
});

test('orchestrator: getPPLNSForShare falls back to pplns_current', async () => {
  const t = makeTransport({
    shares: [sh('a')],
    pplns_current: { Xfallback: 1 },
  });
  const o = new RealtimeOrchestrator({
    transport: t,
    userContext: { shareVersion: 36 },
    containerWidth: () => 1000,
  });
  await o.start();
  assert.equal(o.getPPLNSForShare('a')[0]?.addr, 'Xfallback');
  assert.equal(o.getPPLNSForShare(undefined)[0]?.addr, 'Xfallback');
  await o.stop();
});

test('orchestrator: PPLNS merges additively across deltas', async () => {
  const t = makeTransport(
    {
      shares: [sh('a')],
      pplns_current: { Xfallback: 1 },
      pplns: { 'a': { Xa: 1 } },
    },
    {
      shares: [sh('b')],
      pplns: { 'b': { Xb: 1 } },
    },
  );
  const o = new RealtimeOrchestrator({
    transport: t,
    userContext: { shareVersion: 36 },
    containerWidth: () => 1000,
  });
  await o.start();
  t.fireTip({ hash: 'b', height: 2 });
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
  // Both a and b should resolve to their own entries.
  assert.equal(o.getPPLNSForShare('a')[0]?.addr, 'Xa');
  assert.equal(o.getPPLNSForShare('b')[0]?.addr, 'Xb');
  await o.stop();
});

// ── buildHoverZoomProgram ───────────────────────────────────────

test('buildHoverZoomProgram: empty pplns → setTransform + background only', () => {
  const program = buildHoverZoomProgram({
    pplns: [],
    size: 240,
    dpr: 2,
  });
  assert.equal(program.length, 2);
  assert.equal(program[0]?.op, 'setTransform');
  assert.equal(program[1]?.op, 'fillBackground');
});

test('buildHoverZoomProgram: emits fillCell + strokeRect per miner', () => {
  const program = buildHoverZoomProgram({
    pplns: [
      { addr: 'Xa', amt: 0.5, pct: 0.5 },
      { addr: 'Xb', amt: 0.5, pct: 0.5 },
    ],
    size: 240,
    dpr: 1,
  });
  const fills = program.filter((c) => c.op === 'fillCell');
  const strokes = program.filter((c) => c.op === 'strokeRect');
  assert.equal(fills.length, 2);       // one per miner
  // Two strokes per miner: border + (if hovered) highlight. With no
  // hoveredMinerAddr, only the border stroke fires.
  assert.equal(strokes.length, 2);
});

test('buildHoverZoomProgram: hoveredMinerAddr gets white highlight stroke', () => {
  const program = buildHoverZoomProgram({
    pplns: [{ addr: 'Xa', amt: 1, pct: 1 }],
    size: 240,
    dpr: 1,
    hoveredMinerAddr: 'Xa',
  });
  const strokes = program.filter(
    (c): c is Extract<PaintCommand, { op: 'strokeRect' }> => c.op === 'strokeRect',
  );
  // Border + highlight = 2 stroke ops.
  assert.equal(strokes.length, 2);
  const highlight = strokes.find((s) => s.color === '#ffffff');
  assert.ok(highlight);
  assert.equal(highlight!.lineWidth, 2.5);
});

test('buildHoverZoomProgram: large cells get % label', () => {
  // Use single miner so its cell fills the whole 240×240 panel.
  const program = buildHoverZoomProgram({
    pplns: [{ addr: 'Xaaabbbcccddd', amt: 1, pct: 1 }],
    size: 240,
    dpr: 1,
  });
  const texts = program.filter(
    (c): c is Extract<PaintCommand, { op: 'textCenter' }> => c.op === 'textCenter',
  );
  // Expect both % and address labels (cell is 236×236 — well over the
  // 44×28 threshold).
  assert.ok(texts.length >= 2);
  assert.ok(texts.some((t) => t.text.endsWith('%')));
});

test('buildHoverZoomProgram: tiny cells skip labels', () => {
  const many = Array.from({ length: 50 }, (_, i) => ({
    addr: `X${i}`,
    amt: 1,
    pct: 1 / 50,
  }));
  const program = buildHoverZoomProgram({
    pplns: many,
    size: 120,  // small panel → small cells
    dpr: 1,
  });
  const texts = program.filter((c) => c.op === 'textCenter');
  // Most cells are under the 30×16 threshold — labels suppressed.
  assert.ok(texts.length < many.length);
});
