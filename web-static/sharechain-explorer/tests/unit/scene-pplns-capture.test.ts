// PPLNS treemap gates on a REAL capture: public dash.voidbind endpoints
// fetched within 2.9 s of each other (tests/unit/fixtures/
// dash-voidbind-20261115/META.json), plus the inline/bundled parity gate:
// the engine treemap puts every tile within 1 px of the inline
// dashboard.html "PPLNS Distribution" for the same input.
//
// Gates (agreed with the endpoint owner):
//   1. tile area share == amount / sum(/current_payouts), within 1e-9;
//   2. "% of miner payouts" uses sum(/current_payouts), so tiles add up
//      to 100%; /local_stats block_value_miner is never a denominator
//      (on this relay it is a fee-less projection 0.00021 DASH lower);
//   3. on DASH, /current_payouts and /current_merged_payouts agree on
//      every parent amount.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  buildPplnsItems, parentAmountMismatches, classifyAddress, tooltipLines, createTreemapLayout, TileKind,
  type CurrentPayouts, type CurrentMergedPayouts, type PplnsSnapshot, type Tile, type MinerDatum,
} from '../../src/scene/index.js';
import { squarify } from '../../src/pplns/squarify.js';

const fx = (f: string): unknown =>
  JSON.parse(readFileSync(new URL(`./fixtures/dash-voidbind-20261115/${f}`, import.meta.url), 'utf8'));
const payouts = fx('current_payouts.json') as CurrentPayouts;
const merged = fx('current_merged_payouts.json') as CurrentMergedPayouts;
const windowFields = fx('sharechain_window_fields.json') as { fee_hash160: string; my_address: string };
const SNAP: PplnsSnapshot = { payouts, merged };
const VIEW = { x: 0, y: 0, w: 960, h: 320 };
const sum = (o: Record<string, number>): number => Object.values(o).reduce((s, v) => s + v, 0);

test('capture is what META says (2 entries, sum 0.41115545 DASH)', () => {
  const meta = fx('META.json') as { current_payouts_entries: number; current_payouts_sum: number };
  assert.equal(Object.keys(payouts).length, meta.current_payouts_entries);
  assert.ok(Math.abs(sum(payouts) - meta.current_payouts_sum) < 1e-12);
});

test('gate 1: tile area share == amount / sum(/current_payouts) within 1e-9', () => {
  const total = sum(payouts);
  const tiles = createTreemapLayout({ gap: 0, othersFraction: 0 }).layout(buildPplnsItems(SNAP, 'parent', undefined), VIEW);
  assert.equal(tiles.length, Object.keys(payouts).length);
  for (const t of tiles) {
    assert.ok(Math.abs((t.w * t.h) / (VIEW.w * VIEW.h) - payouts[t.key]! / total) < 1e-9, t.key);
  }
});

test('gate 2: "% of miner payouts" adds up to 100% and uses the payout sum', () => {
  const total = sum(payouts);
  let pct = 0;
  for (const [address, amount] of Object.entries(payouts)) {
    const tile: Tile<MinerDatum> = { key: address, x: 0, y: 0, w: 1, h: 1, weight: amount, aggregate: false,
      items: [{ key: address, weight: amount, data: { address, amount, childAmount: 0, kind: TileKind.Plain } }] };
    const line = tooltipLines(tile, { total, parentTotal: total, mode: 'parent', symbol: 'DASH' })
      .map((l) => l.text).find((l) => l.startsWith('next block:'))!;
    pct += Number(/\(([\d.]+)% of miner payouts\)/.exec(line)![1]);
    assert.ok(line.includes(`${amount.toFixed(8)} DASH`), 'expected payout is the amount as-is');
  }
  assert.ok(Math.abs(pct - 100) < 0.02, `sums to ${pct}`);
});

test('gate 3: DASH /current_payouts and /current_merged_payouts agree on every parent amount', () => {
  assert.deepEqual(parentAmountMismatches(payouts, merged), []);
});

test('this relay publishes no owner and serves no workers: no ⚑, no ★', () => {
  assert.equal(windowFields.fee_hash160, '');
  for (const address of Object.keys(payouts)) {
    assert.equal(classifyAddress(address, { ownerHash160: windowFields.fee_hash160, thisNode: [] }), TileKind.Plain);
  }
});

// ── inline/bundled parity ≤ 1 px ──────────────────────────────────

/** The inline "PPLNS Distribution" layout, run from dashboard.html's own
 *  c2pLayout block (renderMainPPLNS: rows by pct, minStrip 1). */
function inlineMainRects(entries: Array<{ addr: string; pct: number }>, w: number, h: number) {
  const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
  const a = html.indexOf('// BEGIN c2pLayout');
  const b = html.indexOf('// END c2pLayout');
  assert.ok(a >= 0 && b > a, 'c2pLayout block present');
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  const c2pSquarify = new Function('C2PLayout', `${html.slice(a, b)}\nreturn c2pSquarify;`)({ squarify }) as
    (items: unknown[], x: number, y: number, w: number, h: number) => Array<{ x: number; y: number; w: number; h: number; data: { addr: string } }>;
  return c2pSquarify(entries.map((d) => ({ area: d.pct, data: d })), 0, 0, w, h);
}

function assertParity(snap: PplnsSnapshot, label: string): void {
  const total = sum(snap.payouts);
  const entries = Object.entries(snap.payouts).map(([addr, amt]) => ({ addr, amt, pct: amt / total }))
    .sort((x, y) => y.amt - x.amt);
  const inline = new Map(inlineMainRects(entries, VIEW.w, VIEW.h).map((r) => [r.data.addr, r]));
  // The view's layout with aggregation off (the inline treemap has none)
  // and its 1 px gap: each tile is the inline cell inset by 0.5 px.
  const engine = createTreemapLayout({ gap: 1, othersFraction: 0 }).layout(buildPplnsItems(snap, 'parent', undefined), VIEW);
  assert.equal(engine.length, inline.size, `${label}: same tiles`);
  for (const t of engine) {
    const r = inline.get(t.key)!;
    for (const [k, d] of [['x', t.x - r.x], ['y', t.y - r.y], ['w', t.w - r.w], ['h', t.h - r.h]] as const) {
      assert.ok(Math.abs(d) <= 1 + 1e-9, `${label}: ${t.key} ${k} off by ${d}`);
    }
  }
}

test('parity ≤ 1 px: engine treemap vs inline dashboard treemap, DASH capture', () => {
  assertParity(SNAP, 'dash capture');
});

test('parity ≤ 1 px: engine treemap vs inline dashboard treemap, a 12-miner pool', () => {
  const raw = JSON.parse(readFileSync(new URL('../visual/fixtures/merged_payouts.json', import.meta.url), 'utf8')) as
    Record<string, { amount: number }>;
  assertParity({ payouts: Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, v.amount])) }, 'visual fixture');
});
