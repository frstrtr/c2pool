// PPLNS treemap feed (src/scene/views/pplns-feed.ts): payouts required,
// merged children and stratum workers optional, merged symbol read from
// the data, overlapping refreshes coalesced.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadPplnsSnapshot, mergedSymbolOf, coalesce, TileKind, buildPplnsItems } from '../../src/scene/index.js';

const PAYOUTS = { Lwhale: 5, Lmid: 1 };
const MERGED = {
  Lwhale: { amount: 5, merged: [{ symbol: 'doge', address: 'Dw', amount: 100, source: 'auto-convert' }] },
  Lmid: { amount: 1, merged: [] },
};
const STRATUM = { pool: {}, workers: { 'Lmid.rig1': {}, Lmid: {} } };
const ok = (v: unknown) => () => Promise.resolve(v);
const bad = () => Promise.reject(new Error('down'));

test('all feeds: snapshot, ★ from workers, merged symbol from the data', async () => {
  const r = await loadPplnsSnapshot({ payouts: ok(PAYOUTS), merged: ok(MERGED), stratum: ok(STRATUM) });
  assert.ok(r);
  assert.deepEqual(r!.snapshot.payouts, PAYOUTS);
  assert.deepEqual(r!.special.thisNode, ['Lmid']);
  assert.equal(r!.mergedSymbol, 'DOGE');
  const items = buildPplnsItems(r!.snapshot, 'parent', r!.mergedSymbol, r!.special);
  assert.equal(items.find((i) => i.key === 'Lmid')!.data!.kind, TileKind.ThisNode);
});

test('optional feeds may fail: the treemap still gets its payouts', async () => {
  const r = await loadPplnsSnapshot({ payouts: ok(PAYOUTS), merged: bad, stratum: bad });
  assert.ok(r);
  assert.equal(r!.snapshot.merged, undefined);
  assert.deepEqual(r!.special, {});
  assert.equal(r!.mergedSymbol, undefined);
  const r2 = await loadPplnsSnapshot({ payouts: ok(PAYOUTS) });
  assert.ok(r2, 'no optional sources at all');
});

test('no payouts → null (failed, not an object, or an array)', async () => {
  assert.equal(await loadPplnsSnapshot({ payouts: bad }), null);
  assert.equal(await loadPplnsSnapshot({ payouts: ok(null) }), null);
  assert.equal(await loadPplnsSnapshot({ payouts: ok([1, 2]) }), null);
});

test('mergedSymbolOf: first non-empty child symbol, upper-cased; none on DASH-shaped data', () => {
  assert.equal(mergedSymbolOf(MERGED), 'DOGE');
  assert.equal(mergedSymbolOf({ X: { amount: 1, merged: [] } }), undefined);
  assert.equal(mergedSymbolOf(null), undefined);
  assert.equal(mergedSymbolOf({ X: 5 }), undefined);
});

test('coalesce: one run at a time; calls during a run trigger exactly one more', async () => {
  let runs = 0;
  let release!: () => void;
  const gate = () => new Promise<void>((r) => { release = r; });
  let wait = gate();
  const refresh = coalesce(async () => { runs++; await wait; });
  const a = refresh();
  const b = refresh();
  const c = refresh();
  assert.equal(runs, 1, 'second and third calls wait');
  const first = release;
  wait = gate();
  first();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(runs, 2, 'exactly one follow-up run');
  release();
  await Promise.all([a, b, c]);
  assert.equal(runs, 2);
  await refresh();
  assert.equal(runs, 3, 'idle again: a new call runs at once');
});

test('coalesce: a throwing run does not wedge later refreshes', async () => {
  let n = 0;
  const refresh = coalesce(async () => { n++; if (n === 1) throw new Error('boom'); });
  await refresh();
  await refresh();
  assert.equal(n, 2);
});
