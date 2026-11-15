// PPLNS treemap view, pure half: endpoint JSON → items (weights from
// /current_payouts), the weights gate on the laid-out tiles, the parent
// agreement between /current_payouts and /current_merged_payouts,
// special-tile classification (★ ⚑ ◇, never from address prefixes),
// style flags for hover/pin/search, labels and tooltip content.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildPplnsItems, classifyAddress, addressesFromWorkers, parentAmountMismatches,
  pplnsStyle, pplnsLabels, tooltipLines, tooltipHtml, hash160OfAddress, shortAddress, formatAge,
  createTreemapLayout, createSelectionBus, TileKind, kindOf,
  FLAG_DIM, FLAG_MATCH, FLAG_PINNED, FLAG_SELECTED,
  type PplnsSnapshot, type PlacedTile, type MinerDatum, type Tile,
} from '../../src/scene/index.js';

// Shapes as served (web_server.cpp rest_current_payouts /
// rest_current_merged_payouts): coins as floats keyed by address.
const LTC: PplnsSnapshot = {
  payouts: { Lwhale: 5.9, Lmid: 0.25, Lsmall: 0.004, MLhSmDonation: 0.0005 },
  merged: {
    Lwhale: { amount: 5.9, merged: [{ symbol: 'DOGE', address: 'Dwhale', amount: 9400, source: 'auto-convert', parent: 'Lwhale' }] },
    Lmid: { amount: 0.25, merged: [{ symbol: 'DOGE', address: 'Dmid', amount: 410, source: 'explicit', parent: 'Lmid' }] },
    Lsmall: { amount: 0.004, merged: [{ symbol: 'DOGE', address: 'Dsmall', amount: 6.5, source: 'auto-convert', parent: 'Lsmall' }] },
    MLhSmDonation: { amount: 0.0005, merged: [{ symbol: 'DOGE', address: 'Ddon', amount: 0.8, source: 'donation' }] },
  },
};

const DASH: PplnsSnapshot = {
  payouts: { XoZcEF: 1.584, Xy7Pq: 0.0345, Xb19z: 0.0148, XdgF55: 1e-8 },
  merged: { XoZcEF: { amount: 1.584, merged: [] }, Xy7Pq: { amount: 0.0345, merged: [] }, Xb19z: { amount: 0.0148, merged: [] }, XdgF55: { amount: 1e-8, merged: [] } },
};

const VIEW = { x: 0, y: 0, w: 800, h: 300 };
const sum = (xs: number[]): number => xs.reduce((s, v) => s + v, 0);

test('items: weight = /current_payouts amount; merged child attached', () => {
  const items = buildPplnsItems(LTC, 'parent', 'DOGE');
  assert.deepEqual(items.map((i) => [i.key, i.weight]), Object.entries(LTC.payouts));
  const w = items.find((i) => i.key === 'Lwhale')!.data!;
  assert.equal(w.amount, 5.9);
  assert.equal(w.childAmount, 9400);
  assert.equal(w.childAddress, 'Dwhale');
  assert.equal(w.childSource, 'auto-convert');
});

test('merged mode re-weights the SAME keys by the child amount', () => {
  const parent = buildPplnsItems(LTC, 'parent', 'DOGE');
  const merged = buildPplnsItems(LTC, 'merged', 'DOGE');
  assert.deepEqual(merged.map((i) => i.key).sort(), parent.map((i) => i.key).sort());
  assert.equal(merged.find((i) => i.key === 'Lmid')!.weight, 410);
});

test('weights gate: tile cells are proportional to /current_payouts (LTC and DASH shapes)', () => {
  for (const snap of [LTC, DASH]) {
    const items = buildPplnsItems(snap, 'parent', 'DOGE');
    const total = sum(Object.values(snap.payouts));
    const tiles = createTreemapLayout({ gap: 0, othersFraction: 0 }).layout(items, VIEW);
    assert.equal(tiles.length, Object.keys(snap.payouts).length);
    for (const t of tiles) {
      const want = snap.payouts[t.key]! / total;
      assert.ok(Math.abs((t.w * t.h) / (VIEW.w * VIEW.h) - want) < 1e-9, `${t.key}`);
    }
  }
});

test('DASH: /current_payouts and /current_merged_payouts agree on every parent amount', () => {
  assert.deepEqual(parentAmountMismatches(DASH.payouts, DASH.merged!), []);
  assert.deepEqual(parentAmountMismatches(LTC.payouts, LTC.merged!), []);
  const drifted = { ...DASH.merged!, Xy7Pq: { amount: 0.03, merged: [] } };
  assert.deepEqual(parentAmountMismatches(DASH.payouts, drifted).map((m) => m.address), ['Xy7Pq']);
});

test('hash160 of P2PKH / bech32 v0 addresses (known vectors); others null', () => {
  assert.equal(hash160OfAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'), '62e907b15cbf27d5425399ebf6f0fb50ebb88f18');
  assert.equal(hash160OfAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), '751e76e8199196d454941c45d1b3a323f1433bd6');
  assert.equal(hash160OfAddress('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4'), '751e76e8199196d454941c45d1b3a323f1433bd6');
  assert.equal(hash160OfAddress('bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'), null, 'P2WSH is 32 bytes');
  assert.equal(hash160OfAddress('not-an-address!'), null);
  assert.equal(hash160OfAddress(''), null);
});

test('classification: ★ only for listed addresses, ⚑ by address or fee hash160, ◇ only explicit', () => {
  assert.equal(classifyAddress('Lwhale', undefined), TileKind.Plain);
  assert.equal(classifyAddress('Lwhale', { thisNode: ['Lwhale'] }), TileKind.ThisNode);
  assert.equal(classifyAddress('Lmid', { ownerAddresses: ['Lmid'], thisNode: ['Lmid'] }), TileKind.OwnerFee);
  assert.equal(classifyAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    { ownerHash160: '62E907B15CBF27D5425399EBF6F0FB50EBB88F18' }), TileKind.OwnerFee);
  assert.equal(classifyAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', { ownerHash160: '' }), TileKind.Plain);
  assert.equal(classifyAddress('MLhSmDonation', {}), TileKind.Plain, 'never from an address prefix');
  assert.equal(classifyAddress('MLhSmDonation', { donationAddresses: ['MLhSmDonation'] }), TileKind.Donation);
});

test('★ from /stratum_stats workers: the key up to the first dot', () => {
  assert.deepEqual(addressesFromWorkers({ 'Lwhale.rig1': {}, 'Lwhale.rig2': {}, Lmid: {} }).sort(), ['Lmid', 'Lwhale']);
  assert.deepEqual(addressesFromWorkers(null), []);
  const items = buildPplnsItems(LTC, 'parent', 'DOGE', { thisNode: addressesFromWorkers({ 'Lmid.a': {}, 'Lnotpaid.b': {} }) });
  assert.equal(items.find((i) => i.key === 'Lmid')!.data!.kind, TileKind.ThisNode);
  assert.ok(!items.some((i) => i.key === 'Lnotpaid'), 'a worker outside the PPLNS set adds no tile');
});

function tileOf(key: string, weight: number, kind = TileKind.Plain): Tile<MinerDatum> {
  return { key, x: 0, y: 0, w: 100, h: 60, weight, aggregate: false,
    items: [{ key, weight, data: { address: key, amount: weight, childAmount: 0, kind } }] };
}

test('style: hover, pin and search set flags; aggregates follow their members; kind bits set', () => {
  const bus = createSelectionBus();
  const view = () => ({ selection: bus.get() });
  const a = tileOf('Lwhale', 5);
  const others: Tile<MinerDatum> = { ...tileOf('\u0000others', 0.01), aggregate: true,
    items: [tileOf('Lx', 0.005).items[0]!, tileOf('Ly', 0.005).items[0]!] };
  assert.equal(pplnsStyle(a, view()).flags & 0xff, 0);
  bus.hover('Lwhale');
  assert.ok(pplnsStyle(a, view()).flags & FLAG_SELECTED);
  bus.hover('Ly', 'grid');
  assert.ok(pplnsStyle(others, view()).flags & FLAG_SELECTED, 'hover on a member lights the aggregate');
  bus.pin('Lwhale');
  assert.ok(pplnsStyle(a, view()).flags & FLAG_PINNED);
  assert.ok(pplnsStyle(others, view()).flags & FLAG_DIM, 'unpinned tiles dim');
  bus.pin(null);
  bus.search('lx');
  assert.ok(pplnsStyle(others, view()).flags & FLAG_MATCH);
  assert.ok(pplnsStyle(a, view()).flags & FLAG_DIM);
  assert.equal(kindOf(pplnsStyle(others, view()).flags), TileKind.Others);
  assert.equal(kindOf(pplnsStyle(tileOf('Lo', 1, TileKind.OwnerFee), view()).flags), TileKind.OwnerFee);
});

test('labels: percent of total with glyph, short address, "N others"; none on tiny tiles', () => {
  const placed = (t: Tile<MinerDatum>, w: number, h: number): PlacedTile<MinerDatum> =>
    ({ ...t, w, h, color: 0, flags: 0, exiting: false });
  const labels = pplnsLabels([
    placed(tileOf('LwhaleAddress' + 'Q'.repeat(50), 75, TileKind.ThisNode), 300, 120),
    placed({ ...tileOf('\u0000others', 5), aggregate: true, items: [tileOf('a', 2).items[0]!, tileOf('b', 3).items[0]!] }, 120, 80),
    placed(tileOf('Ltiny', 20), 20, 10),
  ], { total: 100, symbol: 'LTC' });
  const texts = labels.map((l) => l.text);
  assert.ok(texts.includes('★ 75.0% LTC'), texts.join(' | '));
  assert.ok(texts.some((t) => t.startsWith('Lwhal') && t.includes('…')));
  assert.ok(texts.includes('2 others'));
  assert.ok(!texts.some((t) => t.includes('20.')), 'tiny tile unlabeled');
  assert.ok(labels.every((l) => l.clip !== undefined), 'clipped to the tile');
  assert.equal(shortAddress('ABCDEFGHIJ', 7), 'ABC…HIJ');
});

test('tooltip: weight %, payout and % of miner payouts, merged child, facts, weight≠count flag; escaped', () => {
  const t: Tile<MinerDatum> = { ...tileOf('Lmid<script>', 25), items: [{ key: 'Lmid<script>', weight: 25,
    data: { address: 'Lmid<script>', amount: 0.25, childAmount: 410, childAddress: 'Dmid', childSource: 'explicit', kind: TileKind.ThisNode } }] };
  const lines = tooltipLines(t, {
    total: 100, mode: 'parent', symbol: 'LTC', mergedSymbol: 'DOGE', parentTotal: 6.25,
    facts: () => ({ shares: 12, countFraction: 0.6, lastShareAgeS: 125, hashrate: '1.2 GH/s', version: 'V36' }),
  }).map((l) => l.text);
  assert.ok(lines.includes('25.00% of PPLNS weight'));
  assert.ok(lines.includes('next block: 0.25000000 LTC (4.00% of miner payouts)'));
  assert.ok(lines.includes('410.0000 DOGE → Dmid · explicit'));
  assert.ok(lines.includes('★ mines on this node'));
  assert.ok(lines.includes('12 shares in window (60.00% of count)'));
  assert.ok(lines.includes('last share 2 min ago'));
  assert.ok(lines.some((l) => l.startsWith('weight ≠ share count')), 'a 25% vs 60% gap is flagged');
  const html = tooltipHtml(tooltipLines(t, { total: 100, mode: 'parent', symbol: 'LTC' }));
  assert.ok(html.includes('Lmid&lt;script&gt;') && !html.includes('<script>'), 'escaped');
  assert.equal(formatAge(30), '30 s ago');
  assert.equal(formatAge(7200), '2.0 h ago');
});
