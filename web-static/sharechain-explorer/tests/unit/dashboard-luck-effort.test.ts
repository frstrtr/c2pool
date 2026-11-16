// The inline dashboard's block pace (dashboard.html, the c2pLuck block): the
// effort of each /recent_blocks and /recent_merged_blocks row, its fast /
// slow tag and the duplets. effort = time taken / expected time of the round
// that ends at the block; under 1 the round was faster than expected. The
// node serves it per row; an older node serves only time_to_find and
// expected_time, and the effort is then their ratio, or unknown when either
// is missing. Orphaned and stale rows are never a round. Runs the functions
// extracted from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface Row {
  hash?: string; pow_hash?: string; ts: number; number?: number; height?: number;
  chain?: string; symbol?: string; status?: string; verified?: boolean;
  luck?: number | null; luck_method?: string | null;
  time_to_find?: number | null; expected_time?: number | null;
  effort?: number | null; effort_method?: string | null; main_chain?: boolean;
  prev_block_hash?: string | null; history_coverage?: number | null;
  network_difficulty?: number; pool_hashrate_at_find?: number;
}
interface Duplet { with: string; withHeight: number; gap: number; prevEffort: number | null; kind: 'plain' | 'dry' | 'triple' }
interface Pace {
  hash: string; chain: string; ts: number; height: number; offChain: boolean;
  effort: number | null; offEffort: number | null; luck: number | null; first: boolean; source: string | null; method: string | null;
  coverage: number | null; gap: number | null; expected: number | null; gapFixed: boolean;
  tier: string; tag: string; prev: string | null; duplet: Duplet | null; dupletOpen: string | null;
}
interface Round { ts: number; effort: number; first: boolean; hash: string; height: number; gap: number | null }
interface PaceSet {
  byHash: Record<string, Pace>; chains: Record<string, Round[]>; chain: string | null;
  rounds: Round[]; noEffort: number[]; lastMain: Row | null;
}
interface Luck {
  c2pPaceTier(e: unknown): string;
  c2pPaceTag(tier: string): string;
  c2pEffortBand(e: unknown): string;
  c2pEffortClass(p: Pace | null): string;
  c2pDupletEdgeClass(p: Pace | null): string | null;
  c2pBlockPace(rows: Row[] | null, sym?: string): PaceSet;
  c2pRoundTimes(b: Row, p: Pace | null): { actual: number; expected: number };
  c2pPaceTip(p: Pace): string;
  c2pDupletTip(p: Pace): string;
  c2pEffortTip(p: Pace): string;
  c2pEffortCellTip(b: Row, p: Pace | null): string;
  c2pFmtX(e: number): string;
  c2pFmtPct(v: number): string;
}

function load(): Luck {
  const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
  const begin = html.indexOf('// BEGIN c2pLuck');
  const end = html.indexOf('// END c2pLuck');
  assert.ok(begin >= 0 && end > begin, 'the c2pLuck block is in dashboard.html');
  const src = html.slice(begin, end);
  const names = [...src.matchAll(/^\s*function (c2p\w+)\(/gm)].map(m => m[1]);
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(src + '\nreturn {' + names.join(',') + '};')() as Luck;
}
function fixture<T>(path: string): T {
  return JSON.parse(readFileSync(new URL(`./fixtures/${path}`, import.meta.url), 'utf8')) as T;
}

const L = load();
const H = 3600;

// A ledger from (height, hours since t0, fields): expected time 10 h, so a
// row found d hours after the previous one has effort d / 10 on an older node.
const T0 = 1794000000, EXPECTED = 10 * H;
function row(height: number, hours: number, more: Partial<Row> = {}): Row {
  return { hash: 'h' + height, number: height, ts: T0 + hours * H, chain: 'DASH', status: 'confirmed',
           expected_time: EXPECTED, ...more };
}
// An older node's rows: time_to_find from the previous ROW (orphans too).
function olderNode(rows: Row[]): Row[] {
  const sorted = rows.slice().sort((a, b) => a.ts - b.ts);
  sorted.forEach((r, i) => {
    if (r.luck_method === 'relayed') return;
    if (i === 0) { r.luck_method = 'first_block'; r.time_to_find = null; r.luck = null; return; }
    r.time_to_find = r.ts - sorted[i - 1]!.ts;
    r.luck = 100 * EXPECTED / r.time_to_find;
  });
  return rows;
}
const paceOf = (set: PaceSet, height: number) => set.byHash['h' + height]!;

test('fast and slow tags: under 1/3 and 0.1, over 2 and 3; the bounds themselves are untagged', () => {
  const cases: [number, string, string][] = [
    [0.0001, 'fast2', '⚡⚡'], [0.0999, 'fast2', '⚡⚡'], [0.1, 'fast', '⚡'], [0.2, 'fast', '⚡'],
    [0.3333, 'fast', '⚡'], [1 / 3, '', ''], [0.3334, '', ''], [0.69, '', ''], [1, '', ''], [1.99, '', ''],
    [2, '', ''], [2.0001, 'slow', '🐢'], [3, 'slow', '🐢'], [3.0001, 'slow2', '🐢🐢'], [40, 'slow2', '🐢🐢'],
  ];
  for (const [e, tier, tag] of cases) {
    assert.equal(L.c2pPaceTier(e), tier, `tier of ${e}`);
    assert.equal(L.c2pPaceTag(L.c2pPaceTier(e)), tag, `tag of ${e}`);
  }
  for (const e of [0, -1, NaN, null, undefined, 'x']) assert.equal(L.c2pPaceTier(e), '', `no tier for ${String(e)}`);
});

test('effort colour bands sit where the luck colours did: 100 % and 75 % luck', () => {
  assert.equal(L.c2pEffortBand(0.05), 'good');
  assert.equal(L.c2pEffortBand(1), 'good');            // luck 100 %
  assert.equal(L.c2pEffortBand(1.0001), 'mid');
  assert.equal(L.c2pEffortBand(4 / 3), 'mid');         // luck 75 %
  assert.equal(L.c2pEffortBand(1.34), 'poor');
  assert.equal(L.c2pEffortBand(null), '');
  const set5 = L.c2pBlockPace(olderNode([row(1, 0), row(2, 5), row(3, 17), row(4, 37), row(5, 47)]), 'DASH');
  assert.deepEqual([2, 3, 4, 5].map(h => L.c2pEffortClass(paceOf(set5, h))),
                   ['status-confirmed', 'status-pending', 'status-orphaned', 'status-confirmed']);
  // The first block's 100 % is a convention: amber, as its "1st" always was.
  assert.equal(L.c2pEffortClass(paceOf(set5, 1)), 'status-pending');
  assert.equal(L.c2pEffortClass(null), 'effort-unknown');
});

test('effort: the row\'s own effort first, then first block = 1, then time_to_find / expected_time, else unknown', () => {
  const set = L.c2pBlockPace([
    // The node's effort wins over the times next to it.
    row(1, 0, { effort: 1, effort_method: 'first_block', luck: 100 }),
    row(2, 5, { effort: 0.42, effort_method: 'integrated', time_to_find: 5 * H, expected_time: 5 * H / 0.42,
                prev_block_hash: 'h1', history_coverage: 0.97, luck: 100 / 0.42 }),
    row(3, 9, { effort: 2.5, effort_method: 'single_sample', time_to_find: 4 * H, prev_block_hash: 'h2' }),
  ], 'DASH');
  assert.deepEqual([1, 2, 3].map(h => [paceOf(set, h).effort, paceOf(set, h).source, paceOf(set, h).method, paceOf(set, h).first]),
                   [[1, 'server', 'first_block', true], [0.42, 'server', 'integrated', false], [2.5, 'server', 'single_sample', false]]);
  assert.equal(paceOf(set, 2).coverage, 0.97);
  assert.ok(Math.abs(paceOf(set, 2).luck! - 100 / 0.42) < 1e-9, 'luck = 100 / effort');
  assert.equal(paceOf(set, 1).tag, '', 'the first block has no tag');
  assert.equal(paceOf(set, 3).tag, '🐢');
  assert.deepEqual(set.rounds.map(r => r.effort), [1, 0.42, 2.5]);
  assert.deepEqual(set.rounds.map(r => r.gap), [null, 5 * H, 4 * H], 'each round carries its length');

  // An older node: no effort field.
  const old = L.c2pBlockPace(olderNode([row(1, 0), row(2, 5), row(3, 9), row(4, 29)]), 'DASH');
  assert.deepEqual([1, 2, 3, 4].map(h => [paceOf(old, h).effort, paceOf(old, h).source]),
                   [[1, 'first_block'], [0.5, 'client'], [0.4, 'client'], [2, 'client']]);
  assert.equal(paceOf(old, 1).first, true);
  assert.equal(paceOf(old, 1).luck, 100, 'the first block counts as 100 %');
});

test('older node: no effort without both time_to_find and expected_time, and never from the luck field', () => {
  const rows: Row[] = [
    row(1, 0, { luck_method: 'first_block', luck: null }),
    row(2, 5, { time_to_find: 5 * H, expected_time: null, luck: 250 }),
    row(3, 9, { time_to_find: null, luck: 250, luck_method: 'interval_unavailable' }),
    row(4, 12, { time_to_find: null, expected_time: null, luck: null, luck_method: 'relayed' }),
    row(5, 13, { time_to_find: 0, luck: 250 }),
    row(6, 14, { time_to_find: -30, luck: 250 }),
    row(7, 19, { time_to_find: 5 * H, luck: 200 }),
  ];
  const set = L.c2pBlockPace(rows, 'DASH');
  for (const h of [2, 3, 4, 5, 6]) {
    assert.equal(paceOf(set, h).effort, null, `row ${h} has no effort`);
    assert.equal(paceOf(set, h).luck, null);
    assert.equal(paceOf(set, h).tag, '');
    assert.equal(L.c2pEffortClass(paceOf(set, h)), 'effort-unknown');
  }
  assert.equal(paceOf(set, 7).effort, 0.5);
  assert.deepEqual(set.rounds.map(r => r.height), [1, 7]);
  assert.deepEqual(set.noEffort, [2, 3, 4, 5, 6].map(h => rows[h - 1]!.ts), 'main-chain rows left out with their rounds');
  assert.match(L.c2pEffortCellTip(rows[3]!, paceOf(set, 4)), /Relayed from a peer/);
  assert.match(L.c2pEffortCellTip(rows[2]!, paceOf(set, 3)), /Effort unknown.*interval_unavailable/);
});

test('orphaned and stale rows are never a round, a tag or a predecessor', () => {
  // 2 is orphaned 1 h after block 1; 3 comes 3 h after block 1. An older
  // node times 3 from the orphan (2 h): the round is 3 h, from block 1.
  const rows = olderNode([row(1, 0), row(2, 1, { status: 'orphaned' }), row(3, 3), row(4, 3.5, { status: 'stale' }), row(5, 33)]);
  assert.equal(rows[2]!.time_to_find, 2 * H, 'served from the orphan');
  const set = L.c2pBlockPace(rows, 'DASH');
  for (const h of [2, 4]) {
    assert.equal(paceOf(set, h).offChain, true);
    assert.equal(paceOf(set, h).effort, null);
    assert.equal(paceOf(set, h).tag, '');
    assert.equal(paceOf(set, h).duplet, null);
    assert.equal(paceOf(set, h).dupletOpen, null);
    assert.match(L.c2pEffortCellTip(rows[h - 1]!, paceOf(set, h)), /ends no round/);
  }
  assert.equal(paceOf(set, 3).gapFixed, true);
  assert.equal(paceOf(set, 3).effort, 0.3, 'timed from block 1, not from the orphan');
  assert.equal(paceOf(set, 3).prev, 'h1');
  assert.equal(paceOf(set, 5).effort, 3, 'the stale row before it is skipped the same way');
  assert.equal(paceOf(set, 5).prev, 'h3');
  assert.deepEqual(set.rounds.map(r => r.height), [1, 3, 5]);
  // The efforts cover the timeline once: 3 h + 30 h over 10 h expected.
  assert.equal(set.rounds.filter(r => !r.first).reduce((a, r) => a + r.effort, 0), 3.3);
  assert.equal(set.lastMain!.number, 5);

  // A time_to_find that is not the gap to the orphan is left as served.
  const kept = L.c2pBlockPace([row(1, 0, { luck_method: 'first_block' }), row(2, 1, { status: 'orphaned' }),
                               row(3, 3, { time_to_find: 3 * H })], 'DASH');
  assert.equal(paceOf(kept, 3).gapFixed, false);
  assert.equal(paceOf(kept, 3).effort, 0.3);
});

test('the node says what is on the coin chain: main_chain, not the status', () => {
  // A find that never confirmed stays "pending" for ever: the node marks it
  // main_chain false, and serves the effort it would have had for display.
  const rows: Row[] = [
    row(1, 0, { effort: 1, effort_method: 'first_block', main_chain: true }),
    row(2, 10, { effort: 1, effort_method: 'integrated', prev_block_hash: 'h1', main_chain: true }),
    row(3, 10.5, { status: 'pending', effort: 0.05, effort_method: 'integrated', prev_block_hash: 'h2', main_chain: false }),
    row(4, 12, { status: 'pending', effort: 0.2, effort_method: 'integrated', prev_block_hash: 'h2', main_chain: true }),
    // An orphan the node still counts on the chain is not for this page to overrule.
    row(5, 40, { status: 'orphaned', effort: 2.8, effort_method: 'integrated', prev_block_hash: 'h4', main_chain: true }),
  ];
  const set = L.c2pBlockPace(rows, 'DASH');
  const off = paceOf(set, 3);
  assert.deepEqual([off.offChain, off.effort, off.offEffort, off.tag, off.duplet], [true, null, 0.05, '', null]);
  assert.deepEqual(set.rounds.map(r => r.height), [1, 2, 4, 5]);
  assert.equal(paceOf(set, 4).duplet!.with, 'h2', 'the pair is with the main-chain block, over the lost find');
  assert.equal(paceOf(set, 5).offChain, false);
  assert.equal(paceOf(set, 5).tag, '🐢');
  assert.equal(L.c2pEffortClass(off), 'effort-unknown', 'shown muted');
  assert.equal(L.c2pEffortCellTip(rows[2]!, off),
    'Not on the coin chain (orphaned, stale or never confirmed): it ends no round of the pool, so it has no tag and is not counted in pool luck. ' +
    'Timed from the last main-chain block before it, it came at 5.0 % of the expected time.');
  // An older node has no main_chain: the status decides, and a pending row is on the chain.
  const old = L.c2pBlockPace(olderNode([row(1, 0), row(2, 10, { status: 'pending' }), row(3, 11, { status: 'orphaned' })]), 'DASH');
  assert.deepEqual([1, 2, 3].map(h => paceOf(old, h).offChain), [false, false, true]);
  assert.equal(paceOf(old, 3).offEffort, null, 'no effort served: a dash');
});

test('a block the node could not rate has no effort: hashrate_unavailable, netdiff_unavailable', () => {
  const rows: Row[] = [
    row(1, 0, { effort: 1, effort_method: 'first_block', main_chain: true }),
    row(2, 10, { effort: null, luck: null, expected_time: null, time_to_find: 10 * H, luck_method: 'hashrate_unavailable',
                 prev_block_hash: 'h1', main_chain: true }),
    row(3, 20, { effort: null, luck: null, expected_time: null, time_to_find: 10 * H, luck_method: 'netdiff_unavailable',
                 prev_block_hash: 'h2', main_chain: true }),
    row(4, 21, { effort: 0.1, effort_method: 'integrated', time_to_find: 1 * H, luck_method: 'relayed', prev_block_hash: 'h3', main_chain: true }),
  ];
  const set = L.c2pBlockPace(rows, 'DASH');
  assert.deepEqual([2, 3].map(h => [paceOf(set, h).effort, paceOf(set, h).tag]), [[null, ''], [null, '']]);
  assert.deepEqual(set.noEffort, [rows[1]!.ts, rows[2]!.ts]);
  assert.match(L.c2pEffortCellTip(rows[1]!, paceOf(set, 2)), /no pool hashrate is known over this block's round/);
  assert.match(L.c2pEffortCellTip(rows[2]!, paceOf(set, 3)), /network difficulty at find time is unknown/);
  assert.deepEqual(L.c2pRoundTimes(rows[1]!, paceOf(set, 2)), { actual: 10 * H, expected: 0 }, 'its round time is still shown');
  // "relayed" is provenance on a row that has an effort: a row like any other.
  assert.deepEqual([paceOf(set, 4).effort, paceOf(set, 4).tag, paceOf(set, 4).duplet!.with], [0.1, '⚡', 'h3']);
});

test('duplet: a fast block and the main-chain block before it', () => {
  // efforts: 1st, 1.0, 0.2 (plain), 0.05 (two fast in a row), 2.5, 0.3 (after a dry spell)
  const set = L.c2pBlockPace(olderNode([row(1, 0), row(2, 10), row(3, 12), row(4, 12.5), row(5, 37.5), row(6, 40.5)]), 'DASH');
  assert.deepEqual([1, 2, 3, 4, 5, 6].map(h => paceOf(set, h).tag), ['', '', '⚡', '⚡⚡', '🐢', '⚡']);
  assert.deepEqual([1, 2, 5].map(h => paceOf(set, h).duplet), [null, null, null]);
  assert.deepEqual(paceOf(set, 3).duplet, { with: 'h2', withHeight: 2, gap: 2 * H, prevEffort: 1, kind: 'plain' });
  assert.deepEqual(paceOf(set, 4).duplet, { with: 'h3', withHeight: 3, gap: 0.5 * H, prevEffort: 0.2, kind: 'triple' });
  assert.deepEqual(paceOf(set, 6).duplet, { with: 'h5', withHeight: 5, gap: 3 * H, prevEffort: 2.5, kind: 'dry' });
  assert.deepEqual([1, 2, 3, 4, 5, 6].map(h => paceOf(set, h).dupletOpen), [null, 'h3', 'h4', null, 'h6', null]);
  // The bracket down the first cell: a tick on the later and the earlier row.
  assert.deepEqual([1, 2, 3, 4, 5, 6].map(h => L.c2pDupletEdgeClass(paceOf(set, h))),
                   [null, 'duplet-edge duplet-bottom', 'duplet-edge', 'duplet-edge duplet-top',
                    'duplet-edge duplet-bottom', 'duplet-edge duplet-top']);
});

test('duplets skip orphaned, stale, relayed and first rows', () => {
  // An orphan 6 min after block 2 would be a near-zero gap: it pairs with
  // nothing, and block 3 pairs with block 2 over it.
  const rows = olderNode([row(1, 0), row(2, 10), row(20, 10.1, { status: 'orphaned' }), row(3, 12),
                          row(30, 12.2, { status: 'stale' }), row(4, 14)]);
  const set = L.c2pBlockPace(rows, 'DASH');
  assert.equal(paceOf(set, 20).duplet, null);
  assert.equal(paceOf(set, 30).duplet, null);
  assert.deepEqual(paceOf(set, 3).duplet, { with: 'h2', withHeight: 2, gap: 2 * H, prevEffort: 1, kind: 'plain' });
  assert.equal(paceOf(set, 4).duplet!.with, 'h3', 'over the stale row');
  assert.equal(paceOf(set, 4).effort, 0.2, 'and timed from block 3');
  assert.deepEqual([20, 30].map(h => paceOf(set, h).dupletOpen), [null, null]);

  // A relayed row has no timing on an older node: it closes no duplet. The
  // block after it is timed from it, and may close one with it.
  const relayed = L.c2pBlockPace(olderNode([row(1, 0), row(2, 10), row(3, 10.5, { luck_method: 'relayed', expected_time: null }),
                                            row(4, 11)]), 'DASH');
  assert.equal(paceOf(relayed, 3).effort, null);
  assert.equal(paceOf(relayed, 3).duplet, null, 'a relayed row closes no duplet');
  assert.deepEqual(paceOf(relayed, 4).duplet, { with: 'h3', withHeight: 3, gap: 0.5 * H, prevEffort: null, kind: 'plain' });

  // The first block never closes a duplet (it has no round); the block
  // after it can, with no "wait" to quote.
  const first = L.c2pBlockPace(olderNode([row(1, 0), row(2, 1)]), 'DASH');
  assert.equal(paceOf(first, 1).duplet, null);
  assert.deepEqual(paceOf(first, 2).duplet, { with: 'h1', withHeight: 1, gap: 1 * H, prevEffort: null, kind: 'plain' });
  const served = L.c2pBlockPace([row(1, 0, { effort: 0.05, effort_method: 'first_block' })], 'DASH');
  assert.equal(paceOf(served, 1).tag, '', 'a first block is untagged whatever effort it carries');
  assert.equal(paceOf(served, 1).duplet, null);
});

test('duplets never pair rows across chains, the same height, or a block the node did not name', () => {
  // An LTC block and a merged DOGE block from the same share, 5 s apart.
  const mixed = L.c2pBlockPace([
    row(1, 0, { chain: 'LTC', effort: 1, effort_method: 'first_block' }),
    row(2, 20, { chain: 'LTC', effort: 2 }),
    { pow_hash: 'd1', symbol: 'DOGE', height: 500, ts: T0 + 20 * H + 5, verified: true, effort: 0.01, effort_method: 'integrated' },
    { pow_hash: 'd2', symbol: 'DOGE', height: 501, ts: T0 + 20 * H + 65, verified: true, effort: 0.2, effort_method: 'integrated' },
    { pow_hash: 'd3', symbol: 'DOGE', height: 502, ts: T0 + 20 * H + 95, verified: false, effort: 0.1, effort_method: 'integrated' },
  ], 'LTC');
  assert.equal(mixed.chain, 'LTC');
  assert.deepEqual(mixed.rounds.map(r => r.height), [1, 2], 'the DOGE rows are not LTC rounds');
  assert.equal(mixed.byHash['d1']!.duplet, null, 'no pair with the LTC block 5 s before it');
  assert.equal(mixed.byHash['d1']!.tag, '⚡⚡');
  assert.equal(mixed.byHash['d2']!.duplet!.with, 'd1', 'DOGE pairs with DOGE');
  assert.equal(mixed.byHash['d3']!.offChain, true, 'a merged row with verified false is orphaned');
  assert.deepEqual(mixed.chains['DOGE']!.map(r => r.height), [500, 501]);
  // Without the symbol: the chain with the most rows.
  assert.equal(L.c2pBlockPace([row(1, 0), row(2, 5), { pow_hash: 'd1', symbol: 'DOGE', height: 9, ts: T0 }]).chain, 'DASH');

  // The same block listed twice is one row; two rows at one height are not a pair.
  const twice = olderNode([row(1, 0), row(2, 10), row(3, 11)]);
  const dup = L.c2pBlockPace(twice.concat([{ ...twice[2]! }]), 'DASH');
  assert.equal(dup.rounds.length, 3);
  const sameHeight = L.c2pBlockPace([row(1, 0, { luck_method: 'first_block' }), row(2, 10, { time_to_find: 10 * H }),
                                     { ...row(2, 10.1, { time_to_find: 0.1 * H }), hash: 'h2b' }], 'DASH');
  assert.equal(sameHeight.byHash['h2b']!.tag, '⚡⚡');
  assert.equal(sameHeight.byHash['h2b']!.duplet, null);

  // The node names the round's start: that block is the pair, by hash.
  const named = L.c2pBlockPace([
    row(1, 0, { effort: 1, effort_method: 'first_block' }),
    row(2, 10, { effort: 1, prev_block_hash: 'h1' }),
    row(3, 11, { effort: 0.1, prev_block_hash: 'h2' }),
    row(4, 12, { effort: 0.1, prev_block_hash: 'not-in-the-ledger' }),
  ], 'DASH');
  assert.equal(paceOf(named, 3).duplet!.with, 'h2');
  assert.equal(paceOf(named, 4).duplet, null);
  assert.equal(paceOf(named, 4).tag, '⚡', 'still a fast block');
});

test('round times: the round as timed, and the expected time from what the row has', () => {
  const rows = olderNode([row(1, 0), row(2, 1, { status: 'orphaned' }), row(3, 3)]);
  const set = L.c2pBlockPace(rows, 'DASH');
  assert.deepEqual(L.c2pRoundTimes(rows[2]!, paceOf(set, 3)), { actual: 3 * H, expected: EXPECTED }, 'the corrected round');
  assert.deepEqual(L.c2pRoundTimes(rows[0]!, paceOf(set, 1)), { actual: 0, expected: EXPECTED });
  const served: Row = row(4, 9, { effort: 0.5, time_to_find: 6 * H, expected_time: null });
  assert.deepEqual(L.c2pRoundTimes(served, L.c2pBlockPace([served], 'DASH').byHash['h4']!), { actual: 6 * H, expected: 12 * H });
  const diff: Row = row(5, 9, { expected_time: null, network_difficulty: 1000, pool_hashrate_at_find: 4294967296 });
  assert.deepEqual(L.c2pRoundTimes(diff, null), { actual: 0, expected: 1000 });
});

test('outside LTC node (older build): its one block is the first block, 100 %', () => {
  // http://92.53.224.27:9328/recent_blocks, 2026-11-16: one row.
  const rows: Row[] = [{ hash: '84024db9063696eabf560504fa15737d6ab15a560441e5bab7fd51bd03571223', number: 3211872, height: 3211872,
                         ts: 1794498365, chain: 'LTC', status: 'confirmed', luck: null, luck_method: 'first_block',
                         time_to_find: null, expected_time: 1921406.0645293593 }];
  const set = L.c2pBlockPace(rows, 'LTC');
  const p = set.byHash[rows[0]!.hash!]!;
  assert.deepEqual([p.effort, p.luck, p.first, p.source, p.tag, p.duplet], [1, 100, true, 'first_block', '', null]);
  assert.deepEqual(set.rounds, [{ ts: 1794498365, effort: 1, first: true, hash: rows[0]!.hash, height: 3211872, gap: null }]);
  assert.match(L.c2pEffortTip(p), /First block known to this node.*counts as effort 100 %/s);
  // Its merged DOGE row has no difficulty at find: no effort, no tag.
  const merged = L.c2pBlockPace([{ pow_hash: 'da2714c8', symbol: 'DOGE', height: 6454700, ts: 1794498370, verified: true }]);
  assert.equal(merged.byHash['da2714c8']!.effort, null);
  assert.equal(merged.byHash['da2714c8']!.tag, '');
});

test('our LTC node (older build): predecessors by time, not by a bogus height', () => {
  // sg-ltc /recent_blocks, 2026-11-16: the height-27,588,573 row is the
  // OLDEST by time and carries first_block.
  const rows: Row[] = [
    { hash: 'f11e', number: 27588573, ts: 1792690954, chain: 'LTC', status: 'pending', luck: null, luck_method: 'first_block',
      time_to_find: null, expected_time: 2028394.7644759316 },
    { hash: '8402', number: 3211872, ts: 1794498365, chain: 'LTC', status: 'confirmed', luck: 262.7468280874259,
      luck_method: 'simple_avg', time_to_find: 1061799, expected_time: 2789843.1931640077 },
    { hash: 'e402', number: 3204796, ts: 1793436566, chain: 'LTC', status: 'confirmed', luck: null,
      luck_method: 'interval_unavailable', time_to_find: null, expected_time: 2002604.8405106394 },
  ];
  const set = L.c2pBlockPace(rows, 'LTC');
  assert.deepEqual(set.rounds.map(r => [r.height, r.first]), [[27588573, true], [3211872, false]]);
  assert.ok(Math.abs(set.byHash['8402']!.effort! - 1061799 / 2789843.1931640077) < 1e-12);
  assert.equal(set.byHash['8402']!.prev, 'e402', 'the block before it by time');
  assert.equal(set.byHash['e402']!.effort, null);
  assert.deepEqual(set.noEffort, [1793436566]);
  assert.equal(set.lastMain!.number, 3211872);
});

interface DashFixture { columns: string[]; rows: (string | number | null)[][] }
function dashRows(): Row[] {
  const f = fixture<DashFixture>('dash-voidbind-20261116/recent_blocks_luck.json');
  return f.rows.map(r => {
    const o: Record<string, unknown> = { chain: 'DASH' };
    f.columns.forEach((c, i) => { o[c] = r[i]; });
    return o as unknown as Row;
  });
}

test('live DASH ledger (older build): tags at the Poisson rates, the orphan-timed round retimed', () => {
  const rows = dashRows();
  const set = L.c2pBlockPace(rows, 'DASH');
  assert.equal(rows.length, 230);
  assert.equal(set.rounds.length, 229, 'the orphaned row is not a round');
  const paces = set.rounds.filter(r => !r.first).map(r => set.byHash[r.hash]!);
  const count = (f: (p: Pace) => boolean) => paces.filter(f).length;
  // 228 rounds: 28.3 % under 1/3, 9.5 % under 0.1, 13.5 % over 2, 5.0 % over 3 expected.
  assert.deepEqual([count(p => p.tier === 'fast' || p.tier === 'fast2'), count(p => p.tier === 'fast2'),
                    count(p => p.tier === 'slow' || p.tier === 'slow2'), count(p => p.tier === 'slow2')], [68, 22, 30, 12]);
  // Every fast block closes a duplet here: each has a main-chain predecessor.
  assert.equal(count(p => p.duplet !== null), 68);
  assert.equal(count(p => p.duplet !== null && p.duplet.kind === 'dry'), 9, 'slow then fast: 3.8 % of pairs expected, 8.7');
  // Block 2561418 was timed from orphan 2561316 (15,515 s, effort 1.29); its
  // round from main-chain block 2561265 is 23,835 s.
  const fixed = paces.filter(p => p.gapFixed);
  assert.deepEqual(fixed.map(p => [p.height, p.gap]), [[2561418, 23835]]);
  assert.ok(Math.abs(fixed[0]!.effort! - 1.98695) < 1e-5);
  const orphan = Object.values(set.byHash).filter(p => p.offChain);
  assert.deepEqual(orphan.map(p => [p.height, p.effort, p.tag]), [[2561316, null, '']]);
});

test('tooltips give the Poisson odds and claim no pattern', () => {
  const set = L.c2pBlockPace(olderNode([row(1, 0), row(2, 24), row(3, 26.1), row(4, 26.6), row(5, 57)]), 'DASH');
  const fast = L.c2pPaceTip(paceOf(set, 3));
  assert.match(fast, /^⚡ Fast block: found in 0\.2× the expected time\. About 28 % of blocks come in under ⅓ of it by pure chance \(Poisson\)\. It does not predict the next block\.$/);
  assert.match(L.c2pPaceTip(paceOf(set, 4)), /28 % of blocks come in under ⅓ of it \(9\.5 % under 0\.1×\) by pure chance/);
  assert.equal(L.c2pPaceTip(paceOf(set, 5)),
    '🐢 Slow block: took 3.0× the expected time. About 13.5 % of blocks take over 2× (5.0 % over 3×) by chance. ' +
    'Mining has no memory, so the pool was never "due" a block.');
  assert.match(L.c2pPaceTip(paceOf(set, 2)), /^🐢 Slow block: took 2\.4× the expected time\./);
  assert.equal(L.c2pPaceTip(paceOf(L.c2pBlockPace(olderNode([row(1, 0), row(2, 10)]), 'DASH'), 2)), '',
               'an untagged block has no pace line');

  const dry = L.c2pDupletTip(paceOf(set, 3));
  assert.match(dry, /^Duplet: 2 blocks 2h 6m apart \(0\.2× the expected time\)\./);
  assert.match(dry, /28 % of consecutive blocks are within ⅓ of the expected time, and 49 % of blocks have a neighbour that close/);
  assert.match(dry, /A dry spell does not speed up the next block: after this 2\.4× wait the chance of a quick follow-up was still 28 %/);
  assert.match(dry, /Our study of 50,707 LTC\+DASH p2pool blocks \(2012-2026\) found no excess\./);
  assert.match(dry, /Long wait then a quick pair: 3\.8 % of block pairs, about 1 in 26\./);
  assert.match(L.c2pDupletTip(paceOf(set, 4)), /Two fast blocks in a row: 8\.0 % of consecutive pairs by chance\./);
  assert.equal(L.c2pDupletTip(paceOf(set, 5)), '');
  // The odds quoted are the Exp(1) ones.
  assert.equal((100 * (1 - Math.exp(-1 / 3))).toFixed(0), '28');
  assert.equal((100 * (1 - Math.exp(-2 / 3))).toFixed(0), '49');
  assert.equal((100 * Math.exp(-2)).toFixed(1), '13.5');
  assert.equal((100 * Math.exp(-2) * (1 - Math.exp(-1 / 3))).toFixed(1), '3.8');
  // Nothing in any pace text says a block is due, a streak is on, or a pattern holds.
  for (const h of [3, 4, 5]) {
    const text = L.c2pPaceTip(paceOf(set, h)) + L.c2pDupletTip(paceOf(set, h)) + L.c2pEffortTip(paceOf(set, h));
    assert.doesNotMatch(text, /streak|overdue|catch(es|ing)? up|hot|pattern|more likely/i);
  }

  const tip = L.c2pEffortTip(paceOf(set, 3));
  assert.match(tip, /^Effort 21 % of expected: found in 2h 6m, expected 10h 0m\.\nLuck = 1 \/ effort = 476 %\./);
  assert.match(tip, /Computed in the browser from this node's time_to_find \/ expected_time \(older node\)/);
  const served = L.c2pBlockPace([row(1, 0, { effort: 1, effort_method: 'first_block' }),
                                 row(2, 5, { effort: 0.5, effort_method: 'integrated', time_to_find: 5 * H, history_coverage: 0.5 })], 'DASH');
  assert.match(L.c2pEffortTip(paceOf(served, 2)), /Effort integrated over the round from the pool hashrate and difficulty history \(history covers 50 % of the round; the rest is taken at its mean\)\.$/);
  const whole = L.c2pBlockPace([row(1, 0, { effort: 1, effort_method: 'first_block' }),
                                row(2, 5, { effort: 0.5, effort_method: 'integrated', time_to_find: 5 * H, history_coverage: 1 })], 'DASH');
  assert.match(L.c2pEffortTip(paceOf(whole, 2)), /difficulty history\.$/);
});

test('formats: effort as a multiple and as a percentage', () => {
  assert.deepEqual([0, 0.004, 0.05, 0.21, 0.6, 2.44, 9.96, 12.3].map(e => L.c2pFmtX(e)),
                   ['0.00×', '<0.01×', '0.05×', '0.2×', '0.6×', '2.4×', '10×', '12×']);
  assert.deepEqual([0.37, 4, 42.4, 240, 172273].map(v => L.c2pFmtPct(v)), ['0.37%', '4.0%', '42%', '240%', '172273%']);
});
