// The inline dashboard's pooled luck (dashboard.html, the c2pLuck block):
// period luck = blocks found / blocks expected = k / sum(effort), the open
// round's effort so far included, with the exact Poisson (Garwood) 95 %
// interval [chi2(.025; 2k) / 2, chi2(.975; 2k + 2) / 2] / expected. The node
// serves it as `periods` and `current_round` in /luck_stats; for an older
// node it is computed here from each row's time_to_find / expected_time.
// Nothing is ever a mean of per-block luck: E[1 / effort] is infinite, so
// that mean reads far above 100 % for a fair pool. Also the Round badge
// states. Runs the functions extracted from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface Row {
  hash: string; ts: number; number: number; chain: string; status: string;
  luck: number | null; luck_method: string | null; time_to_find: number | null; expected_time: number | null;
  effort?: number; effort_method?: string;
}
interface Round { ts: number; effort: number; first: boolean; hash: string; height: number; gap?: number | null }
interface PaceSet { byHash: Record<string, { effort: number | null; tag: string }>; rounds: Round[]; noEffort: number[]; lastMain: Row | null }
interface Open {
  effort: number; elapsed: number | null; expected_time: number | null; source: string; since: string | null;
  pace_time?: number | null; method?: string | null; coverage?: number | null;
}
interface Period {
  k: number; blocks_expected: number; luck: number; ci95_low: number | null; ci95_high: number | null;
  span_s: number | null; source: string; skipped?: number;
}
type Periods = Record<'1d' | '7d' | '30d' | '90d' | 'all', Period | null>;
interface Spell { state: string; text: string; background: string; hint: boolean }
interface Luck {
  c2pBlockPace(rows: unknown[], sym?: string): PaceSet;
  c2pLuckOf(k: number, expected: number): Period | null;
  c2pFairBand(k: number): { low: number; high: number } | null;
  c2pOpenRound(luckStats: unknown, lastMainTs: number | null, nowS: number, fallbackExpected: number): Open | null;
  c2pPeriodLuck(rounds: Round[], nowS: number, spanS: number | null, open: Open | null, noEffort?: number[]): Period | null;
  c2pLuckPeriods(luckStats: unknown, rounds: Round[], nowS: number, open: Open | null, noEffort?: number[]): Periods;
  c2pPeriodView(per: Period | null): { value: string; detail: string; tone: string };
  c2pPeriodTip(label: string, per: Period | null): string;
  c2pDrySpell(e: number | null): Spell | null;
  c2pRoundTip(open: Open | null): string;
  c2pLuckTrendPoints(rounds: Round[], minTime: number, live: unknown, N?: number): { x: number; y: number }[];
}

const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
function load(): Luck {
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
const D = 86400;
const near = (a: number, b: number, rel = 1e-9) => Math.abs(a - b) <= rel * Math.max(1, Math.abs(b));

// Quantiles of Gamma(k, 1), i.e. chi2(p; 2k) / 2: [k, q(.025; k), q(.975; k),
// q(.975; k + 1)]. A hand table computed apart from the dashboard (see its
// note); dashboard-luck-ci.test.ts checks the dashboard's quantiles on it.
const QUANTILES = fixture<{ rows: [number, number, number, number][] }>('gamma-quantiles.json').rows;
const table = (k: number) => QUANTILES.find(r => r[0] === k)!;

test('luck and its exact Poisson interval: k / expected, [chi2(.025; 2k) / 2, chi2(.975; 2k + 2) / 2] / expected', () => {
  const p = L.c2pLuckOf(10, 8)!;
  assert.equal(p.k, 10);
  assert.equal(p.blocks_expected, 8);
  assert.equal(p.luck, 125);
  assert.ok(near(p.ci95_low!, 100 * table(10)[1] / 8) && near(p.ci95_high!, 100 * table(10)[3] / 8));
  const none = L.c2pLuckOf(0, 0.5)!;
  assert.deepEqual([none.luck, none.ci95_low], [0, 0]);
  assert.ok(near(none.ci95_high!, 100 * 3.688879454114 / 0.5), 'no block: the true luck is under 738 %');
  assert.equal(L.c2pLuckOf(3, 0), null, 'nothing expected: no luck');
});

test('where a fair pool lands with k blocks: k / Gamma(k, 1)', () => {
  // The spec's table: 5 blocks 49-310 %, 10 59-209 %, 30 72-148 %, 78 81-127 %.
  const want: [number, number, number][] = [[5, 49, 308], [10, 59, 209], [30, 72, 148], [78, 81, 127]];
  for (const [k, lo, hi] of want) {
    const band = L.c2pFairBand(k)!;
    assert.deepEqual([Math.round(band.low), Math.round(band.high)], [lo, hi], `${k} blocks`);
    assert.ok(near(band.low, 100 * k / table(k)[2]) && near(band.high, 100 * k / table(k)[1]));
  }
  const one = L.c2pFairBand(1)!;
  assert.deepEqual([Math.round(one.low), Math.round(one.high)], [27, 3950], 'one block says almost nothing');
  assert.equal(L.c2pFairBand(0), null);
});

test('the open round: the node\'s current_round, else 100 / current_luck_trend, else the chart\'s own inputs', () => {
  const now = 1794800000, last = now - 7200;
  const served = { current_luck_trend: 1, current_round: { elapsed: 7100, expected_time: 3550, effort: 2, since_block_hash: 'aa' } };
  assert.deepEqual(L.c2pOpenRound(served, last, now, 999),
                   { effort: 2, elapsed: 7100, expected_time: 3550, pace_time: 3550, source: 'server', since: 'aa', method: null, coverage: null });
  // The node's effort is integrated over the round and its expected_time is
  // the time to a block at the rate NOW: after a rate change they differ.
  // pace_time is the round's own elapsed / effort.
  const moved = L.c2pOpenRound({ current_round: { elapsed: 7200, expected_time: 5400, effort: 2.4, effort_method: 'integrated',
                                                  history_coverage: 0.8, since_block_hash: 'bb' } }, last, now, 0)!;
  assert.deepEqual([moved.effort, moved.expected_time, moved.pace_time, moved.method, moved.coverage], [2.4, 5400, 3000, 'integrated', 0.8]);
  // No expected_time served: elapsed / effort.
  assert.equal(L.c2pOpenRound({ current_round: { elapsed: 7200, effort: 2.4 } }, last, now, 0)!.expected_time, 3000);
  assert.equal(L.c2pOpenRound({ current_round: { elapsed: 0, effort: 0 } }, last, now, 0)!.effort, 0, 'a round just begun');
  // The node says there is no round yet (no main-chain block): none, whatever else is there.
  assert.equal(L.c2pOpenRound({ current_round: null, current_luck_trend: 40 }, last, now, 3600), null);
  // An older node: current_luck_trend = expected / elapsed * 100.
  assert.deepEqual(L.c2pOpenRound({ current_luck_trend: 40 }, last, now, 999),
                   { effort: 2.5, elapsed: 7200, expected_time: 2880, pace_time: 2880, source: 'server_trend', since: null, method: null, coverage: null });
  // Neither: the round since the last block against the expected time given.
  assert.deepEqual(L.c2pOpenRound({ luck_available: true }, last, now, 3600),
                   { effort: 2, elapsed: 7200, expected_time: 3600, pace_time: 3600, source: 'client', since: null, method: null, coverage: null });
  assert.deepEqual(L.c2pOpenRound(null, last, now, 3600)!.effort, 2);
  for (const ls of [null, {}, { current_luck_trend: 0 }, { current_luck_trend: null }, { current_round: { effort: null } }])
    assert.equal(L.c2pOpenRound(ls, last, now, 0), null);
  assert.equal(L.c2pOpenRound({}, null, now, 3600), null, 'no block yet: no round');
});

const NOW = 1794800000;
const round = (hoursAgo: number, effort: number, first = false): Round =>
  ({ ts: NOW - hoursAgo * 3600, effort, first, hash: 'h' + hoursAgo, height: 1000 - hoursAgo });

test('period luck is pooled: k / (sum of effort + the open round so far)', () => {
  const rounds = [round(200, 1, true), round(100, 0.5), round(30, 2), round(20, 0.1), round(2, 0.4)];
  const open: Open = { effort: 0.25, elapsed: 7200, expected_time: 28800, source: 'server', since: null };
  const day = L.c2pPeriodLuck(rounds, NOW, D, open)!;
  assert.deepEqual([day.k, day.blocks_expected, day.luck, day.source, day.span_s], [2, 0.75, 100 * 2 / 0.75, 'client', D]);
  assert.ok(near(day.ci95_low!, 100 * 0.242209278544 / 0.75) && near(day.ci95_high!, 100 * 7.224687667724 / 0.75));
  const week = L.c2pPeriodLuck(rounds, NOW, 7 * D, open)!;
  assert.deepEqual([week.k, week.blocks_expected], [4, 3.25]);
  // All: the first block is in, as effort 1.
  const all = L.c2pPeriodLuck(rounds, NOW, null, open)!;
  assert.deepEqual([all.k, all.blocks_expected, all.span_s], [5, 4.25, 200 * 3600]);
  // The mean of the per-block lucks of those five rounds would read 320 %.
  assert.equal((100 / 1 + 100 / 0.5 + 100 / 2 + 100 / 0.1 + 100 / 0.4) / 5, 320);
  assert.ok(near(all.luck, 100 * 5 / 4.25, 1e-12));

  // Without an open round: the completed rounds alone.
  assert.equal(L.c2pPeriodLuck(rounds, NOW, D, null)!.blocks_expected, 0.5);
  // An open round longer than the period: only the part inside it counts.
  const long: Open = { effort: 3, elapsed: 3 * D, expected_time: D, source: 'server', since: null };
  const empty = L.c2pPeriodLuck([round(100, 0.5)], NOW, D, long)!;
  assert.deepEqual([empty.k, empty.blocks_expected, empty.luck, empty.ci95_low], [0, 1, 0, 0]);
  assert.ok(near(empty.ci95_high!, 368.8879454114));
  // The round that straddles the start of the period counts for the part
  // inside it, as in the node's own periods: a 40 h round that ended 4 h
  // into the day is 4 / 40 of its effort.
  const straddle = [{ ...round(60, 1), gap: 20 * 3600 }, { ...round(20, 2), gap: 40 * 3600 }, { ...round(10, 0.5), gap: 10 * 3600 }];
  const clipped = L.c2pPeriodLuck(straddle, NOW, D, null)!;
  assert.deepEqual([clipped.k, clipped.blocks_expected], [2, 2 * 4 / 40 + 0.5]);
  assert.equal(L.c2pPeriodLuck(straddle, NOW, null, null)!.blocks_expected, 3.5, 'all: nothing to clip');
  // The first block has no round to clip: it counts as 1.
  assert.equal(L.c2pPeriodLuck([{ ...round(20, 1, true), gap: null }], NOW, D, null)!.blocks_expected, 1);
  // Nothing at all: no figure.
  assert.equal(L.c2pPeriodLuck([], NOW, D, null), null);
  assert.equal(L.c2pPeriodLuck([round(100, 0.5)], NOW, D, null), null);
});

test('a block with no effort is left out with its round, and alone gives no figure', () => {
  const open: Open = { effort: 0.25, elapsed: 7200, expected_time: 28800, source: 'client', since: null };
  const noEffort = [NOW - 3 * 3600];
  // A block was found today, of unknown effort: not "0 blocks".
  assert.equal(L.c2pPeriodLuck([round(100, 0.5)], NOW, D, open, noEffort), null);
  const week = L.c2pPeriodLuck([round(100, 0.5)], NOW, 7 * D, open, noEffort)!;
  assert.deepEqual([week.k, week.blocks_expected, week.skipped], [1, 0.75, 1]);
  assert.match(L.c2pPeriodTip('7 days', week), /1 block has no known effort and is left out with its round\./);
});

test('the node\'s periods are shown as served; an older node gets the fallback, period by period', () => {
  const rounds = [round(100, 0.5), round(30, 2), round(2, 0.5)];
  const open: Open = { effort: 0.5, elapsed: 7200, expected_time: 14400, source: 'server', since: null };
  const served = {
    periods: {
      '1d': { k: 1, blocks_expected: 0.9, luck: 111.1, ci95_low: 2.8, ci95_high: 619.1, span_s: 86400, k_unmeasured: 2 },
      '7d': { k: 30, blocks_expected: 33.3, luck: 90.09, ci95_low: 60.78, ci95_high: 128.6, span_s: 604800 },
      '30d': { k: 0, blocks_expected: 0, luck: null, ci95_low: null, ci95_high: null, span_s: 2592000 },
    },
  };
  const p = L.c2pLuckPeriods(served, rounds, NOW, open);
  assert.deepEqual(p['1d'], { k: 1, blocks_expected: 0.9, luck: 111.1, ci95_low: 2.8, ci95_high: 619.1, span_s: 86400, skipped: 2, source: 'server' });
  assert.match(L.c2pPeriodTip('1d', p['1d']), /2 blocks have no known effort and are left out with their rounds\./);
  assert.doesNotMatch(L.c2pPeriodTip('1d', p['1d']), /older node/);
  assert.equal(p['7d']!.skipped, 0);
  assert.deepEqual([p['7d']!.k, p['7d']!.luck, p['7d']!.source], [30, 90.09, 'server'], 'not recomputed from the rows');
  assert.equal(p['30d'], null, 'served without a luck: a dash');
  assert.deepEqual([p['90d']!.source, p['90d']!.k, p['90d']!.blocks_expected], ['client', 3, 3.5], 'a period the node left out');
  // An older node: every period from the rows.
  const old = L.c2pLuckPeriods({ luck_available: true, current_luck_trend: 200 }, rounds, NOW, open);
  assert.deepEqual(Object.keys(old), ['1d', '7d', '30d', '90d', 'all']);
  assert.deepEqual([old['1d']!.k, old['1d']!.blocks_expected, old['7d']!.k, old['7d']!.blocks_expected, old['all']!.source],
                   [1, 1, 3, 3.5, 'client']);
  assert.deepEqual(L.c2pLuckPeriods(null, [], NOW, null), { '1d': null, '7d': null, '30d': null, '90d': null, all: null });
});

interface DashFixture { columns: string[]; rows: (string | number | null)[][] }
interface DashMeta {
  captured_utc: number; current_luck_trend: number;
  mean_of_per_block_luck_30d: number; mean_of_per_block_luck_7d: number;
  pooled_reference: Record<string, { k: number; blocks_expected: number; luck: number }>;
}
function dashRows(): Row[] {
  const f = fixture<DashFixture>('dash-voidbind-20261116/recent_blocks_luck.json');
  return f.rows.map(r => {
    const o: Record<string, unknown> = { chain: 'DASH' };
    f.columns.forEach((c, i) => { o[c] = r[i]; });
    return o as unknown as Row;
  });
}
const META = fixture<DashMeta>('dash-voidbind-20261116/META.json');
function dashPeriods(rows: Row[]): { periods: Periods; set: PaceSet; open: Open } {
  const set = L.c2pBlockPace(rows, 'DASH');
  const open = L.c2pOpenRound({ current_luck_trend: META.current_luck_trend }, set.lastMain!.ts, META.captured_utc, 0)!;
  return { set, open, periods: L.c2pLuckPeriods({ current_luck_trend: META.current_luck_trend }, set.rounds, META.captured_utc, open, set.noEffort) };
}

test('live DASH ledger (older build): 7 d 118 %, 30 d 100 %, where the old badges read 522 % and 1281 %', () => {
  const rows = dashRows();
  const { periods } = dashPeriods(rows);
  // The reference was computed apart from the dashboard (META.json).
  for (const key of ['1d', '7d', '30d', '90d', 'all'] as const) {
    const got = periods[key]!, want = META.pooled_reference[key]!;
    assert.equal(got.k, want.k, `${key} k`);
    assert.ok(near(got.blocks_expected, want.blocks_expected, 1e-8), `${key} expected ${got.blocks_expected} vs ${want.blocks_expected}`);
    assert.ok(near(got.luck, want.luck, 1e-8), `${key} luck ${got.luck} vs ${want.luck}`);
    assert.equal(got.source, 'client');
  }
  const week = periods['7d']!, month = periods['30d']!;
  assert.deepEqual([week.k, Math.round(week.luck), month.k, Math.round(month.luck)], [78, 118, 229, 100]);
  // Their intervals, from the hand table.
  assert.ok(near(week.ci95_low!, 100 * table(78)[1] / week.blocks_expected) && near(week.ci95_high!, 100 * table(78)[3] / week.blocks_expected));
  assert.ok(near(month.ci95_low!, 100 * table(229)[1] / month.blocks_expected) && near(month.ci95_high!, 100 * table(229)[3] / month.blocks_expected));
  assert.deepEqual([Math.round(week.ci95_low!), Math.round(week.ci95_high!), Math.round(month.ci95_low!), Math.round(month.ci95_high!)],
                   [93, 147, 88, 114]);
  assert.deepEqual(L.c2pPeriodView(week), { value: '118%', detail: '[93–147] k=78', tone: 'up' });

  // What the old badges showed: the mean of the same rows' per-block luck.
  const meanLuck = (days: number) => {
    const l = rows.filter(r => r.ts >= META.captured_utc - days * D && r.luck).map(r => r.luck!);
    return l.reduce((a, b) => a + b, 0) / l.length;
  };
  assert.ok(near(meanLuck(7), META.mean_of_per_block_luck_7d, 1e-6) && near(meanLuck(30), META.mean_of_per_block_luck_30d, 1e-6));
  assert.deepEqual([Math.round(meanLuck(7)), Math.round(meanLuck(30))], [522, 1281]);
  assert.ok(Math.abs(week.luck - meanLuck(7)) > 400 && Math.abs(month.luck - meanLuck(30)) > 1100);

  const tip = L.c2pPeriodTip('7 days', week);
  assert.match(tip, /^Pool luck, 7 days: 78 blocks found \/ 66\.03 expected = 118 %\./);
  assert.match(tip, /95 % interval for the pool's true luck: 93 – 147 % \(exact Poisson\)\./);
  assert.match(tip, /A fair pool lands in 81 – 127 % 95 % of the time with this many blocks\./);
  assert.match(tip, /Never a mean of per-block luck\./);
  assert.match(tip, /Computed in the browser from this node's time_to_find \/ expected_time \(older node\)\./);
});

test('no figure reads the per-block luck field: it can hold anything', () => {
  const rows = dashRows();
  const clean = dashPeriods(rows);
  const cleanTrend = L.c2pLuckTrendPoints(clean.set.rounds, (META.captured_utc - 7 * D) * 1000,
                                          { x: META.captured_utc * 1000, lastBlkMs: clean.set.lastMain!.ts * 1000, expectedMs: clean.open.pace_time! * 1000 });
  for (const poison of [(_r: Row) => 1e12, (_r: Row) => null, (r: Row) => (r.luck ? r.luck * 37 : 5)]) {
    const bad = rows.map(r => ({ ...r, luck: poison(r) as number | null }));
    const got = dashPeriods(bad);
    assert.deepEqual(got.periods, clean.periods);
    assert.deepEqual(got.set.rounds, clean.set.rounds);
    assert.deepEqual(Object.values(got.set.byHash).map(p => [p.effort, p.tag]), Object.values(clean.set.byHash).map(p => [p.effort, p.tag]));
    assert.deepEqual(L.c2pLuckTrendPoints(got.set.rounds, (META.captured_utc - 7 * D) * 1000,
                                          { x: META.captured_utc * 1000, lastBlkMs: got.set.lastMain!.ts * 1000, expectedMs: got.open.pace_time! * 1000 }),
                     cleanTrend);
  }
  // Rows with a luck and no times give no effort and no figure.
  const lucky = rows.slice(-20).map(r => ({ ...r, time_to_find: null, luck: 250, luck_method: 'simple_avg' }));
  const set = L.c2pBlockPace(lucky, 'DASH');
  assert.equal(set.rounds.length, 0);
  assert.deepEqual(L.c2pLuckPeriods({ current_luck_trend: 150 }, set.rounds, META.captured_utc, null, set.noEffort),
                   { '1d': null, '7d': null, '30d': null, '90d': null, all: null }, 'a dash, not a mean of the luck column');
});

test('the dashboard source has no mean of per-block luck', () => {
  const start = html.indexOf('<script>'), stop = html.lastIndexOf('</script>');
  const lines = html.slice(start, stop).split('\n').filter(l => !/^\s*\/\//.test(l));
  // An aggregate over a luck field, on one line: d3.sum(blocks, b => b.luck), lucks.reduce(...).
  const aggregate = /(d3\.(sum|mean|median)\s*\(|\.reduce\s*\()/;
  const offenders = lines.filter(l => aggregate.test(l) && /\bluck\b|lucks\b/i.test(l));
  assert.deepEqual(offenders, []);
  // The names the old means lived under, and the per-row compat field.
  for (const name of ['validLucks', 'avgLuck', 'fsAvgLuck', 'sevenDayLuck', 'thirtyDayLuck', 'pool_avg_luck'])
    assert.equal(lines.some(l => l.includes(name)), false, `${name} is gone`);
  // /luck_stats `blocks` (hash, luck, ts per block) is not read at all.
  assert.equal(lines.some(l => /(luckData|luckStats|c2pLuckStats|\bls)\.blocks\b/.test(l)), false);
  // The effort functions never read a row's luck: it is only written (p.luck = 100 / p.effort).
  const core = html.slice(html.indexOf('// BEGIN c2pLuck'), html.indexOf('// END c2pLuck'));
  const reads = core.split('\n').filter(l => !/^\s*\/\//.test(l) && /\bb\.luck\b/.test(l));
  assert.deepEqual(reads, []);
});

test('a fair pool reads 100 % pooled, and far above it as a mean of per-block luck', () => {
  // Exp(1) efforts from a fixed-seed generator (mulberry32).
  let seed = 20261116;
  const rand = () => {
    seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const rounds: Round[] = [];
  for (let i = 0; i < 5000; i++) rounds.push({ ts: NOW - (5000 - i) * 600, effort: -Math.log(1 - rand()), first: false, hash: 'r' + i, height: i });
  const all = L.c2pPeriodLuck(rounds, NOW, null, null)!;
  assert.ok(all.luck > 96 && all.luck < 104, `pooled ${all.luck}`);
  assert.ok(all.ci95_low! < 100 && all.ci95_high! > 100, 'and 100 % is inside its interval');
  const meanOfLucks = rounds.reduce((a, r) => a + 100 / r.effort, 0) / rounds.length;
  assert.ok(meanOfLucks > 500, `mean of per-block luck ${meanOfLucks}`);
  // The rolling 10-round luck stays in a sane range: its median is near 100 %.
  const pts = L.c2pLuckTrendPoints(rounds, 0, null, 10).map(p => p.y).sort((a, b) => a - b);
  const median = pts[Math.floor(pts.length / 2)]!;
  assert.ok(median > 95 && median < 112, `median rolling luck ${median}`);
});

test('the Round badge: effort x, a dry spell over 2x, a long one over 3x', () => {
  const states = (e: number) => { const s = L.c2pDrySpell(e)!; return [s.state, s.text, s.background, s.hint]; };
  assert.deepEqual(states(0), ['round', 'Round 0.00×', 'var(--primary)', false]);
  assert.deepEqual(states(0.6), ['round', 'Round 0.6×', 'var(--primary)', false]);
  assert.deepEqual(states(0.999), ['round', 'Round 1.0×', 'var(--primary)', false]);
  assert.deepEqual(states(1), ['over', 'Round 1.0×', '#3a3a5a', false]);
  assert.deepEqual(states(1.6), ['over', 'Round 1.6×', '#3a3a5a', false]);
  assert.deepEqual(states(2), ['over', 'Round 2.0×', '#3a3a5a', false]);
  assert.deepEqual(states(2.4), ['dry', '🏜️ Dry spell 2.4×', '#5b4b8a', false]);
  assert.deepEqual(states(3), ['dry', '🏜️ Dry spell 3.0×', '#5b4b8a', false]);
  assert.deepEqual(states(3.1), ['long', '🏜️ Long dry spell 3.1×', '#5b4b8a', false]);
  assert.deepEqual(states(5), ['long', '🏜️ Long dry spell 5.0×', '#5b4b8a', false]);
  assert.deepEqual(states(5.2), ['long', '🏜️ Long dry spell 5.2×', '#5b4b8a', true]);
  assert.deepEqual(states(14), ['long', '🏜️ Long dry spell 14×', '#5b4b8a', true]);
  for (const e of [null, NaN, -1]) assert.equal(L.c2pDrySpell(e as number), null, 'no round: no badge');
});

test('the Round tooltip gives the odds of a round this long, and no memory', () => {
  const open: Open = { effort: 2.4, elapsed: 21000, expected_time: 8750, source: 'server', since: 'aa' };
  assert.equal(L.c2pRoundTip(open),
    'This round has run 2.4× its expected length (5h 50m so far). 9.1 % of rounds run at least this long by chance (Poisson). ' +
    'A block is expected every 2h 25m at the current rate: the chance of one in the next 2h 25m is 63 %, ' +
    'exactly as at the start of the round. Mining has no memory.');
  assert.equal((100 * Math.exp(-2.4)).toFixed(1), '9.1');
  assert.equal((100 * (1 - Math.exp(-1))).toFixed(0), '63');
  const long = L.c2pRoundTip({ ...open, effort: 5.2, elapsed: 45500 });
  assert.match(long, /0\.55 % of rounds run at least this long/);
  assert.match(long, /Rounds over 5× happen 0\.67 % of the time\. If the CI95 check under the hashrate chart says the reported hashrate is above the band, look for lost hashrate/);
  assert.doesNotMatch(L.c2pRoundTip(open), /Rounds over 5×/);
  assert.match(L.c2pRoundTip({ ...open, source: 'server_trend' }), /From this node's current_luck_trend \(older node\)/);
  assert.match(L.c2pRoundTip({ ...open, method: 'integrated', coverage: 0.8 }),
               /Effort integrated over the open round from the pool hashrate and difficulty history \(history covers 80 % of it; the rest is taken at its mean\)\.$/);
  assert.match(L.c2pRoundTip({ effort: 0.5, elapsed: null, expected_time: null, source: 'server', since: null }),
               /^This round has run 0\.5× its expected length\. 61 % of rounds run at least this long by chance \(Poisson\)\. The chance of a block within one expected round time from now is 63 %/);
  assert.doesNotMatch(long + L.c2pRoundTip(open), /overdue|is due|streak|more likely|catch/i);
  assert.equal(L.c2pRoundTip(null), '');
});

test('a period as shown: luck, its interval and block count; no block is not "0 %"', () => {
  const per = (k: number, expected: number): Period => ({ ...L.c2pLuckOf(k, expected)!, span_s: D, source: 'server' });
  assert.deepEqual(L.c2pPeriodView(per(10, 8)), { value: '125%', detail: '[60–230] k=10', tone: 'up' });
  assert.deepEqual(L.c2pPeriodView(per(9, 10)), { value: '90%', detail: '[41–171] k=9', tone: 'mid' });
  assert.deepEqual(L.c2pPeriodView(per(3, 6)), { value: '50%', detail: '[10–146] k=3', tone: 'down' });
  // 99.6 % reads "100%": the tone follows the figure as shown.
  assert.deepEqual(L.c2pPeriodView(per(229, 229.9)).value, '100%');
  assert.equal(L.c2pPeriodView(per(229, 229.9)).tone, 'up');
  assert.deepEqual(L.c2pPeriodView(per(0, 0.3)), { value: '0 blk', detail: '/ 0.30 exp.', tone: 'none' });
  assert.match(L.c2pPeriodTip('1d', per(0, 0.3)), /With 0\.30 blocks expected, a fair pool finds none 74 % of the time \(Poisson\)\./);
  assert.deepEqual(L.c2pPeriodView(null), { value: '—', detail: '', tone: 'none' });
  assert.equal(L.c2pPeriodTip('7 days', null), 'Pool luck, 7 days: no round with a known effort in this period.');
  // Served without an interval: the block count alone.
  assert.equal(L.c2pPeriodView({ k: 4, blocks_expected: 5, luck: 80, ci95_low: null, ci95_high: null, span_s: D, source: 'server' }).detail, 'k=4');
});
