// The inline dashboard's Luck series on the hashrate charts (dashboard.html,
// c2pLuckTrendPoints in the c2pLuck block): the pooled luck of the last N
// rounds, n blocks / sum of their effort, one point per round. The node's
// first known block has effort 1 and so is a point at 100 %. The open round
// is in the pool too: from the last block the series runs on as
// n / (sum(effort) + elapsed / expected), sampled, to a marked end point.
// It replaced the joined per-block lucks and the expected / elapsed
// hyperbola, which started every round at the 1000 % cap. Runs the function
// extracted from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface Round { ts: number; effort: number; first?: boolean; covered?: number; measured?: boolean; gap?: number | null }
interface Live { x: number; lastBlkMs: number; expectedMs: number }
interface Pt { x: number; y: number; n: number; expected: number; skipped: number; open?: boolean; marker?: { enabled: boolean } }
interface Trend {
  c2pLuckTrendPoints(rounds: Round[] | null, minTime: number, live: Live | null, N?: number): Pt[];
  c2pLuckDisplay(luck: number): number;
  c2pLuckFromDisplay(v: number): number;
  c2pBlockPace(rows: unknown[], sym?: string): { rounds: Round[]; noEffort: number[]; lastMain: { ts: number } | null };
  c2pOpenRound(luckStats: unknown, lastMainTs: number, nowS: number, fallbackExpected: number):
    { effort: number; covered_effort: number; pace_time: number } | null;
  c2pLuckPeriods(luckStats: unknown, rounds: Round[], nowS: number, open: unknown, noEffort?: number[]):
    Record<string, { k: number; blocks_expected: number; luck: number; skipped: number; source: string } | null>;
  c2pPeriodLuck(rounds: Round[], nowS: number, spanS: number | null, open: unknown, noEffort?: number[]):
    { k: number; blocks_expected: number; luck: number; skipped: number } | null;
}

function load(): Trend {
  const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
  const begin = html.indexOf('// BEGIN c2pLuck');
  const end = html.indexOf('// END c2pLuck');
  assert.ok(begin >= 0 && end > begin, 'the c2pLuck block is in dashboard.html');
  const src = html.slice(begin, end);
  const names = [...src.matchAll(/^\s*function (c2p\w+)\(/gm)].map(m => m[1]);
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(src + '\nreturn {' + names.join(',') + '};')() as Trend;
}

const T = load();
const build = T.c2pLuckTrendPoints;
const H = 3600e3, D = 86400e3, SAMPLES = 16, CAP = 1000;
const NOW = 1794777600e3;
const at = (ms: number, effort: number, first = false): Round => ({ ts: ms / 1000, effort, first });
const near = (a: number, b: number) => Math.abs(a - b) < 1e-9 * Math.max(1, Math.abs(b));
const isSample = (p: Pt) => p.marker?.enabled === false;
const xy = (pts: Pt[]) => pts.map(p => [p.x, p.y]);

// The open-round tail from fromX: every point is n / (sum + elapsed /
// expected) at its own x, falling, unmarked up to a marked end point.
function assertTail(pts: Pt[], live: Live, fromX: number, n: number, sum: number) {
  const tail = pts.filter(p => p.open);
  assert.ok(tail.length >= 2 && tail.length <= SAMPLES + 1, `${tail.length} tail points`);
  tail.forEach((p, i) => {
    assert.ok(near(p.y, 100 * n / (sum + Math.max(p.x - live.lastBlkMs, 0) / live.expectedMs)), `tail point at ${p.x} is on the curve`);
    assert.equal(p.n, n);
    if (i > 0) {
      assert.ok(p.x > tail[i - 1]!.x, 'x increases');
      assert.ok(p.y < tail[i - 1]!.y, 'the pooled luck falls while no block comes');
    }
    assert.equal(isSample(p), i < tail.length - 1, 'only the end point has a marker');
  });
  assert.ok(tail[0]!.x >= fromX);
  assert.equal(tail[tail.length - 1]!.x, Math.max(live.x, live.lastBlkMs), 'ends at the live point');
  assert.equal(pts[pts.length - 1], tail[tail.length - 1]);
}

test('each round is a point at the pooled luck of the last N rounds: n / sum(effort)', () => {
  const rounds = [at(NOW - 40 * H, 1, true), at(NOW - 30 * H, 0.5), at(NOW - 20 * H, 2), at(NOW - 10 * H, 0.25)];
  const pts = build(rounds, NOW - 3 * D, null, 3);
  assert.deepEqual(pts, [
    { x: NOW - 40 * H, y: 100, n: 1, expected: 1, skipped: 0 },
    { x: NOW - 30 * H, y: 100 * 2 / 1.5, n: 2, expected: 1.5, skipped: 0 },
    { x: NOW - 20 * H, y: 100 * 3 / 3.5, n: 3, expected: 3.5, skipped: 0 },
    { x: NOW - 10 * H, y: 100 * 3 / 2.75, n: 3, expected: 2.75, skipped: 0 },   // the first block left the window
  ]);
  // Not the per-block lucks 100, 200, 50, 400 joined up.
  assert.notDeepEqual(pts.map(p => p.y), [100, 200, 50, 400]);

  // The default window is 10 rounds.
  const many = Array.from({ length: 14 }, (_, i) => at(NOW - (14 - i) * H, i < 4 ? 2 : 0.5));
  const last = build(many, 0, null);
  assert.deepEqual(last.map(p => p.n), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10, 10, 10, 10]);
  assert.deepEqual([last[9]!.expected, last[13]!.expected], [4 * 2 + 6 * 0.5, 10 * 0.5]);
  assert.equal(last[13]!.y, 200);
});

test('the node\'s first block is a point at 100 %, and nothing is drawn before it', () => {
  const firstMs = NOW - 20 * H;
  const pts = build([at(firstMs, 1, true), at(NOW - 6 * H, 0.5)], NOW - D, null);
  assert.deepEqual(xy(pts), [[firstMs, 100], [NOW - 6 * H, 100 * 2 / 1.5]]);
  assert.ok(pts.every(p => p.x >= firstMs && !isSample(p)), 'both carry the series marker');
});

test('the line starts at the window\'s left edge with the value of the last round before it', () => {
  const minTime = NOW - D;
  const rounds = [at(NOW - 50 * H, 1, true), at(NOW - 30 * H, 0.25), at(NOW - 20 * H, 2), at(NOW - 10 * H, 1)];
  const pts = build(rounds, minTime, null);
  assert.deepEqual(pts, [
    { x: minTime, y: 100 * 2 / 1.25, n: 2, expected: 1.25, skipped: 0, marker: { enabled: false } },
    { x: NOW - 20 * H, y: 100 * 3 / 3.25, n: 3, expected: 3.25, skipped: 0 },
    { x: NOW - 10 * H, y: 100 * 4 / 4.25, n: 4, expected: 4.25, skipped: 0 },
  ]);
  // A round exactly at the edge is a point, not a start value.
  assert.deepEqual(xy(build([at(minTime, 0.5)], minTime, null)), [[minTime, 200]]);
});

test('the open round is in the pool: from the last block the series runs on, falling', () => {
  const minTime = NOW - D, lastMs = NOW - 10 * H;
  const rounds = [at(NOW - 30 * H, 0.8), at(NOW - 20 * H, 0.2), at(lastMs, 1)];
  const live: Live = { x: NOW, lastBlkMs: lastMs, expectedMs: 4 * H };
  const pts = build(rounds, minTime, live);
  assert.deepEqual(pts.slice(0, 3), [
    { x: minTime, y: 100 / 0.8, n: 1, expected: 0.8, skipped: 0, marker: { enabled: false } },
    { x: NOW - 20 * H, y: 200, n: 2, expected: 1, skipped: 0 },
    { x: lastMs, y: 150, n: 3, expected: 2, skipped: 0 },
  ]);
  assert.equal(pts.length, 3 + SAMPLES);
  assertTail(pts, live, lastMs + 1, 3, 2);
  // 10 h into a 4 h round: 3 blocks against 2 + 2.5 expected.
  assert.ok(near(pts[pts.length - 1]!.y, 100 * 3 / 4.5));
  // It leaves the last block's own point without a jump, and never rises
  // above it: no cap, no hyperbola from 1000 %.
  assert.ok(pts.slice(3).every(p => p.y < 150 && p.y > 100 * 3 / 4.5 - 1e-9));
  assert.ok(150 - pts[3]!.y < 150 * 0.1);
});

test('field case: an older node\'s one block, the first, then 100 / (1 + open effort)', () => {
  // http://92.53.224.27:9328 on 2026-11-16: block 84024db9 at 1794498365,
  // luck null, first_block; /luck_stats current_luck_trend 663.75.
  const rows = [{ hash: '84024db9', number: 3211872, ts: 1794498365, chain: 'LTC', status: 'confirmed', luck: null,
                  luck_method: 'first_block', time_to_find: null, expected_time: 1921406.0645293593 }];
  const nowS = 1794816885, blkMs = 1794498365e3;
  const set = T.c2pBlockPace(rows, 'LTC');
  const open = T.c2pOpenRound({ blocks: [], current_luck_trend: 663.7500811361269, luck_available: true }, set.lastMain!.ts, nowS, 0)!;
  assert.ok(near(open.effort, 100 / 663.7500811361269));
  const live: Live = { x: nowS * 1000, lastBlkMs: blkMs, expectedMs: open.pace_time * 1000 };
  const pts = build(set.rounds, blkMs - 3 * D, live);
  assert.deepEqual(pts[0], { x: blkMs, y: 100, n: 1, expected: 1, skipped: 0 });
  assert.ok(pts.every(p => p.x >= blkMs), 'no luck line before the block');
  assertTail(pts, live, blkMs + 1, 1, 1);
  assert.ok(near(pts[pts.length - 1]!.y, 100 / (1 + open.effort)));
  assert.equal(Math.round(pts[pts.length - 1]!.y), 87);
});

test('no block in the window: the line spans it, the open round counted from its start', () => {
  const minTime = NOW - D, lastMs = NOW - 3 * D;
  const rounds = [at(lastMs - 2 * D, 1.5), at(lastMs, 0.5)];
  const live: Live = { x: NOW, lastBlkMs: lastMs, expectedMs: 5 * D };
  const pts = build(rounds, minTime, live);
  // At the left edge the round is 2 d old: 2 blocks / (2 + 2/5) expected.
  assert.deepEqual(pts[0], { x: minTime, y: 100 * 2 / 2.4, n: 2, expected: 2.4, skipped: 0, marker: { enabled: false }, open: true });
  assert.equal(pts.length, SAMPLES + 1);
  assertTail(pts, live, minTime, 2, 2);
  assert.ok(near(pts[pts.length - 1]!.y, 100 * 2 / 2.6));
});

test('a last block with no effort adds no point: the tail starts at it, level with the last point', () => {
  const minTime = NOW - D, lastEffortMs = NOW - 20 * H, lastMs = NOW - 6 * H;
  const rounds = [at(NOW - 30 * H, 1), at(lastEffortMs, 0.25)];   // the block at lastMs has no effort
  const live: Live = { x: NOW, lastBlkMs: lastMs, expectedMs: 4 * H };
  const pts = build(rounds, minTime, live);
  assert.deepEqual(pts.slice(0, 3), [
    { x: minTime, y: 100, n: 1, expected: 1, skipped: 0, marker: { enabled: false } },
    { x: lastEffortMs, y: 160, n: 2, expected: 1.25, skipped: 0 },
    { x: lastMs, y: 160, n: 2, expected: 1.25, skipped: 0, marker: { enabled: false }, open: true },
  ]);
  assertTail(pts, live, lastMs, 2, 1.25);
  assert.ok(pts.every(p => p.y !== null && isFinite(p.y)), 'no break, no cap');
});

// ltc.voidbind's ledger through the node's luck model (fixtures/
// ltc-voidbind-20261116): its rate history starts inside the round that
// ended at block 3160570, which it covers for 13 %.
interface GapFixture { rows: Record<string, unknown>[] }
interface GapStats {
  current_round: { effort: number; history_coverage: number; elapsed: number };
  periods: Record<string, { k: number; blocks_expected: number; luck: number; k_unmeasured: number }>;
}
const fixture = <F>(name: string) =>
  JSON.parse(readFileSync(new URL(`./fixtures/ltc-voidbind-20261116/${name}`, import.meta.url), 'utf8')) as F;

test('rate history with gaps: the series pools covered effort only and ends on the "all" period luck', () => {
  const rows = fixture<GapFixture>('recent_blocks_luck.json').rows;
  const stats = fixture<GapStats>('luck_stats.json');
  const nowS = fixture<{ now_utc: number }>('META.json').now_utc;
  const set = T.c2pBlockPace(rows, 'LTC');
  // Four rounds (two finds never confirmed and are no round). The row of
  // the 13 % round shows its effort scaled up to the whole round, 9.29.
  assert.deepEqual(set.rounds.map(r => [Math.round(r.effort * 100) / 100, Math.round(r.covered! * 100) / 100, r.measured]),
                   [[1, 1, true], [9.29, 1.24, true], [3.35, 3.24, true], [0.52, 0.52, true]]);
  const open = T.c2pOpenRound(stats, set.lastMain!.ts, nowS, 0)!;
  assert.ok(near(open.covered_effort, stats.current_round.effort * stats.current_round.history_coverage));
  const live: Live = { x: nowS * 1000, lastBlkMs: set.lastMain!.ts * 1000, expectedMs: open.pace_time * 1000 };
  const pts = build(set.rounds, 0, live);
  const last = pts[pts.length - 1]!;
  // The node's "all" period: 4 blocks / 6.14 expected = 65 %.
  const all = stats.periods['all']!;
  assert.deepEqual([all.k, Math.round(all.luck)], [4, 65]);
  assert.equal(last.n, all.k);
  assert.ok(near(last.expected, all.blocks_expected), `${last.expected} vs ${all.blocks_expected}`);
  assert.ok(near(last.y, all.luck), `${last.y} vs ${all.luck}`);
  // The badge shows that period as served, and the page's own pooling of
  // the rows gives the same figure.
  assert.equal(T.c2pLuckPeriods(stats, set.rounds, nowS, open, set.noEffort)['all']!.luck, all.luck);
  const own = T.c2pPeriodLuck(set.rounds, nowS, null, open, set.noEffort)!;
  assert.ok(near(own.luck, all.luck) && own.k === all.k && own.skipped === all.k_unmeasured);
  // Summing the rows' scaled efforts instead read 28 %.
  const scaled = set.rounds.reduce((a, r) => a + r.effort, 0) + open.effort;
  assert.equal(Math.round(100 * all.k / scaled), 28);
  // Each point is the same pooling up to its round.
  assert.deepEqual(pts.filter(p => !p.open).map(p => [p.n, Math.round(p.expected * 100) / 100, Math.round(p.y)]),
                   [[1, 1, 100], [2, 2.24, 89], [3, 5.48, 55], [4, 6, 67]]);
});

test('a block found in a gap of the rate history is left out of the blocks found; its covered effort still counts', () => {
  // Round 2 is covered for a quarter and its block came while the history
  // was not watching; round 3 is whole.
  const rounds: Round[] = [
    { ...at(NOW - 30 * H, 1, true) },
    { ...at(NOW - 20 * H, 2), covered: 0.5, measured: false, gap: 10 * 3600 },
    { ...at(NOW - 10 * H, 0.5), covered: 0.5, measured: true, gap: 10 * 3600 },
  ];
  const pts = build(rounds, NOW - 3 * D, null);
  assert.deepEqual(pts, [
    { x: NOW - 30 * H, y: 100, n: 1, expected: 1, skipped: 0 },
    { x: NOW - 20 * H, y: 100 * 1 / 1.5, n: 1, expected: 1.5, skipped: 1 },
    { x: NOW - 10 * H, y: 100, n: 2, expected: 2, skipped: 1 },
  ]);
  // The periods pool the same way: the series' last point is the "all" luck.
  const all = T.c2pPeriodLuck(rounds, NOW / 1000, null, null)!;
  assert.deepEqual([all.k, all.blocks_expected, all.luck, all.skipped], [2, 2, 100, 1]);
  // Rows as the node serves them: `measured` false, the covered part from
  // effort * history_coverage, or the node's own effort_covered.
  const row = (h: number, hours: number, more: object) =>
    ({ hash: 'h' + h, number: h, ts: (NOW - hours * H) / 1000, chain: 'LTC', status: 'confirmed', main_chain: true, ...more });
  const set = T.c2pBlockPace([
    row(1, 30, { effort: 1, effort_method: 'first_block' }),
    row(2, 20, { effort: 2, effort_method: 'integrated', history_coverage: 0.25, measured: false }),
    row(3, 10, { effort: 0.5, effort_method: 'integrated', history_coverage: 1, effort_covered: 0.5 }),
    row(4, 5, { effort: 0.3, effort_method: 'single_sample', history_coverage: 0 }),
  ], 'LTC');
  assert.deepEqual(set.rounds.map(r => [r.covered, r.measured]), [[1, true], [0.5, false], [0.5, true], [0.3, true]]);
  const served = build(set.rounds, 0, null);
  assert.deepEqual(served.map(p => [p.n, p.expected, p.skipped]), [[1, 1, 0], [1, 1.5, 1], [2, 2, 1], [3, 2.3, 1]]);
});

test('no round with an effort: no series, open round or not', () => {
  const live: Live = { x: NOW, lastBlkMs: NOW - 6 * H, expectedMs: 4 * H };
  assert.deepEqual(build([], NOW - D, live), []);
  assert.deepEqual(build([], NOW - D, null), []);
  assert.deepEqual(build(null, NOW - D, live), []);
});

test('without an open round, or with no expected time for it, the series is the round points only', () => {
  const rounds = [at(NOW - 20 * H, 1), at(NOW - 10 * H, 0.5)];
  const points = [[NOW - 20 * H, 100], [NOW - 10 * H, 100 * 2 / 1.5]];
  assert.deepEqual(xy(build(rounds, NOW - D, null)), points);
  assert.deepEqual(xy(build(rounds, NOW - D, { x: NOW, lastBlkMs: NOW - 10 * H, expectedMs: 0 })), points);
});

// The day view's last graph sample is up to a minute old, the year view's up
// to ~14.6 h: a block found since is still a round, and a point.
test('a block found after the last graph sample is a point, and the tail starts at it', () => {
  const blkMs = NOW - 40e3;
  const rounds = [at(NOW - 10 * H, 1), at(blkMs, 0.5)];
  const live: Live = { x: NOW, lastBlkMs: blkMs, expectedMs: 4 * H };
  const pts = build(rounds, NOW - D, live);
  assert.deepEqual(pts.slice(0, 2), [{ x: NOW - 10 * H, y: 100, n: 1, expected: 1, skipped: 0 }, { x: blkMs, y: 100 * 2 / 1.5, n: 2, expected: 1.5, skipped: 0 }]);
  assertTail(pts, live, blkMs + 1, 2, 1.5);
});

test('server clock ahead: the end point is at the last graph sample; a block ahead of now ends the series', () => {
  const rounds = [at(NOW - 20 * H, 1), at(NOW - 10 * H, 0.5)];
  {
    // The last graph sample is 10 min ahead of this clock.
    const live: Live = { x: NOW + 10 * 60e3, lastBlkMs: NOW - 10 * H, expectedMs: 4 * H };
    const pts = build(rounds, NOW - D, live);
    assertTail(pts, live, NOW - 10 * H + 1, 2, 1.5);
    assert.equal(pts[pts.length - 1]!.x, NOW + 10 * 60e3);
  }
  // A block stamped after both: the series ends at its point.
  const blkMs = NOW + 8 * 60e3;
  const ahead = rounds.concat([at(blkMs, 0.5)]);
  const pts = build(ahead, NOW - D, { x: NOW + 5 * 60e3, lastBlkMs: blkMs, expectedMs: 4 * H });
  assert.deepEqual(xy(pts), [[NOW - 20 * H, 100], [NOW - 10 * H, 100 * 2 / 1.5], [blkMs, 150]]);
});

test('values are capped at 1000 % for the axis', () => {
  // A ledger that begins with a 6-second round and no first block.
  const pts = build([at(NOW - 5 * H, 0.0007), at(NOW - 4 * H, 0.9)], NOW - D, null);
  assert.equal(pts[0]!.y, CAP);
  assert.ok(near(pts[1]!.y, 100 * 2 / 0.9007));
  assert.equal(pts[0]!.expected, 0.0007, 'the pool behind the capped point is kept');
});

test('the luck axis: linear to 100 %, log-compressed above, and back', () => {
  assert.deepEqual([0, 40, 100].map(v => T.c2pLuckDisplay(v)), [0, 40, 100]);
  assert.ok(near(T.c2pLuckDisplay(200), 100 + 100 * Math.log10(2)));
  assert.ok(near(T.c2pLuckDisplay(1000), 200));
  for (const luck of [0, 37, 100, 116, 250, 1000]) assert.ok(near(T.c2pLuckFromDisplay(T.c2pLuckDisplay(luck)), luck), `${luck} % round-trips`);
});
