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

interface Round { ts: number; effort: number; first?: boolean }
interface Live { x: number; lastBlkMs: number; expectedMs: number }
interface Pt { x: number; y: number; n: number; expected: number; open?: boolean; marker?: { enabled: boolean } }
interface Trend {
  c2pLuckTrendPoints(rounds: Round[] | null, minTime: number, live: Live | null, N?: number): Pt[];
  c2pLuckDisplay(luck: number): number;
  c2pLuckFromDisplay(v: number): number;
  c2pBlockPace(rows: unknown[], sym?: string): { rounds: Round[]; lastMain: { ts: number } | null };
  c2pOpenRound(luckStats: unknown, lastMainTs: number, nowS: number, fallbackExpected: number): { effort: number; pace_time: number } | null;
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
    { x: NOW - 40 * H, y: 100, n: 1, expected: 1 },
    { x: NOW - 30 * H, y: 100 * 2 / 1.5, n: 2, expected: 1.5 },
    { x: NOW - 20 * H, y: 100 * 3 / 3.5, n: 3, expected: 3.5 },
    { x: NOW - 10 * H, y: 100 * 3 / 2.75, n: 3, expected: 2.75 },   // the first block left the window
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
    { x: minTime, y: 100 * 2 / 1.25, n: 2, expected: 1.25, marker: { enabled: false } },
    { x: NOW - 20 * H, y: 100 * 3 / 3.25, n: 3, expected: 3.25 },
    { x: NOW - 10 * H, y: 100 * 4 / 4.25, n: 4, expected: 4.25 },
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
    { x: minTime, y: 100 / 0.8, n: 1, expected: 0.8, marker: { enabled: false } },
    { x: NOW - 20 * H, y: 200, n: 2, expected: 1 },
    { x: lastMs, y: 150, n: 3, expected: 2 },
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
  assert.deepEqual(pts[0], { x: blkMs, y: 100, n: 1, expected: 1 });
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
  assert.deepEqual(pts[0], { x: minTime, y: 100 * 2 / 2.4, n: 2, expected: 2.4, marker: { enabled: false }, open: true });
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
    { x: minTime, y: 100, n: 1, expected: 1, marker: { enabled: false } },
    { x: lastEffortMs, y: 160, n: 2, expected: 1.25 },
    { x: lastMs, y: 160, n: 2, expected: 1.25, marker: { enabled: false }, open: true },
  ]);
  assertTail(pts, live, lastMs, 2, 1.25);
  assert.ok(pts.every(p => p.y !== null && isFinite(p.y)), 'no break, no cap');
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
  assert.deepEqual(pts.slice(0, 2), [{ x: NOW - 10 * H, y: 100, n: 1, expected: 1 }, { x: blkMs, y: 100 * 2 / 1.5, n: 2, expected: 1.5 }]);
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
