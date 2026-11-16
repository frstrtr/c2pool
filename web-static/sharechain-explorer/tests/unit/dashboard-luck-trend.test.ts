// The inline dashboard's Luck series on the hashrate charts (dashboard.html,
// the c2pLuckTrend block). Completed rounds are points at their luck. The
// in-progress round, luck-if-found-now = expected / elapsed * 100 capped at
// 1000, is a sampled hyperbola that starts at the last block when that block
// is in the window and at the window's left edge only when it is older. The
// node's first known block (luck_method "first_block") counts as 100 %; any
// other block with no computed luck gets no luck value. Runs the function
// extracted from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface Block { ts: number; luck?: number | null; luck_method?: string }
interface Live { x: number; y: number; expectedMs: number; lastBlkMs: number }
type Pt = [number, number | null] | { x: number; y: number; marker?: { enabled: boolean } };
type Build = (observed: [number, number][], sortedBlocks: Block[], minTime: number, live: Live | null) => Pt[];

function load(): Build {
  const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
  const begin = html.indexOf('// BEGIN c2pLuckTrend');
  const end = html.indexOf('// END c2pLuckTrend');
  assert.ok(begin >= 0 && end > begin, 'the c2pLuckTrend block is in dashboard.html');
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(html.slice(begin, end) + '\nreturn c2pLuckTrendPoints;')() as Build;
}

const build = load();
const H = 3600e3, D = 86400e3, CAP = 1000;

// The inline liveLuckPoint of dashboard.html, for an expected round time.
function live(lastBlkMs: number, nowMs: number, maxTime: number, expectedMs: number): Live {
  const elapsedMs = Math.max(nowMs - lastBlkMs, 1000);
  return { x: Math.max(nowMs, maxTime), y: Math.min((expectedMs / elapsedMs) * 100, CAP), expectedMs, lastBlkMs };
}
// The in-window blocks with a computed luck, as renderHashrateGraph collects them.
function observedOf(blocks: Block[], minTime: number, maxTime: number): [number, number][] {
  return blocks.filter(b => b.ts * 1000 >= minTime && b.ts * 1000 <= maxTime && b.luck != null && b.luck > 0)
               .map(b => [b.ts * 1000, b.luck as number]);
}
const xOf = (p: Pt) => (Array.isArray(p) ? p[0] : p.x);
const yOf = (p: Pt) => (Array.isArray(p) ? p[1] : p.y);
const hasMarker = (p: Pt) => Array.isArray(p) || p.marker?.enabled !== false;

// luck-if-found-now at x, as the end point and every curve sample must read.
function onCurve(lv: Live, x: number): number {
  return Math.min((lv.expectedMs / Math.max(x - lv.lastBlkMs, 1000)) * 100, CAP);
}
// The curve samples: luck-if-found-now at each x, falling, between start and the live point.
function assertCurve(pts: Pt[], lv: Live, fromX: number) {
  const curve = pts.filter(p => xOf(p) >= fromX && yOf(p) !== null) as Pt[];
  assert.ok(curve.length >= 24 && curve.length <= 48, `${curve.length} curve points`);
  for (let i = 0; i < curve.length; i++) {
    const p = curve[i]!;
    if (i > 0) {
      assert.ok(xOf(p) > xOf(curve[i - 1]!), 'x increases');
      assert.ok((yOf(p) as number) <= (yOf(curve[i - 1]!) as number) + 1e-9, 'luck-if-found-now never rises');
    }
    if (i < curve.length - 1) {
      assert.ok(Math.abs((yOf(p) as number) - onCurve(lv, xOf(p))) < 1e-6, `sample at ${xOf(p)} is on the hyperbola`);
      assert.equal(hasMarker(p), false, 'curve samples have no marker');
    }
  }
  assert.deepEqual(curve[curve.length - 1], [lv.x, onCurve(lv, lv.x)], 'ends at the live point, on the curve');
}

// kr1z1s LTC node, 1W view: block 84024db9 at 1794498365, luck null,
// luck_method first_block, expected_time 1921406 s; history starts ~3 d
// before it; current_luck_trend ~688 %.
const FIELD_TS = 1794498365, FIELD_EXPECTED = 1921406e3;
function fieldCase(blk: Block, earlier: Block[] = []) {
  const blkMs = blk.ts * 1000, nowMs = blkMs + 279274e3, minTime = blkMs - 3 * D, maxTime = nowMs - 30e3;
  const blocks = earlier.concat([blk]);
  const lv = live(blkMs, nowMs, maxTime, FIELD_EXPECTED);
  return { blkMs, minTime, lv, pts: build(observedOf(blocks, minTime, maxTime), blocks, minTime, lv) };
}

test('field case: the node\'s first block counts as 100 %, then the curve starts just after it', () => {
  const { blkMs, lv, pts } = fieldCase({ ts: FIELD_TS, luck: null, luck_method: 'first_block' });
  assert.ok(Math.abs(lv.y - 688) < 0.01);
  assert.ok(pts.every(p => xOf(p) >= blkMs), 'no luck line before the block');
  assert.deepEqual(pts[0], [blkMs, 100], 'the first block is a point at 100 %, with the series marker');
  assert.deepEqual(pts[1], { x: blkMs + 1000, y: CAP, marker: { enabled: false } });
  // Flat at the cap until expected/10 after the block, then falling.
  const knee = blkMs + FIELD_EXPECTED / 10;
  assert.ok(pts.slice(1).filter(p => xOf(p) <= knee).every(p => yOf(p) === CAP));
  assert.ok(pts.some(p => xOf(p) > knee && (yOf(p) as number) < CAP && (yOf(p) as number) > lv.y));
  assertCurve(pts, lv, blkMs + 1);
});

test('a null-luck block that is not the first block still gets no luck value: the curve starts at it, after a break', () => {
  for (const luck_method of [undefined, 'relayed', 'netdiff_unavailable', 'interval_unavailable']) {
    const blk: Block = { ts: FIELD_TS, luck: null };
    if (luck_method) blk.luck_method = luck_method;
    {
      const { blkMs, lv, pts } = fieldCase(blk);
      assert.ok(pts.every(p => xOf(p) >= blkMs), `${luck_method}: no luck line before the block`);
      assert.deepEqual(pts[0], { x: blkMs, y: CAP, marker: { enabled: false } }, `${luck_method}: no point of its own`);
      assertCurve(pts, lv, blkMs);
    }
    {
      // After a real-luck block: a break, no ramp from 85 % up to the cap.
      const prevMs = FIELD_TS * 1000 - D;
      const { blkMs, minTime, lv, pts } = fieldCase(blk, [{ ts: prevMs / 1000, luck: 85 }]);
      assert.deepEqual(pts.slice(0, 4), [[minTime, 85], [prevMs, 85], [blkMs, null],
                                         { x: blkMs, y: CAP, marker: { enabled: false } }], `${luck_method}`);
      assertCurve(pts, lv, blkMs);
    }
  }
});

test('the first block counts as 100 % wherever it sits; inside the window nothing is drawn before it', () => {
  const nowMs = 1794777600e3, minTime = nowMs - D, maxTime = nowMs - 30e3, lastMs = nowMs - 6 * H;
  for (const firstMs of [nowMs - 20 * H, nowMs - 30 * H]) {
    const blocks: Block[] = [{ ts: firstMs / 1000, luck: null, luck_method: 'first_block' }, { ts: lastMs / 1000, luck: 120 }];
    const lv = live(lastMs, nowMs, maxTime, 4 * H);
    const pts = build(observedOf(blocks, minTime, maxTime), blocks, minTime, lv);
    assert.deepEqual(pts.slice(0, 3), firstMs >= minTime
      ? [[firstMs, 100], [lastMs, 120], { x: lastMs + 1000, y: CAP, marker: { enabled: false } }]
      : [[minTime, 100], [lastMs, 120], { x: lastMs + 1000, y: CAP, marker: { enabled: false } }]);
    assert.ok(pts.every(p => yOf(p) !== null), 'no break');
    assertCurve(pts, lv, lastMs + 1);
  }
});

test('real-luck blocks keep their points and the minTime start; the curve starts just after the last block', () => {
  const nowMs = 1794777600e3, minTime = nowMs - D, maxTime = nowMs - 30e3;
  const blocks: Block[] = [
    { ts: (nowMs - 30 * H) / 1000, luck: 140 },  // before the window
    { ts: (nowMs - 20 * H) / 1000, luck: 85 },
    { ts: (nowMs - 10 * H) / 1000, luck: 120 },
  ];
  const lastMs = nowMs - 10 * H;
  const lv = live(lastMs, nowMs, maxTime, 4 * H);
  const pts = build(observedOf(blocks, minTime, maxTime), blocks, minTime, lv);

  assert.deepEqual(pts.slice(0, 3), [[minTime, 140], [nowMs - 20 * H, 85], [lastMs, 120]]);
  assert.deepEqual(pts[3], { x: lastMs + 1000, y: CAP, marker: { enabled: false } });
  assertCurve(pts, lv, lastMs + 1);
});

test('no block in the window: the curve spans the window from the left edge', () => {
  const nowMs = 1794777600e3, minTime = nowMs - D, maxTime = nowMs - 30e3;
  const lastMs = nowMs - 3 * D;
  const blocks: Block[] = [{ ts: lastMs / 1000, luck: 90 }];
  const lv = live(lastMs, nowMs, maxTime, 5 * D);
  const pts = build(observedOf(blocks, minTime, maxTime), blocks, minTime, lv);

  assert.equal(xOf(pts[0]!), minTime);
  assert.ok(Math.abs((yOf(pts[0]!) as number) - 250) < 1e-9, 'luck if found at the left edge, 2 d into a 5 d round');
  assert.ok(Math.abs(lv.y - 500 / 3) < 1e-9);
  assertCurve(pts, lv, minTime);
});

test('a null-luck last block after a real-luck one breaks the line and restarts the curve there', () => {
  const nowMs = 1794777600e3, minTime = nowMs - D, maxTime = nowMs - 30e3;
  const blocks: Block[] = [{ ts: (nowMs - 20 * H) / 1000, luck: 85 }, { ts: (nowMs - 6 * H) / 1000, luck: null }];
  const lastMs = nowMs - 6 * H;
  const lv = live(lastMs, nowMs, maxTime, 4 * H);
  const pts = build(observedOf(blocks, minTime, maxTime), blocks, minTime, lv);

  // No ramp from 85 % up to the cap: the round ending at the null-luck block has no luck.
  assert.deepEqual(pts.slice(0, 3), [[minTime, 85], [nowMs - 20 * H, 85], [lastMs, null]]);
  assert.deepEqual(pts[3], { x: lastMs, y: CAP, marker: { enabled: false } });
  assertCurve(pts, lv, lastMs);
});

test('without a live point the series is the observed blocks only, and stays empty with none', () => {
  const minTime = 1000e3;
  const blocks: Block[] = [{ ts: 900, luck: 70 }, { ts: 1500, luck: 110 }];
  assert.deepEqual(build([[1500e3, 110]], blocks, minTime, null), [[minTime, 70], [1500e3, 110]]);
  // A block with no computed luck before the window is not a minTime value.
  const nullPrev: Block[] = [{ ts: 900, luck: null }, { ts: 1500, luck: 110 }];
  assert.deepEqual(build([[1500e3, 110]], nullPrev, minTime, null), [[minTime, 110], [1500e3, 110]]);
  assert.deepEqual(build([], [{ ts: 1500, luck: null }], minTime, null), []);
});

test('a round still inside the cap knee stays at the cap to the live point', () => {
  const blkMs = 1794777600e3, nowMs = blkMs + 60e3;
  const lv = live(blkMs, nowMs, nowMs, 1 * D);  // 1 min into a 1 d round: capped
  const pts = build([], [{ ts: blkMs / 1000, luck: null }], blkMs - D, lv);
  assert.deepEqual(pts, [{ x: blkMs, y: CAP, marker: { enabled: false } }, [nowMs, CAP]]);
});

// The day view's last graph sample is up to a minute old, the year view's up
// to ~14.6 h: a block found since is after maxTime, outside the observed
// filter, but inside the series, which runs to now.
test('a real-luck block found after the last graph sample keeps its luck point, not a break', () => {
  const nowMs = 1794777600e3;
  {
    // Day view: luck 130 found 40 s ago, last sample 60 s ago.
    const minTime = nowMs - D, maxTime = nowMs - 60e3, blkMs = nowMs - 40e3;
    const blocks: Block[] = [{ ts: (nowMs - 10 * H) / 1000, luck: 85 }, { ts: blkMs / 1000, luck: 130 }];
    const lv = live(blkMs, nowMs, maxTime, 4 * H);
    const pts = build(observedOf(blocks, minTime, maxTime), blocks, minTime, lv);
    assert.deepEqual(pts, [[minTime, 85], [nowMs - 10 * H, 85], [blkMs, 130],
                           { x: blkMs + 1000, y: CAP, marker: { enabled: false } }, [nowMs, CAP]]);
  }
  {
    // Year view: two real-luck blocks after a 14 h old last sample.
    const minTime = nowMs - 365 * D, maxTime = nowMs - 14 * H, blkMs = nowMs - 3 * H;
    const blocks: Block[] = [{ ts: (nowMs - 20 * H) / 1000, luck: 85 }, { ts: (nowMs - 10 * H) / 1000, luck: 130 },
                             { ts: blkMs / 1000, luck: 90 }];
    const lv = live(blkMs, nowMs, maxTime, 4 * H);
    const pts = build(observedOf(blocks, minTime, maxTime), blocks, minTime, lv);
    assert.deepEqual(pts.slice(0, 4), [[minTime, 85], [nowMs - 20 * H, 85], [nowMs - 10 * H, 130], [blkMs, 90]]);
    assert.ok(pts.every(p => yOf(p) !== null), 'no break: every block here has a luck');
    assert.deepEqual(pts[4], { x: blkMs + 1000, y: CAP, marker: { enabled: false } });
    assertCurve(pts, lv, blkMs + 1);
  }
});

test('server clock ahead (maxTime > now): the end point is on the curve, and a block ahead of now ends the series', () => {
  const nowMs = 1794777600e3, minTime = nowMs - D;
  {
    // The last graph sample 10 min ahead of this clock: the series ends at it,
    // read off the curve there, not the value computed for now.
    const maxTime = nowMs + 10 * 60e3, blkMs = nowMs - 10 * H;
    const blocks: Block[] = [{ ts: (nowMs - 20 * H) / 1000, luck: 85 }, { ts: blkMs / 1000, luck: null }];
    const lv = live(blkMs, nowMs, maxTime, 4 * H);
    const pts = build(observedOf(blocks, minTime, maxTime), blocks, minTime, lv);
    assert.equal(lv.x, maxTime);
    assert.notEqual(onCurve(lv, maxTime), lv.y);
    assert.deepEqual(pts[pts.length - 1], [maxTime, onCurve(lv, maxTime)]);
    assertCurve(pts, lv, blkMs);
  }
  // A block stamped after maxTime and after now: no chord up to the cap
  // before the block; the series ends at the block.
  const maxTime = nowMs + 5 * 60e3, blkMs = nowMs + 8 * 60e3;
  for (const luck of [130, null]) {
    const blocks: Block[] = [{ ts: (nowMs - 10 * H) / 1000, luck: 85 }, { ts: blkMs / 1000, luck }];
    const lv = live(blkMs, nowMs, maxTime, 4 * H);
    const pts = build(observedOf(blocks, minTime, maxTime), blocks, minTime, lv);
    assert.deepEqual(pts, luck
      ? [[minTime, 85], [nowMs - 10 * H, 85], [blkMs, 130]]
      : [[minTime, 85], [nowMs - 10 * H, 85], [blkMs, null], [blkMs, CAP]]);
  }
});
