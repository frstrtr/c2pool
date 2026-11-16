// The inline dashboard's Luck series on the hashrate charts (dashboard.html,
// the c2pLuckTrend block). Completed rounds are points at their luck. The
// in-progress round, luck-if-found-now = expected / elapsed * 100 capped at
// 1000, is a sampled hyperbola that starts at the last block when that block
// is in the window and at the window's left edge only when it is older. A
// block with no computed luck gets no luck value. Runs the function extracted
// from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface Block { ts: number; luck?: number | null }
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
      const want = Math.min(lv.expectedMs / Math.max(xOf(p) - lv.lastBlkMs, 1000) * 100, CAP);
      assert.ok(Math.abs((yOf(p) as number) - want) < 1e-6, `sample at ${xOf(p)} is on the hyperbola`);
      assert.equal(hasMarker(p), false, 'curve samples have no marker');
    }
  }
  assert.deepEqual(curve[curve.length - 1], [lv.x, lv.y], 'ends at the live point');
}

test('field case: the only in-window block has null luck, the curve starts at that block', () => {
  // kr1z1s LTC node, 1W view: block 84024db9 at 1794498365, luck null
  // (first_block), expected_time 1921406 s; history starts ~3 d before it;
  // current_luck_trend ~688 %.
  const blk: Block = { ts: 1794498365, luck: null };
  const blkMs = blk.ts * 1000, nowMs = blkMs + 279274e3, minTime = blkMs - 3 * D;
  const lv = live(blkMs, nowMs, nowMs - 30e3, 1921406e3);
  assert.ok(Math.abs(lv.y - 688) < 0.01);
  const pts = build(observedOf([blk], minTime, nowMs - 30e3), [blk], minTime, lv);

  assert.ok(pts.every(p => xOf(p) >= blkMs), 'no luck line before the block');
  assert.equal(xOf(pts[0]!), blkMs);
  assert.equal(yOf(pts[0]!), CAP, 'starts from the cap: luck-if-found-now at elapsed -> 0');
  assert.equal(hasMarker(pts[0]!), false, 'the null-luck block gets no luck point of its own');
  // Flat at the cap until expected/10 after the block, then falling.
  const knee = blkMs + 1921406e3 / 10;
  assert.ok(pts.filter(p => xOf(p) <= knee).every(p => yOf(p) === CAP));
  assert.ok(pts.some(p => xOf(p) > knee && (yOf(p) as number) < CAP && (yOf(p) as number) > lv.y));
  assertCurve(pts, lv, blkMs);
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
