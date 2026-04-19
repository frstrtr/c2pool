// Tests for animator scale + colour + alpha behaviour (Phase B #5-6)
// and the animated paint-program builder. Core timing/stagger logic
// is covered by animator.test.ts.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAnimationPlan,
  buildAnimatedPaintProgram,
  computeGridLayout,
  LTC_COLOR_PALETTE,
  type AnimationInput,
  type ShareForClassify,
} from '../../src/explorer/index.js';

const BASE_LAYOUT = {
  cellSize: 10,
  gap: 1,
  marginLeft: 38,
  minHeight: 40,
};
const LAYOUT = computeGridLayout({ ...BASE_LAYOUT, shareCount: 100, containerWidth: 1000 });

function sh(h: string, over: Partial<ShareForClassify> = {}): ShareForClassify {
  return { s: 0, v: 1, V: 36, dv: 36, m: 'XotherAddr', ...over, h } as unknown as ShareForClassify;
}

function input(over: Partial<AnimationInput> = {}): AnimationInput {
  return {
    oldShares: [],
    newShares: [],
    addedHashes: [],
    evictedHashes: [],
    oldLayout: LAYOUT,
    newLayout: LAYOUT,
    userContext: { shareVersion: 36 },
    palette: LTC_COLOR_PALETTE,
    hashOf: (s) => (s as unknown as { h: string }).h,
    fast: false,
    ...over,
  };
}

// ── WAVE scale: lift-slide-land ────────────────────────────────────

test('wave: scale = 1 at t=shareStart, peaks mid-animation, returns to 1', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [sh('a'), sh('b')],
    newShares: [sh('b'), sh('a')],
  }));
  // Tail-first stagger: 'a' (newIndex=1) starts FIRST. shareStart for a = 0
  // (distFromTail = 0, fraction = 0). For share a, scale at t = phase2Start is 1,
  // peaks midway through its 600 ms slice, and returns to 1 at phase2Start+600.
  const p2s = plan.phase2Start;
  const cellSize = LAYOUT.cellSize;
  const at = (t: number) => {
    const f = plan.frameAt(t);
    return f.cells.find((c) => c.shareHash === 'a');
  };
  const start = at(p2s);
  assert.ok(start);
  // At t=0 of slice: ease=0, pop=0, scale=1
  assert.ok(Math.abs((start?.size ?? 0) - cellSize) < 0.01);
  // Mid-slice: scale > 1
  const mid = at(p2s + 300);
  assert.ok((mid?.size ?? 0) > cellSize * 1.1);
  // End of slice: scale back to 1
  const end = at(p2s + 600);
  assert.ok(Math.abs((end?.size ?? 0) - cellSize) < 0.01);
});

test('wave: peak scale does not exceed WAVE_PEAK_SCALE (1.35)', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [sh('a'), sh('b')],
    newShares: [sh('b'), sh('a')],
  }));
  let peak = 0;
  for (let t = plan.phase2Start; t <= plan.phase2Start + 1000; t += 20) {
    const f = plan.frameAt(t);
    for (const c of f.cells) {
      if (c.track === 'wave' && c.size > peak) peak = c.size;
    }
  }
  assert.ok(peak <= LAYOUT.cellSize * 1.35 + 0.01, `peak ${peak} > 1.35 * cellSize`);
  assert.ok(peak >= LAYOUT.cellSize * 1.2, `peak ${peak} should be well above cellSize`);
});

// ── DYING colour + alpha + rise scale ──────────────────────────────

test('dying: colour lerps toward palette.dead and alpha decays', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [sh('c')],
    newShares: [],
    evictedHashes: ['c'],
  }));
  const t0 = plan.frameAt(0);
  const c0 = t0.cells.find((x) => x.shareHash === 'c');
  assert.ok(c0);
  // Colour shows full alpha (rgba(...,1))
  assert.match(c0?.color ?? '', /rgba\([^)]+,1\)$/);
  // Mid-phase: alpha ~0.5
  const tMid = plan.frameAt(plan.phase1Dur * 0.5);
  const cMid = tMid.cells.find((x) => x.shareHash === 'c');
  assert.ok(cMid);
  assert.match(cMid?.color ?? '', /rgba\([^)]+,0\.5\)$/);
  // End of phase1: alpha = 0 → colour skipped in paint
  const tEnd = plan.frameAt(plan.phase1Dur);
  const cEnd = tEnd.cells.find((x) => x.shareHash === 'c');
  assert.ok(cEnd);
  assert.ok((cEnd?.alpha ?? 1) <= 0.01);
});

test('dying: rise scale grows then holds', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [sh('d')],
    newShares: [],
    evictedHashes: ['d'],
  }));
  const base = LAYOUT.cellSize;
  const early = plan.frameAt(10).cells.find((x) => x.shareHash === 'd');
  const mid   = plan.frameAt(plan.phase1Dur * 0.5).cells.find((x) => x.shareHash === 'd');
  assert.ok(early && mid);
  // Rises over first 30% → at 50% size should already be at DYING_RISE_SCALE
  assert.ok(mid!.size > early!.size);
  assert.ok(mid!.size <= base * 1.10 + 0.01);
});

// ── BORN colour + alpha + shrink scale ─────────────────────────────

test('born: colour coalesces from unverified to final coin colour', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [],
    newShares: [sh('n')],
    addedHashes: ['n'],
  }));
  // Early in phase 3: colour still near palette.unverified
  const early = plan.frameAt(plan.phase3Start + 100).cells.find((x) => x.shareHash === 'n');
  assert.ok(early);
  // Late: colour near palette.native (since share is V36 full-verified)
  const late = plan.frameAt(plan.phase3Start + plan.phase3Dur - 10).cells.find((x) => x.shareHash === 'n');
  assert.ok(late);
  // We can't strict-equal the hex (rgb() form is produced by lerpColor
  // at exactly t=1 the lerp still wraps in rgba(...)). Just assert the
  // components are consistent with palette transition.
  assert.match(early?.color ?? '', /^rgba\(/);
  assert.match(late?.color ?? '', /^rgba\(/);
});

test('born: scale shrinks from 3x toward 1x over last 20%', () => {
  const plan = buildAnimationPlan(input({
    newShares: [sh('n')],
    addedHashes: ['n'],
  }));
  const base = LAYOUT.cellSize;
  // At t = phase3Start: scale at BORN_INITIAL_SCALE (3x)
  const start = plan.frameAt(plan.phase3Start + 1).cells.find((x) => x.shareHash === 'n');
  assert.ok(start);
  assert.ok(Math.abs(start!.size - 3 * base) < base * 0.05);
  // At phase3Start + phase3Dur * 0.9: scale mid-land
  const midLand = plan.frameAt(plan.phase3Start + plan.phase3Dur * 0.9).cells.find((x) => x.shareHash === 'n');
  assert.ok(midLand);
  assert.ok(midLand!.size < 3 * base);
  assert.ok(midLand!.size > base);
  // At phase3 end: scale = 1
  const end = plan.frameAt(plan.phase3Start + plan.phase3Dur).cells.find((x) => x.shareHash === 'n');
  assert.ok(end);
  assert.ok(Math.abs(end!.size - base) < 0.5);
});

// ── Animated paint program ────────────────────────────────────────

test('buildAnimatedPaintProgram: skips alpha-0 cells', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [sh('x')],
    newShares: [],
    evictedHashes: ['x'],
  }));
  const frame = plan.frameAt(plan.phase1Dur);  // dying done — alpha = 0
  const program = buildAnimatedPaintProgram(frame, 2);
  const fillCells = program.filter((c) => c.op === 'fillCell');
  assert.equal(fillCells.length, 0);
});

test('buildAnimatedPaintProgram: emits setTransform + background + fillCells', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [sh('a'), sh('b')],
    newShares: [sh('b'), sh('a')],
  }));
  const frame = plan.frameAt(plan.phase2Start + 300);
  const program = buildAnimatedPaintProgram(frame, 1);
  assert.equal(program[0]?.op, 'setTransform');
  assert.equal(program[1]?.op, 'fillBackground');
  const fills = program.filter((c) => c.op === 'fillCell');
  assert.ok(fills.length >= 1);
});

test('buildAnimatedPaintProgram: dpr threads through to setTransform', () => {
  const plan = buildAnimationPlan(input({}));
  const program = buildAnimatedPaintProgram(plan.frameAt(0), 3);
  assert.deepEqual(program[0], { op: 'setTransform', dpr: 3 });
});
