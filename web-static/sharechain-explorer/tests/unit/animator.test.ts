// Unit tests for the three-phase animator core (spec §6,
// dashboard.html:4866-5400). Scope this commit: timing math, phase
// boundaries, position interpolation across dying/wave/born tracks,
// controller lifecycle including queue-during-running. Scale +
// colour lerp + particle effects covered in subsequent commits.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAnimationPlan,
  createAnimationController,
  computePhaseTiming,
  easeInOut,
  lerp,
  clamp01,
  SKIP_ANIMATION_NEW_COUNT_THRESHOLD,
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
  return { s: 0, v: 1, V: 36, dv: 36, m: 'XotherAddr', ...over, h: h } as unknown as ShareForClassify;
}

function makeInput(over: Partial<AnimationInput> = {}): AnimationInput {
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

// ── helpers ────────────────────────────────────────────────────────

test('clamp01: bounds', () => {
  assert.equal(clamp01(-1), 0);
  assert.equal(clamp01(0), 0);
  assert.equal(clamp01(0.5), 0.5);
  assert.equal(clamp01(1), 1);
  assert.equal(clamp01(2), 1);
});

test('lerp: endpoints + midpoint', () => {
  assert.equal(lerp(0, 10, 0), 0);
  assert.equal(lerp(0, 10, 1), 10);
  assert.equal(lerp(0, 10, 0.5), 5);
});

test('easeInOut: endpoints + midpoint', () => {
  assert.equal(easeInOut(0), 0);
  assert.equal(easeInOut(1), 1);
  assert.equal(easeInOut(0.5), 0.5);
});

// ── phase timing ───────────────────────────────────────────────────

test('computePhaseTiming: slow defaults', () => {
  const t = computePhaseTiming(false);
  assert.equal(t.phase1Start, 0);
  assert.equal(t.phase1Dur, 3000);
  assert.equal(t.phase2Start, 3000);
  assert.equal(t.phase2Dur, 4000);
  assert.equal(t.phase3Start, 3000 + 4000 * 0.7);
  assert.equal(t.phase3Dur, 3000);
  assert.equal(t.duration, t.phase3Start + t.phase3Dur);
});

test('computePhaseTiming: fast halves phase2', () => {
  const t = computePhaseTiming(true);
  assert.equal(t.phase2Dur, 2000);
  assert.equal(t.phase3Start, 3000 + 2000 * 0.7);
});

test('SKIP_ANIMATION_NEW_COUNT_THRESHOLD constant', () => {
  assert.equal(SKIP_ANIMATION_NEW_COUNT_THRESHOLD, 100);
});

// ── buildAnimationPlan: degenerate ────────────────────────────────

test('empty input → tEnd still computed, empty frame', () => {
  const plan = buildAnimationPlan(makeInput());
  const t = computePhaseTiming(false);
  assert.equal(plan.tEnd, t.duration);
  const f = plan.frameAt(0);
  assert.deepEqual(f.cells, []);
});

test('fast mode → shorter tEnd', () => {
  const slow = buildAnimationPlan(makeInput());
  const fast = buildAnimationPlan(makeInput({ fast: true }));
  assert.ok(fast.tEnd < slow.tEnd);
});

// ── WAVE track: position interpolation ─────────────────────────────

test('wave: shared between old+new but not added/evicted, moves over phase 2', () => {
  const a = sh('a');
  const b = sh('b');
  const plan = buildAnimationPlan(makeInput({
    oldShares: [a, b],
    newShares: [b, a],    // swapped positions — both wave
    oldLayout: LAYOUT,
    newLayout: LAYOUT,
  }));
  // t = 0: every cell at old position (wave easing has only just begun
  //         for the tail and hasn't started for earlier staggers).
  const f0 = plan.frameAt(0);
  assert.equal(f0.cells.length, 2);
  // t = tEnd: every wave cell at its new position
  const fEnd = plan.frameAt(plan.tEnd);
  const byHash = Object.fromEntries(fEnd.cells.map((c) => [c.shareHash, c]));
  // a: was at index 0, now at index 1 — x moves from col 0 to col 1
  const aNewCol = 1 % LAYOUT.cols;
  assert.equal(byHash.a?.x, LAYOUT.marginLeft + aNewCol * LAYOUT.step);
});

test('wave: staggering — tail moves before head', () => {
  // Four shares; all wave. Put them in 4 cols on one row.
  const shares = [sh('a'), sh('b'), sh('c'), sh('d')];
  // Swap (0,3) so all four must move.
  const reordered = [sh('d'), sh('b'), sh('c'), sh('a')];
  const plan = buildAnimationPlan(makeInput({
    oldShares: shares,
    newShares: reordered,
  }));
  // Early in phase 2: the share with highest newIndex (tail = 'a')
  // has started moving; the share with lowest newIndex (head = 'd')
  // has not yet.
  const earlyT = plan.phase2Start + 10;  // 10 ms into phase 2
  const f = plan.frameAt(earlyT);
  const byHash = Object.fromEntries(f.cells.map((c) => [c.shareHash, c]));
  const headX0 = LAYOUT.marginLeft + 0 * LAYOUT.step;  // d target
  const tailX0Old = LAYOUT.marginLeft + 0 * LAYOUT.step;  // a was at 0
  // d: still near old col 3 (hasn't started)
  assert.ok(byHash.d !== undefined);
  assert.ok(Math.abs(byHash.d!.x - (LAYOUT.marginLeft + 3 * LAYOUT.step)) < 0.01);
  // a: has started interpolating toward new col 3
  const aOldX = LAYOUT.marginLeft + 0 * LAYOUT.step;
  assert.ok(byHash.a!.x > aOldX, 'tail should have moved');
  void headX0; void tailX0Old;
});

// ── DYING track ────────────────────────────────────────────────────

test('dying: in old but not in new → present in frame during phase 1, gone by end', () => {
  const a = sh('a');
  const b = sh('b');
  const c = sh('c');
  const plan = buildAnimationPlan(makeInput({
    oldShares: [a, b, c],
    newShares: [a, b],            // c evicted
    evictedHashes: ['c'],
  }));
  const f0 = plan.frameAt(0);
  const dying = f0.cells.filter((x) => x.track === 'dying');
  assert.equal(dying.length, 1);
  assert.equal(dying[0]?.shareHash, 'c');
  assert.equal(dying[0]?.alpha, 1);
  // At phase1 end, alpha has decayed to 0 for the earliest-staggered dying share.
  const fMid = plan.frameAt(plan.phase1Start + plan.phase1Dur);
  const midDying = fMid.cells.filter((x) => x.track === 'dying');
  assert.equal(midDying.length, 1);
  assert.ok((midDying[0]?.alpha ?? 1) <= 0.01);
});

test('dying: multi-dying stagger (last-first)', () => {
  const o = [sh('x'), sh('y'), sh('z')];       // indices 0,1,2
  const plan = buildAnimationPlan(makeInput({
    oldShares: o,
    newShares: [],
    evictedHashes: ['x', 'y', 'z'],
  }));
  // Stagger is last-first → z (index 2) goes first, stagger i=0; y i=1; x i=2.
  // At t = 0, z has alpha=1 (started), x and y alpha=1 also since raw<0 → clamp
  // check at t = 150ms: z ≈ 0.95, y just started, x still ~1.
  const f = plan.frameAt(150);
  const byHash = Object.fromEntries(f.cells.map((c) => [c.shareHash, c]));
  assert.ok((byHash.z?.alpha ?? 0) < (byHash.x?.alpha ?? 0));
});

// ── BORN track ────────────────────────────────────────────────────

test('born: spawns below grid then flies into position', () => {
  const plan = buildAnimationPlan(makeInput({
    oldShares: [],
    newShares: [sh('new0')],
    addedHashes: ['new0'],
  }));
  // t = phase3Start: just starting, should be near spawn position
  const fStart = plan.frameAt(plan.phase3Start);
  const born = fStart.cells.filter((c) => c.track === 'born');
  assert.equal(born.length, 1);
  // y should still be well below the grid
  assert.ok((born[0]?.y ?? 0) > LAYOUT.cssHeight);
  // alpha should be near 0 at very start
  assert.ok((born[0]?.alpha ?? 1) <= 0.02);
  // t = phase3Start + phase3Dur: landed
  const fLanded = plan.frameAt(plan.phase3Start + plan.phase3Dur);
  const landed = fLanded.cells.filter((c) => c.track === 'born');
  assert.equal(landed[0]?.alpha, 1);
  // final y should be 0 (top row)
  assert.ok(Math.abs((landed[0]?.y ?? -1) - 0) < 0.01);
});

test('born: alpha fades in over first 30% of its lifetime', () => {
  const plan = buildAnimationPlan(makeInput({
    newShares: [sh('b')],
    addedHashes: ['b'],
  }));
  const t15pct = plan.phase3Start + plan.phase3Dur * 0.15;
  const f = plan.frameAt(t15pct);
  const b = f.cells[0];
  // 15% of 30%-ramp ≈ 0.5 alpha
  assert.ok((b?.alpha ?? -1) > 0.3 && (b?.alpha ?? -1) < 0.7);
});

// ── Controller lifecycle ──────────────────────────────────────────

test('controller: idle returns null', () => {
  const c = createAnimationController();
  assert.equal(c.isRunning(), false);
  assert.equal(c.tick(0), null);
});

test('controller: start then tick produces frames', () => {
  const c = createAnimationController();
  const plan = buildAnimationPlan(makeInput({
    newShares: [sh('b')],
    addedHashes: ['b'],
  }));
  c.start(plan, 1000);
  assert.equal(c.isRunning(), true);
  const f1 = c.tick(1000);
  assert.ok(f1);
  const f2 = c.tick(1000 + plan.phase3Start);
  assert.ok(f2);
  // at tEnd the controller completes and becomes idle
  const fEnd = c.tick(1000 + plan.tEnd);
  assert.ok(fEnd);
  assert.equal(c.isRunning(), false);
});

test('controller: queueNext kicks in after current plan ends', () => {
  const c = createAnimationController();
  const plan1 = buildAnimationPlan(makeInput({
    newShares: [sh('a')],
    addedHashes: ['a'],
  }));
  const plan2 = buildAnimationPlan(makeInput({
    newShares: [sh('b')],
    addedHashes: ['b'],
  }));
  c.start(plan1, 0);
  c.queueNext(plan2);
  // End plan1 — controller should auto-start plan2
  const f = c.tick(plan1.tEnd);
  assert.ok(f);
  assert.equal(c.isRunning(), true);
  // Now tick somewhere in plan2
  const f2 = c.tick(plan1.tEnd + 100);
  assert.ok(f2);
});

test('controller: queueNext on idle starts on next tick', () => {
  const c = createAnimationController();
  const plan = buildAnimationPlan(makeInput({
    newShares: [sh('a')],
    addedHashes: ['a'],
  }));
  c.queueNext(plan);
  assert.equal(c.isRunning(), false);  // not yet started
  const f = c.tick(500);
  assert.ok(f);
  assert.equal(c.isRunning(), true);
});

test('controller: reset drops plan + queue', () => {
  const c = createAnimationController();
  const plan = buildAnimationPlan(makeInput({
    newShares: [sh('x')],
    addedHashes: ['x'],
  }));
  c.start(plan, 0);
  c.queueNext(plan);
  c.reset();
  assert.equal(c.isRunning(), false);
  assert.equal(c.tick(1000), null);
});
