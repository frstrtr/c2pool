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

// ── DYING colour + rise scale + card + particles ──────────────────

test('dying: colour lerps origColor → palette.dead during RISE', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [sh('c')],
    newShares: [],
    evictedHashes: ['c'],
  }));
  // t=0 (start of rise): cell is at its origin colour (riseEase=0).
  const t0 = plan.frameAt(0);
  const c0 = t0.cells.find((x) => x.shareHash === 'c');
  assert.ok(c0);
  assert.match(c0?.color ?? '', /rgba\([^)]+,1\)$/);
  // Well into rise (≈ dt=0.25 ≈ riseT=0.83): colour near palette.dead.
  const tLate = plan.frameAt(plan.phase1Dur * 0.25);
  const cLate = tLate.cells.find((x) => x.shareHash === 'c');
  assert.ok(cLate);
  assert.match(cLate?.color ?? '', /rgba\([^)]+,1\)$/);
  // End of phase1 (dt>=1): cell removed from list (particles carry visual).
  const tEnd = plan.frameAt(plan.phase1Dur);
  const cEnd = tEnd.cells.find((x) => x.shareHash === 'c');
  assert.equal(cEnd, undefined);
});

test('dying: rise scale grows to dyingScale within RISE phase', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [sh('d')],
    newShares: [],
    evictedHashes: ['d'],
    dyingScale: 5,
  }));
  const base = LAYOUT.cellSize;
  const early = plan.frameAt(10).cells.find((x) => x.shareHash === 'd');
  // HOLD window: dt in [0.3, 0.55). Sample at dt=0.4 → phase1Dur*0.4.
  const hold = plan.frameAt(plan.phase1Dur * 0.4).cells.find((x) => x.shareHash === 'd');
  assert.ok(early && hold);
  assert.ok(hold!.size > early!.size);
  // HOLD: cell at full dyingScale
  assert.ok(Math.abs(hold!.size - base * 5) < 0.01);
});

test('dying HOLD emits a card overlay with miner + PPLNS text', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [sh('c', { m: 'XMINERADDR123' })],
    newShares: [],
    evictedHashes: ['c'],
    pplnsOf: () => 0.01234,  // → "1.234%"
  }));
  // Sample at dt=0.4 (within HOLD, 0.3-0.55).
  const f = plan.frameAt(plan.phase1Dur * 0.4);
  assert.equal(f.cards.length, 1);
  const card = f.cards[0]!;
  assert.equal(card.kind, 'dying');
  assert.equal(card.addrText, 'XMINERADDR');   // sliced to 10 chars
  assert.equal(card.pctText, '1.234%');
});

test('dying HOLD card shows "--" when pplnsOf is absent', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [sh('c')],
    newShares: [],
    evictedHashes: ['c'],
  }));
  const f = plan.frameAt(plan.phase1Dur * 0.4);
  assert.equal(f.cards[0]?.pctText, '--');
});

test('dying DISSOLVE emits particles; HOLD does not', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [sh('x')],
    newShares: [],
    evictedHashes: ['x'],
  }));
  // In HOLD window → no particles.
  const fHold = plan.frameAt(plan.phase1Dur * 0.4);
  assert.equal(fHold.particles.length, 0);
  // In DISSOLVE window (dt=0.75 → well into dissolve, ashT=(0.75-0.55)/0.45 ≈ 0.44)
  const fDiss = plan.frameAt(plan.phase1Dur * 0.75);
  assert.ok(fDiss.particles.length > 0);
  assert.ok(fDiss.particles.length <= 20);
});

test('particles are deterministic for a given rngSeed', () => {
  const mk = (seed: number) =>
    buildAnimationPlan(input({
      oldShares: [sh('x')],
      newShares: [],
      evictedHashes: ['x'],
      rngSeed: seed,
    })).frameAt(2400).particles;
  const a1 = mk(42);
  const a2 = mk(42);
  const b  = mk(43);
  assert.deepEqual(a1, a2);
  assert.notDeepEqual(a1, b);
});

// ── BORN colour + alpha + shrink scale ─────────────────────────────

test('born COALESCE grows a core toward the final coin colour', () => {
  const plan = buildAnimationPlan(input({
    oldShares: [],
    newShares: [sh('n')],
    addedHashes: ['n'],
  }));
  // Mid-coalesce (bt ≈ 0.2 → cT ≈ 0.57). Coalesce cell should exist and
  // have a colour in rgba() form (since lerpColor wraps in rgba).
  const mid = plan.frameAt(plan.phase3Start + plan.phase3Dur * 0.2);
  const bornCell = mid.cells.find((x) => x.shareHash === 'n');
  assert.ok(bornCell);
  assert.match(bornCell?.color ?? '', /^rgba\(/);
});

test('born LAND shrinks from bornScale to 1x; HOLD stays at bornScale', () => {
  const plan = buildAnimationPlan(input({
    newShares: [sh('n')],
    addedHashes: ['n'],
    bornScale: 5,
  }));
  const base = LAYOUT.cellSize;
  // HOLD window: bt in [0.35, 0.65). Sample at 0.5.
  const hold = plan.frameAt(plan.phase3Start + plan.phase3Dur * 0.5)
    .cells.find((x) => x.shareHash === 'n');
  assert.ok(hold);
  assert.ok(Math.abs(hold!.size - base * 5) < 0.01);
  // LAND entry (bt=0.66): scale still near bornScale.
  const landStart = plan.frameAt(plan.phase3Start + plan.phase3Dur * 0.66)
    .cells.find((x) => x.shareHash === 'n');
  assert.ok(landStart);
  assert.ok(landStart!.size > base * 4);
  // LAND end (bt=1.0): scale = 1.
  const end = plan.frameAt(plan.phase3Start + plan.phase3Dur)
    .cells.find((x) => x.shareHash === 'n');
  assert.ok(end);
  assert.ok(Math.abs(end!.size - base) < 0.5);
});

test('born HOLD emits a card overlay; COALESCE emits particles', () => {
  const plan = buildAnimationPlan(input({
    newShares: [sh('n', { m: 'XBORNMINER9' })],
    addedHashes: ['n'],
    pplnsOf: () => 0.00999,
  }));
  // HOLD at bt≈0.5 → centre of HOLD.
  const holdT = plan.phase3Start + plan.phase3Dur * 0.5;
  const holdF = plan.frameAt(holdT);
  assert.equal(holdF.cards.length, 1);
  const card = holdF.cards[0]!;
  assert.equal(card.kind, 'born');
  assert.equal(card.addrText, 'XBORNMINER');
  assert.equal(card.pctText, '0.999%');
  // COALESCE at bt≈0.2 → particles > 0, no card.
  const coalesceT = plan.phase3Start + plan.phase3Dur * 0.2;
  const coalesceF = plan.frameAt(coalesceT);
  assert.equal(coalesceF.cards.length, 0);
  assert.ok(coalesceF.particles.length > 0);
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
