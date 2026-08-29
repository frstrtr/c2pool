// Tests for cell decorations: block borders (LTC gold / DOGE cyan /
// twin orange), tip-marker triangle, hour-axis labels + tick lines.
// Covers the animator wave track and buildAnimatedPaintProgram paint
// command emission. Static-frame coverage lives alongside realtime
// tests; here we exercise the pure data path.

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

const LAYOUT = computeGridLayout({
  shareCount: 100, containerWidth: 1000,
  cellSize: 10, gap: 1, marginLeft: 38, minHeight: 40,
});

function sh(h: string, over: Partial<ShareForClassify> = {}): ShareForClassify {
  return { s: 0, v: 1, V: 36, dv: 36, m: 'XotherAddr', ...over, h } as unknown as ShareForClassify;
}

function input(over: Partial<AnimationInput> = {}): AnimationInput {
  return {
    oldShares: [sh('a'), sh('b'), sh('c')],
    newShares: [sh('a'), sh('b'), sh('c')],
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

// ── CellFrame stroke (block borders) ──────────────────────────────

test('LTC block hash → gold stroke, no fill override', () => {
  const plan = buildAnimationPlan(input({
    primaryBlockHashes: new Set(['b']),
  }));
  // Mid-phase 2 — wave cells drawn with stroke applied.
  const f = plan.frameAt(plan.phase2Start + 200);
  const cellB = f.cells.find((c) => c.shareHash === 'b');
  assert.ok(cellB);
  assert.deepEqual(cellB?.stroke, { color: '#ffd700', lineWidth: 2 });
});

test('DOGE block hash → cyan stroke', () => {
  const plan = buildAnimationPlan(input({
    dogeBlockHashes: new Set(['c']),
  }));
  const f = plan.frameAt(plan.phase2Start + 200);
  const cellC = f.cells.find((c) => c.shareHash === 'c');
  assert.deepEqual(cellC?.stroke, { color: '#00e5ff', lineWidth: 2 });
});

test('twin LTC+DOGE → orange fill + darker orange stroke', () => {
  const plan = buildAnimationPlan(input({
    primaryBlockHashes: new Set(['a']),
    dogeBlockHashes: new Set(['a']),
  }));
  const f = plan.frameAt(plan.phase2Start + 200);
  const cellA = f.cells.find((c) => c.shareHash === 'a');
  assert.equal(cellA?.color, '#ff8000');
  assert.deepEqual(cellA?.stroke, { color: '#ffaa00', lineWidth: 2 });
});

test('non-block cells have no stroke', () => {
  const plan = buildAnimationPlan(input({
    primaryBlockHashes: new Set(['b']),
  }));
  const f = plan.frameAt(plan.phase2Start + 200);
  const cellA = f.cells.find((c) => c.shareHash === 'a');
  assert.equal(cellA?.stroke, undefined);
});

// ── tipMark ───────────────────────────────────────────────────────

test('tip share gets tipMark when not a block', () => {
  const plan = buildAnimationPlan(input({ tipHash: 'a' }));
  const f = plan.frameAt(plan.phase2Start + 200);
  const cellA = f.cells.find((c) => c.shareHash === 'a');
  assert.equal(cellA?.tipMark, true);
});

test('tip share does NOT get tipMark when also a block', () => {
  const plan = buildAnimationPlan(input({
    tipHash: 'a',
    primaryBlockHashes: new Set(['a']),
  }));
  const f = plan.frameAt(plan.phase2Start + 200);
  const cellA = f.cells.find((c) => c.shareHash === 'a');
  assert.equal(cellA?.tipMark, undefined);
});

test('non-tip share does not get tipMark', () => {
  const plan = buildAnimationPlan(input({ tipHash: 'a' }));
  const f = plan.frameAt(plan.phase2Start + 200);
  const cellB = f.cells.find((c) => c.shareHash === 'b');
  assert.equal(cellB?.tipMark, undefined);
});

// ── Paint program emits decoration commands ──────────────────────

test('buildAnimatedPaintProgram emits strokeRect after fillCell for blocks', () => {
  const plan = buildAnimationPlan(input({
    primaryBlockHashes: new Set(['b']),
  }));
  const f = plan.frameAt(plan.phase2Start + 200);
  const program = buildAnimatedPaintProgram(f, 1);
  // Find the fillCell for 'b' — next command should be its strokeRect.
  const strokes = program.filter((c) => c.op === 'strokeRect');
  assert.ok(strokes.length >= 1, 'at least one strokeRect emitted');
  const gold = strokes.find((c) =>
    c.op === 'strokeRect' && c.color === '#ffd700');
  assert.ok(gold, 'gold stroke for LTC block');
});

test('buildAnimatedPaintProgram emits fillTriangle for tipMark', () => {
  const plan = buildAnimationPlan(input({ tipHash: 'a' }));
  const f = plan.frameAt(plan.phase2Start + 200);
  const program = buildAnimatedPaintProgram(f, 1);
  const tri = program.find((c) => c.op === 'fillTriangle');
  assert.ok(tri, 'tip triangle command emitted');
  assert.equal(tri?.op === 'fillTriangle' && tri.color, '#ffffff');
});

test('buildAnimatedPaintProgram: axis labels + lines emitted when present', () => {
  const plan = buildAnimationPlan(input({}));
  const frame = plan.frameAt(plan.phase2Start + 200);
  // Animator emits empty axis; synthesise a frame with labels.
  const synthetic = {
    ...frame,
    axisLabels: [{ text: '1h', x: 34, y: 5, color: '#b0b0cc', font: '11px sans' }],
    axisLines:  [{ x1: 38, y1: 0, x2: 100, y2: 0, color: 'rgba(140,140,180,0.2)', lineWidth: 0.5 }],
  };
  const program = buildAnimatedPaintProgram(synthetic, 1);
  const label = program.find((c) => c.op === 'textRight');
  const line  = program.find((c) => c.op === 'strokeLine');
  assert.ok(label, 'axis label command emitted');
  assert.ok(line, 'axis tick line emitted');
});
