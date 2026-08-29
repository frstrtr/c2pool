// Unit tests for the grid canvas renderer's pure half: paint-program
// construction + execution against a mock CanvasLike. The DOM-touching
// adapter (createGridRenderer) is exercised by the browser/Qt harness.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildPaintProgram,
  executePaintProgram,
  computeGridLayout,
  LTC_COLOR_PALETTE,
  type CanvasLike,
  type PaintCommand,
  type ShareForClassify,
} from '../../src/explorer/index.js';

function share(over: Partial<ShareForClassify> = {}): ShareForClassify {
  return { s: 0, v: 1, V: 36, dv: 36, m: 'XotherAddr', ...over };
}

function mockCtx(): CanvasLike & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    fillStyle: '',
    strokeStyle: '',
    lineWidth: 0,
    font: '',
    textAlign: 'start',
    textBaseline: 'alphabetic',
    setTransform(a, b, c, d, e, f) { calls.push(`setTransform(${a},${b},${c},${d},${e},${f})`); },
    fillRect(x, y, w, h) { calls.push(`fillRect(${x},${y},${w},${h},${this.fillStyle})`); },
    strokeRect(x, y, w, h) {
      calls.push(`strokeRect(${x},${y},${w},${h},${this.strokeStyle},lw=${this.lineWidth})`);
    },
    fillText(text, x, y) {
      calls.push(`fillText("${text}",${x},${y},${this.fillStyle},"${this.font}")`);
    },
  };
}

const BASE_LAYOUT = {
  cellSize: 10,
  gap: 1,
  marginLeft: 38,
  minHeight: 40,
};

// ── buildPaintProgram ────────────────────────────────────────────

test('buildPaintProgram: empty shares → setTransform + background + emptyText', () => {
  const layout = computeGridLayout({ ...BASE_LAYOUT, shareCount: 0, containerWidth: 500 });
  const program = buildPaintProgram({
    layout, shares: [],
    userContext: { shareVersion: 36 },
    backgroundColor: '#0d0d1a',
    dpr: 2,
  });
  assert.equal(program.length, 3);
  assert.equal(program[0]?.op, 'setTransform');
  assert.equal(program[1]?.op, 'fillBackground');
  assert.equal(program[2]?.op, 'textCenter');
});

test('buildPaintProgram: one share → setTransform + bg + fillCell', () => {
  const layout = computeGridLayout({ ...BASE_LAYOUT, shareCount: 1, containerWidth: 500 });
  const program = buildPaintProgram({
    layout, shares: [share()],
    userContext: { shareVersion: 36 },
    backgroundColor: '#0d0d1a',
    dpr: 1,
  });
  assert.equal(program.length, 3);
  assert.equal(program[2]?.op, 'fillCell');
  const cmd = program[2] as Extract<PaintCommand, { op: 'fillCell' }>;
  assert.equal(cmd.color, LTC_COLOR_PALETTE.native);
  assert.equal(cmd.x, layout.marginLeft);
  assert.equal(cmd.y, 0);
  assert.equal(cmd.w, BASE_LAYOUT.cellSize);
  assert.equal(cmd.h, BASE_LAYOUT.cellSize);
});

test('buildPaintProgram: mixed classification yields mixed colours', () => {
  const layout = computeGridLayout({ ...BASE_LAYOUT, shareCount: 3, containerWidth: 500 });
  const program = buildPaintProgram({
    layout,
    shares: [
      share({ s: 2 }),                  // dead
      share({ V: 35, dv: 36 }),         // signaling
      share({ m: 'XmyAddr' }),          // native mine
    ],
    userContext: { myAddress: 'XmyAddr', shareVersion: 36 },
    backgroundColor: '#0d0d1a',
    dpr: 1,
  });
  const fills = program.filter((c): c is Extract<PaintCommand, { op: 'fillCell' }> => c.op === 'fillCell');
  assert.equal(fills.length, 3);
  assert.equal(fills[0]?.color, LTC_COLOR_PALETTE.dead);
  assert.equal(fills[1]?.color, LTC_COLOR_PALETTE.signaling);
  assert.equal(fills[2]?.color, LTC_COLOR_PALETTE.nativeMine);
});

test('buildPaintProgram: hoveredIndex appends strokeRect', () => {
  const layout = computeGridLayout({ ...BASE_LAYOUT, shareCount: 3, containerWidth: 500 });
  const program = buildPaintProgram({
    layout, shares: [share(), share(), share()],
    userContext: { shareVersion: 36 },
    backgroundColor: '#0d0d1a',
    dpr: 1,
    hoveredIndex: 1,
  });
  const last = program[program.length - 1];
  assert.equal(last?.op, 'strokeRect');
});

test('buildPaintProgram: hoveredIndex < 0 ignored', () => {
  const layout = computeGridLayout({ ...BASE_LAYOUT, shareCount: 3, containerWidth: 500 });
  const program = buildPaintProgram({
    layout, shares: [share()],
    userContext: { shareVersion: 36 },
    backgroundColor: '#0d0d1a',
    dpr: 1,
    hoveredIndex: -1,
  });
  assert.equal(program.find((c) => c.op === 'strokeRect'), undefined);
});

test('buildPaintProgram: OOB hoveredIndex ignored', () => {
  const layout = computeGridLayout({ ...BASE_LAYOUT, shareCount: 2, containerWidth: 500 });
  const program = buildPaintProgram({
    layout, shares: [share(), share()],
    userContext: { shareVersion: 36 },
    backgroundColor: '#0d0d1a',
    dpr: 1,
    hoveredIndex: 99,
  });
  assert.equal(program.find((c) => c.op === 'strokeRect'), undefined);
});

// ── executePaintProgram ──────────────────────────────────────────

test('executePaintProgram: setTransform+background+cell against mock ctx', () => {
  const ctx = mockCtx();
  executePaintProgram(ctx, [
    { op: 'setTransform', dpr: 2 },
    { op: 'fillBackground', w: 100, h: 50, color: '#000' },
    { op: 'fillCell', x: 5, y: 6, w: 10, h: 10, color: '#f00' },
  ]);
  assert.deepEqual(ctx.calls, [
    'setTransform(2,0,0,2,0,0)',
    'fillRect(0,0,100,50,#000)',
    'fillRect(5,6,10,10,#f00)',
  ]);
});

test('executePaintProgram: strokeRect applies colour + lineWidth', () => {
  const ctx = mockCtx();
  executePaintProgram(ctx, [
    { op: 'strokeRect', x: 1, y: 2, w: 3, h: 4, color: '#fff', lineWidth: 2 },
  ]);
  assert.equal(ctx.calls.length, 1);
  assert.match(ctx.calls[0] ?? '', /strokeRect\(1,2,3,4,#fff,lw=2\)/);
});

test('executePaintProgram: textCenter sets alignment + font', () => {
  const ctx = mockCtx();
  executePaintProgram(ctx, [
    { op: 'textCenter', text: 'hi', x: 10, y: 20, color: '#abc', font: '12px mono' },
  ]);
  assert.equal(ctx.textAlign, 'center');
  assert.equal(ctx.textBaseline, 'middle');
  assert.equal(ctx.calls.length, 1);
  assert.match(ctx.calls[0] ?? '', /fillText\("hi",10,20,#abc,"12px mono"\)/);
});

// ── round-trip ────────────────────────────────────────────────────

test('round-trip: 4320 shares → program runs without throwing', () => {
  const layout = computeGridLayout({ ...BASE_LAYOUT, shareCount: 4320, containerWidth: 1000 });
  const shares: ShareForClassify[] = Array.from({ length: 4320 }, (_, i) =>
    share({ m: `X${i % 20}`, V: i % 3 === 0 ? 35 : 36 }),
  );
  const program = buildPaintProgram({
    layout, shares,
    userContext: { myAddress: 'X5', shareVersion: 36 },
    backgroundColor: '#0d0d1a',
    dpr: 1,
  });
  assert.equal(program.length, 2 + 4320);  // setTransform + bg + 4320 cells
  const ctx = mockCtx();
  executePaintProgram(ctx, program);
  // Every fillCell emitted exactly one fillRect plus the bg rect.
  const rectCalls = ctx.calls.filter((s) => s.startsWith('fillRect'));
  assert.equal(rectCalls.length, 1 + 4320);
});
