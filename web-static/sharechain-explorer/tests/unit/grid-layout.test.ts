// Unit tests for the Explorer grid-layout primitives.
// Verifies the geometry math preserved from dashboard.html:4676-4691.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeGridLayout,
  cellPosition,
  cellAtPoint,
  iterCells,
  GridLayoutPlugin,
  Host,
} from '../../src/explorer/index.js';

const BASE = {
  cellSize: 10,
  gap: 1,
  marginLeft: 38,
  minHeight: 40,
};

// ── computeGridLayout ──────────────────────────────────────────────

test('computeGridLayout: empty chain', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 0, containerWidth: 1000 });
  assert.equal(l.cols >= 1, true);
  assert.equal(l.rows, 0);
  assert.equal(l.cssHeight, BASE.minHeight);
});

test('computeGridLayout: single row below cols capacity', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 5, containerWidth: 1000 });
  // gridWidth = 1000 - 16 - 38 = 946; cols = floor(946 / 11) = 86
  assert.equal(l.cols, 86);
  assert.equal(l.rows, 1);
  assert.equal(l.step, 11);
});

test('computeGridLayout: wraps to multiple rows', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 4320, containerWidth: 1000 });
  assert.equal(l.cols, 86);
  assert.equal(l.rows, Math.ceil(4320 / 86));
});

test('computeGridLayout: narrow container forces cols=1', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 5, containerWidth: 30 });
  assert.equal(l.cols, 1);
  assert.equal(l.rows, 5);
});

test('computeGridLayout: containerPadding override', () => {
  const a = computeGridLayout({ ...BASE, shareCount: 100, containerWidth: 500 });
  const b = computeGridLayout({ ...BASE, shareCount: 100, containerWidth: 500, containerPadding: 0 });
  // padding 0 → more gridWidth → more cols
  assert.ok(b.cols >= a.cols);
});

test('computeGridLayout: cssWidth == marginLeft + cols*step', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 200, containerWidth: 800 });
  assert.equal(l.cssWidth, l.marginLeft + l.cols * l.step);
});

test('computeGridLayout: negative shareCount clamps to 0', () => {
  const l = computeGridLayout({ ...BASE, shareCount: -5, containerWidth: 800 });
  assert.equal(l.rows, 0);
  assert.equal(l.shareCount, 0);
});

// ── cellPosition ───────────────────────────────────────────────────

test('cellPosition: index 0 sits at (marginLeft, 0)', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 50, containerWidth: 1000 });
  const p = cellPosition(l, 0);
  assert.ok(p);
  assert.equal(p!.x, l.marginLeft);
  assert.equal(p!.y, 0);
  assert.equal(p!.col, 0);
  assert.equal(p!.row, 0);
});

test('cellPosition: last index in a full row', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 200, containerWidth: 1000 });
  const p = cellPosition(l, l.cols - 1);
  assert.equal(p!.col, l.cols - 1);
  assert.equal(p!.row, 0);
});

test('cellPosition: wraps to row 1 at index = cols', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 200, containerWidth: 1000 });
  const p = cellPosition(l, l.cols);
  assert.equal(p!.col, 0);
  assert.equal(p!.row, 1);
  assert.equal(p!.y, l.step);
});

test('cellPosition: out-of-range returns null', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 10, containerWidth: 1000 });
  assert.equal(cellPosition(l, -1), null);
  assert.equal(cellPosition(l, 10), null);
  assert.equal(cellPosition(l, 100), null);
});

// ── cellAtPoint ────────────────────────────────────────────────────

test('cellAtPoint: inside cell 0', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 50, containerWidth: 1000 });
  assert.equal(cellAtPoint(l, l.marginLeft + 1, 1), 0);
  assert.equal(cellAtPoint(l, l.marginLeft + 9, 9), 0);
});

test('cellAtPoint: inside cell at col 1', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 50, containerWidth: 1000 });
  assert.equal(cellAtPoint(l, l.marginLeft + l.step + 1, 0), 1);
});

test('cellAtPoint: rejects points in the left margin', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 50, containerWidth: 1000 });
  assert.equal(cellAtPoint(l, l.marginLeft - 1, 0), null);
});

test('cellAtPoint: rejects negative y', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 50, containerWidth: 1000 });
  assert.equal(cellAtPoint(l, l.marginLeft + 1, -1), null);
});

test('cellAtPoint: rejects gap between cells', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 50, containerWidth: 1000 });
  // x at cellSize exactly lands in the gap
  assert.equal(cellAtPoint(l, l.marginLeft + l.cellSize, 0), null);
});

test('cellAtPoint: rejects index beyond shareCount', () => {
  // 3 shares, 10 cols wide → col 0, row 0 index 0; col 5 row 0 → index 5 > 3 → null
  const l = computeGridLayout({ ...BASE, shareCount: 3, containerWidth: 1000 });
  assert.equal(cellAtPoint(l, l.marginLeft + 10 * l.step + 1, 0), null);
});

test('cellAtPoint: round-trip with cellPosition', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 200, containerWidth: 1000 });
  for (const i of [0, 1, 5, l.cols - 1, l.cols, l.cols * 2 + 3]) {
    const p = cellPosition(l, i);
    if (!p) continue;
    const hit = cellAtPoint(l, p.x + 2, p.y + 2);
    assert.equal(hit, i, `round-trip failed at ${i}`);
  }
});

// ── iterCells ──────────────────────────────────────────────────────

test('iterCells: yields shareCount entries', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 37, containerWidth: 1000 });
  const cells = Array.from(iterCells(l));
  assert.equal(cells.length, 37);
  assert.equal(cells[0]?.index, 0);
  assert.equal(cells[36]?.index, 36);
});

test('iterCells: empty layout yields nothing', () => {
  const l = computeGridLayout({ ...BASE, shareCount: 0, containerWidth: 1000 });
  assert.equal(Array.from(iterCells(l)).length, 0);
});

// ── auto-fit cellSize ─────────────────────────────────────────────

test('autoFit off (default): cellSize preserved from opts', () => {
  const l = computeGridLayout({
    ...BASE, shareCount: 8640, containerWidth: 2000, cellSize: 10,
  });
  assert.equal(l.cellSize, 10);
});

test('autoFit on: picks largest cellSize that fits height', () => {
  const l = computeGridLayout({
    ...BASE, shareCount: 8640,
    containerWidth: 2000,
    containerHeight: 900,
    cellSize: 10, maxCellSize: 24, minCellSize: 4,
    autoFit: true,
  });
  assert.ok(l.cellSize > 4 && l.cellSize <= 24,
    `autoFit cellSize ${l.cellSize} outside [4,24]`);
  assert.ok(l.rows * l.step <= 900,
    `auto-fit violated containerHeight: rows*step=${l.rows * l.step} > 900`);
});

test('autoFit on: tiny container → min cellSize', () => {
  const l = computeGridLayout({
    ...BASE, shareCount: 8640,
    containerWidth: 200, containerHeight: 100,
    cellSize: 10, maxCellSize: 24, minCellSize: 4,
    autoFit: true,
  });
  assert.equal(l.cellSize, 4);
});

test('autoFit on: large container → max cellSize', () => {
  const l = computeGridLayout({
    ...BASE, shareCount: 100,
    containerWidth: 4000, containerHeight: 2000,
    cellSize: 10, maxCellSize: 24, minCellSize: 4,
    autoFit: true,
  });
  assert.equal(l.cellSize, 24);
});

test('autoFit on: cellSize scales with resize', () => {
  const tall = computeGridLayout({
    ...BASE, shareCount: 8640,
    containerWidth: 2000, containerHeight: 900,
    cellSize: 10, maxCellSize: 24, minCellSize: 4,
    autoFit: true,
  });
  const short = computeGridLayout({
    ...BASE, shareCount: 8640,
    containerWidth: 2000, containerHeight: 300,
    cellSize: 10, maxCellSize: 24, minCellSize: 4,
    autoFit: true,
  });
  assert.ok(tall.cellSize > short.cellSize,
    `tall ${tall.cellSize} not greater than short ${short.cellSize}`);
});

// ── plugin registration ────────────────────────────────────────────

test('GridLayoutPlugin: resolvable via host.getCapability', async () => {
  const host = new Host('explorer');
  host.registry.register(GridLayoutPlugin);
  await host.init({ kind: 'explorer' });
  const api = host.getCapability<{
    computeGridLayout: typeof computeGridLayout;
    cellAtPoint: typeof cellAtPoint;
  }>('layout.grid');
  assert.ok(api);
  const l = api!.computeGridLayout({ ...BASE, shareCount: 10, containerWidth: 500 });
  assert.equal(l.rows, 1);
  await host.destroy();
});
