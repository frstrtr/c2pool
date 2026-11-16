// Layout plug-in test: grid. The layout contract (pure, keyed, unique
// keys) plus its geometry: one cell per item, row-major in item order,
// exactly where computeGridLayout (the Classic grid's maths) puts it,
// auto-fitted so the whole window fits the viewport.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGridLayout, type SceneItem } from '../../src/scene/index.js';
import { computeGridLayout } from '../../src/explorer/grid-layout.js';

const items = (n: number): SceneItem[] => Array.from({ length: n }, (_, i) => ({ key: `s${i}`, weight: 1 }));
const VIEW = { x: 0, y: 0, w: 900, h: 400 };

test('contract: pure, deterministic, unique keys in item order, input untouched', () => {
  const layout = createGridLayout();
  const input = items(300);
  const copy = JSON.parse(JSON.stringify(input));
  const a = layout.layout(input, VIEW);
  assert.deepEqual(a, layout.layout(input, VIEW));
  assert.deepEqual(input, copy);
  assert.deepEqual(a.map((t) => t.key), input.map((i) => i.key), 'one cell per item, in order');
  assert.equal(new Set(a.map((t) => t.key)).size, a.length);
  assert.equal(layout.id, 'grid');
});

test('geometry equals computeGridLayout (the Classic grid maths) cell for cell', () => {
  for (const [n, w, h] of [[8640, 1400, 700], [4320, 900, 400], [200, 600, 300], [7, 300, 200]] as const) {
    const layout = createGridLayout({ gap: 1, marginLeft: 38, minCellSize: 4, maxCellSize: 120 });
    const tiles = layout.layout(items(n), { x: 0, y: 0, w, h });
    const g = computeGridLayout({
      shareCount: n, containerWidth: w, containerHeight: h, containerPadding: 0, autoFit: true,
      cellSize: 120, minCellSize: 4, maxCellSize: 120, gap: 1, marginLeft: 38, minHeight: 0,
    });
    tiles.forEach((t, i) => {
      assert.equal(t.x, g.marginLeft + (i % g.cols) * g.step, `${n}: x of ${i}`);
      assert.equal(t.y, Math.floor(i / g.cols) * g.step, `${n}: y of ${i}`);
      assert.equal(t.w, g.cellSize);
      assert.equal(t.h, g.cellSize);
    });
    assert.deepEqual(layout.metrics(n, { x: 0, y: 0, w, h }), g);
  }
});

test('auto-fit: the whole window fits the viewport and cells stay square', () => {
  const layout = createGridLayout();
  const tiles = layout.layout(items(8640), { x: 0, y: 0, w: 1400, h: 700 });
  const last = tiles[tiles.length - 1]!;
  assert.ok(last.y + last.h <= 700 + 1e-9, 'last row inside the viewport');
  assert.ok(tiles.every((t) => t.x + t.w <= 1400 + 1e-9 && t.w === t.h));
  assert.ok(tiles[0]!.x >= 38, 'axis margin kept free');
});

test('viewport offset shifts every cell; weight is ignored', () => {
  const layout = createGridLayout();
  const a = layout.layout(items(50), VIEW);
  const b = layout.layout(items(50).map((it, i) => ({ ...it, weight: i * 7 })), { ...VIEW, x: 10, y: 20 });
  a.forEach((t, i) => {
    assert.equal(b[i]!.x, t.x + 10);
    assert.equal(b[i]!.y, t.y + 20);
    assert.equal(b[i]!.w, t.w);
  });
});

test('degenerate: no items or an empty viewport give no cells', () => {
  const layout = createGridLayout();
  assert.deepEqual(layout.layout([], VIEW), []);
  assert.deepEqual(layout.layout(items(5), { x: 0, y: 0, w: 0, h: 100 }), []);
});
