// Layout plug-in test: treemap. Every layout has one such file proving
// the layout contract (pure, keyed, unique keys) and its own geometry.
// The weights gate lives here: with the linear scale and no gap, every
// tile's area is its weight's share of the viewport.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createTreemapLayout, DEFAULT_OTHERS_KEY, type SceneItem, type Tile } from '../../src/scene/index.js';

const VIEW = { x: 0, y: 0, w: 900, h: 400 };

function fixtureItems(): SceneItem[] {
  // The pixel-harness payouts: {addr: {amount}} like /current_merged_payouts.
  const raw = JSON.parse(readFileSync(new URL('../visual/fixtures/merged_payouts.json', import.meta.url), 'utf8')) as
    Record<string, { amount: number }>;
  return Object.entries(raw).map(([key, v]) => ({ key, weight: v.amount }));
}

const ltcLike = (): SceneItem[] => [
  { key: 'Xwhale', weight: 97 },
  ...Array.from({ length: 40 }, (_, i) => ({ key: `Xsmall${i}`, weight: 3 * (i + 1) / 820 })),
];

const areaOf = (t: Tile): number => t.w * t.h;
const sum = (xs: readonly number[]): number => xs.reduce((s, v) => s + v, 0);

test('contract: pure, deterministic, unique keys, input untouched', () => {
  const items = fixtureItems();
  const copy = JSON.parse(JSON.stringify(items));
  const layout = createTreemapLayout();
  const a = layout.layout(items, VIEW);
  const b = layout.layout(items, VIEW);
  assert.deepEqual(a, b);
  assert.deepEqual(items, copy, 'input not mutated');
  assert.equal(new Set(a.map((t) => t.key)).size, a.length, 'unique keys');
  assert.equal(layout.id, 'treemap');
});

test('weights gate: tile area / viewport area == weight / total (linear, no gap)', () => {
  const items = fixtureItems();
  const total = sum(items.map((i) => i.weight));
  const tiles = createTreemapLayout({ gap: 0, othersFraction: 0 }).layout(items, VIEW);
  assert.equal(tiles.length, items.length);
  const byKey = new Map(items.map((i) => [i.key, i.weight]));
  for (const t of tiles) {
    const share = byKey.get(t.key)! / total;
    assert.ok(Math.abs(areaOf(t) / (VIEW.w * VIEW.h) - share) < 1e-9, `${t.key}`);
    assert.ok(Math.abs(t.weight - byKey.get(t.key)!) === 0, 'tile carries the true weight');
  }
  assert.ok(Math.abs(sum(tiles.map(areaOf)) - VIEW.w * VIEW.h) < 1e-6, 'tiles fill the viewport');
});

test('"N others": small items collapse into one aggregate with their true weight', () => {
  const items = ltcLike();
  const total = sum(items.map((i) => i.weight));
  const tiles = createTreemapLayout({ gap: 0 }).layout(items, VIEW);
  const others = tiles.find((t) => t.key === DEFAULT_OTHERS_KEY);
  assert.ok(others, 'aggregate present');
  assert.equal(others!.aggregate, true);
  const small = items.filter((i) => i.weight / total < 0.005);
  assert.equal(others!.items.length, small.length);
  assert.ok(Math.abs(others!.weight - sum(small.map((i) => i.weight))) < 1e-12);
  assert.ok(Math.abs(areaOf(others!) / (VIEW.w * VIEW.h) - others!.weight / total) < 1e-9, 'aggregate area is proportional');
  assert.equal(tiles.length, items.length - small.length + 1);
});

test('"N others": a single small item is never aggregated alone', () => {
  const tiles = createTreemapLayout({ gap: 0 }).layout([{ key: 'a', weight: 1000 }, { key: 'b', weight: 1 }], VIEW);
  assert.deepEqual(tiles.map((t) => t.key).sort(), ['a', 'b']);
  assert.ok(tiles.every((t) => !t.aggregate));
});

test('"N others": minTileArea aggregates tiles that would be too small to see', () => {
  const items = [{ key: 'a', weight: 100 }, { key: 'b', weight: 0.6 }, { key: 'c', weight: 0.6 }, { key: 'd', weight: 50 }];
  const tiles = createTreemapLayout({ gap: 0, othersFraction: 0, minTileArea: 0.01 * VIEW.w * VIEW.h }).layout(items, VIEW);
  const others = tiles.find((t) => t.aggregate);
  assert.deepEqual(others?.items.map((i) => i.key), ['b', 'c']);
});

test('expandOthers: members laid out inside the aggregate rect, still proportional', () => {
  const items = ltcLike();
  const total = sum(items.map((i) => i.weight));
  const collapsed = createTreemapLayout({ gap: 0 }).layout(items, VIEW);
  const box = collapsed.find((t) => t.aggregate)!;
  const expanded = createTreemapLayout({ gap: 0, expandOthers: true }).layout(items, VIEW);
  assert.equal(expanded.length, items.length);
  assert.ok(!expanded.some((t) => t.aggregate));
  for (const t of expanded.filter((x) => x.key.startsWith('Xsmall'))) {
    assert.ok(t.x >= box.x - 1e-9 && t.y >= box.y - 1e-9, `${t.key} inside`);
    assert.ok(t.x + t.w <= box.x + box.w + 1e-9 && t.y + t.h <= box.y + box.h + 1e-9, `${t.key} inside`);
    assert.ok(Math.abs(areaOf(t) / (VIEW.w * VIEW.h) - t.weight / total) < 1e-9, `${t.key} proportional`);
  }
});

test('log scale lets small items be seen (non-proportional by design)', () => {
  const items = ltcLike();
  const lin = createTreemapLayout({ gap: 0, othersFraction: 0 }).layout(items, VIEW);
  const log = createTreemapLayout({ gap: 0, othersFraction: 0, scale: 'log' }).layout(items, VIEW);
  const a = (ts: Tile[], k: string): number => areaOf(ts.find((t) => t.key === k)!);
  assert.ok(a(log, 'Xsmall0') > 10 * a(lin, 'Xsmall0'));
  assert.ok(a(log, 'Xwhale') < a(lin, 'Xwhale'));
  assert.equal(log.find((t) => t.key === 'Xwhale')!.weight, 97, 'tiles still carry the true weight');
});

test('gap insets tiles by gap/2 and tiles never overlap', () => {
  const tiles = createTreemapLayout({ gap: 2 }).layout(fixtureItems(), VIEW);
  for (let i = 0; i < tiles.length; i++) {
    const a = tiles[i]!;
    assert.ok(a.x >= 1 - 1e-9 && a.y >= 1 - 1e-9 && a.x + a.w <= VIEW.w - 1 + 1e-9 && a.y + a.h <= VIEW.h - 1 + 1e-9);
    for (let j = i + 1; j < tiles.length; j++) {
      const b = tiles[j]!;
      const overlap = a.x < b.x + b.w - 1e-9 && b.x < a.x + a.w - 1e-9 && a.y < b.y + b.h - 1e-9 && b.y < a.y + a.h - 1e-9;
      assert.equal(overlap, false, `${a.key} / ${b.key}`);
    }
  }
});

test('degenerate input: empty, zero viewport, non-positive weights', () => {
  const layout = createTreemapLayout();
  assert.deepEqual(layout.layout([], VIEW), []);
  assert.deepEqual(layout.layout(fixtureItems(), { x: 0, y: 0, w: 0, h: 100 }), []);
  const tiles = layout.layout([{ key: 'a', weight: 0 }, { key: 'b', weight: -1 }, { key: 'c', weight: NaN }, { key: 'd', weight: 2 }], VIEW);
  assert.deepEqual(tiles.map((t) => t.key), ['d']);
});
