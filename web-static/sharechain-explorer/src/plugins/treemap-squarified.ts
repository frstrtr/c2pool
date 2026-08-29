// shared.treemap.squarified — van Wijk squarified treemap layout.
// Ported from dashboard.html:6042-6073 with numerical hardening
// (zero-area guards, NaN-safe aspect comparisons, stable tie order).
// Provides capability `layout.treemap`.

import type { PluginDescriptor } from '../registry.js';

export interface TreemapItem {
  area: number;            // normalised fraction (caller responsibility)
  [key: string]: unknown;  // opaque metadata passes through
}

export interface TreemapRect {
  x: number;
  y: number;
  w: number;
  h: number;
  [key: string]: unknown;
}

export type SquarifyFn = (
  items: readonly TreemapItem[],
  x: number,
  y: number,
  w: number,
  h: number,
) => TreemapRect[];

function aspectFor(area: number, cross: number, main: number): number {
  if (!isFinite(area) || !isFinite(cross) || main <= 0) return Infinity;
  const side = (area / main) * cross;
  if (side <= 0) return Infinity;
  return Math.max(side / cross, cross / side);
}

export const squarify: SquarifyFn = (items, x, y, w, h) => {
  const rects: TreemapRect[] = [];
  const filtered = items.filter((it) => it.area > 0 && isFinite(it.area));
  layout(filtered, x, y, w, h, rects);
  return rects;
};

function layout(
  items: readonly TreemapItem[],
  x: number,
  y: number,
  w: number,
  h: number,
  out: TreemapRect[],
): void {
  if (items.length === 0 || w <= 0 || h <= 0) return;
  let total = 0;
  for (const it of items) total += it.area;
  if (total <= 0) return;

  const vertical = w >= h;
  const main = vertical ? h : w;
  const cross = vertical ? w : h;

  const row: TreemapItem[] = [];
  let rowArea = 0;
  let i = 0;
  while (i < items.length) {
    const next = items[i];
    if (next === undefined) break;
    if (row.length === 0) {
      row.push(next);
      rowArea += next.area;
      i++;
      continue;
    }
    // Worst aspect ratio if we keep the row as-is vs add one more.
    let worstNow = 0;
    const sNow = (rowArea / total) * cross;
    for (const r of row) {
      worstNow = Math.max(worstNow, aspectFor(r.area, sNow, main));
    }
    const testArea = rowArea + next.area;
    const sNext = (testArea / total) * cross;
    let worstNext = 0;
    for (const r of row) {
      worstNext = Math.max(worstNext, aspectFor(r.area, sNext, main));
    }
    worstNext = Math.max(worstNext, aspectFor(next.area, sNext, main));
    if (worstNext > worstNow) break;
    row.push(next);
    rowArea = testArea;
    i++;
  }

  const strip = Math.max(1, (rowArea / total) * cross);
  let off = 0;
  for (const r of row) {
    const size = (r.area / rowArea) * main;
    const rect: TreemapRect = vertical
      ? { ...r, x, y: y + off, w: strip, h: size }
      : { ...r, x: x + off, y, w: size, h: strip };
    out.push(rect);
    off += size;
  }
  const remaining = items.slice(i);
  if (remaining.length > 0) {
    if (vertical) layout(remaining, x + strip, y, w - strip, h, out);
    else layout(remaining, x, y + strip, w, h - strip, out);
  }
}

export const TreemapSquarifiedPlugin: PluginDescriptor = {
  id: 'shared.treemap.squarified',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'util',
  provides: ['layout.treemap'],
  priority: 0,
  capabilities: {
    'layout.treemap': squarify,
  },
};
