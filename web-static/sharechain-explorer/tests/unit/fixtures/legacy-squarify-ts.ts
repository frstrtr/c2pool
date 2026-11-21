// FROZEN verbatim copies of the two TypeScript squarify implementations
// that the one squarify (src/pplns/squarify.ts) replaced, taken from
// master 623f7d9a (exports renamed, plugin descriptor dropped). Used only
// by tests/unit/squarify-parity.test.ts. Do not edit: they are the
// reference.

// ── src/plugins/treemap-squarified.ts ──────────────────────────────
// shared.treemap.squarified — van Wijk squarified treemap layout.
// Ported from dashboard.html:6042-6073 with numerical hardening
// (zero-area guards, NaN-safe aspect comparisons, stable tie order).
// Provides capability `layout.treemap`.


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

export const pluginSquarify: SquarifyFn = (items, x, y, w, h) => {
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

// ── src/pplns/squarify.ts ──────────────────────────────────────────
// Van Wijk squarified treemap — pure function.
//
// Numerical hardening per frstrtr/the/docs/c2pool-pplns-view-module-task.md
// §4.4:
//   - total ≤ 0 → return empty
//   - item.area ≤ 0 → filter out
//   - w*h ≤ 0 → return empty
//   - guard aspect-ratio NaN/Infinity
//   - stable ordering for ties

export interface SquarifyItem<T> {
  /** Area fraction (caller normalises so items sum to ≤ 1.0, or passes
   *  raw magnitudes; squarify scales internally by the sum). */
  area: number;
  /** Opaque payload returned alongside the rect. */
  data: T;
}

export interface SquarifyRect<T> {
  x: number;
  y: number;
  w: number;
  h: number;
  data: T;
}

export function pplnsSquarify<T>(
  items: readonly SquarifyItem<T>[],
  x: number,
  y: number,
  w: number,
  h: number,
): SquarifyRect<T>[] {
  if (w <= 0 || h <= 0) return [];
  // Preserve input order for stable ties — sort descending by area while
  // keeping the original index as secondary key.
  const positive: Array<{ item: SquarifyItem<T>; origIndex: number }> = [];
  for (let i = 0; i < items.length; i++) {
    const it = items[i]!;
    if (Number.isFinite(it.area) && it.area > 0) {
      positive.push({ item: it, origIndex: i });
    }
  }
  if (positive.length === 0) return [];
  positive.sort((a, b) => {
    if (b.item.area !== a.item.area) return b.item.area - a.item.area;
    return a.origIndex - b.origIndex;
  });

  let total = 0;
  for (const p of positive) total += p.item.area;
  if (!(total > 0)) return [];

  // Scale areas → actual pixel area.
  const areaScale = (w * h) / total;
  const scaled = positive.map((p) => ({
    area: p.item.area * areaScale,
    data: p.item.data,
  }));

  const out: SquarifyRect<T>[] = [];
  pplnsSquarifyInner(scaled, x, y, w, h, out);
  return out;
}

function pplnsSquarifyInner<T>(
  items: Array<{ area: number; data: T }>,
  x: number,
  y: number,
  w: number,
  h: number,
  out: SquarifyRect<T>[],
): void {
  if (items.length === 0 || w <= 0 || h <= 0) return;

  if (items.length === 1) {
    out.push({ x, y, w, h, data: items[0]!.data });
    return;
  }

  const short = Math.min(w, h);
  // Greedy row-building: grow the row while the worst aspect improves.
  const row: Array<{ area: number; data: T }> = [];
  let rowArea = 0;
  let i = 0;
  while (i < items.length) {
    const candidate = items[i]!;
    const nextArea = rowArea + candidate.area;
    const currentWorst = row.length > 0 ? pplnsWorstAspect(row, rowArea, short) : Infinity;
    const candidateWorst = pplnsWorstAspect(
      [...row, candidate],
      nextArea,
      short,
    );
    if (row.length === 0 || candidateWorst <= currentWorst) {
      row.push(candidate);
      rowArea = nextArea;
      i++;
    } else {
      break;
    }
  }

  // Lay out `row` in the short direction.
  if (w >= h) {
    // Rows go top-to-bottom, each row is vertical strip of width rowW.
    const rowW = rowArea / h;
    let yy = y;
    for (const r of row) {
      const rh = r.area / rowW;
      out.push({ x, y: yy, w: rowW, h: rh, data: r.data });
      yy += rh;
    }
    pplnsSquarifyInner(items.slice(i), x + rowW, y, w - rowW, h, out);
  } else {
    // Rows go left-to-right, each row is horizontal strip of height rowH.
    const rowH = rowArea / w;
    let xx = x;
    for (const r of row) {
      const rw = r.area / rowH;
      out.push({ x: xx, y, w: rw, h: rowH, data: r.data });
      xx += rw;
    }
    pplnsSquarifyInner(items.slice(i), x, y + rowH, w, h - rowH, out);
  }
}

/** Max aspect ratio (worst = farthest from 1.0) among rectangles
 *  when `row` is laid out along a strip of the given short side. */
function pplnsWorstAspect<T>(
  row: ReadonlyArray<{ area: number; data: T }>,
  rowArea: number,
  short: number,
): number {
  if (!(rowArea > 0) || !(short > 0)) return Infinity;
  let maxArea = -Infinity;
  let minArea = Infinity;
  for (const r of row) {
    if (r.area > maxArea) maxArea = r.area;
    if (r.area < minArea) minArea = r.area;
  }
  if (!(minArea > 0)) return Infinity;
  const s2 = short * short;
  const sum2 = rowArea * rowArea;
  const worstMax = (s2 * maxArea) / sum2;
  const worstMin = sum2 / (s2 * minArea);
  const w = Math.max(worstMax, worstMin);
  return Number.isFinite(w) ? w : Infinity;
}
