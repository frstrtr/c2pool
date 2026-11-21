// Van Wijk squarified treemap — pure function. THE only squarify in
// web-static: the PPLNS View, the bundled hover zoom (via the
// shared.treemap.squarified plugin adapter) and the inline pages
// (dashboard.html hover zoom + "PPLNS Distribution", share.html, via
// the classic-script bundle dist/layout.js → window.C2PLayout) all call
// this. tests/unit/squarify-parity.test.ts pins it against the five
// copies it replaced.
//
// Numerical hardening per frstrtr/the/docs/c2pool-pplns-view-module-task.md
// §4.4:
//   - total ≤ 0 → return empty
//   - item.area ≤ 0 or non-finite → filter out
//   - w*h ≤ 0 → return empty
//   - guard aspect-ratio NaN/Infinity
//   - stable ordering for ties (sorted by area, descending)

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

export interface SquarifyOptions {
  /** Minimum thickness, in px, of every laid-out row (strip). Default 0:
   *  tile areas stay exactly proportional to the weights. The legacy
   *  inline treemaps used 1 so that sub-pixel miners still get a
   *  visible sliver; a clamped row then takes more than its share and
   *  the rows after it are renormalised into the space that is left.
   *  Views that aggregate small tiles ("N others") should keep 0. */
  minStrip?: number;
}

/** Lay `items` out in the rect (x, y, w, h). Items are sorted by area,
 *  descending (ties keep input order); rects come back in that order. */
export function squarify<T>(
  items: readonly SquarifyItem<T>[],
  x: number,
  y: number,
  w: number,
  h: number,
  opts?: SquarifyOptions,
): SquarifyRect<T>[] {
  if (!(w > 0) || !(h > 0)) return [];
  const minStrip = opts?.minStrip !== undefined && opts.minStrip > 0 ? opts.minStrip : 0;
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
  const areas = positive.map((p) => p.item.area);
  const out: SquarifyRect<T>[] = [];
  layout(areas, x, y, w, h, minStrip, (i, rx, ry, rw, rh) => {
    out.push({ x: rx, y: ry, w: rw, h: rh, data: positive[i]!.item.data });
  });
  return out;
}

/** Core layout over a descending `areas` array (any positive scale).
 *  Each level fills the remaining rect: rows run along the short side
 *  and grow while the worst aspect ratio does not get worse. Ratios are
 *  computed relative to the level's own total, exactly as the legacy
 *  inline copies did, so a `minStrip` clamp renormalises the rest. */
function layout(
  areas: readonly number[],
  x: number,
  y: number,
  w: number,
  h: number,
  minStrip: number,
  emit: (index: number, x: number, y: number, w: number, h: number) => void,
): void {
  let start = 0;
  const n = areas.length;
  while (start < n && w > 0 && h > 0) {
    let total = 0;
    for (let i = start; i < n; i++) total += areas[i]!;
    if (!(total > 0)) return;
    const vertical = w >= h;      // rows are vertical strips when wide
    const main = vertical ? h : w;  // the side a row runs along (short side)
    const cross = vertical ? w : h;

    // Greedy row: add the next item while the row's worst aspect ratio
    // does not increase. Item lengths are monotone in area, so the
    // worst ratio of a row is set by its smallest and largest item.
    let end = start + 1;
    let rowArea = areas[start]!;
    let maxA = rowArea;
    let minA = rowArea;
    while (end < n) {
      const next = areas[end]!;
      const worstNow = worstAspect(maxA, minA, rowArea, total, main, cross);
      const nextArea = rowArea + next;
      const worstNext = worstAspect(
        Math.max(maxA, next), Math.min(minA, next), nextArea, total, main, cross);
      if (worstNext > worstNow) break;
      rowArea = nextArea;
      if (next > maxA) maxA = next;
      if (next < minA) minA = next;
      end++;
    }

    const strip = Math.max(minStrip, (rowArea / total) * cross);
    let off = 0;
    for (let i = start; i < end; i++) {
      const size = (areas[i]! / rowArea) * main;
      if (vertical) emit(i, x, y + off, strip, size);
      else emit(i, x + off, y, size, strip);
      off += size;
    }
    if (vertical) { x += strip; w -= strip; }
    else          { y += strip; h -= strip; }
    start = end;
  }
}

/** Worst (largest) aspect ratio among the row's items when the row
 *  holds `rowArea` of the level's `total`. Infinity when degenerate. */
function worstAspect(
  maxA: number,
  minA: number,
  rowArea: number,
  total: number,
  main: number,
  cross: number,
): number {
  const strip = (rowArea / total) * cross;
  const longest = (maxA / rowArea) * main;
  const shortest = (minA / rowArea) * main;
  const worst = Math.max(longest / strip, strip / longest, shortest / strip, strip / shortest);
  return Number.isFinite(worst) ? worst : Infinity;
}
