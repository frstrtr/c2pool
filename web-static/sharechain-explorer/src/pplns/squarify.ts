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

export function squarify<T>(
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
  squarifyInner(scaled, x, y, w, h, out);
  return out;
}

function squarifyInner<T>(
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
    const currentWorst = row.length > 0 ? worstAspect(row, rowArea, short) : Infinity;
    const candidateWorst = worstAspect(
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
    squarifyInner(items.slice(i), x + rowW, y, w - rowW, h, out);
  } else {
    // Rows go left-to-right, each row is horizontal strip of height rowH.
    const rowH = rowArea / w;
    let xx = x;
    for (const r of row) {
      const rw = r.area / rowH;
      out.push({ x: xx, y, w: rw, h: rowH, data: r.data });
      xx += rw;
    }
    squarifyInner(items.slice(i), x, y + rowH, w, h - rowH, out);
  }
}

/** Max aspect ratio (worst = farthest from 1.0) among rectangles
 *  when `row` is laid out along a strip of the given short side. */
function worstAspect<T>(
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
