// Treemap layout plug-in: squarified (the one squarify,
// src/pplns/squarify.ts, minStrip 0), so with the default linear scale
// every tile's area is exactly proportional to its weight.
//
// "N others": items whose share of the total is below `othersFraction`,
// or whose tile would be smaller than `minTileArea` px², collapse into
// one aggregate tile that keeps their true summed weight. With
// `expandOthers` the aggregate's members are laid out inside its rect
// instead (same proportions, one level down). A single small item is
// never aggregated on its own.

import { squarify } from '../../pplns/squarify.js';
import type { Layout, Rect, SceneItem, Tile } from '../types.js';

export interface TreemapOptions {
  /** Gap between tiles in px (each tile is inset by gap/2). Default 1. */
  gap?: number;
  /** Aggregate items under this fraction of the total. Default 0.005. */
  othersFraction?: number;
  /** Aggregate items whose tile would be under this many px². Default 0. */
  minTileArea?: number;
  /** Lay out the aggregate's members inside its rect. Default false. */
  expandOthers?: boolean;
  /** 'log' sizes tiles by log(1 + w / wmin) so small items are visible.
   *  NOT proportional: views must label it as such. Default 'linear'. */
  scale?: 'linear' | 'log';
  /** Key of the aggregate tile. Default '\u0000others'. */
  othersKey?: string;
}

export const DEFAULT_OTHERS_KEY = '\u0000others';

interface Weighted<D> { item: SceneItem<D>; lw: number }

export function createTreemapLayout<D = unknown>(opts: TreemapOptions = {}): Layout<D> {
  const gap = Math.max(0, opts.gap ?? 1);
  const othersFraction = Math.max(0, opts.othersFraction ?? 0.005);
  const minTileArea = Math.max(0, opts.minTileArea ?? 0);
  const othersKey = opts.othersKey ?? DEFAULT_OTHERS_KEY;
  const log = opts.scale === 'log';

  return {
    id: 'treemap',
    layout(items, viewport) {
      if (!(viewport.w > 0) || !(viewport.h > 0)) return [];
      const positive = items.filter((it) => Number.isFinite(it.weight) && it.weight > 0);
      if (positive.length === 0) return [];
      let wmin = Infinity;
      for (const it of positive) if (it.weight < wmin) wmin = it.weight;
      const weighted: Weighted<D>[] = positive.map((item) => ({
        item,
        lw: log ? Math.log1p(item.weight / wmin) : item.weight,
      }));
      let total = 0;
      for (const w of weighted) total += w.lw;
      const area = viewport.w * viewport.h;
      const isSmall = (w: Weighted<D>): boolean =>
        w.lw / total < othersFraction || (w.lw / total) * area < minTileArea;
      let small = weighted.filter(isSmall);
      if (small.length < 2) small = [];
      const smallSet = new Set(small);
      const big = weighted.filter((w) => !smallSet.has(w));

      type Entry = { area: number; data: Weighted<D> | 'others' };
      const entries: Entry[] = big.map((w) => ({ area: w.lw, data: w }));
      let smallLw = 0;
      for (const w of small) smallLw += w.lw;
      if (small.length > 0) entries.push({ area: smallLw, data: 'others' });

      const out: Tile<D>[] = [];
      for (const r of squarify(entries, viewport.x, viewport.y, viewport.w, viewport.h)) {
        if (r.data !== 'others') {
          out.push(tileOf(r.data.item.key, r, [r.data.item], false, gap));
        } else if (opts.expandOthers === true) {
          const inner = squarify(small.map((w) => ({ area: w.lw, data: w })), r.x, r.y, r.w, r.h);
          for (const m of inner) out.push(tileOf(m.data.item.key, m, [m.data.item], false, gap));
        } else {
          out.push(tileOf(othersKey, r, small.map((w) => w.item), true, gap));
        }
      }
      return out;
    },
  };
}

function tileOf<D>(key: string, r: Rect, items: readonly SceneItem<D>[], aggregate: boolean, gap: number): Tile<D> {
  let weight = 0;
  for (const it of items) weight += it.weight;
  const inset = Math.min(gap / 2, r.w / 2, r.h / 2);
  return {
    key,
    x: r.x + inset,
    y: r.y + inset,
    w: r.w - 2 * inset,
    h: r.h - 2 * inset,
    weight,
    items,
    aggregate,
  };
}
