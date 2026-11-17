// Grid layout plug-in: one square cell per item, row-major in item order
// (for the share chain: newest share first), with the cell size auto-fitted
// so the whole window fills the viewport. The geometry is the existing
// computeGridLayout (src/explorer/grid-layout.ts), the same maths the
// Classic share-chain grid draws with, so a cell sits where Classic puts
// it. A left margin is kept free for the hour axis.
//
// Item weight is ignored: every item gets one cell. Keys are the item keys
// (for shares, the full share hash), so when a new share arrives at the
// head every existing cell keeps its key and slides one slot.

import { computeGridLayout, type GridLayout } from '../../explorer/grid-layout.js';
import type { Layout, Rect, SceneItem, Tile } from '../types.js';

export interface GridOptions {
  /** Gap between cells in px. Default 1. */
  gap?: number;
  /** Left strip kept free for the axis, in px. Default 38. */
  marginLeft?: number;
  /** Auto-fit bounds for the cell size in px. Defaults 4 and 120. */
  minCellSize?: number;
  maxCellSize?: number;
}

export interface GridLayoutPlugin<D = unknown> extends Layout<D> {
  /** The grid geometry the layout used for `count` items in `viewport`. */
  metrics(count: number, viewport: Rect): GridLayout;
}

export function createGridLayout<D = unknown>(opts: GridOptions = {}): GridLayoutPlugin<D> {
  const gap = Math.max(0, opts.gap ?? 1);
  const marginLeft = Math.max(0, opts.marginLeft ?? 38);
  const minCellSize = Math.max(1, opts.minCellSize ?? 4);
  const maxCellSize = Math.max(minCellSize, opts.maxCellSize ?? 120);

  const metrics = (count: number, viewport: Rect): GridLayout => computeGridLayout({
    shareCount: count,
    containerWidth: viewport.w,
    containerHeight: viewport.h,
    containerPadding: 0,
    autoFit: true,
    cellSize: maxCellSize,
    minCellSize,
    maxCellSize,
    gap,
    marginLeft,
    minHeight: 0,
  });

  return {
    id: 'grid',
    metrics,
    layout(items: readonly SceneItem<D>[], viewport: Rect): Tile<D>[] {
      if (!(viewport.w > 0) || !(viewport.h > 0) || items.length === 0) return [];
      const g = metrics(items.length, viewport);
      const out: Tile<D>[] = [];
      for (let i = 0; i < items.length; i++) {
        const it = items[i]!;
        const col = i % g.cols;
        const row = Math.floor(i / g.cols);
        out.push({
          key: it.key,
          x: viewport.x + g.marginLeft + col * g.step,
          y: viewport.y + row * g.step,
          w: g.cellSize,
          h: g.cellSize,
          weight: it.weight,
          items: [it],
          aggregate: false,
        });
      }
      return out;
    },
  };
}
