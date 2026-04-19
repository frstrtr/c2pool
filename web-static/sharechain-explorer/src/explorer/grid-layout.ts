// Grid layout math — pure functions, no DOM.
// Extracted from web-static/dashboard.html render() (the `defrag` object),
// specifically lines 4676-4691 for sizing and 4874-4878 for cell position.
// Contract preserved verbatim so M2 pixel-diff holds.
//
// Provides capability `layout.grid` on the Explorer host.

import type { PluginDescriptor } from '../registry.js';

export interface GridLayoutOptions {
  shareCount: number;
  containerWidth: number;  // clientWidth of the canvas's parent, pre-adjustment
  cellSize: number;        // in CSS px
  gap: number;             // in CSS px
  marginLeft: number;      // reserved strip on the left for the time axis
  minHeight: number;       // floor so the canvas isn't zero-height when empty
  /** Optional outer chrome to subtract from containerWidth. Default 16. */
  containerPadding?: number;
}

export interface GridLayout {
  cols: number;
  rows: number;
  cssWidth: number;
  cssHeight: number;
  step: number;            // cellSize + gap (column pitch)
  cellSize: number;
  gap: number;
  marginLeft: number;
  shareCount: number;
}

export interface CellPosition {
  index: number;
  col: number;
  row: number;
  x: number;   // in CSS px, top-left of the cell's bounding box
  y: number;
}

const DEFAULTS = {
  cellSize: 10,
  gap: 1,
  marginLeft: 38,
  minHeight: 40,
  containerPadding: 16,
} as const;

/** Given a container size and share count, compute grid geometry.
 *  Columns are chosen so the grid fills the available width without
 *  overflowing: cols = floor((W - marginLeft) / step), clamped to ≥1. */
export function computeGridLayout(opts: GridLayoutOptions): GridLayout {
  const cellSize = opts.cellSize;
  const gap = opts.gap;
  const marginLeft = opts.marginLeft;
  const containerPadding = opts.containerPadding ?? DEFAULTS.containerPadding;
  const step = cellSize + gap;
  const gridWidth = Math.max(0, opts.containerWidth - containerPadding - marginLeft);
  const cols = Math.max(1, Math.floor(gridWidth / step));
  const shareCount = Math.max(0, opts.shareCount | 0);
  const rows = shareCount === 0 ? 0 : Math.ceil(shareCount / cols);
  const cssWidth = marginLeft + cols * step;
  const cssHeight = Math.max(rows * step, opts.minHeight);
  return { cols, rows, cssWidth, cssHeight, step, cellSize, gap, marginLeft, shareCount };
}

/** Return the CSS-pixel position of the cell at `index`. Returns null
 *  if the index is out of range [0, shareCount). */
export function cellPosition(layout: GridLayout, index: number): CellPosition | null {
  if (index < 0 || index >= layout.shareCount) return null;
  const col = index % layout.cols;
  const row = Math.floor(index / layout.cols);
  const x = layout.marginLeft + col * layout.step;
  const y = row * layout.step;
  return { index, col, row, x, y };
}

/** Hit-test: given a point in canvas-local CSS px, return the share
 *  index under it or null. Excludes gaps (requires the point to be
 *  inside the actual cell square, not the inter-cell padding). */
export function cellAtPoint(layout: GridLayout, x: number, y: number): number | null {
  if (x < layout.marginLeft || y < 0) return null;
  const localX = x - layout.marginLeft;
  const col = Math.floor(localX / layout.step);
  const row = Math.floor(y / layout.step);
  if (col < 0 || col >= layout.cols) return null;
  if (row < 0) return null;
  // Require the point to be inside the actual cell, not the trailing gap.
  const cellX = col * layout.step;
  const cellY = row * layout.step;
  if (localX - cellX >= layout.cellSize) return null;
  if (y - cellY >= layout.cellSize) return null;
  const index = row * layout.cols + col;
  if (index >= layout.shareCount) return null;
  return index;
}

/** Convenience: iterate every cell with its position. Safe over empty
 *  layouts. */
export function* iterCells(layout: GridLayout): Generator<CellPosition> {
  for (let i = 0; i < layout.shareCount; i++) {
    const pos = cellPosition(layout, i);
    if (pos !== null) yield pos;
  }
}

/** Plugin descriptor for the Explorer host. Registers under slot
 *  `explorer.layout.grid` and provides capability `layout.grid`. */
export const GridLayoutPlugin: PluginDescriptor = {
  id: 'explorer.grid.layout',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'util',
  provides: ['layout.grid'],
  slots: ['explorer.layout.grid'],
  priority: 0,
  capabilities: {
    'layout.grid': { computeGridLayout, cellPosition, cellAtPoint, iterCells },
  },
};
