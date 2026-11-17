// shared.treemap.squarified — van Wijk squarified treemap layout.
// Capability `layout.treemap`. A thin adapter over the one squarify in
// web-static (src/pplns/squarify.ts): opaque item fields pass through
// onto the rects. It keeps the 1 px minimum strip of the inline
// dashboard.html hover zoom it was ported from, so the bundled hover
// zoom stays pixel-identical with the inline one.

import type { PluginDescriptor } from '../registry.js';
import { squarify as squarifyCore } from '../pplns/squarify.js';

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

/** Items are laid out largest-first (ties keep input order); zero,
 *  negative and non-finite areas are dropped. */
export const squarify: SquarifyFn = (items, x, y, w, h) =>
  squarifyCore(items.map((it) => ({ area: it.area, data: it })), x, y, w, h, { minStrip: 1 })
    .map((r) => ({ ...r.data, x: r.x, y: r.y, w: r.w, h: r.h }));

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
