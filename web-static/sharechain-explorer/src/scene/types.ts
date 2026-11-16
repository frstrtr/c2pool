// Scene engine — shared types. See src/scene/README.md for the contracts
// (layout plug-ins, Renderer, TextOverlay) these types make up.

/** Axis-aligned rectangle in CSS px. */
export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** One thing a view wants on screen: a miner, a transaction, a share.
 *  `key` is its identity across updates and across layouts. A tile that
 *  keeps its key tweens from where it was to where it goes. */
export interface SceneItem<D = unknown> {
  key: string;
  /** Layout weight (e.g. payout amount). Non-finite or ≤ 0 is dropped. */
  weight: number;
  /** Optional grouping hint for layouts that use one. */
  group?: string;
  /** Opaque view data, handed back on tiles. */
  data?: D;
}

/** A layout's output: one rectangle per key. A tile stands for one item
 *  or, when the layout aggregates ("N others"), several. */
export interface Tile<D = unknown> extends Rect {
  key: string;
  /** Sum of the weights of the items this tile stands for. */
  weight: number;
  /** The items behind the tile: one, or several for an aggregate. */
  items: readonly SceneItem<D>[];
  /** True for a synthetic tile standing for several items. */
  aggregate: boolean;
}

/** A tile with its geometry and colour as drawn at one instant (the
 *  engine interpolates with the same easing the renderer uses). */
export interface PlacedTile<D = unknown> extends Tile<D> {
  /** Packed RGBA8 colour at that instant (see colour.ts). */
  color: number;
  flags: number;
  /** True while the tile is leaving (exit tween). */
  exiting: boolean;
}

/** LAYOUT PLUG-IN CONTRACT. A layout is a pure function of the items and
 *  the viewport: no DOM, no clock, no state between calls. Same input,
 *  same output. Keys in the output must be unique; an output key that
 *  is not an input key is a synthetic tile (an aggregate). */
export interface Layout<D = unknown> {
  readonly id: string;
  layout(items: readonly SceneItem<D>[], viewport: Rect): Tile<D>[];
  /** Optional fast hit-test over tiles placed at "now". The default is a
   *  reverse scan for the topmost rect containing the point. */
  hitTest?(tiles: readonly PlacedTile<D>[], x: number, y: number): PlacedTile<D> | null;
}

/** How a view wants one tile to look right now. */
export interface TileStyle {
  /** Packed RGBA8 colour (see colour.ts). */
  color: number;
  /** FLAG_* bits and a TileKind in bits 8..15 (see renderer.ts). */
  flags: number;
}

/** A text label drawn by the TextOverlay, in CSS px. */
export interface Label {
  text: string;
  x: number;
  y: number;
  color: string;
  font: string;
  align?: 'left' | 'center' | 'right';
  baseline?: 'top' | 'middle' | 'bottom' | 'alphabetic';
  /** Clip the text to this rect (usually its tile). */
  clip?: Rect;
}
