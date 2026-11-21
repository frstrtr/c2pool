// RENDERER CONTRACT. A renderer draws tiles from the instance buffer; it
// knows nothing about layouts, items or views. The engine owns all tween
// state and uploads only changed records; the renderer evaluates the
// motion itself each frame, as progress(now, t0, dur) from easing.ts, so
// the Canvas2D backend and a GPU backend (vertex shader) draw the same
// thing and CPU hit-testing (same easing) agrees with both.
//
// Lifecycle: init(freshCanvas) → resize → (upload | draw)* →
// [contextLost] → dispose. Every renderer gets a canvas of its own (one
// that held a GPU context can never give a 2D one). init may resolve
// later (a GPU backend compiles shaders off the main path); the engine
// keeps Canvas2D drawing until it does, and stays on Canvas2D if it
// fails. On context loss the engine moves to a fallback renderer on a
// fresh canvas and re-uploads every record: no page break.

import type { DirtyRange, InstanceBuffer } from './instance-buffer.js';
import type { Label } from './types.js';

export interface Renderer {
  /** 'canvas2d', 'webgl2', 'webgpu', … */
  readonly kind: string;
  /** `canvas` is created for this renderer alone. */
  init(canvas: HTMLCanvasElement): void | Promise<void>;
  /** Drawing-surface size in CSS px and the device pixel ratio. */
  resize(cssWidth: number, cssHeight: number, dpr: number): void;
  /** New or changed records since the last upload. When
   *  `buffer.generation` differs from the last upload's, the backing
   *  store was replaced and everything must be re-uploaded. */
  upload(buffer: InstanceBuffer, dirty: readonly DirtyRange[]): void;
  /** Draw records [0, buffer.count) at engine time `now` (ms, the clock
   *  of the records' t0). Skips records whose both colours have alpha 0. */
  draw(now: number): void;
  /** The engine's callback for an unrecoverable context loss (WebGL
   *  webglcontextlost, WebGPU device.lost). Canvas2D never calls it. */
  onContextLost(cb: () => void): void;
  dispose(): void;
}

/** TEXT OVERLAY CONTRACT. Labels, axes and marks are drawn by a separate
 *  2D pass on its own canvas stacked above the renderer's, never by the
 *  quad renderer. `draw` replaces the previous labels. */
export interface TextOverlay {
  resize(cssWidth: number, cssHeight: number, dpr: number): void;
  draw(labels: readonly Label[]): void;
  dispose(): void;
}

// ── Flags (record word 12) ─────────────────────────────────────────
// Applied by the renderer instantly (not tweened). A GPU backend must
// give them the same meaning.

/** Fade the tile to DIM_ALPHA of its alpha (filter / highlight mode). */
export const FLAG_DIM = 1 << 0;
/** Hovered here or in a linked view: thin light outline. */
export const FLAG_SELECTED = 1 << 1;
/** Pinned: thick light outline. */
export const FLAG_PINNED = 1 << 2;
/** Matches the current search: amber outline. */
export const FLAG_MATCH = 1 << 3;

export const DIM_ALPHA = 0.25;

/** Tile kind, bits 8..15 of the flags. Renderers may ignore it (the text
 *  overlay draws the marks); views use it to classify tiles. */
export const KIND_SHIFT = 8;
export const KIND_MASK = 0xff << KIND_SHIFT;

export const TileKind = {
  Plain: 0,
  /** ★ a miner on this node. */
  ThisNode: 1,
  /** ⚑ the node owner's fee. */
  OwnerFee: 2,
  /** ◇ the donation output. */
  Donation: 3,
  /** ▣ a block share that is not on the best sharechain. */
  OffChainBlock: 4,
  /** "N others": an aggregate of small tiles. */
  Others: 5,
} as const;
export type TileKindValue = typeof TileKind[keyof typeof TileKind];

export function withKind(flags: number, kind: TileKindValue): number {
  return ((flags & ~KIND_MASK) | ((kind & 0xff) << KIND_SHIFT)) >>> 0;
}

export function kindOf(flags: number): number {
  return (flags & KIND_MASK) >>> KIND_SHIFT;
}
