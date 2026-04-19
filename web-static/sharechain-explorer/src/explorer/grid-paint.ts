// Grid canvas renderer — paints a snapshot of shares on a 2D canvas.
// Split into two halves so the rendering logic is testable without DOM:
//
//   buildPaintProgram(...)     -> PaintCommand[]  (pure; easy to diff)
//   executePaintProgram(ctx..) -> void            (thin canvas adapter)
//
// Extracted from dashboard.html:4672-4763 (the render() body). DPR
// handling is preserved verbatim — fillRect in CSS px after
// ctx.setTransform(dpr, 0, 0, dpr, 0, 0).
//
// Provides capability `renderer.grid.canvas`.

import type { PluginDescriptor } from '../registry.js';
import type { GridLayout } from './grid-layout.js';
import { cellPosition } from './grid-layout.js';
import {
  getColor,
  type ColorPalette,
  type ShareForClassify,
  type UserContext,
} from './colors.js';
import { LTC_COLOR_PALETTE } from './colors.js';

export type PaintCommand =
  | { op: 'setTransform'; dpr: number }
  | { op: 'fillBackground'; w: number; h: number; color: string }
  | { op: 'fillCell'; x: number; y: number; w: number; h: number; color: string }
  | { op: 'strokeRect'; x: number; y: number; w: number; h: number; color: string; lineWidth: number }
  | { op: 'textCenter'; text: string; x: number; y: number; color: string; font: string };

export interface BuildPaintOptions {
  layout: GridLayout;
  shares: readonly ShareForClassify[];
  userContext: UserContext;
  palette?: Readonly<ColorPalette>;
  backgroundColor: string;
  dpr: number;
  /** If set, draws an outline around this cell (hover highlight). */
  hoveredIndex?: number | undefined;
  hoverOutlineColor?: string;
  hoverOutlineWidth?: number;
  /** Rendered when shares.length === 0; matches dashboard.html:4697-4702. */
  emptyText?: string;
  emptyTextColor?: string;
  emptyTextFont?: string;
}

const DEFAULTS = {
  palette:            LTC_COLOR_PALETTE,
  hoverOutlineColor:  '#ffffff',
  hoverOutlineWidth:  2,
  emptyText:          'Waiting for shares...',
  emptyTextColor:     '#555577',
  emptyTextFont:      '12px -apple-system, sans-serif',
} as const;

/** Produce the ordered sequence of paint operations for a frame. */
export function buildPaintProgram(opts: BuildPaintOptions): PaintCommand[] {
  const cmds: PaintCommand[] = [];
  const palette = opts.palette ?? DEFAULTS.palette;

  cmds.push({ op: 'setTransform', dpr: opts.dpr });
  cmds.push({
    op: 'fillBackground',
    w: opts.layout.cssWidth,
    h: opts.layout.cssHeight,
    color: opts.backgroundColor,
  });

  if (opts.shares.length === 0) {
    cmds.push({
      op: 'textCenter',
      text: opts.emptyText ?? DEFAULTS.emptyText,
      x: opts.layout.cssWidth / 2,
      y: opts.layout.cssHeight / 2,
      color: opts.emptyTextColor ?? DEFAULTS.emptyTextColor,
      font: opts.emptyTextFont ?? DEFAULTS.emptyTextFont,
    });
    return cmds;
  }

  const cellSize = opts.layout.cellSize;
  for (let i = 0; i < opts.shares.length; i++) {
    const share = opts.shares[i];
    if (share === undefined) continue;
    const pos = cellPosition(opts.layout, i);
    if (pos === null) continue;
    const color = getColor(share, opts.userContext, palette);
    cmds.push({ op: 'fillCell', x: pos.x, y: pos.y, w: cellSize, h: cellSize, color });
  }

  if (opts.hoveredIndex !== undefined && opts.hoveredIndex >= 0) {
    const pos = cellPosition(opts.layout, opts.hoveredIndex);
    if (pos !== null) {
      const w = opts.hoverOutlineWidth ?? DEFAULTS.hoverOutlineWidth;
      cmds.push({
        op: 'strokeRect',
        x: pos.x + w / 2,
        y: pos.y + w / 2,
        w: cellSize - w,
        h: cellSize - w,
        color: opts.hoverOutlineColor ?? DEFAULTS.hoverOutlineColor,
        lineWidth: w,
      });
    }
  }

  return cmds;
}

/** Subset of CanvasRenderingContext2D our commands use. Allows
 *  injecting a mock in tests (Node has no Canvas by default). */
export interface CanvasLike {
  setTransform(a: number, b: number, c: number, d: number, e: number, f: number): void;
  fillStyle: string;
  strokeStyle: string;
  lineWidth: number;
  font: string;
  textAlign: CanvasTextAlign;
  textBaseline: CanvasTextBaseline;
  fillRect(x: number, y: number, w: number, h: number): void;
  strokeRect(x: number, y: number, w: number, h: number): void;
  fillText(text: string, x: number, y: number): void;
}

/** Execute a paint program against a canvas context. */
export function executePaintProgram(
  ctx: CanvasLike,
  program: readonly PaintCommand[],
): void {
  for (const cmd of program) {
    switch (cmd.op) {
      case 'setTransform':
        ctx.setTransform(cmd.dpr, 0, 0, cmd.dpr, 0, 0);
        break;
      case 'fillBackground':
        ctx.fillStyle = cmd.color;
        ctx.fillRect(0, 0, cmd.w, cmd.h);
        break;
      case 'fillCell':
        ctx.fillStyle = cmd.color;
        ctx.fillRect(cmd.x, cmd.y, cmd.w, cmd.h);
        break;
      case 'strokeRect':
        ctx.strokeStyle = cmd.color;
        ctx.lineWidth = cmd.lineWidth;
        ctx.strokeRect(cmd.x, cmd.y, cmd.w, cmd.h);
        break;
      case 'textCenter':
        ctx.fillStyle = cmd.color;
        ctx.font = cmd.font;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(cmd.text, cmd.x, cmd.y);
        break;
    }
  }
}

// ── Canvas adapter (DOM-touching) ────────────────────────────────────

export interface GridRenderer {
  /** Paint a frame. Also resizes the canvas element per the layout. */
  paint(opts: Omit<BuildPaintOptions, 'dpr'> & { dpr?: number }): void;
  /** Return the commands that would be issued (for testing / pixel diff). */
  buildProgram(opts: Omit<BuildPaintOptions, 'dpr'> & { dpr?: number }): PaintCommand[];
  destroy(): void;
}

/** Create a GridRenderer bound to a canvas element. Used by the
 *  Explorer runtime; tests should use buildPaintProgram directly. */
export function createGridRenderer(canvas: HTMLCanvasElement): GridRenderer {
  const ctx2d = canvas.getContext('2d') as CanvasRenderingContext2D | null;
  if (ctx2d === null) {
    throw new Error('createGridRenderer: canvas.getContext("2d") returned null');
  }
  // CanvasRenderingContext2D.fillStyle is string | CanvasGradient | CanvasPattern;
  // our commands only assign/read strings, so the narrower CanvasLike is safe.
  const ctx = ctx2d as unknown as CanvasLike;
  let destroyed = false;

  const sizeCanvas = (layout: GridLayout, dpr: number) => {
    canvas.style.width = `${layout.cssWidth}px`;
    canvas.style.height = `${layout.cssHeight}px`;
    canvas.width = Math.round(layout.cssWidth * dpr);
    canvas.height = Math.round(layout.cssHeight * dpr);
  };

  return {
    paint(opts) {
      if (destroyed) return;
      const dpr = opts.dpr ?? window.devicePixelRatio ?? 1;
      sizeCanvas(opts.layout, dpr);
      const program = buildPaintProgram({ ...opts, dpr });
      executePaintProgram(ctx, program);
    },
    buildProgram(opts) {
      const dpr = opts.dpr ?? window.devicePixelRatio ?? 1;
      return buildPaintProgram({ ...opts, dpr });
    },
    destroy() {
      destroyed = true;
    },
  };
}

export const GridCanvasPlugin: PluginDescriptor = {
  id: 'explorer.grid.canvas',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'renderer',
  provides: ['renderer.grid.canvas'],
  slots: ['explorer.main.grid'],
  priority: 0,
  capabilities: {
    'renderer.grid.canvas': { buildPaintProgram, executePaintProgram, createGridRenderer },
  },
};
