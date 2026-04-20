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
  | { op: 'textCenter'; text: string; x: number; y: number; color: string; font: string }
  | { op: 'textRight';  text: string; x: number; y: number; color: string; font: string }
  | { op: 'strokeLine'; x1: number; y1: number; x2: number; y2: number; color: string; lineWidth: number }
  | { op: 'fillTriangle'; x1: number; y1: number; x2: number; y2: number; x3: number; y3: number; color: string };

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
  beginPath(): void;
  moveTo(x: number, y: number): void;
  lineTo(x: number, y: number): void;
  closePath(): void;
  fill(): void;
  stroke(): void;
}

/** Build a paint program from an animator frame. Each CellFrame's
 *  `size` field is used directly so scale/transform effects carry
 *  through without the cell-size-based maths buildPaintProgram does
 *  for static frames. Cells with alpha ≤ 0 are skipped.
 *
 *  Paint order (z-ascending):
 *    1. setTransform + background
 *    2. cells (grid + born land + dying rise)
 *    3. particles (ash + coalesce)
 *    4. card overlays (dying HOLD + born HOLD) — drawn last, on top
 *       of everything, matching dashboard.html ordering. */
export function buildAnimatedPaintProgram(
  frame: import('./animator.js').FrameSpec,
  dpr: number,
): PaintCommand[] {
  const cmds: PaintCommand[] = [];
  cmds.push({ op: 'setTransform', dpr });
  cmds.push({
    op: 'fillBackground',
    w: frame.layout.cssWidth,
    h: frame.layout.cssHeight,
    color: frame.backgroundColor,
  });
  for (const cell of frame.cells) {
    if (cell.alpha <= 0) continue;
    cmds.push({
      op: 'fillCell',
      x: cell.x,
      y: cell.y,
      w: cell.size,
      h: cell.size,
      color: cell.color,
    });
    // Block-border stroke (dashboard.html:4759-4775). Inset by 0.5 on
    // each axis + shrink by 1 matches the reference
    // `strokeRect(x+0.5, y+0.5, cs-1, cs-1)`.
    if (cell.stroke !== undefined) {
      cmds.push({
        op: 'strokeRect',
        x: cell.x + 0.5,
        y: cell.y + 0.5,
        w: cell.size - 1,
        h: cell.size - 1,
        color: cell.stroke.color,
        lineWidth: cell.stroke.lineWidth,
      });
    }
    // Tip-marker triangle (dashboard.html:4778-4787) — top-left
    // corner, 4×4 right-triangle, white fill.
    if (cell.tipMark === true) {
      cmds.push({
        op: 'fillTriangle',
        x1: cell.x,         y1: cell.y,
        x2: cell.x + 4,     y2: cell.y,
        x3: cell.x,         y3: cell.y + 4,
        color: '#ffffff',
      });
    }
  }
  // Hour-axis tick lines — rendered on top of cells but below labels.
  for (const line of frame.axisLines) {
    cmds.push({
      op: 'strokeLine',
      x1: line.x1, y1: line.y1,
      x2: line.x2, y2: line.y2,
      color: line.color,
      lineWidth: line.lineWidth,
    });
  }
  // Hour-axis labels in the left margin.
  for (const label of frame.axisLabels) {
    cmds.push({
      op: 'textRight',
      text: label.text,
      x: label.x,
      y: label.y,
      color: label.color,
      font: label.font,
    });
  }
  // Particles render as small fillCell commands. Their colour already
  // includes the alpha channel (rgba(...)).
  for (const p of frame.particles) {
    if (p.size <= 0) continue;
    cmds.push({
      op: 'fillCell',
      x: p.x,
      y: p.y,
      w: p.size,
      h: p.size,
      color: p.color,
    });
  }
  // Card overlays: shadow → glow → fill → inner highlight → text (with
  // shadow pass first for legibility). Matches reference dashboard.html
  // sequence for both dying (:5301-5327) and born (:5089-5112) cards.
  for (const card of frame.cards) {
    const half = card.size / 2;
    // Shadow — offset +6 +6, slightly larger (+4 +4).
    cmds.push({
      op: 'fillCell',
      x: card.cx - half + 6,
      y: card.cy - half + 6,
      w: card.size + 4,
      h: card.size + 4,
      color: card.shadowColor,
    });
    // Glow — extends −4 / +8.
    cmds.push({
      op: 'fillCell',
      x: card.cx - half - 4,
      y: card.cy - half - 4,
      w: card.size + 8,
      h: card.size + 8,
      color: card.glowColor,
    });
    // Solid fill.
    cmds.push({
      op: 'fillCell',
      x: card.cx - half,
      y: card.cy - half,
      w: card.size,
      h: card.size,
      color: card.fillColor,
    });
    // Inner highlight — inset by 3px.
    cmds.push({
      op: 'fillCell',
      x: card.cx - half + 3,
      y: card.cy - half + 3,
      w: card.size - 6,
      h: card.size - 6,
      color: card.innerHighlight,
    });
    // Address text with shadow.
    const addrFont = `bold ${card.fontSize}px Monaco,Consolas,monospace`;
    cmds.push({
      op: 'textCenter',
      text: card.addrText,
      x: card.cx + 1,
      y: card.cy - card.fontSize * 0.8 + 1,
      color: 'rgba(0,0,0,0.8)',
      font: addrFont,
    });
    cmds.push({
      op: 'textCenter',
      text: card.addrText,
      x: card.cx,
      y: card.cy - card.fontSize * 0.8,
      color: card.addrColor,
      font: addrFont,
    });
    // PCT text (slightly larger) with shadow.
    const pctFont = `bold ${card.fontSize + 2}px Monaco,Consolas,monospace`;
    cmds.push({
      op: 'textCenter',
      text: card.pctText,
      x: card.cx + 1,
      y: card.cy + card.fontSize * 0.8 + 1,
      color: 'rgba(0,0,0,0.8)',
      font: pctFont,
    });
    cmds.push({
      op: 'textCenter',
      text: card.pctText,
      x: card.cx,
      y: card.cy + card.fontSize * 0.8,
      color: card.pctColor,
      font: pctFont,
    });
  }
  return cmds;
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
      case 'textRight':
        ctx.fillStyle = cmd.color;
        ctx.font = cmd.font;
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        ctx.fillText(cmd.text, cmd.x, cmd.y);
        break;
      case 'strokeLine':
        ctx.strokeStyle = cmd.color;
        ctx.lineWidth = cmd.lineWidth;
        ctx.beginPath();
        ctx.moveTo(cmd.x1, cmd.y1);
        ctx.lineTo(cmd.x2, cmd.y2);
        ctx.stroke();
        break;
      case 'fillTriangle':
        ctx.fillStyle = cmd.color;
        ctx.beginPath();
        ctx.moveTo(cmd.x1, cmd.y1);
        ctx.lineTo(cmd.x2, cmd.y2);
        ctx.lineTo(cmd.x3, cmd.y3);
        ctx.closePath();
        ctx.fill();
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
