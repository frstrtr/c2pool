// Canvas2D backend — always available (Qt WebEngine has no WebGPU and
// no software GL), and the fallback any GPU backend swaps back to.

import { lerp, progress } from './easing.js';
import { alpha, blue, green, red, toCss } from './colour.js';
import {
  RECORD_WORDS,
  W_DUR, W_FLAGS, W_FROM_H, W_FROM_RGBA, W_FROM_W, W_FROM_X, W_FROM_Y,
  W_T0, W_TO_H, W_TO_RGBA, W_TO_W, W_TO_X, W_TO_Y,
  type DirtyRange, type InstanceBuffer,
} from './instance-buffer.js';
import {
  DIM_ALPHA, FLAG_DIM, FLAG_MATCH, FLAG_PINNED, FLAG_SELECTED,
  type Renderer, type TextOverlay,
} from './renderer.js';
import type { Label } from './types.js';

/** The subset of CanvasRenderingContext2D the backend uses (tests pass
 *  a recording fake). */
export interface Ctx2D {
  fillStyle: string;
  strokeStyle: string;
  lineWidth: number;
  font: string;
  textAlign: string;
  textBaseline: string;
  setTransform(a: number, b: number, c: number, d: number, e: number, f: number): void;
  fillRect(x: number, y: number, w: number, h: number): void;
  clearRect(x: number, y: number, w: number, h: number): void;
  strokeRect(x: number, y: number, w: number, h: number): void;
  fillText(text: string, x: number, y: number): void;
  save(): void;
  restore(): void;
  beginPath(): void;
  rect(x: number, y: number, w: number, h: number): void;
  clip(): void;
}

interface SizedCanvas {
  width: number;
  height: number;
  style: { width: string; height: string };
  getContext(id: '2d'): unknown;
}

export interface Canvas2DOptions {
  /** Packed RGBA8 background; alpha 0 clears to transparent. */
  background?: number;
}

const OUTLINE_SELECTED = 'rgba(255,255,255,0.85)';
const OUTLINE_PINNED = '#ffffff';
const OUTLINE_MATCH = '#ffc531';

/** Size a canvas's backing store, touching it only when it changes
 *  (assigning width/height reallocates and clears it). */
function sizeCanvas(canvas: SizedCanvas, cssW: number, cssH: number, dpr: number): void {
  const bw = Math.max(1, Math.round(cssW * dpr));
  const bh = Math.max(1, Math.round(cssH * dpr));
  if (canvas.width !== bw) canvas.width = bw;
  if (canvas.height !== bh) canvas.height = bh;
  const sw = `${cssW}px`, sh = `${cssH}px`;
  if (canvas.style.width !== sw) canvas.style.width = sw;
  if (canvas.style.height !== sh) canvas.style.height = sh;
}

export function createCanvas2DRenderer(opts: Canvas2DOptions = {}): Renderer {
  let canvas: SizedCanvas | null = null;
  let ctx: Ctx2D | null = null;
  let buffer: InstanceBuffer | null = null;
  let cssW = 0, cssH = 0, dpr = 1;
  const bg = opts.background ?? 0;
  const bgCss = alpha(bg) > 0 ? toCss(bg) : null;

  return {
    kind: 'canvas2d',
    init(c) {
      canvas = c as unknown as SizedCanvas;
      const got = canvas.getContext('2d') as Ctx2D | null;
      if (got === null) throw new Error('canvas2d renderer: 2D context unavailable');
      ctx = got;
    },
    resize(w, h, ratio) {
      cssW = w; cssH = h; dpr = ratio;
      if (canvas !== null) sizeCanvas(canvas, w, h, ratio);
    },
    upload(buf: InstanceBuffer, _dirty: readonly DirtyRange[]) {
      // The CPU backend reads the shared buffer directly at draw time.
      buffer = buf;
    },
    draw(now) {
      if (ctx === null) return;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      if (bgCss !== null) {
        ctx.fillStyle = bgCss;
        ctx.fillRect(0, 0, cssW, cssH);
      } else {
        ctx.clearRect(0, 0, cssW, cssH);
      }
      if (buffer === null) return;
      const f = buffer.f32, u = buffer.u32;
      for (let i = 0; i < buffer.count; i++) {
        const o = i * RECORD_WORDS;
        const c0 = u[o + W_FROM_RGBA]!, c1 = u[o + W_TO_RGBA]!;
        if ((c0 >>> 24) === 0 && (c1 >>> 24) === 0) continue;
        const t = progress(now, f[o + W_T0]!, f[o + W_DUR]!);
        const x = lerp(f[o + W_FROM_X]!, f[o + W_TO_X]!, t);
        const y = lerp(f[o + W_FROM_Y]!, f[o + W_TO_Y]!, t);
        const w = lerp(f[o + W_FROM_W]!, f[o + W_TO_W]!, t);
        const h = lerp(f[o + W_FROM_H]!, f[o + W_TO_H]!, t);
        if (!(w > 0) || !(h > 0)) continue;
        const flags = u[o + W_FLAGS]!;
        const a = lerp(alpha(c0), alpha(c1), t) / 255 * ((flags & FLAG_DIM) !== 0 ? DIM_ALPHA : 1);
        if (!(a > 0)) continue;
        ctx.fillStyle = `rgba(${Math.round(lerp(red(c0), red(c1), t))},${Math.round(lerp(green(c0), green(c1), t))},`
          + `${Math.round(lerp(blue(c0), blue(c1), t))},${+a.toFixed(3)})`;
        ctx.fillRect(x, y, w, h);
        if ((flags & (FLAG_PINNED | FLAG_SELECTED | FLAG_MATCH)) !== 0) {
          const lw = (flags & FLAG_PINNED) !== 0 ? 3 : 1.5;
          ctx.strokeStyle = (flags & FLAG_PINNED) !== 0 ? OUTLINE_PINNED
            : (flags & FLAG_MATCH) !== 0 ? OUTLINE_MATCH : OUTLINE_SELECTED;
          ctx.lineWidth = lw;
          ctx.strokeRect(x + lw / 2, y + lw / 2, Math.max(0, w - lw), Math.max(0, h - lw));
        }
      }
    },
    onContextLost() { /* a 2D context is never lost */ },
    dispose() {
      ctx = null;
      canvas = null;
      buffer = null;
    },
  };
}

/** Labels on a 2D context: the scene canvas itself (Canvas2D renderer)
 *  or, with a GPU renderer, a canvas stacked above it. */
export function createCanvas2DTextOverlay(canvas: HTMLCanvasElement, opts: { ownsCanvas?: boolean } = {}): TextOverlay {
  const target = canvas as unknown as SizedCanvas;
  const got = target.getContext('2d') as Ctx2D | null;
  if (got === null) throw new Error('text overlay: 2D context unavailable');
  let ctx: Ctx2D | null = got;
  let cssW = 0, cssH = 0, dpr = 1;
  return {
    resize(w, h, ratio) {
      cssW = w; cssH = h; dpr = ratio;
      if (opts.ownsCanvas === true) sizeCanvas(target, w, h, ratio);
    },
    draw(labels: readonly Label[]) {
      if (ctx === null) return;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      if (opts.ownsCanvas === true) ctx.clearRect(0, 0, cssW, cssH);
      for (const l of labels) {
        if (l.clip !== undefined) {
          ctx.save();
          ctx.beginPath();
          ctx.rect(l.clip.x, l.clip.y, l.clip.w, l.clip.h);
          ctx.clip();
        }
        ctx.fillStyle = l.color;
        ctx.font = l.font;
        ctx.textAlign = l.align ?? 'center';
        ctx.textBaseline = l.baseline ?? 'middle';
        ctx.fillText(l.text, l.x, l.y);
        if (l.clip !== undefined) ctx.restore();
      }
    },
    dispose() { ctx = null; },
  };
}
