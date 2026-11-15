// Scene engine: layout-agnostic, keyed, animated tiles.
//
//   view items ──layout(items, viewport)──▶ tiles ──style(tile)──▶ records
//                                                   (instance buffer)
//                                                          │
//                                    renderer.draw(now) ◀──┘  + text overlay
//
// - Keyed tweens: a tile that keeps its key moves from where it is drawn
//   now to its new rect/colour over `duration` ms (smootherstep). New
//   keys grow and fade in from their centre; vanished keys shrink and
//   fade out, then free their slot.
// - Retargeting: a new target mid-flight starts from the interpolated
//   current state, so motion never jumps.
// - Merged updates: setItems() during a tween is held (latest wins) and
//   applied when the tween ends: at most one data update per animation.
// - Idle-stop: requestAnimationFrame runs only while something moves or
//   a redraw was requested.
// - Hit-testing runs on the CPU through the active layout, on tiles
//   placed with the same easing the renderer uses, at the instant of the
//   last drawn frame.
// - setLayout() is a keyed transition: the same keys tween from the old
//   layout's rects to the new one's (LOD changes, layout swaps).
//
// Surfaces: the engine draws into a CONTAINER element. Every renderer
// gets a fresh canvas of its own (a canvas that once held a WebGL/WebGPU
// context can never give a 2D one), and the text overlay has its own
// canvas stacked on top (pointer-events: none). Hosts bind pointer events
// to the container, so they survive a renderer swap. The engine always
// boots on Canvas2D; a requested renderer replaces it when (and only if)
// its init resolves, and a context loss swaps a fresh Canvas2D surface
// back in.

import { lerp, progress } from './easing.js';
import { alpha, lerpRgba, withAlpha } from './colour.js';
import {
  InstanceBuffer, RECORD_WORDS,
  W_DUR, W_FLAGS, W_FROM_H, W_FROM_RGBA, W_FROM_W, W_FROM_X, W_FROM_Y,
  W_T0, W_TO_H, W_TO_RGBA, W_TO_W, W_TO_X, W_TO_Y,
  type RecordState,
} from './instance-buffer.js';
import { createCanvas2DRenderer, createCanvas2DTextOverlay } from './canvas2d.js';
import type { Renderer, TextOverlay } from './renderer.js';
import type { Label, Layout, PlacedTile, Rect, SceneItem, Tile, TileStyle } from './types.js';

export interface FrameScheduler {
  request(cb: () => void): number;
  cancel(id: number): void;
}

/** The DOM the engine needs from its container (tests pass a fake). */
interface SurfaceHost {
  appendChild(node: unknown): unknown;
  insertBefore(node: unknown, ref: unknown): unknown;
  removeChild(node: unknown): unknown;
}

export interface SceneOptions<D = unknown> {
  /** Element the engine draws into (give it position: relative and a
   *  size). The engine adds its canvases as children. */
  container: HTMLElement;
  layout: Layout<D>;
  /** Colour and flags of a tile, given the view's current state. */
  style: (tile: Tile<D>) => TileStyle;
  /** Labels for the tiles as placed this frame (text overlay pass). */
  labels?: (tiles: readonly PlacedTile<D>[]) => Label[];
  /** Preferred renderer (e.g. a GPU backend). The engine boots on
   *  Canvas2D and switches when this one's init resolves; if init throws
   *  or rejects it stays on Canvas2D. Default: Canvas2D only. */
  renderer?: Renderer;
  /** Replacement after a context loss. Default: a Canvas2D renderer. */
  fallbackRenderer?: () => Renderer;
  /** Default: a Canvas2D overlay on its own stacked canvas; null
   *  disables labels. */
  overlay?: TextOverlay | null;
  /** Fresh canvas for a renderer or the overlay. Default:
   *  document.createElement('canvas'), absolutely positioned at 0,0. */
  createSurface?: (role: 'renderer' | 'overlay') => HTMLCanvasElement;
  /** Tween length in ms. Default 500. */
  duration?: number;
  /** Packed RGBA8 background (Canvas2D renderers). */
  background?: number;
  /** Clock in ms. Default performance.now. */
  clock?: () => number;
  /** Default: window.requestAnimationFrame. */
  scheduler?: FrameScheduler;
  devicePixelRatio?: () => number;
  /** Renderer failures. Default: console.error. */
  onError?: (err: unknown) => void;
  /** Contract warnings (once each). Default: console.warn. */
  onWarn?: (msg: string) => void;
}

export interface Scene<D = unknown> {
  /** New data. Held while a tween runs unless `immediate`. */
  setItems(items: readonly SceneItem<D>[], opts?: { immediate?: boolean }): void;
  /** Swap the layout; tiles tween to their rects in the new one. */
  setLayout(layout: Layout<D>): void;
  /** Re-run style() for every tile (selection, search, filter changed). */
  restyle(): void;
  /** New viewport in CSS px; tiles snap (no tween). */
  resize(cssWidth: number, cssHeight: number): void;
  /** Topmost live tile at (x, y) in CSS px of the container, as drawn in
   *  the last frame. */
  hitTest(x: number, y: number): PlacedTile<D> | null;
  /** Live tiles (not leaving) as drawn in the last frame. */
  placed(): readonly PlacedTile<D>[];
  isAnimating(): boolean;
  /** Request one redraw. */
  invalidate(): void;
  /** Move to `next` on a fresh surface once its init resolves. Rejects,
   *  keeping the current renderer, if init fails. */
  swapRenderer(next: Renderer): Promise<void>;
  readonly renderer: Renderer;
  readonly buffer: InstanceBuffer;
  destroy(): void;
}

interface Entry<D> {
  slot: number;
  tile: Tile<D>;
  exiting: boolean;
  removeAt: number;
}

/** Rebase the f32 time origin when idle after this long, keeping t0 well
 *  within f32 precision on pages left open for days. */
const EPOCH_REBASE_MS = 3_600_000;

function defaultScheduler(): FrameScheduler {
  return {
    request: (cb) => window.requestAnimationFrame(() => cb()),
    cancel: (id) => window.cancelAnimationFrame(id),
  };
}

function defaultSurface(role: 'renderer' | 'overlay'): HTMLCanvasElement {
  const c = document.createElement('canvas');
  c.style.position = 'absolute';
  c.style.left = '0';
  c.style.top = '0';
  c.style.display = 'block';
  if (role === 'overlay') c.style.pointerEvents = 'none';
  return c;
}

export function createScene<D = unknown>(opts: SceneOptions<D>): Scene<D> {
  const clock = opts.clock ?? (() => performance.now());
  const scheduler = opts.scheduler ?? defaultScheduler();
  const dprOf = opts.devicePixelRatio ?? (() => (typeof window !== 'undefined' && window.devicePixelRatio) || 1);
  const duration = Math.max(0, opts.duration ?? 500);
  const reportError = opts.onError ?? ((e: unknown) => console.error('[scene]', e));
  const warned = new Set<string>();
  const warnOnce = (id: string, msg: string): void => {
    if (warned.has(id)) return;
    warned.add(id);
    (opts.onWarn ?? ((m: string) => console.warn('[scene]', m)))(msg);
  };
  const createSurface = opts.createSurface ?? defaultSurface;
  const host = opts.container as unknown as SurfaceHost;
  const canvas2d = (): Renderer => createCanvas2DRenderer(
    opts.background !== undefined ? { background: opts.background } : {});

  const buffer = new InstanceBuffer();
  const entries = new Map<string, Entry<D>>();

  let layout = opts.layout;
  let renderer: Renderer | null = null;
  let surface: HTMLCanvasElement | null = null;
  let overlay: TextOverlay | null = null;
  let overlaySurface: HTMLCanvasElement | null = null;
  let epoch = clock();
  let items: readonly SceneItem<D>[] = [];
  let pending: readonly SceneItem<D>[] | null = null;
  let viewport: Rect = { x: 0, y: 0, w: 0, h: 0 };
  let animEnd = -Infinity;      // engine time when the last tween ends
  let raf: number | null = null;
  let destroyed = false;
  let uploadedGeneration = -1;
  let lastFrameT: number | null = null;
  /** Settled placement, reused by hitTest/placed while idle. */
  let placedCache: PlacedTile<D>[] | null = null;
  /** Bumps on every renderer switch, so a stale async init is dropped. */
  let switches = 0;

  const now = (): number => clock() - epoch;

  const schedule = (): void => {
    if (destroyed || raf !== null) return;
    raf = scheduler.request(frame);
  };

  const fallback = (): void => {
    const next = opts.fallbackRenderer ? opts.fallbackRenderer() : canvas2d();
    swapRenderer(next).catch((e) => reportError(e));
  };

  /** Put `next` (already initialised on `s`) on screen in place of the
   *  current renderer and its surface. */
  const install = (next: Renderer, s: HTMLCanvasElement): void => {
    const old = renderer;
    const oldSurface = surface;
    host.insertBefore(s, overlaySurface);
    renderer = next;
    surface = s;
    next.onContextLost(fallback);
    next.resize(viewport.w, viewport.h, dprOf());
    buffer.markAllDirty();
    uploadedGeneration = -1;
    switches++;
    if (old !== null && old !== next) old.dispose();
    if (oldSurface !== null && oldSurface !== s) host.removeChild(oldSurface);
    schedule();
  };

  async function swapRenderer(next: Renderer): Promise<void> {
    if (destroyed) return;
    const at = switches;
    const s = createSurface('renderer');
    try {
      await next.init(s);
    } catch (e) {
      next.dispose();
      throw e;
    }
    // Destroyed meanwhile, or another switch (e.g. a context-loss
    // fallback) happened first: keep what is on screen.
    if (destroyed || at !== switches) { next.dispose(); return; }
    install(next, s);
  }

  // Overlay first: its own stacked canvas, so it never shares a surface
  // with a GPU context and does not move when the renderer is swapped.
  if (opts.overlay === undefined) {
    overlaySurface = createSurface('overlay');
    host.appendChild(overlaySurface);
    overlay = createCanvas2DTextOverlay(overlaySurface, { ownsCanvas: true });
  } else {
    overlay = opts.overlay;
  }

  // ── tween bookkeeping ───────────────────────────────────────────

  /** Current interpolated state of a record at engine time t. */
  const current = (slot: number, t: number): { rect: Rect; color: number; settled: boolean; rec: RecordState } => {
    const rec = buffer.read(slot);
    const p = progress(t, rec.t0, rec.dur);
    return {
      rect: {
        x: lerp(rec.fromX, rec.toX, p), y: lerp(rec.fromY, rec.toY, p),
        w: lerp(rec.fromW, rec.toW, p), h: lerp(rec.fromH, rec.toH, p),
      },
      color: lerpRgba(rec.fromRgba, rec.toRgba, p),
      settled: p >= 1,
      rec,
    };
  };

  const collapsed = (r: Rect): Rect => ({ x: r.x + r.w / 2, y: r.y + r.h / 2, w: 0, h: 0 });

  const writeTween = (slot: number, from: Rect, fromRgba: number, to: Rect, toRgba: number,
    t0: number, dur: number, flags: number): void => {
    buffer.write(slot, {
      fromX: from.x, fromY: from.y, fromW: from.w, fromH: from.h,
      toX: to.x, toY: to.y, toW: to.w, toH: to.h,
      fromRgba, toRgba, t0, dur, flags,
    });
    if (dur > 0 && t0 + dur > animEnd) animEnd = t0 + dur;
  };

  const sameRect = (a: Rect, b: { toX: number; toY: number; toW: number; toH: number }): boolean =>
    Math.fround(a.x) === b.toX && Math.fround(a.y) === b.toY
    && Math.fround(a.w) === b.toW && Math.fround(a.h) === b.toH;

  const maybeRebaseEpoch = (): void => {
    const t = now();
    if (t < EPOCH_REBASE_MS || t < animEnd) return;
    // Idle: every record is settled, so fold it to from = to, t0 = 0.
    // Leaving tiles are done (their removeAt is on the old epoch).
    for (const [key, e] of entries) {
      if (e.exiting) {
        buffer.release(e.slot);
        entries.delete(key);
        continue;
      }
      const rec = buffer.read(e.slot);
      buffer.write(e.slot, {
        ...rec,
        fromX: rec.toX, fromY: rec.toY, fromW: rec.toW, fromH: rec.toH,
        fromRgba: rec.toRgba, t0: 0, dur: 0,
      });
    }
    epoch += t;
    animEnd = -Infinity;
    lastFrameT = null;
  };

  /** Lay out `next` and retarget every record. dur 0 snaps. */
  const apply = (next: readonly SceneItem<D>[], dur: number): void => {
    maybeRebaseEpoch();
    placedCache = null;
    items = next;
    const t = now();
    const tiles = layout.layout(items, viewport);
    const seen = new Set<string>();
    for (const tile of tiles) {
      if (seen.has(tile.key)) {
        warnOnce(`dup:${layout.id}`,
          `layout '${layout.id}' returned duplicate key '${tile.key}' (and maybe others); keeping the first of each`);
        continue;
      }
      seen.add(tile.key);
      const style = opts.style(tile);
      const e = entries.get(tile.key);
      if (e === undefined) {
        const slot = buffer.alloc();
        const start = dur > 0 ? collapsed(tile) : tile;
        writeTween(slot, start, dur > 0 ? withAlpha(style.color, 0) : style.color, tile, style.color, t, dur, style.flags);
        entries.set(tile.key, { slot, tile, exiting: false, removeAt: Infinity });
        continue;
      }
      const cur = current(e.slot, t);
      e.tile = tile;
      e.exiting = false;
      e.removeAt = Infinity;
      if (cur.settled && sameRect(tile, cur.rec) && cur.rec.toRgba === style.color >>> 0) {
        if (cur.rec.flags !== style.flags >>> 0) buffer.write(e.slot, { ...cur.rec, flags: style.flags });
        continue;
      }
      writeTween(e.slot, cur.rect, cur.color, tile, style.color, t, dur, style.flags);
    }
    for (const [key, e] of entries) {
      if (seen.has(key)) continue;
      if (dur <= 0) {  // a snap drops leaving tiles too
        buffer.release(e.slot);
        entries.delete(key);
        continue;
      }
      if (e.exiting) continue;
      const cur = current(e.slot, t);
      writeTween(e.slot, cur.rect, cur.color, collapsed(cur.rect), withAlpha(cur.color, 0), t, dur, cur.rec.flags);
      e.exiting = true;
      e.removeAt = t + dur;
    }
    schedule();
  };

  /** Live tiles placed at engine time t, read straight from the buffer. */
  const placedAt = (t: number): PlacedTile<D>[] => {
    const out: PlacedTile<D>[] = [];
    const f = buffer.f32, u = buffer.u32;
    for (const e of entries.values()) {
      if (e.exiting) continue;
      const o = e.slot * RECORD_WORDS;
      const p = progress(t, f[o + W_T0]!, f[o + W_DUR]!);
      out.push({
        ...e.tile,
        x: lerp(f[o + W_FROM_X]!, f[o + W_TO_X]!, p),
        y: lerp(f[o + W_FROM_Y]!, f[o + W_TO_Y]!, p),
        w: lerp(f[o + W_FROM_W]!, f[o + W_TO_W]!, p),
        h: lerp(f[o + W_FROM_H]!, f[o + W_TO_H]!, p),
        color: lerpRgba(u[o + W_FROM_RGBA]!, u[o + W_TO_RGBA]!, p),
        flags: u[o + W_FLAGS]!,
        exiting: false,
      });
    }
    return out;
  };

  /** Placement as on screen: at the last drawn frame while animating,
   *  at now when idle (identical then, and cached until a change). */
  const currentPlacement = (): PlacedTile<D>[] => {
    const t = now();
    if (t < animEnd) return placedAt(lastFrameT ?? t);
    if (placedCache === null) placedCache = placedAt(t);
    return placedCache;
  };

  function frame(): void {
    raf = null;
    if (destroyed || renderer === null) return;
    let t = now();
    for (const [key, e] of entries) {
      if (e.exiting && t >= e.removeAt) {
        buffer.release(e.slot);
        entries.delete(key);
      }
    }
    if (pending !== null && t >= animEnd) {
      const next = pending;
      pending = null;
      apply(next, duration);
      t = now();
    }
    if (buffer.generation !== uploadedGeneration) {
      buffer.markAllDirty();
      uploadedGeneration = buffer.generation;
    }
    renderer.upload(buffer, buffer.takeDirty());
    renderer.draw(t);
    lastFrameT = t;
    if (overlay !== null) {
      if (t >= animEnd) placedCache = null;  // settle: recompute once
      overlay.draw(opts.labels ? opts.labels(t < animEnd ? placedAt(t) : currentPlacement()) : []);
    }
    if (t < animEnd || pending !== null) schedule();
  }

  // Boot on Canvas2D (synchronous, always available), then try the
  // requested renderer in the background.
  {
    const boot = canvas2d();
    const s = createSurface('renderer');
    boot.init(s);
    install(boot, s);
    const el = opts.container as unknown as { clientWidth?: number; clientHeight?: number };
    const w = el.clientWidth ?? 0, h = el.clientHeight ?? 0;
    if (w > 0 && h > 0) {
      viewport = { x: 0, y: 0, w, h };
      boot.resize(w, h, dprOf());
      overlay?.resize(w, h, dprOf());
    }
    if (opts.renderer !== undefined) {
      swapRenderer(opts.renderer).catch((e) => reportError(e));
    }
  }

  const defaultHit = (tiles: readonly PlacedTile<D>[], x: number, y: number): PlacedTile<D> | null => {
    for (let i = tiles.length - 1; i >= 0; i--) {
      const r = tiles[i]!;
      if (x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h) return r;
    }
    return null;
  };

  return {
    setItems(next, o) {
      if (destroyed) return;
      if (o?.immediate !== true && now() < animEnd) {
        pending = next;
        schedule();
        return;
      }
      pending = null;
      apply(next, duration);
    },
    setLayout(next) {
      if (destroyed) return;
      layout = next;
      apply(pending ?? items, duration);
      pending = null;
    },
    restyle() {
      if (destroyed) return;
      placedCache = null;
      for (const e of entries.values()) {
        if (e.exiting) continue;
        const style = opts.style(e.tile);
        const rec = buffer.read(e.slot);
        if (rec.toRgba === style.color >>> 0 && rec.flags === style.flags >>> 0) continue;
        // Colour and flags change at once; any motion in flight goes on,
        // and so does an alpha ramp (a tile still fading in keeps fading).
        buffer.write(e.slot, {
          ...rec,
          fromRgba: withAlpha(style.color, Math.min(alpha(rec.fromRgba), alpha(style.color))),
          toRgba: style.color,
          flags: style.flags,
        });
      }
      schedule();
    },
    resize(w, h) {
      if (destroyed) return;
      viewport = { x: 0, y: 0, w: Math.max(0, w), h: Math.max(0, h) };
      const dpr = dprOf();
      renderer?.resize(viewport.w, viewport.h, dpr);
      overlay?.resize(viewport.w, viewport.h, dpr);
      apply(pending ?? items, 0);
      pending = null;
    },
    hitTest(x, y) {
      const tiles = currentPlacement();
      return layout.hitTest ? layout.hitTest(tiles, x, y) : defaultHit(tiles, x, y);
    },
    placed: () => currentPlacement(),
    isAnimating: () => now() < animEnd,
    invalidate: schedule,
    swapRenderer,
    get renderer() { return renderer!; },
    buffer,
    destroy() {
      if (destroyed) return;
      destroyed = true;
      if (raf !== null) scheduler.cancel(raf);
      raf = null;
      renderer?.dispose();
      overlay?.dispose();
      if (surface !== null) host.removeChild(surface);
      if (overlaySurface !== null) host.removeChild(overlaySurface);
      entries.clear();
      placedCache = null;
    },
  };
}
