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
//   placed with the same easing the renderer uses.
// - setLayout() is a keyed transition: the same keys tween from the old
//   layout's rects to the new one's (LOD changes, layout swaps).

import { lerp, progress } from './easing.js';
import { alpha, lerpRgba, withAlpha } from './colour.js';
import { InstanceBuffer, type RecordState } from './instance-buffer.js';
import { createCanvas2DRenderer, createCanvas2DTextOverlay } from './canvas2d.js';
import type { Renderer, TextOverlay } from './renderer.js';
import type { Label, Layout, PlacedTile, Rect, SceneItem, Tile, TileStyle } from './types.js';

export interface FrameScheduler {
  request(cb: () => void): number;
  cancel(id: number): void;
}

export interface SceneOptions<D = unknown> {
  canvas: HTMLCanvasElement;
  layout: Layout<D>;
  /** Colour and flags of a tile, given the view's current state. */
  style: (tile: Tile<D>) => TileStyle;
  /** Labels for the tiles as placed this frame (text overlay pass). */
  labels?: (tiles: readonly PlacedTile<D>[]) => Label[];
  /** Default: Canvas2D on `canvas`. */
  renderer?: Renderer;
  /** Fallback after a context loss. Default: a Canvas2D renderer. */
  fallbackRenderer?: () => Renderer;
  /** Default: a Canvas2D overlay sharing `canvas`; null disables labels. */
  overlay?: TextOverlay | null;
  /** Tween length in ms. Default 500. */
  duration?: number;
  /** Packed RGBA8 background (Canvas2D default renderer only). */
  background?: number;
  /** Clock in ms. Default performance.now. */
  clock?: () => number;
  /** Default: window.requestAnimationFrame. */
  scheduler?: FrameScheduler;
  devicePixelRatio?: () => number;
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
  /** Topmost live tile at (x, y) in CSS px, as drawn right now. */
  hitTest(x: number, y: number): PlacedTile<D> | null;
  /** Live tiles (not leaving) as drawn right now. */
  placed(): PlacedTile<D>[];
  isAnimating(): boolean;
  /** Request one redraw. */
  invalidate(): void;
  /** Replace the renderer (after init resolves); re-uploads everything. */
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

export function createScene<D = unknown>(opts: SceneOptions<D>): Scene<D> {
  const clock = opts.clock ?? (() => performance.now());
  const scheduler = opts.scheduler ?? defaultScheduler();
  const dprOf = opts.devicePixelRatio ?? (() => (typeof window !== 'undefined' && window.devicePixelRatio) || 1);
  const duration = Math.max(0, opts.duration ?? 500);
  const buffer = new InstanceBuffer();
  const entries = new Map<string, Entry<D>>();
  const canvas = opts.canvas;

  let layout = opts.layout;
  let renderer: Renderer = opts.renderer ?? createCanvas2DRenderer(
    opts.background !== undefined ? { background: opts.background } : {});
  const overlay: TextOverlay | null = opts.overlay === undefined
    ? createCanvas2DTextOverlay(canvas)
    : opts.overlay;
  let epoch = clock();
  let items: readonly SceneItem<D>[] = [];
  let pending: readonly SceneItem<D>[] | null = null;
  let viewport: Rect = { x: 0, y: 0, w: 0, h: 0 };
  let animEnd = -Infinity;      // engine time when the last tween ends
  let raf: number | null = null;
  let destroyed = false;
  let uploadedGeneration = -1;
  /** False until the current renderer's init resolves (GPU backends
   *  compile asynchronously); frames wait, state keeps updating. */
  let ready = true;

  const now = (): number => clock() - epoch;

  const schedule = (): void => {
    if (destroyed || raf !== null) return;
    raf = scheduler.request(frame);
  };

  const fallback = (): void => {
    const fb = opts.fallbackRenderer ? opts.fallbackRenderer() : createCanvas2DRenderer(
      opts.background !== undefined ? { background: opts.background } : {});
    void swapRenderer(fb);
  };

  const initRenderer = (r: Renderer): void | Promise<void> => {
    r.onContextLost(fallback);
    return r.init(canvas);
  };

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
  };

  /** Lay out `next` and retarget every record. dur 0 snaps. */
  const apply = (next: readonly SceneItem<D>[], dur: number): void => {
    maybeRebaseEpoch();
    items = next;
    const t = now();
    const tiles = layout.layout(items, viewport);
    const seen = new Set<string>();
    for (const tile of tiles) {
      if (seen.has(tile.key)) continue;  // keys must be unique; keep the first
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

  const placedAt = (t: number, includeExiting: boolean): PlacedTile<D>[] => {
    const out: PlacedTile<D>[] = [];
    for (const e of entries.values()) {
      if (e.exiting && !includeExiting) continue;
      const cur = current(e.slot, t);
      out.push({
        ...e.tile,
        x: cur.rect.x, y: cur.rect.y, w: cur.rect.w, h: cur.rect.h,
        color: cur.color,
        flags: cur.rec.flags,
        exiting: e.exiting,
      });
    }
    return out;
  };

  function frame(): void {
    raf = null;
    if (destroyed || !ready) return;
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
    if (overlay !== null) overlay.draw(opts.labels ? opts.labels(placedAt(t, false)) : []);
    if (t < animEnd || pending !== null) schedule();
  }

  async function swapRenderer(next: Renderer): Promise<void> {
    await initRenderer(next);
    if (destroyed) { next.dispose(); return; }
    const old = renderer;
    renderer = next;
    next.resize(viewport.w, viewport.h, dprOf());
    buffer.markAllDirty();
    uploadedGeneration = -1;
    if (old !== next) old.dispose();
    schedule();
  }

  // Initial renderer: Canvas2D is synchronous; a renderer whose init is
  // async simply draws once it resolves.
  const first = initRenderer(renderer);
  if (first instanceof Promise) {
    ready = false;
    void first.then(() => { ready = true; schedule(); });
  }

  {
    const el = canvas as unknown as { clientWidth?: number; clientHeight?: number };
    const w = el.clientWidth ?? 0, h = el.clientHeight ?? 0;
    if (w > 0 && h > 0) {
      viewport = { x: 0, y: 0, w, h };
      renderer.resize(w, h, dprOf());
      overlay?.resize(w, h, dprOf());
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
      renderer.resize(viewport.w, viewport.h, dpr);
      overlay?.resize(viewport.w, viewport.h, dpr);
      apply(pending ?? items, 0);
      pending = null;
    },
    hitTest(x, y) {
      const tiles = placedAt(now(), false);
      return layout.hitTest ? layout.hitTest(tiles, x, y) : defaultHit(tiles, x, y);
    },
    placed: () => placedAt(now(), false),
    isAnimating: () => now() < animEnd,
    invalidate: schedule,
    swapRenderer,
    get renderer() { return renderer; },
    buffer,
    destroy() {
      destroyed = true;
      if (raf !== null) scheduler.cancel(raf);
      raf = null;
      renderer.dispose();
      overlay?.dispose();
      entries.clear();
    },
  };
}
