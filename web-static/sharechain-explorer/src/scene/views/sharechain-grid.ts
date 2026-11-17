// Share-chain grid on the scene engine: "Fluid (experimental)".
//
// One cell per share, newest first, laid out by the grid layout plug-in.
// Shares are keyed by their full hash, so when a new share arrives at the
// head every cell keeps its key and slides one slot (keyed tween); shares
// that leave the window shrink and fade at the tail. The engine merges
// bursts (at most one update per animation) and idles when nothing moves.
//
// Colours and block marks come from the host, so the inline dashboard
// gives cells exactly the Classic colours (its own getColor). Hover and
// click are handed back to the host (the Classic tooltip and PPLNS zoom).
// The selection bus links the grid with the PPLNS treemap: hovering a
// cell publishes its miner; a miner pinned (or hovered in another view)
// keeps full colour and the other cells dim.

import { createScene, type FrameScheduler, type Scene } from '../engine.js';
import { createGridLayout, type GridLayoutPlugin } from '../layouts/grid.js';
import { createSelectionBus, type SelectionBus } from '../selection.js';
import { rgba } from '../colour.js';
import { FLAG_DIM, FLAG_MATCH } from '../renderer.js';
import type { Label, PlacedTile, SceneItem, Tile, TileStyle } from '../types.js';
import { isOffChainCell, withOffChainCells, type BlockRow } from './offchain.js';

/** The share fields the grid reads (a /sharechain/window share). */
export interface GridShare {
  /** Short hash (16 hex). */
  h?: string;
  /** Full hash; preferred as the cell key. */
  H?: string;
  /** Payout address (the bus subject). */
  m?: string;
  /** Share timestamp, unix seconds (hour axis). */
  t?: number;
  [field: string]: unknown;
}

export type BlockKind = 'primary' | 'child' | 'twin';

export interface SharechainGridOptions {
  container: HTMLElement;
  /** CSS colour of a share (#rgb, #rrggbb, #rrggbbaa, rgb[a]()). */
  colorOf: (share: GridShare) => string;
  /** Block-solution kind of a share, if it solved one. */
  blockKindOf?: (share: GridShare) => BlockKind | null | undefined;
  /** Bus subject of a share. Default: its payout address `m`. */
  subjectOf?: (share: GridShare) => string | undefined;
  bus?: SelectionBus;
  /** Pointer over a share (null when it leaves the grid). */
  onHover?: (share: GridShare | null, ev: MouseEvent) => void;
  onClick?: (share: GridShare, ev: MouseEvent) => void;
  /** Tween length in ms. Default 700. */
  duration?: number;
  gap?: number;
  marginLeft?: number;
  minCellSize?: number;
  maxCellSize?: number;
  // Test hooks (see the scene engine).
  clock?: () => number;
  scheduler?: FrameScheduler;
  createSurface?: (role: 'renderer' | 'overlay') => HTMLCanvasElement;
  devicePixelRatio?: () => number;
  /** Wall clock in seconds for the hour axis. Default Date.now()/1000. */
  nowSeconds?: () => number;
}

export interface SharechainGrid {
  /** The window, newest share first. Held while a tween runs.
   *  `offChain`: ledger rows of block shares not on the best sharechain
   *  (offChainBlocks), shown as ▣ cells placed by timestamp. */
  update(shares: readonly GridShare[], opts?: { immediate?: boolean; offChain?: readonly BlockRow[] }): void;
  /** Re-run colours (e.g. after the host's colour inputs changed). */
  restyle(): void;
  readonly scene: Scene<GridShare>;
  readonly bus: SelectionBus;
  destroy(): void;
}

const SOURCE = 'grid';
const BG = rgba(13, 13, 26);
const FALLBACK = rgba(85, 85, 119);
/** ▣ off-chain block-share cells: muted violet fill, gold ▣ pip. */
export const OFF_CHAIN_FILL = '#4a3a6e';
export const OFF_CHAIN_MARK = '#ffd700';

/** Ring and core of a block cell, as in the Classic grid's BLOCK_MARK. */
export const BLOCK_MARK: Record<BlockKind, { ring: string; core: string }> = {
  primary: { ring: '#ffd700', core: '#1a1400' },
  child: { ring: '#00e5ff', core: '#001a1d' },
  twin: { ring: '#ffaa00', core: '#1d0e00' },
};

/** Parse a CSS colour into packed RGBA8; null when unrecognised. */
export function parseCssColor(css: string): number | null {
  const s = css.trim().toLowerCase();
  let m = /^#([0-9a-f]{3})$/.exec(s);
  if (m) {
    const [r, g, b] = m[1]!.split('').map((c) => parseInt(c + c, 16));
    return rgba(r!, g!, b!);
  }
  m = /^#([0-9a-f]{6})([0-9a-f]{2})?$/.exec(s);
  if (m) {
    const n = parseInt(m[1]!, 16);
    const a = m[2] !== undefined ? parseInt(m[2], 16) : 255;
    return rgba((n >> 16) & 255, (n >> 8) & 255, n & 255, a);
  }
  m = /^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+)\s*)?\)$/.exec(s);
  if (m) {
    const a = m[4] !== undefined ? Math.round(Math.max(0, Math.min(1, Number(m[4]))) * 255) : 255;
    return rgba(Math.round(Number(m[1])), Math.round(Number(m[2])), Math.round(Number(m[3])), a);
  }
  return null;
}

export const keyOfShare = (s: GridShare, index: number): string => s.H ?? s.h ?? `#${index}`;

/** Hour-axis labels: a row is labelled when its mean share age crosses
 *  into a new hour (the Classic grid's axis). */
export function hourAxisLabels(
  shares: readonly GridShare[],
  g: { cols: number; rows: number; step: number; marginLeft: number },
  nowS: number,
  originY = 0,
): Label[] {
  const out: Label[] = [];
  if (g.cols <= 0) return out;
  let last = -1;
  for (let r = 0; r < g.rows; r++) {
    let sum = 0, n = 0;
    for (let i = r * g.cols; i < Math.min((r + 1) * g.cols, shares.length); i++) {
      const t = shares[i]?.t;
      if (typeof t === 'number') { sum += nowS - t; n++; }
    }
    if (n === 0) continue;
    const hour = Math.floor(sum / n / 3600);
    if (hour === last || hour < 0) continue;
    last = hour;
    out.push({
      text: `${hour}h`, x: g.marginLeft - 4, y: originY + r * g.step + g.step / 2,
      color: '#b0b0cc', font: 'bold 11px -apple-system, sans-serif', align: 'right',
    });
  }
  return out;
}

export function mountSharechainGrid(opts: SharechainGridOptions): SharechainGrid {
  const doc = opts.container.ownerDocument;
  const win = doc.defaultView;
  const bus = opts.bus ?? createSelectionBus();
  const subjectOf = opts.subjectOf ?? ((s: GridShare) => (typeof s.m === 'string' && s.m !== '' ? s.m : undefined));
  const nowS = opts.nowSeconds ?? (() => Date.now() / 1000);
  const layout: GridLayoutPlugin<GridShare> = createGridLayout<GridShare>({
    ...(opts.gap !== undefined ? { gap: opts.gap } : {}),
    ...(opts.marginLeft !== undefined ? { marginLeft: opts.marginLeft } : {}),
    ...(opts.minCellSize !== undefined ? { minCellSize: opts.minCellSize } : {}),
    ...(opts.maxCellSize !== undefined ? { maxCellSize: opts.maxCellSize } : {}),
  });

  let shares: readonly GridShare[] = [];
  /** What the scene lays out: the window plus ▣ cells, duplicates dropped.
   *  The hour axis reads this list so its rows match the cells. */
  let laid: readonly GridShare[] = [];
  let offChainSig = '';
  let axis: Label[] = [];
  let tipKey: string | null = null;
  let viewport = { x: 0, y: 0, w: 0, h: 0 };

  const stage = doc.createElement('div');
  stage.style.cssText = 'position:absolute;inset:0;overflow:hidden;cursor:pointer';
  opts.container.appendChild(stage);

  const shareOf = (tile: Tile<GridShare>): GridShare | undefined => tile.items[0]?.data;

  const style = (tile: Tile<GridShare>): TileStyle => {
    const s = shareOf(tile);
    if (s === undefined) return { color: FALLBACK, flags: 0 };
    let flags = 0;
    if (isOffChainCell(s)) {
      const sel0 = bus.get();
      const focus0 = sel0.pinned ?? (sel0.source !== SOURCE ? sel0.hover : null);
      if (focus0 !== null && subjectOf(s) !== focus0) flags |= FLAG_DIM;
      return { color: parseCssColor(tile.w >= 8 ? OFF_CHAIN_FILL : OFF_CHAIN_MARK) ?? FALLBACK, flags };
    }
    let color = parseCssColor(opts.colorOf(s)) ?? FALLBACK;
    const kind = opts.blockKindOf?.(s);
    if (kind) {
      const big = tile.w >= 8;
      color = parseCssColor(big ? BLOCK_MARK[kind].core : BLOCK_MARK[kind].ring) ?? color;
      if (big) flags |= FLAG_MATCH;  // ring outline
    }
    const sel = bus.get();
    const focus = sel.pinned ?? (sel.source !== SOURCE ? sel.hover : null);
    if (focus !== null && subjectOf(s) !== focus) flags |= FLAG_DIM;
    return { color, flags };
  };

  const labels = (tiles: readonly PlacedTile<GridShare>[]): Label[] => {
    const out = axis.slice();
    for (const t of tiles) {
      const s = shareOf(t);
      if (s === undefined || t.w < 8) continue;
      if (isOffChainCell(s)) {
        out.push({
          text: '▣', x: t.x + t.w / 2, y: t.y + t.h / 2, color: OFF_CHAIN_MARK,
          font: `${Math.max(7, Math.round(t.w * 0.6))}px sans-serif`,
        });
        continue;
      }
      const kind = opts.blockKindOf?.(s);
      if (kind) {
        out.push({
          text: '■', x: t.x + t.w / 2, y: t.y + t.h / 2, color: BLOCK_MARK[kind].ring,
          font: `${Math.max(6, Math.round(t.w * 0.45))}px sans-serif`,
        });
      } else if (t.key === tipKey) {
        out.push({ text: '◤', x: t.x + 1, y: t.y + 1, color: '#ffffff', align: 'left', baseline: 'top',
          font: `${Math.max(6, Math.round(t.w * 0.5))}px sans-serif` });
      }
    }
    return out;
  };

  const scene = createScene<GridShare>({
    container: stage,
    layout,
    style,
    labels,
    background: BG,
    duration: opts.duration ?? 700,
    ...(opts.clock ? { clock: opts.clock } : {}),
    ...(opts.scheduler ? { scheduler: opts.scheduler } : {}),
    ...(opts.createSurface ? { createSurface: opts.createSurface } : {}),
    ...(opts.devicePixelRatio ? { devicePixelRatio: opts.devicePixelRatio } : {}),
  });

  const rebuildAxis = (): void => {
    const g = layout.metrics(laid.length, viewport);
    axis = hourAxisLabels(laid, g, nowS(), viewport.y);
  };

  const toItems = (list: readonly GridShare[]): SceneItem<GridShare>[] => {
    const seen = new Set<string>();
    const items: SceneItem<GridShare>[] = [];
    list.forEach((s, i) => {
      const key = keyOfShare(s, i);
      if (seen.has(key)) return;  // a duplicated share keeps its first cell
      seen.add(key);
      items.push({ key, weight: 1, data: s });
    });
    return items;
  };

  const resize = (): void => {
    viewport = { x: 0, y: 0, w: stage.clientWidth, h: stage.clientHeight };
    scene.resize(viewport.w, viewport.h);
    rebuildAxis();
  };
  const RO = (win as unknown as { ResizeObserver?: new (cb: () => void) => { observe(e: Element): void; disconnect(): void } } | null)
    ?.ResizeObserver;
  const ro = RO !== undefined ? new RO(resize) : null;
  if (ro !== null) ro.observe(stage);
  else win?.addEventListener('resize', resize);
  resize();

  // ── pointer ──────────────────────────────────────────────────────
  let hoverKey: string | null = null;
  const tileAt = (ev: MouseEvent): PlacedTile<GridShare> | null => {
    const r = stage.getBoundingClientRect();
    return scene.hitTest(ev.clientX - r.left, ev.clientY - r.top);
  };
  const onMove = (ev: MouseEvent): void => {
    const tile = tileAt(ev);
    const s = tile !== null ? shareOf(tile) : undefined;
    if (s === undefined) {
      if (hoverKey !== null) { hoverKey = null; bus.hover(null, SOURCE); opts.onHover?.(null, ev); }
      return;
    }
    if (tile!.key !== hoverKey) {
      hoverKey = tile!.key;
      bus.hover(subjectOf(s) ?? null, SOURCE);
    }
    opts.onHover?.(s, ev);
  };
  const onLeave = (ev: MouseEvent): void => {
    if (hoverKey !== null) { hoverKey = null; bus.hover(null, SOURCE); }
    opts.onHover?.(null, ev);
  };
  const onClick = (ev: MouseEvent): void => {
    const tile = tileAt(ev);
    const s = tile !== null ? shareOf(tile) : undefined;
    if (s !== undefined) opts.onClick?.(s, ev);
  };
  stage.addEventListener('mousemove', onMove);
  stage.addEventListener('mouseleave', onLeave);
  stage.addEventListener('click', onClick);
  // Another view's hover or pin changes which cells are dimmed.
  const unsubscribe = bus.subscribe((s) => { if (s.source !== SOURCE) scene.restyle(); });

  return {
    update(next, o) {
      const rows = o?.offChain ?? [];
      const sig = rows.map((b) => b.share || b.hash || '').join(',');
      // Same window array and same off-chain rows: nothing moved, only
      // styles may differ (hosts replace the window array on every change).
      if (next === shares && sig === offChainSig && next.length > 0) { scene.restyle(); return; }
      offChainSig = sig;
      const items = toItems(withOffChainCells(next, rows));
      shares = next;
      laid = items.map((it) => it.data!);
      tipKey = next.length > 0 ? keyOfShare(next[0]!, 0) : null;
      rebuildAxis();
      scene.setItems(items, o?.immediate === true ? { immediate: true } : undefined);
    },
    restyle: () => scene.restyle(),
    scene,
    bus,
    destroy() {
      unsubscribe();
      stage.removeEventListener('mousemove', onMove);
      stage.removeEventListener('mouseleave', onLeave);
      stage.removeEventListener('click', onClick);
      if (ro !== null) ro.disconnect();
      else win?.removeEventListener('resize', resize);
      scene.destroy();
      if (stage.parentNode !== null) stage.parentNode.removeChild(stage);
    },
  };
}
