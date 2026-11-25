// PPLNS treemap view — the DOM half. A view on the scene engine: the
// treemap layout plug-in, pplns-model.ts for data/style/labels/tooltip,
// and the selection bus for hover/pin/search links with other views.
//
//   const view = mountPplnsTreemap({ container, symbol: 'LTC', mergedSymbol: 'DOGE' });
//   view.update({ payouts: currentPayoutsJson, merged: currentMergedPayoutsJson });
//
// Interaction: hover shows the tooltip and highlights the miner in every
// linked view; click pins (Esc unpins); click on "N others" lays the
// small miners out; ctrl/⌘-click opens the address explorer; the search
// box dims non-matching tiles. Pointer events bind to the stage, so they
// survive a renderer swap.

import { createScene, type FrameScheduler, type Scene } from '../engine.js';
import { createTreemapLayout } from '../layouts/treemap.js';
import { createSelectionBus, type SelectionBus } from '../selection.js';
import { rgba } from '../colour.js';
import type { PlacedTile } from '../types.js';
import {
  buildPplnsItems, escapeHtml, pplnsLabels, pplnsStyle, tooltipLines,
  type MinerDatum, type MinerFacts, type PplnsMode, type PplnsSnapshot,
  type SpecialAddresses, type TooltipLine,
} from './pplns-model.js';

export interface PplnsTreemapOptions {
  container: HTMLElement;
  /** Parent coin symbol, e.g. 'LTC', 'DASH'. */
  symbol: string;
  /** Merged child symbol (e.g. 'DOGE'); enables the coin toggle. */
  mergedSymbol?: string;
  /** Share one bus with other views to link hover/pin/search. */
  bus?: SelectionBus;
  special?: SpecialAddresses;
  /** Per-miner facts from the host's share window (tooltip). */
  facts?: (address: string) => MinerFacts | undefined;
  /** Address-explorer URL for ctrl/⌘-click. */
  addressUrl?: (address: string) => string | undefined;
  /** Aggregate tiles under this share of the weight. Default 0.005. */
  othersFraction?: number;
  /** …or smaller than this many px². Default 48. */
  minTileArea?: number;
  /** Minimum stage height in px. Default 240. */
  minHeight?: number;
  // Test hooks (see the scene engine).
  clock?: () => number;
  scheduler?: FrameScheduler;
  createSurface?: (role: 'renderer' | 'overlay') => HTMLCanvasElement;
  devicePixelRatio?: () => number;
  open?: (url: string) => void;
}

export interface PplnsTreemap {
  /** New data, and optionally who is special, in one transition. */
  update(snapshot: PplnsSnapshot, special?: SpecialAddresses): void;
  setSpecial(special: SpecialAddresses): void;
  setMode(mode: PplnsMode): void;
  setScale(scale: 'linear' | 'log'): void;
  expandOthers(on: boolean): void;
  readonly scene: Scene<MinerDatum>;
  readonly bus: SelectionBus;
  destroy(): void;
}

const SOURCE = 'pplns-treemap';
const BG = rgba(13, 13, 26);
const TONE_STYLE: Record<NonNullable<TooltipLine['tone']> | 'plain', string> = {
  title: 'color:#7cc4ff;font-weight:700;margin-bottom:4px;font-family:Monaco,Consolas,monospace;word-break:break-all',
  strong: 'font-weight:600',
  accent: 'color:#ffc531;font-weight:600',
  warn: 'color:#ff8a65;font-weight:600',
  muted: 'color:#9a9ab8;font-size:0.86em',
  plain: '',
};

export function tooltipHtml(lines: readonly TooltipLine[]): string {
  return lines.map((l) => `<div style="${TONE_STYLE[l.tone ?? 'plain']}">${escapeHtml(l.text)}</div>`).join('');
}

export function mountPplnsTreemap(opts: PplnsTreemapOptions): PplnsTreemap {
  const doc = opts.container.ownerDocument;
  const bus = opts.bus ?? createSelectionBus();
  const el = <K extends keyof HTMLElementTagNameMap>(tag: K, css: string): HTMLElementTagNameMap[K] => {
    const e = doc.createElement(tag);
    e.style.cssText = css;
    return e;
  };

  let snapshot: PplnsSnapshot = { payouts: {} };
  let mode: PplnsMode = 'parent';
  let scale: 'linear' | 'log' = 'linear';
  let expanded = false;
  let special: SpecialAddresses = opts.special ?? {};
  let total = 0;
  let parentTotal = 0;
  let hoverKey: string | null = null;

  // ── DOM ──────────────────────────────────────────────────────────
  const root = el('div', 'display:flex;flex-direction:column;width:100%;height:100%;gap:6px');
  root.className = 'c2p-pplns-treemap';
  const bar = el('div', 'display:flex;flex-wrap:wrap;align-items:center;gap:6px;font-size:12px;color:#b0b0cc');
  const btnCss = 'background:#1e1e38;color:#b0b0cc;border:1px solid #3a3a5a;border-radius:6px;padding:2px 8px;cursor:pointer;font:inherit';
  const modeBtns = new Map<PplnsMode, HTMLButtonElement>();
  if (opts.mergedSymbol !== undefined) {
    for (const [m, label] of [['parent', opts.symbol], ['merged', opts.mergedSymbol]] as const) {
      const b = el('button', btnCss);
      b.type = 'button';
      b.textContent = label;
      b.addEventListener('click', () => api.setMode(m));
      modeBtns.set(m, b);
      bar.appendChild(b);
    }
  }
  const scaleSel = el('select', btnCss);
  for (const [v, label] of [['linear', 'Weight'], ['log', 'Log (not proportional)']] as const) {
    const o = doc.createElement('option');
    o.value = v;
    o.textContent = label;
    scaleSel.appendChild(o);
  }
  scaleSel.addEventListener('change', () => api.setScale(scaleSel.value === 'log' ? 'log' : 'linear'));
  bar.appendChild(scaleSel);
  const search = el('input', `${btnCss};cursor:text;min-width:140px;flex:0 1 220px`);
  search.type = 'search';
  search.placeholder = 'address…';
  search.addEventListener('input', () => bus.search(search.value, SOURCE));
  bar.appendChild(search);
  const collapse = el('button', `${btnCss};display:none`);
  collapse.type = 'button';
  collapse.textContent = '◂ group small miners';
  collapse.addEventListener('click', () => api.expandOthers(false));
  bar.appendChild(collapse);
  const logBadge = el('span', 'display:none;color:#ff8a65;font-weight:600');
  logBadge.textContent = 'log scale: tile areas are NOT proportional';
  bar.appendChild(logBadge);
  const legend = el('span', 'margin-left:auto;opacity:0.8');
  legend.textContent = 'area = PPLNS weight · ★ this node · ⚑ node owner · ◇ donation';
  bar.appendChild(legend);

  const stage = el('div', `position:relative;flex:1 1 auto;min-height:${opts.minHeight ?? 240}px;overflow:hidden;border-radius:8px;cursor:pointer`);
  const tip = el('div', 'display:none;position:fixed;z-index:9999;pointer-events:none;background:#1e1e38;'
    + 'border:1px solid #3a3a5a;border-radius:8px;padding:8px 12px;font-size:0.82rem;color:#e0e0f0;'
    + 'box-shadow:0 6px 20px rgba(0,0,0,0.5);max-width:340px');
  root.appendChild(bar);
  root.appendChild(stage);
  root.appendChild(tip);
  opts.container.appendChild(root);

  // ── scene ────────────────────────────────────────────────────────
  const layoutNow = () => createTreemapLayout<MinerDatum>({
    gap: 1,
    othersFraction: opts.othersFraction ?? 0.005,
    minTileArea: opts.minTileArea ?? 48,
    expandOthers: expanded,
    scale,
  });
  const scene = createScene<MinerDatum>({
    container: stage,
    layout: layoutNow(),
    style: (tile) => pplnsStyle(tile, { selection: bus.get() }),
    labels: (tiles) => pplnsLabels(tiles, { total, symbol: mode === 'merged' ? (opts.mergedSymbol ?? opts.symbol) : opts.symbol }),
    background: BG,
    ...(opts.clock ? { clock: opts.clock } : {}),
    ...(opts.scheduler ? { scheduler: opts.scheduler } : {}),
    ...(opts.createSurface ? { createSurface: opts.createSurface } : {}),
    ...(opts.devicePixelRatio ? { devicePixelRatio: opts.devicePixelRatio } : {}),
  });

  const refreshItems = (immediate: boolean): void => {
    const items = buildPplnsItems(snapshot, mode, opts.mergedSymbol, special);
    total = 0;
    for (const it of items) total += it.weight;
    parentTotal = 0;
    for (const v of Object.values(snapshot.payouts ?? {})) {
      if (typeof v === 'number' && Number.isFinite(v) && v > 0) parentTotal += v;
    }
    scene.setItems(items, { immediate });
  };

  const syncBar = (): void => {
    for (const [m, b] of modeBtns) {
      b.style.background = m === mode ? '#008de4' : '#1e1e38';
      b.style.color = m === mode ? '#ffffff' : '#b0b0cc';
    }
    scaleSel.value = scale;
    logBadge.style.display = scale === 'log' ? 'inline' : 'none';
    collapse.style.display = expanded ? 'inline-block' : 'none';
  };

  const resize = (): void => scene.resize(stage.clientWidth, stage.clientHeight);
  const win = doc.defaultView;
  const RO = (win as unknown as { ResizeObserver?: new (cb: () => void) => { observe(e: Element): void; disconnect(): void } } | null)
    ?.ResizeObserver;
  const ro = RO !== undefined ? new RO(resize) : null;
  if (ro !== null) ro.observe(stage);
  else win?.addEventListener('resize', resize);
  resize();

  // ── interaction ──────────────────────────────────────────────────
  const tileAt = (ev: MouseEvent): PlacedTile<MinerDatum> | null => {
    const r = stage.getBoundingClientRect();
    return scene.hitTest(ev.clientX - r.left, ev.clientY - r.top);
  };

  const showTip = (tile: PlacedTile<MinerDatum>, ev: MouseEvent): void => {
    tip.innerHTML = tooltipHtml(tooltipLines(tile, {
      total,
      parentTotal,
      mode,
      symbol: opts.symbol,
      ...(opts.mergedSymbol !== undefined ? { mergedSymbol: opts.mergedSymbol } : {}),
      ...(opts.facts ? { facts: opts.facts } : {}),
    }));
    tip.style.display = 'block';
    const vw = win?.innerWidth ?? 1e9, vh = win?.innerHeight ?? 1e9;
    const tw = tip.offsetWidth || 320, th = tip.offsetHeight || 120;
    let x = ev.clientX + 14, y = ev.clientY + 14;
    if (x + tw > vw - 8) x = ev.clientX - tw - 14;
    if (y + th > vh - 8) y = ev.clientY - th - 14;
    tip.style.left = `${Math.max(8, x)}px`;
    tip.style.top = `${Math.max(8, y)}px`;
  };

  const onMove = (ev: MouseEvent): void => {
    const tile = tileAt(ev);
    const key = tile !== null && !tile.aggregate ? tile.key : null;
    if (key !== hoverKey) {
      hoverKey = key;
      bus.hover(key, SOURCE);
    }
    if (tile !== null) showTip(tile, ev);
    else tip.style.display = 'none';
  };
  const onLeave = (): void => {
    tip.style.display = 'none';
    if (hoverKey !== null) {
      hoverKey = null;
      bus.hover(null, SOURCE);
    }
  };
  const onClick = (ev: MouseEvent): void => {
    const tile = tileAt(ev);
    if (tile === null) return;
    if (tile.aggregate) { api.expandOthers(true); return; }
    if (ev.ctrlKey || ev.metaKey) {
      const url = opts.addressUrl?.(tile.key);
      if (url !== undefined) (opts.open ?? ((u: string) => { win?.open(u, '_blank', 'noopener'); }))(url);
      return;
    }
    bus.togglePin(tile.key, SOURCE);
  };
  const onKey = (ev: KeyboardEvent): void => {
    if (ev.key !== 'Escape') return;
    if (bus.get().pinned !== null) bus.pin(null, SOURCE);
    else if (expanded) api.expandOthers(false);
  };
  stage.addEventListener('mousemove', onMove);
  stage.addEventListener('mouseleave', onLeave);
  stage.addEventListener('click', onClick);
  doc.addEventListener('keydown', onKey);

  const unsubscribe = bus.subscribe((s) => {
    if (s.source !== SOURCE && search.value.trim().toLowerCase() !== s.query) search.value = s.query;
    scene.restyle();
  });

  const api: PplnsTreemap = {
    update(next, nextSpecial) {
      snapshot = next;
      if (nextSpecial !== undefined) special = nextSpecial;
      refreshItems(false);
    },
    setSpecial(next) {
      special = next;
      refreshItems(true);
    },
    setMode(next) {
      if (next === mode || (next === 'merged' && opts.mergedSymbol === undefined)) return;
      mode = next;
      syncBar();
      refreshItems(true);  // same keys: each miner tweens to its new weight
    },
    setScale(next) {
      if (next === scale) return;
      scale = next;
      syncBar();
      scene.setLayout(layoutNow());
    },
    expandOthers(on) {
      if (on === expanded) return;
      expanded = on;
      syncBar();
      scene.setLayout(layoutNow());
    },
    scene,
    bus,
    destroy() {
      unsubscribe();
      stage.removeEventListener('mousemove', onMove);
      stage.removeEventListener('mouseleave', onLeave);
      stage.removeEventListener('click', onClick);
      doc.removeEventListener('keydown', onKey);
      if (ro !== null) ro.disconnect();
      else win?.removeEventListener('resize', resize);
      scene.destroy();
      if (root.parentNode !== null) root.parentNode.removeChild(root);
    },
  };
  syncBar();
  return api;
}
