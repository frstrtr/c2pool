// PPLNS View DOM renderer. Strictly createElement + textContent — no
// innerHTML anywhere (the legacy tooltip at dashboard.html:6199 used
// innerHTML on server-supplied strings; extraction rewrites the path).
//
// Adaptive-content thresholds per
// frstrtr/the/docs/c2pool-pplns-view-module-task.md §7.

import { addrColor } from './colors.js';
import type {
  CoinPplnsDescriptor,
  PplnsMiner,
  PplnsSnapshot,
  PplnsViewOptions,
} from './types.js';
import { squarify, type SquarifyItem } from './squarify.js';
import { formatHashrate } from './classify.js';

export interface RenderOptions {
  container: HTMLElement;
  snapshot: PplnsSnapshot;
  coin: CoinPplnsDescriptor;
  opts: {
    minCellPx: number;
    showVersionBadge: boolean;
    showHashrate: boolean;
    showMerged: boolean;
  };
  onMinerClick?: (miner: PplnsMiner) => void;
  /** Optional address → CSS colour override (e.g. highlight search match). */
  addressColor?: (miner: PplnsMiner) => string;
}

/** Clear + repopulate the container with the laid-out treemap. */
export function render(ro: RenderOptions): void {
  const { container, snapshot, coin, opts } = ro;
  clearChildren(container);
  container.style.position = 'relative';
  container.style.display = 'block';
  const rect = container.getBoundingClientRect();
  const w = Math.max(0, Math.floor(rect.width));
  const h = Math.max(0, Math.floor(rect.height));
  if (snapshot.miners.length === 0 || w === 0 || h === 0) {
    renderEmpty(container);
    return;
  }
  const items: SquarifyItem<PplnsMiner>[] = snapshot.miners
    .filter((m) => m.amount > 0)
    .map((m) => ({ area: m.amount, data: m }));
  const rects = squarify(items, 0, 0, w, h);
  for (const r of rects) {
    const cellOpts: CellOpts = {
      miner: r.data,
      x: r.x, y: r.y, w: r.w, h: r.h,
      coin,
      opts,
      addressColor: ro.addressColor ?? ((mm) => addrColor(mm.address, severityOf(mm, coin))),
    };
    if (ro.onMinerClick !== undefined) cellOpts.onClick = ro.onMinerClick;
    container.appendChild(buildCell(cellOpts));
  }
}

function renderEmpty(container: HTMLElement): void {
  const empty = document.createElement('div');
  empty.className = 'pv-empty';
  empty.style.cssText =
    'position:absolute;inset:0;display:flex;align-items:center;' +
    'justify-content:center;color:#555577;font-size:12px;';
  empty.textContent = 'No payouts in current window';
  container.appendChild(empty);
}

interface CellOpts {
  miner: PplnsMiner;
  x: number; y: number; w: number; h: number;
  coin: CoinPplnsDescriptor;
  opts: RenderOptions['opts'];
  addressColor: (m: PplnsMiner) => string;
  onClick?: ((m: PplnsMiner) => void) | undefined;
}

function buildCell(c: CellOpts): HTMLElement {
  const { miner, x, y, w, h, coin, opts, addressColor, onClick } = c;
  const cell = document.createElement('div');
  cell.className = 'pv-cell';
  cell.setAttribute('role', 'button');
  cell.setAttribute('tabindex', '0');
  cell.dataset['address'] = miner.address;
  cell.style.cssText =
    `position:absolute;left:${x}px;top:${y}px;width:${w}px;height:${h}px;` +
    `background:${addressColor(miner)};border:1px solid rgba(0,0,0,0.35);` +
    `box-sizing:border-box;cursor:pointer;color:#0d0d1a;` +
    `overflow:hidden;font-family:-apple-system,sans-serif;`;
  // Adaptive content — thresholds per spec §7.
  if (w > 28 && h > 14) {
    cell.appendChild(textLine(
      formatPercent(miner.pct),
      { size: fontSize(w, h), weight: 700 },
    ));
  }
  if (opts.showMerged && w > 35 && h > 28 && coin.mergedChains.length > 0) {
    for (const chain of coin.mergedChains) {
      const entry = miner.merged.find((m) => m.symbol === chain.symbol);
      if (entry === undefined && chain.alwaysShow !== true) continue;
      const row = document.createElement('div');
      row.className = 'pv-merged';
      row.style.cssText =
        `font-size:${Math.max(9, fontSize(w, h) - 2)}px;color:${chain.color};` +
        `font-weight:600;line-height:1.1;`;
      row.textContent = entry !== undefined
        ? `${(entry.pct * 100).toFixed(1)}% ${chain.tooltipLabel}`
        : `— no ${chain.tooltipLabel}`;
      cell.appendChild(row);
    }
  }
  if (w > 45 && h > 42) {
    const addr = document.createElement('div');
    addr.className = 'pv-addr';
    addr.style.cssText = `font-family:Monaco,Consolas,monospace;font-size:10px;opacity:0.75;`;
    addr.textContent = truncateAddress(miner.address, w);
    cell.appendChild(addr);
  }
  if (opts.showHashrate && w > 55 && h > 55 && typeof miner.hashrateHps === 'number' && miner.hashrateHps > 0) {
    const hr = document.createElement('div');
    hr.className = 'pv-hashrate';
    hr.style.cssText = `font-size:10px;opacity:0.7;`;
    hr.textContent = (coin.formatHashrate ?? formatHashrate)(miner.hashrateHps);
    cell.appendChild(hr);
  }
  if (opts.showVersionBadge && w > 30 && h > 52) {
    const key = coin.versionBadges.classify(miner);
    const badge = coin.versionBadges.palette[key];
    if (badge !== undefined) {
      const b = document.createElement('div');
      b.className = 'pv-badge';
      b.style.cssText =
        `position:absolute;right:4px;bottom:4px;padding:1px 5px;` +
        `font-size:9px;font-weight:600;border-radius:3px;` +
        `background:${badge.color};color:#0d0d1a;`;
      b.textContent = badge.label;
      cell.appendChild(b);
    }
  }
  const mergedAmountLine = miner.merged.map((m) =>
    `${m.symbol}: ${m.amount.toFixed(8)} (${(m.pct * 100).toFixed(3)}%)`,
  ).join('\n');
  cell.title = [
    miner.address,
    `Amount: ${miner.amount.toFixed(8)} (${(miner.pct * 100).toFixed(3)}%)`,
    typeof miner.hashrateHps === 'number'
      ? `Hashrate: ${(coin.formatHashrate ?? formatHashrate)(miner.hashrateHps)}`
      : null,
    typeof miner.sharesInWindow === 'number'
      ? `Shares in window: ${miner.sharesInWindow}`
      : null,
    mergedAmountLine,
  ].filter((x) => x !== null && x !== '').join('\n');
  if (onClick !== undefined) {
    cell.addEventListener('click', () => onClick(miner));
    cell.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') {
        ev.preventDefault();
        onClick(miner);
      }
    });
  }
  return cell;
}

function textLine(text: string, style: { size: number; weight: number }): HTMLElement {
  const el = document.createElement('div');
  el.style.cssText = `font-size:${style.size}px;font-weight:${style.weight};`;
  el.textContent = text;
  return el;
}

function fontSize(w: number, h: number): number {
  const s = Math.min(w, h);
  if (s < 30) return 10;
  if (s < 55) return 12;
  if (s < 90) return 14;
  return 16;
}

function formatPercent(pct: number): string {
  if (!(pct > 0)) return '0%';
  return `${(pct * 100).toFixed(pct >= 0.1 ? 1 : 2)}%`;
}

function truncateAddress(addr: string, w: number): string {
  // Monospace ~6 px per char at 10 px font; subtract paddings.
  const chars = Math.max(6, Math.floor((w - 8) / 6));
  if (addr.length <= chars) return addr;
  const head = Math.ceil((chars - 1) / 2);
  const tail = Math.floor((chars - 1) / 2);
  return addr.slice(0, head) + '…' + addr.slice(addr.length - tail);
}

function severityOf(
  miner: PplnsMiner,
  coin: CoinPplnsDescriptor,
): 'ok' | 'signaling' | 'warn' | 'muted' {
  const key = coin.versionBadges.classify(miner);
  return coin.versionBadges.palette[key]?.severity ?? 'ok';
}

function clearChildren(el: HTMLElement): void {
  while (el.firstChild !== null) el.removeChild(el.firstChild);
}

export function resolveContainer(
  target: string | HTMLElement,
): HTMLElement | null {
  if (typeof target === 'string') {
    return document.querySelector(target);
  }
  return target;
}

/** Expose for unit tests that can't easily synthesise a BoundingClientRect. */
export function renderAtSize(
  ro: Omit<RenderOptions, 'container'> & {
    container: HTMLElement;
    width: number;
    height: number;
  },
): void {
  const { width, height } = ro;
  // Stash size on the element so tests can read back.
  ro.container.style.width = `${width}px`;
  ro.container.style.height = `${height}px`;
  render({
    container: ro.container,
    snapshot: ro.snapshot,
    coin: ro.coin,
    opts: ro.opts,
    ...(ro.onMinerClick !== undefined ? { onMinerClick: ro.onMinerClick } : {}),
    ...(ro.addressColor !== undefined ? { addressColor: ro.addressColor } : {}),
  });
}

/** Expose the unused options contract for the controller layer. */
export type { PplnsViewOptions };
