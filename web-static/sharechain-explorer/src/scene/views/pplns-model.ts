// PPLNS treemap view — the pure half: endpoint JSON → scene items, tile
// style, labels and tooltip content. No DOM; the mount is in
// pplns-treemap.ts.
//
// Data (agreed with the endpoint owners, see the PR / design §3):
//   - tile weight = /current_payouts {address: coins}: what the payout
//     code pays. Never the share count.
//   - merged children (e.g. DOGE on LTC) from /current_merged_payouts
//     {parent: {amount, merged: [{symbol, address, amount, source}]}}.
//     In "merged" mode the SAME keys (parent addresses) are re-weighted
//     by their child amount, so toggling tweens each miner in place.
//   - ★ this node: addresses this node's stratum serves, that are in the
//     PPLNS set. ⚑ node owner: the explicit owner address, or a tile
//     whose address hash160 equals the node's published fee hash160.
//     ◇ donation: only an explicit donation address. Nothing is ever
//     inferred from address prefixes.

import { hsl, rgba } from '../colour.js';
import {
  FLAG_DIM, FLAG_MATCH, FLAG_PINNED, FLAG_SELECTED, TileKind, withKind,
  type TileKindValue,
} from '../renderer.js';
import { matchesQuery, type SelectionState } from '../selection.js';
import type { Label, PlacedTile, SceneItem, Tile, TileStyle } from '../types.js';
import { hash160OfAddress } from './address-hash.js';

export type CurrentPayouts = Record<string, number>;

export interface MergedChild {
  symbol?: string;
  address?: string;
  amount?: number;
  source?: string;
}

export type CurrentMergedPayouts = Record<string, { amount?: number; merged?: readonly MergedChild[] } | number>;

export interface PplnsSnapshot {
  payouts: CurrentPayouts;
  merged?: CurrentMergedPayouts;
}

export type PplnsMode = 'parent' | 'merged';

/** Who is special, as published by the node. Every field is optional;
 *  an absent or empty field marks nothing. */
export interface SpecialAddresses {
  /** Payout addresses this node's stratum serves (★). */
  thisNode?: readonly string[];
  /** Explicit node-owner fee address(es) (⚑). */
  ownerAddresses?: readonly string[];
  /** Node-owner fee as a 20-byte hash160, lower-case hex (⚑, LTC). A P2SH
   *  and a key-hash address with the same 20 bytes would both match;
   *  that cannot happen by accident. */
  ownerHash160?: string;
  /** Explicit donation address(es) (◇). */
  donationAddresses?: readonly string[];
}

export interface MinerDatum {
  address: string;
  /** Parent-coin amount (/current_payouts), coins. */
  amount: number;
  /** Merged-child amount and payee for the configured child symbol. */
  childAmount: number;
  childAddress?: string;
  /** /current_merged_payouts "source" of the child output. */
  childSource?: string;
  kind: TileKindValue;
}

export function isFiniteAmount(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v) && v > 0;
}

/** Kind of a payout address. ★ yields to ⚑ and ◇ (those say more). */
export function classifyAddress(address: string, special: SpecialAddresses | undefined): TileKindValue {
  if (special === undefined) return TileKind.Plain;
  if (special.donationAddresses?.includes(address)) return TileKind.Donation;
  if (special.ownerAddresses?.includes(address)) return TileKind.OwnerFee;
  const fh = special.ownerHash160;
  if (fh !== undefined && fh.length === 40 && hash160OfAddress(address) === fh.toLowerCase()) return TileKind.OwnerFee;
  if (special.thisNode?.includes(address)) return TileKind.ThisNode;
  return TileKind.Plain;
}

/** /stratum_stats `workers` keys ("addr.worker" or "addr") → addresses. */
export function addressesFromWorkers(workers: unknown): string[] {
  if (workers === null || typeof workers !== 'object') return [];
  const out = new Set<string>();
  for (const key of Object.keys(workers as Record<string, unknown>)) {
    const dot = key.indexOf('.');
    const addr = dot < 0 ? key : key.slice(0, dot);
    if (addr.length > 0) out.add(addr);
  }
  return [...out];
}

/** Child amount and payee of one parent row for `symbol`. */
function childOf(row: CurrentMergedPayouts[string] | undefined, symbol: string | undefined): {
  amount: number; address?: string; source?: string;
} {
  if (symbol === undefined || row === undefined || typeof row === 'number' || !Array.isArray(row.merged)) {
    return { amount: 0 };
  }
  let amount = 0;
  let address: string | undefined;
  let source: string | undefined;
  for (const m of row.merged) {
    if ((m.symbol ?? '').toUpperCase() !== symbol.toUpperCase()) continue;
    if (isFiniteAmount(m.amount)) amount += m.amount;
    if (address === undefined && typeof m.address === 'string' && m.address.length > 0) address = m.address;
    if (source === undefined && typeof m.source === 'string') source = m.source;
  }
  const out: { amount: number; address?: string; source?: string } = { amount };
  if (address !== undefined) out.address = address;
  if (source !== undefined) out.source = source;
  return out;
}

/** Scene items for the snapshot. Keys are parent payout addresses in
 *  both modes; the weight is the parent amount ('parent') or the merged
 *  child amount ('merged'). ★ is only given to addresses in the set. */
export function buildPplnsItems(
  snap: PplnsSnapshot,
  mode: PplnsMode,
  mergedSymbol: string | undefined,
  special?: SpecialAddresses,
): SceneItem<MinerDatum>[] {
  const keys = new Set<string>();
  for (const [addr, amt] of Object.entries(snap.payouts ?? {})) if (isFiniteAmount(amt)) keys.add(addr);
  if (mode === 'merged' && snap.merged) for (const addr of Object.keys(snap.merged)) keys.add(addr);
  const items: SceneItem<MinerDatum>[] = [];
  for (const address of keys) {
    const amtRaw = snap.payouts?.[address];
    const amount = isFiniteAmount(amtRaw) ? amtRaw : 0;
    const child = childOf(snap.merged?.[address], mergedSymbol);
    const weight = mode === 'merged' ? child.amount : amount;
    if (!(weight > 0)) continue;
    const datum: MinerDatum = { address, amount, childAmount: child.amount, kind: classifyAddress(address, special) };
    if (child.address !== undefined) datum.childAddress = child.address;
    if (child.source !== undefined) datum.childSource = child.source;
    items.push({ key: address, weight, data: datum });
  }
  return items;
}

/** Addresses whose parent amount differs between /current_payouts and
 *  /current_merged_payouts by more than `tol` coins (they come from one
 *  computation; the merged copy is cached for about two seconds). */
export function parentAmountMismatches(
  payouts: CurrentPayouts,
  merged: CurrentMergedPayouts,
  tol = 1e-8,
): Array<{ address: string; payouts: number; merged: number }> {
  const out: Array<{ address: string; payouts: number; merged: number }> = [];
  const addrs = new Set([...Object.keys(payouts), ...Object.keys(merged)]);
  for (const address of addrs) {
    const p = isFiniteAmount(payouts[address]) ? payouts[address]! : 0;
    const row = merged[address];
    const m = typeof row === 'number' ? row : (isFiniteAmount(row?.amount) ? row!.amount! : 0);
    if (Math.abs(p - m) > tol) out.push({ address, payouts: p, merged: m });
  }
  return out;
}

// ── look ───────────────────────────────────────────────────────────

/** Same hash as the inline dashboard's addrHue (dashboard.html). */
export function addrHue(addr: string): number {
  let hash = 0;
  for (let i = 0; i < addr.length; i++) hash = ((hash << 5) - hash + addr.charCodeAt(i)) | 0;
  return ((hash % 360) + 360) % 360;
}

export const KIND_GLYPH: Record<number, string> = {
  [TileKind.ThisNode]: '★',
  [TileKind.OwnerFee]: '⚑',
  [TileKind.Donation]: '◇',
  [TileKind.OffChainBlock]: '▣',
};

export const OTHERS_COLOR = rgba(58, 58, 88);

export interface ViewState {
  selection: Readonly<SelectionState>;
}

function subjectsOf(tile: Tile<MinerDatum>): string[] {
  return tile.items.map((i) => i.key);
}

export function pplnsStyle(tile: Tile<MinerDatum>, view: ViewState): TileStyle {
  const sel = view.selection;
  const subjects = subjectsOf(tile);
  let color: number;
  let kind: TileKindValue;
  if (tile.aggregate) {
    color = OTHERS_COLOR;
    kind = TileKind.Others;
  } else {
    const d = tile.items[0]?.data;
    kind = d?.kind ?? TileKind.Plain;
    const hue = addrHue(tile.key);
    color = kind === TileKind.OwnerFee ? hsl(42, 72, 40)
      : kind === TileKind.Donation ? hsl(190, 30, 32)
      : kind === TileKind.ThisNode ? hsl(hue, 62, 42)
      : hsl(hue, 45, 32);
  }
  let flags = 0;
  if (sel.hover !== null && subjects.includes(sel.hover)) flags |= FLAG_SELECTED;
  if (sel.pinned !== null) flags |= subjects.includes(sel.pinned) ? FLAG_PINNED : FLAG_DIM;
  if (sel.query.length > 0) {
    flags |= subjects.some((s) => matchesQuery(s, sel.query)) ? FLAG_MATCH : FLAG_DIM;
  }
  return { color, flags: withKind(flags, kind) };
}

export interface LabelContext {
  total: number;
  symbol: string;
}

/** Percent + glyph + short address, sized to the tile; nothing on tiles
 *  too small to read. "N others" says how many it holds. */
export function pplnsLabels(tiles: readonly PlacedTile<MinerDatum>[], ctx: LabelContext): Label[] {
  const out: Label[] = [];
  if (!(ctx.total > 0)) return out;
  for (const t of tiles) {
    if (t.w < 30 || t.h < 15) continue;
    const pct = (t.weight / ctx.total) * 100;
    const kind = t.aggregate ? TileKind.Others : (t.items[0]?.data?.kind ?? TileKind.Plain);
    const glyph = KIND_GLYPH[kind] !== undefined ? `${KIND_GLYPH[kind]} ` : '';
    const bare = t.aggregate ? `${t.items.length} others` : `${glyph}${pct.toFixed(pct >= 10 ? 1 : 2)}%`;
    // Fit the head line to the tile: drop the coin symbol first, then
    // shrink the font (~0.6 em per glyph for this font stack).
    const room = t.w - 6;
    let size = Math.round(Math.max(9, Math.min(t.w / 6, t.h / 4, 22)));
    let head = t.aggregate ? bare : `${bare} ${ctx.symbol}`;
    if (head.length * size * 0.6 > room) head = bare;
    if (head.length * size * 0.6 > room) size = Math.floor(room / (head.length * 0.6));
    if (size < 9) continue;
    const cx = t.x + t.w / 2;
    const cy = t.y + t.h / 2;
    const clip = { x: t.x, y: t.y, w: t.w, h: t.h };
    const twoLines = t.h >= size * 2.6 && t.w >= 50;
    out.push({ text: head, x: cx, y: twoLines ? cy - size * 0.55 : cy, color: '#ffffff', font: `600 ${size}px -apple-system, sans-serif`, clip });
    if (twoLines) {
      const small = Math.max(8, Math.round(size * 0.55));
      const second = t.aggregate
        ? `${pct.toFixed(2)}% · click to expand`
        : shortAddress(t.key, Math.max(6, Math.floor(t.w / (small * 0.62))));
      out.push({ text: second, x: cx, y: cy + size * 0.6, color: 'rgba(255,255,255,0.72)', font: `${small}px Monaco, Consolas, monospace`, clip });
    }
  }
  return out;
}

export function shortAddress(addr: string, maxChars: number): string {
  if (addr.length <= maxChars) return addr;
  const keep = Math.max(2, Math.floor((maxChars - 1) / 2));
  return `${addr.slice(0, keep)}…${addr.slice(-keep)}`;
}

// ── tooltip ────────────────────────────────────────────────────────

/** Optional per-miner facts the host knows from the share window. */
export interface MinerFacts {
  shares?: number;
  /** This miner's share of the window's share COUNT, 0..1. */
  countFraction?: number;
  lastShareAgeS?: number;
  hashrate?: string;
  version?: string;
}

export interface TooltipContext {
  total: number;
  mode: PplnsMode;
  symbol: string;
  mergedSymbol?: string;
  /** Sum of all parent payouts (/current_payouts): the miners' share of
   *  the next block. The denominator for "% of miner payouts", so the
   *  tiles add up to 100%. Never /local_stats block_value_miner: on a
   *  relay that is a projection without fees, and it describes another
   *  template. */
  parentTotal?: number;
  facts?: (address: string) => MinerFacts | undefined;
}

export interface TooltipLine {
  text: string;
  tone?: 'title' | 'strong' | 'muted' | 'warn' | 'accent';
}

const KIND_TEXT: Record<number, string> = {
  [TileKind.ThisNode]: '★ mines on this node',
  [TileKind.OwnerFee]: '⚑ node owner fee',
  [TileKind.Donation]: '◇ donation',
};

/** A share of weight and a share of count this far apart get flagged. */
export const WEIGHT_COUNT_GAP = 0.25;

export function formatAge(s: number): string {
  if (!(s >= 0)) return '';
  if (s < 90) return `${Math.round(s)} s ago`;
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  return `${(s / 3600).toFixed(1)} h ago`;
}

export function tooltipLines(tile: Tile<MinerDatum>, ctx: TooltipContext): TooltipLine[] {
  const share = ctx.total > 0 ? tile.weight / ctx.total : 0;
  const weightName = ctx.mode === 'merged' && ctx.mergedSymbol ? `${ctx.mergedSymbol} weight` : 'PPLNS weight';
  if (tile.aggregate) {
    return [
      { text: `${tile.items.length} others`, tone: 'title' },
      { text: `${(share * 100).toFixed(3)}% of ${weightName} together`, tone: 'strong' },
      { text: 'Each is under the size cut-off; click to lay them out.', tone: 'muted' },
    ];
  }
  const d = tile.items[0]?.data;
  const lines: TooltipLine[] = [{ text: tile.key, tone: 'title' }];
  if (d !== undefined && KIND_TEXT[d.kind] !== undefined) lines.push({ text: KIND_TEXT[d.kind]!, tone: 'accent' });
  lines.push({ text: `${(share * 100).toFixed(2)}% of ${weightName}`, tone: 'strong' });
  if (d !== undefined && d.amount > 0) {
    const of = ctx.parentTotal !== undefined && ctx.parentTotal > 0
      ? ` (${((d.amount / ctx.parentTotal) * 100).toFixed(2)}% of miner payouts)` : '';
    lines.push({ text: `next block: ${d.amount.toFixed(8)} ${ctx.symbol}${of}` });
  }
  if (d !== undefined && ctx.mergedSymbol !== undefined && d.childAmount > 0) {
    const src = d.childSource !== undefined && d.childSource !== '' ? ` · ${d.childSource}` : '';
    lines.push({ text: `${d.childAmount.toFixed(4)} ${ctx.mergedSymbol}${d.childAddress ? ` → ${d.childAddress}` : ''}${src}` });
  }
  const f = ctx.facts?.(tile.key);
  if (f !== undefined) {
    if (f.shares !== undefined) {
      const cnt = f.countFraction !== undefined ? ` (${(f.countFraction * 100).toFixed(2)}% of count)` : '';
      lines.push({ text: `${f.shares} share${f.shares === 1 ? '' : 's'} in window${cnt}` });
    }
    if (f.lastShareAgeS !== undefined) lines.push({ text: `last share ${formatAge(f.lastShareAgeS)}`, tone: 'muted' });
    if (f.hashrate !== undefined) lines.push({ text: f.hashrate, tone: 'muted' });
    if (f.version !== undefined) lines.push({ text: f.version, tone: 'muted' });
    if (ctx.mode === 'parent' && f.countFraction !== undefined && share > 0) {
      const gap = Math.abs(share - f.countFraction) / Math.max(share, f.countFraction);
      if (gap > WEIGHT_COUNT_GAP) {
        lines.push({ text: 'weight ≠ share count: weight follows difficulty and PPLNS decay', tone: 'warn' });
      }
    }
  }
  lines.push({ text: 'click: pin · Esc: unpin · ctrl-click: address explorer', tone: 'muted' });
  return lines;
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}
