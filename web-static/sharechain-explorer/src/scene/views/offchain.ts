// ▣ off-chain block shares for the Fluid share-chain grid.
//
// A share can solve a block and still not be on the best sharechain (a
// same-parent sibling won the head race). The block is fine and paid; the
// finder lost that one share's PPLNS weight. Such a share is not in the
// window's share list, so the grid shows it as an extra ▣ cell, placed by
// its timestamp among the window's shares.
//
// offChainBlocks() selects exactly the rows that the dashboard's "Blocks in
// Window" counts as off-chain (c2pWindowBlocks in dashboard.html): ledger
// rows (/recent_blocks) no older than the window's oldest share, of the
// page's coin, whose share is not in the window. A parity test pins the
// two together.

import type { GridShare } from './sharechain-grid.js';

/** A /recent_blocks row (only the fields used here). */
export interface BlockRow {
  hash?: string;
  share?: string | null;
  ts?: number;
  chain?: string;
  height?: number;
  miner?: string;
  explorer_url?: string;
  status?: string;
}

/** A ▣ cell: a GridShare that stands for an off-chain block share. */
export interface OffChainCell extends GridShare {
  offChain: true;
  block: BlockRow;
}

export const isOffChainCell = (s: GridShare): s is OffChainCell => (s as Partial<OffChainCell>).offChain === true;

/** Ledger rows the dashboard counts as off-chain for this window. */
export function offChainBlocks(
  blocks: readonly BlockRow[] | null | undefined,
  shares: readonly GridShare[],
  symbol: string | undefined,
): BlockRow[] {
  const inFull = new Set<string>();
  const inShort = new Set<string>();
  let oldest = Infinity;
  for (const s of shares) {
    if (s.H) inFull.add(s.H);
    else if (s.h) inShort.add(s.h);
    if (typeof s.t === 'number' && s.t > 0 && s.t < oldest) oldest = s.t;
  }
  const out: BlockRow[] = [];
  const seen = new Set<string>();
  for (const b of blocks ?? []) {
    if (!b || typeof b.ts !== 'number' || !(b.ts >= oldest)) continue;
    if (b.chain && symbol && String(b.chain).toUpperCase() !== String(symbol).toUpperCase()) continue;
    const key = b.share || b.hash;
    if (!key || seen.has(key)) continue;
    seen.add(key);
    const hit = inFull.has(key) || (b.hash !== undefined && inFull.has(b.hash)) || inShort.has(key.substring(0, 16));
    if (!hit) out.push(b);
  }
  return out;
}

/** The window with one ▣ cell per off-chain row, inserted by timestamp
 *  (the window is newest first). Ties go after the window's share. */
export function withOffChainCells(shares: readonly GridShare[], rows: readonly BlockRow[]): GridShare[] {
  if (rows.length === 0) return shares.slice();
  const cells: OffChainCell[] = rows
    .map((b): OffChainCell => {
      const cell: OffChainCell = { H: `offchain:${b.share || b.hash || ''}`, t: b.ts ?? 0, offChain: true, block: b };
      if (b.miner) cell.m = b.miner;
      return cell;
    })
    .sort((a, b) => (b.t ?? 0) - (a.t ?? 0));
  const out: GridShare[] = [];
  let j = 0;
  for (const s of shares) {
    const st = typeof s.t === 'number' ? s.t : -Infinity;
    while (j < cells.length && (cells[j]!.t ?? 0) > st) out.push(cells[j++]!);
    out.push(s);
  }
  while (j < cells.length) out.push(cells[j++]!);
  return out;
}

/** A ledger row's explorer link, only when it is plain http(s). The value
 *  comes from the node; a javascript: or data: URL would otherwise run in
 *  a new window that inherits the dashboard's origin. */
export function safeExplorerUrl(url: unknown): string | null {
  return typeof url === 'string' && /^https?:\/\//i.test(url.trim()) ? url.trim() : null;
}

/** Hover text for a ▣ cell. Never says "block lost": the block was paid. */
export function offChainLines(b: BlockRow, nowS: number): string[] {
  const lines = [
    `▣ solved block${typeof b.height === 'number' ? ` ${b.height}` : ''}${b.chain ? ` (${b.chain})` : ''}`,
    'share not on the best sharechain — finder lost one share of PPLNS weight',
  ];
  if (b.miner) lines.push(`finder ${b.miner}`);
  if (typeof b.ts === 'number' && nowS >= b.ts) {
    const s = nowS - b.ts;
    lines.push(s < 5400 ? `${Math.round(s / 60)} min ago` : `${(s / 3600).toFixed(1)} h ago`);
  }
  return lines;
}
