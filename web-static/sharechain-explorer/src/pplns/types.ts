// PPLNS View — data types.
//
// Mirrors the /pplns/current payload shape from
// frstrtr/the/docs/c2pool-pplns-view-module-task.md §5.1. Treated as
// authoritative; the parser (parse.ts) accepts the old
// /current_merged_payouts shape and projects it onto these types for
// backward-compat during the migration window (spec §5.3 option B).

import type { ExplorerError } from '../errors.js';
import type { Transport } from '../transport/types.js';

export type MergedSource = 'donation' | 'auto-convert' | 'explicit';

export interface MergedPayout {
  symbol: string;
  address: string;
  amount: number;
  pct: number;
  source?: MergedSource;
}

export interface PplnsMiner {
  address: string;
  amount: number;
  pct: number;
  sharesInWindow?: number;
  hashrateHps?: number;
  version?: number;
  desiredVersion?: number;
  lastShareAt?: number;
  merged: readonly MergedPayout[];
}

export interface PplnsSnapshot {
  tip?: string;
  windowSize?: number;
  coin?: string;
  totalPrimary: number;
  mergedChains: readonly string[];
  mergedTotals: Readonly<Record<string, number>>;
  computedAt?: number;
  schemaVersion: string;
  miners: readonly PplnsMiner[];
}

// ── Coin descriptor extension fields ───────────────────────────────

export interface MergedChainDescriptor {
  symbol: string;
  displayLabel: string;
  color: string;
  tooltipLabel: string;
  addressExplorer?: string;
  /** Render an empty "— no $SYMBOL" row even when the miner has no
   *  entry for this chain. Default false. */
  alwaysShow?: boolean;
}

export type BadgeSeverity = 'ok' | 'signaling' | 'warn' | 'muted';

export interface VersionBadge {
  label: string;
  color: string;
  severity: BadgeSeverity;
}

export interface VersionBadgeConfig {
  palette: Readonly<Record<string, VersionBadge>>;
  classify(miner: Pick<PplnsMiner, 'version' | 'desiredVersion'>): string;
}

export interface CoinPplnsDescriptor {
  /** Default palette per spec §4.3 if left undefined. */
  mergedChains: readonly MergedChainDescriptor[];
  versionBadges: VersionBadgeConfig;
  /** Hashrate formatter — pure, no units in code paths. Default formats
   *  raw H/s as k/M/G/T with 2 decimals. */
  formatHashrate?: (hps: number) => string;
  /** Block-explorer URL prefix for the primary address. Concatenated
   *  with the address (no trailing separator logic — spec decides). */
  addressExplorer?: string;
}

// ── Public API — mirrors spec §6 ────────────────────────────────────

export type ViewMode = 'full' | 'compact' | 'embed';
export type HeightMode = 'adaptive' | `fixed:${number}` | 'fill';
export type SortKey = 'amount' | 'hashrate' | 'address' | 'version';

export interface PplnsViewOptions {
  container: string | HTMLElement;
  transport: Transport;
  coin: CoinPplnsDescriptor;
  mode?: ViewMode;
  heightMode?: HeightMode;
  minCellPx?: number;
  sort?: SortKey;
  filter?: ((miner: PplnsMiner) => boolean) | null;
  search?: string | null;
  showVersionBadge?: boolean;
  showHashrate?: boolean;
  showMerged?: boolean;
  refreshIntervalMs?: number | null;
  onMinerClick?: ((miner: PplnsMiner) => void) | null;
  onMinerOpenLink?: ((miner: PplnsMiner, symbol?: string) => void) | null;
  onError?: ((err: ExplorerError) => void) | null;
}

export interface PplnsState {
  snapshot: PplnsSnapshot | null;
  sort: SortKey;
  filter: ((miner: PplnsMiner) => boolean) | null;
  search: string | null;
  lastTip: string | null;
}

export interface PplnsController {
  refresh(): Promise<void>;
  setSort(key: SortKey): void;
  setFilter(predicate: ((miner: PplnsMiner) => boolean) | null): void;
  setSearch(prefix: string | null): void;
  selectMiner(address: string | null): void;
  getState(): Readonly<PplnsState>;
  destroy(): Promise<void>;
  on(event: PplnsEvent, cb: (payload: unknown) => void): () => void;
}

export type PplnsEvent =
  | 'tip-changed'
  | 'miner-clicked'
  | 'error'
  | 'ready';
