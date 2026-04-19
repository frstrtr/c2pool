// Delta merger — reconciles a window snapshot with an SSE delta.
// Spec contract per c2pool-sharechain-explorer-module-task.md §5.3:
//
//   - Delta returns shares newer than `since`, newest-first.
//   - Client prepends to current window.
//   - Dedup by short-hash.
//   - Slice to windowSize (evicting oldest).
//   - If `fork_switch: true`, drop current window and rebuild from
//     delta.shares (capped at windowSize). Server caps the list at
//     200 in this mode; we re-sort-trust-newest regardless.
//
// Pure function — no DOM, no Host dependency, trivially testable.
// Property-based tests against fast-check are a follow-up.
//
// Provides capability `merger.delta`.

import type { PluginDescriptor } from '../registry.js';

/** Subset of the share shape delta merging cares about: just a
 *  short-hash for dedup/ordering. Full shares pass through as opaque
 *  payloads. No index signature — the constraint is deliberately
 *  minimal so strict interfaces (e.g. ShareForClassify) satisfy it. */
export interface DeltaShare {
  h: string;  // short-hash (16 hex); spec §5 contract — dedup key
}

export interface WindowSnapshot<S extends DeltaShare = DeltaShare> {
  shares: readonly S[];  // newest first (shares[0] is the tip)
  tip?: string;          // short-hash of current tip
  // Optional metadata captured from /sharechain/window and kept in
  // sync across merges. Used by the stat-panel emission (Phase B #10)
  // to preserve parity with the inline dashboard.html renderer.
  chainLength?: number | undefined;
  primaryBlocks?: readonly string[] | undefined;
  dogeBlocks?: readonly string[] | undefined;
  // PPLNS data captured from /sharechain/window pplns_current +
  // pplns fields (Phase B #12 hover-zoom). Orchestrator stores
  // parsed PPLNSEntry[] so render paths don't re-parse on hover.
  pplnsCurrent?: ReadonlyArray<{ addr: string; amt: number; pct: number }> | undefined;
  pplnsByShare?: ReadonlyMap<string, ReadonlyArray<{ addr: string; amt: number; pct: number }>> | undefined;
}

export interface DeltaPayload<S extends DeltaShare = DeltaShare> {
  shares: readonly S[];  // newest first
  count?: number;
  tip?: string;
  fork_switch?: boolean;
  window_size?: number;
  heads?: readonly string[];
  blocks?: readonly string[];
  doge_blocks?: readonly string[];
}

export interface MergeOptions {
  windowSize: number;
  /** Clamp the output; 0 means "no limit, trust server". Default: windowSize. */
  maxShares?: number;
}

export interface MergeResult<S extends DeltaShare = DeltaShare> {
  shares: readonly S[];
  added: readonly S[];           // new shares actually prepended
  evicted: readonly string[];    // short-hashes dropped off the tail
  forkSwitch: boolean;           // true iff delta indicated a fork switch
  tip: string | undefined;
}

/** Merge a delta into the current window. Pure; does NOT mutate inputs. */
export function mergeDelta<S extends DeltaShare>(
  current: WindowSnapshot<S>,
  delta: DeltaPayload<S>,
  opts: MergeOptions,
): MergeResult<S> {
  const windowSize = opts.windowSize;
  const maxShares = opts.maxShares ?? windowSize;
  const cap = maxShares > 0 ? maxShares : Number.POSITIVE_INFINITY;
  const forkSwitch = delta.fork_switch === true;

  if (forkSwitch) {
    // Rebuild from delta alone. Everything current gets evicted.
    const evicted = current.shares.map((s) => s.h);
    const seen = new Set<string>();
    const rebuilt: S[] = [];
    for (const s of delta.shares) {
      if (seen.has(s.h)) continue;
      seen.add(s.h);
      rebuilt.push(s);
      if (rebuilt.length >= cap) break;
    }
    const tip = rebuilt[0]?.h ?? delta.tip;
    return {
      shares: rebuilt,
      added: rebuilt,
      evicted,
      forkSwitch: true,
      tip,
    };
  }

  // Normal prepend + dedup. Iterate delta.shares newest-first and
  // drop any whose short-hash already exists in the current window.
  const existing = new Set(current.shares.map((s) => s.h));
  const added: S[] = [];
  for (const s of delta.shares) {
    if (existing.has(s.h)) continue;
    existing.add(s.h);
    added.push(s);
  }

  const combined: S[] = [...added, ...current.shares];

  // Trim to cap, tracking evictions off the tail.
  const evicted: string[] = [];
  if (combined.length > cap) {
    const overflow = combined.length - cap;
    for (let i = combined.length - overflow; i < combined.length; i++) {
      const drop = combined[i];
      if (drop !== undefined) evicted.push(drop.h);
    }
    combined.length = cap;
  }

  const tip = combined[0]?.h ?? current.tip ?? delta.tip;
  return { shares: combined, added, evicted, forkSwitch: false, tip };
}

export const DeltaMergerPlugin: PluginDescriptor = {
  id: 'explorer.delta.merger-default',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'util',
  provides: ['merger.delta'],
  priority: 0,
  capabilities: {
    'merger.delta': { mergeDelta },
  },
};
