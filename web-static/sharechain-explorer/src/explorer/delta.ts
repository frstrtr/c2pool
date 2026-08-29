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

/** Subset of the share shape delta merging cares about: a short-hash
 *  plus an optional full 64-hex hash. Full shares pass through as opaque
 *  payloads. No index signature — the constraint is deliberately
 *  minimal so strict interfaces (e.g. ShareForClassify) satisfy it.
 *
 *  Dedup/eviction keys on the FULL hash when present (H), falling back
 *  to the short hash. On coins whose share hashes carry many leading
 *  zero nibbles (DASH: ~11-12), the 16-hex short has only ~20 bits of
 *  entropy and collides within a single window (measured: 4320 entries,
 *  4227 distinct shorts). A short-hash dedup key would then collapse the
 *  client window below windowSize, so the cap trim never fires and the
 *  tail eviction (and its dying animation) is silently suppressed.
 *  On coins with no collisions (LTC), keying on H is byte-identical. */
export interface DeltaShare {
  h: string;   // short-hash (16 hex); dedup fallback when H absent
  H?: string;  // full hash (64 hex); preferred dedup key when present
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
  evicted: readonly string[];    // hashes dropped off the tail (full hash H when present, else short h)
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
    const evicted = current.shares.map((s) => s.H ?? s.h);
    const seen = new Set<string>();
    const rebuilt: S[] = [];
    for (const s of delta.shares) {
      const k = s.H ?? s.h;
      if (seen.has(k)) continue;
      seen.add(k);
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
  const existing = new Set(current.shares.map((s) => s.H ?? s.h));
  const added: S[] = [];
  for (const s of delta.shares) {
    const k = s.H ?? s.h;
    if (existing.has(k)) continue;
    existing.add(k);
    added.push(s);
  }

  const combined: S[] = [...added, ...current.shares];

  // Trim to cap, tracking evictions off the tail. Report the FULL hash
  // (fallback to short) so downstream consumers — which key old-position
  // maps on the same full hash — resolve the evicted share's dying cell.
  const evicted: string[] = [];
  if (combined.length > cap) {
    const overflow = combined.length - cap;
    for (let i = combined.length - overflow; i < combined.length; i++) {
      const drop = combined[i];
      if (drop !== undefined) evicted.push(drop.H ?? drop.h);
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
