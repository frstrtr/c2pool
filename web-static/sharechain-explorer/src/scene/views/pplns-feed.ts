// Feed for the PPLNS treemap view, independent of how the JSON arrives
// (fetch on a web page, PplnsBridge invokables in the Qt embed).
//
//   const r = await loadPplnsSnapshot({ payouts, merged, stratum });
//   if (r) view.update(r.snapshot, r.special);
//
// /current_payouts is required. /current_merged_payouts and
// /stratum_stats are optional: if either fails, the treemap still renders
// (no merged children, no ★).

import { addressesFromWorkers, type CurrentMergedPayouts, type CurrentPayouts, type PplnsSnapshot, type SpecialAddresses } from './pplns-model.js';

export interface PayoutSource {
  /** /current_payouts → {address: coins}. */
  payouts(): Promise<unknown>;
  /** /current_merged_payouts → {parent: {amount, merged: [...]}}. */
  merged?(): Promise<unknown>;
  /** /stratum_stats → {pool, workers: {"addr.worker": …}}. */
  stratum?(): Promise<unknown>;
}

export interface LoadedSnapshot {
  snapshot: PplnsSnapshot;
  special: SpecialAddresses;
  /** The merged child's symbol, read from the data (e.g. 'DOGE'), if any. */
  mergedSymbol?: string;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v);

/** The first merged-child symbol present in /current_merged_payouts. */
export function mergedSymbolOf(merged: unknown): string | undefined {
  if (!isObject(merged)) return undefined;
  for (const row of Object.values(merged)) {
    if (!isObject(row) || !Array.isArray(row.merged)) continue;
    for (const m of row.merged) {
      const sym = isObject(m) && typeof m.symbol === 'string' ? m.symbol.trim() : '';
      if (sym !== '') return sym.toUpperCase();
    }
  }
  return undefined;
}

const settle = (p: Promise<unknown> | undefined): Promise<unknown> =>
  p === undefined ? Promise.resolve(null) : p.catch(() => null);

/** Fetch the feeds in parallel. Null when the payouts are unavailable. */
export async function loadPplnsSnapshot(src: PayoutSource): Promise<LoadedSnapshot | null> {
  const [payouts, merged, stratum] = await Promise.all([
    settle(src.payouts()),
    settle(src.merged?.()),
    settle(src.stratum?.()),
  ]);
  if (!isObject(payouts)) return null;
  const snapshot: PplnsSnapshot = { payouts: payouts as CurrentPayouts };
  if (isObject(merged)) snapshot.merged = merged as CurrentMergedPayouts;
  const special: SpecialAddresses = {};
  if (isObject(stratum)) special.thisNode = addressesFromWorkers(stratum.workers);
  const sym = mergedSymbolOf(merged);
  return sym !== undefined ? { snapshot, special, mergedSymbol: sym } : { snapshot, special };
}

/** Wrap an async refresh so overlapping calls collapse: at most one runs
 *  at a time, and calls during a run trigger exactly one more run. */
export function coalesce(run: () => Promise<void>): () => Promise<void> {
  let running: Promise<void> | null = null;
  let again = false;
  const loop = async (): Promise<void> => {
    do {
      again = false;
      try { await run(); } catch { /* the caller reports its own errors */ }
    } while (again);
    running = null;
  };
  return () => {
    if (running !== null) { again = true; return running; }
    running = loop();
    return running;
  };
}
