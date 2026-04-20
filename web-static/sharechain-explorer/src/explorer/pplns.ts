// PPLNS payload parsing — normalises the two shapes served by
// /sharechain/window (spec §5.1):
//
//   flat:   { "Xaddr": 0.123, ... }
//   merged: { "Xaddr": { amount: 0.123, merged: [...] }, ... }
//
// Into the sorted-by-amount-desc array the hover-zoom treemap wants:
//
//   [{ addr, amt, pct }, ...]
//
// Ported from dashboard.html:5631-5643 verbatim so any cached PPLNS
// computations stay byte-identical across the flag-on boundary.

import type { PluginDescriptor } from '../registry.js';

export interface PPLNSEntry {
  addr: string;
  amt: number;
  pct: number;  // amt / total, in [0,1]
}

/** Accept the two payload shapes and emit a sorted PPLNSEntry[].
 *  Invalid input collapses to an empty array. */
export function parsePPLNS(raw: unknown): PPLNSEntry[] {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return [];
  let total = 0;
  const entries: { addr: string; amt: number }[] = [];
  for (const [addr, v] of Object.entries(raw as Record<string, unknown>)) {
    let amt: number;
    if (typeof v === 'number') {
      amt = v;
    } else if (v !== null && typeof v === 'object' && 'amount' in v) {
      const a = (v as { amount?: unknown }).amount;
      amt = typeof a === 'number' ? a : 0;
    } else {
      amt = 0;
    }
    if (!isFinite(amt) || amt <= 0) continue;
    total += amt;
    entries.push({ addr, amt });
  }
  entries.sort((a, b) => b.amt - a.amt);
  return entries.map((e) => ({
    addr: e.addr,
    amt: e.amt,
    pct: total > 0 ? e.amt / total : 0,
  }));
}

export const PPLNSPlugin: PluginDescriptor = {
  id: 'explorer.pplns.parser',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'util',
  provides: ['pplns.parser'],
  priority: 0,
  capabilities: {
    'pplns.parser': { parsePPLNS },
  },
};
