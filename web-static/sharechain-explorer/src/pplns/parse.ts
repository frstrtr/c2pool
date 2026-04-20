// PPLNS snapshot parser. Accepts:
//
//  (a) The new /pplns/current shape defined in
//      frstrtr/the/docs/c2pool-pplns-view-module-task.md §5.1.
//  (b) Legacy /current_merged_payouts shape: a flat
//      `{ addr: amount | { amount, merged: [...] } }` projection.
//      Backward-compat per spec §5.3 option B.
//
// Unknown / malformed / zero-amount entries are dropped rather than
// throwing, so a single corrupt miner row doesn't break the view.

import type {
  PplnsSnapshot,
  PplnsMiner,
  PplnsMinerDetail,
  MergedPayout,
  MergedSource,
  HashrateSeriesPoint,
  VersionHistoryPoint,
  RecentShare,
} from './types.js';

export function parseSnapshot(raw: unknown): PplnsSnapshot {
  if (raw === null || typeof raw !== 'object') {
    return emptySnapshot();
  }
  const obj = raw as Record<string, unknown>;

  // Shape (a): has top-level `miners` array → new contract.
  if (Array.isArray(obj.miners)) {
    return parseNewShape(obj);
  }

  // Shape (b): flat map keyed by address → legacy /current_merged_payouts.
  return parseLegacyShape(obj);
}

function emptySnapshot(): PplnsSnapshot {
  return {
    totalPrimary: 0,
    mergedChains: [],
    mergedTotals: {},
    schemaVersion: '1.0',
    miners: [],
  };
}

function num(v: unknown, fallback = 0): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function parseMergedEntry(raw: unknown): MergedPayout | null {
  if (raw === null || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  const symbol = str(o.symbol);
  const address = str(o.address);
  const amount = num(o.amount);
  const pct = num(o.pct);
  if (symbol === undefined || address === undefined) return null;
  if (!(amount > 0)) return null;
  const source = parseSource(o.source);
  const out: MergedPayout = { symbol, address, amount, pct };
  if (source !== undefined) out.source = source;
  return out;
}

function parseSource(v: unknown): MergedSource | undefined {
  if (v === 'donation' || v === 'auto-convert' || v === 'explicit') return v;
  return undefined;
}

function parseNewShape(obj: Record<string, unknown>): PplnsSnapshot {
  const totalPrimary = num(obj.total_primary);
  const mergedChains = Array.isArray(obj.merged_chains)
    ? (obj.merged_chains.filter((x) => typeof x === 'string') as readonly string[])
    : [];

  const rawTotals = obj.merged_totals as Record<string, unknown> | undefined;
  const mergedTotals: Record<string, number> = {};
  if (rawTotals !== undefined && rawTotals !== null && typeof rawTotals === 'object') {
    for (const [k, v] of Object.entries(rawTotals)) {
      const n = num(v);
      if (n > 0) mergedTotals[k] = n;
    }
  }

  const minerArr = obj.miners as unknown[];
  const miners: PplnsMiner[] = [];
  for (const entry of minerArr) {
    if (entry === null || typeof entry !== 'object') continue;
    const m = entry as Record<string, unknown>;
    const address = str(m.address);
    const amount = num(m.amount);
    if (address === undefined || !(amount > 0)) continue;
    const miner: PplnsMiner = {
      address,
      amount,
      pct: num(m.pct),
      merged: Array.isArray(m.merged)
        ? m.merged
            .map((x) => parseMergedEntry(x))
            .filter((x): x is MergedPayout => x !== null)
        : [],
    };
    if (typeof m.shares_in_window === 'number') miner.sharesInWindow = m.shares_in_window;
    if (typeof m.hashrate_hps === 'number')     miner.hashrateHps    = m.hashrate_hps;
    if (typeof m.version === 'number')          miner.version        = m.version;
    if (typeof m.desired_version === 'number')  miner.desiredVersion = m.desired_version;
    if (typeof m.last_share_at === 'number')    miner.lastShareAt    = m.last_share_at;
    miners.push(miner);
  }
  // Ensure descending amount order (server should already, but be defensive).
  miners.sort((a, b) => b.amount - a.amount);

  const snap: PplnsSnapshot = {
    totalPrimary: totalPrimary > 0
      ? totalPrimary
      : miners.reduce((s, m) => s + m.amount, 0),
    mergedChains,
    mergedTotals,
    schemaVersion: str(obj.schema_version) ?? '1.0',
    miners,
  };
  const tip = str(obj.tip);
  if (tip !== undefined) snap.tip = tip;
  if (typeof obj.window_size === 'number') snap.windowSize = obj.window_size;
  const coinLabel = str(obj.coin);
  if (coinLabel !== undefined) snap.coin = coinLabel;
  if (typeof obj.computed_at === 'number') snap.computedAt = obj.computed_at;
  return snap;
}

export function parseMinerDetail(raw: unknown): PplnsMinerDetail | null {
  // Per spec §5.2. Returns null on anything that isn't an object — the
  // caller decides how to surface the error (404 / network / parse).
  if (raw === null || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  const address = str(o.address);
  if (address === undefined) return null;

  const detail: PplnsMinerDetail = {
    address,
    inWindow: o.in_window === true,
    merged: Array.isArray(o.merged)
      ? o.merged
          .map((x) => parseMergedEntry(x))
          .filter((x): x is MergedPayout => x !== null)
      : [],
  };
  if (typeof o.amount === 'number')           detail.amount          = o.amount;
  if (typeof o.pct === 'number')              detail.pct             = o.pct;
  if (typeof o.shares_in_window === 'number') detail.sharesInWindow  = o.shares_in_window;
  if (typeof o.shares_total === 'number')     detail.sharesTotal     = o.shares_total;
  if (typeof o.first_seen_at === 'number')    detail.firstSeenAt     = o.first_seen_at;
  if (typeof o.last_share_at === 'number')    detail.lastShareAt     = o.last_share_at;
  if (typeof o.hashrate_hps === 'number')     detail.hashrateHps     = o.hashrate_hps;
  if (typeof o.version === 'number')          detail.version         = o.version;
  if (typeof o.desired_version === 'number')  detail.desiredVersion  = o.desired_version;

  if (Array.isArray(o.hashrate_series)) {
    const pts: HashrateSeriesPoint[] = [];
    for (const p of o.hashrate_series) {
      if (p === null || typeof p !== 'object') continue;
      const po = p as Record<string, unknown>;
      const t = num(po.t, NaN);
      const hps = num(po.hps, NaN);
      if (Number.isFinite(t) && Number.isFinite(hps)) pts.push({ t, hps });
    }
    if (pts.length > 0) detail.hashrateSeries = pts;
  }
  if (Array.isArray(o.version_history)) {
    const pts: VersionHistoryPoint[] = [];
    for (const p of o.version_history) {
      if (p === null || typeof p !== 'object') continue;
      const po = p as Record<string, unknown>;
      const t = num(po.t, NaN);
      const version = num(po.version, NaN);
      if (!Number.isFinite(t) || !Number.isFinite(version)) continue;
      const point: VersionHistoryPoint = { t, version };
      if (typeof po.desired_version === 'number') point.desiredVersion = po.desired_version;
      pts.push(point);
    }
    if (pts.length > 0) detail.versionHistory = pts;
  }
  if (Array.isArray(o.recent_shares)) {
    const rs: RecentShare[] = [];
    for (const p of o.recent_shares) {
      if (p === null || typeof p !== 'object') continue;
      const po = p as Record<string, unknown>;
      const h = str(po.h);
      const t = num(po.t, NaN);
      if (h === undefined || !Number.isFinite(t)) continue;
      const share: RecentShare = { h, t };
      if (typeof po.s === 'number') share.s = po.s;
      if (typeof po.V === 'number') share.V = po.V;
      rs.push(share);
    }
    if (rs.length > 0) detail.recentShares = rs;
  }
  return detail;
}

function parseLegacyShape(obj: Record<string, unknown>): PplnsSnapshot {
  // { "addr": amount | { amount, merged: [{ addr, amount, source }] } }
  // merged entries in legacy shape have `addr` not `address`, sometimes
  // lack `symbol` (implicit DOGE for LTC chains).
  interface LegacyEntry {
    address: string;
    amount: number;
    merged: MergedPayout[];
  }
  const entries: LegacyEntry[] = [];
  const mergedSymbols = new Set<string>();
  const mergedTotals: Record<string, number> = {};

  for (const [addr, v] of Object.entries(obj)) {
    if (typeof addr !== 'string' || addr.length === 0) continue;
    let amount: number;
    let mergedRaw: unknown[] = [];
    if (typeof v === 'number') {
      amount = v;
    } else if (v !== null && typeof v === 'object') {
      const o = v as Record<string, unknown>;
      amount = num(o.amount);
      if (Array.isArray(o.merged)) mergedRaw = o.merged;
    } else {
      continue;
    }
    if (!(amount > 0)) continue;
    const merged: MergedPayout[] = [];
    for (const mr of mergedRaw) {
      if (mr === null || typeof mr !== 'object') continue;
      const mo = mr as Record<string, unknown>;
      const sym = str(mo.symbol) ?? 'DOGE';    // legacy assumed DOGE
      const mAddr = str(mo.address) ?? str(mo.addr);
      const mAmount = num(mo.amount);
      if (mAddr === undefined || !(mAmount > 0)) continue;
      mergedSymbols.add(sym);
      mergedTotals[sym] = (mergedTotals[sym] ?? 0) + mAmount;
      const mp: MergedPayout = {
        symbol: sym,
        address: mAddr,
        amount: mAmount,
        pct: 0, // filled below once per-chain total is known
      };
      const src = parseSource(mo.source);
      if (src !== undefined) mp.source = src;
      merged.push(mp);
    }
    entries.push({ address: addr, amount, merged });
  }

  const totalPrimary = entries.reduce((s, e) => s + e.amount, 0);
  entries.sort((a, b) => b.amount - a.amount);

  const miners: PplnsMiner[] = entries.map((e) => ({
    address: e.address,
    amount: e.amount,
    pct: totalPrimary > 0 ? e.amount / totalPrimary : 0,
    merged: e.merged.map((m) => ({
      ...m,
      pct: (mergedTotals[m.symbol] ?? 0) > 0
        ? m.amount / mergedTotals[m.symbol]!
        : 0,
    })),
  }));

  return {
    totalPrimary,
    mergedChains: [...mergedSymbols].sort(),
    mergedTotals,
    schemaVersion: '1.0',
    miners,
  };
}
