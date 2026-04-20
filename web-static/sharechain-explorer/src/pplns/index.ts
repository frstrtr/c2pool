// PPLNS View — public entry.
//
// Exports the full type surface + two constructors:
//   init(opts): browser/Qt; fetches /pplns/current via Transport.
//   demo(opts): synthetic seeded miners; no network.
//
// Returns a PplnsController matching the spec §6 contract. Subscribes
// to the Transport tip stream when available; falls back to polling if
// the Transport has no subscribeStream (e.g. a test stub).

import type { Transport } from '../transport/types.js';
import { PendingTracker } from '../abort.js';
import type { ExplorerError } from '../errors.js';
import { parseSnapshot, parseMinerDetail } from './parse.js';
import { render, resolveContainer } from './render.js';
import { LTC_COIN_PPLNS_DESCRIPTOR } from './classify.js';
import { renderMinerDetail, type DetailPanelHandle } from './detail.js';
import {
  renderToolbar,
  minerVersionKey,
  type ToolbarState,
} from './toolbar.js';
import type {
  PplnsController,
  PplnsEvent,
  PplnsMiner,
  PplnsSnapshot,
  PplnsState,
  PplnsViewOptions,
  SortKey,
  CoinPplnsDescriptor,
} from './types.js';

export type {
  PplnsController,
  PplnsEvent,
  PplnsMiner,
  PplnsSnapshot,
  PplnsState,
  PplnsViewOptions,
  CoinPplnsDescriptor,
};
export { parseSnapshot, render, LTC_COIN_PPLNS_DESCRIPTOR };

const DEFAULTS = {
  mode:              'full' as const,
  heightMode:        'adaptive' as const,
  minCellPx:         28,
  sort:              'amount' as SortKey,
  showVersionBadge:  true,
  showHashrate:      true,
  showMerged:        true,
  refreshIntervalMs: null as number | null,
};

export const PplnsView = {
  init(options: PplnsViewOptions): PplnsController {
    return buildController(options, false);
  },
  demo(options: Omit<PplnsViewOptions, 'transport'> & {
    seed?: number;
    minerCount?: number;
  }): PplnsController {
    const transport = createDemoTransport({
      seed: options.seed ?? 42,
      minerCount: options.minerCount ?? 40,
    });
    return buildController({ ...options, transport }, true);
  },
};

// ── Controller ────────────────────────────────────────────────────

function buildController(
  options: PplnsViewOptions,
  isDemo: boolean,
): PplnsController {
  const container = resolveContainer(options.container);
  if (container === null) {
    throw new Error('PplnsView.init: container not found');
  }
  const coin: CoinPplnsDescriptor = options.coin;
  const transport = options.transport;
  const tracker = new PendingTracker();
  const state: PplnsState = {
    snapshot: null,
    sort: options.sort ?? DEFAULTS.sort,
    filter: options.filter ?? null,
    search: options.search ?? null,
    lastTip: null,
  };
  const listeners = new Map<PplnsEvent, Set<(p: unknown) => void>>();
  let destroyed = false;
  let abortCtl: AbortController | null = null;
  let streamSub: { unsubscribe(): void } | null = null;
  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let detailPanel: DetailPanelHandle | null = null;
  let detailAbortCtl: AbortController | null = null;

  // Split the caller's container into a toolbar row + grid area so
  // render() can clear the grid without wiping the toolbar. When
  // showToolbar is false the grid takes the full container.
  const showToolbar = options.showToolbar ?? true;
  while (container.firstChild !== null) {
    container.removeChild(container.firstChild);
  }
  container.style.display = 'flex';
  container.style.flexDirection = 'column';
  const toolbarEl = showToolbar ? document.createElement('div') : null;
  if (toolbarEl !== null) {
    toolbarEl.style.flex = '0 0 auto';
    container.appendChild(toolbarEl);
  }
  const gridEl = document.createElement('div');
  gridEl.style.flex = '1 1 auto';
  gridEl.style.minHeight = '0';
  gridEl.style.position = 'relative';
  container.appendChild(gridEl);

  // Version-filter state lives alongside the existing filter (options.filter
  // still applies as an outer and; toolbar chips refine further).
  let versionKeys: Set<string> = new Set();
  const applyCombinedFilter = (): void => {
    const userFilter = options.filter ?? null;
    if (versionKeys.size === 0) {
      state.filter = userFilter;
      return;
    }
    const keys = versionKeys;
    const predicate = (m: PplnsMiner): boolean => {
      if (!keys.has(minerVersionKey(m, coin))) return false;
      return userFilter === null || userFilter(m);
    };
    state.filter = predicate;
  };

  const emit = (ev: PplnsEvent, payload: unknown) => {
    const set = listeners.get(ev);
    if (set === undefined) return;
    for (const cb of Array.from(set)) {
      try { cb(payload); } catch { /* caller error — swallow */ }
    }
  };

  // Default click handler: fetch miner detail, render the drill-down
  // panel. Callers can override by supplying their own onMinerClick.
  const openDetailPanel = async (address: string): Promise<void> => {
    if (detailPanel !== null) {
      detailPanel.close();
      detailPanel = null;
    }
    if (detailAbortCtl !== null) detailAbortCtl.abort();
    detailAbortCtl = new AbortController();
    try {
      const raw = await tracker.track(
        transport.fetchMinerDetail(address, { signal: detailAbortCtl.signal }),
      );
      if (destroyed) return;
      const detail = parseMinerDetail(raw);
      if (detail === null) {
        emit('error', { type: 'parse', message: 'Invalid miner detail payload' });
        return;
      }
      detailPanel = renderMinerDetail({
        host: gridEl,
        detail,
        coin,
        onClose: () => { detailPanel = null; },
      });
    } catch (err) {
      if (destroyed) return;
      const typed = asExplorerError(err);
      emit('error', typed);
      if (options.onError !== undefined && options.onError !== null) {
        options.onError(typed);
      }
    }
  };

  const userClickHandler = options.onMinerClick;
  const clickHandler = (miner: PplnsMiner): void => {
    emit('miner-clicked', miner);
    if (userClickHandler !== undefined && userClickHandler !== null) {
      userClickHandler(miner);
    } else {
      void openDetailPanel(miner.address);
    }
  };

  const paintToolbar = (): void => {
    if (toolbarEl === null) return;
    const ts: ToolbarState = {
      sort:              state.sort,
      search:            state.search ?? '',
      activeVersionKeys: versionKeys,
    };
    renderToolbar({
      host: toolbarEl,
      state: ts,
      snapshot: state.snapshot,
      coin,
      callbacks: {
        onSortChange: (key) => {
          state.sort = key;
          paintFromState();
        },
        onSearchChange: (prefix) => {
          state.search = prefix.length > 0 ? prefix : null;
          paintFromState();
        },
        onVersionKeysChange: (next) => {
          versionKeys = new Set(next);
          applyCombinedFilter();
          paintFromState();
        },
      },
    });
  };

  const paintFromState = () => {
    if (destroyed) return;
    paintToolbar();
    if (state.snapshot === null) return;
    render({
      container: gridEl,
      snapshot: applyViewTransforms(state.snapshot, state),
      coin,
      opts: {
        minCellPx:        options.minCellPx        ?? DEFAULTS.minCellPx,
        showVersionBadge: options.showVersionBadge ?? DEFAULTS.showVersionBadge,
        showHashrate:     options.showHashrate     ?? DEFAULTS.showHashrate,
        showMerged:       options.showMerged       ?? DEFAULTS.showMerged,
      },
      onMinerClick: clickHandler,
    });
  };

  const refresh = async (): Promise<void> => {
    if (destroyed) return;
    if (abortCtl !== null) abortCtl.abort();
    abortCtl = new AbortController();
    try {
      const raw = await tracker.track(
        transport.fetchCurrentPayouts({ signal: abortCtl.signal }),
      );
      if (destroyed) return;
      const snapshot = parseSnapshot(raw);
      state.snapshot = snapshot;
      state.lastTip  = snapshot.tip ?? state.lastTip;
      paintFromState();
      emit('ready', snapshot);
    } catch (err) {
      if (destroyed) return;
      const typed = asExplorerError(err);
      emit('error', typed);
      if (options.onError !== undefined && options.onError !== null) {
        options.onError(typed);
      }
    }
  };

  // Wire tip stream (best-effort) — refetch on every tip event.
  if (typeof transport.subscribeStream === 'function') {
    streamSub = transport.subscribeStream(
      () => {
        emit('tip-changed', state.lastTip);
        void refresh();
      },
      (err) => emit('error', err),
      () => { /* reconnect — no action beyond next tip */ },
    );
  }

  if (options.refreshIntervalMs !== null &&
      options.refreshIntervalMs !== undefined &&
      options.refreshIntervalMs > 0) {
    pollTimer = setInterval(() => { void refresh(); }, options.refreshIntervalMs);
  }

  // Initial fetch.
  void refresh();

  // ResizeObserver → repaint on grid area resize. Toolbar sits above
  // the grid and doesn't need to be observed.
  const resize = isDemo || typeof ResizeObserver === 'undefined'
    ? null
    : new ResizeObserver(() => { paintFromState(); });
  if (resize !== null) resize.observe(gridEl);

  const controller: PplnsController = {
    refresh,
    setSort(key) {
      state.sort = key;
      paintFromState();
    },
    setFilter(pred) {
      state.filter = pred;
      paintFromState();
    },
    setSearch(prefix) {
      state.search = prefix;
      paintFromState();
    },
    selectMiner(address) {
      if (address === null) {
        if (detailPanel !== null) {
          detailPanel.close();
          detailPanel = null;
        }
        return;
      }
      const miner = state.snapshot?.miners.find((m) => m.address === address);
      if (miner !== undefined) clickHandler(miner);
    },
    getState() {
      return { ...state };
    },
    async destroy() {
      if (destroyed) return;
      destroyed = true;
      if (abortCtl !== null) abortCtl.abort();
      if (detailAbortCtl !== null) detailAbortCtl.abort();
      if (detailPanel !== null) detailPanel.close();
      if (streamSub !== null) streamSub.unsubscribe();
      if (pollTimer !== null) clearInterval(pollTimer);
      if (resize !== null) resize.disconnect();
      listeners.clear();
      await tracker.settled();
      // Clear DOM last so users can inspect state.
      while (container.firstChild !== null) {
        container.removeChild(container.firstChild);
      }
    },
    on(event, cb) {
      if (!listeners.has(event)) listeners.set(event, new Set());
      listeners.get(event)!.add(cb);
      return () => listeners.get(event)?.delete(cb);
    },
  };
  return controller;
}

function applyViewTransforms(snap: PplnsSnapshot, state: PplnsState): PplnsSnapshot {
  let miners: readonly PplnsMiner[] = snap.miners;
  if (state.filter !== null) {
    miners = miners.filter(state.filter);
  }
  if (state.search !== null && state.search.length > 0) {
    const prefix = state.search;
    miners = miners.filter((m) => m.address.startsWith(prefix));
  }
  switch (state.sort) {
    case 'amount':
      miners = [...miners].sort((a, b) => b.amount - a.amount);
      break;
    case 'hashrate':
      miners = [...miners].sort((a, b) =>
        (b.hashrateHps ?? 0) - (a.hashrateHps ?? 0));
      break;
    case 'address':
      miners = [...miners].sort((a, b) =>
        a.address.localeCompare(b.address));
      break;
    case 'version':
      miners = [...miners].sort((a, b) =>
        (b.version ?? 0) - (a.version ?? 0));
      break;
  }
  return { ...snap, miners };
}

function asExplorerError(e: unknown): ExplorerError {
  if (typeof e === 'object' && e !== null && 'type' in e) {
    return e as ExplorerError;
  }
  if (e instanceof Error) {
    return { type: 'internal', message: e.message };
  }
  return { type: 'internal', message: String(e) };
}

// ── Demo transport (seeded synthetic payouts) ─────────────────────

interface DemoCfg { seed: number; minerCount: number; }

function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return () => {
    t = (t + 0x6d2b79f5) >>> 0;
    let r = t;
    r = Math.imul(r ^ (r >>> 15), r | 1);
    r ^= r + Math.imul(r ^ (r >>> 7), r | 61);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

function createDemoTransport(cfg: DemoCfg): Transport {
  const rng = mulberry32(cfg.seed);
  const miners: PplnsMiner[] = [];
  const addrChars = 'LMXYTFabcdef0123456789';
  for (let i = 0; i < cfg.minerCount; i++) {
    let a = '';
    for (let j = 0; j < 34; j++) {
      a += addrChars[Math.floor(rng() * addrChars.length)];
    }
    // Log-normal amount.
    const amount = Math.exp(rng() * 5 - 1) * 0.0001;
    const verRoll = rng();
    const version = verRoll < 0.7 ? 36 : 35;
    const desiredVersion = version === 36 ? 36 : (rng() < 0.5 ? 36 : 35);
    miners.push({
      address: a,
      amount,
      pct: 0,
      sharesInWindow: Math.floor(rng() * 200),
      hashrateHps: Math.floor(rng() * 5e8),
      version,
      desiredVersion,
      lastShareAt: 1776551000 - Math.floor(rng() * 4320),
      merged: rng() < 0.7
        ? [{ symbol: 'DOGE', address: 'D' + a.slice(1),
             amount: amount * (30 + rng() * 20), pct: 0 }]
        : [],
    });
  }
  miners.sort((a, b) => b.amount - a.amount);
  const total = miners.reduce((s, m) => s + m.amount, 0);
  for (const m of miners) m.pct = total > 0 ? m.amount / total : 0;
  const mergedTotal = miners.reduce((s, m) =>
    s + (m.merged[0]?.amount ?? 0), 0);
  for (const m of miners) {
    if (m.merged.length > 0 && mergedTotal > 0) {
      (m.merged[0] as { pct: number }).pct = m.merged[0]!.amount / mergedTotal;
    }
  }
  const snapshot = {
    tip: 'DEMO' + cfg.seed.toString(16),
    window_size: 4320,
    coin: 'LTC',
    total_primary: total,
    merged_chains: ['DOGE'],
    merged_totals: { DOGE: mergedTotal },
    computed_at: 1776551000,
    schema_version: '1.0',
    miners: miners.map((m) => ({
      address: m.address,
      amount: m.amount,
      pct: m.pct,
      shares_in_window: m.sharesInWindow,
      hashrate_hps: m.hashrateHps,
      version: m.version,
      desired_version: m.desiredVersion,
      last_share_at: m.lastShareAt,
      merged: m.merged,
    })),
  };
  const stub = async <T>(result: T): Promise<T> =>
    new Promise((r) => setTimeout(() => r(result), 0));
  return {
    kind: 'demo',
    fetchWindow:         () => stub({}),
    fetchTip:            () => stub({ hash: snapshot.tip }),
    fetchDelta:          () => stub({ shares: [] }),
    fetchStats:          () => stub({}),
    fetchShareDetail:    () => stub({}),
    negotiate:           async () => ({ apiVersion: '1.0.0' }),
    fetchCurrentPayouts: () => stub(snapshot),
    fetchMinerDetail:    (address) => stub(synthMinerDetail(
      miners.find((m) => m.address === address), cfg.seed)),
    subscribeStream:     () => ({ unsubscribe: () => { /* noop */ } }),
  };
}

function synthMinerDetail(
  miner: PplnsMiner | undefined,
  seed: number,
): unknown {
  if (miner === undefined) return { error: 'miner_not_found' };
  const rng = mulberry32((seed * 7919) >>> 0);
  const now = Math.floor(Date.now() / 1000);
  const base = miner.hashrateHps ?? 0;
  const series = [];
  for (let i = 30; i >= 0; i--) {
    const jitter = 0.85 + rng() * 0.3;
    series.push({ t: now - i * 120, hps: Math.max(0, Math.floor(base * jitter)) });
  }
  // Simulate version signalling in the last third of the window.
  const history = miner.version === 36
    ? [{ t: now - 8000, version: 36, desired_version: 36 }]
    : [
        { t: now - 10000, version: 35, desired_version: 35 },
        { t: now - 4000,  version: 35, desired_version: 36 },
      ];
  const recent = [];
  const shareHashChars = '0123456789abcdef';
  for (let i = 0; i < 12; i++) {
    let h = '';
    for (let j = 0; j < 16; j++) {
      h += shareHashChars[Math.floor(rng() * 16)];
    }
    recent.push({
      h,
      t: now - i * 60 - Math.floor(rng() * 30),
      s: rng() < 0.08 ? 1 : 0,
      V: miner.version ?? 36,
    });
  }
  return {
    address: miner.address,
    in_window: true,
    amount: miner.amount,
    pct: miner.pct,
    shares_in_window: miner.sharesInWindow ?? 0,
    shares_total:     (miner.sharesInWindow ?? 0) + Math.floor(rng() * 5000),
    first_seen_at:    now - 86400 * 7 - Math.floor(rng() * 86400 * 30),
    last_share_at:    miner.lastShareAt ?? now,
    hashrate_hps:     miner.hashrateHps ?? 0,
    hashrate_series:  series,
    version:          miner.version,
    desired_version:  miner.desiredVersion,
    version_history:  history,
    merged: miner.merged.map((m) => ({ ...m, source: 'auto-convert' })),
    recent_shares: recent,
  };
}
