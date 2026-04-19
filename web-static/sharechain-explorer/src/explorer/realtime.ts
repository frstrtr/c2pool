// Realtime orchestrator — wires Transport subscribeStream + fetchDelta
// + mergeDelta + Animator + renderer into the complete live-updates
// flow. Decomposed so the state machine (RealtimeOrchestrator) is
// pure and testable in Node; the DOM/RAF adapter (createRealtime)
// is a thin wrapper.
//
// Behaviour (spec §5 + §6):
//   1. start() fetches the full window, then subscribes to the tip
//      stream.
//   2. Each tip event triggers fetchDelta(since=currentTip).
//   3. mergeDelta → if fork_switch, full refresh. Otherwise apply
//      new shares and build an AnimationPlan.
//   4. If already animating, queue the new plan (current tip
//      sequence wins — out-of-order tips ignored).
//   5. If added-count ≥ skipAnimationThreshold, skip the animation
//      and render directly.
//   6. renderer loop paints each RAF frame until animation idle.
//
// Provides capability `realtime.orchestrator`.

import type { PluginDescriptor } from '../registry.js';
import type {
  Transport,
  TipEvent,
  RequestOptions,
  StreamSubscription,
} from '../transport/types.js';
import type { ExplorerError } from '../errors.js';
import type { GridLayout } from './grid-layout.js';
import { computeGridLayout } from './grid-layout.js';
import type {
  ColorPalette,
  ShareForClassify,
  UserContext,
} from './colors.js';
import { LTC_COLOR_PALETTE } from './colors.js';
import {
  mergeDelta,
  type DeltaPayload,
  type WindowSnapshot,
} from './delta.js';
import { parsePPLNS, type PPLNSEntry } from './pplns.js';
import {
  buildAnimationPlan,
  createAnimationController,
  SKIP_ANIMATION_NEW_COUNT_THRESHOLD,
  type AnimationController,
  type AnimationPlan,
  type FrameSpec,
} from './animator.js';
import {
  buildAnimatedPaintProgram,
  createGridRenderer,
  executePaintProgram,
  type PaintCommand,
  type GridRenderer,
} from './grid-paint.js';
import { getColor } from './colors.js';

export interface LayoutParams {
  cellSize: number;
  gap: number;
  marginLeft: number;
  minHeight: number;
}

const DEFAULT_LAYOUT_PARAMS: LayoutParams = Object.freeze({
  cellSize: 10,
  gap: 1,
  marginLeft: 38,
  minHeight: 40,
});

export interface RealtimeConfig {
  transport: Transport;
  userContext: UserContext;
  palette?: Readonly<ColorPalette>;
  windowSize?: number;
  hashOf?: (share: ShareForClassify) => string;
  layoutParams?: Partial<LayoutParams>;
  containerWidth: () => number;
  skipAnimationThreshold?: number;
  backgroundColor?: string;
  fastAnimation?: boolean;
  /** Called whenever a structured ExplorerError surfaces from the
   *  Transport or contract-validation path. */
  onError?: (err: ExplorerError) => void;
}

export interface RealtimeStats {
  shares: number;
  chainLength: number | null;
  verified: number;
  mine: number;
  stale: number;         // share.s === 1
  dead: number;          // share.s === 2
  fee: number;           // share.fee truthy
  v36native: number;     // share.V >= shareVersion threshold
  v36signaling: number;  // share.V < threshold && share.dv >= threshold
  primaryBlocks: number;
  dogeBlocks: number;
}

export interface RealtimeState {
  window: WindowSnapshot<ShareForClassify>;
  animating: boolean;
  hasQueued: boolean;
  started: boolean;
  shareCount: number;
  lastAppliedTip: string | null;
  deltaInFlight: boolean;
  stats: RealtimeStats;
}

/** Pure state machine — no DOM, no requestAnimationFrame. Drive it
 *  via start()/stop() and fetch frames via currentFrame(now). */
export class RealtimeOrchestrator {
  private readonly config: Required<Omit<RealtimeConfig, 'onError' | 'layoutParams'>> & {
    onError?: (err: ExplorerError) => void;
    layoutParams: LayoutParams;
  };
  private readonly anim: AnimationController;
  private window: WindowSnapshot<ShareForClassify> = { shares: [] };
  private subscription: StreamSubscription | null = null;
  private abort: AbortController | null = null;
  private _started = false;
  private _stopped = false;
  private _deltaInFlight = false;
  private _lastAppliedTip: string | null = null;
  private _pendingTip: string | null = null;
  private _hasQueued = false;
  private _currentLayout: GridLayout | null = null;
  private _statsCache: RealtimeStats | null = null;
  private _statsTipAtCompute: string | null = null;

  constructor(config: RealtimeConfig) {
    const layoutParams: LayoutParams = {
      ...DEFAULT_LAYOUT_PARAMS,
      ...(config.layoutParams ?? {}),
    };
    this.config = {
      transport: config.transport,
      userContext: config.userContext,
      palette: config.palette ?? LTC_COLOR_PALETTE,
      windowSize: config.windowSize ?? 4320,
      hashOf: config.hashOf ?? ((s) => (s as unknown as { h: string }).h),
      containerWidth: config.containerWidth,
      skipAnimationThreshold: config.skipAnimationThreshold ?? SKIP_ANIMATION_NEW_COUNT_THRESHOLD,
      backgroundColor: config.backgroundColor ?? '#0d0d1a',
      fastAnimation: config.fastAnimation ?? false,
      layoutParams,
      ...(config.onError ? { onError: config.onError } : {}),
    };
    this.anim = createAnimationController();
  }

  async start(): Promise<void> {
    if (this._started) return;
    this._started = true;
    this._stopped = false;
    this.abort = new AbortController();
    await this.rebuildWindow();
    this.subscribe();
  }

  async stop(): Promise<void> {
    if (!this._started) return;
    this._stopped = true;
    this._started = false;  // allow a subsequent start() (toggle support)
    this.abort?.abort();
    this.subscription?.unsubscribe();
    this.subscription = null;
    this.anim.reset();
  }

  /** Force a full window re-fetch (e.g. operator clicked refresh). */
  async refresh(): Promise<void> {
    if (!this._started || this._stopped) return;
    await this.rebuildWindow();
  }

  getState(): Readonly<RealtimeState> {
    return {
      window: this.window,
      animating: this.anim.isRunning(),
      hasQueued: this._hasQueued,
      started: this._started,
      shareCount: this.window.shares.length,
      lastAppliedTip: this._lastAppliedTip,
      deltaInFlight: this._deltaInFlight,
      stats: this.currentStats(),
    };
  }

  /** Compute a stat snapshot from the current window. Cached by
   *  tip-hash so repeated polls on the same tip are O(1). */
  private currentStats(): RealtimeStats {
    if (this._statsCache !== null && this._statsTipAtCompute === this._lastAppliedTip) {
      return this._statsCache;
    }
    const threshold = this.config.userContext.shareVersion;
    const myAddr = this.config.userContext.myAddress;
    const s: RealtimeStats = {
      shares: this.window.shares.length,
      chainLength: this.window.chainLength ?? null,
      verified: 0,
      mine: 0,
      stale: 0,
      dead: 0,
      fee: 0,
      v36native: 0,
      v36signaling: 0,
      primaryBlocks: this.window.primaryBlocks?.length ?? 0,
      dogeBlocks: this.window.dogeBlocks?.length ?? 0,
    };
    for (const share of this.window.shares) {
      if (share.s === 2) s.dead++;
      else if (share.s === 1) s.stale++;
      if (share.v) s.verified++;
      if (share.fee) s.fee++;
      if (myAddr !== undefined && myAddr !== '' && share.m === myAddr) s.mine++;
      if (share.V >= threshold) s.v36native++;
      else if (share.dv >= threshold) s.v36signaling++;
    }
    this._statsCache = s;
    this._statsTipAtCompute = this._lastAppliedTip;
    return s;
  }

  /** Return the frame to paint at time `now`. Returns a static frame
   *  (no cells moving) when no animation is running. Returns null if
   *  the window is empty AND there's nothing to paint. */
  currentFrame(now: number): FrameSpec | null {
    const animFrame = this.anim.tick(now);
    if (animFrame !== null) return animFrame;
    // Idle: emit a static frame so the renderer can re-paint on resize.
    return this.buildStaticFrame();
  }

  /** Return the PPLNS distribution for a specific share, falling back
   *  (per dashboard.html:5647-5663): exact hash match → walk backward
   *  (toward newer shares) for nearest cached entry → pplns_current. */
  getPPLNSForShare(shortHash: string | undefined): readonly PPLNSEntry[] {
    if (shortHash !== undefined && this.window.pplnsByShare) {
      const exact = this.window.pplnsByShare.get(shortHash);
      if (exact !== undefined) return exact;
      // Walk toward head (newer) from share's index.
      const shares = this.window.shares;
      for (let i = 0; i < shares.length; i++) {
        const s = shares[i]!;
        if (this.config.hashOf(s) === shortHash) {
          for (let j = i; j >= 0; j--) {
            const cand = this.config.hashOf(shares[j]!);
            const got = this.window.pplnsByShare.get(cand);
            if (got !== undefined) return got;
          }
          break;
        }
      }
    }
    return this.window.pplnsCurrent ?? [];
  }

  /** Render a static snapshot frame (no animation). */
  buildStaticFrame(): FrameSpec | null {
    const layout = this.updateLayout();
    if (layout.shareCount === 0 && this.window.shares.length === 0) {
      return {
        cells: [],
        particles: [],
        cards: [],
        backgroundColor: this.config.backgroundColor,
        layout,
      };
    }
    const cells = this.window.shares.map((s, i) => {
      const col = i % layout.cols;
      const row = Math.floor(i / layout.cols);
      const x = layout.marginLeft + col * layout.step;
      const y = row * layout.step;
      return {
        shareHash: this.config.hashOf(s),
        track: 'wave' as const,
        x, y,
        size: layout.cellSize,
        color: getColor(s, this.config.userContext, this.config.palette),
        alpha: 1,
      };
    });
    return {
      cells,
      particles: [],
      cards: [],
      backgroundColor: this.config.backgroundColor,
      layout,
    };
  }

  // ── internal ──────────────────────────────────────────────────────

  private updateLayout(): GridLayout {
    const layout = computeGridLayout({
      ...this.config.layoutParams,
      shareCount: this.window.shares.length,
      containerWidth: this.config.containerWidth(),
    });
    this._currentLayout = layout;
    return layout;
  }

  private async rebuildWindow(): Promise<void> {
    try {
      const signal = this.abort?.signal;
      const opts: RequestOptions = signal !== undefined ? { signal } : {};
      const raw = await this.config.transport.fetchWindow(opts);
      const shares = this.extractShares(raw);
      const tip = shares.length > 0 ? this.config.hashOf(shares[0]!) : undefined;
      const meta = this.extractMeta(raw);
      this.window = {
        shares,
        ...(tip !== undefined ? { tip } : {}),
        ...meta,
      };
      this._lastAppliedTip = tip ?? null;
      this._statsCache = null;  // invalidate cache for new window
      this.anim.reset();
    } catch (err) {
      this.emitError(err);
    }
  }

  /** Capture optional top-level metadata from window / delta
   *  responses: chain_length, blocks, doge_blocks, pplns_current,
   *  pplns. Returns only defined fields so exactOptionalPropertyTypes
   *  stays happy. */
  private extractMeta(raw: unknown): {
    chainLength?: number;
    primaryBlocks?: readonly string[];
    dogeBlocks?: readonly string[];
    pplnsCurrent?: readonly PPLNSEntry[];
    pplnsByShare?: ReadonlyMap<string, readonly PPLNSEntry[]>;
  } {
    if (raw === null || typeof raw !== 'object') return {};
    const obj = raw as Record<string, unknown>;
    const out: {
      chainLength?: number;
      primaryBlocks?: readonly string[];
      dogeBlocks?: readonly string[];
      pplnsCurrent?: readonly PPLNSEntry[];
      pplnsByShare?: ReadonlyMap<string, readonly PPLNSEntry[]>;
    } = {};
    if (typeof obj.chain_length === 'number') out.chainLength = obj.chain_length;
    if (Array.isArray(obj.blocks)) {
      out.primaryBlocks = obj.blocks.filter((x): x is string => typeof x === 'string');
    }
    if (Array.isArray(obj.doge_blocks)) {
      out.dogeBlocks = obj.doge_blocks.filter((x): x is string => typeof x === 'string');
    }
    if (obj.pplns_current !== undefined) {
      const parsed = parsePPLNS(obj.pplns_current);
      if (parsed.length > 0) out.pplnsCurrent = parsed;
    }
    if (obj.pplns !== null && typeof obj.pplns === 'object' && !Array.isArray(obj.pplns)) {
      const m = new Map<string, readonly PPLNSEntry[]>();
      for (const [shortHash, payload] of Object.entries(obj.pplns as Record<string, unknown>)) {
        const parsed = parsePPLNS(payload);
        if (parsed.length > 0) m.set(shortHash, parsed);
      }
      if (m.size > 0) out.pplnsByShare = m;
    }
    return out;
  }

  private subscribe(): void {
    if (this.subscription !== null) this.subscription.unsubscribe();
    this.subscription = this.config.transport.subscribeStream(
      (ev) => this.onTip(ev),
      (err) => this.emitError(err),
      () => this.onReconnect(),
    );
  }

  private onTip(ev: TipEvent): void {
    if (this._stopped) return;
    if (ev.hash === this._lastAppliedTip) return;  // dedup
    if (ev.hash === this._pendingTip) return;      // dedup in-flight
    this._pendingTip = ev.hash;
    if (this._deltaInFlight) return;                // coalesce: one request at a time
    void this.fetchAndApply();
  }

  private async onReconnect(): Promise<void> {
    if (this._stopped) return;
    // Catch-up per delta v1 §A.3 — fetch tip, apply if changed.
    try {
      const signal = this.abort?.signal;
      const opts: RequestOptions = signal !== undefined ? { signal } : {};
      const tipRaw = await this.config.transport.fetchTip(opts);
      const hash = (tipRaw as { hash?: unknown } | null)?.hash;
      if (typeof hash === 'string' && hash !== this._lastAppliedTip) {
        this._pendingTip = hash;
        if (!this._deltaInFlight) void this.fetchAndApply();
      }
    } catch (err) {
      this.emitError(err);
    }
  }

  private async fetchAndApply(): Promise<void> {
    if (this._stopped) return;
    if (this._deltaInFlight) return;
    const pendingAtStart = this._pendingTip;
    if (pendingAtStart === null) return;
    const since = this.window.tip;
    if (since === undefined) {
      // No baseline to delta against — rebuild the whole window.
      this._deltaInFlight = true;
      try {
        await this.rebuildWindow();
      } finally {
        this._deltaInFlight = false;
        this._pendingTip = null;
      }
      return;
    }
    this._deltaInFlight = true;
    try {
      const signal = this.abort?.signal;
      const opts: RequestOptions = signal !== undefined ? { signal } : {};
      const raw = await this.config.transport.fetchDelta(since, opts);
      this.applyDelta(raw);
    } catch (err) {
      this.emitError(err);
    } finally {
      this._deltaInFlight = false;
    }
    // If another tip arrived while we were fetching, drain it.
    if (this._pendingTip !== null && this._pendingTip !== pendingAtStart) {
      void this.fetchAndApply();
    } else {
      this._pendingTip = null;
    }
  }

  private applyDelta(raw: unknown): void {
    const delta = this.normaliseDelta(raw);
    const oldShares = this.window.shares;
    const oldLayout = this._currentLayout ?? this.updateLayout();
    const merge = mergeDelta(this.window, delta, { windowSize: this.config.windowSize });

    // Swap state. Re-capture any top-level meta from the delta body
    // (chain_length + block lists + pplns — spec §5.3 keeps them
    // mirrored). PPLNS maps merge additively: delta entries win;
    // prior entries survive if not overridden.
    const deltaMeta = this.extractMeta(raw);
    let mergedPplnsByShare: ReadonlyMap<string, readonly PPLNSEntry[]> | undefined;
    if (deltaMeta.pplnsByShare !== undefined || this.window.pplnsByShare !== undefined) {
      const combined = new Map<string, readonly PPLNSEntry[]>();
      if (this.window.pplnsByShare !== undefined) {
        for (const [h, e] of this.window.pplnsByShare) combined.set(h, e);
      }
      if (deltaMeta.pplnsByShare !== undefined) {
        for (const [h, e] of deltaMeta.pplnsByShare) combined.set(h, e);
      }
      // Bound growth: cap at 2 × windowSize (matches architecture doc
      // §2 "up to 10000 entries" with the LRU rule from delta v1 §C.2).
      const cap = this.config.windowSize * 2;
      if (combined.size > cap) {
        const toDrop = combined.size - cap;
        const it = combined.keys();
        for (let i = 0; i < toDrop; i++) {
          const k = it.next();
          if (k.done) break;
          combined.delete(k.value);
        }
      }
      mergedPplnsByShare = combined;
    }
    const newTip = merge.tip;
    const newShares = merge.shares as readonly ShareForClassify[];
    this.window = {
      shares: newShares,
      ...(newTip !== undefined ? { tip: newTip } : {}),
      ...(deltaMeta.chainLength !== undefined
          ? { chainLength: deltaMeta.chainLength }
          : this.window.chainLength !== undefined
          ? { chainLength: this.window.chainLength }
          : {}),
      ...(deltaMeta.primaryBlocks !== undefined
          ? { primaryBlocks: deltaMeta.primaryBlocks }
          : this.window.primaryBlocks !== undefined
          ? { primaryBlocks: this.window.primaryBlocks }
          : {}),
      ...(deltaMeta.dogeBlocks !== undefined
          ? { dogeBlocks: deltaMeta.dogeBlocks }
          : this.window.dogeBlocks !== undefined
          ? { dogeBlocks: this.window.dogeBlocks }
          : {}),
      ...(deltaMeta.pplnsCurrent !== undefined
          ? { pplnsCurrent: deltaMeta.pplnsCurrent }
          : this.window.pplnsCurrent !== undefined
          ? { pplnsCurrent: this.window.pplnsCurrent }
          : {}),
      ...(mergedPplnsByShare !== undefined ? { pplnsByShare: mergedPplnsByShare } : {}),
    };
    this._lastAppliedTip = newTip ?? null;
    this._statsCache = null;  // invalidate cache after merge

    if (merge.forkSwitch) {
      // Can't smoothly animate a reorg — full refresh.
      void this.rebuildWindow();
      return;
    }

    if (merge.added.length === 0 && merge.evicted.length === 0) {
      // Tip advance with no window-visible change — skip animation.
      return;
    }

    if (merge.added.length >= this.config.skipAnimationThreshold) {
      // Bulk update — skip animation, reset the animator so the next
      // idle frame renders the new static state.
      this.anim.reset();
      return;
    }

    const newLayout = this.updateLayout();
    const plan = buildAnimationPlan({
      oldShares,
      newShares: this.window.shares,
      addedHashes: merge.added.map((s) => this.config.hashOf(s)),
      evictedHashes: [...merge.evicted],
      oldLayout,
      newLayout,
      userContext: this.config.userContext,
      palette: this.config.palette,
      hashOf: this.config.hashOf,
      fast: this.config.fastAnimation,
    });

    if (this.anim.isRunning()) {
      this.anim.queueNext(plan);
      this._hasQueued = true;
    } else {
      this.anim.start(plan, this.nowMs());
      this._hasQueued = false;
    }
  }

  private extractShares(raw: unknown): readonly ShareForClassify[] {
    if (raw === null || typeof raw !== 'object') return [];
    const arr = (raw as { shares?: unknown }).shares;
    if (!Array.isArray(arr)) return [];
    return arr as readonly ShareForClassify[];
  }

  private normaliseDelta(raw: unknown): DeltaPayload<ShareForClassify> {
    if (raw === null || typeof raw !== 'object') {
      return { shares: [] };
    }
    const obj = raw as Record<string, unknown>;
    const shares = Array.isArray(obj.shares) ? (obj.shares as ShareForClassify[]) : [];
    const out: DeltaPayload<ShareForClassify> = { shares };
    if (typeof obj.tip === 'string') out.tip = obj.tip;
    if (typeof obj.window_size === 'number') out.window_size = obj.window_size;
    if (obj.fork_switch === true) out.fork_switch = true;
    return out;
  }

  private emitError(err: unknown): void {
    if (!this.config.onError) return;
    const error = (typeof err === 'object' && err !== null && 'type' in err)
      ? err as ExplorerError
      : { type: 'internal', message: 'realtime error', cause: err } as ExplorerError;
    this.config.onError(error);
  }

  private nowMs(): number {
    return typeof performance !== 'undefined' ? performance.now() : Date.now();
  }
}

// ── DOM adapter ───────────────────────────────────────────────────

export interface RealtimeDOMOptions extends RealtimeConfig {
  canvas: HTMLCanvasElement;
  /** Optional override; defaults to window.devicePixelRatio. */
  getDevicePixelRatio?: () => number;
}

export interface RealtimeController {
  start(): Promise<void>;
  stop(): Promise<void>;
  refresh(): Promise<void>;
  getState(): Readonly<RealtimeState>;
  /** PPLNS distribution for a specific share (hover-zoom lookup). */
  getPPLNSForShare(shortHash: string | undefined): readonly PPLNSEntry[];
}

export function createRealtime(opts: RealtimeDOMOptions): RealtimeController {
  const orchestrator = new RealtimeOrchestrator(opts);
  const renderer: GridRenderer = createGridRenderer(opts.canvas);
  const ctx2d = opts.canvas.getContext('2d');
  if (ctx2d === null) throw new Error('createRealtime: canvas context unavailable');
  const getDpr = opts.getDevicePixelRatio ?? (() => window.devicePixelRatio || 1);
  let raf: number | null = null;
  let stopped = false;

  const loop = (now: number): void => {
    if (stopped) return;
    const frame = orchestrator.currentFrame(now);
    if (frame !== null) {
      const dpr = getDpr();
      opts.canvas.style.width = `${frame.layout.cssWidth}px`;
      opts.canvas.style.height = `${frame.layout.cssHeight}px`;
      opts.canvas.width = Math.round(frame.layout.cssWidth * dpr);
      opts.canvas.height = Math.round(frame.layout.cssHeight * dpr);
      const program: PaintCommand[] = buildAnimatedPaintProgram(frame, dpr);
      executePaintProgram(ctx2d as unknown as import('./grid-paint.js').CanvasLike, program);
    }
    raf = window.requestAnimationFrame(loop);
  };

  return {
    async start() {
      stopped = false;
      await orchestrator.start();
      raf = window.requestAnimationFrame(loop);
    },
    async stop() {
      stopped = true;
      if (raf !== null) window.cancelAnimationFrame(raf);
      raf = null;
      await orchestrator.stop();
      renderer.destroy();
    },
    refresh: () => orchestrator.refresh(),
    getState: () => orchestrator.getState(),
    getPPLNSForShare: (h) => orchestrator.getPPLNSForShare(h),
  };
}

// ── Plugin ────────────────────────────────────────────────────────

export const RealtimePlugin: PluginDescriptor = {
  id: 'explorer.realtime.default',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'loader',
  provides: ['realtime.orchestrator'],
  slots: ['explorer.data.realtime'],
  priority: 0,
  capabilities: {
    'realtime.orchestrator': { RealtimeOrchestrator, createRealtime },
  },
};
