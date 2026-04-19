// Three-phase animator core (spec §6, dashboard.html:4866-5400).
//
// This commit ships the core state machine: timing math, stagger
// schedules, position interpolation across the three phases, and the
// controller (start/tick/queue/reset). Scale effects, colour lerps,
// particle dissolution and card overlays land in subsequent commits —
// deliberately separated because each adds ~50-100 LOC of clearly
// isolable work, and the pure-function structure accommodates them
// without redesign.
//
// Phase timing (verbatim from dashboard.html:4977-4982):
//   phase1Dur  = 3000
//   phase2Dur  = fast ? 2000 : 4000     ← note: spec §6 text has typo,
//                                         code is authoritative
//   phase2Start = phase1Dur
//   phase3Start = phase2Start + phase2Dur * 0.7    (overlap)
//   phase3Dur  = 3000
//   duration   = phase3Start + phase3Dur
//
// Staggers:
//   - DYING: last dying share first, 150 ms per share
//   - WAVE:  tail → head, fraction of position-in-new-layout
//   - BORN:  newest share first, 150 ms per share

import type { PluginDescriptor } from '../registry.js';
import type { GridLayout } from './grid-layout.js';
import { cellPosition } from './grid-layout.js';
import type {
  ColorPalette,
  ShareForClassify,
  UserContext,
} from './colors.js';
import { getColor } from './colors.js';

// ── Input / output types ────────────────────────────────────────────

export interface AnimationInput {
  /** Shares array BEFORE the merge (defrag.shares at phase start). */
  oldShares: readonly ShareForClassify[];
  /** Shares array AFTER the merge (defrag.shares post-apply). */
  newShares: readonly ShareForClassify[];
  /** Short-hashes that are in newShares but not in oldShares. */
  addedHashes: readonly string[];
  /** Short-hashes that were in oldShares but not newShares. */
  evictedHashes: readonly string[];
  oldLayout: GridLayout;
  newLayout: GridLayout;
  userContext: UserContext;
  palette: Readonly<ColorPalette>;
  /** Short-hash accessor — `share.h` in the spec contract. */
  hashOf: (share: ShareForClassify) => string;
  /** 'fast' mode uses shorter wave phase (§6 "fast-mode"). */
  fast?: boolean;
}

export type AnimTrack = 'dying' | 'wave' | 'born';

export interface CellFrame {
  shareHash: string;
  track: AnimTrack;
  x: number;
  y: number;
  size: number;   // effective cell size (currently constant; scale lands next commit)
  color: string;
  alpha: number;  // 0..1 (currently constant 1; fade lands next commit)
}

export interface FrameSpec {
  cells: readonly CellFrame[];
  backgroundColor: string;
  layout: GridLayout;  // the post-merge layout — grid sizing follows newLayout
}

export interface AnimationPlan {
  tEnd: number;          // total duration in ms
  phase1Start: number;
  phase1Dur: number;
  phase2Start: number;
  phase2Dur: number;
  phase3Start: number;
  phase3Dur: number;
  /** Internal — frame computer snapshot. Pure inputs preserved so
   *  frameAt(t) is deterministic and the caller can seek arbitrary t. */
  frameAt(t: number): FrameSpec;
}

// ── Phase timing ────────────────────────────────────────────────────

export interface PhaseTiming {
  phase1Start: number;
  phase1Dur: number;
  phase2Start: number;
  phase2Dur: number;
  phase3Start: number;
  phase3Dur: number;
  duration: number;
}

export function computePhaseTiming(fast = false): PhaseTiming {
  const phase1Start = 0;
  const phase1Dur   = 3000;
  const phase2Start = phase1Start + phase1Dur;
  const phase2Dur   = fast ? 2000 : 4000;
  const phase3Start = phase2Start + phase2Dur * 0.7;
  const phase3Dur   = 3000;
  const duration    = phase3Start + phase3Dur;
  return { phase1Start, phase1Dur, phase2Start, phase2Dur, phase3Start, phase3Dur, duration };
}

// ── Interpolation helpers ───────────────────────────────────────────

export function clamp01(x: number): number {
  return x < 0 ? 0 : x > 1 ? 1 : x;
}

export function lerp(a: number, b: number, t: number): number {
  return a + (b - a) * t;
}

/** cubic ease-in-out */
export function easeInOut(t: number): number {
  const x = clamp01(t);
  return x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2;
}

// ── Plan builder ────────────────────────────────────────────────────

const DYING_STAGGER_MS = 150;
const BORN_STAGGER_MS  = 150;
/** Per-share wave-animation duration (dashboard.html:5150, "/ 600"). */
const WAVE_PER_SHARE_MS = 600;
/** Birth "spawn" y offset below the grid, expressed in cell-sizes. */
const BORN_Y_BELOW_CELLS = 2;

export function buildAnimationPlan(input: AnimationInput): AnimationPlan {
  const timing = computePhaseTiming(input.fast === true);
  const {
    phase1Start, phase1Dur,
    phase2Start, phase2Dur,
    phase3Start, phase3Dur,
    duration,
  } = timing;

  // Build lookup: new-share index by hash (for wave destinations).
  const newIndexByHash = new Map<string, number>();
  for (let i = 0; i < input.newShares.length; i++) {
    const s = input.newShares[i];
    if (s !== undefined) newIndexByHash.set(input.hashOf(s), i);
  }
  const oldIndexByHash = new Map<string, number>();
  for (let i = 0; i < input.oldShares.length; i++) {
    const s = input.oldShares[i];
    if (s !== undefined) oldIndexByHash.set(input.hashOf(s), i);
  }

  const addedSet   = new Set(input.addedHashes);
  const evictedSet = new Set(input.evictedHashes);

  // Precompute static colours per share hash — both the ending (coin)
  // colour and, for dying shares, the starting colour. Colour lerp to
  // red across phase 1 lands next commit.
  const colorForHash = (hash: string, source: readonly ShareForClassify[],
                        idxByHash: Map<string, number>): string => {
    const idx = idxByHash.get(hash);
    if (idx === undefined) return input.palette.unverified;
    const share = source[idx];
    if (share === undefined) return input.palette.unverified;
    return getColor(share, input.userContext, input.palette);
  };

  // ── Dying shares: in oldShares ∩ evictedHashes. Stagger last-first. ──
  const dyingList = input.evictedHashes
    .filter((h) => oldIndexByHash.has(h))
    .map((h) => ({ hash: h, oldIndex: oldIndexByHash.get(h)! }))
    .sort((a, b) => b.oldIndex - a.oldIndex);  // largest oldIndex first

  // ── Born shares: in addedHashes. Stagger newest (lowest newIndex) first. ──
  const bornList = input.addedHashes
    .filter((h) => newIndexByHash.has(h))
    .map((h) => ({ hash: h, newIndex: newIndexByHash.get(h)! }))
    .sort((a, b) => a.newIndex - b.newIndex);

  // ── Wave shares: present in both old and new (and not evicted). ──
  //    Stagger fraction = newIndex / (shareCount-1): tail moves first.
  const waveList: Array<{
    hash: string;
    oldIndex: number;
    newIndex: number;
  }> = [];
  for (const [hash, newIdx] of newIndexByHash) {
    if (addedSet.has(hash)) continue;
    const oldIdx = oldIndexByHash.get(hash);
    if (oldIdx === undefined) continue;
    if (evictedSet.has(hash)) continue;
    waveList.push({ hash, oldIndex: oldIdx, newIndex: newIdx });
  }

  // ── Frame computer ──
  const frameAt = (t: number): FrameSpec => {
    const cells: CellFrame[] = [];

    // WAVE cells — stagger tail-first per dashboard.html:5146-5151.
    // distFromTail = (N-1) - newIndex; fraction = distFromTail/(N-1);
    // shareStart = fraction * phase2Dur * 0.7; per-share duration 600ms.
    const shareCountMinus1 = input.newShares.length - 1;
    for (const entry of waveList) {
      const oldPos = cellPosition(input.oldLayout, entry.oldIndex);
      const newPos = cellPosition(input.newLayout, entry.newIndex);
      if (oldPos === null || newPos === null) continue;
      const distFromTail = shareCountMinus1 - entry.newIndex;
      const fraction = shareCountMinus1 > 0 ? distFromTail / shareCountMinus1 : 0;
      const shareStart = fraction * phase2Dur * 0.7;
      const shareT = clamp01(((t - phase2Start) - shareStart) / WAVE_PER_SHARE_MS);
      const e = 1 - Math.pow(1 - shareT, 3);  // easeOut-cubic, matches dashboard:5151
      const x = lerp(oldPos.x, newPos.x, e);
      const y = lerp(oldPos.y, newPos.y, e);
      const color = colorForHash(entry.hash, input.newShares, newIndexByHash);
      cells.push({
        shareHash: entry.hash,
        track: 'wave',
        x, y,
        size: input.newLayout.cellSize,
        color,
        alpha: 1,
      });
    }

    // DYING cells — held in their old positions during phase 1, then
    // shrink/dissolve. For this commit they disappear at phase1 end
    // by clamping alpha to 0; full particle/rise effects land next.
    for (let i = 0; i < dyingList.length; i++) {
      const entry = dyingList[i];
      if (entry === undefined) continue;
      const oldPos = cellPosition(input.oldLayout, entry.oldIndex);
      if (oldPos === null) continue;
      const dStart = phase1Start + i * DYING_STAGGER_MS;
      const dRaw   = (t - dStart) / phase1Dur;
      const dt = clamp01(dRaw);
      const color = colorForHash(entry.hash, input.oldShares, oldIndexByHash);
      // Alpha fades to 0 at the end of its stagger window — placeholder
      // until the rise+dissolve effect lands.
      const alpha = 1 - dt;
      cells.push({
        shareHash: entry.hash,
        track: 'dying',
        x: oldPos.x,
        y: oldPos.y,
        size: input.newLayout.cellSize,
        color,
        alpha,
      });
    }

    // BORN cells — spawn from below the grid, fly into new position
    // over phase 3. Position interpolation only for this commit.
    const bornYBelow = input.newLayout.cssHeight + BORN_Y_BELOW_CELLS * input.newLayout.cellSize;
    for (let i = 0; i < bornList.length; i++) {
      const entry = bornList[i];
      if (entry === undefined) continue;
      const newPos = cellPosition(input.newLayout, entry.newIndex);
      if (newPos === null) continue;
      const bStart = phase3Start + i * BORN_STAGGER_MS;
      const bRaw = (t - bStart) / phase3Dur;
      const bt = clamp01(bRaw);
      const e = easeInOut(bt);
      const spawnX = newPos.x;
      const spawnY = bornYBelow;
      const x = lerp(spawnX, newPos.x, e);
      const y = lerp(spawnY, newPos.y, e);
      const color = colorForHash(entry.hash, input.newShares, newIndexByHash);
      // Alpha fades in from 0 to 1 over first 30% of its stagger slice.
      const alpha = clamp01(bt / 0.3);
      cells.push({
        shareHash: entry.hash,
        track: 'born',
        x, y,
        size: input.newLayout.cellSize,
        color,
        alpha,
      });
    }

    return {
      cells,
      backgroundColor: '#0d0d1a',
      layout: input.newLayout,
    };
  };

  return {
    tEnd: duration,
    phase1Start, phase1Dur,
    phase2Start, phase2Dur,
    phase3Start, phase3Dur,
    frameAt,
  };
}

// ── Animation controller ────────────────────────────────────────────

export interface AnimationController {
  isRunning(): boolean;
  /** Begin playing a plan. `nowMs` is the reference timestamp (e.g.
   *  performance.now()) — all subsequent tick() values are compared
   *  against it. */
  start(plan: AnimationPlan, nowMs: number): void;
  /** Advance the clock. Returns the frame to paint, or null when the
   *  animation has completed (after which the controller is idle). */
  tick(nowMs: number): FrameSpec | null;
  /** Queue a follow-up plan to start as soon as the current one ends.
   *  If no animation is running, the queued plan starts immediately on
   *  the next tick. (§6 threshold rule #2: _animDeferred.) */
  queueNext(plan: AnimationPlan): void;
  /** Hard reset — drops current plan + queue. */
  reset(): void;
}

interface ControllerState {
  plan: AnimationPlan | null;
  startedAt: number;
  queued: AnimationPlan | null;
}

export function createAnimationController(): AnimationController {
  const state: ControllerState = { plan: null, startedAt: 0, queued: null };

  const applyStart = (plan: AnimationPlan, nowMs: number) => {
    state.plan = plan;
    state.startedAt = nowMs;
  };

  return {
    isRunning(): boolean {
      return state.plan !== null;
    },
    start(plan, nowMs) {
      applyStart(plan, nowMs);
    },
    tick(nowMs) {
      if (state.plan === null && state.queued !== null) {
        applyStart(state.queued, nowMs);
        state.queued = null;
      }
      if (state.plan === null) return null;
      const elapsed = nowMs - state.startedAt;
      if (elapsed >= state.plan.tEnd) {
        // Play the final frame once, then idle.
        const final = state.plan.frameAt(state.plan.tEnd);
        state.plan = null;
        if (state.queued !== null) {
          applyStart(state.queued, nowMs);
          state.queued = null;
        }
        return final;
      }
      return state.plan.frameAt(elapsed);
    },
    queueNext(plan) {
      state.queued = plan;
    },
    reset() {
      state.plan = null;
      state.queued = null;
      state.startedAt = 0;
    },
  };
}

/** §6 threshold: when the new-share delta exceeds this, skip the
 *  animation entirely and render directly. Preserved from
 *  dashboard.html:5014-ish ("if (newCount >= 100) render directly"). */
export const SKIP_ANIMATION_NEW_COUNT_THRESHOLD = 100;

// ── Plugin ──────────────────────────────────────────────────────────

export const AnimatorPlugin: PluginDescriptor = {
  id: 'explorer.animator.three-phase',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'animator',
  provides: ['animator.grid'],
  priority: 0,
  capabilities: {
    'animator.grid': {
      buildAnimationPlan,
      createAnimationController,
      computePhaseTiming,
      SKIP_ANIMATION_NEW_COUNT_THRESHOLD,
    },
  },
};
