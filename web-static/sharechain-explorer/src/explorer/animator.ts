// Three-phase animator core (spec §6, dashboard.html:4866-5400).
//
// Phase B #11 — adds particles + card overlays + reference-faithful
// phase boundaries for dying/born shares. Particles are seeded
// deterministically at plan-build time (mulberry32) so frameAt(t) is
// pure: same input + same seed → identical particle frames.
//
// Dying phases (per share, after its stagger):
//   dt < 0.30 → RISE    — scale 1 → dyingScale, fly to spread slot
//   dt < 0.55 → HOLD    — scale = dyingScale, card (miner + PPLNS%)
//   dt < 1.00 → DISSOLVE — core shrinks, 20 ash particles fly
//
// Born phases (per share, after its stagger):
//   bt < 0.35 → COALESCE — particles gather into growing core
//   bt < 0.65 → HOLD     — scale = bornScale, card (miner + PPLNS%)
//   bt < 1.00 → LAND     — scale bornScale → 1, fly to grid position
//
// Staggers:
//   - DYING: last-first, 150 ms per share (reference: dIdx within dyingList)
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
import { lerpColor, applyAlpha, parseHexColor } from './color-utils.js';

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
  /** Card scale for dying shares (cs * dyingScale). Default 5. The
   *  runtime computes this from canvas.measureText so cards always
   *  fit; tests can leave it at default. */
  dyingScale?: number;
  /** Card scale for born shares. Default 5. */
  bornScale?: number;
  /** Returns PPLNS fraction (0..1) for a share. Used in card "pct"
   *  text. Dying lookup uses oldShares; born uses newShares. If
   *  omitted, cards show "--" instead of "X.XXX%". */
  pplnsOf?: (share: ShareForClassify) => number;
  /** Miner address accessor — used for the card "addr" text. Defaults
   *  to share.m. First 10 chars are shown. */
  minerOf?: (share: ShareForClassify) => string;
  /** Seed for deterministic particle positions/velocities. Default 0. */
  rngSeed?: number;
}

export type AnimTrack = 'dying' | 'wave' | 'born';

export interface CellFrame {
  shareHash: string;
  track: AnimTrack;
  x: number;
  y: number;
  size: number;
  color: string;
  alpha: number;
}

export interface ParticleFrame {
  x: number;
  y: number;
  size: number;
  /** Packed rgba(...) string Canvas 2D understands. */
  color: string;
}

export type CardKind = 'dying' | 'born';

export interface CardOverlayFrame {
  kind: CardKind;
  shareHash: string;
  /** Miner address, up to 10 chars. */
  addrText: string;
  /** PPLNS percent, formatted as "X.XXX%" or "--" when unknown. */
  pctText: string;
  /** Centre x of the scaled card square (CSS px). */
  cx: number;
  /** Centre y. */
  cy: number;
  /** Card square side length. */
  size: number;
  /** Solid fill for the card interior. */
  fillColor: string;
  /** Shadow rect colour (includes alpha). */
  shadowColor: string;
  /** Glow rect colour (includes alpha). */
  glowColor: string;
  /** Inner highlight overlay colour. */
  innerHighlight: string;
  fontSize: number;
  addrColor: string;
  pctColor: string;
}

export interface FrameSpec {
  cells: readonly CellFrame[];
  particles: readonly ParticleFrame[];
  cards: readonly CardOverlayFrame[];
  backgroundColor: string;
  layout: GridLayout;
}

export interface AnimationPlan {
  tEnd: number;
  phase1Start: number;
  phase1Dur: number;
  phase2Start: number;
  phase2Dur: number;
  phase3Start: number;
  phase3Dur: number;
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

export function easeInOut(t: number): number {
  const x = clamp01(t);
  return x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2;
}

// ── Deterministic RNG (mulberry32) ──────────────────────────────────

function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return function rng(): number {
    t = (t + 0x6d2b79f5) >>> 0;
    let r = t;
    r = Math.imul(r ^ (r >>> 15), r | 1);
    r ^= r + Math.imul(r ^ (r >>> 7), r | 61);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

// ── Constants ───────────────────────────────────────────────────────

const DYING_STAGGER_MS = 150;
const BORN_STAGGER_MS  = 150;
const WAVE_PER_SHARE_MS = 600;
const WAVE_PEAK_SCALE = 1.35;
const DYING_RISE_SCALE_DEFAULT = 5;
const BORN_SCALE_DEFAULT = 5;
const PARTICLES_PER_SHARE = 20;
/** Vertical offset of the dying card above its original cell (in
 *  units of `layout.step`). dashboard.html:5259 uses step*9. */
const DYING_CARD_STEP_UP = 9;

interface ParticleSeed {
  ox: number;
  oy: number;
  vx: number;
  vy: number;
  size: number;
  delay: number;
}

function seedParticles(rng: () => number, cs: number): readonly ParticleSeed[] {
  const out: ParticleSeed[] = [];
  for (let p = 0; p < PARTICLES_PER_SHARE; p++) {
    out.push({
      ox: (rng() - 0.5) * cs * 3,
      oy: (rng() - 0.5) * cs * 3,
      vx: (rng() - 0.5) * 8,
      vy: -rng() * 8 - 3,
      size: 2 + rng() * 4,
      delay: rng() * 0.3,
    });
  }
  return out;
}

// ── Card geometry helpers ───────────────────────────────────────────

/** Compute the x-centre of the dyingIdx-th dying card, laid out in a
 *  horizontal strip centred on the average of the dying shares'
 *  original positions. Mirrors dashboard.html:5242-5254. */
function dyingCardX(
  dIdx: number,
  dyingCount: number,
  dyingPositions: readonly { x: number }[],
  layout: GridLayout,
  dsc: number,
): number {
  const cs = layout.cellSize;
  const dsw = cs * dsc;
  const gap = dsw * 0.15;
  const totalW = dyingCount * dsw + (dyingCount - 1) * gap;
  let avgX = 0;
  for (const p of dyingPositions) avgX += p.x;
  avgX = avgX / dyingCount + cs / 2;
  let groupLeft = avgX - totalW / 2 - layout.step * 2;
  if (groupLeft < layout.marginLeft + layout.step * 2) {
    groupLeft = layout.marginLeft + layout.step * 2;
  }
  if (groupLeft + totalW > layout.cssWidth - layout.step * 2) {
    groupLeft = layout.cssWidth - layout.step * 2 - totalW;
  }
  return groupLeft + dIdx * (dsw + gap) + dsw / 2;
}

/** Compute the x-centre of the bornIdx-th born card, laid out in a
 *  horizontal strip centred on the average of the new top-row positions.
 *  Mirrors dashboard.html:5032-5044. */
function bornCardX(
  bIdx: number,
  newCount: number,
  newTopPositions: readonly { x: number }[],
  layout: GridLayout,
  bsc: number,
): number {
  const cs = layout.cellSize;
  const bsw = cs * bsc;
  const gap = bsw * 0.15;
  const totalW = newCount * bsw + (newCount - 1) * gap;
  let avgX = 0;
  for (const p of newTopPositions) avgX += p.x;
  avgX = avgX / newCount + cs / 2;
  let groupLeft = avgX - totalW / 2;
  if (groupLeft < layout.marginLeft + layout.step * 2) {
    groupLeft = layout.marginLeft + layout.step * 2;
  }
  if (groupLeft + totalW > layout.cssWidth - layout.step * 2) {
    groupLeft = layout.cssWidth - layout.step * 2 - totalW;
  }
  return groupLeft + bIdx * (bsw + gap) + bsw / 2;
}

// ── Plan builder ────────────────────────────────────────────────────

export function buildAnimationPlan(input: AnimationInput): AnimationPlan {
  const timing = computePhaseTiming(input.fast === true);
  const {
    phase1Start, phase1Dur,
    phase2Start, phase2Dur,
    phase3Start, phase3Dur,
    duration,
  } = timing;

  const layout = input.newLayout;
  const cs = layout.cellSize;
  const dyingScale = input.dyingScale ?? DYING_RISE_SCALE_DEFAULT;
  const bornScale  = input.bornScale  ?? BORN_SCALE_DEFAULT;
  const minerOf    = input.minerOf    ?? ((s) => s.m);
  const pplnsOf    = input.pplnsOf;

  // Build indices.
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

  const colorForHash = (hash: string, source: readonly ShareForClassify[],
                        idxByHash: Map<string, number>): string => {
    const idx = idxByHash.get(hash);
    if (idx === undefined) return input.palette.unverified;
    const share = source[idx];
    if (share === undefined) return input.palette.unverified;
    return getColor(share, input.userContext, input.palette);
  };

  const shareByHash = (hash: string, source: readonly ShareForClassify[],
                       idxByHash: Map<string, number>): ShareForClassify | null => {
    const idx = idxByHash.get(hash);
    if (idx === undefined) return null;
    const s = source[idx];
    return s ?? null;
  };

  // Dying list — largest oldIndex first (reference "last-first").
  const dyingList = input.evictedHashes
    .filter((h) => oldIndexByHash.has(h))
    .map((h) => ({ hash: h, oldIndex: oldIndexByHash.get(h)! }))
    .sort((a, b) => b.oldIndex - a.oldIndex);
  const dyingCount = dyingList.length;

  // Born list — lowest newIndex first (newest shares start first).
  const bornList = input.addedHashes
    .filter((h) => newIndexByHash.has(h))
    .map((h) => ({ hash: h, newIndex: newIndexByHash.get(h)! }))
    .sort((a, b) => a.newIndex - b.newIndex);
  const bornCount = bornList.length;

  // Wave list.
  const waveList: Array<{ hash: string; oldIndex: number; newIndex: number }> = [];
  for (const [hash, newIdx] of newIndexByHash) {
    if (addedSet.has(hash)) continue;
    const oldIdx = oldIndexByHash.get(hash);
    if (oldIdx === undefined) continue;
    if (evictedSet.has(hash)) continue;
    waveList.push({ hash, oldIndex: oldIdx, newIndex: newIdx });
  }

  // Precompute geometry that doesn't change per-frame.
  const dyingOldPositions: Array<{ x: number; y: number }> = [];
  for (const entry of dyingList) {
    const p = cellPosition(input.oldLayout, entry.oldIndex);
    dyingOldPositions.push(p !== null ? { x: p.x, y: p.y } : { x: 0, y: 0 });
  }
  const bornNewPositions: Array<{ x: number; y: number }> = [];
  for (const entry of bornList) {
    const p = cellPosition(input.newLayout, entry.newIndex);
    bornNewPositions.push(p !== null ? { x: p.x, y: p.y } : { x: 0, y: 0 });
  }

  // Precompute card text + original colour per dying / born share.
  const dyingMeta = dyingList.map((entry) => {
    const s = shareByHash(entry.hash, input.oldShares, oldIndexByHash);
    const miner = s ? minerOf(s) : '';
    const pct = s && pplnsOf ? pplnsOf(s) : NaN;
    const pctText = Number.isFinite(pct) ? (pct * 100).toFixed(3) + '%' : '--';
    const origColor = colorForHash(entry.hash, input.oldShares, oldIndexByHash);
    return { miner: miner.slice(0, 10), pctText, origColor };
  });
  const bornMeta = bornList.map((entry) => {
    const s = shareByHash(entry.hash, input.newShares, newIndexByHash);
    const miner = s ? minerOf(s) : '';
    const pct = s && pplnsOf ? pplnsOf(s) : NaN;
    const pctText = Number.isFinite(pct) ? (pct * 100).toFixed(3) + '%' : '--';
    const finalColor = colorForHash(entry.hash, input.newShares, newIndexByHash);
    return { miner: miner.slice(0, 10), pctText, finalColor };
  });

  // Pre-seed particles — one list per dying share and one per born share.
  const rng = mulberry32((input.rngSeed ?? 0) | 0);
  const dyingParticles: Array<readonly ParticleSeed[]> = [];
  for (let i = 0; i < dyingCount; i++) dyingParticles.push(seedParticles(rng, cs));
  const bornParticles: Array<readonly ParticleSeed[]> = [];
  for (let i = 0; i < bornCount; i++) bornParticles.push(seedParticles(rng, cs));

  const shareCountMinus1 = input.newShares.length - 1;
  const baseSize = layout.cellSize;

  // The "born spawn Y" — below destination, capped at middle of canvas.
  const bornBelowY = (dstY: number): number =>
    Math.min(dstY + layout.step * 8, layout.cssHeight * 0.5);

  const frameAt = (t: number): FrameSpec => {
    const cells: CellFrame[] = [];
    const particles: ParticleFrame[] = [];
    const cards: CardOverlayFrame[] = [];

    // ═══ WAVE (phase 2) ═══
    for (const entry of waveList) {
      const oldPos = cellPosition(input.oldLayout, entry.oldIndex);
      const newPos = cellPosition(input.newLayout, entry.newIndex);
      if (oldPos === null || newPos === null) continue;
      const distFromTail = shareCountMinus1 - entry.newIndex;
      const fraction = shareCountMinus1 > 0 ? distFromTail / shareCountMinus1 : 0;
      const shareStart = fraction * phase2Dur * 0.7;
      const shareT = clamp01(((t - phase2Start) - shareStart) / WAVE_PER_SHARE_MS);
      const ease = 1 - Math.pow(1 - shareT, 3);
      let liftA: number, slideA: number, landA: number;
      if (ease < 0.2) { liftA = ease / 0.2;       slideA = 0;               landA = 0; }
      else if (ease < 0.8) { liftA = 1;           slideA = (ease-0.2)/0.6;  landA = 0; }
      else                 { liftA = 1;           slideA = 1;               landA = (ease-0.8)/0.2; }
      const pop = liftA * (1 - landA);
      const scale = 1 + (WAVE_PEAK_SCALE - 1) * pop;
      const size = baseSize * scale;
      const xCentre = lerp(oldPos.x, newPos.x, slideA) + baseSize / 2;
      const yCentre = lerp(oldPos.y, newPos.y, slideA) + baseSize / 2;
      const color = colorForHash(entry.hash, input.newShares, newIndexByHash);
      cells.push({
        shareHash: entry.hash,
        track: 'wave',
        x: xCentre - size / 2,
        y: yCentre - size / 2,
        size,
        color,
        alpha: 1,
      });
    }

    // ═══ DYING (phase 1) ═══
    const p1t = clamp01((t - phase1Start) / phase1Dur);
    for (let d = 0; d < dyingCount; d++) {
      const entry = dyingList[d];
      const meta  = dyingMeta[d];
      const seeds = dyingParticles[d];
      const origPos = dyingOldPositions[d];
      if (!entry || !meta || !seeds || !origPos) continue;
      // Stagger: largest-oldIndex first. My sort put largest at d=0, so
      // d=0 has NO delay and last d has max delay — matches "last-first".
      const dDelay = (d * DYING_STAGGER_MS) / phase1Dur;
      const dt = clamp01((p1t - dDelay) / (1 - dDelay));
      if (dt >= 1) continue;

      const dcx = origPos.x + cs / 2;
      const dcy = origPos.y + cs / 2;
      const finalX = dyingCardX(d, dyingCount, dyingOldPositions, layout, dyingScale);
      const finalY = dcy - layout.step * DYING_CARD_STEP_UP;
      const dsw = cs * dyingScale;

      if (dt < 0.3) {
        // RISE: scale 1 → dyingScale, colour lerps toward dead
        const riseT = dt / 0.3;
        const riseEase = 1 - Math.pow(1 - riseT, 2);
        const scale = 1 + riseEase * (dyingScale - 1);
        const size = cs * scale;
        const animX = dcx + (finalX - dcx) * riseEase;
        const animY = dcy + (finalY - dcy) * riseEase;
        const color = lerpColor(meta.origColor, input.palette.dead, riseEase);
        cells.push({
          shareHash: entry.hash,
          track: 'dying',
          x: animX - size / 2,
          y: animY - size / 2,
          size,
          color: applyAlpha(color, 1),
          alpha: 1,
        });
      } else if (dt < 0.55) {
        // HOLD: full-size card visible
        cells.push({
          shareHash: entry.hash,
          track: 'dying',
          x: finalX - dsw / 2,
          y: finalY - dsw / 2,
          size: dsw,
          color: applyAlpha(input.palette.dead, 1),
          alpha: 1,
        });
        cards.push({
          kind: 'dying',
          shareHash: entry.hash,
          addrText: meta.miner,
          pctText: meta.pctText,
          cx: finalX,
          cy: finalY,
          size: dsw,
          fillColor: 'rgb(200,15,15)',
          shadowColor: 'rgba(0,0,0,0.85)',
          glowColor: 'rgba(255,40,30,0.15)',
          innerHighlight: 'rgba(255,60,50,0.2)',
          fontSize: 20,
          addrColor: '#ffffff',
          pctColor: '#ffd700',
        });
      } else {
        // DISSOLVE: shrinking core + particles
        const ashT = (dt - 0.55) / 0.45;
        const coreAlpha = Math.max(0, 1 - ashT * 1.3);
        if (coreAlpha > 0) {
          const shrink = 1 - ashT * 0.5;
          const cw = dsw * shrink;
          cells.push({
            shareHash: entry.hash,
            track: 'dying',
            x: finalX - cw / 2,
            y: finalY - cw / 2,
            size: cw,
            color: applyAlpha('#ff3040', coreAlpha),
            alpha: coreAlpha,
          });
        }
        const ashSpread = dsw * 0.8;
        for (let p = 0; p < seeds.length; p++) {
          const seed = seeds[p]!;
          const pt = clamp01((ashT - seed.delay) / (1 - seed.delay));
          if (pt <= 0 || pt >= 1) continue;
          const alpha = (1 - pt) * (1 - pt);
          const pSize = (seed.size + dsw * 0.04) * (1 - pt * 0.4);
          // Colour: bright ember (255,120,30) → dark ash (100,80,70)
          const r = Math.floor(255 * (1 - pt) + 100 * pt);
          const g = Math.floor(120 * (1 - pt) +  80 * pt);
          const b = Math.floor( 30 * (1 - pt) +  70 * pt);
          particles.push({
            x: finalX + seed.ox * ashSpread / cs + seed.vx * pt * 60,
            y: finalY + seed.oy * ashSpread / cs + seed.vy * pt * 60,
            size: pSize,
            color: `rgba(${r},${g},${b},${alpha.toFixed(3)})`,
          });
        }
      }
    }

    // ═══ BORN (phase 3) ═══
    for (let b = 0; b < bornCount; b++) {
      const entry = bornList[b];
      const meta  = bornMeta[b];
      const seeds = bornParticles[b];
      const dstPos = bornNewPositions[b];
      if (!entry || !meta || !seeds || !dstPos) continue;

      const bStagger = (b * BORN_STAGGER_MS) / phase3Dur;
      const rawBt = ((t - phase3Start) / phase3Dur - bStagger) / (1 - bStagger);
      const bt = clamp01(rawBt);
      const bdsw = cs * bornScale;
      const bFinalX = bornCardX(b, bornCount, bornNewPositions, layout, bornScale);
      const bFinalY = bornBelowY(dstPos.y);

      if (rawBt <= 0) {
        // Not started — render at destination with final colour so
        // the grid has no gap (matches reference dashboard.html:5049-5054).
        cells.push({
          shareHash: entry.hash,
          track: 'born',
          x: dstPos.x,
          y: dstPos.y,
          size: cs,
          color: applyAlpha(meta.finalColor, 1),
          alpha: 1,
        });
        continue;
      }

      if (bt < 0.35) {
        // COALESCE: particles gather into a growing core
        const cT = bt / 0.35;
        const coreAlpha = cT;
        const coreShrink = 0.3 + cT * 0.7;
        const cw = bdsw * coreShrink;
        if (coreAlpha > 0.1) {
          cells.push({
            shareHash: entry.hash,
            track: 'born',
            x: bFinalX - cw / 2,
            y: bFinalY - cw / 2,
            size: cw,
            color: applyAlpha(lerpColor('#50c850', meta.finalColor, cT), coreAlpha),
            alpha: coreAlpha,
          });
        }
        const ashSpread = bdsw * 0.8;
        const origRGB = parseHexColor(meta.finalColor);
        const startR = 100, startG = 200, startB = 100;  // green spark
        const endR = origRGB?.r ?? 180;
        const endG = origRGB?.g ?? 180;
        const endB = origRGB?.b ?? 180;
        const r = Math.floor(startR * (1 - cT) + endR * cT);
        const g = Math.floor(startG * (1 - cT) + endG * cT);
        const blu = Math.floor(startB * (1 - cT) + endB * cT);
        for (let p = 0; p < seeds.length; p++) {
          const seed = seeds[p]!;
          // Reverse-direction "pt": starts at ~1, diminishes to 0
          const raw = 1 - (cT - seed.delay) / (1 - seed.delay);
          if (raw <= 0 || raw > 1) continue;
          const alpha = 1 - raw * 0.5;
          const pSize = (seed.size + bdsw * 0.04) * (0.5 + raw * 0.5);
          particles.push({
            x: bFinalX + seed.ox * ashSpread / cs * raw + seed.vx * raw * 40,
            y: bFinalY + seed.oy * ashSpread / cs * raw + seed.vy * raw * 40,
            size: pSize,
            color: `rgba(${r},${g},${blu},${alpha.toFixed(3)})`,
          });
        }
      } else if (bt < 0.65) {
        // HOLD: card visible at bornScale
        cells.push({
          shareHash: entry.hash,
          track: 'born',
          x: bFinalX - bdsw / 2,
          y: bFinalY - bdsw / 2,
          size: bdsw,
          color: applyAlpha(meta.finalColor, 1),
          alpha: 1,
        });
        cards.push({
          kind: 'born',
          shareHash: entry.hash,
          addrText: meta.miner,
          pctText: meta.pctText,
          cx: bFinalX,
          cy: bFinalY,
          size: bdsw,
          fillColor: meta.finalColor,
          shadowColor: 'rgba(0,0,0,0.85)',
          glowColor: 'rgba(0,255,100,0.15)',
          innerHighlight: 'rgba(255,255,255,0.1)',
          fontSize: 20,
          addrColor: '#ffffff',
          pctColor: '#ffd700',
        });
      } else {
        // LAND: shrink from bornScale → 1, fly to dst
        const landT = (bt - 0.65) / 0.35;
        const landEase = 1 - Math.pow(1 - landT, 2);
        const scale = bornScale - (bornScale - 1) * landEase;
        const size = cs * scale;
        const xC = bFinalX + (dstPos.x + cs / 2 - bFinalX) * landEase;
        const yC = bFinalY + (dstPos.y + cs / 2 - bFinalY) * landEase;
        cells.push({
          shareHash: entry.hash,
          track: 'born',
          x: xC - size / 2,
          y: yC - size / 2,
          size,
          color: applyAlpha(meta.finalColor, 1),
          alpha: 1,
        });
      }
    }

    return {
      cells,
      particles,
      cards,
      backgroundColor: '#0d0d1a',
      layout,
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
  start(plan: AnimationPlan, nowMs: number): void;
  tick(nowMs: number): FrameSpec | null;
  queueNext(plan: AnimationPlan): void;
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
