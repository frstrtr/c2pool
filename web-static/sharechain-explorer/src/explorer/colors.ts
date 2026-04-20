// Colors — classifies a share and maps its class to a palette colour.
// Extracted verbatim from dashboard.html:5404-5429 (the `getColor` fn).
// Classification is coin-agnostic — the share-version threshold comes
// from the coin descriptor's `shareVersion`. The palette ships as
// `LTC_COLOR_PALETTE` today (identical to dashboard.html values for
// M2 pixel-diff); coin descriptors will supply their own palettes per
// M1 D5 / PPLNS spec §4.3.
//
// Provides capability `explorer.colors`.

import type { PluginDescriptor } from '../registry.js';

/** Stale enum from /sharechain/window §5.1: 0=none, 1=stale, 2=dead. */
export type StaleInfo = 0 | 1 | 2;

export interface ShareForClassify {
  h: string;            // short-hash per spec §5.1 (16 hex)
  s: StaleInfo;
  v: 0 | 1;
  V: number;
  dv: number;
  m: string;
  fee?: number;
  blk?: number;
  /** Unix seconds — share.t. Used for hour-axis labels. */
  t?: number;
  /** Compact-bits difficulty — share.b. Used by pplnsOf for card %. */
  b?: number;
}

export type ShareClass =
  | 'dead'          // share.s === 2
  | 'stale'         // share.s === 1
  | 'unverified'    // !share.v
  | 'fee'           // share.fee truthy
  | 'native'        // version >= coin.shareVersion
  | 'signaling'     // V < threshold && dv >= threshold
  | 'legacy';       // V < threshold && dv < threshold

export interface ColorPalette {
  dead:           string;
  stale:          string;
  unverified:     string;
  fee:            string;
  native:         string;
  nativeMine:     string;
  signaling:      string;
  signalingMine:  string;
  legacy:         string;
  legacyMine:     string;
}

/** Default palette — LTC's V35 → V36 transition. Values match
 *  dashboard.html:5404-5428 exactly so the extraction is pixel-stable. */
export const LTC_COLOR_PALETTE: Readonly<ColorPalette> = Object.freeze({
  dead:          '#dc3545',
  stale:         '#ffc107',
  unverified:    '#555577',
  fee:           '#9c27b0',
  native:        '#00e676',   // V36 non-mine
  nativeMine:    '#00b0ff',   // V36 mine
  signaling:     '#26c6da',   // V35 signalling V36 non-mine
  signalingMine: '#0097a7',   // V35 signalling V36 mine
  legacy:        '#2e7d32',   // V35 only non-mine
  legacyMine:    '#1565c0',   // V35 only mine
});

export interface UserContext {
  myAddress?: string | undefined;
  shareVersion: number;  // coin.shareVersion — the native threshold
}

/** Pure classifier. Priority order (per dashboard.html:5404): dead →
 *  stale → unverified → fee → version tier. Matches the verbatim
 *  behaviour so M2 pixel-diff holds. */
export function classifyShare(share: ShareForClassify, ctx: UserContext): ShareClass {
  if (share.s === 2) return 'dead';
  if (share.s === 1) return 'stale';
  if (!share.v) return 'unverified';
  if (share.fee) return 'fee';
  if (share.V >= ctx.shareVersion) return 'native';
  if (share.dv >= ctx.shareVersion) return 'signaling';
  return 'legacy';
}

/** Resolve the palette colour for a share. "Mine" variants only
 *  apply to version-tier classes (not dead/stale/unverified/fee). */
export function getColor(
  share: ShareForClassify,
  ctx: UserContext,
  palette: Readonly<ColorPalette> = LTC_COLOR_PALETTE,
): string {
  const klass = classifyShare(share, ctx);
  const isMine = ctx.myAddress !== undefined && ctx.myAddress !== '' && share.m === ctx.myAddress;
  switch (klass) {
    case 'dead':       return palette.dead;
    case 'stale':      return palette.stale;
    case 'unverified': return palette.unverified;
    case 'fee':        return palette.fee;
    case 'native':     return isMine ? palette.nativeMine    : palette.native;
    case 'signaling':  return isMine ? palette.signalingMine : palette.signaling;
    case 'legacy':     return isMine ? palette.legacyMine    : palette.legacy;
  }
}

export const ColorsPlugin: PluginDescriptor = {
  id: 'explorer.colors',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'util',
  provides: ['explorer.colors'],
  priority: 0,
  capabilities: {
    'explorer.colors': { classifyShare, getColor, LTC_COLOR_PALETTE },
  },
};
