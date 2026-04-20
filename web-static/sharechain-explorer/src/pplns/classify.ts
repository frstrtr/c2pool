// Default LTC-family version-badge config. Coin descriptors may pass
// their own palette + classify. Per
// frstrtr/the/docs/c2pool-pplns-view-module-task.md §4.3.

import type {
  PplnsMiner,
  VersionBadgeConfig,
  CoinPplnsDescriptor,
} from './types.js';

export const LTC_VERSION_BADGES: VersionBadgeConfig = {
  palette: Object.freeze({
    v36:         { label: 'V36',      color: '#66bb6a', severity: 'ok' },
    'v35-to-v36': { label: 'V35\u2192V36', color: '#4dd0e1', severity: 'signaling' },
    'v35-only':  { label: 'V35 ONLY', color: '#ff6b6b', severity: 'warn' },
    unknown:     { label: '?',        color: '#555577', severity: 'muted' },
  }),
  classify(miner: Pick<PplnsMiner, 'version' | 'desiredVersion'>): string {
    const v = miner.version;
    const dv = miner.desiredVersion;
    if (typeof v !== 'number') return 'unknown';
    if (v >= 36) return 'v36';
    if (typeof dv === 'number' && dv >= 36) return 'v35-to-v36';
    return 'v35-only';
  },
};

/** Default LTC + DOGE merged descriptor. Coins like Dash override
 *  with `mergedChains: []`. */
export const LTC_COIN_PPLNS_DESCRIPTOR: CoinPplnsDescriptor = {
  mergedChains: [
    Object.freeze({
      symbol: 'DOGE',
      displayLabel: 'Dogecoin',
      color: '#ffd700',
      tooltipLabel: 'DOGE',
      addressExplorer: 'https://blockchair.com/dogecoin/address/',
    }),
  ],
  versionBadges: LTC_VERSION_BADGES,
  formatHashrate: formatHashrate,
  addressExplorer: 'https://blockchair.com/litecoin/address/',
};

/** Default hashrate formatter: pick unit so the mantissa is ∈ [1,1000).
 *  Caps at P (petahash). Returns "0" for non-positive input. */
export function formatHashrate(hps: number): string {
  if (!(hps > 0)) return '0 H/s';
  const units = ['H/s', 'KH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s'];
  let idx = 0;
  let v = hps;
  while (v >= 1000 && idx < units.length - 1) {
    v /= 1000;
    idx++;
  }
  const digits = v >= 100 ? 0 : v >= 10 ? 1 : 2;
  return `${v.toFixed(digits)} ${units[idx]}`;
}
