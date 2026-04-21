// shared.hashrate.si-units — formats H/s with SI prefixes.
// Handles 0, NaN, and negative defensively (returns "0 H/s").
// Provides capability `hashrate-formatter`.

import type { PluginDescriptor } from '../registry.js';

export type HashrateFormatter = (hps: number, precision?: number) => string;

const UNITS = ['H/s', 'kH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s', 'EH/s'] as const;

export const formatHashrate: HashrateFormatter = (hps, precision = 2) => {
  if (!isFinite(hps) || hps <= 0) return `0 ${UNITS[0]}`;
  let i = 0;
  let v = hps;
  while (v >= 1000 && i < UNITS.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v.toFixed(precision)} ${UNITS[i]}`;
};

export const HashrateSiPlugin: PluginDescriptor = {
  id: 'shared.hashrate.si-units',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'util',
  provides: ['hashrate-formatter'],
  priority: 0,
  capabilities: {
    'hashrate-formatter': formatHashrate,
  },
};
