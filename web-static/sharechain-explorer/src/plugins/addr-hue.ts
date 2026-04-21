// shared.addr.hue-hash — deterministic address → HSL hue mapping.
// djb2-style hash. Stable across renders: the same address always
// picks the same colour, making miners visually identifiable.
// Provides capability `address-classifier.hue`.

import type { PluginDescriptor } from '../registry.js';

export type AddrHueFn = (address: string) => number;

export const addrHue: AddrHueFn = (address) => {
  let h = 5381;
  for (let i = 0; i < address.length; i++) {
    h = ((h << 5) + h) ^ address.charCodeAt(i);
    h |= 0;
  }
  return Math.abs(h) % 360;
};

export interface HslTriple { h: number; s: number; l: number }

/** Suggested HSL for a miner cell — hue from address, saturation +
 *  lightness keyed to status ('ok' | 'muted' | 'warn'). */
export function addrHsl(address: string, status: 'ok' | 'muted' | 'warn' = 'ok'): HslTriple {
  const h = addrHue(address);
  switch (status) {
    case 'muted': return { h, s: 30, l: 25 };
    case 'warn':  return { h, s: 70, l: 45 };
    case 'ok':
    default:      return { h, s: 45, l: 32 };
  }
}

export const AddrHuePlugin: PluginDescriptor = {
  id: 'shared.addr.hue-hash',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'util',
  provides: ['address-classifier.hue'],
  priority: 0,
  capabilities: {
    'address-classifier.hue': { addrHue, addrHsl },
  },
};
