// shared.short-hash.prefix16 — truncates a full hex hash to its first
// 16 characters, per Explorer spec §5 contract.
// Provides capability `short-hash`.

import type { PluginDescriptor } from '../registry.js';

export type ShortHashFn = (fullHash: string) => string;

export const shortHash: ShortHashFn = (fullHash) => {
  if (fullHash.length <= 16) return fullHash.toLowerCase();
  return fullHash.slice(0, 16).toLowerCase();
};

export const ShortHashPlugin: PluginDescriptor = {
  id: 'shared.short-hash.prefix16',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'util',
  provides: ['short-hash'],
  priority: 0,
  capabilities: {
    'short-hash': shortHash,
  },
};
