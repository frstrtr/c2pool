// shared.i18n.en — English translation catalog (delta v1 §H.2).
// Key format: dotted namespace "section.term" with {placeholder} slots.
// Plugin ships the catalog as a capability; a higher-level dispatcher
// (to come in M3) resolves keys through active-locale fallback.
// Provides capability `i18n.catalog`.

import type { PluginDescriptor } from '../registry.js';

export interface I18nCatalog {
  readonly locale: string;
  readonly strings: Readonly<Record<string, string>>;
}

export const EN_CATALOG: I18nCatalog = Object.freeze({
  locale: 'en',
  strings: Object.freeze({
    // Generic
    'generic.loading':           'Loading…',
    'generic.error':             'Error',
    'generic.unknown':           'Unknown',
    'generic.yes':               'Yes',
    'generic.no':                'No',

    // Sharechain Explorer
    'explorer.legend.title':     'Legend',
    'explorer.stats.title':      'Chain Window',
    'explorer.stat.shares':      'Shares',
    'explorer.stat.chainLength': 'Chain length',
    'explorer.stat.verified':    'Verified',
    'explorer.stat.thisNode':    'This node',
    'explorer.stat.orphan':      'Orphan / stale',
    'explorer.stat.dead':        'Dead',
    'explorer.stat.nodeFee':     'Node fee',
    'explorer.stat.blocksFound': 'Blocks found',
    'explorer.toggle.realtime':  'Real-time',
    'explorer.toggle.fastmode':  'Fast animation',
    'explorer.share.born':       'Share {hash} born from {miner}, PPLNS {pct}%',
    'explorer.share.died':       'Share {hash} evicted from window',
    'explorer.share.blockFound': 'Block found! {symbol}',

    // PPLNS View
    'pplns.title':               'PPLNS Payouts',
    'pplns.miner.header':        'Miner',
    'pplns.miner.amount':        'Amount',
    'pplns.miner.pct':           'Share',
    'pplns.miner.hashrate':      'Hashrate',
    'pplns.miner.version':       'Version',
    'pplns.miner.mergedChains':  'Merged',
    'pplns.drill.title':         'Miner detail',
    'pplns.drill.history':       'Version history',
    'pplns.drill.recentShares':  'Recent shares',
    'pplns.action.copyAddress':  'Copy address',
    'pplns.action.openExplorer': 'View on block explorer',

    // Errors
    'error.transport':           'Network error',
    'error.schema':              'Server response malformed',
    'error.contract':            'Server contract violation',
    'error.version_mismatch':    'Incompatible server version',
    'error.rate_limited':        'Rate limited — please wait',
    'error.fork_switch':         'Chain reorganisation — reloading',
    'error.internal':            'Internal error',
  }),
});

export const I18nEnPlugin: PluginDescriptor = {
  id: 'shared.i18n.en',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'util',
  provides: ['i18n.catalog'],
  priority: 0,
  capabilities: {
    'i18n.catalog': EN_CATALOG,
  },
};

/** Resolve an i18n key with {placeholder} substitution. Returns the key
 *  verbatim on miss. Callers typically go through a dispatcher plugin,
 *  not this function directly. */
export function translate(
  catalog: I18nCatalog,
  key: string,
  vars?: Readonly<Record<string, string | number>>,
): string {
  const raw = catalog.strings[key];
  if (raw === undefined) return key;
  if (vars === undefined) return raw;
  return raw.replace(/\{(\w+)\}/g, (_m, name) => {
    const v = vars[name];
    return v === undefined ? `{${name}}` : String(v);
  });
}
