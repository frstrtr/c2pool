// @c2pool/sharechain-explorer — Dash coin descriptor.
// Spec: frstrtr/the/docs/c2pool-sharechain-explorer-module-task.md §4.4
// Consumed by the bundled Explorer as `window.DASH_DESCRIPTOR`.
//
// Pool params (reference: frstrtr/p2pool-dash/p2pool/networks/dash.py):
//   share_period = 20s, chain_length = 4320, current share VERSION = 16.
//
// Dash has no merged mining at this time — `merged` is null. If Platform
// merged-mining is added later, mirror the LTC/DOGE pattern: set
// `merged: { symbol: 'PLATFORM', blockColor: '#…', … }`.

(function () {
  window.DASH_DESCRIPTOR = {
    // ── Required ────────────────────────────────────────────────────
    symbol:          'DASH',
    shareVersion:    16,
    windowSize:      4320,
    sharePeriodSec:  20,

    // ── Colour palette ───────────────────────────────────────────
    // Defaults from §4.4. Dash-specific tweak: `blockSolution` gold
    // matches the "DASH block" legend row.
    colors: {
      native:        '#00e676',
      nativeMine:    '#00b0ff',
      signaling:     '#26c6da',
      signalingMine: '#0097a7',
      legacy:        '#2e7d32',
      legacyMine:    '#1565c0',
      unverified:    '#555577',
      stale:         '#ffc107',
      dead:          '#dc3545',
      fee:           '#9c27b0',
      blockSolution: '#ffd700',
      // twinBlock unused — no merged mining.
    },

    // ── Legend rows ────────────────────────────────────────────────
    // Dash ships a single live share version (16). No DOGE block /
    // Twin block entries — merged mining is not in scope.
    legend: [
      { key: 'native',        label: 'Dash v16 share' },
      { key: 'unverified',    label: 'Unverified'     },
      { key: 'stale',         label: 'Orphan / Stale' },
      { key: 'dead',          label: 'Dead'           },
      { key: 'fee',           label: 'Node fee share' },
      { key: 'blockSolution', label: 'DASH block'     },
      { key: 'chainHead',     label: 'Chain head'     },
    ],

    // ── Right-panel stat rows ──────────────────────────────────────
    // blocksFound renders as "<N> DASH" — no second chain.
    stats: ['shares', 'chainLength', 'verified', 'thisNode',
            'orphan', 'dead', 'nodeFee', 'blocksFound'],

    // ── Merged-mining config ────────────────────────────────────────
    merged: null,

    // ── Block-explorer links ────────────────────────────────────────
    // Mirrors the URLs in /web/currency_info so dashboard links stay
    // in sync with the rest of the app.
    blockExplorer: {
      address: 'https://blockchair.com/dash/address/',
      block:   'https://blockchair.com/dash/block/',
      tx:      'https://blockchair.com/dash/transaction/',
    },

    // ── Version classifier ──────────────────────────────────────────
    // Dash currently ships V=16 only. When a future boundary arrives
    // (e.g. V17 with v16 nodes signalling via desired_version), extend
    // this to return 'signaling' when share.dv points forward.
    classifyVersion: function (share) {
      return share.V === 16 ? 'native' : 'legacy';
    },
  };
})();
