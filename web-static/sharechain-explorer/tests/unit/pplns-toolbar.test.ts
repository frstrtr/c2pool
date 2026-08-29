// Toolbar tests: sort dropdown, version chips, search input,
// Ctrl-F focus shortcut, minerVersionKey classification.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  renderToolbar,
  minerVersionKey,
  type ToolbarCallbacks,
  type ToolbarState,
} from '../../src/pplns/toolbar.js';
import { LTC_COIN_PPLNS_DESCRIPTOR } from '../../src/pplns/classify.js';
import type { PplnsSnapshot } from '../../src/pplns/types.js';

const hasDom = typeof document !== 'undefined';

const snapshot: PplnsSnapshot = {
  totalPrimary: 3,
  mergedChains: [],
  mergedTotals: {},
  schemaVersion: '1.0',
  miners: [
    { address: 'L1', amount: 1, pct: 0.33, merged: [], version: 36 },
    { address: 'L2', amount: 1, pct: 0.33, merged: [],
      version: 35, desiredVersion: 36 },
    { address: 'L3', amount: 1, pct: 0.33, merged: [], version: 35 },
  ],
};

function makeArgs(
  overrides: Partial<ToolbarState & { callbacks: Partial<ToolbarCallbacks> }> = {},
): {
  host: HTMLElement;
  state: ToolbarState;
  callbacks: ToolbarCallbacks;
} {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const defaults: ToolbarState = {
    sort:              overrides.sort ?? 'amount',
    search:            overrides.search ?? '',
    activeVersionKeys: overrides.activeVersionKeys ?? new Set(),
  };
  const cbs: ToolbarCallbacks = {
    onSortChange: overrides.callbacks?.onSortChange ?? (() => undefined),
    onSearchChange: overrides.callbacks?.onSearchChange ?? (() => undefined),
    onVersionKeysChange: overrides.callbacks?.onVersionKeysChange ?? (() => undefined),
  };
  return { host, state: defaults, callbacks: cbs };
}

// ── minerVersionKey ──────────────────────────────────────────────────

test('minerVersionKey: v36 / v35-to-v36 / v35-only / unknown', () => {
  const k = (miner: {version?: number; desiredVersion?: number}) =>
    minerVersionKey(miner, LTC_COIN_PPLNS_DESCRIPTOR);
  assert.equal(k({ version: 36 }),                           'v36');
  assert.equal(k({ version: 35, desiredVersion: 36 }),       'v35-to-v36');
  assert.equal(k({ version: 35 }),                           'v35-only');
  assert.equal(k({}),                                        'unknown');
});

// ── renderToolbar ────────────────────────────────────────────────────

test('renderToolbar: emits one chip per present version badge',
     { skip: !hasDom }, () => {
  const args = makeArgs();
  renderToolbar({
    host: args.host,
    state: args.state,
    snapshot,
    coin: LTC_COIN_PPLNS_DESCRIPTOR,
    callbacks: args.callbacks,
  });
  const chips = args.host.querySelectorAll('button');
  // Chips: V36, V35→V36, V35 ONLY = 3 buttons; plus no "Clear".
  assert.equal(chips.length, 3);
  assert.ok(args.host.textContent?.includes('V36'));
  assert.ok(args.host.textContent?.includes('V35 ONLY'));
});

test('renderToolbar: sort select fires onSortChange',
     { skip: !hasDom }, () => {
  const calls: string[] = [];
  const args = makeArgs({
    callbacks: { onSortChange: (k) => calls.push(k) },
  });
  renderToolbar({
    host: args.host,
    state: args.state,
    snapshot,
    coin: LTC_COIN_PPLNS_DESCRIPTOR,
    callbacks: args.callbacks,
  });
  const sel = args.host.querySelector('select') as HTMLSelectElement;
  sel.value = 'hashrate';
  sel.dispatchEvent(new Event('change'));
  assert.deepEqual(calls, ['hashrate']);
});

test('renderToolbar: chip click toggles version key',
     { skip: !hasDom }, () => {
  const received: ReadonlySet<string>[] = [];
  const args = makeArgs({
    callbacks: { onVersionKeysChange: (s) => received.push(s) },
  });
  renderToolbar({
    host: args.host,
    state: args.state,
    snapshot,
    coin: LTC_COIN_PPLNS_DESCRIPTOR,
    callbacks: args.callbacks,
  });
  // Click the first chip (V36).
  const chip = args.host.querySelector('button') as HTMLButtonElement;
  chip.click();
  assert.equal(received.length, 1);
  assert.ok(received[0]!.has('v36'));
});

test('renderToolbar: search input fires onSearchChange on input',
     { skip: !hasDom }, () => {
  const calls: string[] = [];
  const args = makeArgs({
    callbacks: { onSearchChange: (s) => calls.push(s) },
  });
  renderToolbar({
    host: args.host,
    state: args.state,
    snapshot,
    coin: LTC_COIN_PPLNS_DESCRIPTOR,
    callbacks: args.callbacks,
  });
  const input = args.host.querySelector(
    'input[type="search"]') as HTMLInputElement;
  input.value = 'Lab';
  input.dispatchEvent(new Event('input'));
  assert.deepEqual(calls, ['Lab']);
});

test('renderToolbar: Ctrl-F focuses search input when mounted',
     { skip: !hasDom }, () => {
  const args = makeArgs();
  renderToolbar({
    host: args.host,
    state: args.state,
    snapshot,
    coin: LTC_COIN_PPLNS_DESCRIPTOR,
    callbacks: args.callbacks,
  });
  const input = args.host.querySelector(
    'input[type="search"]') as HTMLInputElement;
  // JSDOM polyfill: dispatch a KeyboardEvent-like to document.
  const ev = new KeyboardEvent('keydown', {
    key: 'f', ctrlKey: true, bubbles: true, cancelable: true,
  });
  document.dispatchEvent(ev);
  assert.equal(document.activeElement, input);
});

test('renderToolbar: Ctrl-F is ignored once toolbar is detached',
     { skip: !hasDom }, () => {
  const args = makeArgs();
  renderToolbar({
    host: args.host,
    state: args.state,
    snapshot,
    coin: LTC_COIN_PPLNS_DESCRIPTOR,
    callbacks: args.callbacks,
  });
  args.host.parentNode?.removeChild(args.host);
  // Should not throw, should not focus anything.
  document.dispatchEvent(new KeyboardEvent('keydown', {
    key: 'f', ctrlKey: true, bubbles: true, cancelable: true,
  }));
});
