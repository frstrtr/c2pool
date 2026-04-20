// Unit tests for the PPLNS View module: squarify, classify, parse,
// render (DOM + XSS safety). Controller-level tests (tip event →
// refetch, refresh flow, destroy fence) deferred to a follow-up.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { squarify } from '../../src/pplns/squarify.js';
import { parseSnapshot } from '../../src/pplns/parse.js';
import {
  LTC_VERSION_BADGES,
  LTC_COIN_PPLNS_DESCRIPTOR,
  DASH_VERSION_BADGES,
  DASH_COIN_PPLNS_DESCRIPTOR,
  formatHashrate,
} from '../../src/pplns/classify.js';
import { render } from '../../src/pplns/render.js';
import { addrHash, addrColor } from '../../src/pplns/colors.js';
import type { PplnsSnapshot } from '../../src/pplns/types.js';

// ── Squarify ──────────────────────────────────────────────────────

test('squarify: empty items returns []', () => {
  assert.deepEqual(squarify([], 0, 0, 100, 100), []);
});

test('squarify: zero/negative box returns []', () => {
  assert.deepEqual(
    squarify([{ area: 1, data: 'a' }], 0, 0, 0, 100),
    [],
  );
  assert.deepEqual(
    squarify([{ area: 1, data: 'a' }], 0, 0, 100, 0),
    [],
  );
});

test('squarify: single item fills the whole rect', () => {
  const out = squarify([{ area: 5, data: 'x' }], 0, 0, 100, 100);
  assert.equal(out.length, 1);
  assert.deepEqual(out[0], { x: 0, y: 0, w: 100, h: 100, data: 'x' });
});

test('squarify: degenerate items filtered', () => {
  const out = squarify(
    [
      { area: 0, data: 'a' },
      { area: -1, data: 'b' },
      { area: NaN, data: 'c' },
      { area: 10, data: 'd' },
    ],
    0, 0, 50, 50,
  );
  assert.equal(out.length, 1);
  assert.equal(out[0]?.data, 'd');
});

test('squarify: total area preserved to within rounding', () => {
  const items = Array.from({ length: 12 }, (_, i) => ({
    area: 1 + (i % 4),
    data: i,
  }));
  const out = squarify(items, 0, 0, 400, 300);
  const total = out.reduce((s, r) => s + r.w * r.h, 0);
  assert.ok(Math.abs(total - 400 * 300) < 1e-6,
    `total area ${total} ≠ 400*300`);
});

test('squarify: stable ordering when areas tie', () => {
  const items = Array.from({ length: 8 }, (_, i) => ({ area: 1, data: i }));
  const out1 = squarify(items, 0, 0, 80, 80);
  const out2 = squarify(items, 0, 0, 80, 80);
  assert.deepEqual(
    out1.map((r) => r.data),
    out2.map((r) => r.data),
  );
});

test('squarify: large stress test produces no NaN / Infinity', () => {
  const items = Array.from({ length: 1000 }, (_, i) => ({
    area: Math.random() * 10 + 0.1,
    data: i,
  }));
  const out = squarify(items, 0, 0, 1200, 800);
  for (const r of out) {
    assert.ok(Number.isFinite(r.x) && Number.isFinite(r.y));
    assert.ok(Number.isFinite(r.w) && Number.isFinite(r.h));
    assert.ok(r.w >= 0 && r.h >= 0);
  }
});

// ── Parse ─────────────────────────────────────────────────────────

test('parseSnapshot: new shape passes through', () => {
  const raw = {
    tip: 'aabbccdd',
    window_size: 4320,
    coin: 'LTC',
    total_primary: 1.5,
    merged_chains: ['DOGE'],
    merged_totals: { DOGE: 500 },
    schema_version: '1.0',
    miners: [
      { address: 'A', amount: 1.0, pct: 0.667,
        version: 36, desired_version: 36,
        hashrate_hps: 100, shares_in_window: 50, last_share_at: 1776,
        merged: [{ symbol: 'DOGE', address: 'D_A',
                   amount: 333, pct: 0.667, source: 'auto-convert' }] },
      { address: 'B', amount: 0.5, pct: 0.333, merged: [] },
    ],
  };
  const snap = parseSnapshot(raw);
  assert.equal(snap.miners.length, 2);
  assert.equal(snap.miners[0]?.address, 'A');
  assert.equal(snap.miners[0]?.hashrateHps, 100);
  assert.equal(snap.miners[0]?.merged[0]?.source, 'auto-convert');
  assert.deepEqual(snap.mergedChains, ['DOGE']);
});

test('parseSnapshot: legacy /current_merged_payouts shape accepted', () => {
  const raw = {
    Xaddr1: 1.0,
    Xaddr2: {
      amount: 0.5,
      merged: [
        { addr: 'D_Xaddr2', amount: 100 },   // no symbol → defaults to DOGE
      ],
    },
    Xaddr3: 0,                              // zero — dropped
    bad: 'not-a-number',                    // bad — dropped
  };
  const snap = parseSnapshot(raw);
  assert.equal(snap.miners.length, 2);
  // Sorted by amount desc
  assert.equal(snap.miners[0]?.address, 'Xaddr1');
  assert.equal(snap.miners[1]?.address, 'Xaddr2');
  assert.deepEqual(snap.mergedChains, ['DOGE']);
  // pct computed
  assert.equal(snap.totalPrimary, 1.5);
  assert.ok(Math.abs(snap.miners[0]!.pct - 2/3) < 1e-6);
});

test('parseSnapshot: invalid entries silently dropped', () => {
  const raw = {
    miners: [
      { address: 'ok', amount: 1, pct: 1, merged: [] },
      { address: '', amount: 1, pct: 0, merged: [] },      // empty addr
      { amount: 1, pct: 0, merged: [] },                    // no addr
      { address: 'z', amount: 0, pct: 0, merged: [] },      // zero amount
      'not-an-object',
    ],
  };
  const snap = parseSnapshot(raw);
  assert.equal(snap.miners.length, 1);
  assert.equal(snap.miners[0]?.address, 'ok');
});

// ── Classify + formatHashrate ─────────────────────────────────────

test('LTC_VERSION_BADGES: classify matches spec', () => {
  const c = LTC_VERSION_BADGES.classify;
  assert.equal(c({ version: 36 }), 'v36');
  assert.equal(c({ version: 35, desiredVersion: 36 }), 'v35-to-v36');
  assert.equal(c({ version: 35, desiredVersion: 35 }), 'v35-only');
  assert.equal(c({}), 'unknown');
});

test('DASH_VERSION_BADGES: classify matches spec (v16 boundary)', () => {
  const c = DASH_VERSION_BADGES.classify;
  assert.equal(c({ version: 16 }), 'v16');
  assert.equal(c({ version: 17 }), 'v16');    // ≥16 stays current
  assert.equal(c({ version: 15 }), 'stale');
  assert.equal(c({}), 'unknown');
});

test('DASH_COIN_PPLNS_DESCRIPTOR: no merged chains, Dash explorer link', () => {
  assert.deepEqual(DASH_COIN_PPLNS_DESCRIPTOR.mergedChains, []);
  assert.match(DASH_COIN_PPLNS_DESCRIPTOR.addressExplorer!,
               /blockchair\.com\/dash\/address/);
});

test('formatHashrate: scales through k/M/G/T/P', () => {
  assert.match(formatHashrate(0), /^0 H\/s$/);
  assert.match(formatHashrate(500), /^500 H\/s$/);
  assert.match(formatHashrate(1_500), /^1\.50 KH\/s$/);
  assert.match(formatHashrate(2_500_000), /^2\.50 MH\/s$/);
  assert.match(formatHashrate(3.4e12), /TH\/s$/);
});

// ── Colors ────────────────────────────────────────────────────────

test('addrHash: deterministic + positive', () => {
  const h1 = addrHash('XaddrFoo');
  const h2 = addrHash('XaddrFoo');
  const h3 = addrHash('XaddrBar');
  assert.equal(h1, h2);
  assert.notEqual(h1, h3);
  assert.ok(h1 >= 0);
});

test('addrColor: returns hsl string with valid fields', () => {
  const c = addrColor('XaddrFoo');
  assert.match(c, /^hsl\(\d+,\s*\d+%,\s*\d+%\)$/);
});

// ── Render: DOM structure + XSS safety ────────────────────────────

// Minimal DOM shim — enough for renderer to produce elements we can
// inspect. Node doesn't ship a DOM; tests run under --experimental-dom
// or a shim. For this commit, we detect and skip when `document` is
// absent; the renderer is otherwise covered indirectly by the squarify
// + parse tests and by the visual harness (post-integration).
const hasDom = typeof (globalThis as { document?: Document }).document !== 'undefined';

test('render: skips cleanly when no miners', { skip: !hasDom }, () => {
  const container = document.createElement('div');
  container.style.width  = '200px';
  container.style.height = '200px';
  // JSDOM returns 0×0 BoundingClientRect for unattached elements — we
  // only need the path to not throw.
  const empty: PplnsSnapshot = {
    totalPrimary: 0,
    mergedChains: [],
    mergedTotals: {},
    schemaVersion: '1.0',
    miners: [],
  };
  render({
    container,
    snapshot: empty,
    coin: LTC_COIN_PPLNS_DESCRIPTOR,
    opts: {
      minCellPx: 28, showVersionBadge: true,
      showHashrate: true, showMerged: true,
    },
  });
  // With zero miners, renderEmpty() path fires.
  assert.ok(container.firstChild !== null);
});

test('render: address text uses textContent (XSS regression)',
     { skip: !hasDom }, () => {
  const container = document.createElement('div');
  container.style.width  = '400px';
  container.style.height = '300px';
  Object.defineProperty(container, 'getBoundingClientRect', {
    value: () => ({ x: 0, y: 0, top: 0, left: 0,
                    width: 400, height: 300, right: 400, bottom: 300,
                    toJSON: () => ({}) }),
  });
  const hostile: PplnsSnapshot = {
    totalPrimary: 1,
    mergedChains: [],
    mergedTotals: {},
    schemaVersion: '1.0',
    miners: [
      {
        address: '<img src=x onerror=window.__xss=1>',
        amount: 1, pct: 1, merged: [],
      },
    ],
  };
  render({
    container,
    snapshot: hostile,
    coin: LTC_COIN_PPLNS_DESCRIPTOR,
    opts: {
      minCellPx: 28, showVersionBadge: true,
      showHashrate: true, showMerged: true,
    },
  });
  const img = container.querySelector('img');
  assert.equal(img, null, 'hostile <img> must not parse into DOM');
  // And the global sentinel must remain unset.
  assert.equal((globalThis as { __xss?: number }).__xss, undefined);
});
