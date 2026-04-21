// Unit tests for the per-miner drill-down panel: parseMinerDetail
// shape tolerance + renderMinerDetail DOM safety + open/close
// lifecycle. Covers spec §5.2 contract rules.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseMinerDetail } from '../../src/pplns/parse.js';
import { renderMinerDetail } from '../../src/pplns/detail.js';
import { LTC_COIN_PPLNS_DESCRIPTOR } from '../../src/pplns/classify.js';
import type { PplnsMinerDetail } from '../../src/pplns/types.js';

const hasDom = typeof document !== 'undefined';

// ── parseMinerDetail ─────────────────────────────────────────────────

test('parseMinerDetail: returns null on non-object', () => {
  assert.equal(parseMinerDetail(null), null);
  assert.equal(parseMinerDetail(42), null);
  assert.equal(parseMinerDetail('nope'), null);
});

test('parseMinerDetail: returns null when address missing', () => {
  assert.equal(parseMinerDetail({}), null);
  assert.equal(parseMinerDetail({ address: 123 }), null);
});

test('parseMinerDetail: populates every optional field from full payload', () => {
  const raw = {
    address: 'Labc',
    in_window: true,
    amount: 1.5,
    pct: 0.04,
    shares_in_window: 12,
    shares_total: 3400,
    first_seen_at: 1000000000,
    last_share_at: 1700000000,
    hashrate_hps: 500_000_000,
    hashrate_series: [
      { t: 1, hps: 100 },
      { t: 2, hps: 200 },
      'garbage',
      { t: 'x', hps: 0 },   // non-numeric t rejected
    ],
    version: 36,
    desired_version: 36,
    version_history: [
      { t: 10, version: 35, desired_version: 35 },
      { t: 20, version: 36 },
      { garbage: true },
    ],
    merged: [
      { symbol: 'DOGE', address: 'D1', amount: 0.5, pct: 0.1, source: 'auto-convert' },
      { symbol: 'DOGE', address: 'D2', amount: 0 },   // zero-amount dropped
    ],
    recent_shares: [
      { h: 'abcdef', t: 1700000000, V: 36, s: 0 },
      { h: 'deadbeef', t: 1699999000, s: 1 },
      { h: '', t: 1 },        // empty hash dropped
    ],
  };
  const d = parseMinerDetail(raw);
  assert.ok(d !== null);
  assert.equal(d.address, 'Labc');
  assert.equal(d.inWindow, true);
  assert.equal(d.amount, 1.5);
  assert.equal(d.hashrateSeries?.length, 2);
  assert.equal(d.versionHistory?.length, 2);
  assert.equal(d.merged.length, 1);
  assert.equal(d.recentShares?.length, 2);
  assert.equal(d.recentShares?.[1]?.s, 1);
});

test('parseMinerDetail: in_window defaults to false when missing', () => {
  const d = parseMinerDetail({ address: 'X' });
  assert.ok(d !== null);
  assert.equal(d.inWindow, false);
  assert.deepEqual(d.merged, []);
  assert.equal(d.hashrateSeries, undefined);
});

// ── renderMinerDetail (DOM) ──────────────────────────────────────────

function makeHost(): HTMLElement {
  const host = document.createElement('div');
  host.style.width  = '600px';
  host.style.height = '400px';
  document.body.appendChild(host);
  return host;
}

test('renderMinerDetail: attaches panel to host and close() removes it',
     { skip: !hasDom }, () => {
  const host = makeHost();
  const detail: PplnsMinerDetail = {
    address: 'Labc', inWindow: true, amount: 1, pct: 0.1,
    merged: [],
  };
  const handle = renderMinerDetail({
    host, detail, coin: LTC_COIN_PPLNS_DESCRIPTOR,
  });
  assert.ok(host.querySelector('.pplns-detail-panel') !== null);
  handle.close();
  assert.equal(host.querySelector('.pplns-detail-panel'), null);
});

test('renderMinerDetail: address text uses textContent (XSS regression)',
     { skip: !hasDom }, () => {
  const host = makeHost();
  const hostile: PplnsMinerDetail = {
    address: '<img src=x onerror=window.__panelXss=1>',
    inWindow: true,
    merged: [{
      symbol: 'DOGE',
      address: '<script>window.__panelXss=2</script>',
      amount: 0.1,
      pct: 0.05,
    }],
  };
  renderMinerDetail({
    host, detail: hostile, coin: LTC_COIN_PPLNS_DESCRIPTOR,
  });
  assert.equal(host.querySelector('img'), null);
  assert.equal(host.querySelector('script'), null);
  assert.equal((globalThis as { __panelXss?: number }).__panelXss, undefined);
});

test('renderMinerDetail: sparkline rendered when hashrateSeries has 2+ points',
     { skip: !hasDom }, () => {
  const host = makeHost();
  const detail: PplnsMinerDetail = {
    address: 'Labc', inWindow: true, hashrateHps: 100, merged: [],
    hashrateSeries: [
      { t: 1, hps: 100 },
      { t: 2, hps: 150 },
      { t: 3, hps: 200 },
    ],
  };
  renderMinerDetail({ host, detail, coin: LTC_COIN_PPLNS_DESCRIPTOR });
  const svg = host.querySelector('svg');
  assert.ok(svg !== null, 'expected inline sparkline SVG');
  const paths = svg!.querySelectorAll('path');
  assert.ok(paths.length >= 1, 'sparkline path missing');
});

test('renderMinerDetail: recent shares table renders one row per share + header',
     { skip: !hasDom }, () => {
  const host = makeHost();
  const detail: PplnsMinerDetail = {
    address: 'Labc', inWindow: true, merged: [],
    recentShares: [
      { h: 'abcd', t: 1700000000, V: 36 },
      { h: 'efgh', t: 1700000050, V: 35, s: 1 },
    ],
  };
  renderMinerDetail({ host, detail, coin: LTC_COIN_PPLNS_DESCRIPTOR });
  // Grid has header row (4 cells) + 2 share rows (4 cells each) = 12 cells.
  // Grab the column label header to anchor the grid.
  assert.ok(host.textContent?.includes('abcd'));
  assert.ok(host.textContent?.includes('efgh'));
});
