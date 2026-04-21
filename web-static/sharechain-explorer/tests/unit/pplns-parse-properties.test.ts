// Property-based tests for parseSnapshot + parseMinerDetail.
// Per delta v1 §G.2 — the parsers must be total (never throw) and
// preserve structural invariants regardless of input shape, since
// they sit at the server→client trust boundary.
//
// Strategy: fast-check generates arbitrary shapes (including
// hostile / malformed input) and asserts:
//   1. parseSnapshot never throws.
//   2. parseSnapshot output always has the required keys with
//      correct types.
//   3. When miners[] is populated, every entry has {address:str,
//      amount>0, pct:number, merged:array}.
//   4. miners[] is sorted by amount descending (defensive sort
//      we added in parseNewShape).
//   5. parseMinerDetail never throws; returns null OR a shape
//      with address:str, inWindow:bool, merged:array.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import { parseSnapshot, parseMinerDetail } from '../../src/pplns/parse.js';

// ── Arbitrary generators ─────────────────────────────────────────────

// Anything goes — null, primitives, objects, arrays, nested. Used as
// a chaos input to prove total parsing.
const arbAny = fc.anything({ maxDepth: 4 });

// A semi-plausible snake_case miner entry (mix of valid / invalid).
const arbMinerNew = fc.record({
  address: fc.oneof(fc.string(), fc.constant(undefined), fc.integer()),
  amount: fc.oneof(fc.double({ min: -1, max: 1000 }), fc.constant(undefined)),
  pct: fc.oneof(fc.double({ min: 0, max: 1 }), fc.constant(undefined)),
  shares_in_window: fc.oneof(fc.integer(), fc.constant(undefined)),
  hashrate_hps: fc.oneof(fc.double({ min: 0, max: 1e12 }), fc.constant(undefined)),
  version: fc.oneof(fc.integer({ min: 0, max: 50 }), fc.constant(undefined)),
  desired_version: fc.oneof(fc.integer({ min: 0, max: 50 }), fc.constant(undefined)),
  last_share_at: fc.oneof(fc.integer(), fc.constant(undefined)),
  merged: fc.oneof(
    fc.constant(undefined),
    fc.array(
      fc.record({
        symbol: fc.oneof(fc.string(), fc.constant('DOGE'),
                          fc.constant(undefined)),
        address: fc.oneof(fc.string(), fc.constant(undefined)),
        amount: fc.oneof(fc.double(), fc.constant(undefined)),
        pct: fc.oneof(fc.double(), fc.constant(undefined)),
        source: fc.oneof(fc.constant('donation'),
                          fc.constant('auto-convert'),
                          fc.constant('explicit'),
                          fc.constant('bogus'),
                          fc.constant(undefined)),
      }),
      { maxLength: 3 }),
  ),
}, { requiredKeys: [] });

// Semi-plausible /pplns/current payload.
const arbSnapshotNew = fc.record({
  tip: fc.oneof(fc.string({ maxLength: 16 }), fc.constant(undefined)),
  window_size: fc.oneof(fc.integer({ min: 0, max: 10000 }), fc.constant(undefined)),
  coin: fc.oneof(fc.string({ maxLength: 10 }), fc.constant(undefined)),
  total_primary: fc.oneof(fc.double({ min: 0, max: 1e6 }), fc.constant(undefined)),
  merged_chains: fc.oneof(
    fc.array(fc.string({ maxLength: 10 }), { maxLength: 3 }),
    fc.constant(undefined)),
  merged_totals: fc.oneof(
    fc.dictionary(fc.string({ maxLength: 10 }), fc.double({ min: 0, max: 1e6 })),
    fc.constant(undefined)),
  computed_at: fc.oneof(fc.integer(), fc.constant(undefined)),
  schema_version: fc.oneof(fc.constant('1.0'), fc.string(), fc.constant(undefined)),
  miners: fc.array(arbMinerNew, { maxLength: 12 }),
}, { requiredKeys: ['miners'] });

// Legacy shape: flat map addr → amount | {amount, merged[]}.
const arbSnapshotLegacy = fc.dictionary(
  fc.string({ maxLength: 20 }),
  fc.oneof(
    fc.double({ min: -10, max: 100 }),
    fc.record({
      amount: fc.oneof(fc.double({ min: -1, max: 100 }), fc.constant(undefined)),
      merged: fc.oneof(
        fc.array(
          fc.record({
            symbol: fc.oneof(fc.string(), fc.constant(undefined)),
            address: fc.oneof(fc.string(), fc.constant(undefined)),
            addr: fc.oneof(fc.string(), fc.constant(undefined)),
            amount: fc.oneof(fc.double(), fc.constant(undefined)),
          }, { requiredKeys: [] }),
          { maxLength: 2 }),
        fc.constant(undefined)),
    }, { requiredKeys: [] }),
  ));

// ── parseSnapshot ────────────────────────────────────────────────────

test('parseSnapshot: never throws on arbitrary input', () => {
  fc.assert(fc.property(arbAny, (raw) => {
    parseSnapshot(raw);
  }), { numRuns: 300 });
});

test('parseSnapshot: output always has required keys with correct types', () => {
  fc.assert(fc.property(arbAny, (raw) => {
    const snap = parseSnapshot(raw);
    assert.equal(typeof snap.totalPrimary, 'number');
    assert.ok(Number.isFinite(snap.totalPrimary));
    assert.ok(Array.isArray(snap.mergedChains));
    assert.ok(snap.mergedTotals !== null && typeof snap.mergedTotals === 'object');
    assert.equal(typeof snap.schemaVersion, 'string');
    assert.ok(Array.isArray(snap.miners));
  }), { numRuns: 300 });
});

test('parseSnapshot: each miner entry is well-formed', () => {
  fc.assert(fc.property(arbSnapshotNew, (raw) => {
    const snap = parseSnapshot(raw);
    for (const m of snap.miners) {
      assert.equal(typeof m.address, 'string');
      assert.ok(m.address.length > 0);
      assert.ok(m.amount > 0);
      assert.equal(typeof m.pct, 'number');
      assert.ok(Number.isFinite(m.pct));
      assert.ok(Array.isArray(m.merged));
    }
  }), { numRuns: 300 });
});

test('parseSnapshot: miners[] sorted by amount descending', () => {
  fc.assert(fc.property(arbSnapshotNew, (raw) => {
    const snap = parseSnapshot(raw);
    for (let i = 1; i < snap.miners.length; i++) {
      const prev = snap.miners[i - 1]!.amount;
      const cur = snap.miners[i]!.amount;
      assert.ok(prev >= cur, `out-of-order: ${prev} before ${cur}`);
    }
  }), { numRuns: 300 });
});

test('parseSnapshot: totalPrimary equals sum of miner amounts when server did not supply one', () => {
  fc.assert(fc.property(arbSnapshotNew, (raw) => {
    // Force the "server omitted total_primary" branch.
    const copy = { ...raw, total_primary: 0 };
    const snap = parseSnapshot(copy);
    if (snap.miners.length === 0) return;
    const sum = snap.miners.reduce((s, m) => s + m.amount, 0);
    // parseSnapshot falls back to sum when total_primary <= 0; allow
    // a tiny float epsilon.
    assert.ok(Math.abs(snap.totalPrimary - sum) < 1e-9);
  }), { numRuns: 200 });
});

test('parseSnapshot: legacy shape → positive miners', () => {
  fc.assert(fc.property(arbSnapshotLegacy, (raw) => {
    const snap = parseSnapshot(raw);
    for (const m of snap.miners) {
      assert.ok(m.amount > 0);
      // Legacy shape must fabricate pct from amount/total_primary.
      assert.ok(m.pct >= 0 && m.pct <= 1.0000001);
    }
  }), { numRuns: 200 });
});

test('parseSnapshot: merged[] entries are well-typed', () => {
  fc.assert(fc.property(arbSnapshotNew, (raw) => {
    const snap = parseSnapshot(raw);
    for (const m of snap.miners) {
      for (const mp of m.merged) {
        assert.equal(typeof mp.symbol, 'string');
        assert.equal(typeof mp.address, 'string');
        assert.equal(typeof mp.amount, 'number');
        assert.ok(mp.amount > 0);
      }
    }
  }), { numRuns: 300 });
});

// ── parseMinerDetail ─────────────────────────────────────────────────

test('parseMinerDetail: never throws on arbitrary input', () => {
  fc.assert(fc.property(arbAny, (raw) => {
    parseMinerDetail(raw);
  }), { numRuns: 300 });
});

test('parseMinerDetail: null-or-well-formed return contract', () => {
  fc.assert(fc.property(arbAny, (raw) => {
    const d = parseMinerDetail(raw);
    if (d === null) return;
    assert.equal(typeof d.address, 'string');
    assert.ok(d.address.length > 0);
    assert.equal(typeof d.inWindow, 'boolean');
    assert.ok(Array.isArray(d.merged));
  }), { numRuns: 300 });
});

const arbMinerDetail = fc.record({
  address: fc.oneof(fc.string({ minLength: 1, maxLength: 40 }),
                     fc.constant(undefined),
                     fc.integer()),
  in_window: fc.oneof(fc.boolean(), fc.constant(undefined)),
  amount: fc.oneof(fc.double({ min: 0, max: 100 }), fc.constant(undefined)),
  pct: fc.oneof(fc.double({ min: 0, max: 1 }), fc.constant(undefined)),
  shares_in_window: fc.oneof(fc.integer({ min: 0 }), fc.constant(undefined)),
  shares_total: fc.oneof(fc.integer({ min: 0 }), fc.constant(undefined)),
  first_seen_at: fc.oneof(fc.integer(), fc.constant(undefined)),
  last_share_at: fc.oneof(fc.integer(), fc.constant(undefined)),
  hashrate_hps: fc.oneof(fc.double({ min: 0, max: 1e12 }),
                         fc.constant(undefined)),
  hashrate_series: fc.oneof(
    fc.array(fc.record({
      t: fc.oneof(fc.integer(), fc.string(), fc.constant(undefined)),
      hps: fc.oneof(fc.double(), fc.constant(undefined)),
    }, { requiredKeys: [] }), { maxLength: 8 }),
    fc.constant(undefined)),
  version: fc.oneof(fc.integer({ min: 0, max: 50 }), fc.constant(undefined)),
  desired_version: fc.oneof(fc.integer({ min: 0, max: 50 }),
                             fc.constant(undefined)),
  version_history: fc.oneof(
    fc.array(fc.record({
      t: fc.oneof(fc.integer(), fc.constant(undefined)),
      version: fc.oneof(fc.integer({ min: 0, max: 50 }),
                         fc.constant(undefined)),
      desired_version: fc.oneof(fc.integer({ min: 0, max: 50 }),
                                 fc.constant(undefined)),
    }, { requiredKeys: [] }), { maxLength: 8 }),
    fc.constant(undefined)),
  recent_shares: fc.oneof(
    fc.array(fc.record({
      h: fc.oneof(fc.string(), fc.constant(undefined)),
      t: fc.oneof(fc.integer(), fc.constant(undefined)),
      s: fc.oneof(fc.integer({ min: 0, max: 1 }), fc.constant(undefined)),
      V: fc.oneof(fc.integer({ min: 0, max: 50 }), fc.constant(undefined)),
    }, { requiredKeys: [] }), { maxLength: 8 }),
    fc.constant(undefined)),
  merged: fc.oneof(
    fc.array(fc.record({
      symbol: fc.oneof(fc.string(), fc.constant(undefined)),
      address: fc.oneof(fc.string(), fc.constant(undefined)),
      amount: fc.oneof(fc.double(), fc.constant(undefined)),
      pct: fc.oneof(fc.double(), fc.constant(undefined)),
    }, { requiredKeys: [] }), { maxLength: 3 }),
    fc.constant(undefined)),
}, { requiredKeys: [] });

test('parseMinerDetail: well-formed input produces typed output', () => {
  fc.assert(fc.property(arbMinerDetail, (raw) => {
    const d = parseMinerDetail(raw);
    if (d === null) return;
    if (d.hashrateSeries !== undefined) {
      for (const p of d.hashrateSeries) {
        assert.equal(typeof p.t, 'number');
        assert.equal(typeof p.hps, 'number');
      }
    }
    if (d.versionHistory !== undefined) {
      for (const p of d.versionHistory) {
        assert.equal(typeof p.t, 'number');
        assert.equal(typeof p.version, 'number');
      }
    }
    if (d.recentShares !== undefined) {
      for (const s of d.recentShares) {
        assert.equal(typeof s.h, 'string');
        assert.ok(s.h.length > 0);
        assert.equal(typeof s.t, 'number');
      }
    }
    for (const mp of d.merged) {
      assert.equal(typeof mp.symbol, 'string');
      assert.equal(typeof mp.address, 'string');
      assert.ok(mp.amount > 0);
    }
  }), { numRuns: 300 });
});
