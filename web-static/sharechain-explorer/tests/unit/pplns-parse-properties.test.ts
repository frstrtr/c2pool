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

// ── Regression: non-finite numbers (Infinity / -Infinity / NaN) ──────
// Pinned counterexamples for the fast-check flake on PRs #49/#50
// (seed -1679627146, shrunk input [Infinity]). A bare Infinity in the
// legacy flat-map shape was assigned to amount without finite filtering,
// so it survived the amount > 0 guard and poisoned totalPrimary. These
// explicit cases lock the three non-finite shapes regardless of seed.

test('parseSnapshot: non-finite amounts are dropped, total stays finite', () => {
  // Array shape: Object.entries([x]) -> ["0", x], hits the legacy
  // bare-number branch — the exact path the property test shrank to.
  for (const raw of [[Infinity], [-Infinity], [NaN]]) {
    const snap = parseSnapshot(raw);
    assert.ok(Number.isFinite(snap.totalPrimary),
      `totalPrimary not finite for ${String(raw[0])}`);
    assert.equal(snap.totalPrimary, 0);
    assert.equal(snap.miners.length, 0);
    // Required-keys contract (mirrors the property assertions at L107-112).
    assert.equal(typeof snap.totalPrimary, 'number');
    assert.ok(Array.isArray(snap.mergedChains));
    assert.ok(snap.mergedTotals !== null && typeof snap.mergedTotals === 'object');
    assert.equal(typeof snap.schemaVersion, 'string');
    assert.ok(Array.isArray(snap.miners));
  }
});

test('parseSnapshot: finite amounts whose SUM overflows stay finite', () => {
  // Each amount is finite and passes the amount>0 guard, but the
  // aggregate overflows to +Infinity. totalPrimary must be clamped
  // finite (finiteTotal). Shrunk counterexample: seed 1831858192,
  // raw = [8.98e292, 1.797e308] (legacy bare-number / array path).
  const big = 1.797693134862315e+308; // just under Number.MAX_VALUE
  for (const raw of [
    [8.98128139290624e+292, big],                 // legacy array path
    { a: big, b: big },                            // legacy dict path
    { total_primary: 0,                            // new-shape fallback sum
      miners: [{ address: 'a', amount: big, pct: 0 },
               { address: 'b', amount: big, pct: 0 }] },
  ]) {
    const snap = parseSnapshot(raw);
    assert.ok(Number.isFinite(snap.totalPrimary),
      `totalPrimary overflowed for ${JSON.stringify(raw).slice(0, 40)}`);
    // Per-miner pct must remain a finite number in [0,1].
    for (const m of snap.miners) {
      assert.ok(Number.isFinite(m.pct));
      assert.ok(m.pct >= 0 && m.pct <= 1.0000001);
    }
  }
});

test('parseSnapshot: non-finite legacy-object amounts are dropped', () => {
  // Legacy { addr: { amount } } shape with a non-finite amount field.
  for (const bad of [Infinity, -Infinity, NaN]) {
    const snap = parseSnapshot({ miner1: { amount: bad } });
    assert.ok(Number.isFinite(snap.totalPrimary));
    assert.equal(snap.totalPrimary, 0);
    assert.equal(snap.miners.length, 0);
  }
});

test('parseSnapshot: non-finite new-shape miner amounts are dropped', () => {
  // New shape: a miner row whose amount is non-finite must not appear
  // and must not poison the totalPrimary fallback sum.
  for (const bad of [Infinity, -Infinity, NaN]) {
    const snap = parseSnapshot({
      total_primary: 0,
      miners: [{ address: 'a', amount: bad, pct: 0 }],
    });
    assert.ok(Number.isFinite(snap.totalPrimary));
    assert.equal(snap.totalPrimary, 0);
    assert.equal(snap.miners.length, 0);
  }
});
