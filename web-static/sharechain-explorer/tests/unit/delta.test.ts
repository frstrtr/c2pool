// Unit tests for the delta merger.
// Spec contract: c2pool-sharechain-explorer-module-task.md §5.3.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  mergeDelta,
  type DeltaShare,
} from '../../src/explorer/index.js';

function s(h: string, extra: Record<string, unknown> = {}): DeltaShare {
  return { h, ...extra };
}

// ── Empty cases ──────────────────────────────────────────────────

test('empty delta → shares unchanged', () => {
  const current = { shares: [s('a'), s('b'), s('c')], tip: 'a' };
  const r = mergeDelta(current, { shares: [] }, { windowSize: 100 });
  assert.deepEqual(r.shares.map((x) => x.h), ['a', 'b', 'c']);
  assert.equal(r.added.length, 0);
  assert.equal(r.evicted.length, 0);
  assert.equal(r.forkSwitch, false);
  assert.equal(r.tip, 'a');
});

test('empty current + empty delta → empty result', () => {
  const r = mergeDelta({ shares: [] }, { shares: [] }, { windowSize: 100 });
  assert.equal(r.shares.length, 0);
  assert.equal(r.tip, undefined);
});

// ── Normal prepend ───────────────────────────────────────────────

test('prepends delta shares newest-first', () => {
  const current = { shares: [s('b'), s('c')], tip: 'b' };
  const r = mergeDelta(current, { shares: [s('a')] }, { windowSize: 100 });
  assert.deepEqual(r.shares.map((x) => x.h), ['a', 'b', 'c']);
  assert.deepEqual(r.added.map((x) => x.h), ['a']);
  assert.equal(r.tip, 'a');
  assert.equal(r.forkSwitch, false);
});

test('preserves multi-share delta order', () => {
  const current = { shares: [s('z')] };
  const r = mergeDelta(current, { shares: [s('a'), s('b'), s('c')] }, { windowSize: 100 });
  assert.deepEqual(r.shares.map((x) => x.h), ['a', 'b', 'c', 'z']);
  assert.equal(r.tip, 'a');
});

test('opaque payload fields pass through', () => {
  const current = { shares: [] };
  const r = mergeDelta(
    current,
    { shares: [s('a', { miner: 'Xfoo', v: 1 })] },
    { windowSize: 100 },
  );
  assert.equal((r.shares[0] as { miner?: string }).miner, 'Xfoo');
  assert.equal((r.shares[0] as { v?: number }).v, 1);
});

// ── Dedup ────────────────────────────────────────────────────────

test('dedup: delta share that already exists in window is skipped', () => {
  const current = { shares: [s('a'), s('b')], tip: 'a' };
  const r = mergeDelta(current, { shares: [s('a')] }, { windowSize: 100 });
  assert.deepEqual(r.shares.map((x) => x.h), ['a', 'b']);
  assert.equal(r.added.length, 0);
});

test('dedup: duplicates within a single delta collapse', () => {
  const r = mergeDelta(
    { shares: [] },
    { shares: [s('a'), s('b'), s('a'), s('c')] },
    { windowSize: 100 },
  );
  assert.deepEqual(r.shares.map((x) => x.h), ['a', 'b', 'c']);
});

// ── Window cap / eviction ────────────────────────────────────────

test('evicts oldest when prepend pushes past windowSize', () => {
  const current = { shares: [s('b'), s('c'), s('d')] };
  const r = mergeDelta(current, { shares: [s('a')] }, { windowSize: 3 });
  assert.deepEqual(r.shares.map((x) => x.h), ['a', 'b', 'c']);
  assert.deepEqual(r.evicted, ['d']);
});

test('evicts multiple when delta is large', () => {
  const current = { shares: [s('x'), s('y'), s('z')] };
  const r = mergeDelta(
    current,
    { shares: [s('a'), s('b'), s('c'), s('d')] },
    { windowSize: 5 },
  );
  assert.deepEqual(r.shares.map((x) => x.h), ['a', 'b', 'c', 'd', 'x']);
  assert.deepEqual(r.evicted, ['y', 'z']);
});

test('windowSize 0 + maxShares undefined => no cap (unlimited)', () => {
  const r = mergeDelta(
    { shares: [s('x'), s('y')] },
    { shares: [s('a'), s('b'), s('c')] },
    { windowSize: 0 },
  );
  assert.equal(r.shares.length, 5);
  assert.equal(r.evicted.length, 0);
});

test('maxShares overrides windowSize', () => {
  const current = { shares: [s('b'), s('c')] };
  const r = mergeDelta(current, { shares: [s('a')] }, { windowSize: 100, maxShares: 2 });
  assert.deepEqual(r.shares.map((x) => x.h), ['a', 'b']);
});

// ── Fork switch ──────────────────────────────────────────────────

test('fork_switch: rebuilds from delta alone, evicts entire current window', () => {
  const current = { shares: [s('x'), s('y'), s('z')], tip: 'x' };
  const r = mergeDelta(
    current,
    { shares: [s('a'), s('b')], fork_switch: true },
    { windowSize: 100 },
  );
  assert.deepEqual(r.shares.map((x) => x.h), ['a', 'b']);
  assert.equal(r.forkSwitch, true);
  assert.deepEqual(r.evicted.sort(), ['x', 'y', 'z']);
  assert.deepEqual(r.added.map((x) => x.h), ['a', 'b']);
  assert.equal(r.tip, 'a');
});

test('fork_switch: dedups within delta', () => {
  const r = mergeDelta(
    { shares: [s('x')] },
    { shares: [s('a'), s('a'), s('b')], fork_switch: true },
    { windowSize: 100 },
  );
  assert.deepEqual(r.shares.map((x) => x.h), ['a', 'b']);
});

test('fork_switch: respects windowSize cap', () => {
  const r = mergeDelta(
    { shares: [s('x'), s('y')] },
    {
      shares: [s('a'), s('b'), s('c'), s('d'), s('e')],
      fork_switch: true,
    },
    { windowSize: 3 },
  );
  assert.deepEqual(r.shares.map((x) => x.h), ['a', 'b', 'c']);
  assert.equal(r.forkSwitch, true);
});

test('fork_switch + empty delta → empty shares + tip undefined', () => {
  const r = mergeDelta(
    { shares: [s('x'), s('y')], tip: 'x' },
    { shares: [], fork_switch: true },
    { windowSize: 100 },
  );
  assert.equal(r.shares.length, 0);
  assert.equal(r.tip, undefined);
  assert.deepEqual(r.evicted.sort(), ['x', 'y']);
});

// ── Immutability ─────────────────────────────────────────────────

test('does not mutate current.shares', () => {
  const currentShares = [s('b'), s('c')];
  const current = { shares: currentShares, tip: 'b' };
  mergeDelta(current, { shares: [s('a')] }, { windowSize: 100 });
  assert.deepEqual(currentShares.map((x) => x.h), ['b', 'c']);
});

test('does not mutate delta.shares', () => {
  const deltaShares = [s('a'), s('b')];
  mergeDelta({ shares: [s('c')] }, { shares: deltaShares }, { windowSize: 100 });
  assert.deepEqual(deltaShares.map((x) => x.h), ['a', 'b']);
});

// ── Stress / sanity ──────────────────────────────────────────────

test('window stress: preserves length after saturation', () => {
  const W = 500;
  let window = { shares: [] as DeltaShare[], tip: undefined as string | undefined };
  // Fill with enough batches to guarantee saturation: ~3000 shares total.
  let counter = 0;
  for (let batch = 0; batch < 1000; batch++) {
    const batchSize = 1 + Math.floor(Math.random() * 5);
    const newShares = [];
    for (let i = 0; i < batchSize; i++) {
      newShares.push(s(`h${counter++}`));
    }
    const r = mergeDelta(window, { shares: newShares }, { windowSize: W });
    window = { shares: r.shares as DeltaShare[], tip: r.tip };
    assert.ok(window.shares.length <= W, `length ${window.shares.length} > ${W} at batch ${batch}`);
  }
  assert.equal(window.shares.length, W);
  // Tip matches the newest share.
  assert.equal(window.tip, window.shares[0]?.h);
});

test('invariant: no duplicate short-hashes after arbitrary merge sequence', () => {
  let window = { shares: [] as DeltaShare[] };
  let id = 0;
  const history = new Set<string>();
  for (let i = 0; i < 100; i++) {
    const batch: DeltaShare[] = [];
    const n = 1 + (i % 5);
    for (let j = 0; j < n; j++) {
      // Mix in occasional repeats
      if (history.size > 0 && Math.random() < 0.2) {
        const arr = [...history];
        batch.push(s(arr[Math.floor(Math.random() * arr.length)] ?? `h${id}`));
      } else {
        const h = `h${id++}`;
        history.add(h);
        batch.push(s(h));
      }
    }
    const r = mergeDelta(window, { shares: batch }, { windowSize: 50 });
    window = { shares: r.shares as DeltaShare[] };
    const hashes = window.shares.map((x) => x.h);
    assert.equal(hashes.length, new Set(hashes).size, `duplicates at iter ${i}`);
  }
});
