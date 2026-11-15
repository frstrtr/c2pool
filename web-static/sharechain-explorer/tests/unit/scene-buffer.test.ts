// Scene engine: the fixed 56-byte instance record, packed colours,
// easing, and the linked-selection bus.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  InstanceBuffer, RECORD_BYTES, RECORD_WORDS,
  W_FROM_X, W_TO_H, W_FROM_RGBA, W_TO_RGBA, W_T0, W_DUR, W_FLAGS, W_PAD,
  rgba, red, green, blue, alpha, lerpRgba, hsl, toCss,
  smootherstep, progress,
  createSelectionBus, matchesQuery,
} from '../../src/scene/index.js';

const rec = (over: Partial<Parameters<InstanceBuffer['write']>[1]> = {}) => ({
  fromX: 1, fromY: 2, fromW: 3, fromH: 4, toX: 5, toY: 6, toW: 7, toH: 8,
  fromRgba: rgba(10, 20, 30, 40), toRgba: rgba(50, 60, 70, 80),
  t0: 1234.5, dur: 500, flags: 0x0502, ...over,
});

test('record layout: 56 bytes, 14 words, fixed word offsets', () => {
  assert.equal(RECORD_BYTES, 56);
  assert.equal(RECORD_WORDS, 14);
  assert.deepEqual([W_FROM_X, W_TO_H, W_FROM_RGBA, W_TO_RGBA, W_T0, W_DUR, W_FLAGS, W_PAD], [0, 7, 8, 9, 10, 11, 12, 13]);
  const b = new InstanceBuffer(4);
  const s = b.alloc();
  b.write(s, rec());
  const bytes = new Uint8Array(b.bytes, s * RECORD_BYTES, RECORD_BYTES);
  // Colours sit at byte 32 and 36 in memory order R, G, B, A.
  assert.deepEqual([...bytes.slice(32, 36)], [10, 20, 30, 40]);
  assert.deepEqual([...bytes.slice(36, 40)], [50, 60, 70, 80]);
  const dv = new DataView(b.bytes, s * RECORD_BYTES, RECORD_BYTES);
  assert.equal(dv.getFloat32(0, true), 1);
  assert.equal(dv.getFloat32(28, true), 8);
  assert.equal(dv.getFloat32(40, true), 1234.5);
  assert.equal(dv.getFloat32(44, true), 500);
  assert.equal(dv.getUint32(48, true), 0x0502);
  assert.equal(dv.getUint32(52, true), 0, 'pad is zero');
  assert.deepEqual(b.read(s), rec());
});

test('slots: freed slots are reused, trailing holes trimmed, renderers skip free slots', () => {
  const b = new InstanceBuffer(2);
  const a = b.alloc(), c = b.alloc(), d = b.alloc();
  assert.deepEqual([a, c, d], [0, 1, 2]);
  assert.equal(b.count, 3);
  b.write(c, rec());
  b.release(c);
  assert.equal(b.count, 3, 'a hole in the middle keeps the high-water mark');
  assert.equal(b.read(c).fromRgba | b.read(c).toRgba, 0, 'a free slot is fully transparent');
  assert.equal(b.alloc(), c, 'hole reused first');
  b.release(d);
  assert.equal(b.count, 2, 'a trailing hole is trimmed');
  b.release(c);
  assert.equal(b.count, 1);
  assert.equal(b.holes, 0);
});

test('dirty ranges cover exactly the written slots, then clear', () => {
  const b = new InstanceBuffer(8);
  for (let i = 0; i < 6; i++) b.alloc();
  b.takeDirty();
  b.write(4, rec());
  b.write(2, rec());
  assert.deepEqual(b.takeDirty(), [{ start: 2, end: 5 }]);
  assert.deepEqual(b.takeDirty(), []);
  b.markAllDirty();
  assert.deepEqual(b.takeDirty(), [{ start: 0, end: 6 }]);
});

test('growth keeps every record and bumps the generation', () => {
  const b = new InstanceBuffer(1);
  const g0 = b.generation;
  const slots = Array.from({ length: 5 }, () => b.alloc());
  slots.forEach((s, i) => b.write(s, rec({ fromX: i })));
  assert.ok(b.capacity >= 5);
  assert.ok(b.generation > g0);
  slots.forEach((s, i) => assert.equal(b.read(s).fromX, i));
});

test('colour packing, interpolation and CSS', () => {
  const c = rgba(1, 2, 3, 4);
  assert.deepEqual([red(c), green(c), blue(c), alpha(c)], [1, 2, 3, 4]);
  assert.ok(c >= 0, 'unsigned');
  assert.equal(lerpRgba(rgba(0, 0, 0, 0), rgba(200, 100, 50, 255), 0.5), rgba(100, 50, 25, 128));
  assert.equal(hsl(0, 100, 50), rgba(255, 0, 0, 255));
  assert.equal(hsl(120, 100, 50), rgba(0, 255, 0, 255));
  assert.equal(toCss(rgba(255, 0, 0, 255), 0.25), 'rgba(255,0,0,0.25)');
});

test('easing: smootherstep endpoints, symmetry, monotone; zero duration is done', () => {
  assert.equal(smootherstep(0), 0);
  assert.equal(smootherstep(1), 1);
  assert.equal(smootherstep(0.5), 0.5);
  assert.equal(smootherstep(-1), 0);
  assert.equal(smootherstep(2), 1);
  let prev = 0;
  for (let i = 1; i <= 100; i++) {
    const v = smootherstep(i / 100);
    assert.ok(v >= prev);
    assert.ok(Math.abs(v + smootherstep(1 - i / 100) - 1) < 1e-12);
    prev = v;
  }
  assert.equal(progress(10, 0, 0), 1);
  assert.equal(progress(0, 0, 100), 0);
  assert.equal(progress(100, 0, 100), 1);
});

test('selection bus: hover, pin, toggle, search; no-op changes are silent', () => {
  const bus = createSelectionBus();
  const seen: string[] = [];
  const off = bus.subscribe((s) => seen.push(`${s.hover}|${s.pinned}|${s.query}|${s.source}`));
  bus.hover('Xa', 'treemap');
  bus.hover('Xa', 'treemap');
  bus.togglePin('Xa', 'treemap');
  bus.togglePin('Xa', 'grid');
  bus.search('  XA ', 'toolbar');
  off();
  bus.hover(null);
  assert.deepEqual(seen, [
    'Xa|null||treemap',
    'Xa|Xa||treemap',
    'Xa|null||grid',
    'Xa|null|xa|toolbar',
  ]);
  assert.equal(matchesQuery('XabcDEF', 'cde'), true);
  assert.equal(matchesQuery('Xabc', ''), false);
});
