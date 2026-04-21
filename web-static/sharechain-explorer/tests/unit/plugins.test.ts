// Unit tests for baseline SharedCore plugins.
//   - treemap (squarify)
//   - addr-hue
//   - short-hash
//   - hashrate-si
//   - i18n-en (translate)
//
// Plugins that create DOM nodes (sparkline, tooltip, aria-live-log) are
// covered by jsdom-hosted tests in a separate file once jsdom is wired;
// until then they're exercised via the bundle in browser/Qt harness.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  squarify,
  addrHue,
  addrHsl,
  shortHash,
  formatHashrate,
  EN_CATALOG,
  translate,
} from '../../src/index.js';

// ── squarify ─────────────────────────────────────────────────────
test('squarify: empty input returns empty', () => {
  assert.deepEqual(squarify([], 0, 0, 100, 100), []);
});

test('squarify: zero dimensions returns empty', () => {
  const r = squarify([{ area: 1, label: 'a' }], 0, 0, 0, 100);
  assert.deepEqual(r, []);
});

test('squarify: single item fills area', () => {
  const r = squarify([{ area: 1, label: 'a' }], 0, 0, 100, 50);
  assert.equal(r.length, 1);
  const [rect] = r;
  assert.equal(rect?.x, 0);
  assert.equal(rect?.y, 0);
  assert.equal(rect?.label, 'a');
});

test('squarify: opaque fields pass through', () => {
  const r = squarify(
    [{ area: 0.5, addr: 'X' }, { area: 0.5, addr: 'Y' }],
    0, 0, 100, 50,
  );
  const addrs = r.map((x) => x.addr);
  assert.deepEqual(addrs.sort(), ['X', 'Y']);
});

test('squarify: negative/NaN areas filtered', () => {
  const r = squarify(
    [{ area: 1, ok: true }, { area: -1 }, { area: NaN }],
    0, 0, 100, 100,
  );
  assert.equal(r.length, 1);
  assert.equal(r[0]?.ok, true);
});

test('squarify: total coverage close to 100%', () => {
  const items = Array.from({ length: 10 }, (_, i) => ({ area: 0.1, i }));
  const r = squarify(items, 0, 0, 200, 100);
  const totalArea = r.reduce((s, rec) => s + rec.w * rec.h, 0);
  const ratio = totalArea / (200 * 100);
  assert.ok(ratio >= 0.99 && ratio <= 1.01, `ratio ${ratio}`);
});

test('squarify: no overlapping rectangles', () => {
  const items = Array.from({ length: 20 }, (_, i) => ({ area: 1 / 20, i }));
  const r = squarify(items, 0, 0, 400, 300);
  for (let i = 0; i < r.length; i++) {
    for (let j = i + 1; j < r.length; j++) {
      const a = r[i]!;
      const b = r[j]!;
      const overlap =
        a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
      assert.equal(overlap, false, `rects ${i} and ${j} overlap`);
    }
  }
});

// ── addr-hue ─────────────────────────────────────────────────────
test('addrHue: deterministic', () => {
  assert.equal(addrHue('XabcDEF'), addrHue('XabcDEF'));
});

test('addrHue: different addresses likely different hues', () => {
  const a = addrHue('X1111111111');
  const b = addrHue('X2222222222');
  assert.notEqual(a, b);
});

test('addrHue: in [0, 360)', () => {
  for (const addr of ['X', 'Xabcd', 'Xaaaaa', 'Z9z9z9z9z9', '']) {
    const h = addrHue(addr);
    assert.ok(h >= 0 && h < 360, `hue ${h} out of range for ${addr}`);
  }
});

test('addrHsl: status controls saturation/lightness', () => {
  const ok = addrHsl('XAA', 'ok');
  const muted = addrHsl('XAA', 'muted');
  const warn = addrHsl('XAA', 'warn');
  assert.equal(ok.h, muted.h);
  assert.equal(ok.h, warn.h);
  assert.notEqual(ok.s, muted.s);
  assert.notEqual(ok.l, muted.l);
});

// ── short-hash ───────────────────────────────────────────────────
test('shortHash: truncates to 16 chars lowercase', () => {
  assert.equal(shortHash('000000000000352836AAA0BCDE'), '0000000000003528');
});

test('shortHash: short input passes through lowercase', () => {
  assert.equal(shortHash('ABC'), 'abc');
});

// ── hashrate-si ──────────────────────────────────────────────────
test('formatHashrate: zero', () => {
  assert.equal(formatHashrate(0), '0 H/s');
});

test('formatHashrate: various scales', () => {
  assert.equal(formatHashrate(500), '500.00 H/s');
  assert.equal(formatHashrate(1500), '1.50 kH/s');
  assert.equal(formatHashrate(2_500_000), '2.50 MH/s');
  assert.equal(formatHashrate(3_500_000_000), '3.50 GH/s');
  assert.equal(formatHashrate(4_500_000_000_000), '4.50 TH/s');
});

test('formatHashrate: defensive on NaN/negative', () => {
  assert.equal(formatHashrate(NaN), '0 H/s');
  assert.equal(formatHashrate(-5), '0 H/s');
});

// ── i18n-en ──────────────────────────────────────────────────────
test('translate: known key', () => {
  assert.equal(translate(EN_CATALOG, 'generic.loading'), 'Loading…');
});

test('translate: placeholder substitution', () => {
  const s = translate(EN_CATALOG, 'explorer.share.born', {
    hash: 'abc', miner: 'X1', pct: '5.2',
  });
  assert.match(s, /abc.*X1.*5\.2/);
});

test('translate: unknown key returns key verbatim', () => {
  assert.equal(translate(EN_CATALOG, 'does.not.exist'), 'does.not.exist');
});

test('translate: missing placeholder stays bracketed', () => {
  const s = translate(EN_CATALOG, 'explorer.share.born', { hash: 'A' });
  assert.match(s, /\{miner\}/);
});
