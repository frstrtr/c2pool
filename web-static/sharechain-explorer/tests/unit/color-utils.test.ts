// Unit tests for the colour utilities used by the animator.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseHexColor,
  lerpColor,
  applyAlpha,
  lerpColorWithAlpha,
} from '../../src/explorer/index.js';

// ── parseHexColor ────────────────────────────────────────────────

test('parseHexColor: 6-digit hex', () => {
  assert.deepEqual(parseHexColor('#ff8800'), { r: 255, g: 136, b: 0 });
  assert.deepEqual(parseHexColor('#000000'), { r: 0, g: 0, b: 0 });
  assert.deepEqual(parseHexColor('#ffffff'), { r: 255, g: 255, b: 255 });
});

test('parseHexColor: 3-digit shorthand', () => {
  assert.deepEqual(parseHexColor('#f80'), { r: 255, g: 136, b: 0 });
});

test('parseHexColor: 8-digit with alpha ignores alpha', () => {
  assert.deepEqual(parseHexColor('#ff8800aa'), { r: 255, g: 136, b: 0 });
});

test('parseHexColor: rejects non-hex / rgb', () => {
  assert.equal(parseHexColor('#gg0000'), null);
  assert.equal(parseHexColor('rgb(255,0,0)'), null);
  assert.equal(parseHexColor(''), null);
});

// ── lerpColor ────────────────────────────────────────────────────

test('lerpColor: endpoints', () => {
  assert.equal(lerpColor('#ff0000', '#0000ff', 0), 'rgb(255,0,0)');
  assert.equal(lerpColor('#ff0000', '#0000ff', 1), 'rgb(0,0,255)');
});

test('lerpColor: midpoint', () => {
  const r = lerpColor('#ff0000', '#0000ff', 0.5);
  // sRGB-naive midpoint: (128, 0, 128) with rounding
  assert.match(r, /^rgb\(128,0,128\)$/);
});

test('lerpColor: clamps t to [0,1]', () => {
  assert.equal(lerpColor('#ff0000', '#0000ff', -1), 'rgb(255,0,0)');
  assert.equal(lerpColor('#ff0000', '#0000ff', 2), 'rgb(0,0,255)');
});

test('lerpColor: falls back on unparseable input', () => {
  assert.equal(lerpColor('bogus', '#000', 0.5), 'bogus');
});

// ── applyAlpha ───────────────────────────────────────────────────

test('applyAlpha: hex → rgba()', () => {
  assert.equal(applyAlpha('#ff0000', 0.5), 'rgba(255,0,0,0.5)');
});

test('applyAlpha: clamps alpha', () => {
  assert.equal(applyAlpha('#000', -0.1), 'rgba(0,0,0,0)');
  assert.equal(applyAlpha('#000', 1.5), 'rgba(0,0,0,1)');
});

test('applyAlpha: rgb() → rgba()', () => {
  assert.equal(applyAlpha('rgb(10,20,30)', 0.3), 'rgba(10,20,30,0.3)');
});

test('applyAlpha: rgba() → rgba() with new alpha', () => {
  assert.equal(applyAlpha('rgba(1,2,3,0.9)', 0.1), 'rgba(1,2,3,0.1)');
});

// ── lerpColorWithAlpha ───────────────────────────────────────────

test('lerpColorWithAlpha: composes both helpers', () => {
  const s = lerpColorWithAlpha('#ff0000', '#0000ff', 0.5, 0.25);
  assert.match(s, /^rgba\(128,0,128,0\.25\)$/);
});
