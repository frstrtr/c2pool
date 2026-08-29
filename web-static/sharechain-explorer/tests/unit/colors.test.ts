// Unit tests for Explorer Colors plugin.
// Verifies classification priority + palette mapping preserved from
// dashboard.html:5404-5429 exactly.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyShare,
  getColor,
  LTC_COLOR_PALETTE,
  type ShareForClassify,
  type UserContext,
} from '../../src/explorer/index.js';

const LTC_CTX: UserContext = {
  myAddress: 'XmyAddr',
  shareVersion: 36,
};

function share(over: Partial<ShareForClassify> = {}): ShareForClassify {
  return { s: 0, v: 1, V: 36, dv: 36, m: 'XotherAddr', ...over };
}

// ── classifyShare: priority order ────────────────────────────────

test('classifyShare: dead beats everything', () => {
  assert.equal(classifyShare(share({ s: 2, v: 0, V: 20, fee: 1 }), LTC_CTX), 'dead');
});

test('classifyShare: stale beats unverified', () => {
  assert.equal(classifyShare(share({ s: 1, v: 0 }), LTC_CTX), 'stale');
});

test('classifyShare: unverified beats fee', () => {
  assert.equal(classifyShare(share({ v: 0, fee: 1 }), LTC_CTX), 'unverified');
});

test('classifyShare: fee short-circuits version tier', () => {
  assert.equal(classifyShare(share({ fee: 1, V: 20 }), LTC_CTX), 'fee');
});

test('classifyShare: native when V >= shareVersion', () => {
  assert.equal(classifyShare(share({ V: 36, dv: 36 }), LTC_CTX), 'native');
  assert.equal(classifyShare(share({ V: 37, dv: 37 }), LTC_CTX), 'native');
});

test('classifyShare: signaling when V < threshold but dv >= threshold', () => {
  assert.equal(classifyShare(share({ V: 35, dv: 36 }), LTC_CTX), 'signaling');
});

test('classifyShare: legacy when both V and dv < threshold', () => {
  assert.equal(classifyShare(share({ V: 35, dv: 35 }), LTC_CTX), 'legacy');
});

test('classifyShare: threshold comes from context (Dash V16 example)', () => {
  const dashCtx: UserContext = { shareVersion: 16 };
  assert.equal(classifyShare(share({ V: 16, dv: 16 }), dashCtx), 'native');
  assert.equal(classifyShare(share({ V: 15, dv: 16 }), dashCtx), 'signaling');
  assert.equal(classifyShare(share({ V: 15, dv: 15 }), dashCtx), 'legacy');
});

// ── getColor: palette mapping ────────────────────────────────────

test('getColor: dead → palette.dead', () => {
  assert.equal(getColor(share({ s: 2 }), LTC_CTX), LTC_COLOR_PALETTE.dead);
});

test('getColor: stale → palette.stale', () => {
  assert.equal(getColor(share({ s: 1 }), LTC_CTX), LTC_COLOR_PALETTE.stale);
});

test('getColor: unverified → palette.unverified', () => {
  assert.equal(getColor(share({ v: 0 }), LTC_CTX), LTC_COLOR_PALETTE.unverified);
});

test('getColor: fee → palette.fee (ignores mine)', () => {
  assert.equal(getColor(share({ fee: 1, m: 'XmyAddr' }), LTC_CTX), LTC_COLOR_PALETTE.fee);
});

test('getColor: native non-mine', () => {
  assert.equal(getColor(share(), LTC_CTX), LTC_COLOR_PALETTE.native);
});

test('getColor: native mine', () => {
  assert.equal(getColor(share({ m: 'XmyAddr' }), LTC_CTX), LTC_COLOR_PALETTE.nativeMine);
});

test('getColor: signaling non-mine', () => {
  assert.equal(
    getColor(share({ V: 35, dv: 36 }), LTC_CTX),
    LTC_COLOR_PALETTE.signaling,
  );
});

test('getColor: signaling mine', () => {
  assert.equal(
    getColor(share({ V: 35, dv: 36, m: 'XmyAddr' }), LTC_CTX),
    LTC_COLOR_PALETTE.signalingMine,
  );
});

test('getColor: legacy non-mine', () => {
  assert.equal(
    getColor(share({ V: 35, dv: 35 }), LTC_CTX),
    LTC_COLOR_PALETTE.legacy,
  );
});

test('getColor: legacy mine', () => {
  assert.equal(
    getColor(share({ V: 35, dv: 35, m: 'XmyAddr' }), LTC_CTX),
    LTC_COLOR_PALETTE.legacyMine,
  );
});

test('getColor: empty/undefined myAddress does NOT mark as mine', () => {
  const ctx: UserContext = { shareVersion: 36 };
  assert.equal(getColor(share({ m: '' }), ctx), LTC_COLOR_PALETTE.native);
  assert.equal(
    getColor(share({ m: 'XotherAddr' }), { myAddress: '', shareVersion: 36 }),
    LTC_COLOR_PALETTE.native,
  );
});

test('getColor: custom palette is used when provided', () => {
  const custom = { ...LTC_COLOR_PALETTE, native: '#123456' };
  assert.equal(getColor(share(), LTC_CTX, custom), '#123456');
});

// ── Verbatim parity with dashboard.html:5404-5428 ────────────────

test('palette matches dashboard.html verbatim values', () => {
  assert.equal(LTC_COLOR_PALETTE.dead, '#dc3545');
  assert.equal(LTC_COLOR_PALETTE.stale, '#ffc107');
  assert.equal(LTC_COLOR_PALETTE.unverified, '#555577');
  assert.equal(LTC_COLOR_PALETTE.fee, '#9c27b0');
  assert.equal(LTC_COLOR_PALETTE.native, '#00e676');
  assert.equal(LTC_COLOR_PALETTE.nativeMine, '#00b0ff');
  assert.equal(LTC_COLOR_PALETTE.signaling, '#26c6da');
  assert.equal(LTC_COLOR_PALETTE.signalingMine, '#0097a7');
  assert.equal(LTC_COLOR_PALETTE.legacy, '#2e7d32');
  assert.equal(LTC_COLOR_PALETTE.legacyMine, '#1565c0');
});
