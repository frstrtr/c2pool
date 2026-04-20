// Deterministic c2pool fixture generator.
// Writes JSON files the mock server serves during pixel-regression
// runs. Seeded RNG so the set is byte-identical across runs.
//
// Usage: node tests/visual/fixtures/generate.mjs

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
mkdirSync(HERE, { recursive: true });

// ── seeded mulberry32 RNG ────────────────────────────────────────
function mulberry32(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6D2B79F5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rng = mulberry32(0xC2FFEE); // deterministic seed

// ── share generation ────────────────────────────────────────────
const MINERS = [
  'XminerAAAAA1', 'XminerBBBBB2', 'XminerCCCCC3', 'XminerDDDDD4',
  'XminerEEEEE5', 'XminerFFFFF6', 'XminerGGGGG7', 'XminerHHHHH8',
  'XMINEADDRESS', 'XminerJJJJJ9', 'XminerKKKKK0', 'XminerLLLLLa',
];
const MY_ADDRESS = 'XMINEADDRESS';

function rand(n) { return Math.floor(rng() * n); }
function pick(arr) { return arr[rand(arr.length)]; }

function shortHash(i) {
  const hex = '0123456789abcdef';
  let s = '';
  for (let j = 0; j < 16; j++) s += hex[(i * 7919 + j * 31 + rand(16)) % 16];
  return s;
}
function fullHash(short) {
  const hex = '0123456789abcdef';
  let s = short;
  while (s.length < 64) s += hex[rand(16)];
  return s;
}

// Defaults to 200 so the pixel-diff harness stays quick + byte-stable.
// Override via FIXTURE_SHARES env var for manual preview against a
// realistic chain window:
//   FIXTURE_SHARES=8640 node fixtures/generate.mjs   (LTC mainnet)
//   FIXTURE_SHARES=4320 node fixtures/generate.mjs   (LTC testnet-ish)
const FIXTURE_SHARES = Number(process.env.FIXTURE_SHARES ?? 200);
const SHARE_COUNT = Number.isFinite(FIXTURE_SHARES) && FIXTURE_SHARES > 0
  ? Math.floor(FIXTURE_SHARES) : 200;
const WINDOW_SIZE = SHARE_COUNT;
const NOW = 1776550560;

const shares = [];
for (let i = 0; i < SHARE_COUNT; i++) {
  const r = rng();
  let V = 36, dv = 36;
  if (r < 0.15) { V = 35; dv = 35; }          // legacy V35 only
  else if (r < 0.30) { V = 35; dv = 36; }     // signalling V36
  const staleRoll = rng();
  const s = staleRoll < 0.02 ? 2 : staleRoll < 0.05 ? 1 : 0;
  const v = rng() < 0.03 ? 0 : 1;
  const fee = rng() < 0.01 ? 1 : undefined;
  const blk = rng() < 0.01 ? 1 : undefined;
  const h = shortHash(i);
  const sharerec = {
    h, H: fullHash(h),
    p: i,
    v, t: NOW - i * 20,
    V, s,
    b: 0x1a6b0d14,
    a: 541536 - i,
    dv,
    m: pick(MINERS),
  };
  if (fee) sharerec.fee = fee;
  if (blk) sharerec.blk = blk;
  shares.push(sharerec);
}

const blocks = shares.filter((sh) => sh.blk === 1).map((sh) => sh.h);
const doge_blocks = [];  // simplify — no merged blocks in this fixture

const pplns_current = {};
const pplns = {};
const minerTotals = {};
for (const sh of shares) {
  minerTotals[sh.m] = (minerTotals[sh.m] ?? 0) + 1;
}
let totalCurrent = 0;
for (const [m, n] of Object.entries(minerTotals)) {
  const amt = n * 0.00123456;
  pplns_current[m] = amt;
  totalCurrent += amt;
}
// Per-share PPLNS (just use the same distribution for every share so
// the hover-zoom exercises rendering deterministically)
for (const sh of shares) {
  pplns[sh.h] = { ...pplns_current };
}

const windowPayload = {
  best_hash:   shares[0].H,
  chain_length: 8650,
  window_size: WINDOW_SIZE,
  my_address:  MY_ADDRESS,
  fee_hash160: '',
  total:       shares.length,
  shares,
  heads:       [shares[0].h],
  blocks,
  doge_blocks,
  pplns_current,
  pplns,
};

const tipPayload = {
  hash:   shares[0].h,
  height: 8650,
  total:  8650,
};

const statsPayload = {
  chain_height: 8650,
  total_shares: shares.length,
  verified_count: shares.filter((s) => s.v).length,
  head_count: 1,
  fork_count: 1,
};

const mergedPayouts = {};
for (const [m, amt] of Object.entries(pplns_current)) {
  mergedPayouts[m] = { amount: amt, merged: [] };
}

writeFileSync(join(HERE, 'window.json'), JSON.stringify(windowPayload, null, 2) + '\n');
writeFileSync(join(HERE, 'tip.json'),    JSON.stringify(tipPayload, null, 2) + '\n');
writeFileSync(join(HERE, 'stats.json'),  JSON.stringify(statsPayload, null, 2) + '\n');
writeFileSync(join(HERE, 'merged_payouts.json'), JSON.stringify(mergedPayouts, null, 2) + '\n');

console.log(`wrote fixtures: ${shares.length} shares, ${blocks.length} blocks, ${Object.keys(pplns_current).length} miners`);
