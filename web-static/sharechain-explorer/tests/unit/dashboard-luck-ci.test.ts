// The inline dashboard's exact Poisson interval (dashboard.html, the c2pLuck
// block). k blocks found where `expected` were expected: the 95 % interval of
// the true mean is [chi2(.025; 2k) / 2, chi2(.975; 2k + 2) / 2] (Garwood),
// i.e. Gamma(k, 1) and Gamma(k + 1, 1) quantiles. The "Effective vs
// reported" hashrate diagnostic under the charts is that interval on the
// block rate, times the hashes per block, with no prior. Runs the functions
// extracted from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface Ci {
  c2pGammaP(a: number, x: number): number;
  c2pGammaQuantile(p: number, shape: number): number;
  c2pPoissonCI(k: number): { low: number; high: number };
  c2pEffectiveHashrateCI(k: number, windowSec: number, netDiff: number): { low: number; high: number } | null;
}

const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
function load(): Ci {
  const begin = html.indexOf('// BEGIN c2pLuck');
  const end = html.indexOf('// END c2pLuck');
  assert.ok(begin >= 0 && end > begin, 'the c2pLuck block is in dashboard.html');
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(html.slice(begin, end) +
    '\nreturn { c2pGammaP, c2pGammaQuantile, c2pPoissonCI, c2pEffectiveHashrateCI };')() as Ci;
}

const L = load();
const D = 86400;
const near = (a: number, b: number, rel = 1e-9) => Math.abs(a - b) <= rel * Math.max(1, Math.abs(b));
// [k, q(.025; k), q(.975; k), q(.975; k + 1)]: a hand table, see its note.
const QUANTILES = (JSON.parse(readFileSync(new URL('./fixtures/gamma-quantiles.json', import.meta.url), 'utf8')) as
  { rows: [number, number, number, number][] }).rows;

test('Gamma quantiles match the hand table', () => {
  assert.ok(near(QUANTILES[0]![1], -Math.log(0.975)) && near(QUANTILES[0]![2], -Math.log(0.025)), 'the table\'s closed forms');
  for (const [k, lo, hi, hiNext] of QUANTILES) {
    assert.ok(near(L.c2pGammaQuantile(0.025, k), lo), `q(.025; ${k}) = ${L.c2pGammaQuantile(0.025, k)} vs ${lo}`);
    assert.ok(near(L.c2pGammaQuantile(0.975, k), hi), `q(.975; ${k}) = ${L.c2pGammaQuantile(0.975, k)} vs ${hi}`);
    assert.ok(near(L.c2pGammaQuantile(0.975, k + 1), hiNext), `q(.975; ${k + 1})`);
    // And back through the CDF.
    assert.ok(Math.abs(L.c2pGammaP(k, lo) - 0.025) < 1e-11 && Math.abs(L.c2pGammaP(k, hi) - 0.975) < 1e-11, `P(${k}, q)`);
  }
  assert.equal(L.c2pGammaQuantile(0.5, 0), 0);
  assert.equal(L.c2pGammaQuantile(0, 5), 0);
  assert.equal(L.c2pGammaQuantile(1, 5), Infinity);
  assert.ok(near(L.c2pGammaQuantile(0.5, 1), Math.LN2), 'the median of Exp(1)');
});

test('the exact Poisson interval: [chi2(.025; 2k) / 2, chi2(.975; 2k + 2) / 2]', () => {
  assert.equal(L.c2pPoissonCI(0).low, 0);
  assert.ok(near(L.c2pPoissonCI(0).high, 3.688879454114), 'no block: up to 3.69 expected');
  for (const [k, lo, , hiNext] of QUANTILES) {
    const ci = L.c2pPoissonCI(k);
    assert.ok(near(ci.low, lo) && near(ci.high, hiNext), `k = ${k}`);
    assert.ok(ci.low < k && k < ci.high, 'the count is inside its own interval');
  }
});

test('CI95 diagnostic: the exact interval on the block rate, no prior', () => {
  const netDiff = 99265353.4, perBlock = netDiff * 4294967296;
  const ten = L.c2pEffectiveHashrateCI(10, D, netDiff)!;
  assert.ok(near(ten.low, 4.795388696132 / D * perBlock) && near(ten.high, 18.390356042018 / D * perBlock));
  const none = L.c2pEffectiveHashrateCI(0, D, netDiff)!;
  assert.equal(none.low, 0);
  assert.ok(near(none.high, 3.688879454114 / D * perBlock));
  // Ten blocks where ten were expected: the rate that expects ten is inside.
  const reported = 10 * perBlock / D;
  assert.ok(ten.low < reported && reported < ten.high);
  // The band it replaced: a Gamma(5 + k, .) posterior whose prior was centred
  // on the reported rate, mean +/- 1.96 sd. Five blocks in a window where
  // the reported rate expects one (a 0.4 % event) read [63 %, 270 %] of the
  // reported rate: "OK (reported within CI95)". The blocks alone say
  // [162 %, 1167 %]: the miners report too little.
  const one = perBlock / D;
  const prior = (k: number, rep: number) => {
    const a = 5 + k, b = 5 / (rep / perBlock) + D, mean = a / b, sd = Math.sqrt(a) / b;
    return { low: Math.max(0, mean - 1.96 * sd) * perBlock, high: (mean + 1.96 * sd) * perBlock };
  };
  const old = prior(5, one), five = L.c2pEffectiveHashrateCI(5, D, netDiff)!;
  assert.deepEqual([Math.round(100 * old.low / one), Math.round(100 * old.high / one)], [63, 270]);
  assert.deepEqual([Math.round(100 * five.low / one), Math.round(100 * five.high / one)], [162, 1167]);
  assert.ok(old.low < one && one < old.high && one < five.low);
  // It takes the blocks, the window and the difficulty: no reported rate.
  assert.equal(L.c2pEffectiveHashrateCI.length, 3);
  for (const bad of [[10, 0, netDiff], [10, D, 0], [-1, D, netDiff]] as const)
    assert.equal(L.c2pEffectiveHashrateCI(bad[0], bad[1], bad[2]), null);
});

test('the diagnostic in the page uses that interval and keeps its verdicts', () => {
  const a = html.indexOf('function updateHashrateDiagnostic(');
  const body = html.slice(a, html.indexOf('\n        }\n', a));
  assert.match(body, /c2pEffectiveHashrateCI\(k, windowSec, netDiff\)/);
  assert.doesNotMatch(body, /alpha0|beta0|1\.96/, 'no prior, no normal approximation');
  assert.match(body, /Low evidence \(/);
  assert.match(body, /reported >= effLow && reported <= effHigh/);
});
