// The inline dashboard's exact Poisson interval (dashboard.html, the c2pLuck
// block). k blocks found where `expected` were expected: the 95 % interval of
// the true mean is [chi2(.025; 2k) / 2, chi2(.975; 2k + 2) / 2] (Garwood),
// i.e. Gamma(k, 1) and Gamma(k + 1, 1) quantiles. The "Effective vs
// reported" hashrate diagnostic under the charts is that interval on the
// block rate, times the hashes per block, with no prior; the difficulty is
// the time-harmonic mean over the window the blocks are counted in. Runs the
// functions extracted from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface Ci {
  c2pGammaP(a: number, x: number): number;
  c2pGammaQuantile(p: number, shape: number): number;
  c2pPoissonCI(k: number): { low: number; high: number };
  c2pEffectiveHashrateCI(k: number, windowSec: number, netDiff: number): { low: number; high: number } | null;
  c2pWindowNetDiff(series: unknown, minMs: number, maxMs: number, fallback: number): number;
}

const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
function load(): Ci {
  const begin = html.indexOf('// BEGIN c2pLuck');
  const end = html.indexOf('// END c2pLuck');
  assert.ok(begin >= 0 && end > begin, 'the c2pLuck block is in dashboard.html');
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(html.slice(begin, end) +
    '\nreturn { c2pGammaP, c2pGammaQuantile, c2pPoissonCI, c2pEffectiveHashrateCI, c2pWindowNetDiff };')() as Ci;
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

// The page's verdict: updateHashrateDiagnostic from dashboard.html on the
// c2pLuck block, with a stub element and a plain number formatter.
function loadVerdict(): (k: number, windowSec: number, netDiff: number, reported: number) => string {
  const begin = html.indexOf('// BEGIN c2pLuck'), end = html.indexOf('// END c2pLuck');
  const a = html.indexOf('function updateHashrateDiagnostic(');
  const src = html.slice(a, html.indexOf('\n        }\n', a) + 10);
  const el = { textContent: '', style: { color: '' } };
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  const fn = new Function('document', 'format_hashrate', html.slice(begin, end) + '\n' + src +
    '\nreturn updateHashrateDiagnostic;')({ getElementById: () => el }, (x: number) => String(x)) as
    (id: string, avg: number, k: number, windowSec: number, netDiff: number, prefix: string) => void;
  return (k, windowSec, netDiff, reported) => {
    fn('x', reported, k, windowSec, netDiff, '');
    return el.textContent.split(' • ')[1]!;
  };
}
const verdict = loadVerdict();
const H = 3600 * 1000;  // one hour in ms: the window and the samples are in ms

test('window difficulty: a constant difficulty gives the band it gave before', () => {
  const d = 99265353.4;
  const series: [number, number][] = [];
  for (let t = 0; t <= 24 * H; t += H) series.push([t, d]);
  const w = L.c2pWindowNetDiff(series, 0, 24 * H, d);
  assert.ok(near(w, d, 1e-12), `${w} vs ${d}`);
  const was = L.c2pEffectiveHashrateCI(10, D, d)!, now = L.c2pEffectiveHashrateCI(10, D, w)!;
  assert.ok(near(now.low, was.low, 1e-12) && near(now.high, was.high, 1e-12));
  // Samples outside the window at another difficulty change nothing.
  const wide: [number, number][] = [[-48 * H, 5], ...series, [30 * H, 5]];
  assert.ok(near(L.c2pWindowNetDiff(wide, 0, 24 * H, 5), d, 1e-12));
});

test('window difficulty: a step halfway gives the time-harmonic mean', () => {
  // 100 for the first hour, 300 for the second: 2 / (1/100 + 1/300) = 150,
  // not the arithmetic 200, not the newest 300.
  const series: [number, number][] = [];
  for (let t = 0; t <= 2 * H; t += H / 6) series.push([t, t < H ? 100 : 300]);
  assert.ok(near(L.c2pWindowNetDiff(series, 0, 2 * H, 300), 150, 1e-12));
  // Any order.
  assert.ok(near(L.c2pWindowNetDiff(series.slice().reverse(), 0, 2 * H, 300), 150, 1e-12));
  // The first interval clipped to the window: a sample before it holds into it.
  assert.ok(near(L.c2pWindowNetDiff([[-H, 100], [H, 300], [2 * H, 300]], 0, 2 * H, 300), 150, 1e-12));
  // The last interval clipped to the window: a sample after it ends the hold
  // at maxMs, and holds nothing itself.
  assert.ok(near(L.c2pWindowNetDiff([[0, 100], [H, 300], [3 * H, 1]], 0, 2 * H, 1), 150, 1e-12));
  // Unmeasured samples (null, 0) hold nothing and are not averaged in.
  assert.ok(near(L.c2pWindowNetDiff([[0, null], [H, 100], [1.5 * H, 300], [2 * H, 0]], 0, 2 * H, 300), 150, 1e-12));
});

test('window difficulty: fewer than 2 samples in the window returns the fallback', () => {
  // One sample in the window, one carried in from before: the fallback.
  assert.equal(L.c2pWindowNetDiff([[-2 * H, 50], [0.5 * H, 123]], 0, H, 123), 123);
  assert.equal(L.c2pWindowNetDiff([[0.5 * H, 123]], 0, H, 456), 456);
  assert.equal(L.c2pWindowNetDiff([], 0, H, 456), 456);
  assert.equal(L.c2pWindowNetDiff(null, 0, H, 456), 456);
  assert.equal(L.c2pWindowNetDiff([[0, null], [0.5 * H, 0], [H, 7]], 0, H, 9), 9, 'one measured sample');
  assert.equal(L.c2pWindowNetDiff([[0, 100], [H, 300]], H, H, 9), 9, 'an empty window');
});

test('window difficulty: the last sample inside the window holds until maxMs', () => {
  // 300 from 1 h to the window end at 2 h: 2 / (1/100 + 1/300) = 150, not
  // the first hour's 100 alone.
  assert.equal(L.c2pWindowNetDiff([[0, 100], [H, 300]], 0, 2 * H, 9), 150);
});

test('window difficulty: an unmeasured sample mid-series holds nothing', () => {
  // 100 for [0, 1 h), nothing for [1 h, 1.5 h), 300 for [1.5 h, 2 h]:
  // 1.5 / (1/100 + 0.5/300) = 128.571..., not 100 held across the gap (120).
  assert.ok(near(L.c2pWindowNetDiff([[0, 100], [H, null], [1.5 * H, 300]], 0, 2 * H, 9), 1.5 / (1 / 100 + 0.5 / 300), 1e-12));
});

test('window difficulty: 2 samples but no measured time returns the fallback', () => {
  // Both samples at maxMs: no interval inside the window holds a difficulty.
  assert.equal(L.c2pWindowNetDiff([[2 * H, 100], [2 * H, 300]], 0, 2 * H, 9), 9);
});

test('a difficulty drop no longer reads Critical', () => {
  // A 30-day window, the pool at a steady 1 PH/s, reporting exactly that.
  // Difficulty D1 (one block a day at 1 PH/s) for 27 days, then D1 / 4 for
  // the last 3: the window expects 27 + 3 * 4 = 39 blocks, and 39 are found.
  const rate = 1e15, day = 24 * H, T = 30 * day, d1 = rate * 86400 / 4294967296;
  const series: [number, number][] = [];
  for (let t = 0; t <= T; t += 6 * H) series.push([t, t < 27 * day ? d1 : d1 / 4]);
  const newest = d1 / 4, k = 39;
  const w = L.c2pWindowNetDiff(series, 0, T, newest);
  assert.ok(near(w, d1 * 30 / 39, 1e-12), 'T / sum(dt / D) = 30 / 39 of D1');
  // The newest difficulty reads the band at 0.325 of the window's: up to
  // 44 % of the reported rate, a false Critical.
  const old = L.c2pEffectiveHashrateCI(k, T / 1000, newest)!;
  assert.equal(Math.round(100 * old.high / rate), 44);
  assert.equal(verdict(k, T / 1000, newest, rate), 'Critical: effective far below reported');
  // The window's difficulty: [71 %, 137 %], the reported rate inside.
  const band = L.c2pEffectiveHashrateCI(k, T / 1000, w)!;
  assert.deepEqual([Math.round(100 * band.low / rate), Math.round(100 * band.high / rate)], [71, 137]);
  assert.equal(verdict(k, T / 1000, w, rate), 'OK (reported within CI95)');
});

test('both charts pass the window difficulty of the window they count blocks in', () => {
  for (const [fn, id] of [['renderHashrateGraph', 'hashrate-diagnostic'], ['renderFullscreenGraph', 'fs-hashrate-diagnostic']]) {
    const a = html.indexOf(`function ${fn}(`);
    const body = html.slice(a, html.indexOf('\n        }\n', a));
    assert.ok(a >= 0 && body.includes(`updateHashrateDiagnostic('${id}'`), fn);
    // One window: [minTime, maxTime], set once.
    assert.equal(body.match(/\bminTime =/g)!.length, 1, `${fn}: minTime set once`);
    assert.equal(body.match(/\bmaxTime =/g)!.length, 1, `${fn}: maxTime set once`);
    // k: the blocks in that window.
    assert.match(body, /if \(blockTime >= minTime && blockTime <= maxTime\) \{/);
    assert.match(body, /var kBlocks = blockMarkers\.filter\(/);
    // The difficulty: the series over that window, the newest as its fallback.
    assert.match(body, new RegExp(`updateHashrateDiagnostic\\('${id}', avg, kBlocks,\\s*\\(maxTime - minTime\\) / 1000, ` +
      'c2pWindowNetDiff\\(netDiffData, minTime, maxTime, lastNetDiff\\),'));
  }
});
