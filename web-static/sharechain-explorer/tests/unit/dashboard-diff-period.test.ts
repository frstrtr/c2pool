// The inline dashboard shows a block's difficulty as the hashrate it implies:
// difficulty x 2^32 / block period (dashboard.html, the c2pDiffPeriod block).
// The period is the block interval of the algorithm the difficulty belongs
// to. On DGB that is 75 s (five algorithms under a 15 s chain), which the
// node serves as currency_info.algo_block_period and uses for its own
// network_hashrate; everywhere else it is the chain's block_period. Runs the
// functions extracted from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface Info { symbol?: string; block_period?: unknown; algo_block_period?: unknown }
interface DiffPeriod {
  c2pDifficultyBlockPeriod(info: Info | null | undefined): number | null;
  c2pDifficultyBlockPeriodNote(info: Info | null | undefined): string;
}

const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
function load(): DiffPeriod {
  const begin = html.indexOf('// BEGIN c2pDiffPeriod');
  const end = html.indexOf('// END c2pDiffPeriod');
  assert.ok(begin >= 0 && end > begin, 'the c2pDiffPeriod block is in dashboard.html');
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(html.slice(begin, end) + '\nreturn { c2pDifficultyBlockPeriod, c2pDifficultyBlockPeriodNote };')() as DiffPeriod;
}

const P = load();

test('the algorithm\'s block period when the node serves one, else the chain\'s', () => {
  // DGB: the chain makes a block every 15 s, each algorithm every 75 s.
  assert.equal(P.c2pDifficultyBlockPeriod({ symbol: 'DGB', block_period: 15, algo_block_period: 75 }), 75);
  // A node that does not serve it (an older build, or a one-algorithm coin).
  assert.equal(P.c2pDifficultyBlockPeriod({ symbol: 'DGB', block_period: 15 }), 15);
  assert.equal(P.c2pDifficultyBlockPeriod({ symbol: 'LTC', block_period: 150 }), 150);
  assert.equal(P.c2pDifficultyBlockPeriod({ symbol: 'BTC', block_period: 600, algo_block_period: 600 }), 600);
  // Neither, or not a positive number: no period (the page keeps its default).
  for (const info of [null, undefined, {}, { block_period: 0 }, { block_period: null, algo_block_period: null }, { algo_block_period: -5 }])
    assert.equal(P.c2pDifficultyBlockPeriod(info), null);
  assert.equal(P.c2pDifficultyBlockPeriod({ block_period: 15, algo_block_period: 0 }), 15, 'a zero algo period falls back');
});

test('a DGB difficulty reads as the hashrate of its algorithm, five times under the 15 s figure', () => {
  const difficulty = 1.2e9, twoTo32 = 4294967296;
  const dgb = { symbol: 'DGB', block_period: 15, algo_block_period: 75 };
  const shown = difficulty * twoTo32 / P.c2pDifficultyBlockPeriod(dgb)!;
  assert.equal(shown, difficulty * twoTo32 / 75);
  assert.equal(shown * 5, difficulty * twoTo32 / 15);
});

test('the tooltip names the algorithm\'s block time where it is not the chain\'s', () => {
  assert.equal(P.c2pDifficultyBlockPeriodNote({ block_period: 15, algo_block_period: 75 }),
               '75 s, the block time of this algorithm (the chain\'s is 15 s)');
  assert.equal(P.c2pDifficultyBlockPeriodNote({ block_period: 150 }), '150 s block time');
  assert.equal(P.c2pDifficultyBlockPeriodNote({ block_period: 600, algo_block_period: 600 }), '600 s block time');
  assert.equal(P.c2pDifficultyBlockPeriodNote({ algo_block_period: 75 }), '75 s block time');
  assert.equal(P.c2pDifficultyBlockPeriodNote({}), '');
  assert.equal(P.c2pDifficultyBlockPeriodNote(null), '');
});

test('the page converts with that period', () => {
  const a = html.indexOf('function block_period_sec()');
  const body = html.slice(a, html.indexOf('\n        }\n', a));
  assert.match(body, /c2pDifficultyBlockPeriod\(window\.currency_info\)/);
  // Its fallback while currency_info is not loaded: the chain period, 150 s by default.
  assert.match(body, /parentBlockPeriodMs \/ 1000 : 150/);
  assert.match(html, /function diff_as_hashrate\(diff\) \{\s*return format_hashrate\(Math\.floor\(diff \* Math\.pow\(2, 32\) \/ block_period_sec\(\)\)\);/);
});
