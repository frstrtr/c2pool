// The inline dashboard's p2pool.info nods (dashboard.html): the "Pool Luck
// (7 days, 30 days, 90 days)" line with its strip of the last 40 rounds, a
// cha-ching when the pool finds a block, and the classic vertical block
// lines on the hashrate charts. The two toggles are off by default and kept
// in localStorage. Runs the functions extracted from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface Round { ts: number; effort: number; first: boolean; hash: string; height: number }
interface Glyph { glyph: string; tier: string; height: number; hash: string; effort: number; first: boolean }
type Seen = { hash: string | null; ts: number | null };
interface Retro {
  c2pGlyphStrip(rounds: Round[] | null, count?: number): Glyph[];
  c2pIsNewBlock(prev: Seen | null, cur: Seen): boolean;
}

const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
function load(): Retro {
  const begin = html.indexOf('// BEGIN c2pLuck');
  const end = html.indexOf('// END c2pLuck');
  assert.ok(begin >= 0 && end > begin, 'the c2pLuck block is in dashboard.html');
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(html.slice(begin, end) + '\nreturn { c2pGlyphStrip, c2pIsNewBlock };')() as Retro;
}

const L = load();
const round = (height: number, effort: number, first = false): Round =>
  ({ ts: 1794000000 + height * 600, effort, first, hash: 'h' + height, height });

test('the glyph strip: one glyph per round, oldest first, the last 40', () => {
  // ⚡ under 1/3 of the expected time (one glyph for ⚡⚡ too), 🐢 over 2x.
  const rounds = [round(1, 1, true), round(2, 1), round(3, 0.2), round(4, 0.05), round(5, 2.5), round(6, 4.25), round(7, 1 / 3), round(8, 2)];
  assert.equal(L.c2pGlyphStrip(rounds).map(g => g.glyph).join(''), '··⚡⚡🐢🐢··');
  assert.deepEqual(L.c2pGlyphStrip(rounds, 2).map(g => [g.height, g.tier, g.glyph]), [[7, '', '·'], [8, '', '·']]);
  assert.deepEqual(L.c2pGlyphStrip(rounds)[3], { glyph: '⚡', tier: 'fast2', height: 4, hash: 'h4', effort: 0.05, first: false });
  // The first block counts as 100 % and is never tagged, whatever it carries.
  assert.equal(L.c2pGlyphStrip([round(1, 0.01, true)])[0]!.glyph, '·');
  const many = Array.from({ length: 55 }, (_, i) => round(i, i % 3 === 0 ? 0.1 : 1));
  const strip = L.c2pGlyphStrip(many);
  assert.equal(strip.length, 40);
  assert.deepEqual([strip[0]!.height, strip[39]!.height], [15, 54]);
  assert.deepEqual(L.c2pGlyphStrip([]), []);
  assert.deepEqual(L.c2pGlyphStrip(null), []);
});

test('a new pool block is one whose newest main-chain row changed to a later one; never the first load', () => {
  const a = { hash: 'a', ts: 100 }, b = { hash: 'b', ts: 200 }, none = { hash: null, ts: null };
  assert.equal(L.c2pIsNewBlock(null, b), false, 'first load');
  assert.equal(L.c2pIsNewBlock(a, a), false);
  assert.equal(L.c2pIsNewBlock(a, b), true);
  assert.equal(L.c2pIsNewBlock(b, a), false, 'an older row, e.g. the newest one was dropped');
  assert.equal(L.c2pIsNewBlock(none, a), true, 'the node\'s first block, after a load with none');
  assert.equal(L.c2pIsNewBlock(a, none), false);
});

test('the cha-ching and the classic block lines are off by default', () => {
  // The legend chips start struck through (off), in the compact and the fullscreen legend.
  const chips = html.match(/<div class="[^"]*"[^>]*data-toggle="classiclines"/g) ?? [];
  assert.equal(chips.length, 2);
  for (const chip of chips) assert.match(chip, /class="legend-item disabled"/);
  // The checkbox is not pre-checked.
  const box = html.match(/<input[^>]*id="chaching_toggle"[^>]*>/)![0];
  assert.doesNotMatch(box, /\schecked[\s=>]/);
  // Both read a stored '1' and nothing else as on.
  assert.match(html, /function c2pPrefGet\(key\) \{\s*try \{ return localStorage\.getItem\(key\) === '1'; \} catch \(e\) \{ return false; \}/);
  assert.match(html, /var c2pChaChing = \{ on: c2pPrefGet\('c2p_cha_ching'\)/);
  assert.match(html, /var c2pClassicLines = c2pPrefGet\('c2p_classic_block_lines'\);/);
  // The charts draw the lines only when the toggle is on.
  assert.equal((html.match(/plotLines: c2pClassicLines \? c2pClassicPlotLines\(c2pMainBlockTimes\(blockMarkers\)\) : \[\]/g) ?? []).length, 2);
});

test('the luck line is the p2pool.info one: 7, 30 and 90 days, from the pooled period luck', () => {
  assert.match(html, /Pool Luck \(7 days, 30 days, 90 days\):/);
  for (const id of ['classic_luck_7d', 'classic_luck_30d', 'classic_luck_90d', 'classic_luck_glyphs'])
    assert.ok(html.includes(`id="${id}"`), id);
  // It is filled from the same periods as the badges.
  const a = html.indexOf('function c2pRenderClassicLuck(periods, pace)');
  const body = html.slice(a, html.indexOf('\n        }\n', a));
  assert.match(body, /c2pPeriodView\(per\)/);
  assert.match(body, /c2pPeriodTip\(d\[2\], per\)/);
  assert.match(body, /c2pGlyphStrip\(pace\.rounds, C2P_STRIP_ROUNDS\)/);
});
