// The inline dashboard's block-solution marking (dashboard.html, the
// c2pBlockMarks block): a share is marked when the tracker flags it (blk) or
// when its FULL hash is in the found-block ledger (block_hashes). A 16-hex
// short hash is display only: DASH share hashes are X11 PoW hashes with ~14
// leading zero hex digits, so an ordinary share's short hash can equal a
// block's. Runs the functions extracted from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface WindowShare { h: string; H?: string; blk?: number }
interface Marks {
  c2pShareKey(s: WindowShare): string;
  c2pMarkBlocks(set: Record<string, boolean>, data: unknown, shares: WindowShare[]): Record<string, boolean>;
  c2pIsBlockShare(set: Record<string, boolean>, s: WindowShare): boolean;
}

function loadMarks(): Marks {
  const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
  const begin = html.indexOf('// BEGIN c2pBlockMarks');
  const end = html.indexOf('// END c2pBlockMarks');
  assert.ok(begin >= 0 && end > begin, 'the c2pBlockMarks block is in dashboard.html');
  const src = html.slice(begin, end);
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(src + '\nreturn { c2pShareKey, c2pMarkBlocks, c2pIsBlockShare };')() as Marks;
}

const m = loadMarks();

// A DASH-like share: 14 leading zero hex digits, then the rest.
function dashShare(tail50: string, blk?: number): WindowShare {
  const H = ('00000000000000' + tail50).padEnd(64, '0').slice(0, 64);
  const s: WindowShare = { h: H.slice(0, 16), H };
  if (blk !== undefined) s.blk = blk;
  return s;
}

test('a share whose short hash equals a block\'s but whose full hash differs is not marked', () => {
  const block = dashShare('21' + 'a'.repeat(48));
  const lookalike = dashShare('21' + 'b'.repeat(48));
  assert.equal(block.h, lookalike.h, 'the two share one 16-hex short hash');
  assert.notEqual(block.H, lookalike.H);
  const set = m.c2pMarkBlocks({}, { blocks: [block.h], block_hashes: [block.H] }, [block, lookalike]);
  assert.equal(m.c2pIsBlockShare(set, block), true);
  assert.equal(m.c2pIsBlockShare(set, lookalike), false);
});

test('the blocks in a window are the ledger blocks whose share is in the window, plus flagged shares', () => {
  // A window of 2,000 DASH-like shares: the short hashes take few values, so
  // many shares share one with a block.
  const shares: WindowShare[] = [];
  for (let i = 0; i < 2000; ++i) {
    const tail = (i % 7).toString(16).padStart(2, '0') + i.toString(16).padStart(48, '0');
    shares.push(dashShare(tail));
  }
  const inWindow = [shares[10]!, shares[500]!, shares[1999]!];
  const outside = dashShare('03' + 'f'.repeat(48));   // a ledger block older than the window
  const ledger = [...inWindow.map((s) => s.H!), outside.H!];
  shares[700]!.blk = 1;   // flagged by the tracker (also in the ledger in practice)

  const set = m.c2pMarkBlocks({}, { blocks: ledger.map((h) => h.slice(0, 16)), block_hashes: ledger }, shares);
  const marked = shares.filter((s) => m.c2pIsBlockShare(set, s));
  assert.deepEqual(marked.map((s) => s.H), [shares[10]!.H, shares[500]!.H, shares[700]!.H, shares[1999]!.H]);

  // Matching on the short hash, as before, marks far more.
  const shortSet = new Set(ledger.map((h) => h.slice(0, 16)));
  assert.ok(shares.filter((s) => shortSet.has(s.h)).length > 100);
});

test('a delta merges into the marks of the window', () => {
  const a = dashShare('01' + 'a'.repeat(48));
  const b = dashShare('01' + 'b'.repeat(48));
  const c = dashShare('02' + 'c'.repeat(48), 1);
  const set = m.c2pMarkBlocks({}, { block_hashes: [a.H] }, [a, b]);
  m.c2pMarkBlocks(set, { block_hashes: [] }, [c, a, b]);
  assert.equal(m.c2pIsBlockShare(set, a), true);
  assert.equal(m.c2pIsBlockShare(set, b), false);
  assert.equal(m.c2pIsBlockShare(set, c), true);
});

test('a node without block_hashes: the short hashes match as before', () => {
  const a = { h: '1234567890abcdef', H: '1234567890abcdef' + '0'.repeat(48) };
  const b = { h: 'fedcba0987654321', H: 'fedcba0987654321' + '1'.repeat(48) };
  const set = m.c2pMarkBlocks({}, { blocks: [a.h] }, [a, b]);
  assert.equal(m.c2pIsBlockShare(set, a), true);
  assert.equal(m.c2pIsBlockShare(set, b), false);
  // A share without a full hash is keyed on its short one.
  const legacy = { h: 'abcdabcdabcdabcd' };
  const set2 = m.c2pMarkBlocks({}, { blocks: [legacy.h] }, [legacy]);
  assert.equal(m.c2pIsBlockShare(set2, legacy), true);
});
