// The inline dashboard's block-solution marking (dashboard.html, the
// c2pBlockMarks block): a share is marked when the tracker flags it (blk) or
// when its FULL hash is in the found-block ledger (block_hashes). A 16-hex
// short hash is display only: DASH share hashes are X11 PoW hashes with ~14
// leading zero hex digits, so an ordinary share's short hash can equal a
// block's. The window sends the block_hashes of its own shares and a delta
// those of its new shares (omitted when none); they accumulate. The delta
// cursor is the client's full tip hash, so a newer share sharing the tip's
// short hash cannot end a delta early. Runs the functions extracted from
// dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface WindowShare { h: string; H?: string; blk?: number }
interface Marks {
  c2pShareKey(s: WindowShare): string;
  c2pMarkBlocks(set: Record<string, boolean>, data: unknown, shares: WindowShare[], full: boolean): boolean;
  c2pIsBlockShare(set: Record<string, boolean>, s: WindowShare): boolean;
  c2pDeltaCursor(tipShort: string | null, tipFull: string | undefined, serverFull: boolean): string;
}

function loadMarks(): Marks {
  const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
  const begin = html.indexOf('// BEGIN c2pBlockMarks');
  const end = html.indexOf('// END c2pBlockMarks');
  assert.ok(begin >= 0 && end > begin, 'the c2pBlockMarks block is in dashboard.html');
  const src = html.slice(begin, end);
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(src + '\nreturn { c2pShareKey, c2pMarkBlocks, c2pIsBlockShare, c2pDeltaCursor };')() as Marks;
}

const m = loadMarks();

// A window response, then the marks it gives.
function marksOf(data: unknown, shares: WindowShare[]): { set: Record<string, boolean>; full: boolean } {
  const set: Record<string, boolean> = {};
  const full = m.c2pMarkBlocks(set, data, shares, false);
  return { set, full };
}

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
  const { set } = marksOf({ blocks: [block.h], block_hashes: [block.H] }, [block, lookalike]);
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

  // The node sends the in-window ones as block_hashes, the whole ledger short.
  const { set } = marksOf({ blocks: ledger.map((h) => h.slice(0, 16)), block_hashes: inWindow.map((s) => s.H!) }, shares);
  const marked = shares.filter((s) => m.c2pIsBlockShare(set, s));
  assert.deepEqual(marked.map((s) => s.H), [shares[10]!.H, shares[500]!.H, shares[700]!.H, shares[1999]!.H]);

  // Matching on the short hash, as before, marks far more.
  const shortSet = new Set(ledger.map((h) => h.slice(0, 16)));
  assert.ok(shares.filter((s) => shortSet.has(s.h)).length > 100);
});

test('deltas accumulate into the marks of the window', () => {
  const a = dashShare('01' + 'a'.repeat(48));
  const b = dashShare('01' + 'b'.repeat(48));
  const c = dashShare('02' + 'c'.repeat(48));
  const d = dashShare('02' + 'd'.repeat(48), 1);
  const e = dashShare('01' + 'e'.repeat(48));
  const { set, full } = marksOf({ blocks: [a.h], block_hashes: [a.H] }, [a, b]);
  assert.equal(full, true);
  // A delta with a new found block among its new shares.
  const f2 = m.c2pMarkBlocks(set, { blocks: [a.h, c.h], block_hashes: [c.H] }, [c, a, b], full);
  // A delta without block_hashes (none new): the short `blocks` are NOT
  // matched (e shares a's short hash), the blk flag still marks d.
  const f3 = m.c2pMarkBlocks(set, { blocks: [a.h, c.h] }, [e, d, c, a, b], f2);
  assert.equal(f3, true);
  for (const [s, want] of [[a, true], [b, false], [c, true], [d, true], [e, false]] as const)
    assert.equal(m.c2pIsBlockShare(set, s), want, s.H);
});

test('a node without block_hashes: the short hashes match as before', () => {
  const a = { h: '1234567890abcdef', H: '1234567890abcdef' + '0'.repeat(48) };
  const b = { h: 'fedcba0987654321', H: 'fedcba0987654321' + '1'.repeat(48) };
  const { set, full } = marksOf({ blocks: [a.h] }, [a, b]);
  assert.equal(full, false);
  assert.equal(m.c2pIsBlockShare(set, a), true);
  assert.equal(m.c2pIsBlockShare(set, b), false);
  // Its deltas too.
  const c = { h: '0f0f0f0f0f0f0f0f', H: '0f0f0f0f0f0f0f0f' + '2'.repeat(48) };
  assert.equal(m.c2pMarkBlocks(set, { blocks: [a.h, c.h] }, [c, a, b], full), false);
  assert.equal(m.c2pIsBlockShare(set, c), true);
  // A share without a full hash is keyed on its short one.
  const legacy = { h: 'abcdabcdabcdabcd' };
  const { set: set2 } = marksOf({ blocks: [legacy.h] }, [legacy]);
  assert.equal(m.c2pIsBlockShare(set2, legacy), true);
});

// /sharechain/delta walks back from the best share and stops at the first
// share matching `since` on its short or its full hash (main_ltc.cpp,
// dashboard_views.hpp build_delta, main_bip110.cpp). Newest first.
function serverDelta(chain: WindowShare[], since: string): WindowShare[] {
  const out: WindowShare[] = [];
  for (const s of chain) {
    if (s.h === since || s.H === since) break;
    out.push(s);
  }
  return out;
}

test('the delta cursor is the full tip hash: a newer share sharing its short hash does not end the delta', () => {
  const tip = dashShare('21' + 'a'.repeat(48));
  const older = dashShare('07' + 'b'.repeat(48));
  const n1 = dashShare('09' + 'c'.repeat(48));
  const n2 = dashShare('21' + 'd'.repeat(48));   // the tip's short hash
  const n3 = dashShare('33' + 'e'.repeat(48));
  assert.equal(n2.h, tip.h);
  const chain = [n3, n2, n1, tip, older];

  const since = m.c2pDeltaCursor(tip.h, tip.H, true);
  assert.equal(since, tip.H);
  assert.deepEqual(serverDelta(chain, since).map((s) => s.H), [n3.H, n2.H, n1.H]);
  // The short cursor ends the walk at n2: n2 and n1 never reach the client.
  assert.deepEqual(serverDelta(chain, tip.h).map((s) => s.H), [n3.H]);
});

test('the delta cursor stays the short hash for an older node or an unknown full hash', () => {
  const tip = dashShare('21' + 'a'.repeat(48));
  assert.equal(m.c2pDeltaCursor(tip.h, tip.H, false), tip.h, 'a node without block_hashes');
  assert.equal(m.c2pDeltaCursor(tip.h, '', true), tip.h, 'full hash not known');
  assert.equal(m.c2pDeltaCursor(tip.h, dashShare('22' + 'a'.repeat(48)).H, true), tip.h,
               'a full hash of another tip is not used');
  assert.equal(m.c2pDeltaCursor(null, undefined, true), '');
});
