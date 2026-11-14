// The inline dashboard's "Blocks in Window" count (dashboard.html, the
// c2pWindowBlocks block) and the DASH share-version labels (the
// c2pLiveShareVersion block).
//
// "Blocks in Window" is the blocks found since the oldest share in the window:
// the window's own block shares, plus the found-block ledger's blocks whose
// solving share is not on the best sharechain (a same-parent sibling share
// won the head race), counted apart. The hashrate chart marks every ledger
// block, so the panel and the chart must agree. Runs the functions extracted
// from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface WindowShare { h: string; H?: string; t?: number; blk?: number }
interface LedgerBlock { hash?: string; share?: string; ts?: number; chain?: string }
interface Count { total: number; onChain: number; offChain: number; oldest: number | null }
interface Descriptor {
  threshold: number; signaling: boolean; fromLive?: boolean;
  statNative: string; legendNative: string; legendStale: string;
}
interface Fns {
  c2pMarkBlocks(set: Record<string, boolean>, data: unknown, shares: WindowShare[], full: boolean): boolean;
  c2pWindowBlocks(blocks: LedgerBlock[] | null | undefined, shares: WindowShare[],
                  set: Record<string, boolean> | null, sym: string): Count;
  c2pWindowBlocksText(r: Count, sym: string): string;
  liveShareVersionDescriptor(base: Descriptor, live: unknown): Descriptor;
}

function section(html: string, name: string): string {
  const begin = html.indexOf('// BEGIN ' + name);
  const end = html.indexOf('// END ' + name);
  assert.ok(begin >= 0 && end > begin, `the ${name} block is in dashboard.html`);
  return html.slice(begin, end);
}

function load(): Fns {
  const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
  const src = section(html, 'c2pBlockMarks') + section(html, 'c2pWindowBlocks')
            + section(html, 'c2pLiveShareVersion');
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(src + '\nreturn { c2pMarkBlocks, c2pWindowBlocks, c2pWindowBlocksText, liveShareVersionDescriptor };')() as Fns;
}

const f = load();

// A DASH-like full hash: 14 leading zero hex digits, then the tail.
function full(tail50: string): string {
  return ('00000000000000' + tail50).padEnd(64, '0').slice(0, 64);
}
function share(tail50: string, t: number, blk?: number): WindowShare {
  const H = full(tail50);
  const s: WindowShare = { h: H.slice(0, 16), H, t };
  if (blk !== undefined) s.blk = blk;
  return s;
}

// The 11-14 dash.voidbind case: 10 blocks solved by window shares, 2 more in
// the ledger whose solving shares lost the head race to same-parent siblings.
test('ledger blocks whose share is off the best sharechain are counted apart', () => {
  const shares: WindowShare[] = [];
  const ledger: LedgerBlock[] = [];
  for (let i = 0; i < 10; i++) {
    const s = share('b' + String(i).padStart(2, '0') + 'a'.repeat(47), 2000 + i * 10, 1);
    shares.push(s);
    ledger.push({ hash: s.H, share: s.H, ts: 2001 + i * 10, chain: 'DASH' });
  }
  for (let i = 0; i < 50; i++) shares.push(share('c' + String(i).padStart(2, '0') + 'c'.repeat(47), 1000 + i * 30));
  const orphanA = full('22a7698e043c' + 'd'.repeat(38));
  const orphanB = full('023dd4b4dd4f' + 'e'.repeat(38));
  ledger.push({ hash: orphanA, share: orphanA, ts: 2500, chain: 'DASH' });
  ledger.push({ hash: orphanB, share: orphanB, ts: 1500, chain: 'DASH' });
  const set: Record<string, boolean> = {};
  f.c2pMarkBlocks(set, { block_hashes: shares.filter(s => s.blk).map(s => s.H) }, shares, false);

  const r = f.c2pWindowBlocks(ledger, shares, set, 'DASH');
  assert.deepEqual([r.total, r.onChain, r.offChain], [12, 10, 2]);
  assert.equal(r.oldest, 1000);
  assert.equal(f.c2pWindowBlocksText(r, 'DASH'), '12 DASH (2 by off-chain shares)');
});

test('with no off-chain block the text is the plain count, as before', () => {
  const a = share('aa' + '1'.repeat(48), 100, 1);
  const b = share('bb' + '2'.repeat(48), 200);
  const set: Record<string, boolean> = {};
  f.c2pMarkBlocks(set, { block_hashes: [a.H] }, [a, b], false);
  const r = f.c2pWindowBlocks([{ hash: a.H, share: a.H, ts: 101, chain: 'DASH' }], [a, b], set, 'DASH');
  assert.deepEqual([r.total, r.onChain, r.offChain], [1, 1, 0]);
  assert.equal(f.c2pWindowBlocksText(r, 'DASH'), '1 DASH');
  assert.equal(f.c2pWindowBlocksText({ total: 3, onChain: 2, offChain: 1, oldest: 1 }, 'DASH'),
               '3 DASH (1 by off-chain share)');
});

test('blocks found before the oldest window share are not counted', () => {
  const a = share('aa' + '1'.repeat(48), 1000);
  const old = full('ff' + '9'.repeat(48));
  const r = f.c2pWindowBlocks([{ hash: old, share: old, ts: 999, chain: 'DASH' }], [a], {}, 'DASH');
  assert.deepEqual([r.total, r.offChain], [0, 0]);
});

test('a window block share the ledger lacks still counts; one the ledger has counts once', () => {
  const a = share('aa' + '1'.repeat(48), 100, 1);   // found by a sharechain peer, not in our ledger
  const b = share('bb' + '2'.repeat(48), 200, 1);   // in both
  const set: Record<string, boolean> = {};
  f.c2pMarkBlocks(set, { block_hashes: [a.H, b.H] }, [a, b], false);
  const r = f.c2pWindowBlocks([{ hash: b.H, share: b.H, ts: 201, chain: 'DASH' },
                                { hash: b.H, share: b.H, ts: 201, chain: 'DASH' }], [a, b], set, 'DASH');
  assert.deepEqual([r.total, r.onChain, r.offChain], [2, 2, 0]);
});

test('ledger rows of another chain (a merged child) are not counted for the parent', () => {
  const a = share('aa' + '1'.repeat(48), 100);
  const doge = full('dd' + '3'.repeat(48));
  const r = f.c2pWindowBlocks([{ hash: doge, share: a.H, ts: 150, chain: 'DOGE' }], [a], {}, 'LTC');
  assert.equal(r.total, 0);
});

test('no ledger yet: the count is the window marks alone', () => {
  const a = share('aa' + '1'.repeat(48), 100, 1);
  const set: Record<string, boolean> = {};
  f.c2pMarkBlocks(set, { block_hashes: [a.H] }, [a], false);
  for (const ledger of [null, undefined, []]) {
    const r = f.c2pWindowBlocks(ledger, [a], set, 'DASH');
    assert.deepEqual([r.total, r.onChain, r.offChain], [1, 1, 0]);
  }
});

test('a share without its full hash (older node) is matched on the short hash', () => {
  const H = full('aa' + '1'.repeat(48));
  const legacy: WindowShare = { h: H.slice(0, 16), t: 100 };
  const r = f.c2pWindowBlocks([{ hash: H, share: H, ts: 101, chain: 'DASH' }], [legacy], {}, 'DASH');
  assert.deepEqual([r.total, r.onChain, r.offChain], [1, 1, 0]);
});

const DASH_BASE: Descriptor = {
  threshold: 16, signaling: false, fromLive: true,
  statNative: 'V16 Current', legendNative: 'V16 (others)', legendStale: 'Below V16',
};
const LTC_BASE: Descriptor = {
  threshold: 36, signaling: true,
  statNative: 'V36 Native', legendNative: 'V36 (others)', legendStale: 'V35 only',
};

test('DASH labels follow the live share version (V36 network)', () => {
  const d = f.liveShareVersionDescriptor(DASH_BASE, 36);
  assert.equal(d.threshold, 36);
  assert.equal(d.statNative, 'V36 Current');
  assert.equal(d.legendNative, 'V36 (others)');
  assert.equal(d.legendStale, 'Below V36');
  assert.equal(d.signaling, false);
});

test('the legacy DASH chain keeps V16, and no live version keeps the default', () => {
  assert.equal(f.liveShareVersionDescriptor(DASH_BASE, 16).statNative, 'V16 Current');
  for (const live of [null, undefined, 0, '36', NaN]) {
    assert.equal(f.liveShareVersionDescriptor(DASH_BASE, live), DASH_BASE);
  }
});

test('a coin that is not fromLive (LTC family) is never relabelled', () => {
  assert.equal(f.liveShareVersionDescriptor(LTC_BASE, 36), LTC_BASE);
  assert.equal(f.liveShareVersionDescriptor(LTC_BASE, 35), LTC_BASE);
});
