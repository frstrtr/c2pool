// The inline dashboard's "Current Payouts" row roles (dashboard.html, the
// c2pPayoutRole block): which row is the coinbase donation output and which
// is this node's owner fee payee, the V<thr>? cell and the small label.
//
// The donation output is not a miner and has no share version, so its
// version cell is a neutral ◇, never ✓ / ⇧ / ✗. It is found from what the
// node publishes (/web/currency_info donation_address and
// merged_donation_addresses, #2236), or on a node without those fields from
// the /current_merged_payouts child source "donation"; never from an address
// prefix (the PPLNS treemap's classifyAddress rule). Runs the functions
// extracted from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface MergedChild { symbol?: string; address?: string; amount?: number; source?: string; parent?: string }
interface Row { amount: number; merged: MergedChild[] }
interface CurrencyInfo {
  symbol?: string;
  donation_address?: string;
  merged_donation_addresses?: Record<string, string>;
  node_owner_address?: string;
}
interface Ver { ver: number; dv: number }
interface Fns {
  c2pPayoutRole(addr: string, entry: Row | null, ci: CurrencyInfo | undefined): string;
  c2pMergedIsDonation(merged: MergedChild, ci: CurrencyInfo | undefined): boolean;
  c2pPayoutVersionHtml(role: string, mv: Ver, thr: number, staleTitle: string): string | null;
  c2pPayoutRoleLabel(role: string, sym: string): { text: string; title: string } | null;
  c2pPayoutRowSymbol(addr: string, entry: Row | null, ci: CurrencyInfo | undefined): string;
}

const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');

function section(name: string): string {
  const begin = html.indexOf('// BEGIN ' + name);
  const end = html.indexOf('// END ' + name);
  assert.ok(begin >= 0 && end > begin, `the ${name} block is in dashboard.html`);
  return html.slice(begin, end);
}

// eslint-disable-next-line @typescript-eslint/no-implied-eval
const f = new Function(section('c2pPayoutRole')
  + '\nreturn { c2pPayoutRole, c2pMergedIsDonation, c2pPayoutVersionHtml, c2pPayoutRoleLabel, c2pPayoutRowSymbol };')() as Fns;

const DON_LTC = 'MLhSmVQxMusLE3pjGFvp4unFckgjeD8LUA';
// The DOGE donation output: the aux coinbase's single P2PKH key
// (merged_donation_script, c2pool/merged/merged_donation.hpp).
const DON_DOGE = 'D88Vn6Dyct7DKfVCfR3syHkjyNx9gEyyiv';

// /current_merged_payouts as served 2026-11-16 (sg-ltc and the outside LTC
// node 92.53.224.27 agree), trimmed to two miners and the donation row, with
// the donation row's DOGE address the one the aux coinbase pays now.
const LTC_MERGED: Record<string, Row> = {
  LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F: { amount: 6.18633968, merged: [{ address: 'DFtxz7j9cN7P1cY5dz5RuYbSk9df7dyjuS', amount: 9915.74776462, parent: 'LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F', source: 'explicit', symbol: 'DOGE' }] },
  LLd7gHqnEkaYahJ3s4gGuR7Qqps9pqQtYi: { amount: 0.04739658, merged: [{ address: 'DMjcAEDQ6Qg96ZaVR5dy4oidvrfoPB5kzC', amount: 58.42132557, parent: 'LLd7gHqnEkaYahJ3s4gGuR7Qqps9pqQtYi', source: 'explicit', symbol: 'DOGE' }] },
  [DON_LTC]: { amount: 0.00629519, merged: [{ address: DON_DOGE, amount: 10.07108689, source: 'donation', symbol: 'DOGE' }] },
};

// (a) a node with the #2236 fields (sg-ltc /web/currency_info).
const CI_NEW: CurrencyInfo = {
  symbol: 'LTC', donation_address: DON_LTC, merged_donation_addresses: { DOGE: DON_DOGE },
  node_owner_address: '',
};
// (c) a node from before #2236 (the outside node): no donation fields.
const CI_OLD: CurrencyInfo = { symbol: 'LTC' };

const V36: Ver = { ver: 36, dv: 36 };
const NONE: Ver = { ver: 0, dv: 0 };   // getMinerVersion of an address with no shares

function cell(role: string, mv: Ver, thr = 36): string | null {
  return f.c2pPayoutVersionHtml(role, mv, thr, 'V' + mv.ver + ' only');
}

test('(a) node with the donation fields: the donation row is ◇, miners keep their version', () => {
  assert.equal(f.c2pPayoutRole(DON_LTC, LTC_MERGED[DON_LTC]!, CI_NEW), 'donation');
  // Without the merged entry too (the /current_payouts fallback path).
  assert.equal(f.c2pPayoutRole(DON_LTC, null, CI_NEW), 'donation');
  assert.equal(f.c2pPayoutRole('LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F', LTC_MERGED.LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F!, CI_NEW), '');

  const don = cell('donation', NONE)!;
  assert.match(don, /◇/);
  assert.match(don, /title="Donation output \(protocol\), not a miner — no share version"/);
  assert.match(don, /var\(--text-muted\)/);
  assert.doesNotMatch(don, /[⇧✓✗]|signaling/);
  // Whatever version data there is, the donation row never shows one.
  assert.equal(cell('donation', { ver: 35, dv: 36 }), don);
  assert.match(cell('', V36)!, /✓/);

  const child = LTC_MERGED[DON_LTC]!.merged[0]!;
  assert.equal(f.c2pMergedIsDonation(child, CI_NEW), true);
  assert.deepEqual(f.c2pPayoutRoleLabel('donation', child.symbol!),
    { text: '◇ donation', title: 'Donation output of the coinbase for DOGE' });
  assert.deepEqual(f.c2pPayoutRoleLabel('donation', 'LTC'),
    { text: '◇ donation', title: 'Donation output of the coinbase for LTC' });
  assert.equal(f.c2pMergedIsDonation(LTC_MERGED.LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F!.merged[0]!, CI_NEW), false);
});

test('(c) node without the donation fields: found from source "donation"', () => {
  assert.equal(f.c2pPayoutRole(DON_LTC, LTC_MERGED[DON_LTC]!, CI_OLD), 'donation');
  assert.equal(f.c2pMergedIsDonation(LTC_MERGED[DON_LTC]!.merged[0]!, CI_OLD), true);
  assert.equal(f.c2pPayoutRole('LLd7gHqnEkaYahJ3s4gGuR7Qqps9pqQtYi', LTC_MERGED.LLd7gHqnEkaYahJ3s4gGuR7Qqps9pqQtYi!, CI_OLD), '');
});

test('never from an address prefix', () => {
  // The donation address with nothing published about it is a plain row.
  assert.equal(f.c2pPayoutRole(DON_LTC, { amount: 0.006, merged: [] }, CI_OLD), '');
  assert.equal(f.c2pPayoutRole(DON_LTC, null, {}), '');
  assert.equal(f.c2pPayoutRole('LeD2fnnDJYZuyt8zgDsZ2oBGmuVcxGKCLd', null, undefined), '');
  assert.equal(f.c2pMergedIsDonation({ symbol: 'DOGE', address: DON_DOGE, source: 'explicit' }, CI_OLD), false);
  // No prefix test left in the payouts code: the block, and getMinerVersion
  // (it used to answer V35-signaling-V36 for LeD2f / MLhSm addresses).
  const gmv = html.slice(html.indexOf('function getMinerVersion('), html.indexOf('// END c2pPayoutRole'));
  assert.ok(gmv.length > 0);
  assert.doesNotMatch(gmv, /indexOf\(\s*['"](LeD2f|MLhSm)/);
});

test('(b) DASH-like node: no donation fields and no merged children, every row a miner', () => {
  const ci: CurrencyInfo = { symbol: 'DASH' };
  const rows: Record<string, Row> = {
    XmFirstMinerAddr000000000000000000: { amount: 1.2, merged: [] },
    XmSecondMinerAddr00000000000000000: { amount: 0.3, merged: [] },
  };
  for (const [addr, row] of Object.entries(rows)) {
    assert.equal(f.c2pPayoutRole(addr, row, ci), '');
    assert.equal(f.c2pPayoutRoleLabel('', 'DASH'), null);
  }
  assert.match(cell('', { ver: 16, dv: 16 }, 16)!, /✓/);
  assert.match(cell('', { ver: 15, dv: 15 }, 16)!, /✗/);
  assert.equal(cell('', NONE, 16), null, 'unknown version: the caller shows "-"');
});

test('a donation output no parent row took is its own row, keyed by its merged address', () => {
  const row: Row = { amount: 0, merged: [{ symbol: 'DOGE', address: DON_DOGE, amount: 10.07, source: 'donation' }] };
  assert.equal(f.c2pPayoutRole(DON_DOGE, row, CI_NEW), 'donation');
  assert.equal(f.c2pPayoutRole(DON_DOGE, row, CI_OLD), 'donation');
  // A lower-case symbol is matched against the upper-case currency_info keys.
  assert.equal(f.c2pMergedIsDonation({ symbol: 'doge', address: DON_DOGE }, CI_NEW), true);
  // Its label names the chain the output is on, not the parent coin.
  assert.equal(f.c2pPayoutRowSymbol(DON_DOGE, row, CI_NEW), 'DOGE');
  assert.equal(f.c2pPayoutRowSymbol(DON_DOGE, row, CI_OLD), 'DOGE', 'older node: its own child\'s symbol');
  assert.equal(f.c2pPayoutRowSymbol(DON_DOGE, null, CI_NEW), 'DOGE', 'from merged_donation_addresses alone');
  assert.equal(f.c2pPayoutRoleLabel('donation', f.c2pPayoutRowSymbol(DON_DOGE, row, CI_NEW))!.title,
    'Donation output of the coinbase for DOGE');
  // A parent row stays on the parent coin.
  assert.equal(f.c2pPayoutRowSymbol(DON_LTC, LTC_MERGED[DON_LTC]!, CI_NEW), 'LTC');
  assert.equal(f.c2pPayoutRowSymbol(DON_LTC, LTC_MERGED[DON_LTC]!, CI_OLD), 'LTC');
  assert.equal(f.c2pPayoutRowSymbol('LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F', LTC_MERGED.LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F!, CI_NEW), 'LTC');
  assert.equal(f.c2pPayoutRowSymbol('XmMiner', null, {}), 'COIN');
});

test('⚑ node fee: the published node-owner address; the donation outranks it', () => {
  const owner = 'LOwnerFeeAddr00000000000000000000';
  const ci: CurrencyInfo = { ...CI_NEW, node_owner_address: owner };
  assert.equal(f.c2pPayoutRole(owner, { amount: 0.1, merged: [] }, ci), 'owner');
  // The owner's fee shares carry a version: the cell is the miner's.
  assert.match(cell('owner', V36)!, /✓/);
  assert.equal(f.c2pPayoutRoleLabel('owner', 'LTC')!.text, '⚑ node fee');
  // node_owner_address "" (no fee) marks nothing.
  assert.equal(f.c2pPayoutRole('', null, CI_NEW), '');
  assert.equal(f.c2pPayoutRole('LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F', null, CI_NEW), '');
  assert.equal(f.c2pPayoutRole(DON_LTC, null, { ...ci, node_owner_address: DON_LTC }), 'donation');
});
