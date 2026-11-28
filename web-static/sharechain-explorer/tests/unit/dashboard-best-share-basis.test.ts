// The inline dashboard's Best Share card (dashboard.html renderBestShare):
// the "best / difficulty" line shows the network difficulty in effect when
// the share was found (network_difficulty_at_share), for the parent and the
// merged row. A pct measured against that value (pct_basis "at_share") is
// shown plain with the tooltip "vs network difficulty when the share was
// found"; a pct against the live difficulty (pct_basis "current", or no
// pct_basis from an older node) is marked with the tooltip "vs current
// difficulty" and a dotted underline. No record: no marks. Runs the
// functions extracted from dashboard.html itself, over a d3 stub.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

interface El {
  text: string | null;
  html: string | null;
  attrs: Record<string, string>;
  style: Record<string, string>;
}
interface Leg {
  difficulty: number;
  pct_of_block: number;
  network_difficulty_at_share?: number;
  pct_basis?: string;
}
interface BestShare {
  network_difficulty: number;
  has_best_share?: boolean;
  round: Leg;
  all_time: Leg;
  session?: Leg;
  merged?: { network_difficulty: number; symbol?: string; round: Leg; all_time: Leg };
}

function extract(html: string, name: string): string {
  const start = html.indexOf('function ' + name + '(');
  assert.ok(start >= 0, name + ' is in dashboard.html');
  const end = html.indexOf('\n        function ', start + 1);
  assert.ok(end > start, name + ' ends');
  return html.slice(start, end);
}

function loadCard(): (bs: BestShare) => Record<string, El> {
  const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
  const src = ['format_difficulty', 'format_pct_fancy', 'renderBestShare']
    .map((n) => extract(html, n)).join('\n');
  let els: Record<string, El> = {};
  const select = (sel: string) => {
    const id = sel.replace(/^#/, '');
    const e = els[id] ?? (els[id] = { text: null, html: null, attrs: {}, style: {} });
    const o = {
      text(v: string) { e.text = v; return o; },
      html(v: string) { e.html = v; return o; },
      attr(k: string, v: string | null) { if (v === null) delete e.attrs[k]; else e.attrs[k] = v; return o; },
      style(k: string, v: string | null) { if (v === null) delete e.style[k]; else e.style[k] = v; return o; },
    };
    return o;
  };
  const d3 = {
    select,
    format: (spec: string) => (x: number) => x.toFixed(parseInt(spec.slice(1), 10)),
  };
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  const render = new Function('d3', src + '\nreturn renderBestShare;')(d3) as (bs: BestShare) => void;
  return (bs: BestShare) => { els = {}; render(bs); return els; };
}

const card = loadCard();
const plain = (h: string | null) => (h ?? '').replace(/<[^>]+>/g, '');
const AT_PCT = 'vs network difficulty when the share was found';
const CUR_PCT = 'vs current difficulty';
const AT_DIFF = 'network difficulty when the share was found';
const CUR_DIFF = 'current difficulty';

function leg(difficulty: number, at: number, live: number): Leg {
  return {
    difficulty,
    network_difficulty_at_share: at,
    pct_of_block: (difficulty / (at > 0 ? at : live)) * 100,
    pct_basis: at > 0 ? 'at_share' : 'current',
  };
}

function el(els: Record<string, El>, id: string): El {
  const e = els[id];
  assert.ok(e, id + ' was rendered');
  return e;
}

function assertAtShare(e: El, title: string): void {
  assert.equal(e.attrs['title'], title);
  assert.equal(e.style['text-decoration'], undefined, 'an at-share value is not marked');
}

function assertCurrent(e: El, title: string): void {
  assert.equal(e.attrs['title'], title);
  assert.equal(e.style['text-decoration'], 'underline dotted');
}

test('the incident: DOGE 58.56 M against 62.63 M at the share reads 93.5%, unmarked', () => {
  const els = card({
    network_difficulty: 9.5e7, has_best_share: true,
    round: leg(58.56e6, 9.0e7, 9.5e7), all_time: leg(58.56e6, 9.0e7, 9.5e7),
    merged: { network_difficulty: 39.77e6, symbol: 'DOGE',
              round: leg(58.56e6, 62.63e6, 39.77e6), all_time: leg(58.56e6, 62.63e6, 39.77e6) },
  });
  assert.equal(el(els, 'best_share_round_diff').text, '58.56 M');
  assert.equal(el(els, 'best_share_net_diff').text, '90.00 M', 'the parent at-share difficulty, not the live 95 M');
  assert.equal(el(els, 'best_share_merged_round_diff').text, '58.56 M');
  assert.equal(el(els, 'best_share_merged_net_diff').text, '62.63 M', 'the aux at-share difficulty, not the live 39.77 M');
  assert.equal(plain(el(els, 'best_share_merged_pct_fancy').html), '93.5015%');
  assert.equal(plain(el(els, 'best_share_merged_alltime_pct_fancy').html), '93.5015%');
  for (const id of ['best_share_round_pct_fancy', 'best_share_alltime_pct_fancy',
                    'best_share_merged_pct_fancy', 'best_share_merged_alltime_pct_fancy'])
    assertAtShare(el(els, id), AT_PCT);
  assertAtShare(el(els, 'best_share_net_diff'), AT_DIFF);
  assertAtShare(el(els, 'best_share_merged_net_diff'), AT_DIFF);
});

test('an all-time leg from an older sidecar (pct_basis "current") is marked, the round leg is not', () => {
  const els = card({
    network_difficulty: 2e8, has_best_share: true,
    round: leg(1e7, 1.9e8, 2e8), all_time: leg(5e7, 0, 2e8),
    merged: { network_difficulty: 39.77e6, round: leg(1e7, 62.63e6, 39.77e6), all_time: leg(5.856e7, 0, 39.77e6) },
  });
  assertAtShare(el(els, 'best_share_round_pct_fancy'), AT_PCT);
  assertCurrent(el(els, 'best_share_alltime_pct_fancy'), CUR_PCT);
  assertAtShare(el(els, 'best_share_merged_pct_fancy'), AT_PCT);
  assertCurrent(el(els, 'best_share_merged_alltime_pct_fancy'), CUR_PCT);
  assert.equal(plain(el(els, 'best_share_alltime_pct_fancy').html), '25.0000%');
  assert.equal(el(els, 'best_share_net_diff').text, '190.00 M');
  assertAtShare(el(els, 'best_share_net_diff'), AT_DIFF);
});

test('a round leg with no at-share value shows the live difficulty, marked', () => {
  const els = card({
    network_difficulty: 1e8, has_best_share: true,
    round: leg(5e7, 0, 1e8), all_time: leg(5e7, 0, 1e8),
  });
  assert.equal(el(els, 'best_share_net_diff').text, '100.00 M');
  assertCurrent(el(els, 'best_share_net_diff'), CUR_DIFF);
  assertCurrent(el(els, 'best_share_round_pct_fancy'), CUR_PCT);
});

test('an older node (no pct_basis) is read as measured against the live difficulty', () => {
  const els = card({
    network_difficulty: 1e8, has_best_share: true,
    round: { difficulty: 5e7, pct_of_block: 50 }, all_time: { difficulty: 5e7, pct_of_block: 50 },
  });
  assert.equal(plain(el(els, 'best_share_round_pct_fancy').html), '50.0000%');
  assert.equal(el(els, 'best_share_net_diff').text, '100.00 M');
  assertCurrent(el(els, 'best_share_round_pct_fancy'), CUR_PCT);
  assertCurrent(el(els, 'best_share_alltime_pct_fancy'), CUR_PCT);
  assertCurrent(el(els, 'best_share_net_diff'), CUR_DIFF);
  assert.equal(els['best_share_merged_round_part'], undefined, 'no merged row without an aux chain');
});

test('an at-share value with pct_basis "current" is not trusted', () => {
  const r: Leg = { difficulty: 5e7, pct_of_block: 50, network_difficulty_at_share: 9e7, pct_basis: 'current' };
  const els = card({ network_difficulty: 1e8, has_best_share: true, round: r, all_time: r });
  assert.equal(el(els, 'best_share_net_diff').text, '100.00 M');
  assertCurrent(el(els, 'best_share_round_pct_fancy'), CUR_PCT);
});

test('no record yet: no value, no marks', () => {
  const els = card({ network_difficulty: 1e8, has_best_share: false, round: leg(0, 0, 1e8), all_time: leg(0, 0, 1e8) });
  assert.equal(el(els, 'best_share_round_diff').text, 'no record yet');
  assert.equal(el(els, 'best_share_net_diff').text, '100.00 M');
  for (const id of ['best_share_round_pct_fancy', 'best_share_alltime_pct_fancy', 'best_share_net_diff']) {
    assert.equal(el(els, id).attrs['title'], undefined, id);
    assert.equal(el(els, id).style['text-decoration'], undefined, id);
  }
});
