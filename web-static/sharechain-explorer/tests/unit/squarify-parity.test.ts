// Parity of the ONE squarify (src/pplns/squarify.ts) against the five
// copies it replaced (frozen verbatim in tests/unit/fixtures/). For a
// fixed input, every view must put every tile exactly where its old copy
// did — bit-identical for the inline copies, within 1e-9 relative for
// the PPLNS View (whose old copy used a different but equivalent ratio
// formula):
//   - dashboard.html hover zoom (extracted from the page itself)
//   - dashboard.html "PPLNS Distribution" (renderMainPPLNS)
//   - share.html PPLNS treemap (extracted from the page itself)
//   - src/plugins/treemap-squarified.ts (bundled hover zoom)
//   - src/pplns/squarify.ts before the change (PPLNS View)
// The four inline/plugin copies clamped each strip to ≥ 1 px; the PPLNS
// View copy did not. The one squarify carries that as `minStrip`, so each
// call site keeps its exact geometry. It also checks the built classic
// bundle dist/layout.js (window.C2PLayout) gives the same rects.
//
// Two copies had silently diverged; the tests pin both findings:
//   - the plugin (bundled hover zoom) computed an aspect ratio that ignores
//     the strip, so every row held one tile (slice-and-dice). It now
//     matches the inline hover zoom it was ported from.
//   - the inline hover copy had no "box used up" guard: once the 1 px
//     clamp had consumed the box it kept emitting zero/negative-size
//     slivers outside it. The one squarify stops there.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { squarify } from '../../src/pplns/squarify.js';
import { squarify as pluginSquarify } from '../../src/plugins/treemap-squarified.js';
import {
  dashboardHover as legacyHover,
  dashboardMain as legacyMain,
  sharePage as legacyShare,
} from './fixtures/legacy-squarify-inline.mjs';
import {
  pluginSquarify as legacyPlugin,
  pplnsSquarify as legacyPplns,
} from './fixtures/legacy-squarify-ts.js';

/** Exact (bit-identical) unless a relative tolerance is given. */
const EXACT = 0;
const REL_1E9 = 1e-9;
const C2PLayout = { squarify };

interface Entry { addr: string; amt: number; pct: number; doge: number; dogeAddr: string }
interface R { x: number; y: number; w: number; h: number; [k: string]: unknown }

// ── inputs ────────────────────────────────────────────────────────

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Rows as every inline view builds them: sorted by amount, desc. */
function entriesOf(amounts: readonly number[]): Entry[] {
  const rows = amounts.map((amt, i) => ({ addr: `X${i.toString(36).padStart(6, '0')}`, amt, doge: 0, dogeAddr: '' }));
  rows.sort((a, b) => b.amt - a.amt);
  const total = rows.reduce((s, r) => s + r.amt, 0);
  return rows.map((r) => ({ ...r, pct: total > 0 ? r.amt / total : 0 }));
}

function fixturePayouts(): number[] {
  const raw = JSON.parse(readFileSync(new URL('../visual/fixtures/merged_payouts.json', import.meta.url), 'utf8')) as
    Record<string, { amount: number }>;
  return Object.values(raw).map((v) => v.amount);
}

/** Named fixed inputs plus seeded random ones (uniform, heavy-tailed,
 *  one dominant miner, ties). */
function cases(): Array<{ name: string; amounts: number[] }> {
  const out: Array<{ name: string; amounts: number[] }> = [
    { name: 'visual fixture (12 miners)', amounts: fixturePayouts() },
    { name: 'one miner', amounts: [3.2] },
    { name: 'two equal', amounts: [1, 1] },
    { name: 'eight equal', amounts: Array(8).fill(0.125) },
    { name: 'LTC-like: 97% + 40 tiny', amounts: [97, ...Array.from({ length: 40 }, (_, i) => 3 * (i + 1) / 820)] },
  ];
  for (let seed = 1; seed <= 120; seed++) {
    const rnd = mulberry32(seed);
    const n = 1 + Math.floor(rnd() * 160);
    const kind = seed % 4;
    const amounts = Array.from({ length: n }, () => {
      const u = rnd();
      if (kind === 0) return 0.01 + u;                       // uniform
      if (kind === 1) return Math.pow(1 - u, -1.6);          // heavy tail
      if (kind === 2) return Math.round(u * 5 + 1);          // many ties
      return u < 0.04 ? 500 + u : 0.001 + u * 0.01;          // whales + dust
    });
    out.push({ name: `seed ${seed} (kind ${kind}, n=${n})`, amounts });
  }
  return out;
}

const BOXES: Array<[number, number, number, number]> = [
  [2, 2, 236, 236],   // hover zoom (240 px with 2 px padding)
  [0, 0, 1200, 400],  // main treemap, wide
  [0, 0, 360, 640],   // main treemap, portrait
  [0, 0, 1000, 700],  // share page
  [0, 0, 60, 30],     // tiny: the 1 px clamp bites
];

// ── page extraction ───────────────────────────────────────────────

const DASH = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
const SHARE = readFileSync(new URL('../../../share.html', import.meta.url), 'utf8');

function slice(src: string, from: string, to: string): string {
  const a = src.indexOf(from);
  assert.ok(a >= 0, `marker not found: ${from}`);
  const b = src.indexOf(to, a + from.length);
  assert.ok(b > a, `end marker not found after: ${from}`);
  return src.slice(a, b + to.length);
}

function loadDashHelpers(): {
  c2pSquarify: (items: unknown[], x: number, y: number, w: number, h: number) => R[];
  treemap: (data: Entry[], x: number, y: number, w: number, h: number) => R[];
} {
  const helpers = slice(DASH, '// BEGIN c2pLayout', '// END c2pLayout');
  const method = slice(DASH, 'treemap: function(data, x, y, w, h) {', '\n            },');
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function('C2PLayout', `${helpers}
    var view = { ${method} };
    return { c2pSquarify: c2pSquarify, treemap: function (d, x, y, w, h) { return view.treemap(d, x, y, w, h); } };`,
  )(C2PLayout);
}

function loadSharePplnsTreemap(): (data: Entry[], x: number, y: number, w: number, h: number) => R[] {
  const fn = slice(SHARE, 'function pplnsTreemap(data, x, y, w, h) {', '\n        }');
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function('C2PLayout', `${fn}\nreturn pplnsTreemap;`)(C2PLayout);
}

// ── comparison ────────────────────────────────────────────────────

function assertSameRects(
  got: readonly R[], want: readonly R[], keys: readonly string[], label: string, rel = EXACT,
): void {
  assert.equal(got.length, want.length, `${label}: rect count`);
  for (let i = 0; i < want.length; i++) {
    const g = got[i]!;
    const w = want[i]!;
    for (const k of ['x', 'y', 'w', 'h'] as const) {
      const d = Math.abs((g[k] as number) - (w[k] as number));
      const tol = rel * Math.max(1, Math.abs(w[k] as number));
      assert.ok(d <= tol, `${label}: rect ${i} ${k} ${g[k]} vs ${w[k]} (Δ ${d})`);
    }
    for (const k of keys) assert.equal(g[k], w[k], `${label}: rect ${i} ${k}`);
  }
}

const dash = loadDashHelpers();
const shareTreemap = loadSharePplnsTreemap();

/** The legacy hover copy minus the zero/negative-size slivers it emitted
 *  after the 1 px clamp had used up the box; asserts they are only that. */
function legacyHoverVisible(e: Entry[], x: number, y: number, w: number, h: number, label: string): R[] {
  const all = legacyHover.treemap(e, x, y, w, h) as R[];
  const firstBad = all.findIndex((r) => !(r.w > 0) || !(r.h > 0));
  if (firstBad < 0) return all;
  for (const r of all.slice(firstBad)) {
    assert.ok(!(r.w > 0 && r.h > 0), `${label}: a visible legacy tile after an exhausted box`);
  }
  return all.slice(0, firstBad);
}

test('dashboard.html hover zoom: rects identical to the legacy copy', () => {
  for (const c of cases()) {
    const e = entriesOf(c.amounts);
    const [x, y, w, h] = BOXES[0]!;
    const want = legacyHoverVisible(e, x, y, w, h, `hover ${c.name}`);
    assertSameRects(dash.treemap(e, x, y, w, h), want, ['addr', 'pct'], `hover ${c.name}`);
  }
});

test('dashboard.html PPLNS Distribution: rects identical to the legacy copy', () => {
  // renderMainPPLNS maps entries the same way the extracted helper is fed here.
  assert.ok(/c2pSquarify\(entries\.map\(function\(d\) \{ return \{ area: d\.pct, data: d \}; \}\), 0, 0, w, h\)/.test(DASH),
    'renderMainPPLNS lays out entries by pct through c2pSquarify');
  for (const c of cases()) {
    const e = entriesOf(c.amounts);
    for (const [, , w, h] of BOXES.slice(1)) {
      const want = legacyMain(e, w, h) as R[];
      const got = dash.c2pSquarify(e.map((d) => ({ area: d.pct, data: d })), 0, 0, w, h)
        .map((r) => ({ x: r.x, y: r.y, w: r.w, h: r.h, ...(r.data as Entry) }));
      assertSameRects(got, want, ['addr', 'pct', 'amt', 'doge', 'dogeAddr'], `main ${c.name} ${w}x${h}`);
    }
  }
});

test('share.html PPLNS treemap: rects identical to the legacy copy', () => {
  for (const c of cases()) {
    const e = entriesOf(c.amounts);
    for (const [x, y, w, h] of BOXES.slice(1)) {
      const want = legacyShare(e, x, y, w, h) as R[];
      assertSameRects(shareTreemap(e, x, y, w, h), want, ['addr', 'pct', 'amt', 'doge', 'dogeAddr'],
        `share ${c.name} ${w}x${h}`);
    }
  }
});

test('plugin layout.treemap (bundled hover zoom): rects identical to the inline hover zoom', () => {
  for (const c of cases()) {
    const e = entriesOf(c.amounts);
    const items = e.map((d) => ({ area: d.pct, addr: d.addr, pct: d.pct }));
    for (const [x, y, w, h] of BOXES) {
      const label = `plugin ${c.name} ${w}x${h}`;
      assertSameRects(pluginSquarify(items, x, y, w, h), legacyHoverVisible(e, x, y, w, h, label), ['addr', 'pct'], label);
    }
  }
});

test('finding: the old plugin copy had diverged from the inline hover zoom', () => {
  // Its aspectFor(area, strip, main) reduces to max(area/main, main/area),
  // independent of the strip, so adding a smaller tile always looked
  // worse and every row closed after one tile: thin slivers instead of
  // squarified tiles.
  const e = entriesOf(fixturePayouts());
  const items = e.map((d) => ({ area: d.pct, addr: d.addr, pct: d.pct }));
  const old = legacyPlugin(items, 2, 2, 236, 236);
  const inline = legacyHover.treemap(e, 2, 2, 236, 236) as R[];
  assert.equal(old.length, inline.length);
  assert.notDeepEqual(old.map((r) => [r.x, r.y, r.w, r.h]), inline.map((r) => [r.x, r.y, r.w, r.h]));
  const worst = (rs: readonly R[]): number => Math.max(...rs.map((r) => Math.max(r.w / r.h, r.h / r.w)));
  assert.ok(worst(old) > 2 * worst(inline), `old worst aspect ${worst(old)} vs inline ${worst(inline)}`);
});

test('PPLNS View squarify (minStrip 0): rects identical to the legacy copy', () => {
  for (const c of cases()) {
    // The PPLNS View passes raw amounts, unsorted; squarify sorts.
    const items = c.amounts.map((a, i) => ({ area: a, data: i }));
    for (const [x, y, w, h] of BOXES) {
      const want = legacyPplns(items, x, y, w, h).map((r) => ({ ...r, id: r.data }));
      const got = squarify(items, x, y, w, h).map((r) => ({ ...r, id: r.data }));
      assertSameRects(got, want, ['id'], `pplns ${c.name} ${w}x${h}`, REL_1E9);
    }
  }
});

test('minStrip 0 keeps tile areas proportional to the weights', () => {
  const amounts = [97, ...Array.from({ length: 40 }, (_, i) => 3 * (i + 1) / 820)];
  const total = amounts.reduce((s, a) => s + a, 0);
  const rects = squarify(amounts.map((a, i) => ({ area: a, data: i })), 0, 0, 240, 240);
  assert.equal(rects.length, amounts.length);
  for (const r of rects) {
    const want = (amounts[r.data]! / total) * 240 * 240;
    assert.ok(Math.abs(r.w * r.h - want) <= 1e-6 * 240 * 240, `tile ${r.data}`);
  }
});

test('minStrip only changes a layout whose strips would be thinner than it', () => {
  // A row's strip is one side of each of its tiles, so when no tile is
  // thinner than 1 px no strip was clamped and the layouts must match.
  let clamped = 0;
  for (const c of cases()) {
    const items = c.amounts.map((a, i) => ({ area: a, data: i }));
    for (const [x, y, w, h] of BOXES) {
      const free = squarify(items, x, y, w, h);
      const one = squarify(items, x, y, w, h, { minStrip: 1 });
      if (free.every((r) => Math.min(r.w, r.h) >= 1)) {
        assert.deepEqual(one, free, `${c.name} ${w}x${h}`);
      } else if (JSON.stringify(one) !== JSON.stringify(free)) {
        clamped++;
      }
    }
  }
  assert.ok(clamped > 0, 'the corpus exercises the clamp');
});

test('dist/layout.js (window.C2PLayout) matches the module', () => {
  const path = new URL('../../dist/layout.js', import.meta.url);
  if (!existsSync(path)) {
    assert.fail('dist/layout.js is not built; run `npm run build`');
  }
  const src = readFileSync(path, 'utf8');
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  const built = new Function(`${src}\nreturn C2PLayout;`)() as { squarify: typeof squarify };
  assert.equal(typeof built.squarify, 'function');
  for (const c of cases().slice(0, 30)) {
    const items = entriesOf(c.amounts).map((e) => ({ area: e.pct, data: e.addr }));
    for (const [x, y, w, h] of BOXES) {
      for (const opts of [undefined, { minStrip: 1 }]) {
        const want = squarify(items, x, y, w, h, opts);
        assert.deepEqual(built.squarify(items, x, y, w, h, opts), want, `${c.name} ${w}x${h}`);
      }
    }
  }
});

test('pages load layout.js with a content-hash stamp and hold no squarify copy', () => {
  for (const [name, html] of [['dashboard.html', DASH], ['share.html', SHARE]] as const) {
    assert.ok(/<script[^>]+src="sharechain-explorer\/dist\/layout\.js\?v=[0-9a-f]{8}"/.test(html), `${name} loads layout.js`);
    assert.ok(!/_layoutRow|_worstAspect|function tmLayout|_tmLayout|_tmWorst/.test(html), `${name} has no inline squarify`);
  }
});
