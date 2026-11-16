// Cache-bust stamps for every HTTP-served page and loader that pulls in
// this package's scripts.
//
// Static assets are served with a long cache (c2pool: max-age=3600; the
// dash.voidbind edge forces no-cache on *.html only), so after a deploy a
// browser could pair a fresh page with a cached older script. Every
// reference from the files below to a script inside this package — a
// `src="…"` attribute, a dynamic `import('…')` or a static `from '…'` —
// therefore carries `?v=<first 8 hex of the target's sha256>`: new
// content, new URL. (c2pool's static server strips the query before the
// file lookup, http_session.cpp.)
//
// Order matters: a loader is stamped before the page that references
// it, because stamping changes the loader's own hash.
//
// Not stamped: the Qt embeds (dashboard-embed.html, pplns-embed.html).
// They load from qrc:/ resources compiled into the binary, so there is
// no HTTP cache to go stale, and a query string on a qrc:/ URL buys
// nothing. References to files outside this package (web-static's own
// d3.v2.min.js, highcharts.js, …) are left alone.
//
//   node scripts/stamp-html.mjs           rewrite stamps
//   node scripts/stamp-html.mjs --check   exit 1 when a stamp is stale
//                                         (run by `npm run verify`)
//
// Run after `npm run build`.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TARGETS = [
  'dashboard-bundled.mjs',   // → dist/sharechain-explorer.js
  'dashboard-bundled.html',  // → dashboard-bundled.mjs (stamped above)
  '../dashboard.html',       // → dist/layout.js, dist/sharechain-explorer.js
  '../share.html',           // → dist/layout.js
].map((p) => join(ROOT, p));

// A src="…" attribute, an import('…') specifier or a `from '…'` clause
// naming a relative .js/.mjs path, with an optional existing stamp.
const REF = /(src="|import\(\s*['"]|from\s+['"])((?:\.\/)?[A-Za-z0-9_][A-Za-z0-9_./-]*\.m?js)(\?v=[0-9a-f]*)?(?=['"])/g;

const check = process.argv.includes('--check');

function stampOf(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex').slice(0, 8);
}

let stale = 0;
let missing = 0;
for (const page of TARGETS) {
  if (!existsSync(page)) continue;
  const text = readFileSync(page, 'utf8');
  const next = text.replace(REF, (whole, lead, ref, oldQuery) => {
    const target = resolve(dirname(page), ref);
    const rel = relative(ROOT, target);
    if (rel.startsWith('..') || rel.split(sep).includes('node_modules')) return whole;  // not ours
    if (!existsSync(target)) {
      console.error(`${relative(ROOT, page)}: references ${rel}, which does not exist (run npm run build)`);
      missing++;
      return whole;
    }
    const want = `${lead}${ref}?v=${stampOf(target)}`;
    if (whole !== want) {
      stale++;
      console.log(`${check ? 'stale' : 'stamped'}: ${relative(ROOT, page)} ${rel} ${oldQuery ?? '(none)'} -> ${want.slice(want.lastIndexOf('?'))}`);
    }
    return want;
  });
  // Write as we go: a later target may hash this one.
  if (!check && next !== text) writeFileSync(page, next);
}

if (missing > 0) process.exit(1);
if (check && stale > 0) {
  console.error(`\n${stale} stale cache-bust stamp(s): run \`npm run stamp\` after \`npm run build\` and commit the result.`);
  process.exit(1);
}
console.log(check ? 'cache-bust stamps up to date' : `cache-bust stamps written (${stale} changed)`);
