// Cache-bust stamps for the web-static pages that load bundles.
//
// Static assets are served with a long cache (c2pool: max-age=3600; the
// dash.voidbind edge forces no-cache on *.html only), so after a deploy a
// browser could pair a fresh page with a cached older bundle. Every
// reference to `sharechain-explorer/dist/<file>.js` in the pages below
// therefore carries `?v=<first 8 hex of the file's sha256>`: new content,
// new URL. (c2pool's static server strips the query before the file
// lookup, http_session.cpp.)
//
//   node scripts/stamp-html.mjs           rewrite stamps from dist/
//   node scripts/stamp-html.mjs --check   exit 1 when a stamp is stale
//                                         (run by `npm run verify`)
//
// Run after `npm run build`.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

const ROOT = new URL('..', import.meta.url).pathname;
const DIST = join(ROOT, 'dist');
const PAGES = ['../dashboard.html', '../share.html'].map((p) => join(ROOT, p));
// Only real loads: a src="…" attribute or an import('…') specifier —
// not comments or messages that merely mention the path.
const REF = /(src="|import\(['"])(\.\/)?sharechain-explorer\/dist\/([A-Za-z0-9_.-]+\.js)(\?v=[0-9a-f]*)?/g;

const check = process.argv.includes('--check');
const hashCache = new Map();

function stampOf(file) {
  if (!hashCache.has(file)) {
    const path = join(DIST, file);
    hashCache.set(file, existsSync(path)
      ? createHash('sha256').update(readFileSync(path)).digest('hex').slice(0, 8)
      : null);
  }
  return hashCache.get(file);
}

let stale = 0;
let missing = 0;
for (const page of PAGES) {
  if (!existsSync(page)) continue;
  const html = readFileSync(page, 'utf8');
  const next = html.replace(REF, (whole, lead, dot, file, oldQuery) => {
    const v = stampOf(file);
    if (v === null) {
      console.error(`${page}: references dist/${file}, which is not built`);
      missing++;
      return whole;
    }
    const want = `${lead}${dot ?? ''}sharechain-explorer/dist/${file}?v=${v}`;
    if (whole !== want) {
      stale++;
      console.log(`${check ? 'stale' : 'stamped'}: ${page.replace(ROOT, '')} dist/${file} ${oldQuery ?? '(none)'} -> ?v=${v}`);
    }
    return want;
  });
  if (!check && next !== html) writeFileSync(page, next);
}

if (missing > 0) process.exit(1);
if (check && stale > 0) {
  console.error(`\n${stale} stale cache-bust stamp(s): run \`npm run stamp\` after \`npm run build\` and commit the pages.`);
  process.exit(1);
}
console.log(check ? 'cache-bust stamps up to date' : `cache-bust stamps written (${stale} changed)`);
