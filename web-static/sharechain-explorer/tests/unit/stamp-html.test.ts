// Cache-bust stamps (scripts/stamp-html.mjs): every HTTP-served page or
// loader reference to one of this package's scripts carries ?v=<hash of
// the target>, and the committed stamps match the files on disk.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const read = (p: string): string => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8');

test('stamp-html --check passes on the committed tree', () => {
  const out = execFileSync(process.execPath, ['scripts/stamp-html.mjs', '--check'], { cwd: root, encoding: 'utf8' });
  assert.match(out, /cache-bust stamps up to date/);
});

test('every package script load in the served pages and loaders is stamped', () => {
  const files: Record<string, RegExp[]> = {
    '../dashboard.html': [
      /src="sharechain-explorer\/dist\/layout\.js\?v=[0-9a-f]{8}"/,
      /import\('\.\/sharechain-explorer\/dist\/sharechain-explorer\.js\?v=[0-9a-f]{8}'\)/,
    ],
    '../share.html': [/src="sharechain-explorer\/dist\/layout\.js\?v=[0-9a-f]{8}"/],
    'dashboard-bundled.html': [/src="\.\/dashboard-bundled\.mjs\?v=[0-9a-f]{8}"/],
    'dashboard-bundled.mjs': [/from '\.\/dist\/sharechain-explorer\.js\?v=[0-9a-f]{8}'/],
  };
  for (const [file, patterns] of Object.entries(files)) {
    const text = read(file);
    for (const p of patterns) assert.match(text, p, `${file} ${p}`);
    // No unstamped reference into dist/ or to a local .mjs remains.
    assert.doesNotMatch(text, /(src="|import\(\s*['"]|from\s+['"])[^'"?]*(dist\/[A-Za-z0-9_.-]+\.js|\.mjs)['"]/,
      `${file} has an unstamped package script load`);
  }
});
