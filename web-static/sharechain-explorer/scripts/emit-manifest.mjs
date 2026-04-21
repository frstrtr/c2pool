// Emits web-static/sharechain-explorer/resources-manifest.json
// describing every shipping bundle file. Consumed by:
//   - the c2pool HTTP server (preload hints, SRI)
//   - c2pool-qt CMake (.qrc file list — M1 D11)
// Run after `npm run build`.

import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { createHash } from 'node:crypto';

const ROOT = new URL('..', import.meta.url).pathname;
const DIST = join(ROOT, 'dist');
const OUT  = join(ROOT, 'resources-manifest.json');

const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));

function walk(dir, acc = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const s = statSync(full);
    if (s.isDirectory()) walk(full, acc);
    else acc.push(full);
  }
  return acc;
}

function sha384(path) {
  const buf = readFileSync(path);
  return 'sha384-' + createHash('sha384').update(buf).digest('base64');
}

const all = walk(DIST).map((abs) => {
  const rel = relative(DIST, abs).split(sep).join('/');
  return { path: rel, bytes: statSync(abs).size, integrity: sha384(abs) };
});

const files    = all.filter((f) => !f.path.endsWith('.map')).map((f) => f.path);
const filesDev = all.filter((f) => f.path.endsWith('.map')).map((f) => f.path);
const integrity = Object.fromEntries(all.map((f) => [f.path, f.integrity]));
const sizes     = Object.fromEntries(all.map((f) => [f.path, f.bytes]));

const manifest = {
  version: pkg.version,
  generated: new Date().toISOString(),
  files,
  filesDev,
  integrity,
  sizes,
};

writeFileSync(OUT, JSON.stringify(manifest, null, 2) + '\n');
console.log(`manifest written: ${files.length} files + ${filesDev.length} dev files`);
console.log(`total size: ${files.reduce((a, p) => a + (sizes[p] ?? 0), 0)} bytes`);
