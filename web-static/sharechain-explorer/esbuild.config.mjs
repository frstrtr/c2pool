import * as esbuild from 'esbuild';
import { mkdirSync } from 'node:fs';

const isDev = process.argv.includes('--dev');

mkdirSync('dist', { recursive: true });

const common = {
  bundle: true,
  format: 'esm',
  target: 'es2020',
  platform: 'browser',
  logLevel: 'info',
  minify: !isDev,
  sourcemap: isDev ? 'inline' : 'linked',
  metafile: true,
};

/** Bundles we emit. Each corresponds to a size.config.json budget.
 *  Keep self-contained (shared-core vendored into each host) so a page
 *  only loads one <script src> per surface; externalization is a
 *  post-phase-2 optimisation. */
const entries = [
  { entryPoints: ['src/index.ts'],          outfile: 'dist/shared-core.js' },
  { entryPoints: ['src/explorer/index.ts'], outfile: 'dist/sharechain-explorer.js' },
  { entryPoints: ['src/pplns/index.ts'],    outfile: 'dist/pplns-view.js' },
];

for (const e of entries) {
  await esbuild.build({ ...common, ...e });
  console.log(`Built ${e.outfile} (${isDev ? 'dev' : 'production'})`);
}

/** Classic-script bundle for the inline pages (dashboard.html,
 *  share.html): an IIFE that defines the global `C2PLayout`, loaded with
 *  a plain <script src> so the pages call it synchronously. */
await esbuild.build({
  ...common,
  format: 'iife',
  globalName: 'C2PLayout',
  entryPoints: ['src/layout-global.ts'],
  outfile: 'dist/layout.js',
});
console.log(`Built dist/layout.js (${isDev ? 'dev' : 'production'})`);
