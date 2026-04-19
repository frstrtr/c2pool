import * as esbuild from 'esbuild';
import { mkdirSync } from 'node:fs';

const isDev = process.argv.includes('--dev');

mkdirSync('dist', { recursive: true });

const common = {
  entryPoints: ['src/index.ts'],
  bundle: true,
  format: 'esm',
  target: 'es2020',
  platform: 'browser',
  logLevel: 'info',
};

await esbuild.build({
  ...common,
  outfile: 'dist/shared-core.js',
  minify: !isDev,
  sourcemap: isDev ? 'inline' : 'linked',
  metafile: true,
});

console.log(`Built dist/shared-core.js (${isDev ? 'dev' : 'production'})`);
