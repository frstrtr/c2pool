// Diff two PNGs produced by capture.mjs. Writes a pixel-diff PNG and
// prints a summary with delta fraction. Exits non-zero if fraction
// exceeds the threshold (default 0.02 — 2% of pixels differ).
//
// Usage: node tests/visual/diff.mjs [threshold=0.02]

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PNG } from 'pngjs';
import pixelmatch from 'pixelmatch';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, 'out');

// Default 2.5% — relaxed from the original 0.5% after fractional-
// cellSize autoFit landed (`3a50a2ab`/`bbbf9ab7`). The two render
// paths (inline dashboard.html canvas vs bundled Explorer
// QtTransport) solve cellSize independently from container
// dimensions; when cellSize is fractional (e.g. 23.97 px) the two
// implementations accumulate sub-pixel rounding differently at
// each column boundary. Observed natural delta on explorer-module
// HEAD is ~1.66% — cell borders shifted by 1 px on the right half
// of the canvas, not a content regression. 2.5% cap catches real
// rendering drift (colour, shape, missing cells) while tolerating
// this known sub-pixel noise. Override via CLI arg or THRESHOLD env.
const threshold = Number(process.argv[2] ?? process.env.THRESHOLD ?? 0.025);

function loadPng(path) {
  const buf = readFileSync(path);
  return PNG.sync.read(buf);
}

const a = loadPng(join(OUT, 'inline.png'));
const b = loadPng(join(OUT, 'bundled.png'));

if (a.width !== b.width || a.height !== b.height) {
  console.error(
    `size mismatch: inline=${a.width}x${a.height} bundled=${b.width}x${b.height}`,
  );
  process.exit(2);
}

const diff = new PNG({ width: a.width, height: a.height });
const diffPixels = pixelmatch(
  a.data, b.data, diff.data,
  a.width, a.height,
  { threshold: 0.1, includeAA: false, alpha: 0.5, diffColor: [255, 0, 0] },
);
writeFileSync(join(OUT, 'diff.png'), PNG.sync.write(diff));

const totalPixels = a.width * a.height;
const delta = diffPixels / totalPixels;
const deltaPct = (delta * 100).toFixed(3);
const thrPct = (threshold * 100).toFixed(2);

console.log(`diff pixels: ${diffPixels} / ${totalPixels} (${deltaPct}%)`);
console.log(`threshold:   ${thrPct}%`);
console.log(`output:      ${join(OUT, 'diff.png')}`);

if (delta > threshold) {
  console.error(`FAIL — delta ${deltaPct}% exceeds threshold ${thrPct}%`);
  process.exit(1);
}
console.log(`OK — within threshold`);
