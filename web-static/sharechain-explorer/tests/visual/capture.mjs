// Pixel-regression capture: opens dashboard.html in both inline and
// bundled modes against the mock c2pool server, screenshots the
// shares-explorer section in each, and saves PNGs to tests/visual/out/.
//
// Uses puppeteer-core against the system-installed Chrome so we don't
// ship a ~100 MB browser download. Override CHROME_BIN to point at a
// different executable.
//
// Usage: node tests/visual/capture.mjs [port=18082]

import puppeteer from 'puppeteer-core';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, 'out');
mkdirSync(OUT, { recursive: true });

const PORT = Number(process.argv[2] ?? 18082);
const BASE = `http://127.0.0.1:${PORT}/dashboard.html`;

const CHROME_CANDIDATES = [
  process.env.CHROME_BIN,
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/snap/bin/chromium',
];
const executablePath = CHROME_CANDIDATES.find((p) => p && existsSync(p));
if (!executablePath) {
  console.error('no Chrome binary found — set CHROME_BIN');
  process.exit(2);
}

// Deterministic viewport so pixels are stable across runs.
const VIEWPORT = { width: 1280, height: 900, deviceScaleFactor: 1 };
const WAIT_AFTER_LOAD_MS = 3000;  // allow initial fetch + first paint

async function capture(mode, outfile) {
  const url = mode === 'bundled' ? `${BASE}?new-explorer=1&autoconnect=1` : BASE;
  const browser = await puppeteer.launch({
    executablePath,
    headless: true,
    defaultViewport: VIEWPORT,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--font-render-hinting=none',
      '--disable-features=TranslateUI,PaintHolding',
    ],
  });
  try {
    const page = await browser.newPage();
    // Suppress console errors from unused endpoints (Mock returns {} for
    // a handful of dashboards we don't care about.)
    page.on('pageerror', (err) => console.error(`[${mode}] pageerror`, err.message));
    // `load` rather than `networkidle0` — bundled mode opens a
    // persistent SSE connection that keeps "network" non-idle.
    await page.goto(url, { waitUntil: 'load', timeout: 15000 });
    await page.waitForSelector('#defrag-canvas', { timeout: 5000 });
    // Generous fixed delay lets both paths complete their initial
    // fetch + render. Deterministic against the mock server (no live
    // data, no SSE pushes).
    await new Promise((r) => setTimeout(r, WAIT_AFTER_LOAD_MS));
    // Screenshot only the share-grid canvas. Same fixture → same
    // cols/rows math → both paths produce an identically-sized canvas,
    // so pixelmatch can compare without cropping/resizing.
    const el = await page.$('#defrag-canvas');
    if (!el) throw new Error(`${mode}: #defrag-canvas not found`);
    await el.screenshot({ path: outfile, type: 'png' });
    console.log(`[${mode}] → ${outfile}`);
  } finally {
    await browser.close();
  }
}

await capture('inline',  join(OUT, 'inline.png'));
await capture('bundled', join(OUT, 'bundled.png'));
console.log('capture complete');
