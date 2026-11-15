// Screenshots of the interactive PPLNS treemap (dashboard.html?pplns-view=1)
// against the mock server, for PR bodies and manual review. Not a gate.
//
//   CHROME_BIN=… node tests/visual/capture-pplns.mjs
//
// Writes tests/visual/out/pplns-view.png (hover + tooltip) and
// tests/visual/out/pplns-linked.png (a pinned miner: the treemap outlines
// it, the share-chain grid dims everyone else).

import puppeteer from 'puppeteer-core';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, 'out');
mkdirSync(OUT, { recursive: true });

const chrome = [process.env.CHROME_BIN, '/usr/bin/google-chrome', '/usr/bin/chromium'].find((p) => p && existsSync(p));
if (!chrome) { console.error('no Chrome binary found — set CHROME_BIN'); process.exit(2); }

const portFile = join(OUT, 'pplns-mock.port');
rmSync(portFile, { force: true });
const server = spawn(process.execPath, [join(HERE, 'mock-server.mjs'), '0', portFile], {
  env: { ...process.env, MOCK_PAYOUTS: '1' }, stdio: 'ignore',
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** Page-coordinate clip of an element (boundingBox() is viewport-relative). */
async function pageClip(page, handle, extraH = 0, maxH = 900) {
  return page.evaluate((el, extra, max) => {
    const r = el.getBoundingClientRect();
    return { x: r.left + window.scrollX, y: r.top + window.scrollY, width: r.width, height: Math.min(r.height + extra, max) };
  }, handle, extraH, maxH);
}
try {
  for (let i = 0; i < 120 && !existsSync(portFile); i++) await sleep(250);
  const port = readFileSync(portFile, 'utf8').trim();
  const browser = await puppeteer.launch({
    executablePath: chrome, headless: true,
    defaultViewport: { width: 1280, height: 1000, deviceScaleFactor: 1 },
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--font-render-hinting=none'],
  });
  try {
    const page = await browser.newPage();
    page.on('pageerror', (e) => console.error('pageerror', e.message));
    await page.goto(`http://127.0.0.1:${port}/dashboard.html?pplns-view=1`, { waitUntil: 'domcontentloaded', timeout: 45000 });
    await page.waitForSelector('#pplns-main-grid .c2p-pplns-treemap canvas', { timeout: 20000 });
    await sleep(2500);  // fetches + the enter tween
    const card = await page.evaluateHandle(() => document.getElementById('pplns-main-grid').closest('.card') || document.getElementById('pplns-main-grid').parentElement);
    const grid = await page.$('#defrag-canvas');
    // 1. The share-chain grid as it is, nothing hovered or pinned.
    await page.mouse.move(2, 2);
    await grid.scrollIntoView();
    await sleep(300);
    await page.screenshot({ path: join(OUT, 'pplns-grid-before.png'), clip: await pageClip(page, grid, 0, 500) });
    console.log('→ out/pplns-grid-before.png');
    // 2. Hover a tile right of the biggest one: tooltip + highlight.
    await card.scrollIntoView();
    await sleep(300);
    const stage = await page.$('#pplns-main-grid .c2p-pplns-treemap > div:nth-child(2)');
    const box = await stage.boundingBox();
    const at = { x: box.x + box.width * 0.75, y: box.y + box.height * 0.3 };
    await page.mouse.move(at.x, at.y);
    await sleep(400);
    await page.screenshot({ path: join(OUT, 'pplns-view.png'), clip: await pageClip(page, card, 160) });
    console.log('→ out/pplns-view.png');
    // 3. Pin it and leave: the grid keeps that miner's shares, dims the rest.
    await page.mouse.click(at.x, at.y);
    await page.mouse.move(2, 2);
    await grid.scrollIntoView();
    await sleep(600);
    await page.screenshot({ path: join(OUT, 'pplns-linked.png'), clip: await pageClip(page, grid, 0, 500) });
    console.log('→ out/pplns-linked.png');
  } finally {
    await browser.close();
  }
} finally {
  server.kill();
}
