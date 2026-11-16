// Real-browser check + screenshots of the "Fluid (experimental)" share-chain
// grid (dashboard.html?explorer-anim=fluid) against the mock server
// (MOCK_PAYOUTS=1 so the PPLNS treemap is live for the bus link). Not a gate.
//
//   CHROME_BIN=… node tests/visual/capture-fluid.mjs
//
// Checks: the default page has no Fluid stage; with the flag the engine grid
// mounts in place of the Classic canvas; hovering a cell shows the Classic
// tooltip; pinning a miner in the treemap dims the other miners' cells.
// Writes out/fluid-grid.png and out/fluid-linked.png. Exits 1 on a failed check.

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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const portFile = join(OUT, 'fluid-mock.port');
rmSync(portFile, { force: true });
const server = spawn(process.execPath, [join(HERE, 'mock-server.mjs'), '0', portFile], {
  env: { ...process.env, MOCK_PAYOUTS: '1' }, stdio: 'ignore',
});
async function pageClip(page, handle, extraH = 0, maxH = 900) {
  return page.evaluate((el, extra, max) => {
    const r = el.getBoundingClientRect();
    return { x: r.left + window.scrollX, y: r.top + window.scrollY, width: r.width, height: Math.min(r.height + extra, max) };
  }, handle, extraH, maxH);
}

let failed = 0;
const check = (ok, label) => { console.log(`${ok ? 'PASS' : 'FAIL'} ${label}`); if (!ok) failed++; };
try {
  for (let i = 0; i < 120 && !existsSync(portFile); i++) await sleep(250);
  const port = readFileSync(portFile, 'utf8').trim();
  const browser = await puppeteer.launch({
    executablePath: chrome, headless: true,
    defaultViewport: { width: 1280, height: 1000, deviceScaleFactor: 1 },
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--font-render-hinting=none'],
  });
  try {
    // Default page: Classic only.
    const classic = await browser.newPage();
    await classic.goto(`http://127.0.0.1:${port}/dashboard.html`, { waitUntil: 'domcontentloaded' });
    await sleep(2500);
    check(await classic.evaluate(() => !document.getElementById('defrag-fluid')
      && getComputedStyle(document.getElementById('defrag-canvas')).display !== 'none'), 'default page: Classic canvas, no Fluid stage');
    await classic.close();

    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.goto(`http://127.0.0.1:${port}/dashboard.html?explorer-anim=fluid&pplns-view=1`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#defrag-fluid canvas', { timeout: 20000 });
    await sleep(2500);
    check(await page.evaluate(() => getComputedStyle(document.getElementById('defrag-canvas')).display === 'none'),
      'Fluid: engine grid mounted, Classic canvas hidden');
    check(await page.evaluate(() => getComputedStyle(document.getElementById('anim-fluid')).fontWeight === '700'),
      'Fluid: the Animation chip marks Fluid');
    const stage = await page.$('#defrag-fluid > div');
    await stage.scrollIntoView();
    await sleep(300);
    const box = await stage.boundingBox();
    await page.mouse.move(box.x + 60, box.y + 6);
    await sleep(400);
    check(await page.evaluate(() => {
      const t = document.querySelector('.defrag-tooltip, #defrag-tooltip');
      return !!t && getComputedStyle(t).display !== 'none';
    }), 'Fluid: hovering a cell shows the Classic tooltip');
    await page.screenshot({ path: join(OUT, 'fluid-grid.png'), clip: await pageClip(page, stage, 0, 520) });
    console.log('→ out/fluid-grid.png');
    // Pin the biggest treemap tile; the grid dims the other miners.
    await page.mouse.move(2, 2);
    const tm = await page.$('#pplns-main-grid .c2p-pplns-treemap > div:nth-child(2)');
    await tm.scrollIntoView();
    await sleep(300);
    const tb = await tm.boundingBox();
    await page.mouse.click(tb.x + 30, tb.y + 30);
    await page.mouse.move(2, 2);
    await stage.scrollIntoView();
    await sleep(800);
    check(await page.evaluate(() => window.c2pSelectionBus && window.c2pSelectionBus.get().pinned !== null),
      'treemap pin reaches the shared bus');
    await page.screenshot({ path: join(OUT, 'fluid-linked.png'), clip: await pageClip(page, stage, 0, 520) });
    console.log('→ out/fluid-linked.png');
    check(errors.length === 0, `no page errors${errors.length ? ': ' + errors.join(' | ') : ''}`);
  } finally {
    await browser.close();
  }
} finally {
  server.kill();
}
process.exit(failed > 0 ? 1 : 0);
