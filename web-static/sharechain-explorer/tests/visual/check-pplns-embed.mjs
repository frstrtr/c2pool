// Real-browser check of the Qt PPLNS embed page (pplns-embed.html) without
// Qt: a fake QWebChannel exposes `pplns` / `sharechain` bridge objects
// backed by the mock server (MOCK_PAYOUTS=1). Not a CI gate.
//
//   CHROME_BIN=… node tests/visual/check-pplns-embed.mjs
//
// Checks the three boot paths and writes out/pplns-embed.png:
//   1. new binary (bridge has getPayouts…)  → scene-engine treemap
//   2. older binary (no getPayouts)         → classic PplnsView
//   3. ?legacy=1                            → classic PplnsView
// Exits 1 if any path boots the wrong view.

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
const portFile = join(OUT, 'embed-mock.port');
rmSync(portFile, { force: true });
const server = spawn(process.execPath, [join(HERE, 'mock-server.mjs'), '0', portFile], {
  env: { ...process.env, MOCK_PAYOUTS: '1' }, stdio: 'ignore',
});

/** Installed before the page runs: a QWebChannel whose bridge objects
 *  answer like PplnsBridge / SharechainBridge, via fetch to the mock. */
function fakeChannel(newBinary) {
  const signal = () => {
    const fns = new Set();
    return { connect: (f) => fns.add(f), disconnect: (f) => fns.delete(f), emit: (...a) => fns.forEach((f) => f(...a)) };
  };
  const pplns = { responseReady: signal(), responseFailed: signal(), calls: [] };
  const route = (path) => (id) => {
    pplns.calls.push(path);
    fetch(path).then((r) => r.json()).then(
      (j) => pplns.responseReady.emit(id, Array.isArray(j) ? { data: j } : j),
      (e) => pplns.responseFailed.emit(id, { type: 'transport', message: String(e) }));
  };
  pplns.getCurrentPayouts = route('/pplns/current');
  pplns.getMinerDetail = (id) => pplns.responseFailed.emit(id, { type: 'transport', message: 'n/a' });
  pplns.cancelRequest = () => {};
  if (newBinary) {
    pplns.getPayouts = route('/current_payouts');
    pplns.getMergedPayouts = route('/current_merged_payouts');
    pplns.getStratumStats = route('/stratum_stats');
  }
  const sharechain = { tipChanged: signal(), tipReconnected: signal(), startStream: () => {} };
  window.__fakePplns = pplns;
  window.qt = { webChannelTransport: {} };
  window.QWebChannel = function QWebChannel(_t, cb) { setTimeout(() => cb({ objects: { pplns, sharechain } }), 0); };
}

let failed = 0;
try {
  for (let i = 0; i < 120 && !existsSync(portFile); i++) await sleep(250);
  const port = readFileSync(portFile, 'utf8').trim();
  const browser = await puppeteer.launch({
    executablePath: chrome, headless: true,
    defaultViewport: { width: 1000, height: 640, deviceScaleFactor: 1 },
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--font-render-hinting=none'],
  });
  try {
    const run = async (label, newBinary, query, wantScene, shot) => {
      const page = await browser.newPage();
      const errors = [];
      page.on('pageerror', (e) => errors.push(e.message));
      await page.evaluateOnNewDocument(fakeChannel, newBinary);
      await page.goto(`http://127.0.0.1:${port}/sharechain-explorer/pplns-embed.html${query}`, { waitUntil: 'domcontentloaded' });
      await sleep(2500);
      const r = await page.evaluate(() => ({
        scene: !!document.querySelector('#tree .c2p-pplns-treemap canvas'),
        treeChildren: document.getElementById('tree').children.length,
        status: document.getElementById('status').textContent,
        calls: window.__fakePplns.calls,
      }));
      const okView = wantScene ? r.scene : (!r.scene && r.treeChildren > 0);
      console.log(`${okView ? 'PASS' : 'FAIL'} ${label}: scene=${r.scene} children=${r.treeChildren} status="${r.status}" calls=${[...new Set(r.calls)].join(',')}${errors.length ? ` errors=${errors.join(' | ')}` : ''}`);
      if (!okView) failed++;
      if (shot) await page.screenshot({ path: join(OUT, 'pplns-embed.png') });
      await page.close();
    };
    await run('new binary → scene treemap', true, '?coin=LTC', true, true);
    await run('older binary (no getPayouts) → classic view', false, '?coin=LTC', false, false);
    await run('?legacy=1 → classic view', true, '?coin=LTC&legacy=1', false, false);
  } finally {
    await browser.close();
  }
} finally {
  server.kill();
}
process.exit(failed > 0 ? 1 : 0);
