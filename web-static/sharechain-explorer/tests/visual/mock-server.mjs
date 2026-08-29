// Mock c2pool HTTP server for pixel-regression runs. Serves fixture
// JSON for the endpoints dashboard.html consumes (inline + bundled
// paths both hit the same URLs), plus dashboard.html itself and
// the bundle.
//
// Usage: node tests/visual/mock-server.mjs [port=18082]

import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { extname, join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../../../');            // c2pool repo root
const STATIC_ROOT = resolve(ROOT, 'web-static');
const FIXTURES = join(HERE, 'fixtures');
const PORT = Number(process.argv[2] ?? 18082);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.mjs':  'text/javascript; charset=utf-8',
  '.js':   'text/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map':  'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
};

function serveJson(res, payload, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(typeof payload === 'string' ? payload : JSON.stringify(payload));
}

function serveFile(res, absPath) {
  const ext = extname(absPath).toLowerCase();
  res.writeHead(200, { 'Content-Type': MIME[ext] ?? 'application/octet-stream' });
  res.end(readFileSync(absPath));
}

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  let path = url.pathname;
  if (path.endsWith('/')) path += 'index.html';

  // ── Mocked c2pool endpoints ────────────────────────────────────
  if (path === '/sharechain/window') {
    const raw = readFileSync(join(FIXTURES, 'window.json'), 'utf8');
    return serveJson(res, raw);
  }
  if (path === '/sharechain/tip') {
    const raw = readFileSync(join(FIXTURES, 'tip.json'), 'utf8');
    return serveJson(res, raw);
  }
  if (path === '/sharechain/stats') {
    const raw = readFileSync(join(FIXTURES, 'stats.json'), 'utf8');
    return serveJson(res, raw);
  }
  if (path === '/sharechain/delta') {
    // Empty delta — fixture is static
    return serveJson(res, { shares: [], count: 0, tip: '', chain_length: 8650, window_size: 200 });
  }
  if (path === '/current_merged_payouts') {
    const raw = readFileSync(join(FIXTURES, 'merged_payouts.json'), 'utf8');
    return serveJson(res, raw);
  }
  if (path === '/sharechain/stream') {
    // Minimal SSE: hello + keep-alive only. No tips fired = no animation
    // churn during the screenshot window.
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.write('data: {"connected": true}\n\n');
    const keepAlive = setInterval(() => res.write(': keep-alive\n\n'), 15000);
    req.on('close', () => { clearInterval(keepAlive); try { res.end(); } catch {} });
    return;
  }

  // Other endpoints dashboard.html may call — return empty/reasonable
  // defaults so loads don't error out and distort the screenshots.
  if (
    path === '/uptime' ||
    path === '/rate' ||
    path === '/peers' ||
    path === '/stratum_stats' ||
    path === '/current_payouts' ||
    path === '/version' ||
    path === '/peer_counts' ||
    path === '/merged_peers' ||
    path === '/api/negotiate'
  ) {
    return serveJson(res, path === '/api/negotiate' ? { apiVersion: '1.0' } : {});
  }

  // ── Static files ───────────────────────────────────────────────
  let filePath = path.startsWith('/web-static/')
    ? join(ROOT, path)
    : join(STATIC_ROOT, path);
  if (!existsSync(filePath)) {
    filePath = join(STATIC_ROOT, path.replace(/^\//, ''));
  }
  if (existsSync(filePath) && !filePath.includes('..')) {
    return serveFile(res, filePath);
  }

  res.writeHead(404);
  res.end('not found: ' + path);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`mock c2pool listening on http://127.0.0.1:${PORT}`);
});
