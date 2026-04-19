// Bundle-mode driver — connects the extracted Explorer to a live
// c2pool server via HttpTransport. Tracks connection state, surfaces
// structured ExplorerError via onError to the on-page log, and
// exposes the live controller on window.__explorer for devtools.
//
// URL params accepted (all optional):
//   ?base=http://host:port   — override base URL (else localStorage)
//   ?addr=XMineAddress        — override my-address for "mine" colouring
//   ?autoconnect=0            — skip auto-connect on load
//   ?fast=1                   — enable fast animation mode

import {
  createHttpTransport,
  createRealtime,
} from './dist/sharechain-explorer.js';

const params   = new URL(location.href).searchParams;
const qsBase   = params.get('base');
const qsAddr   = params.get('addr');
const qsAuto   = params.get('autoconnect');
const qsFast   = params.get('fast') === '1';

const canvas    = /** @type {HTMLCanvasElement} */ (document.getElementById('grid'));
const wrap      = document.getElementById('grid-wrap');
const baseInput = /** @type {HTMLInputElement} */ (document.getElementById('base-url'));
const addrInput = /** @type {HTMLInputElement} */ (document.getElementById('my-address'));
const connectBtn    = document.getElementById('connect');
const disconnectBtn = document.getElementById('disconnect');
const refreshBtn    = document.getElementById('refresh');
const statusEl      = document.getElementById('status');
const statsEl       = document.getElementById('stats');
const logEl         = document.getElementById('log');

// ── Persisted prefs ─────────────────────────────────────────────
const STORAGE = 'c2p-bundled-prefs';
function loadPrefs() {
  try { return JSON.parse(localStorage.getItem(STORAGE) ?? '{}'); }
  catch { return {}; }
}
function savePrefs(prefs) {
  try { localStorage.setItem(STORAGE, JSON.stringify(prefs)); }
  catch { /* private mode etc. */ }
}

const prefs = loadPrefs();
baseInput.value = qsBase ?? prefs.base ?? 'http://127.0.0.1:8080';
addrInput.value = qsAddr ?? prefs.myAddress ?? '';

// ── Logging ─────────────────────────────────────────────────────
function log(level, msg, ctx) {
  const stamp = new Date().toISOString().split('T')[1].slice(0, 8);
  const line = `[${stamp}] ${level.padEnd(5)} ${msg}` +
               (ctx !== undefined ? '  ' + JSON.stringify(ctx) : '');
  logEl.textContent = (line + '\n' + logEl.textContent).slice(0, 8000);
}

function setStatus(label, kind = '') {
  statusEl.textContent = label;
  statusEl.className = 'status ' + kind;
}

// ── Connection state ────────────────────────────────────────────
let rt = null;
let statsTimer = null;

function stopStatsLoop() {
  if (statsTimer !== null) { clearInterval(statsTimer); statsTimer = null; }
}

function startStatsLoop() {
  stopStatsLoop();
  statsTimer = setInterval(() => {
    if (!rt) return;
    const s = rt.getState();
    statsEl.textContent =
      `${s.shareCount} shares` +
      (s.window.tip ? ` — tip ${s.window.tip.slice(0, 12)}…` : '') +
      (s.animating ? ' — animating' : '') +
      (s.hasQueued ? ' (queued)' : '') +
      (s.deltaInFlight ? ' — fetching' : '');
  }, 250);
}

async function connect() {
  await disconnect();
  const baseUrl = baseInput.value.trim();
  const myAddress = addrInput.value.trim();
  if (!baseUrl) {
    setStatus('needs base URL', 'err');
    return;
  }
  savePrefs({ base: baseUrl, myAddress });

  setStatus('connecting...', 'warn');
  log('info', 'connecting', { baseUrl, fast: qsFast });

  try {
    const transport = createHttpTransport({ baseUrl });
    rt = createRealtime({
      canvas,
      transport,
      userContext: { myAddress: myAddress || undefined, shareVersion: 36 },
      containerWidth: () => wrap.clientWidth,
      fastAnimation: qsFast,
      onError: (err) => {
        setStatus('error', 'err');
        log('error', err.message, {
          type: err.type,
          ...('status' in err ? { status: err.status } : {}),
        });
      },
    });
    await rt.start();
    setStatus('connected', 'ok');
    log('info', 'connected');
    startStatsLoop();
    window.__explorer = rt;
  } catch (err) {
    setStatus('connection failed', 'err');
    log('error', String(err?.message ?? err));
  }
}

async function disconnect() {
  if (rt !== null) {
    try { await rt.stop(); }
    catch (err) { log('warn', 'stop() failed', { msg: String(err?.message ?? err) }); }
    rt = null;
    window.__explorer = null;
  }
  stopStatsLoop();
  setStatus('idle');
  statsEl.textContent = '';
}

async function refresh() {
  if (rt === null) return;
  setStatus('refreshing...', 'warn');
  try {
    await rt.refresh();
    setStatus('connected', 'ok');
    log('info', 'refresh complete');
  } catch (err) {
    setStatus('refresh failed', 'err');
    log('error', String(err?.message ?? err));
  }
}

// ── Wire controls + autoconnect ─────────────────────────────────
connectBtn.addEventListener('click', () => { void connect(); });
disconnectBtn.addEventListener('click', () => { void disconnect(); });
refreshBtn.addEventListener('click', () => { void refresh(); });

window.addEventListener('beforeunload', () => { void disconnect(); });

if (qsAuto !== '0') {
  void connect();
}
