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
  createHoverZoomPanel,
  computeGridLayout,
  cellAtPoint,
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
let hoverPanel = null;
let hoveredIdx = -1;

function stopStatsLoop() {
  if (statsTimer !== null) { clearInterval(statsTimer); statsTimer = null; }
}

function startStatsLoop() {
  stopStatsLoop();
  statsTimer = setInterval(() => {
    if (!rt) return;
    const s = rt.getState();
    const st = s.stats;
    const parts = [
      `${s.shareCount} shares`,
      s.window.tip ? `tip ${s.window.tip.slice(0, 12)}…` : null,
      st.chainLength !== null ? `chain ${st.chainLength}` : null,
      `v36 ${st.v36native}/${st.v36signaling}`,
      st.mine > 0 ? `mine ${st.mine}` : null,
      st.stale + st.dead > 0 ? `stale ${st.stale}·${st.dead}` : null,
      st.primaryBlocks + st.dogeBlocks > 0 ? `blocks ${st.primaryBlocks}·${st.dogeBlocks}` : null,
      s.animating ? 'animating' : null,
      s.hasQueued ? 'queued' : null,
      s.deltaInFlight ? 'fetching' : null,
    ].filter(Boolean);
    statsEl.textContent = parts.join(' — ');
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
      containerWidth:  () => wrap.clientWidth,
      containerHeight: () => wrap.clientHeight,
      minCellSize: 4,   // default maxCellSize (120) kicks in
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
    startHover();
    window.__explorer = rt;
  } catch (err) {
    setStatus('connection failed', 'err');
    log('error', String(err?.message ?? err));
  }
}

function startHover() {
  stopHover();
  hoverPanel = createHoverZoomPanel({ size: 240 });
  canvas.addEventListener('mousemove', onMouseMove);
  canvas.addEventListener('mouseleave', onMouseLeave);
}
function stopHover() {
  canvas.removeEventListener('mousemove', onMouseMove);
  canvas.removeEventListener('mouseleave', onMouseLeave);
  if (hoverPanel) { hoverPanel.destroy(); hoverPanel = null; }
  hoveredIdx = -1;
}
function onMouseMove(ev) {
  if (!rt || !hoverPanel) return;
  const state = rt.getState();
  const shares = state.window.shares;
  if (shares.length === 0) return;
  const layout = computeGridLayout({
    shareCount: shares.length,
    containerWidth: wrap.clientWidth,
    cellSize: 10,
    gap: 1,
    marginLeft: 38,
    minHeight: 40,
  });
  const rect = canvas.getBoundingClientRect();
  const x = ev.clientX - rect.left;
  const y = ev.clientY - rect.top;
  const idx = cellAtPoint(layout, x, y);
  if (idx === null) {
    if (hoveredIdx !== -1) { hoveredIdx = -1; hoverPanel.hide(); }
    return;
  }
  if (idx === hoveredIdx) return;
  hoveredIdx = idx;
  const share = shares[idx];
  if (!share) { hoverPanel.hide(); return; }
  const pplns = rt.getPPLNSForShare(share.h);
  const myAddr = addrInput.value.trim();
  hoverPanel.show(
    { h: share.h, m: share.m },
    pplns,
    ev.clientX, ev.clientY,
    myAddr ? { myAddress: myAddr } : undefined,
  );
}
function onMouseLeave() {
  if (hoveredIdx !== -1) { hoveredIdx = -1; hoverPanel && hoverPanel.hide(); }
}

async function disconnect() {
  if (rt !== null) {
    try { await rt.stop(); }
    catch (err) { log('warn', 'stop() failed', { msg: String(err?.message ?? err) }); }
    rt = null;
    window.__explorer = null;
  }
  stopStatsLoop();
  stopHover();
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
