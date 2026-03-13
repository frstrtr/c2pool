# c2pool Dashboard Integration Guide

> Build custom dashboards for c2pool using the HTTP API.
> Fully compatible with the p2pool dashboard lineage:
> **p2pool/p2pool → jtoomim/p2pool → frstrtr/p2pool-merged-v36 → frstrtr/c2pool**

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Architecture Overview](#architecture-overview)
3. [Serving Your Dashboard](#serving-your-dashboard)
4. [API Reference — Native c2pool](#api-reference--native-c2pool)
5. [API Reference — p2pool Legacy Compatibility](#api-reference--p2pool-legacy-compatibility)
6. [API Reference — JSON-RPC Methods](#api-reference--json-rpc-methods)
7. [JavaScript SDK — c2pool.js](#javascript-sdk--c2pooljs)
8. [Building a Custom Dashboard](#building-a-custom-dashboard)
9. [Migrating from p2pool Dashboards](#migrating-from-p2pool-dashboards)
10. [Theming and Branding](#theming-and-branding)
11. [Security Considerations](#security-considerations)
12. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# 1. Start c2pool with dashboard enabled (default: web-static/)
./c2pool --integrated --net litecoin --web-port 8080 ...

# 2. Open your browser
xdg-open http://localhost:8080/

# 3. Point to a custom dashboard directory
./c2pool --dashboard-dir /path/to/my-dashboard ...
```

The built-in dashboard is served from the `web-static/` directory. Replace or
extend it by passing `--dashboard-dir` to point at any folder of static HTML,
CSS, and JavaScript files.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   c2pool daemon                      │
│                                                     │
│   ┌──────────────┐    ┌──────────────────────────┐  │
│   │ Stratum TCP  │    │   HTTP Server (Boost.Beast)│ │
│   │  port 9327   │    │      port 8080            │  │
│   └──────────────┘    │                            │  │
│                       │  ┌─── API routes ────────┐ │  │
│                       │  │ /local_rate            │ │  │
│                       │  │ /global_rate           │ │  │
│                       │  │ /current_payouts       │ │  │
│                       │  │ /local_stats  (legacy) │ │  │
│                       │  │ /web/version  (legacy) │ │  │
│                       │  │ ...                    │ │  │
│                       │  └────────────────────────┘ │  │
│                       │                            │  │
│                       │  ┌─── Static files ──────┐ │  │
│                       │  │ web-static/index.html  │ │  │
│                       │  │ web-static/style.css   │ │  │
│                       │  │ web-static/*.js         │ │  │
│                       │  │ (any custom dashboard) │ │  │
│                       │  └────────────────────────┘ │  │
│                       └──────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

**Request routing priority:**
1. Known API endpoints (`/local_rate`, `/global_rate`, etc.) — always
2. p2pool legacy endpoints (`/local_stats`, `/web/version`, etc.) — always
3. Static file from `--dashboard-dir` (default `web-static/`) — if file exists
4. Fallback → `getinfo` JSON response

API endpoints **always take priority** over static files, so you cannot
accidentally shadow an endpoint with a file.

---

## Serving Your Dashboard

### Built-in serving (recommended)

Place your HTML/CSS/JS files in a directory and pass it to c2pool:

```bash
./c2pool --dashboard-dir ./my-dashboard --web-port 8080 ...
```

- `/` → serves `index.html`
- Any path → looks up the corresponding file in the directory
- CORS headers are set on every response (configurable via `--cors-origin`)
- Static files are cached for 1 hour (`Cache-Control: public, max-age=3600`)

**Supported MIME types:**

| Extension | Content-Type |
|-----------|-------------|
| `.html` | `text/html; charset=utf-8` |
| `.js` | `application/javascript; charset=utf-8` |
| `.css` | `text/css; charset=utf-8` |
| `.json` | `application/json; charset=utf-8` |
| `.ico` | `image/x-icon` |
| `.png` | `image/png` |
| `.svg` | `image/svg+xml` |
| `.woff2` | `font/woff2` |
| `.woff` | `font/woff` |
| `.txt` | `text/plain; charset=utf-8` |

### External web server (alternative)

Run your dashboard on a separate web server (nginx, Caddy, etc.)
and configure CORS to allow requests to c2pool's API:

```bash
./c2pool --cors-origin "https://my-dashboard.example.com" --web-port 8080 ...
```

```javascript
// In your dashboard JavaScript:
const API_BASE = "http://pool-server:8080";
fetch(API_BASE + "/local_rate").then(r => r.json()).then(console.log);
```

### YAML configuration

```yaml
# config/c2pool.yaml
dashboard_dir: /opt/dashboards/custom
cors_origin: "*"
http_port: 8080
http_host: 0.0.0.0
```

---

## API Reference — Native c2pool

All native endpoints return JSON. All support CORS.

### GET `/local_rate`

Pool hashrate in H/s (from the sharechain tracker).

**Response:** `12345678.9` (bare number)

### GET `/global_rate`

Network hashrate in H/s (from the last block template).

**Response:** `987654321000.0` (bare number)

### GET `/current_payouts`

PPLNS expected payouts if a block were found now. Keys are hex-encoded
output scripts; values are satoshis.

**Response:**
```json
{
  "76a914...88ac": 625000000,
  "76a914...88ac": 312500000
}
```

### GET `/users`

Number of active miners (unique payout addresses in the PPLNS window).

**Response:** `42` (bare number)

### GET `/fee`

Pool operator fee as a percentage.

**Response:** `1.0` (bare number)

### GET `/recent_blocks`

Last 100 blocks found by the pool.

**Response:**
```json
[
  {"height": 2500000, "hash": "00000000...", "ts": 1741875600},
  ...
]
```

### GET `/uptime`

Daemon uptime in seconds.

**Response:** `86400` (bare number)

### GET `/connected_miners`

```json
{
  "total_connected": 5,
  "active_workers": 5,
  "stale_count": 0
}
```

### GET `/stratum_stats`

Stratum protocol metrics.

```json
{
  "difficulty": 1.0,
  "accepted_shares": 0,
  "rejected_shares": 0,
  "stale_shares": 0,
  "hashrate": 0.0,
  "active_workers": 0,
  "unique_addresses": 0,
  "shares_per_minute": 0.0,
  "mining_enabled": true,
  "banned_count": 0
}
```

### GET `/global_stats`

Comprehensive pool statistics.

```json
{
  "pool_hashrate": 0.0,
  "network_hashrate": 0.0,
  "pool_stale_ratio": 0.0,
  "shares_in_chain": 0,
  "unique_miners": 0,
  "current_height": 0,
  "uptime_seconds": 86400,
  "status": "operational",
  "last_block": 0
}
```

### GET `/sharechain/stats`

Live tracker data — shares by version, miner distribution, timeline.

```json
{
  "total_shares": 15000,
  "shares_by_version": {"36": 15000},
  "shares_by_miner": {"tltc1q...": 1234, "tltc1q...": 567},
  "chain_height": 15000,
  "chain_tip_hash": "abcd1234...",
  "fork_count": 0,
  "average_difficulty": 1.0,
  "timeline": [
    {"timestamp": 1741875600, "share_count": 10, "miner_distribution": {...}}
  ]
}
```

### GET `/sharechain/window`

Per-share grid data (last 2000 shares in the PPLNS window).

```json
{
  "shares": [
    {"hash": "...", "miner": "...", "version": 36, ...}
  ],
  "total": 2000,
  "best_hash": "...",
  "chain_length": 2000
}
```

### GET `/web/log`

Last 500 lines of `debug.log` as plain text.

**Content-Type:** `text/plain`

### GET `/logs/export`

Filtered log export. Parameters:

| Param | Values | Default |
|-------|--------|---------|
| `scope` | all, stratum, p2p, web | all |
| `from` | Unix timestamp | 0 |
| `to` | Unix timestamp | now |
| `format` | csv, jsonl, plain | plain |

Example: `/logs/export?scope=stratum&from=1741875600&format=csv`

### Control Endpoints

| Path | Action |
|------|--------|
| `/control/mining/start` | Resume mining |
| `/control/mining/stop` | Pause mining |
| `/control/mining/restart` | Restart mining |
| `/control/mining/ban?target=X` | Ban address/IP |
| `/control/mining/unban?target=X` | Unban |

---

## API Reference — p2pool Legacy Compatibility

These endpoints reproduce the **exact JSON shape** that the original
p2pool/p2pool (Forrest Voight) and jtoomim/p2pool dashboards expect.
Community dashboards that were built for the classic p2pool lineage
(e.g. p2pool-node-status, bitcoin-p2pool-dashboard) can consume
these without modification.

### GET `/local_stats`

Main data source for the original p2pool `index.html`.

```json
{
  "peers": {"incoming": 0, "outgoing": 3},
  "miner_hash_rates": {"tltc1q...": 12345678.9},
  "miner_dead_hash_rates": {},
  "shares": {"total": 15000, "orphan": 0, "dead": 0},
  "efficiency": null,
  "uptime": 86400,
  "block_value": 12.5,
  "warnings": [],
  "donation_proportion": 0.01,
  "attempts_to_share": 0,
  "attempts_to_block": 0
}
```

### GET `/p2pool_global_stats`

p2pool-format global stats (separate from the c2pool `/global_stats`
which has a different shape).

```json
{
  "pool_hash_rate": 12345678.9,
  "pool_stale_prop": 0.0,
  "min_difficulty": 1.0
}
```

### GET `/web/version`

Version string.

**Response:** `"c2pool/0.8.0"`

### GET `/web/currency_info`

Blockchain explorer URLs and currency symbol. Used by the original
p2pool dashboard to construct hyperlinks.

```json
{
  "symbol": "LTC",
  "address_explorer_url_prefix": "https://litecoinspace.org/address/",
  "block_explorer_url_prefix": "https://litecoinspace.org/block/",
  "tx_explorer_url_prefix": "https://litecoinspace.org/tx/"
}
```

### GET `/payout_addr`

Primary payout address (from `--address` CLI flag).

**Response:** `"tltc1q..."`

### GET `/payout_addrs`

Array of all payout addresses.

**Response:** `["tltc1q..."]`

### GET `/web/best_share_hash`

Hash of the sharechain tip (best share).

**Response:** `"abcd1234..."`

### Endpoints NOT implemented (yet)

The following p2pool-era endpoints require time-series data collection
infrastructure that is not yet implemented in c2pool. They return
empty arrays or null:

| Endpoint | Status |
|----------|--------|
| `/web/graph_data/*` | Not implemented (empty) |
| `/web/share/<hash>` | Not implemented |
| `/web/verified_heads` | Not implemented |
| `/web/verified_tails` | Not implemented |
| `/web/heads` | Not implemented |
| `/web/tails` | Not implemented |
| `/web/my_share_hashes` | Not implemented |

Contributions welcome — these would require adding a `GraphDataCollector`
that samples time-series data every few seconds and stores the last
Hour/Day/Week/Month/Year of data points.

---

## API Reference — JSON-RPC Methods

All JSON-RPC methods are available via POST to the same HTTP port.

```bash
curl -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"getinfo","params":[]}' \
    http://localhost:8080/
```

| Method | Parameters | Description |
|--------|-----------|-------------|
| `getinfo` | — | Pool status and configuration |
| `getstats` | — | Detailed pool statistics |
| `getpeerinfo` | — | Connected P2P peers |
| `getpayoutinfo` | — | PPLNS payout statistics |
| `getminerstats` | — | Per-miner stats |
| `getblocktemplate` | `[params]` | Block template (GBT protocol) |
| `submitblock` | `["hex"]` | Submit a block |
| `validate_address` | `["addr"]` | Validate a payout address |
| `getblockcandidate` | `{params}` | Block with full payout distribution |
| `setmessageblob` | `["hex"]` | Set V36 authority message blob |
| `getmessageblob` | — | Get current message blob |
| `mining.subscribe` | `["user_agent"]` | Stratum subscribe (HTTP) |
| `mining.authorize` | `["user","pass"]` | Stratum authorize (HTTP) |
| `mining.submit` | `[user,job,en2,ntime,nonce]` | Submit share (HTTP) |

---

## JavaScript SDK — c2pool.js

The bundled `c2pool.js` provides a `C2PoolAPI` object with methods for
every endpoint plus helper functions.

### Usage

```html
<script src="c2pool.js"></script>
<script>
    // Fetch all data in one call
    const data = await C2PoolAPI.fetchAll();
    console.log(data.localRate);      // 12345678.9
    console.log(data.recentBlocks);   // [{height, hash, ts}, ...]

    // Individual endpoints
    const rate = await C2PoolAPI.localRate();
    const pays = await C2PoolAPI.payouts();

    // p2pool legacy
    const ls = await C2PoolAPI.localStats();

    // Helper functions
    C2PoolAPI.formatHashrate(123456789);  // "123.46 MH/s"
    C2PoolAPI.formatDuration(86400);      // "1d 0h"
    C2PoolAPI.formatCoins(625000000);     // "6.25000000"
</script>
```

### API methods

| Method | Returns | Endpoint |
|--------|---------|----------|
| `localRate()` | number | `/local_rate` |
| `globalRate()` | number | `/global_rate` |
| `payouts()` | object | `/current_payouts` |
| `users()` | number | `/users` |
| `fee()` | number | `/fee` |
| `recentBlocks()` | array | `/recent_blocks` |
| `uptime()` | number | `/uptime` |
| `miners()` | object | `/connected_miners` |
| `stratumStats()` | object | `/stratum_stats` |
| `globalStats()` | object | `/global_stats` |
| `sharechainStats()` | object | `/sharechain/stats` |
| `sharechainWindow()` | object | `/sharechain/window` |
| `webLog()` | string | `/web/log` |
| `localStats()` | object | `/local_stats` |
| `p2poolGlobalStats()` | object | `/p2pool_global_stats` |
| `version()` | string | `/web/version` |
| `currencyInfo()` | object | `/web/currency_info` |
| `payoutAddr()` | string | `/payout_addr` |
| `payoutAddrs()` | array | `/payout_addrs` |
| `bestShareHash()` | string | `/web/best_share_hash` |
| `fetchAll()` | object | All major endpoints in parallel |

### Helper functions

| Function | Example |
|----------|---------|
| `formatHashrate(h)` | `formatHashrate(1e9)` → `"1.00 GH/s"` |
| `formatDuration(s)` | `formatDuration(3661)` → `"1h 1m"` |
| `formatCoins(sat, d)` | `formatCoins(625000000, 4)` → `"6.2500"` |
| `timeAgo(ts)` | `timeAgo(Date.now()/1000 - 60)` → `"1m 0s ago"` |

---

## Building a Custom Dashboard

### Minimal example

```html
<!DOCTYPE html>
<html>
<head>
    <title>My Pool</title>
    <script src="c2pool.js"></script>
</head>
<body>
    <h1>My Pool Dashboard</h1>
    <div id="hashrate">Loading…</div>
    <div id="miners">Loading…</div>

    <script>
    async function refresh() {
        const data = await C2PoolAPI.fetchAll();
        document.getElementById("hashrate").textContent =
            "Pool: " + C2PoolAPI.formatHashrate(data.localRate);
        document.getElementById("miners").textContent =
            "Miners: " + (data.users || 0);
        setTimeout(refresh, 10000);
    }
    refresh();
    </script>
</body>
</html>
```

Save as `my-dashboard/index.html` and run:
```bash
./c2pool --dashboard-dir ./my-dashboard ...
```

### React / Vue / Svelte

For a framework-based dashboard, use a separate build step:

```bash
# Development: run Vite dev server + c2pool backend
cd my-dashboard
npm run dev        # serves on :5173
# Configure CORS on c2pool:
./c2pool --cors-origin "http://localhost:5173" ...

# Production: build static files
npm run build
./c2pool --dashboard-dir ./my-dashboard/dist ...
```

### Dashboard requirements

Your dashboard only needs:
- An `index.html` file in the root of the dashboard directory
- Any CSS/JS/assets you want alongside it
- Call the c2pool API endpoints from JavaScript (same-origin, no CORS issues)

There are **no framework requirements** — use vanilla JS, React, Vue, Svelte,
Angular, D3, Chart.js, or anything that runs in a browser.

---

## Migrating from p2pool Dashboards

If you have an existing dashboard built for the original p2pool (or a
jtoomim fork), here is what you need to know:

### Endpoint mapping

| p2pool endpoint | c2pool endpoint | Notes |
|----------------|----------------|-------|
| `/local_stats` | `/local_stats` | Compatible shape |
| `/global_stats` | `/p2pool_global_stats` | Use this one, not `/global_stats` |
| `/current_payouts` | `/current_payouts` | Same |
| `/recent_blocks` | `/recent_blocks` | Same (keys: height, hash, ts) |
| `/web/version` | `/web/version` | Same |
| `/web/currency_info` | `/web/currency_info` | Same shape |
| `/payout_addr` | `/payout_addr` | Same |
| `/payout_addrs` | `/payout_addrs` | Same |
| `/web/best_share_hash` | `/web/best_share_hash` | Same |
| `/web/graph_data/*` | — | Not yet implemented |
| `/web/share/<hash>` | — | Not yet implemented |

### URL prefix change

The original p2pool served the dashboard from `web-static/` under
a `/static/` URL prefix, with API endpoints one level up (`../local_stats`).
In c2pool, everything is at the same level — the dashboard is at `/`
and the API is also at `/`:

```javascript
// Old p2pool:
d3.json('../local_stats', callback);

// c2pool:
d3.json('/local_stats', callback);  // OR just 'local_stats' (relative)
```

If your dashboard uses `../` prefixed API URLs, the easiest fix is a
global search-and-replace of `'../'` with `'/'`.

### Differences from p2pool

| Feature | p2pool (Python) | c2pool (C++) |
|---------|----------------|-------------|
| `/global_stats` shape | `{pool_hash_rate, pool_stale_prop, min_difficulty}` | Different — use `/p2pool_global_stats` for the legacy shape |
| Graph data endpoints | Full time-series `/web/graph_data/*` | Not yet implemented |
| Share explorer | `/web/share/<hash>` returns full share data | Not yet implemented |
| Sharechain data | — | `/sharechain/stats` and `/sharechain/window` (new) |
| Stratum stats | — | `/stratum_stats` (new) |
| Control API | — | `/control/mining/{start,stop,restart,ban,unban}` (new) |
| Log access | — | `/web/log` and `/logs/export` (new) |

---

## Theming and Branding

The default dashboard uses CSS custom properties for theming.
Override them in your own stylesheet:

```css
:root {
    --bg: #ffffff;        /* page background */
    --surface: #f8f9fa;   /* card backgrounds */
    --border: #dee2e6;    /* borders */
    --text: #212529;      /* primary text */
    --text-dim: #6c757d;  /* secondary text */
    --accent: #0d6efd;    /* links, highlights */
    --green: #198754;     /* positive indicators */
    --red: #dc3545;       /* negative indicators */
    --orange: #fd7e14;    /* warnings */
}
```

To create a completely custom theme:
1. Copy `web-static/` to a new directory
2. Edit `style.css` or replace it entirely
3. Pass `--dashboard-dir ./your-theme`

---

## Security Considerations

### Path traversal protection

The static file server validates all paths using `std::filesystem::canonical()`
to resolve symlinks and `..` sequences. Only files **physically inside** the
dashboard directory can be served. Any attempt to escape the directory
returns the fallback `getinfo` JSON — no error or 404 is leaked.

### CORS

By default, `Access-Control-Allow-Origin` is set to `*` (open for any
dashboard location). For production, restrict it:

```bash
./c2pool --cors-origin "https://dashboard.mypool.com" ...
```

### Control endpoints

The `/control/mining/*` endpoints can start/stop mining and ban addresses.
In production, consider placing an authentication proxy (nginx with basic
auth, or Cloudflare Access) in front of c2pool's HTTP port.

### No server-side templating

c2pool serves **static files only** — no PHP, no SSR. This eliminates
server-side injection attacks. All dynamic content is fetched via
client-side JavaScript from the JSON API.

---

## Troubleshooting

### Dashboard shows "Loading…" forever

1. Check that `--dashboard-dir` points to a directory with `index.html`
2. Check the browser console for fetch errors
3. Verify the API is responding: `curl http://localhost:8080/local_rate`
4. Check CORS if your dashboard is hosted externally

### API returns `getinfo` instead of expected data

The URL path doesn't match any known endpoint. Check for typos.
Remember that API endpoints take priority over static files.

### Hashrate shows 0 or —

The pool needs at least one active stratum connection submitting shares
to report hashrate. Check your miner configuration.

### Graphs page is empty

The in-browser hashrate chart requires at least 2 data points (collected
every 10 seconds). Wait 20+ seconds after page load.

For historical graph data (`/web/graph_data/*`), these endpoints are
not yet implemented — they require a time-series data collector.

### Custom dashboard files not updating

Static files are served with `Cache-Control: public, max-age=3600`.
Clear your browser cache or use a cache-busting query string:
```html
<link rel="stylesheet" href="style.css?v=2">
```

---

## Contributing

Dashboard improvements are welcome! See:
- [README.md](../README.md) for build instructions
- [CHANGELOG.md](../CHANGELOG.md) for recent changes
- [GitHub Issues](https://github.com/frstrtr/c2pool/issues) for planned work

Priority areas for contribution:
- **Time-series data collection** (`GraphDataCollector`) for graph endpoints
- **Share explorer** (`/web/share/<hash>`) for detailed share inspection
- **Multiple dashboard themes** (light, dark, mining-focused, stats-focused)
- **Localization** (i18n support for different languages)
