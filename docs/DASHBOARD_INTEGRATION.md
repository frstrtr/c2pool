# c2pool Dashboard Integration Guide

> Build custom dashboards for c2pool using the HTTP API.
> Fully compatible with the p2pool dashboard lineage:
> **p2pool/p2pool → jtoomim/p2pool → frstrtr/p2pool-merged-v36 → frstrtr/c2pool**
>
> **Both the dashboard (`web-static/`) and explorer (`explorer/explorer.py`) are
> user-customizable.** Edit HTML/JS/CSS or Python code to change the design, add
> features, or integrate with your infrastructure. Block explorer hyperlinks
> default to Blockchair and can be overridden per-node via YAML config.

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

Blockchain explorer URLs and currency symbol. Used by the dashboard to
construct hyperlinks. Defaults to Blockchair; overridable via YAML config
(`address_explorer_prefix`, `block_explorer_prefix`, `tx_explorer_prefix`).

Also includes `explorer_enabled` (bool) and `explorer_url` (string) when the
lite block explorer is active.

```json
{
  "symbol": "LTC",
  "address_explorer_url_prefix": "https://blockchair.com/litecoin/address/",
  "block_explorer_url_prefix": "https://blockchair.com/litecoin/block/",
  "tx_explorer_url_prefix": "https://blockchair.com/litecoin/transaction/",
  "explorer_enabled": false,
  "explorer_url": ""
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

All p2pool-era endpoints from the jtoomim fork are now routed and return
data.  Some endpoints return stub/placeholder values where deep
infrastructure is not yet wired (e.g., per-miner hashrate history,
full share inspection).  Contributions welcome.

---

## API Reference — Additional p2pool-compatible Endpoints

These endpoints match the JSON shapes from jtoomim/p2pool's `web.py`,
giving full backward-compatibility with classic p2pool dashboards.

### GET `/rate`
Returns the pool hashrate as a single number (float).

### GET `/difficulty`
Returns the current share difficulty as a single number (float).

### GET `/user_stales`
Returns `{ "address": stale_proportion, ... }` (currently stub: empty object).

### GET `/peer_addresses`
Returns a **plain text** space-separated list of peer addresses.
Content-Type: `text/plain`.

### GET `/peer_versions`
```json
{ "ip:port": "version_string", ... }
```

### GET `/peer_txpool_sizes`
```json
{ "ip:port": txpool_size_int, ... }
```

### GET `/peer_list`
```json
[
  {
    "address": "ip:port",
    "version": "string",
    "incoming": bool,
    "uptime": float,
    "txpool_size": int
  }
]
```

### GET `/pings`
```json
{ "ip:port": ping_ms, ... }
```

### GET `/stale_rates`
```json
{ "good": 0.95, "orphan": 0.03, "dead": 0.02 }
```

### GET `/node_info`
```json
{
  "external_ip": "0.0.0.0",
  "worker_port": 9327,
  "p2p_port": 9338,
  "network": "litecoin_testnet",
  "symbol": "LTC"
}
```

### GET `/luck_stats`
```json
{
  "luck_available": bool,
  "current_luck_trend": float,
  "blocks": [ { "ts": unix_ts, "hash": "hex", "luck": float } ]
}
```

### GET `/ban_stats`
```json
{ "total_banned": int, "banned_targets": ["target1", ...] }
```

### GET `/stratum_security`
DDoS detection metrics (stub).
```json
{ "connections_per_second": 0.0, "potential_ddos": false, "blacklisted_ips": [] }
```

### GET `/best_share`
Node-wide best share difficulty statistics.
```json
{
  "network_difficulty": float,
  "all_time": { "difficulty": float, "pct_of_block": float, "miner": "addr", "timestamp": int },
  "session": { "difficulty": float, "pct_of_block": float, "miner": "addr", "timestamp": int, "started": int },
  "round": { "difficulty": float, "pct_of_block": float, "miner": "addr", "timestamp": int, "started": int },
  "median_pct": float
}
```

### GET `/miner_stats/<address>`
Detailed per-miner statistics.
```json
{
  "address": "string",
  "active": bool,
  "hashrate": float,
  "dead_hashrate": float,
  "current_payout": float,
  "network_difficulty": float,
  "best_difficulty_all_time": float,
  "best_difficulty_session": float,
  "best_difficulty_round": float,
  "hashrate_periods": { "1m": {...}, "10m": {...}, "1h": {...} },
  "total_shares": int,
  "unstale_shares": int,
  "dead_shares": int,
  "orphan_shares": int
}
```

### GET `/miner_payouts/<address>`
Payout history per miner.
```json
{
  "address": "string",
  "current_payout": float,
  "blocks_found": int,
  "total_estimated_rewards": float,
  "confirmed_rewards": float,
  "maturing_rewards": float,
  "blocks": []
}
```

### GET `/version_signaling`
Share version tracking (V36 transition support).

### GET `/v36_status`
V36 diagnostic information.

### GET `/patron_sendmany/<total>`
Builds a sendmany text splitting `<total>` among current miners.

### GET `/tracker_debug`
Debug sharechain information (forwarded from sharechain_stats callback).

### Merged Mining Endpoints

| Endpoint | Description |
|----------|-------------|
| `/merged_stats` | Merged mining block statistics |
| `/current_merged_payouts` | Current merged mining payouts |
| `/recent_merged_blocks` | Recent merged-mined blocks |
| `/all_merged_blocks` | All merged-mined blocks |
| `/discovered_merged_blocks` | Merged block proofs |
| `/broadcaster_status` | Parent chain broadcaster status |
| `/merged_broadcaster_status` | Merged chain broadcaster status |
| `/network_difficulty` | Historical network difficulty samples |

### Web Sub-Endpoints (Share Chain Inspection)

| Endpoint | Description |
|----------|-------------|
| `/web/heads` | Share chain head hashes |
| `/web/verified_heads` | Verified share chain head hashes |
| `/web/tails` | Share chain tail hashes |
| `/web/verified_tails` | Verified share chain tail hashes |
| `/web/my_share_hashes` | Hashes of locally produced shares |
| `/web/my_share_hashes50` | First 50 locally produced share hashes |
| `/web/share/<hash>` | Full share details for a given hash |
| `/web/payout_address/<hash>` | Payout address for a share |
| `/web/log_json` | Rolling stat log as JSON array |
| `/web/graph_data/<source>/<view>` | Time-series graph data |

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
| `rate()` | number | `/rate` |
| `difficulty()` | number | `/difficulty` |
| `userStales()` | object | `/user_stales` |
| `peerAddresses()` | string | `/peer_addresses` |
| `peerVersions()` | object | `/peer_versions` |
| `peerTxpoolSizes()` | object | `/peer_txpool_sizes` |
| `peerList()` | array | `/peer_list` |
| `pings()` | object | `/pings` |
| `staleRates()` | object | `/stale_rates` |
| `nodeInfo()` | object | `/node_info` |
| `luckStats()` | object | `/luck_stats` |
| `banStats()` | object | `/ban_stats` |
| `stratumSecurity()` | object | `/stratum_security` |
| `bestShare()` | object | `/best_share` |
| `versionSignaling()` | object | `/version_signaling` |
| `v36Status()` | object | `/v36_status` |
| `trackerDebug()` | object | `/tracker_debug` |
| `networkDifficulty()` | array | `/network_difficulty` |
| `minerStats(addr)` | object | `/miner_stats/<addr>` |
| `minerPayouts(addr)` | object | `/miner_payouts/<addr>` |
| `patronSendmany(total)` | string | `/patron_sendmany/<total>` |
| `mergedStats()` | object | `/merged_stats` |
| `currentMergedPayouts()` | object | `/current_merged_payouts` |
| `recentMergedBlocks()` | array | `/recent_merged_blocks` |
| `allMergedBlocks()` | array | `/all_merged_blocks` |
| `discoveredMergedBlocks()` | array | `/discovered_merged_blocks` |
| `broadcasterStatus()` | object | `/broadcaster_status` |
| `mergedBroadcasterStatus()` | object | `/merged_broadcaster_status` |
| `webHeads()` | array | `/web/heads` |
| `webVerifiedHeads()` | array | `/web/verified_heads` |
| `webTails()` | array | `/web/tails` |
| `webVerifiedTails()` | array | `/web/verified_tails` |
| `webMyShareHashes()` | array | `/web/my_share_hashes` |
| `webMyShareHashes50()` | array | `/web/my_share_hashes50` |
| `webShare(hash)` | object | `/web/share/<hash>` |
| `webPayoutAddress(hash)` | string | `/web/payout_address/<hash>` |
| `webLogJson()` | array | `/web/log_json` |
| `webGraphData(source, view)` | object | `/web/graph_data/<source>/<view>` |
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
