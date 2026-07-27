# Dashboard & REST API Integration

c2pool serves a built-in web dashboard and a JSON REST API from the same HTTP
port (default **8080**, `--web-port`). This document is the reference for
integrating with that API — feeding an external block explorer, building a
custom dashboard, or scraping pool metrics.

> The authoritative source for exact response fields is
> [`src/core/web_server.cpp`](../src/core/web_server.cpp) (the request router)
> and the `rest_*` handlers behind it. Endpoint descriptions below are stable;
> response shapes may gain fields over time.

---

## Serving basics

- **Base URL:** `http://<host>:8080/` (change the port with `--web-port`, bind
  address with `--http-host`, default `0.0.0.0`).
- **Dashboard:** the HTML/JS UI is served from `web-static/` (override with
  `--dashboard-dir`). Open `http://localhost:8080/` in a browser.
- **Format:** read endpoints return `application/json` (the `/web/*` helpers
  back the bundled dashboard and may return HTML/JSON as noted).
- **Method:** the public stats/read API is `GET`-only. Mutating routes live
  under `/control/*` and `/api/admin/*` and are access-gated (see below).
- **CORS:** set `--cors-origin <origin>` (YAML `cors_origin`) to emit an
  `Access-Control-Allow-Origin` header for cross-origin dashboards.
- **Availability:** the dashboard + REST API are served in `integrated`,
  `solo`, and `custodial` modes (not in `sharechain` relay-only mode).

---

## Node & pool statistics

| Endpoint | Returns |
|----------|---------|
| `/local_stats` | Local node stats — peers, hashrates, share counts |
| `/global_stats` | Pool-wide aggregate statistics |
| `/p2pool_global_stats` | Sharechain-wide (p2pool-compatible) global stats |
| `/node_info` | Node identity / build / mode info |
| `/uptime` | Node uptime |
| `/rate`, `/local_rate`, `/global_rate` | Hashrate (node / local miners / pool) |
| `/difficulty`, `/network_difficulty` | Current share difficulty / parent-chain network difficulty |
| `/fee` | Node operator fee configuration |
| `/best_share` | Current best share (sharechain tip) summary |
| `/version_signaling`, `/v36_status` | Share-version signalling tallies and V36 AutoRatchet state |

## Payouts

| Endpoint | Returns |
|----------|---------|
| `/current_payouts` | Current PPLNS payout distribution |
| `/pplns/current` | PPLNS window snapshot |
| `/pplns/miner/<address>` | PPLNS share/weight for one address |
| `/miner_payouts/<address>` | Payout history/estimate for one address |
| `/payout_addr`, `/payout_addrs` | Configured payout address(es) |

## Miners & stratum

| Endpoint | Returns |
|----------|---------|
| `/connected_miners` | Currently connected stratum workers |
| `/stratum_stats` | Per-worker stratum stats (hashrate, difficulty, accepted/rejected) |
| `/miner_stats/<address>` | Stats for one miner address |
| `/miner_thresholds` | Minimum viable hashrate and dust range |
| `/stratum_security` | Stratum connection/security posture |
| `/users`, `/user_stales`, `/stale_rates` | Per-user list and stale-share rates |

## Blocks & luck

| Endpoint | Returns |
|----------|---------|
| `/recent_blocks` | Recently found blocks |
| `/luck_stats` | Pool luck statistics |
| `/checkpoint`, `/checkpoints` | SPV header checkpoint(s) in effect |

## Sharechain

| Endpoint | Returns |
|----------|---------|
| `/sharechain/stats` | Sharechain state summary |
| `/sharechain/tip` | Current sharechain tip |
| `/sharechain/window` | PPLNS window contents (cached, ETag/`304`, rate-limited) |
| `/sharechain/delta` | Incremental sharechain updates |
| `/sharechain/stream` | Streaming sharechain updates (for live visualizations) |
| `/tracker_debug` | Share-tracker debug view |

## Merged mining

| Endpoint | Returns |
|----------|---------|
| `/merged_stats` | Merged-mining block statistics |
| `/current_merged_payouts` | Current merged-mining payout distribution |
| `/recent_merged_blocks` | Recently found merged (aux) blocks |
| `/all_merged_blocks`, `/discovered_merged_blocks` | Full / discovered merged-block lists |
| `/broadcaster_status`, `/merged_broadcaster_status` | Parent- and aux-chain block broadcaster status |

## Peers & network

| Endpoint | Returns |
|----------|---------|
| `/peer_list`, `/peer_addresses` | Connected sharechain peers |
| `/peer_versions`, `/peer_txpool_sizes` | Peer protocol versions / mempool sizes |
| `/pings` | Peer latency |
| `/ban_stats` | P2P ban statistics |
| `/api/coin_peers` | Parent-coin daemon peer info |
| `/api/node_topology` | Sharechain topology graph |
| `/p2p_stats` | Per-message-type p2p wire counters + tx-pool and embedded-timestamp gauges |

### `/p2p_stats`

Read-only observability for the pool p2p protocol. Before it existed, none of
the pool message types emitted anything at any verbosity, so "is this message
type actually moving on the wire?" had no observable answer and a log-grep
returning zero was easy to misread as "not implemented".

```json
{
  "messages": { "shares": { "in": 412, "out": 388 }, "remember_tx": { "in": 9, "out": 14 }, "...": {} },
  "totals": { "in": 1204, "out": 1189 },
  "trace_enabled": false,
  "txpool": {
    "known_txs_size": 12043,
    "known_txs_order_size": 12043,
    "last_have_tx_advert_size": 500,
    "last_losing_tx_advert_size": 0,
    "have_tx_adverts_sent": 37,
    "updated_at": 1785049468
  },
  "sharechain_timestamps": {
    "tip_embedded_timestamp": 1785024952,
    "tip_lag_seconds": 24516,
    "clip_upper_bound": 39,
    "delta_samples": 100,
    "delta_saturated": 97,
    "saturation_fraction": 0.97,
    "updated_at": 1785049468
  }
}
```

* `messages` — one `in`/`out` pair per canonical p2pool message type, counted at
  the two shared choke points every pool message passes through, so the numbers
  are identical in meaning across every coin. `unknown` buckets anything that
  did not match a known command. `verack`/`pong` belong to the coin-daemon p2p
  layer, not the pool protocol, and read 0 on a healthy pool node — that zero is
  an answer, not a gap.
* `txpool` — settles whether a peer dashboard showing `TXPOOL=0` for this node
  means the pool is genuinely empty (`known_txs_size` 0) or the advert is being
  suppressed (`known_txs_size` > 0 with no adverts sent).
  `known_txs_order_size` is `null` on lanes with no recency deque (DASH), which
  is deliberately distinct from `0`.
* `sharechain_timestamps` — `tip_lag_seconds` is wall-clock now minus the chain
  tip's **embedded** `share_data.timestamp`; `saturation_fraction` is the share
  of the last 100 embedded deltas pinned exactly to the clip upper bound
  (`2*SHARE_PERIOD - 1`; 39 s on DASH). Upstream p2pool clips embedded
  timestamps to `[prev+1, prev+2*SHARE_PERIOD-1]`, so once real cadence outruns
  that bound the embedded clock saturates, the difficulty retarget goes blind to
  hashrate, and the floor decays. **These two fields are the honest
  early-warning signal; `pool_hash_rate` and `min_difficulty` are not** — under
  saturation they are computed from that same saturated history and report floor
  decay rather than the pool.

`trace_enabled` reports the per-message debug log, which is off by default and
is not switched on by any code path in-tree; the counters are the mechanism.

---

## Explorer integration (loopback, opt-in)

For feeding an **external block explorer**, c2pool exposes a Bitcoin-RPC-style
subset under `/api/explorer/`. These are **loopback-only** (127.0.0.1) and
require `explorer: true` in the config:

| Endpoint | Returns |
|----------|---------|
| `/api/explorer/getblockchaininfo` | Parent-chain info |
| `/api/explorer/getblockhash` | Block hash by height |
| `/api/explorer/getblock` | Full block JSON by hash or height |

Enable and point the bundled explorer at them:

```yaml
# config
explorer: true
explorer_url: "http://localhost:9090"
explorer_depth_ltc: 288      # blocks to retain (LTC)
explorer_depth_doge: 1440    # blocks to retain (DOGE)
```

```bash
python3 explorer/explorer.py \
  --ltc-c2pool http://127.0.0.1:8080/api/explorer \
  --doge-c2pool http://127.0.0.1:8080/api/explorer \
  --web-port 9090
```

Then browse `http://localhost:9090/`. The explorer shows block details, decoded
coinbase scripts, and THE commitment proofs for c2pool-found blocks, and links
out to a public explorer (default Blockchair) for anything outside the stored
range.

---

## Dashboard customization

Both the dashboard and the explorer are user-editable components:

- **Dashboard:** edit HTML/JS/CSS in `web-static/` (or point `--dashboard-dir`
  at your own directory). The bundled UI consumes the `/web/*` helper endpoints
  (`/web/heads`, `/web/tails`, `/web/graph_data/…`, `/web/share/<hash>`,
  `/web/best_share_hash`, `/web/sync_status`, `/web/currency_info`, …).
- **Explorer:** modify `explorer/explorer.py`.
- **External explorer links** default to Blockchair and can be overridden
  per-node:

```yaml
address_explorer_prefix: "https://your-explorer.example.com/address/"
block_explorer_prefix:   "https://your-explorer.example.com/block/"
tx_explorer_prefix:      "https://your-explorer.example.com/tx/"
```

- **Analytics:** set `--analytics-id G-XXXXXXXXXX` (YAML `analytics_id`) to
  inject a measurement snippet into the dashboard `</head>`.

---

## Control & admin endpoints

Mutating and administrative routes exist under `/control/*` (e.g.
`/control/mining/start`, `/stop`, `/restart`, `/ban`, `/unban`) and
`/api/admin/*` (`/api/admin/pool/…`, `/api/admin/coin/…`). These change node
state and are **not** part of the read-only integration surface — treat them as
operator-only and keep them off any public binding. Consult
`src/core/web_server.cpp` for their exact contracts before wiring automation to
them.
