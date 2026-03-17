# c2pool REST API Reference

All endpoints return JSON unless otherwise noted. The web server runs on `--web-port` (default 8080).

## Pool Statistics

| Endpoint | Method | Returns | Description |
|----------|--------|---------|-------------|
| `/rate` | GET | `number` | Pool hash rate (H/s) |
| `/difficulty` | GET | `number` | Current share difficulty |
| `/users` | GET | `number` | Active miner count |
| `/fee` | GET | `number` | Pool fee (0.0-1.0) |
| `/uptime` | GET | `number` | Uptime in seconds |
| `/local_rate` | GET | `number` | Local miner hash rate |
| `/global_rate` | GET | `number` | Global pool hash rate |

## Detailed Statistics

### `/local_stats` (GET)
Per-miner statistics with warnings.
```json
{
  "peers": {"incoming": 0, "outgoing": 3},
  "miner_hash_rates": {"tltc1q...": 123456.7},
  "miner_dead_hash_rates": {"tltc1q...": 0.0},
  "shares": {"total": 100, "orphan": 2, "dead": 0},
  "efficiency": 0.98,
  "uptime": 3600,
  "block_value": 12.5,
  "warnings": [
    "LOST CONTACT WITH LTC DAEMON for 120s!",
    "No P2Pool peers connected"
  ],
  "donation_proportion": 0.01,
  "attempts_to_share": 4294967296,
  "attempts_to_block": 274877906944,
  "attempts_to_merged_block": 17179869184
}
```

### `/global_stats` (GET)
Pool-wide statistics.
```json
{
  "pool_hash_rate": 50000000000.0,
  "pool_nonstale_hash_rate": 49500000000.0,
  "pool_stale_prop": 0.01,
  "min_difficulty": 0.001,
  "network_block_difficulty": 12345678.9,
  "network_hashrate": 500000000000000.0
}
```

### `/version_signaling` (GET)
Share version vote distribution.
```json
{
  "versions": {"36": 850, "35": 50},
  "window": 900,
  "v36_percentage": 94.4
}
```

### `/v36_status` (GET)
V36 share format activation status.

## Payouts

| Endpoint | Method | Returns | Description |
|----------|--------|---------|-------------|
| `/current_payouts` | GET | `object` | `{address: amount}` current PPLNS distribution |
| `/current_merged_payouts` | GET | `object` | Per-address merged payout breakdown |
| `/payout_addr` | GET | `string` | Node operator payout address |
| `/payout_addrs` | GET | `object` | Per-coin payout addresses |

### `/current_merged_payouts` (GET)
```json
{
  "tltc1q...": {
    "amount": 0.123,
    "merged": [
      {"symbol": "DOGE", "address": "abc123...", "amount": 456.789}
    ]
  }
}
```

## Blocks

| Endpoint | Method | Returns | Description |
|----------|--------|---------|-------------|
| `/recent_blocks` | GET | `array` | Recent found blocks with status |
| `/recent_merged_blocks` | GET | `array` | Recent merged chain blocks |
| `/all_merged_blocks` | GET | `array` | All merged blocks ever found |
| `/discovered_merged_blocks` | GET | `array` | High-confidence merged finds |
| `/luck_stats` | GET | `object` | Block luck metrics |

### `/recent_blocks` (GET)
```json
[
  {
    "hash": "0000...",
    "height": 12345,
    "ts": 1710000000,
    "chain": "LTC",
    "status": "confirmed",
    "confirmations": 6,
    "checks": 3
  }
]
```

## Share Chain

| Endpoint | Method | Returns | Description |
|----------|--------|---------|-------------|
| `/best_share` | GET | `object` | Best share metadata |
| `/web/best_share_hash` | GET | `string` | Best share hash (64-char hex) |
| `/web/share/<hash>` | GET | `object` | Share details by hash |
| `/web/payout_address/<hash>` | GET | `string` | Payout address for share |
| `/web/heads` | GET | `array` | Chain head hashes |
| `/web/verified_heads` | GET | `array` | Verified chain heads |
| `/web/tails` | GET | `array` | Chain tail hashes |
| `/web/verified_tails` | GET | `array` | Verified chain tails |
| `/web/my_share_hashes` | GET | `array` | Local miner's share hashes |
| `/web/my_share_hashes50` | GET | `array` | Last 50 local shares |
| `/sharechain/stats` | GET | `object` | Share chain metrics |
| `/sharechain/window` | GET | `object` | Window size and period |
| `/tracker_debug` | GET | `object` | Internal chain state (admin) |

## Workers & Miners

| Endpoint | Method | Returns | Description |
|----------|--------|---------|-------------|
| `/connected_miners` | GET | `array` | Connected miner list |
| `/stratum_stats` | GET | `object` | Per-worker Stratum statistics |
| `/miner_stats/<address>` | GET | `object` | Per-address metrics |
| `/miner_payouts/<address>` | GET | `array` | Address payout history |
| `/user_stales` | GET | `object` | Per-user stale counts |

## Network & Peers

| Endpoint | Method | Returns | Description |
|----------|--------|---------|-------------|
| `/peer_addresses` | GET | `text/plain` | Space-separated peer list |
| `/peer_list` | GET | `array` | Detailed peer info |
| `/peer_versions` | GET | `object` | Peer software versions |
| `/peer_txpool_sizes` | GET | `object` | Peer transaction pool sizes |
| `/pings` | GET | `array` | Peer latencies (ms) |
| `/stale_rates` | GET | `object` | Per-peer stale rates |
| `/node_info` | GET | `object` | Node identity and ports |
| `/network_difficulty` | GET | `array` | Difficulty time series |

## Merged Mining

| Endpoint | Method | Returns | Description |
|----------|--------|---------|-------------|
| `/merged_stats` | GET | `object` | Per-chain merged mining stats |
| `/broadcaster_status` | GET | `object` | Main chain broadcaster state |
| `/merged_broadcaster_status` | GET | `object` | Per-chain broadcaster state |

### `/merged_stats` (GET)
```json
{
  "total_blocks": 53,
  "block_value": 10000.0,
  "symbol": "DOGE",
  "difficulty": 0.001234,
  "networks": {
    "DOGE": {
      "chain_id": 98,
      "blocks_found": 53,
      "current_height": 25100,
      "block_value": 10000.0,
      "difficulty": 0.001234
    }
  },
  "recent": [...]
}
```

## Messaging

| Endpoint | Method | Returns | Description |
|----------|--------|---------|-------------|
| `/msg/config` | GET | `object` | Message configuration |
| `/msg/recent` | GET | `array` | Recent messages |
| `/msg/chat` | GET | `array` | Chat messages |
| `/msg/announcements` | GET | `array` | Pool announcements |
| `/msg/alerts` | GET | `array` | Pool alerts |
| `/msg/status` | GET | `object` | Message store status |
| `/msg/stats` | GET | `object` | Message statistics |
| `/msg/bans` | GET | `object` | Current ban list |
| `/msg/ban` | POST | `object` | Add ban entry (localhost only) |
| `/msg/unban` | POST | `object` | Remove ban entry (localhost only) |
| `/msg/load_blob` | POST | `object` | Load message blob (localhost only) |
| `/msg/diag` | GET | `object` | Diagnostics (localhost only) |

## Graph Data

Time series data for dashboard charts. Periods: `last_hour`, `last_day`, `last_week`, `last_month`, `last_year`.

| Endpoint | Method | Returns | Description |
|----------|--------|---------|-------------|
| `/web/graph_data/pool_rates/<period>` | GET | `array` | `[[timestamp, rate], ...]` |
| `/web/graph_data/worker_count/<period>` | GET | `array` | `[[timestamp, count], ...]` |
| `/web/graph_data/unique_miner_count/<period>` | GET | `array` | `[[timestamp, count], ...]` |
| `/web/graph_data/connected_miners/<period>` | GET | `array` | `[[timestamp, count], ...]` |

## Admin (Requires `?token=<auth_token>`)

| Endpoint | Method | Returns | Description |
|----------|--------|---------|-------------|
| `/control/mining/start` | GET | `object` | Start mining |
| `/control/mining/stop` | GET | `object` | Stop mining |
| `/control/mining/restart` | GET | `object` | Restart mining |
| `/control/mining/ban?target=<addr>` | GET | `object` | Ban address |
| `/control/mining/unban?target=<addr>` | GET | `object` | Unban address |
| `/web/log` | GET | `text/plain` | Raw log output |
| `/logs/export` | GET | `text/plain` | Log export (scope, from, to, format) |

## Version & Config

| Endpoint | Method | Returns | Description |
|----------|--------|---------|-------------|
| `/web/version` | GET | `string` | c2pool version |
| `/web/currency_info` | GET | `object` | Chain configuration |
| `/p2pool_global_stats` | GET | `object` | Legacy p2pool-compatible stats |
| `/patron_sendmany/<total>` | GET | `text/plain` | Redistribution calculator |
| `/help` | GET | `text/html` | API documentation |

## Stratum Protocol (TCP, JSON-RPC 2.0)

Connect via `stratum+tcp://host:worker_port` (default 9327).

### Client-to-Server

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `mining.subscribe` | `[user_agent]` | `[[subscriptions], extranonce1, extranonce2_size]` | Subscribe to work |
| `mining.authorize` | `[username, password]` | `true/false` | Authorize worker. Username format: `LTC_ADDR[,DOGE_ADDR][.worker][+difficulty]` |
| `mining.configure` | `[extensions[], params{}]` | `{ext: result}` | BIP 310 extension negotiation (version-rolling, subscribe-extranonce) |
| `mining.submit` | `[worker, job_id, extranonce2, ntime, nonce, version_bits?]` | `true/false` | Submit share (6th param = ASICBoost version bits) |
| `mining.suggest_difficulty` | `[difficulty]` | `true` | Suggest initial difficulty |
| `mining.extranonce.subscribe` | `[]` | `true` | NiceHash extranonce subscription |
| `mining.set_merged_addresses` | `[{chain_id: address}]` | `true/false` | Set merged chain addresses (c2pool extension) |

### Server-to-Client (Notifications)

| Method | Params | Description |
|--------|--------|-------------|
| `mining.notify` | `[job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean]` | New work |
| `mining.set_difficulty` | `[difficulty]` | Difficulty update |
| `mining.set_extranonce` | `[extranonce1, extranonce2_size]` | Extranonce change (requires subscription) |

### BIP 310: mining.configure

Negotiate extensions before subscribing. Pool mask: `0x1fffe000` (bits 13-28).

```json
// Request
{"method": "mining.configure", "params": [
  ["version-rolling", "subscribe-extranonce"],
  {"version-rolling.mask": "1fffe000", "version-rolling.min-bit-count": 2}
]}
// Response
{"result": {
  "version-rolling": true, "version-rolling.mask": "1fffe000",
  "subscribe-extranonce": true
}}
```

After version-rolling is negotiated, miners pass rolled version bits as the 6th param in `mining.submit`:
```json
{"method": "mining.submit", "params": ["worker", "job_1", "deadbeef", "5f123456", "00000001", "1fffe000"]}
```

### NiceHash/MiningRigRentals Compatibility

Subscribe to extranonce changes via either:
- BIP 310: `mining.configure(["subscribe-extranonce"], {})`, or
- NiceHash: `mining.extranonce.subscribe([])`

After subscription, the server may send `mining.set_extranonce` followed by `mining.notify` with `clean_jobs=true`.

### Address Format in `mining.authorize`

Multiple separator styles are supported for maximum firmware compatibility:

| Format | Example | Behavior |
|--------|---------|----------|
| `LTC_ADDR` | `tltc1q...` | LTC payout, auto-derive DOGE from same pubkey_hash |
| `LTC_ADDR,DOGE_ADDR` | `tltc1q...,nXyz...` | Comma separator (standard Stratum) |
| `LTC_ADDR\|DOGE_ADDR` | `tltc1q...\|nXyz...` | Pipe separator (Vnish firmware) |
| `LTC_ADDR;DOGE_ADDR` | `tltc1q...;nXyz...` | Semicolon separator (alternative) |
| `LTC_ADDR DOGE_ADDR` | `tltc1q... nXyz...` | Space separator (some web UIs) |
| `LTC_ADDR/98:DOGE_ADDR` | `tltc1q.../98:nXyz...` | Slash format with explicit chain_id |
| `DOGE_ADDR,LTC_ADDR` | `nXyz...,tltc1q...` | Auto-detected swap, corrected to LTC,DOGE |
| `LTC_ADDR.worker` | `tltc1q....rig1` | Worker name (stripped, used for stats) |
| `LTC_ADDR_worker` | `tltc1q..._rig1` | Underscore worker separator |
| `LTC_ADDR+1024` | `tltc1q...+1024` | Fixed difficulty override |

Separator priority: slash (explicit chain IDs) > comma > pipe > semicolon > space.

## CORS

Enabled via `--cors-origin '*'` (or specific origin). Required for browser-based dashboard access from different ports.
