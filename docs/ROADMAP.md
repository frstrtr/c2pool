# c2pool Roadmap

## Current State (v36)

- LTC parent chain: production-ready (embedded SPV — no external daemon needed)
- DOGE merged mining: implemented, embedded SPV (chain_id=98)
- Multi-chain merged mining: PEP, BELLS, LKY, JKC, SHIC, DINGO (external daemons)
- Stratum V1: full spec + ASICBoost + NiceHash/MRR + suggest_difficulty
- Address separators: comma, pipe, semicolon, space, slash (Vnish compatible)
- Web dashboard: 80+ REST endpoints, full API
- HiveOS/MinerStat/RaveOS: deploy templates ready
- THE state root commitment: anchored in coinbase OP_RETURN across all MM chains
- Code separated: stratum_server, address_utils, web_server (clean modules)
- Test suite: 390 tests passing

### Merged mining chains (all implemented)

| Coin | chain_id | Daemon | Status |
|------|----------|--------|--------|
| DOGE | 98 | Embedded SPV or external | Done |
| PEP | 63 | External (`pepecoind`) | Done |
| BELLS | 16 | External (`bellsd`) | Done |
| LKY | 8211 | External (`luckycoind`) | Done |
| JKC | 8224 | External (`junkcoind`) | Done |
| SHIC | 74 | External (`shibacoind`) | Done |
| DINGO | 98 | External (conflicts with DOGE) | Done |

## Phase 6 — DigiByte Scrypt Parent Chain

DGB Scrypt runs as a second parent chain (`--net digibyte`) with its own
P2Pool sharechain network. Already implemented in
[p2pool-merged-v36](https://github.com/frstrtr/p2pool-merged-v36).

### DGB chain params (from p2pool reference)

| Parameter | Value |
|-----------|-------|
| Algorithm | Scrypt (1 of 5 DGB algos, 15s rotation) |
| Block period | 15 seconds (75s total / 5 algos) |
| P2Pool share period | 25 seconds |
| Chain length | 8640 shares (~24 hours) |
| P2P port (pool) | 5024 |
| Stratum port (pool) | 5025 |
| P2P port (DGB Core) | 12024 |
| RPC port (DGB Core) | 14024 |
| Address version | 0x1e (30) — D prefix |
| P2SH version | 0x3f (63) — S prefix |
| Bech32 HRP | "dgb" |
| P2P magic | fac3b6da |
| GBT_ALGO | "scrypt" (multi-algo requires algo specification) |

### Implementation plan

1. `impl/dgb/config_pool.hpp` — DGB Scrypt pool config (share period, chain length, etc.)
2. `impl/dgb/config_coin.hpp` — DGB coin params (address versions, subsidy schedule)
3. `impl/dgb/node.cpp` — DGB pool node orchestration (reuse LTC pattern)
4. `impl/dgb/share_check.hpp` — Share validation (identical to LTC Scrypt)
5. Address validation for DGB (0x1e P2PKH, 0x3f P2SH, bech32 "dgb")
6. GBT_ALGO="scrypt" filter in getblocktemplate requests
7. DGB subsidy schedule (3-phase decay: 72K→8K→2.4K→1 DGB minimum)
8. DGB merged mining: DOGE, DINGO, PEP, BELLS, LKY, JKC, SHIC (same AuxPoW)

### DGB subsidy schedule
```
Height < 67,200:     Pre-DigiShield fixed rewards (72K → 16K → 8K DGB)
67,200 ≤ H < 400K:  8,000 DGB base, -0.5% decay every 10,080 blocks
H ≥ 400,000:        2,459 DGB base, -1% decay every 80,160 blocks
Minimum:             1 DGB
```

## Priority 1 — Miner Adoption (v36.x)

### Public P2Pool Observer
A public website showing all c2pool nodes, total network hashrate, recent
blocks found, and payout history. Builds confidence that the network is
alive and paying.

### Payout History API
`/miner_payouts/<address>` with historical block data, amounts, and
confirmation status. Miners need proof that payouts happen reliably.

### Block Luck Display
Show "expected time to next block" on the dashboard based on current
pool hashrate vs network difficulty.

### Real ASIC Validation
Test the full flow with Antminer L7/L9 via HiveOS flight sheet on
Litecoin testnet. Validate: connection, vardiff ramp-up, share
acceptance, block finding, DOGE merged payout.

## Priority 2 — Infrastructure

### Prometheus /metrics Endpoint
Standard Prometheus exposition format for Grafana dashboards:
```
p2pool_connected_workers 6
p2pool_pool_hashrate 948000000000
p2pool_shares_accepted 15234
p2pool_blocks_found 3
```

### Block Found Webhook
`--block-webhook URL` — POST notification to external services (Discord,
Telegram, monitoring) when the pool finds a block.

### WebSocket Real-Time Updates
Replace HTTP polling with WebSocket push for live dashboard stats.

## Priority 3 — Protocol Enhancements

### Stratum V2 (Binary + Noise Encryption)
Not needed for Litecoin/Scrypt ASICs (no firmware supports it). Only
relevant for future Bitcoin chain support. Can be added alongside V1
on a separate port — no consensus change required, no V37 needed.

### SSL/TLS Stratum
Encrypted Stratum V1 connections for miners on untrusted networks.
```
--stratum-ssl-port 3334 --ssl-cert cert.pem --ssl-key key.pem
```

## V37 — THE (Time Hybrid Evaluation)

THE extends V36 with temporal layer stratification. Foundation work
(Steps 0-4) is complete in V36. V37 activation required for:

- Step 5: Adaptive window (pool_aps formula)
- Step 6: IncrementalVestingCache (O(1) decay)
- Step 7: Temporal layer settlement with TLA+ formal verification

THE state root commitment is already anchored in coinbase OP_RETURN
across all merged mining chains (LTC, DOGE, PEP, BELLS, LKY, JKC, SHIC).

See [frstrtr/the](https://github.com/frstrtr/the) for design documents.

## Not Planned

### Auto-Switch Tool
Automatically switching hash to c2pool based on centralization metrics.
Niche use case — better served by a standalone monitoring tool.

### MEV Dashboard (Litecoin)
Transaction fee analysis. On Litecoin, fees are ~0.001 LTC/block — not
enough to motivate behavior change. Only relevant for future BTC support.
