# c2pool Roadmap

## Current State (v36)

- LTC sharechain: production-ready
- DOGE merged mining: implemented (chain_id=98)
- Stratum V1: full spec + ASICBoost + NiceHash/MRR compat
- Web dashboard: full API
- HiveOS/MinerStat/RaveOS: deploy templates ready

## Priority 1 — Miner Adoption (v36.x)

### Public P2Pool Observer
A public website showing all c2pool nodes, total network hashrate, recent
blocks found, and payout history. Builds confidence that the network is
alive and paying. This is the #1 thing that convinces miners to join.

### Payout History API
`/miner_payouts/<address>` with historical block data, amounts, and
confirmation status. Miners need proof that payouts happen reliably.

### Block Luck Display
Show "expected time to next block" on the dashboard based on current
pool hashrate vs network difficulty. Helps miners set realistic
expectations about variance.

### Real ASIC Validation
Test the full flow with Antminer L7/L9 via HiveOS flight sheet on
Litecoin testnet. Validate: connection, vardiff ramp-up, share
acceptance, block finding, DOGE merged payout.

## Priority 2 — Additional Merged Mining Coins

All Scrypt AuxPoW coins use the same `createauxblock`/`submitauxblock`
RPC interface. No embedded daemons needed — operators run the coin
daemon alongside litecoind and pass RPC credentials via `--merged`.

### Revenue ranking (March 2026 prices)

| Coin | chain_id | Daily Network USD | Exchange Liquidity | Priority |
|------|----------|-------------------|-------------------|----------|
| DOGE | 98 | $1,440,000 | Excellent (all majors) | **DONE** |
| PEP | 63 | $4,500 | CoinEx, MEXC | HIGH |
| LKY | TBD | $4,100 | MEXC, Gate | HIGH |
| JKC | TBD | $560 | CoinEx | MEDIUM |
| BELLS | TBD | $170 | Gate, MEXC | MEDIUM |
| SHIC | TBD | $780 (fake liq.) | CoinEx | LOW |
| DINGO | TBD | negligible | MEXC | LOW |

### Implementation per coin
Each new coin requires:
1. Chain params entry: chain_id, address version bytes, RPC port default
2. Address validation rules (bech32 HRP if any, base58 version bytes)
3. Test with the coin's daemon (`createauxblock` / `submitauxblock`)

The existing `MergedMiningManager` handles AuxPoW construction, merkle
tree building, and block submission generically. Estimated effort per
coin: 1-2 hours for params + testing.

### Embedded daemon strategy
Only DOGE justifies an embedded SPV node (73% of total mining revenue).
All other coins: operators run external daemons. Rationale:
- DOGE embedded node removes the #1 setup friction point
- Small coins have trivial daemon setup (`docker run pepecoin-core`)
- Embedding 7 daemons would bloat the binary and maintenance burden

## Priority 3 — Infrastructure

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

## Priority 4 — Protocol Enhancements

### Stratum V2 (Binary + Noise Encryption)
Not needed for Litecoin/Scrypt ASICs (no firmware supports it). Only
relevant for future Bitcoin chain support. Can be added alongside V1
on a separate port — no consensus change required, no V37 needed.

### SSL/TLS Stratum
Encrypted Stratum V1 connections for miners on untrusted networks.
```
--stratum-ssl-port 3334 --ssl-cert cert.pem --ssl-key key.pem
```

### mining.configure Extensions
- `minimum-difficulty` — miner requests minimum diff floor
- `mining.set_version_mask` — dynamic version mask updates mid-session

## Not Planned

### DigiByte (DGB) Merged Mining
DGB does NOT support AuxPoW with Litecoin despite using Scrypt as one
of its five algorithms. It would require DGB protocol changes (DIP-0012
proposes AuxPoW but for Verthash, not Scrypt).

### Auto-Switch Tool
Automatically switching hash to c2pool based on centralization metrics.
Niche use case — better served by a standalone monitoring tool.

### MEV Dashboard (Litecoin)
Transaction fee analysis showing "how much more you'd earn picking your
own transactions." On Litecoin, fees are ~0.001 LTC/block — not enough
to motivate behavior change. Only relevant for future Bitcoin support.
