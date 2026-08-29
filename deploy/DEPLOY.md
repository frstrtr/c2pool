# c2pool Deployment — Mining OS Integration

Integration templates for HiveOS, MinerStat, and RaveOS.

c2pool is a **pool node**, not a standalone miner. It connects to a local Litecoin Core daemon and exposes a Stratum port for miners. The mining OS templates configure c2pool to talk to your litecoind.

## Prerequisites

On every machine running c2pool:
- Litecoin Core (`litecoind`) running and synced
- c2pool binary (build from source or download release)
- For merged mining: Dogecoin Core (`dogecoind`) running

## HiveOS

### Quick Setup

1. Build c2pool and package it:
```bash
cd c2pool && mkdir build && cd build
conan install .. --build=missing --settings=build_type=Release
cmake .. --preset conan-release && cmake --build . --target c2pool -j$(nproc)

# Package for HiveOS
mkdir -p /tmp/c2pool-pkg/c2pool
cp src/c2pool/c2pool /tmp/c2pool-pkg/c2pool/
cp ../deploy/hiveos/h-manifest.conf /tmp/c2pool-pkg/c2pool/
cp ../deploy/hiveos/h-run.sh /tmp/c2pool-pkg/c2pool/
cp ../deploy/hiveos/h-stats.sh /tmp/c2pool-pkg/c2pool/
cp ../deploy/hiveos/h-config.sh /tmp/c2pool-pkg/c2pool/
chmod +x /tmp/c2pool-pkg/c2pool/{h-run.sh,h-stats.sh,h-config.sh,c2pool}
cd /tmp/c2pool-pkg && tar czf c2pool-1.0.0.tar.gz c2pool/
```

2. Upload `c2pool-1.0.0.tar.gz` to a URL accessible from your HiveOS rigs.

3. Create a Flight Sheet:
   - **Miner**: Custom
   - **Installation URL**: `https://your-server/c2pool-1.0.0.tar.gz`
   - **Hash algorithm**: (leave blank)
   - **Wallet and worker template**: Your LTC address (e.g., `ltc1q...`)
   - **Pool URL**: litecoind RPC address (e.g., `127.0.0.1:9332`)
   - **Pass**: litecoind RPC credentials as `user:password`
   - **Extra config arguments** (optional):
     ```
     --merged DOGE:98:127.0.0.1:44556:dogerpc:dogepass --fee 1.0
     ```

### Flight Sheet Fields

| Field | Value | Example |
|-------|-------|---------|
| Pool URL | `litecoind_host:rpc_port` | `127.0.0.1:9332` |
| Wallet | LTC payout address | `ltc1qkek8r3uymzqyajzezqgl99d2f948st5v67a5h3` |
| Password | `rpc_user:rpc_password` | `litecoinrpc:mypassword` |
| Extra config | Additional c2pool CLI flags | `--merged DOGE:98:...` |

### Merged Mining (LTC + DOGE + more)

Add to **Extra config arguments** (one `--merged` per chain):
```
--merged SYMBOL:CHAIN_ID:RPC_HOST:RPC_PORT:RPC_USER:RPC_PASS
```

Supported merged mining chains:

| Coin | chain_id | Default RPC Port | Example |
|------|----------|-----------------|---------|
| DOGE | 98 | 22555 | `--merged DOGE:98:127.0.0.1:22555:dogerpc:dogepass` |
| PEP | 63 | 29377 | `--merged PEP:63:127.0.0.1:29377:peprpc:peppass` |
| BELLS | 16 | 19918 | `--merged BELLS:16:127.0.0.1:19918:bellsrpc:bellspass` |
| LKY | 8211 | 9916 | `--merged LKY:8211:127.0.0.1:9916:lkyrpc:lkypass` |
| JKC | 8224 | 9770 | `--merged JKC:8224:127.0.0.1:9770:jkcrpc:jkcpass` |
| SHIC | 74 | 33863 | `--merged SHIC:74:127.0.0.1:33863:shicrpc:shicpass` |
| DINGO | 98 | 33116 | `--merged DINGO:98:...` (conflicts with DOGE — cannot use both) |

Full example (LTC + DOGE + PEP + BELLS):
```
--merged DOGE:98:127.0.0.1:22555:dogerpc:dogepass \
--merged PEP:63:127.0.0.1:29377:peprpc:peppass \
--merged BELLS:16:127.0.0.1:19918:bellsrpc:bellspass
```

Each merged chain requires its daemon running externally. c2pool connects via RPC (`createauxblock`/`submitauxblock`).

**Note**: DINGO uses chain_id=98 (same as DOGE) — they cannot be merge-mined simultaneously.

### Monitoring

HiveOS dashboard shows:
- Total hashrate (kH/s)
- Accepted/rejected shares
- Pool efficiency
- Per-worker hashrate breakdown

Stats are scraped from c2pool's REST API on port 8080.

## MinerStat

### Setup

1. In MinerStat dashboard, add a **Custom Miner**.
2. Upload the c2pool binary.
3. Set the launch script to `deploy/minerstat/minerstat-config.sh`.
4. Configure pool settings:

| Field | Value |
|-------|-------|
| Pool Host | `127.0.0.1` |
| Pool Port | `9332` |
| Wallet | Your LTC address |
| Password | `rpc_user:rpc_password` |
| Algorithm | `scrypt` |
| Extra params | `--merged DOGE:98:...` (optional) |

## RaveOS

### Setup

1. Package c2pool for RaveOS:
```bash
mkdir -p /tmp/c2pool-raveos/RAVINOS
cp c2pool /tmp/c2pool-raveos/
cp deploy/raveos/manifest.json /tmp/c2pool-raveos/RAVINOS/
cp deploy/raveos/start.sh /tmp/c2pool-raveos/RAVINOS/
cp deploy/raveos/stats.sh /tmp/c2pool-raveos/RAVINOS/
chmod +x /tmp/c2pool-raveos/RAVINOS/{start.sh,stats.sh} /tmp/c2pool-raveos/c2pool
cd /tmp && zip -r c2pool-1.0.0.zip c2pool-raveos/
```

2. Upload to RaveOS Custom Miner Manager.
3. Configure pool settings same as HiveOS (host, port, wallet, password).

## Stratum Miner Configuration

Miners (ASICs, GPU rigs) connect to c2pool's Stratum port:

```
stratum+tcp://C2POOL_HOST:9327
```

### Worker Name Formats

| Format | Example | Description |
|--------|---------|-------------|
| `LTC_ADDR` | `ltc1q...` | LTC payout only |
| `LTC_ADDR,DOGE_ADDR` | `ltc1q...,D...` | LTC + DOGE merged |
| `LTC_ADDR\|DOGE_ADDR` | `ltc1q...\|D...` | Pipe separator (Vnish) |
| `LTC_ADDR.worker` | `ltc1q....rig1` | With worker name |
| `LTC_ADDR+1024` | `ltc1q...+1024` | Fixed difficulty |

### Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 9327 | Stratum (TCP) | Miner connections |
| 8080 | HTTP (REST) | Dashboard + API |
| 9326 | P2P (TCP) | Sharechain network |
