# c2pool — P2Pool rebirth in C++

[![CI](https://github.com/frstrtr/c2pool/actions/workflows/build.yml/badge.svg)](https://github.com/frstrtr/c2pool/actions/workflows/build.yml)

C++ reimplementation of [forrestv/p2pool](https://github.com/p2pool/p2pool) targeting the **V36 share format** with Litecoin + multi-chain merged mining (DOGE, PEP, BELLS, LKY, JKC, SHIC). DigiByte Scrypt support planned as an additional parent chain.

Bitcoin wiki: <https://en.bitcoin.it/wiki/P2Pool>
Original forum thread: <https://bitcointalk.org/index.php?topic=18313>

> **First merged-mined DOGE block:** [#6135703](https://blockchair.com/dogecoin/block/f84500c25a4cce2a08887f29763726bd5ecec7b66fed65a88b181fb0b0ab2383) (2026-03-23) — decentralized LTC+DOGE merged mining via P2Pool V36, cross-validated with c2pool on shared share chain
>
> **First daemonless DOGE block:** (2026-03-27) — DOGE block accepted on testnet4alpha via embedded SPV P2P, no dogecoind RPC needed

---

## Status

| Area | Status |
|---|---|
| V36 share format (LTC parent chain) | Active development |
| V36 share format (DGB Scrypt parent chain) | Planned |
| Merged mining (DOGE, PEP, BELLS, LKY, JKC, SHIC) | Working |
| Embedded LTC SPV node (`--embedded-ltc`) | Working — blocks accepted on testnet |
| Embedded DOGE SPV node (`--embedded-doge`) | Working — blocks accepted on testnet4alpha |
| Coin daemon RPC/P2P | Hardened (softfork gate, keepalive, timeouts) |
| Stratum mining server | Working |
| VARDIFF | Working |
| Payout / PPLNS | Working |
| Authority message blobs (V36) | Working |
| Test suite | 390 tests, all passing |

> **Need a pool running today?**  
> [frstrtr/p2pool-merged-v36](https://github.com/frstrtr/p2pool-merged-v36) — production Python V36 pool (LTC + DGB + DOGE, Docker, dashboard).

---

## Quick start

```bash
# 1 — prerequisites (Ubuntu 24.04)
sudo apt-get install -y g++ cmake make libleveldb-dev libsecp256k1-dev python3-pip
pip install "conan>=2.0,<3.0" --break-system-packages
conan profile detect --force

# 2 — clone and build
git clone https://github.com/frstrtr/c2pool.git
cd c2pool && mkdir build && cd build
conan install .. --build=missing --output-folder=. --settings=build_type=Debug
cmake .. --preset conan-debug
cmake --build . --target c2pool -j$(nproc)
```

Full step-by-step guide: [doc/build-unix.md](doc/build-unix.md)

---

## Running

```bash
# Integrated mode with embedded SPV (no separate LTC/DOGE daemons needed)
./src/c2pool/c2pool --integrated --net litecoin --embedded-ltc --embedded-doge \
  --address YOUR_LTC_ADDRESS

# Or with external daemons + additional merged chains
./src/c2pool/c2pool --integrated --net litecoin \
  --coind-address 127.0.0.1 --coind-rpc-port 9332 \
  --rpcuser litecoinrpc --rpcpassword RPCPASSWORD \
  --address YOUR_LTC_ADDRESS \
  --merged DOGE:98:127.0.0.1:22555:dogerpc:dogepass \
  --merged PEP:63:127.0.0.1:29377:peprpc:peppass \
  --merged LKY:8211:127.0.0.1:9916:lkyrpc:lkypass

# Testnet quick smoke-test
./src/c2pool/c2pool --integrated --testnet

# Full option reference
./src/c2pool/c2pool --help
```

**Default ports**

| Port | Purpose |
|------|--------|
| 9326 | P2Pool sharechain (peer-to-peer) |
| 9327 | Stratum mining + HTTP API |

**Merged mining chains**

LTC and DOGE have built-in embedded SPV nodes — no separate daemon required.
Other chains need their daemon running externally.

| Coin | chain_id | Daemon | `--merged` example |
|------|----------|--------|--------------------|
| DOGE | 98 | **Embedded SPV** (or external) | `DOGE:98:127.0.0.1:22555:user:pass` |
| PEP | 63 | External (`pepecoind`) | `PEP:63:127.0.0.1:29377:user:pass` |
| BELLS | 16 | External (`bellsd`) | `BELLS:16:127.0.0.1:19918:user:pass` |
| LKY | 8211 | External (`luckycoind`) | `LKY:8211:127.0.0.1:9916:user:pass` |
| JKC | 8224 | External (`junkcoind`) | `JKC:8224:127.0.0.1:9770:user:pass` |
| SHIC | 74 | External (`shibacoind`) | `SHIC:74:127.0.0.1:33863:user:pass` |
| DINGO | 98 | External (`dingocoind`) | Cannot run with DOGE (same chain_id) |

LTC and DOGE use built-in embedded SPV nodes — zero external dependencies for the core LTC+DOGE setup. External daemons use `createauxblock`/`submitauxblock` RPC.

**DigiByte Scrypt** is planned as a second parent chain (`--net digibyte`), running its own P2Pool sharechain network. DGB Scrypt produces valid Scrypt PoW, so it can also merge-mine DOGE and the other AuxPoW coins.

See [deploy/DEPLOY.md](deploy/DEPLOY.md) for HiveOS/MinerStat/RaveOS setup.

**API endpoints** (integrated mode)

```
GET  /local_rate          local pool hashrate
GET  /global_rate         network hashrate
GET  /current_payouts     PPLNS expected payouts
GET  /recent_blocks       blocks found by pool
GET  /global_stats        comprehensive pool stats
GET  /sharechain/stats    sharechain tracker data
GET  /local_stats         p2pool-compatible local stats
POST {jsonrpc}            getinfo, getminerstats, getpayoutinfo, ...
```

**Web dashboard** — served by default from `web-static/`:

```bash
# Built-in dashboard
xdg-open http://localhost:8080/

# Custom dashboard directory
./src/c2pool/c2pool --dashboard-dir /path/to/my-dashboard ...
```

See [docs/DASHBOARD_INTEGRATION.md](docs/DASHBOARD_INTEGRATION.md) for the
complete API reference and custom dashboard development guide.

---

## Authority message blobs (V36)

Node operators distributing upgrade signals or pool announcements use the
standalone Python 3 CLI in [util/](util/):

```bash
# authority key holder — create transition signal
python3 util/create_transition_message.py create \
    --privkey <64-hex> \
    --from 36 --to 37 --msg "Upgrade to V37" --urgency recommended

# node operator — pass blob at startup
./src/c2pool/c2pool ... --message-blob-hex 01a2b3c4...
```

See [util/README.md](util/README.md) for full documentation.

---

## Configuration

c2pool supports configuration via CLI arguments, YAML config file, or both.
CLI arguments always take priority over YAML values.

```bash
# Use a YAML config file
./src/c2pool/c2pool --config config/c2pool_testnet.yaml

# Or pass everything via CLI
./src/c2pool/c2pool --integrated --testnet --net litecoin \
    --p2pool-port 19338 -w 19327 --web-port 8080 ...
```

### Configuration reference

| CLI flag | YAML key | Default | Description |
|----------|----------|---------|-------------|
| `--net` | — | — | Blockchain: `litecoin`, `bitcoin`, `dogecoin` |
| `--testnet` | — | off | Enable testnet mode |
| `--p2pool-port` | `port` | 9326 | P2P sharechain port |
| `-w` / `--worker-port` | `stratum_port` | 9327 | Stratum mining port |
| `--web-port` | `http_port` | 8080 | HTTP API / dashboard port |
| `--http-host` | `http_host` | 0.0.0.0 | HTTP bind address |
| `--coind-address` | `ltc_rpc_host` | 127.0.0.1 | Coin daemon RPC host |
| `--coind-rpc-port` | `ltc_rpc_port` | auto | Coin daemon RPC port |
| `--rpcuser` | `ltc_rpc_user` | — | RPC username |
| `--rpcpassword` | `ltc_rpc_password` | — | RPC password |
| `--address` | — | — | Payout address |
| `--give-author` | `donation_percentage` | 0 | Developer donation % |
| `-f` / `--fee` | `node_owner_fee` | 0 | Node owner fee % |
| `--node-owner-address` | `node_owner_address` | — | Node owner payout addr |
| `--redistribute` | `redistribute` | pplns | Mode: pplns/fee/boost/donate |
| `--max-conns` | — | 8 | Target outbound P2P peers |
| `--stratum-min-diff` | `min_difficulty` | 0.0005 | Vardiff floor |
| `--stratum-max-diff` | `max_difficulty` | 65536 | Vardiff ceiling |
| `--stratum-target-time` | `target_time` | 10 | Seconds between pseudoshares |
| `--no-vardiff` | `vardiff_enabled` | true | Disable auto-difficulty |
| `--max-coinbase-outputs` | `max_coinbase_outputs` | 4000 | Max coinbase outputs |
| `--log-file` | `log_file` | debug.log | Log filename |
| `--log-level` | `log_level` | trace | trace/debug/info/warning/error |
| `--log-rotation-mb` | `log_rotation_size_mb` | 10 | Log rotation threshold (MB) |
| `--log-max-mb` | `log_max_total_mb` | 50 | Max rotated log space (MB) |
| `--p2p-max-peers` | `p2p_max_peers` | 30 | Max total P2P peers |
| `--ban-duration` | `ban_duration` | 300 | P2P ban duration (seconds) |
| `--rss-limit-mb` | `rss_limit_mb` | 4000 | RSS memory abort limit (MB) |
| `--cors-origin` | `cors_origin` | * | CORS Allow-Origin header |
| `--payout-window` | `payout_window_seconds` | 86400 | PPLNS window (seconds) |
| `--storage-save-interval` | `storage_save_interval` | 300 | Sharechain save interval |
| `--dashboard-dir` | `dashboard_dir` | web-static | Static dashboard directory |
| `--coinbase-text` | `coinbase_text` | — | Custom coinbase scriptSig text (see below) |
| `--message-blob-hex` | — | — | V36 authority message blob |
| `--embedded-ltc` | — | off | Use embedded SPV for LTC (no litecoind needed) |
| `--network-id` | `network_id` | 0 | Private chain identifier (hex, see below) |

See [config/c2pool_testnet.yaml](config/c2pool_testnet.yaml) for a complete example.

---

## Coinbase customization

Every block found by c2pool embeds structured data in the coinbase
scriptSig. The 100-byte scriptSig is partitioned as follows:

```
┌─────────────────────────────────────────────────────────────────┐
│ [4]  BIP34 block height (consensus required)                    │
│ [44] AuxPoW merged mining commitment (when merged mining active)│
│ [N]  Tag or operator text (see below)                           │
│ [32] THE state root (sharechain state commitment)               │
│ [M]  THE metadata (pool analytics, fills remaining space)       │
└─────────────────────────────────────────────────────────────────┘
  Total: 100 bytes (Bitcoin consensus limit)
```

**Operator text (`--coinbase-text`)**

By default, c2pool uses `/c2pool/` (8 bytes) as the tag. Node operators
can replace this with custom text via `--coinbase-text`:

```bash
# Default: "/c2pool/" tag
./src/c2pool/c2pool --integrated ...

# Custom: your node name
./src/c2pool/c2pool --integrated --coinbase-text "EU-Node1" ...

# Custom: pool branding
./src/c2pool/c2pool --integrated --coinbase-text "MyPool.io" ...
```

**Size limits** (enforced at startup):

| Mode | Max text | Reason |
|------|----------|--------|
| With merged mining | **20 bytes** | AuxPoW commitment uses 44 bytes |
| Without merged mining | **64 bytes** | No AuxPoW overhead |

c2pool is always identified by the **combined donation address** in
coinbase outputs (visible in any block explorer) — the scriptSig tag
is optional branding, not the primary identifier.

**THE state root** (32 bytes, always present)

Commits the sharechain state at block-find time:
- PPLNS weight distribution snapshot
- Sharechain height and chain parameters
- Epoch metadata (difficulty, pool hashrate)

This enables trustless checkpoints: any c2pool node can verify that
a found block's PPLNS distribution matches the committed state root.

**THE metadata** (variable, fills remaining space after tag)

| Byte | Field | Description |
|------|-------|-------------|
| 0 | version | Protocol version (0x01 = V36) |
| 1-4 | sharechain_height | Share chain height at block-find |
| 5-6 | miner_count | Unique miners in PPLNS window |
| 7 | hashrate_class | log2(pool hashrate in H/s) |
| 8-15 | chain_fingerprint | 0=public, SHA256d(PREFIX\|\|IDENTIFIER)[0:8]=private |
| 16-17 | share_period | Current share period (seconds) |
| 18-19 | verified_length | Verified chain length |

Metadata is truncated from the end when space is limited (e.g., long
operator text reduces metadata space).

---

## Private sharechains

c2pool supports private sharechains for isolated mining networks.

```bash
# Start a private chain (operator)
./src/c2pool/c2pool --integrated --network-id DEADBEEF12345678 \
  --net litecoin --address YOUR_LTC_ADDRESS ...

# Join the same private chain (miner)
./src/c2pool/c2pool --integrated --network-id DEADBEEF12345678 \
  -n OPERATOR_IP:9326 ...
```

**How it works:**

The `--network-id` overrides the IDENTIFIER used in share consensus
verification. p2pool uses two-layer network isolation:

| Layer | Value | Security |
|-------|-------|----------|
| Transport | PREFIX (derived from network-id) | Filters connections — visible on wire |
| Consensus | IDENTIFIER (= network-id) | Hashed into every share's `ref_hash` — **secret** |

A node that doesn't know the network-id **cannot forge valid shares**
because the IDENTIFIER is hashed into every share's verification hash.
Sharing the network-id with a miner grants them sharechain access.

**Genesis behavior:** When the chain is empty, c2pool automatically
creates genesis shares — no special flag needed. The first miner
solution becomes the genesis share, and the chain grows from there.
Peers that connect later download shares from the genesis node.

**Security:** The IDENTIFIER is never stored raw on the blockchain — it is
the consensus secret. The `chain_fingerprint` in THE metadata is
`SHA256d(PREFIX || IDENTIFIER)[0:4]` — a 4-byte cryptographic fingerprint
using Bitcoin's standard double-SHA256. Even if the PREFIX is sniffed from
network traffic, the IDENTIFIER half requires 2^64 brute force to recover.
Blockchain scanners can group blocks by fingerprint without learning the
secret needed to join the chain.

Default `--network-id 0` = public p2pool network (standard IDENTIFIER).

---

## Build targets

| Target | Description |
|--------|-------------|
| `c2pool` | Primary binary |
| `test_hardening` | Softfork gate + reply-matcher regression tests |
| `test_share_messages` | V36 authority message decrypt/verify tests |
| `test_coin_broadcaster` | Coin peer-manager and broadcaster tests |

Run all tests:
```bash
cd build && ctest --output-on-failure -j$(nproc)
```

---

## Community

- Telegram: <https://t.me/c2pooldev>
- Discord: <https://discord.gg/yb6ujsPRsv>

---

<details>
<summary>Donations</summary>

### PayPal
[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=9DF676HUWAHKY)

</details>

---

### Install guides
- [Ubuntu / Debian / Linux](doc/build-unix.md)
- [FreeBSD](doc/build-freebsd.md)
- [Windows](doc/build-windows.md)

---

## API endpoints

See [docs/DASHBOARD_INTEGRATION.md](docs/DASHBOARD_INTEGRATION.md) for the complete HTTP API reference, including:

- Native c2pool endpoints (hashrate, payouts, stats, blocks, miners)
- p2pool legacy endpoints (local_stats, web/version, etc.)
- Merged mining endpoints (merged_stats, recent_merged_blocks, discovered_merged_blocks, current_merged_payouts, etc.)
- JSON-RPC methods (getinfo, getminerstats, getpayoutinfo, submitblock, etc.)

**Merged mining endpoints:**

| Endpoint                   | Description                       |
|---------------------------|-----------------------------------|
| `/merged_stats`           | Merged mining block statistics     |
| `/current_merged_payouts` | Current merged mining payouts      |
| `/recent_merged_blocks`   | Recent merged-mined blocks         |
| `/all_merged_blocks`      | All merged-mined blocks            |
| `/discovered_merged_blocks` | Merged block proofs               |
| `/broadcaster_status`     | Parent chain broadcaster status    |
| `/merged_broadcaster_status` | Merged chain broadcaster status |
| `/network_difficulty`     | Historical network difficulty      |

For full field details and dashboard integration, see [docs/DASHBOARD_INTEGRATION.md](docs/DASHBOARD_INTEGRATION.md).
