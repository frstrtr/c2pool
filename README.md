# c2pool — P2Pool rebirth in C++

[![CI](https://github.com/frstrtr/c2pool/actions/workflows/build.yml/badge.svg)](https://github.com/frstrtr/c2pool/actions/workflows/build.yml)

C++ reimplementation of [forrestv/p2pool](https://github.com/p2pool/p2pool) targeting the **V36 share format** with Litecoin + multi-chain merged mining (DOGE, PEP, BELLS, LKY, JKC, SHIC).

Bitcoin wiki: <https://en.bitcoin.it/wiki/P2Pool>  
Original forum thread: <https://bitcointalk.org/index.php?topic=18313>

---

## Status

| Area | Status |
|---|---|
| V36 share format (LTC) | Active development |
| Merged mining (DOGE, PEP, BELLS, LKY, JKC, SHIC) | Working |
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
# Integrated mode — full pool (LTC + multi-chain merged mining)
./src/c2pool/c2pool --integrated --net litecoin \
  --coind-address 127.0.0.1 --coind-rpc-port 9332 \
  --rpcuser litecoinrpc --rpcpassword RPCPASSWORD \
  --address YOUR_LTC_ADDRESS \
  --merged DOGE:98:127.0.0.1:22555:dogerpc:dogepass \
  --merged PEP:63:127.0.0.1:29377:peprpc:peppass \
  --merged BELLS:16:127.0.0.1:19918:bellsrpc:bellspass \
  --merged LKY:8211:127.0.0.1:9916:lkyrpc:lkypass

# Testnet quick smoke-test
./src/c2pool/c2pool --integrated --testnet

# Full option reference
./src/c2pool/c2pool --help
```

**Default ports**

| Port | Purpose |
|------|--------|
| 9338 | P2Pool sharechain (peer-to-peer) |
| 9327 | Stratum mining + HTTP API |

**Merged mining chains** — each requires its daemon running externally:

| Coin | chain_id | `--merged` example |
|------|----------|--------------------|
| DOGE | 98 | `DOGE:98:127.0.0.1:22555:user:pass` |
| PEP | 63 | `PEP:63:127.0.0.1:29377:user:pass` |
| BELLS | 16 | `BELLS:16:127.0.0.1:19918:user:pass` |
| LKY | 8211 | `LKY:8211:127.0.0.1:9916:user:pass` |
| JKC | 8224 | `JKC:8224:127.0.0.1:9770:user:pass` |
| SHIC | 74 | `SHIC:74:127.0.0.1:33863:user:pass` |

All chains use `createauxblock`/`submitauxblock` RPC. See [deploy/DEPLOY.md](deploy/DEPLOY.md) for HiveOS/MinerStat/RaveOS setup.

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
| `--p2pool-port` | `port` | 9338 | P2P sharechain port |
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
| `--stratum-min-diff` | `min_difficulty` | 0.001 | Vardiff floor |
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

See [config/c2pool_testnet.yaml](config/c2pool_testnet.yaml) for a complete example.

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
