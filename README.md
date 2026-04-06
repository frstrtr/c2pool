# c2pool — P2Pool rebirth in C++

[![CI](https://github.com/frstrtr/c2pool/actions/workflows/build.yml/badge.svg)](https://github.com/frstrtr/c2pool/actions/workflows/build.yml)

C++ reimplementation of [forrestv/p2pool](https://github.com/p2pool/p2pool) targeting the **V36 share format** with Litecoin + multi-chain merged mining (DOGE, PEP, BELLS, LKY, JKC, SHIC). DigiByte Scrypt support planned as an additional parent chain.

Bitcoin wiki: <https://en.bitcoin.it/wiki/P2Pool>
Original forum thread: <https://bitcointalk.org/index.php?topic=18313>

> **First merged-mined DOGE block:** [#6135703](https://blockchair.com/dogecoin/block/f84500c25a4cce2a08887f29763726bd5ecec7b66fed65a88b181fb0b0ab2383) (2026-03-23) — decentralized LTC+DOGE merged mining via P2Pool V36, cross-validated with c2pool on shared share chain
>
> **First daemonless DOGE block:** (2026-03-27) — DOGE block accepted on testnet4alpha via embedded SPV P2P, no dogecoind RPC needed
>
> **First V36 Twin Block:** LTC [#3085349](https://blockchair.com/litecoin/block/3085349) + DOGE [#6154761](https://blockchair.com/dogecoin/block/6154761) (2026-04-05) — simultaneous LTC+DOGE block found by v36-signalling nodes running p2pool v36 producing V35 shares with `desired_version=36`; detected and displayed by c2pool's embedded block scanner

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

# 3 — run (zero config)
./src/c2pool/c2pool
```

That's it. No litecoind, no dogecoind, no config file. The node starts in
**integrated P2P pool mode** with embedded LTC and DOGE SPV nodes, connects
to p2pool sharechain peers via hardcoded bootstrap hosts, and waits for
shares before opening stratum to miners.

Miners connect to stratum and set their LTC payout address as the username
(p2pool convention). No `--address` flag needed.

Full step-by-step guide: [doc/build-unix.md](doc/build-unix.md)

---

## Operating modes

c2pool has four operating modes. The default is a full P2P pool — no flags required.

| Mode | CLI flag | P2P sharechain | Coinbase payouts | Use case |
|------|----------|:-:|---|---|
| **Integrated** | *(default)* | yes | PPLNS from sharechain | Decentralized pool node |
| **Solo** | `--solo` | no | Proportional by miner hashrate | Private pool for own ASICs |
| **Custodial** | `--custodial` | no | 100% to `--address` | Hosted pool, off-chain accounting |
| **Sharechain** | `--sharechain` | yes | *(no mining)* | P2P relay node only |

Legacy `--standalone` mode (minimal stratum + RPC daemon, no embedded SPV) is available for backwards compatibility.

### Startup examples

```bash
# Default: full P2P pool, embedded SPV, wait for peers
./c2pool

# Same, with explicit address for node-owner fee
./c2pool --address YOUR_LTC_ADDRESS --fee 1

# Solo pool for own miners (no sharechain, proportional payouts)
./c2pool --solo

# Custodial pool (all coinbase to operator, stratum for accounting)
./c2pool --custodial --address YOUR_LTC_ADDRESS

# With external LTC daemon instead of embedded SPV
./c2pool --no-embedded-ltc \
  --coind-address 127.0.0.1 --coind-rpc-port 9332 \
  --rpcuser user --rpcpassword pass

# Testnet
./c2pool --testnet

# With config file
./c2pool --config config/c2pool_mainnet.yaml

# Full option reference
./c2pool --help
```

### Feature matrix

| Feature | Integrated | Solo | Custodial | Sharechain |
|---------|:---:|:---:|:---:|:---:|
| Embedded LTC SPV | on | on | on | -- |
| Embedded DOGE SPV | on | on | on | -- |
| Stratum server | yes | yes | yes | -- |
| VARDIFF | yes | yes | yes | -- |
| P2P share exchange | yes | -- | -- | yes |
| PPLNS payouts | yes | -- | -- | -- |
| Proportional payouts | -- | yes | -- | -- |
| Single-address coinbase | -- | -- | yes | -- |
| Merged mining (DOGE etc.) | yes | yes | yes | -- |
| Web dashboard + REST API | yes | yes | yes | -- |
| Per-worker accounting | yes | yes | yes | -- |
| `--address` required | no | no | **yes** | no |
| `--fee` supported | yes | yes | -- | -- |
| Redistribute modes | yes | -- | -- | -- |
| ShareTracker / LevelDB | yes | -- | -- | yes |
| Think loop / monitoring | yes | -- | -- | -- |

### Payout model by mode

| Mode | Who gets paid | How amounts are calculated |
|------|---------------|---------------------------|
| **Integrated** | All miners in PPLNS window | Share weight from sharechain (decentralized consensus) |
| **Solo** | Connected stratum miners | Proportional to real-time hashrate from RateMonitor |
| **Custodial** | Node operator only | 100% of block reward to `--address`; miners tracked in `/stratum_stats` |

In **integrated** and **solo** modes, miners set their payout address as
their stratum username (e.g., `LcAddress.worker1`). The address appears
directly in coinbase outputs. `--address` is optional — it serves as the
node operator's fee destination and fallback when no miners are connected.

In **custodial** mode, miner stratum usernames are used for accounting only
and never appear in coinbase outputs. The backoffice polls `/stratum_stats`
for per-worker hashrate, accepted shares, and connection time.

---

## Defaults

Running `c2pool` with no arguments is equivalent to:

```
--integrated --embedded-ltc --embedded-doge --wait-for-peers
--header-checkpoint 3079000:862daf...
--doge-header-checkpoint 6140000:743b7e...
```

| Setting | Default | Override |
|---------|---------|----------|
| Operating mode | Integrated P2P pool | `--solo`, `--custodial`, `--sharechain`, `--standalone` |
| LTC backend | Embedded SPV (DNS seeds) | `--no-embedded-ltc` (requires RPC daemon) |
| DOGE backend | Embedded SPV | `--no-embedded-doge` (disables merged mining) |
| LTC bootstrap | Block 3,079,000 | `--header-checkpoint HEIGHT:HASH` |
| DOGE bootstrap | Block 6,140,000 | `--doge-header-checkpoint HEIGHT:HASH` |
| Startup mode | Wait for peers (persist=true) | `--genesis` or `--startup-mode auto` |
| Coin daemon | Not required | `--coind-address` / `--coind-rpc-port` |
| `--address` | Optional (miners use stratum username) | Required only for `--custodial` |
| `--fee` | 0% | `-f 1` (1% to `--address`) |
| Stratum port | 9327 | `-w PORT` |
| P2P port | 9326 | `--p2pool-port PORT` |
| Web port | 8080 | `--web-port PORT` |

### Testnet overrides

On `--testnet`, mainnet SPV checkpoints are automatically cleared (testnet
uses a different chain). Ports shift to testnet defaults (P2P 19326,
stratum 19327).

---

## Peer discovery and sharechain bootstrap

The sharechain P2P layer discovers peers from multiple sources:

| Source | Config | Priority |
|--------|--------|----------|
| CLI seed nodes | `-n HOST:PORT` (repeatable) | Highest |
| YAML config | `seed_nodes:` list | Appended to CLI |
| `~/.c2pool/ltc/pool.yaml` | `bootstrap_addrs:` (auto-generated, persists learned peers) | Medium |
| Hardcoded bootstrap hosts | `ml.toom.im`, `usa.p2p-spb.xyz`, + 9 IPs | Fallback |

With `startup_mode: wait` (default), the node waits until peers deliver
shares before opening stratum. This matches p2pool's `PERSIST=True` behavior.

| Startup mode | CLI flag | Behavior |
|-------------|----------|----------|
| **wait** (default) | `--wait-for-peers` | Wait for peers to deliver shares, then mine |
| genesis | `--genesis` | Create first share immediately (new chain) |
| auto | `--startup-mode auto` | Wait 60s for peers, then genesis |

---

## Merged mining

LTC and DOGE have built-in embedded SPV nodes (enabled by default).
Other chains need their daemon running externally.

| Coin | chain_id | Backend | `--merged` example |
|------|----------|---------|---------------------|
| DOGE | 98 | **Embedded SPV** | auto-configured |
| PEP | 63 | External | `PEP:63:127.0.0.1:29377:user:pass` |
| BELLS | 16 | External | `BELLS:16:127.0.0.1:19918:user:pass` |
| LKY | 8211 | External | `LKY:8211:127.0.0.1:9916:user:pass` |
| JKC | 8224 | External | `JKC:8224:127.0.0.1:9770:user:pass` |
| SHIC | 74 | External | `SHIC:74:127.0.0.1:33863:user:pass` |
| DINGO | 98 | External | Cannot run with DOGE (same chain_id) |

DOGE merged mining activates automatically when `--embedded-doge` is on (default).
External daemons use `createauxblock`/`submitauxblock` RPC.

**DigiByte Scrypt** is planned as a second parent chain (`--net digibyte`),
running its own P2Pool sharechain network.

---

## Ports

| Port | Purpose |
|------|---------|
| 9326 | P2Pool sharechain (peer-to-peer) |
| 9327 | Stratum mining |
| 8080 | Web dashboard + REST API |

---

## Configuration

CLI arguments always take priority over YAML values.

```bash
# Use a YAML config file
./c2pool --config config/c2pool_mainnet.yaml
```

See [config/c2pool_mainnet.yaml](config/c2pool_mainnet.yaml) (mainnet) and
[config/c2pool_testnet.yaml](config/c2pool_testnet.yaml) (testnet) for
complete examples with all options documented.

### Configuration reference

| CLI flag | YAML key | Default | Description |
|----------|----------|---------|-------------|
| `--integrated` | `integrated` | **true** | Full P2P pool mode |
| `--solo` | `solo` | false | Solo pool (no sharechain) |
| `--custodial` | `custodial` | false | Custodial pool (single-address coinbase) |
| `--sharechain` | `sharechain` | false | P2P node only (no mining) |
| `--standalone` | -- | false | Legacy solo (RPC daemon, no embedded SPV) |
| `--embedded-ltc` | `embedded_ltc` | **true** | Embedded LTC SPV node |
| `--no-embedded-ltc` | | | Disable embedded LTC, use RPC daemon |
| `--embedded-doge` | `embedded_doge` | **true** | Embedded DOGE SPV for merged mining |
| `--no-embedded-doge` | | | Disable embedded DOGE |
| `--net` | -- | litecoin | Blockchain: `litecoin`, `bitcoin`, `dogecoin` |
| `--testnet` | `testnet` | false | Enable testnet mode |
| `--config FILE` | -- | -- | YAML config file path |
| `--address` | `solo_address` | -- | Node operator payout address (optional) |
| `--give-author` | `donation_percentage` | 0.1 | Developer fee % (p2pool default: 0.5%) |
| `-f` / `--fee` | `node_owner_fee` | 0 | Node owner fee % |
| `--node-owner-address` | `node_owner_address` | -- | Node owner payout address |
| `--redistribute` | `redistribute` | pplns | Mode: pplns/fee/boost/donate |
| `-n HOST:PORT` | `seed_nodes` | -- | Sharechain seed peer (repeatable) |
| `--startup-mode` | `startup_mode` | **wait** | Bootstrap: `wait`, `genesis`, `auto` |
| `--genesis` | | | Shortcut for `--startup-mode genesis` |
| `--wait-for-peers` | | | Shortcut for `--startup-mode wait` |
| `--header-checkpoint` | `header_checkpoint` | mainnet default | LTC SPV starting point (`HEIGHT:HASH`) |
| `--doge-header-checkpoint` | `doge_header_checkpoint` | mainnet default | DOGE SPV starting point |
| `--p2pool-port` | `port` | 9326 | P2P sharechain port |
| `-w` / `--worker-port` | `stratum_port` | 9327 | Stratum mining port |
| `--web-port` | `web_port` | 8080 | HTTP API / dashboard port |
| `--http-host` | `http_host` | 0.0.0.0 | HTTP bind address |
| `--coind-address` | `ltc_rpc_host` | 127.0.0.1 | Coin daemon RPC host |
| `--coind-rpc-port` | `ltc_rpc_port` | auto | Coin daemon RPC port |
| `--rpcuser` | `ltc_rpc_user` | -- | RPC username |
| `--rpcpassword` | `ltc_rpc_password` | -- | RPC password |
| `--max-conns` | -- | 8 | Target outbound P2P peers |
| `--stratum-min-diff` | `min_difficulty` | 0.001 | Vardiff floor |
| `--stratum-max-diff` | `max_difficulty` | 65536 | Vardiff ceiling |
| `--stratum-target-time` | `target_time` | 10 | Seconds between pseudoshares |
| `--no-vardiff` | `vardiff_enabled` | true | Disable auto-difficulty |
| `--max-coinbase-outputs` | `max_coinbase_outputs` | 4000 | Max coinbase outputs |
| `--network-id` | `network_id` | 0 | Private chain identifier (hex) |
| `--log-level` | `log_level` | INFO | trace/debug/info/warning/error |
| `--log-file` | `log_file` | debug.log | Log filename |
| `--log-rotation-mb` | `log_rotation_size_mb` | 100 | Log rotation threshold (MB) |
| `--log-max-mb` | `log_max_total_mb` | 50 | Max rotated log space (MB) |
| `--p2p-max-peers` | `p2p_max_peers` | 30 | Max total P2P peers |
| `--ban-duration` | `ban_duration` | 300 | P2P ban duration (seconds) |
| `--rss-limit-mb` | `rss_limit_mb` | 4000 | RSS memory abort limit (MB) |
| `--cors-origin` | `cors_origin` | -- | CORS Allow-Origin header |
| `--payout-window` | `payout_window_seconds` | 86400 | PPLNS window (seconds) |
| `--storage-save-interval` | `storage_save_interval` | 300 | Sharechain save interval |
| `--dashboard-dir` | `dashboard_dir` | web-static | Static dashboard directory |
| `--analytics-id` | `analytics_id` | -- | Google Analytics measurement ID (e.g. `G-XXXXXXXXXX`); injected into dashboard HTML `</head>` |
| -- | `address_explorer_prefix` | Blockchair | Custom address explorer URL prefix |
| -- | `block_explorer_prefix` | Blockchair | Custom block explorer URL prefix |
| -- | `tx_explorer_prefix` | Blockchair | Custom tx explorer URL prefix |
| -- | `explorer` | false | Enable lite block explorer (stores recent blocks + REST API) |
| -- | `explorer_url` | -- | Explorer URL injected into dashboard nav (e.g. `http://localhost:9090`) |
| -- | `explorer_depth_ltc` | 288 | LTC blocks to keep in explorer store |
| -- | `explorer_depth_doge` | 1440 | DOGE blocks to keep in explorer store |
| `--coinbase-text` | `coinbase_text` | /c2pool/ | Custom coinbase scriptSig text |
| `--message-blob-hex` | -- | -- | V36 authority message blob |
| `--doge-testnet4alpha` | -- | false | Use DOGE testnet4alpha |

---

## API endpoints

| Endpoint | Description |
|----------|-------------|
| `/local_stats` | Local node statistics (peers, hashrates, shares) |
| `/global_stats` | Pool-wide statistics |
| `/current_payouts` | Current PPLNS payout distribution |
| `/recent_blocks` | Recently found blocks |
| `/connected_miners` | Connected stratum workers |
| `/stratum_stats` | Per-worker stratum statistics (hashrate, difficulty, accepted/rejected) |
| `/sharechain_stats` | Share chain state |
| `/miner_thresholds` | Minimum viable hashrate, dust range |
| `/merged_stats` | Merged mining block statistics |
| `/current_merged_payouts` | Current merged mining payouts |
| `/recent_merged_blocks` | Recent merged-mined blocks |
| `/broadcaster_status` | Parent chain broadcaster status |
| `/api/explorer/getblockchaininfo` | Chain info (loopback-only, requires `explorer: true`) |
| `/api/explorer/getblockhash` | Block hash by height (loopback-only) |
| `/api/explorer/getblock` | Full block JSON by hash or height (loopback-only) |

See [docs/DASHBOARD_INTEGRATION.md](docs/DASHBOARD_INTEGRATION.md) for the
complete API reference.

**Web dashboard** — served from `web-static/` by default:

```bash
xdg-open http://localhost:8080/
```

**Lite block explorer** — bundled Python app in `explorer/` for browsing recent blocks:

```yaml
# Enable in config to store blocks + serve REST API
explorer: true
explorer_url: "http://localhost:9090"
```

```bash
# Run the explorer UI against c2pool's API
python3 explorer/explorer.py --ltc-c2pool http://127.0.0.1:8080/api/explorer --web-port 9090
```

The explorer shows block details, decoded coinbase scripts, THE commitment proofs for c2pool-found blocks, and links to Blockchair for transactions/addresses outside the stored range.

**Customization** — both the dashboard (`web-static/`) and the explorer (`explorer/explorer.py`)
are user-customizable components. Edit HTML/JS/CSS in `web-static/` or modify
`explorer/explorer.py` to change the design, add features, or integrate with your
own infrastructure. Block explorer links default to Blockchair but can be overridden
per-node via YAML config:

```yaml
address_explorer_prefix: "https://your-explorer.example.com/address/"
block_explorer_prefix: "https://your-explorer.example.com/block/"
tx_explorer_prefix: "https://your-explorer.example.com/tx/"
```

---

## Coinbase structure

Every block found by c2pool embeds structured data in the coinbase scriptSig:

```
[4]  BIP34 block height (consensus)
[44] AuxPoW merged mining commitment (when active)
[N]  Operator text (--coinbase-text, default "/c2pool/")
[32] THE state root (sharechain state commitment)
[M]  THE metadata (pool analytics, fills remaining space)
     Total: 100 bytes (Bitcoin consensus limit)
```

The THE state root commits the sharechain state at block-find time (PPLNS
distribution, chain height, difficulty). Any node can verify a found block's
payouts match the committed state root.

---

## Authority message blobs (V36)

```bash
# Create transition signal (authority key holder)
python3 util/create_transition_message.py create \
    --privkey <64-hex> \
    --from 36 --to 37 --msg "Upgrade to V37" --urgency recommended

# Pass blob at startup (node operator)
./c2pool --message-blob-hex 01a2b3c4...
```

See [util/README.md](util/README.md) for full documentation.

---

## Private sharechains

```bash
# Start a private chain
./c2pool --network-id DEADBEEF12345678

# Join the same chain
./c2pool --network-id DEADBEEF12345678 -n OPERATOR_IP:9326
```

The `--network-id` overrides the IDENTIFIER hashed into every share's
verification hash. Nodes without the correct ID cannot forge valid shares.
See [above](#configuration-reference) for details.

---

## Build targets

| Target | Description |
|--------|-------------|
| `c2pool` | Primary binary |
| `test_hardening` | Softfork gate + reply-matcher regression tests |
| `test_share_messages` | V36 authority message decrypt/verify tests |
| `test_coin_broadcaster` | Coin peer-manager and broadcaster tests |

```bash
cd build && ctest --output-on-failure -j$(nproc)
```

---

## Status

| Area | Status |
|---|---|
| V36 share format (LTC parent chain) | Active development |
| V36 share format (DGB Scrypt parent chain) | Planned |
| Merged mining (DOGE, PEP, BELLS, LKY, JKC, SHIC) | Working |
| Embedded LTC SPV node | Working |
| Embedded DOGE SPV node | Working |
| Coin daemon RPC/P2P | Hardened |
| Stratum mining server | Working |
| VARDIFF | Working |
| Payout / PPLNS | Working |
| Authority message blobs (V36) | Working |
| Solo / Custodial modes | Working |
| Test suite | 501 tests passing |

> **Need a pool running today?**
> [frstrtr/p2pool-merged-v36](https://github.com/frstrtr/p2pool-merged-v36) — production Python V36 pool (LTC + DGB + DOGE, Docker, dashboard).

---

## Community

- Telegram: <https://t.me/c2pooldev>
- Discord: <https://discord.gg/yb6ujsPRsv>

---

### Install guides
- [Ubuntu / Debian / Linux](doc/build-unix.md)
- [FreeBSD](doc/build-freebsd.md)
- [Windows](doc/build-windows.md)

See [deploy/DEPLOY.md](deploy/DEPLOY.md) for HiveOS/MinerStat/RaveOS setup.
