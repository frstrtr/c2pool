# c2pool — P2Pool rebirth in C++

[![CI](https://github.com/frstrtr/c2pool/actions/workflows/build.yml/badge.svg)](https://github.com/frstrtr/c2pool/actions/workflows/build.yml)

C++ reimplementation of [forrestv/p2pool](https://github.com/p2pool/p2pool) targeting the **V36 share format** with Litecoin + Dogecoin merged mining.

Bitcoin wiki: <https://en.bitcoin.it/wiki/P2Pool>  
Original forum thread: <https://bitcointalk.org/index.php?topic=18313>

---

## Status

| Area | Status |
|---|---|
| V36 share format (LTC) | Active development |
| Merged mining (LTC+DOGE) | Working |
| Coin daemon RPC/P2P | Hardened (softfork gate, keepalive, timeouts) |
| Stratum mining server | Working |
| VARDIFF | Working |
| Payout / PPLNS | Working |
| Authority message blobs (V36) | Working |
| Test suite | 94 tests, all passing |

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
# Integrated mode — full pool (LTC + DOGE merged mining)
./src/c2pool/c2pool --integrated --net litecoin \
  --coind-address 127.0.0.1 --coind-rpc-port 9332 \
  --coind-p2p-port 9333 \
  --merged DOGE:98:127.0.0.1:44556:rpcuser:rpcpass \
  --address YOUR_LTC_ADDRESS \
  litecoinrpc RPCPASSWORD

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

**API endpoints** (integrated mode)

```
GET  /api/stats          pool statistics and hashrate
POST /api/getinfo        pool information
POST /api/getminerstats  per-miner statistics
POST /api/getpayoutinfo  payout balances
```

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
