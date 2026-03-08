# c2pool — Roadmap & Future Enhancements

> Derived from [p2pool-merged-v36 FUTURE.md](../ref/docs/FUTURE.md) and
> [POOL_HOPPING_ATTACKS.md §7.3](../ref/docs/POOL_HOPPING_ATTACKS.md).
> Tracks what has been ported, what remains, and what's new for c2pool.

---

## Porting Status from p2pool-merged-v36

### Done

| Feature | Evidence |
|---------|----------|
| V36 share format (ratchet, AutoRatchet, `PUBKEY_TYPE`) | `src/impl/ltc/share.hpp`, `share_check.hpp` |
| Merged mining (auxpow, multi-chain coinbase, `submitauxblock`) | `src/c2pool/merged/merged_mining.hpp/.cpp` |
| Address conversion (P2PKH / P2WPKH / P2SH) | `src/core/address_validator.cpp` |
| Share redistribution (`--redistribute pplns\|fee\|boost\|donate`) | `src/impl/ltc/redistribute.hpp` |
| Transition messaging — ECDSA-signed share signals | `src/impl/ltc/share_messages.hpp` (verify + create) |
| Share message creation (`ecdsa_sign`, `pack_message`, `create_message_data`) | `src/impl/ltc/share_messages.hpp` |
| WeightsSkipList — O(log n) PPLNS weight computation | `src/sharechain/weights_skiplist.hpp` |
| Pool statistics / hashrate tracking | `src/impl/ltc/pool_monitor.hpp`, `src/c2pool/hashrate/tracker.hpp` |
| Event-driven caching (Boost.Signals2) | `src/core/events.hpp` |
| Worker auto-banning (300 s default) | `src/impl/ltc/node.hpp` ban list |
| CLI safeguards (`--testnet`, `--dev-donation`, etc.) | `src/c2pool/c2pool_refactored.cpp` |
| Persistent storage (LevelDB) | `src/c2pool/storage/sharechain_storage.cpp` |
| REST API (`/api/stats`, `/api/getinfo`, `/current_payouts`, …) | `src/core/web_server.cpp` |
| VARDIFF (automatic difficulty adjustment) | `src/c2pool/hashrate/` |
| Stratum server (HTTP / JSON-RPC) | `src/core/web_server.cpp` |
| secp256k1 linked for ECDSA | root `CMakeLists.txt` |

### Partial

| Feature | What exists | Gap |
|---------|-------------|-----|
| Stratum monitor web UI | REST endpoints at `/api/*` | No dedicated `/stratum_stats` page |
| Block-found callback | `m_on_block_submitted` callback fires | No HTTP webhook delivery (POST to external URL) |

### Not Yet Ported

| Feature | Ref source | Priority | Notes |
|---------|-----------|----------|-------|
| Graduated boost redistribution | `FUTURE.md §redistribute` | Medium | Weight by `uptime × pseudoshares × difficulty` |
| Hybrid redistribute mode | `FUTURE.md §redistribute` | Medium | `--redistribute boost:70,donate:20,fee:10` |
| Share-rate threshold boost | `FUTURE.md §redistribute` | Low | Boost "unlucky" miners below expected weight |
| Stratum `mining.ping` / pong | `FUTURE.md §1` | Low | Connection health monitoring |
| SSL/TLS stratum | `FUTURE.md §2` | Medium | `--stratum-ssl-port`, `--ssl-cert`, `--ssl-key` |
| `mining.set_version_mask` | `FUTURE.md §4` | Low | Dynamic version-rolling mask mid-session |
| `client.show_message` | `FUTURE.md §5` | Low | Operator → miner broadcast |
| Prometheus `/metrics` endpoint | `FUTURE.md §8` | Medium | Standard scrape format for Grafana |
| Block-found webhook delivery | `FUTURE.md §9` | Low | `--block-webhook URL` with HTTP POST |
| Historical worker stats DB | `FUTURE.md §10` | Low | SQLite persistence + retention policy |
| Direct peer block broadcast | `FUTURE.md §16` | High | Parallel P2P broadcast to reduce orphan rate |

---

## V37 Adaptive PPLNS Windows

> Reference: [POOL_HOPPING_ATTACKS.md §7.3.10–§7.3.13](../ref/docs/POOL_HOPPING_ATTACKS.md)

### Background

V36 uses a **fixed** `CHAIN_LENGTH = 8640` shares for the PPLNS window.
V37 proposes an **adaptive** window that scales with pool hashrate to cover
a constant fraction (50 %) of the expected time-to-block (TTB):

```
adaptive_chain_length = min(MAX_WINDOW,
    max(MIN_WINDOW, expected_ttb * TARGET_COVERAGE / SHARE_PERIOD))
```

At Litecoin mainnet conditions (target 2.5 min blocks), the window size at
various pool hashrates:

| Pool Hashrate | Adaptive Window | Wall Time |
|---------------|-----------------|-----------|
| 295 GH/s (peak) | 51,573 shares | ~9 days |
| 72 GH/s (average) | 211,111 shares | ~37 days |
| **49.5 GH/s (current)** | **307,996 shares** | **~53.5 days** |
| 10 GH/s | 1,519,200 shares | ~265 days |

Recommended upper bound: `40 × CHAIN_LENGTH` = **345,600 shares** (~60 days).

### WeightsSkipList Performance — No Changes Needed

The current `WeightsSkipList` (O(log n) with geometric random levels, max
height 30) handles adaptive windows with zero performance concerns:

| Window Size | Skip List Steps | Query Time |
|-------------|-----------------|------------|
| 8,640 (V36 fixed) | ~13 | ~0.04 ms |
| 51K (peak hashrate) | ~16 | ~0.05 ms |
| **308K (current)** | **~18** | **~0.09 ms** |
| 1.5M (10 GH/s) | ~21 | ~0.12 ms |

The reference analysis (§7.3.13) explicitly states: **"Not a bottleneck."**
Union-Find does not apply here — it solves disjoint set connectivity, not
range-weighted-sum queries. The skip list is the correct data structure.

### What V37 Actually Requires

#### P0: `get_adaptive_chain_length()`

New consensus function computing the adaptive window from `pool_aps` and
`block_target`. Needs integration into share validation and PPLNS payout.

```cpp
uint64_t get_adaptive_chain_length(uint256 block_target,
                                   double pool_aps,
                                   uint64_t min_window,
                                   uint64_t max_window,
                                   double target_coverage,
                                   uint64_t share_period);
```

#### P0: IncrementalVestingCache

The **real bottleneck** for adaptive windows is vesting computation — an O(n)
walk over the entire window. At 308K shares this takes ~616 ms (naive),
consuming 4–200 % of a share period.

The solution is an incremental cache using exponential decay running sums:

| Pool Hashrate | Naive O(n) | Incremental O(1) | Speedup |
|---------------|------------|-------------------|---------|
| 295 GH/s | ~103 ms | ~0.003 ms | 34,000× |
| **49.5 GH/s** | **~616 ms** | **~0.003 ms** | **205,000×** |
| 10 GH/s | ~3,049 ms | ~0.003 ms | 1,016,000× |

Implementation: `on_new_share()` updates per-address running sums with
`decay_factor = 2^(-work / half_life)`. Uses O(log n) repeated squaring
for `decay_power()` and 40-bit fixed-point integer arithmetic for
consensus-safe deterministic results.

Startup cost: one full O(n) rebuild, then all incremental. Optional
periodic resync every ~10K shares to prevent fixed-point drift.

#### P0: Share Compaction (Tiered Storage)

At 308K shares × ~4.5 KB/share = **~1.39 GB RAM**. Three-tier architecture:

| Tier | Scope | Content | RAM |
|------|-------|---------|-----|
| **Hot** (Tier 1) | PPLNS window (308K shares) | Full share objects | ~1.39 GB |
| **Warm** (Tier 2) | Vesting tail (window+1 to 2×window) | Per-address per-epoch aggregates | ~1.3 MB |
| **Cold** (Tier 3) | Historical (on-disk SQLite) | Wire-format shares for crash recovery | ~150–400 MB disk |

Epoch size: 720 shares (~3 hours). Each epoch summary replaces 720 full
share objects (~216 KB) with one ~100-byte record — **2,160× compression**.

#### P1: Adaptive Window Consensus Integration

- Share validation must agree on `adaptive_chain_length` given the same
  chain state — deterministic computation from on-chain data only.
- PPLNS payout, vesting, and share redistribution all parameterized by
  the adaptive window instead of a constant.
- Version ratchet: V37 shares opt into adaptive windows; mixed V36/V37
  chains use `max(V36_CHAIN_LENGTH, adaptive_chain_length)` during
  transition.

---

## Stratum Protocol Enhancements (from p2pool-merged-v36)

### `mining.ping` — Not Started
Connection health monitoring via ping/pong. Detects dead connections faster.
Low priority — existing TCP keepalives cover most cases.

### SSL/TLS Stratum — Not Started
Encrypted stratum connections. Protects against MITM and hash-rate hijacking.
Requires `boost::asio::ssl::stream` wrapping of existing TCP sockets.

```
--stratum-ssl-port PORT
--ssl-cert FILE
--ssl-key FILE
```

### `mining.set_version_mask` — Not Started
Dynamic version-rolling mask updates mid-session without reconnection.

### `client.show_message` — Not Started
Broadcast operator messages to all connected miners.

---

## Infrastructure Enhancements (from p2pool-merged-v36)

### Prometheus `/metrics` — Not Started
Standard Prometheus text format for Grafana dashboards. Stats already exist
in REST endpoints — needs a format adapter producing:

```
p2pool_connected_workers 6
p2pool_pool_hashrate 948000000000
p2pool_shares_accepted 15234
p2pool_blocks_found 3
```

### Block-Found Webhook — Partial
Callback infrastructure exists (`m_on_block_submitted`). Needs HTTP POST
delivery to a configurable URL (`--block-webhook URL`).

### Historical Worker Stats DB — Not Started
Persist per-worker statistics to SQLite with configurable retention.

### Direct Peer Block Broadcast — Not Started
Parallel P2P broadcast of found blocks to multiple full nodes to reduce
orphan rate. High impact for solo miners.

---

## Share Redistribution Enhancements (from p2pool-merged-v36)

### Graduated Boost — Not Started
Weight boost eligibility by `uptime × pseudoshare_count × avg_difficulty`
instead of equal probability. Data sources already available in stratum
session state.

### Hybrid Mode — Not Started
Split redistributed shares across multiple modes:

```
--redistribute boost:70,donate:20,fee:10
```

Single-mode syntax (`--redistribute boost`) backward-compatible at 100 %.

### Share-Rate Threshold Boost — Not Started
Extend boost to miners whose PPLNS weight is < 10 % of their expected
contribution based on stratum pseudoshare rate.

---

## Phased Roadmap

| Phase | Focus | Key Items |
|-------|-------|-----------|
| **Current** | V36 compatibility | Feature parity with p2pool-merged-v36 (mostly done) |
| **Next** | Observability | Prometheus metrics, block webhook delivery, `/stratum_stats` |
| **V37 prep** | Adaptive windows | `get_adaptive_chain_length()`, IncrementalVestingCache, share compaction |
| **V37** | Anti-hopping defense | Adaptive PPLNS consensus, vesting with exponential decay |
| **Later** | Stratum hardening | SSL/TLS, `mining.ping`, graduated boost, hybrid redistribute |

---

## References

- [p2pool-merged-v36 FUTURE.md](../ref/docs/FUTURE.md) — original roadmap
- [POOL_HOPPING_ATTACKS.md](../ref/docs/POOL_HOPPING_ATTACKS.md) — V37 adaptive window design (§7.3.10–§7.3.13)
- [V36_RELEASE_NOTES.md](../ref/docs/V36_RELEASE_NOTES.md) — V36 feature set
- [CHANGELOG.md](../ref/CHANGELOG.md) — p2pool-merged-v36 change history
