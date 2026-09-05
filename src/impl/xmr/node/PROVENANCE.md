# PROVENANCE — X2 monerod adapter (`src/impl/xmr/node/`)

**Every file in this leg is a fresh, clean-room c2pool file** (AGPL-3.0,
attribution-clean, using `license-manifest/header-templates/agpl-fresh-header.txt`).
No p2pool source lines are copied; the p2pool *patterns* (struct shapes, method
flow, topic set, seed math, prune policy) are reimplemented and cited here and in
per-file banner comments. Per the leg license plan
(`../license-manifest/PROVENANCE.md`), if any later X2 PR instead lifts p2pool
source verbatim into a file, that file switches to
`header-templates/gpl-ported-header.txt` (GPLv3 notice preserved + provenance
line) and is listed in the root `NOTICE`.

## Upstream pin (read 2026-09-05)

| Upstream | License | Pin (tag) | Commit |
|---|---|---|---|
| SChernykh/p2pool | GPL-3.0-only | v4.18 | `128643114f9bea55bfdb95462eaeffa2e3f666bd` |
| monero-project/monero | BSD-3-Clause | v0.18.5.1 | `3d3920d7487b5df7ac388b6b8577fd04d505885f` |

p2pool is portable into the AGPL-3.0 combined work via AGPLv3/GPLv3 §13 (see
`../license-manifest/LICENSING.md`); this leg nonetheless stays clean-room.

## Per-symbol mapping (c2pool ← p2pool pattern)

| c2pool symbol (this leg) | Modelled on p2pool `src/…@128643114` | Adapted / v37 delta |
|---|---|---|
| `MinerData` | `common.h struct MinerData` | `difficulty_type`→`Difficulty128` (explicit u128, no boost); dropped `aux_chains`/`aux_nonce` (v37 places its own owed_digest commitment, OI-W4-6); added `local_recv_ns` |
| `ChainMainBlock` | `common.h struct ChainMain` | added `prev_id` (reorg-by-parent without a daemon round-trip; p2pool defers reorg to SideChain) |
| `TxBacklogEntry` | `common.h struct TxMempoolData` | 1:1 (`id,blob_size,weight,fee,time_received`); the `operator<` fee/byte ordering lives in the W5 selector, not the node leg |
| `Difficulty128` | p2pool `difficulty_type` (uint128) | minimal dependency-free `{lo,hi}` with `<`/`==`; JSON `difficulty`+`difficulty_top64` |
| `IMoneroNodeObserver` | `util.h struct MinerCallbackHandler` | kept `handle_tx`/`handle_miner_data`/`handle_chain_main` (→ `on_txpool_add`/`on_miner_data`/`on_chain_main`); **dropped** `handle_monero_block_broadcast` (pool-model gossip) |
| `MoneroDaemonRpc::get_miner_data` | `p2pool.cpp p2pool::get_miner_data()` (`"method":"get_miner_data"`) | same body; typed `MinerData` result |
| `MoneroDaemonRpc::submit_block` | `p2pool.cpp p2pool::submit_block()` (`"method":"submit_block","params":["<blob>"]`) | same body; typed result |
| `MoneroDaemonRpc::get_block_header_by_height` | `p2pool.cpp` seed download (`get_block_header_by_height`) | used to backfill a missing seed anchor |
| `MoneroDaemonRpc::get_block_headers_range` | `p2pool.cpp update_block_template()` backfill (`get_block_headers_range`) | used on a ZMQ gap resync |
| `MoneroDaemonRpc::get_block` | (scoping §4/§14.3 names `get_block`) | v37: read a won coinbase blob + selected tx bodies; by height or hash |
| `MoneroDaemonRpc::calc_pow` | *not in p2pool.cpp* (it uses its own RandomX) | v37 OPTIONAL daemon-side PoW cross-check during bring-up |
| `MoneroDaemonRpc::get_fee_estimate` | *not called by p2pool* (reward from `median_weight`) | v37 uses it for `k_live(XMR)` (scoping §16 `k_live` row) |
| `IJsonRpcTransport` | `json_rpc_request.h JSONRPCRequest::Call(...)` | abstracted seam (no libuv/httplib/TLS-pinning in skeleton) |
| `MoneroZmqReader` + topic constants | `zmq_reader.{h,cpp}` `set(sockopt::subscribe, "json-full-chain_main" / "json-full-miner_data" / "json-minimal-txpool_add")` + `parse()` dispatch | same three topics + dispatch; transport thread abstracted behind `IZmqSubscriber`; broadcast handler dropped |
| `MainchainIndex::{by_height_,by_hash_}` | `p2pool.h std::map<uint64_t,ChainMain> m_mainchainByHeight; unordered_map<hash,ChainMain> m_mainchainByHash` | same dual index |
| `rx_seed_height` / `SEEDHASH_EPOCH_BLOCKS`(2048) / `SEEDHASH_EPOCH_LAG`(64) | `p2pool.cpp get_seed_height()` + same constants; canonical form from monero `rx-slow-hash.c rx_seedheight()@3d3920d7` | compile-time constants (monerod's env override is a test hook a consensus verifier must not honor); **must** collapse to a single `#include coin/xmr_seedheight.hpp` in-tree |
| `MainchainIndex::seed_hash_for_height` / `get_seed` | `p2pool.cpp p2pool::get_seed()` | `std::optional<Hash>`; drives the RPC backfill of a missing anchor |
| `MainchainIndex::prune` / `required_seed_heights` | `p2pool.cpp cleanup_mainchain_data()` (keep `BLOCK_HEADERS_REQUIRED`=720 recent + the 3-4 live seed anchors) | reach ≥2112 promoted to a first-class invariant; anchors pinned explicitly |
| `MainchainIndex::apply` (Extend/Reorg/Orphan) | *no p2pool analog* — `handle_chain_main` just overwrites `m_mainchainByHeight[h]` | **v37 addition**: explicit event stream for W4 un-confirm; reorg detected by height/parent mismatch against the mirror |
| `MainchainIndex::confirmation_depth` | derived from the by-hash/by-height maps | **v37**: W4 depth vs `D_conf`=60 with NO address monitoring (O5.3) |
| `MoneroNodeAdapter::on_miner_data` (tip upsert) | `p2pool.cpp handle_miner_data()` (upsert `c0`@height, `c1`@height-1 id=prev_id) | backfill-only (no event); event source is `on_chain_main` |
| `MoneroNodeAdapter::on_chain_main` | `p2pool.cpp handle_chain_main()` (remove mined txs, upsert settled row) | single event source into `MainchainIndex::apply` |
| `MoneroNodeAdapter::start` | `p2pool.cpp` get_miner_data bootstrap + ZMQ start | + `refresh_fee_estimate`; + HF tripwire |

## What is explicitly NOT ported (the p2pool POOL-MODEL)

`side_chain.{h,cpp}` (SideChain), `pool_block.{h,cpp}` (PoolBlock share
consensus, `calculate_tx_key_seed`), PPLNS window / `get_shares` / uncle
mechanism, `block_template.{h,cpp}` payout `split_reward`, `p2pool_api.*`,
`params.*` pool options, the found-block p2p gossip (`handle_monero_block_
broadcast`), host-failover + TLS SPKI pinning, merge-mining client. v37 supplies
its own RDWR / work-receipts / K_fair settlement above the sharechain seam; the
W5 coinbase (deterministic `r`, exact-sum residual sink) is a separate leg.

## monerod requirement

`get_miner_data` and the three ZMQ topics require **monerod ≥ v0.18.0.0**. The
daemon must be launched with `--zmq-pub tcp://<host>:<zmq_port>` (default 18083).
