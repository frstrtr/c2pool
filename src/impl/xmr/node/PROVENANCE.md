# Provenance — `src/impl/xmr/node/` (Track X / Family B: XMR lane, X2 monerod adapter)

**Status:** every file in this directory is a **fresh c2pool file**, licensed
**AGPL-3.0-or-later** (the c2pool repo license), authored — **not** a copy of any
p2pool source. No GPLv3 source lines were lifted, so no verbatim GPLv3 file
header travels on these files. What is ported is **Monero-plumbing PATTERNS**
(the *shape* of the RPC/ZMQ glue and the mainchain mirror), which is permitted
into AGPL-3.0 via **AGPLv3 §13**; the pattern sources are cited below so the
lineage is auditable.

## What was ported (patterns only) vs. what was deliberately NOT

**Ported (structure/'shape' only, clean reimplementation):**

- The set of monerod calls a Monero pool needs: `get_miner_data`, `submit_block`,
  `get_block_header_by_height` / `get_block_headers_range`, `get_block`,
  `calc_pow`, `get_fee_estimate`; the JSON-RPC request bodies.
- The three `--zmq-pub` topics a pool subscribes to and their decode intent:
  `json-full-miner_data` (primary new-block/template trigger), `json-minimal-txpool_add`,
  `json-full-chain_main`.
- A bounded mirror of monerod's best chain, keyed by height **and** by id, with
  RandomX-seed retention: `SEEDHASH_EPOCH_BLOCKS = 2048`, `SEEDHASH_EPOCH_LAG = 64`,
  a ~720-block recent window plus pinned seed-epoch anchors.
- The daemon-ful posture: an external monerod is the fork-choice oracle and the
  only tx validator; the pool builds the whole block itself.

**NOT ported (this is the p2pool "pool model" c2pool v37 does not adopt):**

- `SideChain`, `PoolBlock`, PPLNS, uncles, `split_reward`, `get_shares`, the
  deterministic-tx-key coinbase derivation, wallet output-key re-derivation.
- p2pool's in-`SideChain` reorg handling (prev_id walk). v37 instead surfaces an
  explicit **Extend / Reorg / Orphan** event stream at the adapter layer for W4.
- Host-failover lists, TLS SPKI pinning, `api_*`/stats plumbing.

## Pattern sources

| this file | p2pool pattern source (reference only, NOT copied) |
|---|---|
| `xmr_node_types.hpp` | `src/common.h` — `MinerData`, `ChainMain`, `TxMempoolData` |
| `monerod_transport.hpp` | `src/json_rpc_request.h` (`JSONRPCRequest::Call`), `src/zmq_reader.cpp` (`ZMQReader`) — unified here behind one `IMonerodTransport` seam |
| `monero_rpc.{hpp,cpp}` | `src/p2pool.cpp` — `get_miner_data()`, `submit_block()`, `get_seed()`/`update_block_template()` request bodies. `calc_pow` + `get_fee_estimate` are v37 additions (p2pool calls neither). |
| `monero_zmq.{hpp,cpp}` | `src/zmq_reader.cpp` — the three-topic subscribe/dispatch. Field keys follow monero-project `src/serialization/json_object.cpp`. |
| `mainchain_index.hpp` | `src/p2pool.{h,cpp}` — `m_mainchainByHeight`/`m_mainchainByHash`, `get_seed_height()`/`get_seed()`, `cleanup_mainchain_data()`, `BLOCK_HEADERS_REQUIRED = 720`. Seed-height math is **not** duplicated here: it `#include`s the X1 coin-leg primitive `impl/xmr/coin/xmr_seedheight.hpp` (`::xmr::coin::rx_seedheight`). |
| `monero_node_adapter.hpp` | overall p2pool RPC+ZMQ→state wiring; the Extend/Reorg/Orphan stream and the miner_data-driven tip are v37 deltas. |

- **p2pool** — `SChernykh/p2pool`, GPL-3.0. Files cited above at HEAD (v4.x).
  Relicensing basis for the ported patterns: **AGPLv3 §13** (GPLv3 ⇄ AGPLv3 interop).
- **monero-project/monero** — RPC/ZMQ schema and JSON field keys, BSD-3-Clause.
  `src/crypto/rx-slow-hash.c` (seed-height rule, mirrored in the X1 coin leg),
  `src/serialization/json_object.cpp` (ZMQ JSON keys),
  docs.getmonero.org daemon-rpc reference.

## Design-of-record

Scoping note `/home/ubuntu/v37-work/v37-monero-randomx-lane-scoping.md` — §2.2
(node interface), §1.4 item 2 (inverted admission order; ≥ 2112 seed reach),
§4 item 9 (monerod adapter), §5 WBS row **X2**. Base branch
`v37/xmr-x1-primitives @ 11e63a8a` (X1 PR #1502) supplies the vendored primitives
this leg builds on; this leg re-vendors nothing.
