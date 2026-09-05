# X2 — monerod adapter (Track X / Family B: Monero/RandomX v37 lane)

Fresh, AGPL-3.0-or-later c2pool code for `frstrtr/c2pool`. New isolated family
under `src/impl/xmr/node/`. Builds on the X1 primitives (base branch
`v37/xmr-x1-primitives @ 11e63a8a`, PR #1502); **re-vendors nothing**. Does not
touch `src/sharechain/v37` consensus digest. Coinbase-output derivation is
**FCMP-fenced** out (that is X6).

## What this leg delivers

A **daemon-ful** monerod adapter that mirrors monerod's best chain and hands the
XMR lane exactly what W2/W4/W5 need — behind a single mockable I/O seam.

| file | role |
|---|---|
| `xmr_node_types.hpp` | value types: `MinerData`, `ChainMainBlock`, `TxBacklogEntry`, `FeeEstimate`, `Difficulty128`, `MainchainEvent {Extend,Reorg,Orphan}`, `DaemonEndpoint`, the three ZMQ topic names |
| `monerod_transport.hpp` | **`IMonerodTransport`** — the one I/O seam (JSON-RPC `rpc_post` + `zmq_subscribe`) — and **`MockMonerodTransport`** for tests (canned RPC bodies, on-demand ZMQ frames, posted-body introspection) |
| `monero_rpc.{hpp,cpp}` | `MoneroDaemonRpc`: `get_miner_data`, `submit_block`, `get_block_header_by_height`, `get_block_headers_range`, `get_block`, `calc_pow`, `get_fee_estimate`. Real request-body builders + typed parsers |
| `monero_zmq.{hpp,cpp}` | `ZmqSubscriber`: decodes `json-full-miner_data` → `MinerData`, `json-minimal-txpool_add` → `[TxBacklogEntry]`, `json-full-chain_main` → `ChainMainZmq` |
| `mainchain_index.hpp` | `MainchainIndex`: by-height + by-id mirror; **RandomX seed resolution with ≥ 2112-block reach** via the X1 primitive `::xmr::coin::rx_seedheight`; fee-sorted tx backlog; **Extend/Reorg/Orphan** event stream; confirmation depth with **no address monitoring** (scoping O5.3) |
| `monero_node_adapter.hpp` | `MonerodAdapter`: wires RPC + ZMQ → index; miner_data-driven tip; RPC seed backfill; `submit_block`; `get_fee_estimate` for `k_live(XMR)` |
| `../test/x2_adapter_kat.cpp` | the light KAT (below) |
| `PROVENANCE.md` | p2pool pattern lineage + AGPLv3 §13 basis; monero-project schema refs |

## The seam (`IMonerodTransport`)

Every byte to/from monerod — JSON-RPC over HTTP and the ZMQ SUB stream — goes
through `IMonerodTransport`. The RPC layer, ZMQ layer and index therefore carry
**no** libuv / cpp-httplib / libzmq / rapidjson dependency and are driven by
`MockMonerodTransport` in tests. Production backs the seam with the engine's
async HTTP client + a libzmq SUB socket (engine/X5 work, out of X2 scope).

## RandomX seed reach — uses the X1 primitive, not a copy

`mainchain_index.hpp` `#include`s the X1 coin-leg header
`impl/xmr/coin/xmr_seedheight.hpp` and calls `::xmr::coin::rx_seedheight()`.
`SEED_REACH_MIN` (2112) is **derived** from `::xmr::coin::SEEDHASH_EPOCH_BLOCKS`
(2048) + `SEEDHASH_EPOCH_LAG` (64), so the node leg and the coin leg can never
disagree on the epoch. (The X1 constants are compile-time, **env-UNtunable** —
monerod's `rx-slow-hash.c` reads an env override for tests that a consensus
verifier must not honor.) Seed anchors reaching ≥ 2112 back are **pinned** on top
of the ~720 recent window so seed resolution never breaks under prune.

## Daemon-ful (recommended) vs. embedded (no)

This is the **daemon-ful** (p2pool) model: talk to an external `monerod` over
RPC + ZMQ; monerod is the fork-choice oracle and the only tx validator; the pool
builds the whole block itself. An **embedded** Monero node (validating
RingCT/FCMP proofs in-process) is the DASH-embedded class × 3 and is **not
recommended** — nothing here pulls monerod's tx-validation stack (scoping §4
item 9).

## Light KAT (no RandomX, no cmake, OOM-safe)

`test/x2_adapter_kat.cpp` — 51 checks, single-TU + 2 small `.cpp`. Feeds a mock
monerod `get_miner_data` and a small reorg through the seam and asserts the index
resolves `seed_height` (≥ 2112 reach, anchor pinning under prune) and surfaces
the Orphan+Reorg events; also covers RPC bodies/parsers, the three ZMQ decoders,
RPC seed backfill, and `submit_block`.

```
g++ -std=c++20 -O1 -I <leg>/src -I /home/ubuntu/x1-verify/src \
    test/x2_adapter_kat.cpp \
    src/impl/xmr/node/monero_rpc.cpp src/impl/xmr/node/monero_zmq.cpp \
    -o /tmp/x2kat && /tmp/x2kat        # RESULT: PASS (0 failures)
```

CI target (CTest): **`xmr-x2-node-kat`** (see `src/impl/xmr/node/CMakeLists.txt`).

## Scope boundaries

- New isolated `src/impl/xmr/` family; does **not** touch `src/sharechain/v37`.
- **FCMP-fence:** no coinbase-output / stealth-key derivation here (X6).
- Not ported from p2pool: `SideChain`/`PoolBlock`/PPLNS/uncles/`split_reward`.
