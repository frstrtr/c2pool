# X2 — monerod RPC + ZMQ adapter skeleton (`src/impl/xmr/node/`)

Foundation leg **X2** of the v37 Work-Receipts XMR settlement lane
("Family B: XMR lane", frstrtr/c2pool, **AGPL-3.0**). Design of record:
`v37-monero-randomx-lane-scoping.md` — §4 item 9, §14.3, §16 rows
(coinbase/settlement), §23 (row "PoW verify path" / "Node plumbing"), and the
X2 WBS row (§5). All Track-X code is **DEFERRED** per the scoping GO/NO-GO; this
is the skeleton with real signatures + p2pool provenance that a later X2 PR
fleshes out.

## What this leg is

The daemon-ful bridge between an **external monerod (≥ v0.18.0.0)** and the XMR
V37Engine. It turns the daemon's JSON-RPC + ZMQ streams into exactly three
things the lane needs, and nothing else:

1. **A bounded mainchain index** with **≥ 2112-block RandomX seed reach**
   (2048 epoch + 64 lag), so any in-window share/receipt can be light-verified
   locally (256 MiB cache) without a daemon round-trip.
2. **A fee-sorted tx backlog** snapshot for the W5 whole-block template builder.
3. **An Extend / Reorg / Orphan event stream** feeding W4 settlement — the piece
   p2pool never surfaces (it buries reorg handling inside its SideChain, the
   pool-model we do not port).

It stores **no address and no output state** (scoping O5.3: "SETTLED + opaque,
never monitor a recipient address"); confirmation depth is measured purely on
the pool's own view of monerod's best chain.

## Files

| File | Role | State |
|---|---|---|
| `src/impl/xmr/node/xmr_node_types.hpp` | Value types (`MinerData`, `ChainMainBlock`, `TxBacklogEntry`, `FeeEstimate`, `MainchainEvent`, `Difficulty128`, `DaemonEndpoint`) | complete, STL-only |
| `src/impl/xmr/node/xmr_node_observer.hpp` | `IMoneroNodeObserver` callback contract (models p2pool `MinerCallbackHandler`) | complete |
| `src/impl/xmr/node/mainchain_index.hpp` | `MainchainIndex`: seed math, ≥2112 reach, anchor-pinning prune, reorg/orphan classification, confirmation depth, backlog | **complete + tested** (header-only) |
| `src/impl/xmr/node/monero_rpc.{hpp,cpp}` | `MoneroDaemonRpc`: the five daemon calls with real request bodies; parse = X2 stub | skeleton |
| `src/impl/xmr/node/monero_zmq.{hpp,cpp}` | `MoneroZmqReader`: the three topics + dispatch; parse = X2 stub | skeleton |
| `src/impl/xmr/node/monero_node_adapter.{hpp,cpp}` | `MoneroNodeAdapter`: wires RPC+ZMQ+index, W4/W5 seam, HF fence | skeleton (orchestration concrete) |
| `src/impl/xmr/node/xmr_node_index_check.cpp` | standalone compile+run check of the index (30 assertions) | **PASS** |
| `PROVENANCE.md` | per-symbol c2pool→p2pool@commit mapping; what is / is NOT ported | — |

## Wiring

```
   external monerod (>= v0.18.0.0)
     |  JSON-RPC (/json_rpc)          |  ZMQ pub (tcp://host:18083)
     |  get_miner_data                |  json-full-miner_data
     |  submit_block                  |  json-full-chain_main
     |  get_block[_header_by_height]  |  json-minimal-txpool_add
     |  get_block_headers_range       |
     |  calc_pow  (optional x-check)  |
     |  get_fee_estimate (k_live)     |
     v                                v
   IJsonRpcTransport            IZmqSubscriber        <- transport seams (mockable,
     |                                |                  no libuv/zmq dep in skeleton)
   MoneroDaemonRpc            MoneroZmqReader
     |                                |  IMoneroNodeObserver
     |                                v  (on_txpool_add / on_miner_data / on_chain_main)
     +--------> MoneroNodeAdapter <---+
                     |
                     |  drives
                     v
                MainchainIndex  --(EventSink)--> EngineHooks.on_mainchain_event --> W4
                     |
                     +-- latest_miner_data() + tx_backlog() --> EngineHooks.on_miner_data --> W5
                     +-- confirmation_depth(id)  --> W4 (vs D_conf = 60)
                     +-- seed_hash_for_height(h)  --> RandomX verify leg (X1)
                     +-- submit_block(blob)       --> W5 publish
```

**Event sourcing rule.** `MainchainIndex::apply()` is driven **only** from
`on_chain_main` (the settled-block stream + RPC backfill), so each real block
yields exactly one Extend/Reorg/Orphan. `on_miner_data` only learns the tip id
(from `prev_id`), refreshes template inputs, and backfills seed anchors — it
never emits a mainchain event. monerod is the fork-choice oracle; the index only
mirrors its best chain and surfaces the delta.

## Deployment: daemon-ful (recommended) vs embedded (do NOT)

- **Daemon-ful** (this design, the p2pool model): talk to an external monerod
  that does all Monero consensus (Levin p2p, RingCT/CLSAG/FCMP proof
  verification, relay, fork choice). c2pool adds only ~256 MiB (light RandomX for
  its own verify), never a second consensus implementation.
- **Embedded** (rejected): an in-process node must fully validate every relayed
  tx (range proofs, ring sigs, post-fork FCMP++ membership proofs) — DASH-embedded
  class ×3, a second consensus-grade codebase with chain-split liability and ~0%
  reuse below the sharechain seam. There is intentionally **no** embedded backend.

## CARROT / FCMP++ fence

This adapter derives **no** coinbase output. It forwards `MinerData.major_version`
to the RandomX-verify leg (algorithm select) and the W5 builder (which owns the
pre-CARROT-fenced derivation), and trips `hardfork_beyond_known()` when the
daemon reports `major_version > XMR_MAX_KNOWN_HF_MAJOR` (=16 as of 2026-09-05),
halting template building rather than building against an unvalidated fork.

## Build / verify (light — OOM-safe)

```
# consensus-relevant logic, compiles and runs (single TU, STL-only):
g++ -std=c++20 -O1 -Wall -Wextra src/impl/xmr/node/xmr_node_index_check.cpp -o /tmp/xmrn && /tmp/xmrn
# => RESULT: PASS (0 failures)   [30 assertions]

# skeleton TUs (no libuv/zmq/rapidjson needed): syntax check only
for f in monero_rpc monero_zmq monero_node_adapter; do
  g++ -std=c++20 -Wall -Wextra -fsyntax-only src/impl/xmr/node/$f.cpp; done
```

## What a later X2 PR must finish (see `open_questions` in the return manifest)

- Wire the rapidjson parses (the only stubs; field paths are documented at each).
- Back `IJsonRpcTransport` with the engine's async HTTP client (digest auth, TLS,
  host failover) and `IZmqSubscriber` with cppzmq on its own thread + a monitor.
- Replace the duplicated seed constants with a single `#include` of the coin
  leg's `impl/xmr/coin/xmr_seedheight.hpp`.
- Supply the chain_main block-id hasher (coin leg) so `on_chain_main` gets a
  canonical id, and the mined-tx-hash → backlog prune inside `parse_chain_main`.
