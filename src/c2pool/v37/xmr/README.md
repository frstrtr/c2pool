# c2pool-v37-xmr — the live single-node Monero/RandomX daemon (Milestone A)

> **EXPERIMENTAL — PROTOTYPE / STAGENET ONLY. DO NOT RUN AGAINST MAINNET VALUE.**
> This is a research bring-up of the v37 Work-Receipts Family-B (Monero /
> RandomX) settlement lane. It is not audited, not production, and defaults to
> **stagenet**. Mainnet is fenced twice: `--i-understand-mainnet` is required to
> even attempt it, and the X6 coinbase builder is FCMP/CARROT-fenced on the
> Monero hard-fork `major_version` regardless.

This directory is the **daemon lifecycle** that ties the already-merged
Family-B lane code (`src/impl/xmr/`, `src/c2pool/v37/`) into a runnable node.
It defines **no consensus digest**: every consensus operation is delegated to
the merged `V37Engine` / `OwedLedger` / lane executor / X6 coinbase builder.

## Files

| file | role |
|------|------|
| `xmr_node_config.hpp` | config surface (network, monerod RPC/ZMQ, stratum bind, lane params, D_conf) |
| `xmr_settle_store.hpp` | W6 `ISettleStore` seam + `FileSettleStore` + `RecoveryDriver` (fail-closed open) |
| `xmr_finalize_driver.hpp` | **the F1 finalize driver** — `on_block_finalized` once per coin-height, in order, `bin_height` = the high-water AT THE STEP, never the live tip |
| `xmr_node.hpp` | `XmrNode` — owns the wiring + donor lifecycle order |
| `xmr_live_transport.hpp` | production `IMonerodTransport` (dependency-free raw-socket RPC; RPC-poll ZMQ fallback) |
| `xmr_node_smoke.hpp` | shared network-free smoke (monerod stub) |
| `../main_v37_xmr.cpp` | the `c2pool-v37-xmr` entrypoint |
| `../test/v37_xmr_node_smoke.cpp` | CI gate (both build.yml legs) |

## Run

```
# CI / offline smoke (monerod stub, no RandomX, no sockets):
c2pool-v37-xmr --mock-smoke

# against a live stagenet monerod (run monerod with --stagenet --zmq-pub ... and
# an unrestricted/no-login RPC on 38081):
c2pool-v37-xmr --network stagenet --rpc-host 127.0.0.1 --rpc-port 38081 --zmq-port 38083
```

## Construction order (donor lifecycle)

1. install BOTH descriptor backends (P-1 descriptor validator + ed25519
   point-check) and **assert** they are live — else refuse to start (fail-closed);
2. open the W6 settlement store at `config_path()/<net>/v37_settle_db`;
3. run `RecoveryDriver` to rebuild the OWED ledger + high-water + finalize
   cursor **before** `V37Engine::start()` (a torn store aborts — F2);
4. start the engine, seed `AddLane` for the Monero-parent lane;
5. bind the X2 `MonerodAdapter` and route its Extend/Reorg/Orphan stream into
   the F1 finalize driver;
6. start the adapter (ZMQ subscribe + initial RPC sync).

Teardown reverses it: stop the network first, then drain-and-join the engine.

## Hard safety

- **No consensus-digest change.** The daemon calls the merged types; the smoke
  proves the lane digest and `owed_digest` are byte-identical to a bare-library
  replay.
- **F1 contract.** The finalize driver steps per coin-height off the
  mainchain-index progression; it never copies the w4 test harness's
  at-current-tip `reconcile()` shape.
- **FCMP/CARROT fence** stays at the X6 coinbase (`major_version <= 16`).
- **Fail-closed descriptors.** Both backends install at startup or the node refuses to run.

## Known follow-ons (not in this cut)

- Real multi-node p2p carrier relay (`src/pool` p2p) — this cut is single-node.
- Heavy RandomX verify + the X6 coinbase crypto are linked only in the
  CI/stagenet build; the light build runs index + settlement + the F1 driver.
- The W6 store here is a self-contained `FileSettleStore` on merged-master
  types; production swaps in the `v37/w6-persistence` branch's
  `LevelDBSettleStore` + `RecoveryDriver` (same `ISettleStore` shape) once merged.
- Real libzmq SUB (`XMR_NODE_HAVE_ZMQ`) — the default build uses the RPC-poll
  tip fallback.
