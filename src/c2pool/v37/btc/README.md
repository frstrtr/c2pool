# c2pool-v37-btc — the live single-node BITCOIN-FAMILY daemon (Milestone A-BTC)

The sibling of Milestone A-XMR. It wires the coin-agnostic, MERGED v37 engine to
the mature v36 Bitcoin-family coin plumbing to make a runnable, testnet-capable
BTC-family node. EXPERIMENTAL / prototype — **DASH regtest/devnet default, do not
run in production.** Mainnet is a loud opt-in (`--i-understand-mainnet`).

## What is native here

The BTC-family PayoutDescriptor canon (`src/sharechain/v37/v37_descriptor.hpp`:
P2PKH/P2SH/P2WPKH/P2WSH/P2TR/RAW) is the **NATIVE ratified V37.0 canon** —
SHA-256d/Scrypt/X11 PoW is native. **No P-1 activation, no X6, no RandomX.** The
W5 coinbase (`w5_coinbase.hpp`) is the native BTC-family coinbase.

| file | role |
|------|------|
| `btc_node_config.hpp` | config surface: coin (dash/ltc), network (regtest default), daemon RPC endpoint, stratum bind, lane params, D_conf |
| `btc_coin_backend.hpp` | `ICoinBackend` — the v36 coin-adapter seam (mainchain view / canonicality / subsidy / submit); `MockCoinBackend` for the smoke; Dash/Ltc production bindings (GAP, CI leg) |
| `btc_settle_store.hpp` | W6 `ISettleStore` seam + Mem/File store + `RecoveryDriver` (F2 fail-closed) |
| `btc_finalize_driver.hpp` | the live **F1** driver the node runs (same contract, adds W6 write-ahead persistence) |
| `btc_node.hpp` | `XbtcNode` lifecycle: `open()` → `start()` → `on_tip()`/`on_block_won()` → `stop()` |
| `btc_node_smoke.hpp` | `run_btc_node_smoke()` — shared body |
| `dash_rpc_coin_backend.hpp` | `DashRpcCoinBackend` — the REAL `ICoinBackend` for ONE `dashd -regtest`/`-devnet` over the v36 `dash::coin::NodeRPC` client (getblockchaininfo / getblockheader tri-state / getblocktemplate miner-spendable value / submitblock); chain-tag + regtest-genesis fence; D6 byte-order pin; `height_of()` (D8). HEAVY TU (Boost/jsonrpccxx) — `c2pool-v37-btc-dash` only, never the Threads-only leg |
| `block_event_driver.hpp` | `BlockEventDriver` — coin-agnostic, header-only sequencer of FOUND → FINALIZED → ORPHANED into `XbtcNode`; write-ahead pending-FOUND sidecar + `reseed_after_open()` restart re-drive (D10) through `BtcFinalizeDriver::reseed_found`; D11 poll-side reorg re-check; the one GAP-7 mutex |
| `../main_v37_btc_dash.cpp` | the `c2pool-v37-btc-dash` entrypoint — the live DASH-regtest daemon (v36 `DASHWorkSource` + `core::StratumServer` front-end, height-watch, exit codes 2..9) |
| `../tools/runbook_dash_regtest.sh` | the VM100 A1–A9 DASH-regtest runbook (Dash Core v23.1.7 pinned); the runtime gate of the heavy leg — operator-run only |
| `../settle_finalize_driver.hpp` | the coin-agnostic **F1** driver, **byte-for-byte the driver A-XMR runs** (`c2pool::v37n::settle::FinalizeDriver`); the node's `btc_finalize_driver.hpp` is the persistence-integrated wrapper of this same per-height contract (unifying the two is the noted follow-on) |
| `../main_v37_btc.cpp` | the `c2pool-v37-btc` entrypoint |
| `../test/v37_btc_node_smoke.cpp` | lifecycle smoke — CI gate (both build.yml legs) |
| `../test/v37_btc_digest_drift_kat.cpp` | drift-guard (HARD SAFETY 1) |
| `../test/f1_finalize_kat_btc.cpp` | **F1 falsifier KAT** over `settle_finalize_driver.hpp`: per-height/burst/restart catch-up == real-time, O5.5 shorter-branch refusal, and the jump-to-tip driver **forks** the owed_digest (7 checks) |

## The construction / donor order (open before start)

1. **`open()` — durable side, BEFORE the engine spins:** build the `ISettleStore`;
   `RecoveryDriver::recover()` rebuilds the `OwedLedger` + `SettleHW` + finalize
   cursor (F2: a torn store returns false → the daemon refuses to start);
   construct the `BtcFinalizeDriver` seeded with the recovered cursor + event seq,
   its `CanonicalFn` bound to the coin backend's `is_canonical()`.
2. **`start()` — live side:** `V37Engine::start()`; `AddLane(lane_chain,
   lane_params)` through the engine (so the lane digest is the executor's); bind
   the v36 `core::StratumServer` to the stratum endpoint; run the height-watch
   (`poll_tip()` → `BtcFinalizeDriver::advance_to_tip()`).
3. **`stop()` — donor teardown:** network down first, then `V37Engine::stop()`
   drains-and-joins.

## The v36 seams reused (wired, not rewritten)

- **Stratum front-end:** `core::stratum::IWorkSource` + `core::StratumServer`
  (`src/core/stratum_work_source.hpp`); BTC impl `btc::stratum::BTCWorkSource`
  (`src/impl/btc/stratum/work_source.hpp`), LTC impl `core::MiningInterface`.
  `IWorkSource::mining_submit` classifies PoW ≤ block target → submit.
- **DASH mainchain view (embedded-SPV, daemonless):** `dash::coin::chain_rpc`
  getbestblockhash/getblockhash/getblockchaininfo from `HeaderChain`
  (`src/impl/dash/coin/chain_rpc.hpp`, `header_chain.hpp`); reception feed
  `dash::interfaces::TipAdvance`/`BlockConnected` (`node_interface.hpp`).
- **DASH work/template:** `dash::coin::select_dash_work` / `build_embedded_workdata`
  (`work_source.hpp`, `embedded_gbt.hpp`), bundle `dash::coin::NodeCoinState`.
- **DASH block submit:** `dash::coin::reconstruct_won_block` →
  `dash::coin::won_block_dispatch` (`won_block_dispatch.hpp`): ARM A
  `CoinClient::submit_block_p2p_raw`, ARM B `NodeRPC::submit_block_hex`.
- **Subsidy:** `dash::coin::subsidy` (creditPool-aware) / LTC `GetBlockSubsidy`.
- **v37 engine types:** `c2pool::v37n::V37Engine` (`v37_engine.hpp`),
  `c2pool::v37n::settle::OwedLedger` + `SettleHW` (`w4_settlement.hpp`),
  `c2pool::v37n::coinbase::assemble` (`w5_coinbase.hpp`).

## Run

```
c2pool-v37-btc --selftest   # network-free lifecycle invariants (CI-runnable)
# live (CI/heavy leg): --coin dash --network regtest --daemon-rpc 127.0.0.1:19998 --stratum-bind 127.0.0.1:3032
```
