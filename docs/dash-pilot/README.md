# Dash pilot (v37 btc-dash arm): T1-prep

This directory holds the design record for the DASH testnet pilot of the v37
settlement arm (`c2pool-v37-btc-dash`).

| file | what |
|---|---|
| `04-residual-rule.md` | where the unallocated block value goes (sink / donation / PPLNS), the accounting identity, the first D_conf blocks. Needs a ruling |
| `05-arming-finality-and-v0x03.md` | ChainLock vs D_conf arming, the C/K_max/h_min pilot caps, the v0x03 payout-set wire, RECON and the flag day. Needs rulings |

## What T1-prep changed (branch `v37/dash-t1-prep`)

1. **Pool identity fails closed.** `--pool-payout-address ADDR` is required. It
   is decoded under the stratum door's acceptance set for the selected network
   and must be P2PKH or P2SH. It replaces the fixed `0xB0…` placeholder.
2. **`--settlement off|on`**, default off. Off is byte-identical to the
   previous binary: W5 emission is withheld and `payout_emitted = 0` on the
   wire. On is refused until the v0x03 wire lands (note 5). There is
   deliberately no pool-id flag. That belongs to the roundabout S1 `lane_tag`
   track (seam note in `btc_node_config.hpp`).
3. **The reward is verified at fold time** (`btc/mined_block_verify.hpp`).
   * Own fold: it reads the miner slice of the coinbase this node **mined**,
     never the cached GBT value. The template at the same (height, parent)
     only names the masternode and burn payee scripts. Their amounts are read
     from the mined outputs, because those amounts scale with the block's
     fees (see "Soak finding, round 899" below). After an accepted submit, a
     self-check asks dashd the same question the peers ask
     (`own_postcheck_ok/mismatch`).
   * Peer fold: dashd must have the block on the best chain at `H_b`, and the
     reward must equal `sum(coinbase vout) - masternode payments(bid)`.
   * At superblock-cycle heights the block is VALUELESS on every node,
     because treasury payments cannot be reconstructed after the fact.
   * Every refusal is counted on the `stop:` line as `s1v{…}`.
   * KAT: `v37_t1_reward_verify_kat`.
4. **Round-523 crash fix** (see below).

## The round-523 crash (soak 2026-09-18)

* **Symptom:** nodeA died within 1 s of boot with a SIGSEGV. The kernel logged
  `segfault at 60 … error 6` on a worker thread. There was no core file
  (`ulimit -c 0`, and apport is the handler), and the supervisor discarded the
  node's log.
* **Symbolized:** the fault address maps to
  `boost::asio::detail::epoll_reactor::register_descriptor`
  (`epoll_reactor.ipp:164`, `descriptor_data->reactor_ = this`, boost 1.83).
  After taking the descriptor mutex, the code re-reads the per-descriptor slot
  and finds it NULL, so another thread had deregistered or closed the same
  socket in between.
* **Root cause:** `main_v37_btc_dash.cpp` called the **async**
  `NodeRPC::connect()` and then, straight away,
  `DashRpcCoinBackend::wait_ready()` on the main thread. The two threads then
  drove the same `m_stream`:
  * the io thread ran `async_resolve → async_connect → check()`, and on
    failure `m_stream.close()`;
  * the main thread's first `Send()` failed with EBADF and ran
    `sync_reconnect()`, which does `m_stream.close()` and a blocking
    `connect()` under `m_rpc_mutex`.

  The two threads never shared a lock.
* **It happened on every boot:** 23 of the 24 preserved round logs open with
  `CoindRPC write failed: Bad file descriptor — reconnecting...` /
  `reconnected (sync)`, then `...CoindRPC connected!` about 3 ms later, which
  is two connects of one socket. In round 885 the race resolved the other way:
  the io thread closed the live socket, and the main thread then logged 117
  `read failed: Bad file descriptor`. Round 523 was the tightest interleaving,
  and it crashed. The crash rate is about 1 in 1,786 node boots, but the
  degraded shape happened in nearly every boot.
* **Fix:** `NodeRPC::connect_sync()` (additive, `src/impl/dash/coin/rpc.*`) sets
  the same request/auth state, then connects on the caller thread under
  `m_rpc_mutex`, and never schedules async socket work. The v37 arm uses it.
  The v36 `c2pool-dash` keeps `connect()` unchanged.
* **Harness:** `supervise.sh` now runs with `ulimit -c unlimited` and keeps a
  node's log on a boot failure (`evidence/bootfail-*.log`).

## Soak finding, round 899 (first binary e9d2aefc, fixed in the follow-up commit)

* **What happened:** the first T1-prep binary computed the own-win slice as
  `sum(mined coinbase) - template.payments`. In round 899, nodeB mined block
  `000000247da2…ea5f` (h=1558847) and folded 59525746. NodeA asked dashd and
  got `sum(vout) - masternode payments = 59526072`. NodeA refused the claim
  (`reward_mismatch=1`), credited nothing, and counted it.
* **Why:** the masternode and platform-burn amounts are a fixed share of
  (subsidy + fees of the mined block). The stratum work source mined a block
  from its own GBT, with no fee-paying transactions. The backend's cached GBT
  at the same (height, parent) held 434 duffs of fees, so its payment total
  was 326 duffs higher.
* **Fix:** match the template's payee scripts to the mined outputs and
  subtract the mined amounts (`non_miner_amount`), and add the post-submit
  self-check. The KAT pins it (`4b`).
* **Did the ledgers diverge?** No. The block was still pending when both
  nodes stopped, and a pending FOUND does not enter `owed_digest`, so the
  digests stayed equal. The refusal is permanent on the peer, though. If the
  winner had later finalized its credit, the owed_digest check would have
  caught the divergence. The strict verdict stayed green on that round, but
  the `s1v` counters named the fault.
