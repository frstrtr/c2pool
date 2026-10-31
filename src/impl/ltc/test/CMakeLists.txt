if (BUILD_TESTING AND GTest_FOUND)
    # broadcast_tx_completeness_test.cpp: the LTC/DOGE share-broadcast
    # tx-completeness gate and mark-only-what-was-sent de-dup rule, exercised
    # against the REAL ltc::ShareType variants. FOLDED into the EXISTING
    # allowlisted `share_test` target rather than a new add_executable — a
    # standalone target is absent from build.yml's --target list, so CI would
    # never build it and CTest would report it "Not Run" (the #769 trap).
    #
    # broadcast_lock_discipline_test.cpp: drives a REAL ltc::NodeImpl over a real
    # populated sharechain to pin that broadcast_share invoked under the caller's
    # OWN exclusive tracker lock broadcasts nothing at all — a std::shared_mutex
    # cannot grant a shared lock to a thread already holding it exclusively — and
    # that without that lock the walk runs and the per-peer send loop is entered.
    # Same folding rule: into the existing allowlisted target.
    #
    # auto_ratchet_blocked_by_test.cpp: the VOTING explain-line — asserts the
    # ratchet names the FIRST unmet of its four activation conditions, with the
    # measurement that justifies it, and that an all-pass window logs no blocked
    # line and actually activates. Same folding rule: into the existing
    # allowlisted target.
    #
    # head_retention_test.cpp + share_fetch_failover_test.cpp: the two
    # p2pool-merged-v36 kr1z1s convergence hotfixes ported into c2pool LTC — the
    # clean_tracker head-retention predicate (F2 (#23) + #25(B)) and the
    # parent-fetch failover memory (#25(C)). Both drive the REAL pure headers
    # (head_retention.hpp / share_fetch_failover.hpp) that node.cpp wires in.
    # RED on master semantics, GREEN after the fix. Same folding rule: into the
    # existing allowlisted target (a standalone add_executable would be absent
    # from build.yml's --target list and silently Not-Run — the #769 trap).
    #
    # pool_rate_head_select_test.cpp: the coin-generic dashboard pool-rate
    # HEAD-SELECTION + get_average_stale_prop SSOT (sharechain/
    # pool_rate_head_select.hpp, issue #1482) — verified best when live, else the
    # fastest LIVE raw head; stale-prop = stales/(lookbehind+stales). Pure
    # header-only KAT. Same folding rule: into the existing allowlisted target.
    #
    # ingest_convergence_test.cpp: the admission budget must not defeat the
    # drop-OLDEST liveness policy it sits on top of. A few large deferred
    # batches exhaust MAX_INFLIGHT_SHARES while m_pending_adds is far below
    # MAX_PENDING_ADDS, so the drop-OLDEST branch never runs and the newest,
    # tip-extending batches are the ones refused. RED on budget-only admission,
    # GREEN once admission evicts the oldest deferred batch and retries; the
    # bound of that retry is tested too. Same folding rule: into the existing
    # allowlisted target.
    #
    # ingest_bounds_test.cpp + ingest_ownership_test.cpp: the LTC inbound-share
    # memory bounds that replace the rss_limit_mb self-abort (contabo
    # 2026-09-09..11). The first is KAT + source-structural (IngestBudget,
    # ancestor-walk depth bound, per-peer remembered-tx cap, and the guards that
    # keep the cache eviction WIRED — its predecessor prune_shares had no call
    # site at all). The second drives a REAL ltc::NodeImpl through
    # processing_shares_phase2 to pin share OWNERSHIP: a dropped/duplicate/
    # verify-failed/late-reply share is freed, an adopted one is not. Same
    # folding rule: into the existing allowlisted target.
    #
    # per_peer_ingest_test.cpp: #1600 per-peer ingest-budget fairness — one peer
    # cannot exceed its per-peer slice while others still admit, releases
    # decrement the per-peer counters, and the global ceiling is never exceeded.
    # invalid_pow_score_test.cpp: #1601 conservative invalid-PoW misbehavior
    # scoring — only a sustained genuine PoW-target-miss flood crosses the high,
    # time-decayed threshold; honest/stale/duplicate peers are never penalized.
    # Same folding rule: into the existing allowlisted target (the #769 trap).
    #
    # legacy_addrme_self_probe_test.cpp (#1716, sibling half of #882): drives the
    # REAL ltc::Legacy / ltc::Actual addrme handlers over a REAL loopback socket.
    # Needs NodeImpl + protocol_legacy.cpp from the `ltc` lib already on this
    # target. Same folding rule (the #769 trap).
    #
    # version_switch_floor_test.cpp: the version-switch 60% gate must use the
    # oracle FLOOR threshold (sum*60//100), not the cross-multiplied real 60%,
    # which rejected new == floor(0.6*total) when 60*total is not a multiple of
    # 100. Pure-helper boundary KAT. Same folding rule.
    #
    # ltc_gentx_golden_kat_test.cpp (T5): cross-impl gentx golden-vector KAT.
    # Reproduces the six frozen fixtures from frstrtr/p2pool-merged-v36 f38d6bb7
    # p2pool/test/golden/ (embedded verbatim in ltc_gentx_golden_fixtures.hpp)
    # byte-equal -- witness gentx, stripped gentx, packed share_info, and
    # other_tx_hashes in GBT order -- by driving the REAL LTC production path
    # (generate_share_transaction, compute_ref_hash_for_work, the share
    # Formatter); no coinbase re-implementation in the test. Same folding rule.
    #
    # template_hogex_survives_truncation_test.cpp: the LTC MWEB template shape.
    # Drives the REAL TemplateBuilder: a max_weight-truncated selection still
    # ends with the HogEx and carries mweb, an MWEB-active builder without MWEB
    # state returns nullopt (never a "segwit"-only template), and pins the
    # mainnet/testnet activation heights. Same folding rule.
    #
    # compact_block_mweb_relay_test.cpp: relay_mode_for (a HogEx block always
    # goes out as a full block: a v2 cmpctblock cannot carry mweb) and the
    # sendcmpct highest-version fold. Same folding rule.
    #
    # cmpct_v3_mweb_state_test.cpp: v3 (MWEB) compact blocks over the REAL
    # mainnet block 3200424 (ltc_mweb_cmpct_fixtures.hpp): wire format, HogEx
    # extraction, reconstruction and blocktxn completion carrying the mw::Block
    # into the same MWEB state as the full block, the full-block fallbacks,
    # forged/flipped/replayed commitments never becoming state, BIP 152 SipHash
    # keys, the 65535 limit and the sendcmpct announce order. Same folding rule.
    #
    # cmpct_litecoind_vector_test.cpp: BIP 152 short ids, parse and re-encoding
    # pinned to compact blocks litecoind 0.21.5.6 produced for a regtest block
    # (ltc_regtest_cmpct_fixtures.hpp documents how). Same folding rule.
    #
    # mweb_fetch_retry_test.cpp: the tip full-block fetch retry state machine
    # (schedule, one peer then all, cancel, re-arm, give-up cadence), the MWEB
    # window metrics and the seen-blocks LRU. Same folding rule.
    #
    # mweb_state_hash_binding_test.cpp: MWEB state is bound to the hash of its
    # block; the template builder HOLDs on a sibling's state and builds the
    # HogEx template on the tip's (real block 3200424). Same folding rule.
    #
    # utxo_order_test.cpp: embedded LTC blocks reach the UTXO set strictly in
    # height order (a REAL UTXOViewCache/UTXOViewDB through the utxo_order.hpp
    # helpers the full-block handler uses): out-of-order arrival, a wide gap,
    # a sibling reorg, a reorg while a fill is running, the connect-point check
    # (stale buffered blocks, a pipeline above the UTXO set, a UTXO set on
    # another branch), and the undo records a disconnect uses (#2059): spent
    # coins put back (intra-block spends included), the format-2 record bytes,
    # REAL mainnet blocks 3199539/3199540 disconnected byte-exact against
    # litecoind's coins (ltc_utxo_undo_fixtures.hpp). Same folding rule.
    #
    # mweb_next_header_test.cpp: the MWEB header of the next empty-body block
    # is built as libmw builds it (cumulative roots, txo count and kernel offset
    # carried; kernel root, kernel count and stealth offset zero), byte-equal to
    # REAL mainnet blocks 3200604 and litecoind's 3200605 template
    # (ltc_mweb_tx_fixtures.hpp). Same folding rule.
    #
    # mweb_tx_wire_test.cpp: txs carrying an mw::Transaction (REAL mainnet
    # peg-in and peg-out) parse to the end of the message with litecoind's
    # txid / wtxid / locktime / re-encoding; truncation, trailing bytes and
    # malformed MWEB parts are refused; mw::Block bodies walk exactly with
    # CompactSize lengths; a block with MWEB data in a transaction is refused
    # (unexpected-mweb-data). Same folding rule.
    #
    # mempool_mweb_admission_test.cpp: the embedded LTC mempool refuses what
    # its empty-body MWEB blocks can never carry -- txs with an MWEB part
    # (REAL peg-in / peg-out), pegin outputs without a kernel, empty vin/vout,
    # a loose HogEx -- counted by code with the kernel fees given up. Same
    # folding rule.
    #
    # doge_template_gate_test.cpp: the embedded DOGE template never carries
    # txs its tip confirmed: a pool not cleaned for the tip yields a
    # coinbase-only template marked degraded (a sibling's body does not
    # count), and the merged-mining poll fetches again until it is clean.
    # Same folding rule.
    #
    # doge_utxo_lane_test.cpp: the embedded DOGE UTXO set follows the best
    # chain in height order and through reorgs (#2070): doge::coin::UtxoLane,
    # the object main_ltc.cpp's DOGE full-block and tip handlers call, over a
    # REAL UTXOViewCache/UTXOViewDB -- a taller heavier branch is a reorg,
    # out-of-order bodies connect in order, every block of a new branch is
    # connected, a legacy undo record rebuilds, and a child of a tx confirmed
    # only on the old branch never reaches the template without its parent.
    # Same folding rule.
    #
    # doge_utxo_full_test.cpp: the full DOGE UTXO set (doge::coin::UtxoLane,
    # Mode::Full, over doge_utxo_lane_harness.hpp): armed from height 1 in
    # order within the window, every block from best + 1 after a restart, the
    # mining gate closed until the set is built from genesis, a body spending
    # a coin the set does not hold refused. Same folding rule.
    #
    # doge_utxo_full_wiring_test.cpp: the rules main_ltc's DOGE handlers apply
    # through doge::coin::UtxoFullState (every copy of a deep body placed, the
    # pool's tip never 0, start live only near the tip, the swap on every
    # completion). Same folding rule.
    #
    # doge_mempool_validity_test.cpp: a tx reaches a DOGE template only when
    # priced against the set: a premature coinbase spend is refused at
    # admission, nothing is selected without a view, an orphan waits outside
    # the pool and is admitted priced when its parent is. Same folding rule.
    #
    # doge_hash_schedule_test.cpp: the DOGE block hash at every height below
    # the header checkpoint (doge::coin::HashSchedule), served only once the
    # hash chain links from genesis into the checkpoint. Same folding rule.
    #
    # doge_range_sync_test.cpp: the anchored, parallel hash schedule
    # (doge::coin::RangeSync): exact 2,000-header ranges between anchors, the
    # sequential sync as the fallback, the headers routing. Same folding rule.
    #
    # merged_refresh_request_test.cpp: MergedMiningManager::request_refresh
    # runs one merged-work poll at once (the DOGE tip handler's poke), without
    # the poll timer. Same folding rule.
    #
    # doge_template_budget_test.cpp: embedded DOGE templates dogecoind can
    # accept: a REAL DOGE TemplateBuilder template over a mempool above 1 MB,
    # within the merged-mining size budget, assembles (REAL AuxPoW and PPLNS
    # coinbase producers, 4,000 payees on both chains) to at most 1,000,000
    # bytes (bad-blk-length); curtime and mintime above the median time past
    # (time-too-old). Same folding rule.
    #
    # ltc_template_time_test.cpp: the embedded LTC template's curtime and
    # mintime are above the parent's median time past (time-too-old). Same
    # folding rule.
    #
    # found_block_verify_test.cpp: the dashboard verdict on a found LTC block
    # and a found DOGE block (ltc::coin::found_block, the verifiers main_ltc
    # wires): a side-branch block is never confirmed, a block the chain never
    # saw is orphaned once the chain is 6 deep from its height, a live DOGE
    # tip is not a confirmation, a best-chain block confirms once 6 deep.
    # Same folding rule.
    #
    # merged_found_record_test.cpp: a merged find on a stale job is recorded
    # as the block the share committed to (its hash and height from the
    # frozen snapshot), not the current work. Same folding rule.
    #
    # auxpow_tree_slot_test.cpp: merged-mining chain merkle tree slots are the
    # aux daemons' CAuxPow::getExpectedIndex (#2060): two chains {98, 1} at
    # {0, 1}, colliding ids grow the tree, every proof carries the index and
    # size the daemon checks. Same folding rule.
    #
    # merged_rebuild_payouts_test.cpp: the merged work is always buildable: a
    # rebuild without payouts never commits to the parent's hash (keeps the
    # last block on the same parent, else no commitment), a stale rebuild is
    # not frozen under a newer template, and MergedPayoutSource produces the
    # payouts while the tracker lock is busy. Same folding rule.
    #
    # doge_auxpow_witness_test.cpp: the AuxPoW parent (LTC) coinbase read as
    # Dogecoin Core reads it, witness allowed: REAL mainnet 'headers' entries
    # whose parent coinbase carries the BIP144 witness (h4715979, h5080796,
    # h5641398, h6101857; doge_headers_witness_fixtures.hpp) parse to their
    # count and link, re-emit byte-identical, the stripped form still parses,
    # the txid stays witness-stripped, flag 8 and empty witnesses are refused.
    # Same folding rule.
    #
    # doge_p2p_raw_parser_test.cpp: NodeP2P with a raw (AuxPoW) parser: what
    # it cannot read is delivered by no standard-parse fallback. Same
    # folding rule.
    #
    # doge_headers_parse_test.cpp: a 'headers' message that does not parse to
    # its end yields the clean prefix (entries that link) and truncated_at,
    # never garbage that reads like another chain; the parent coinbase params
    # (wire: witness, no MWEB; txid: stripped). Same folding rule.
    #
    # doge_schedule_witness_test.cpp: the hash schedule fed the parse of the
    # captured witness-coinbase batches (h4715979, h5080796, h5641398,
    # h6101857) extends by the whole batch; an asked peer's answer cuts
    # nothing. Same folding rule.
    # One source per line, sorted: concurrent PRs then edit different lines and stop conflicting (#908).
    add_executable(share_test
        auto_ratchet_blocked_by_test.cpp
        auto_ratchet_sim_test.cpp
        auto_ratchet_tail_guard_test.cpp
        auxpow_tree_slot_test.cpp
        broadcast_lock_discipline_test.cpp
        broadcast_tx_completeness_test.cpp
        build_stops_test.cpp
        chain_topology_endpoints_kat_test.cpp
        chain_walk_window_test.cpp
        cmpct_litecoind_vector_test.cpp
        cmpct_v3_mweb_state_test.cpp
        compact_block_merkle_test.cpp
        compact_block_mweb_relay_test.cpp
        desired_request_pacer_test.cpp
        desired_version_tally_test.cpp
        doge_auxpow_witness_test.cpp
        doge_hash_schedule_test.cpp
        doge_headers_parse_test.cpp
        doge_mempool_validity_test.cpp
        doge_p2p_raw_parser_test.cpp
        doge_range_sync_test.cpp
        doge_schedule_witness_test.cpp
        doge_template_budget_test.cpp
        doge_template_gate_test.cpp
        doge_template_underfill_test.cpp
        doge_utxo_full_test.cpp
        doge_utxo_full_wiring_test.cpp
        doge_utxo_lane_test.cpp
        emergency_decay_overflow_test.cpp
        f11_donation_invariance_test.cpp
        found_block_peer_txid_test.cpp
        found_block_verify_test.cpp
        head_retention_test.cpp
        ingest_bounds_test.cpp
        ingest_convergence_test.cpp
        ingest_ownership_test.cpp
        invalid_pow_score_test.cpp
        legacy_addrme_self_probe_test.cpp
        ltc_gentx_golden_kat_test.cpp
        ltc_template_time_test.cpp
        mempool_mweb_admission_test.cpp
        merged_found_record_test.cpp
        merged_rebuild_payouts_test.cpp
        merged_refresh_request_test.cpp
        mweb_fetch_retry_test.cpp
        mweb_next_header_test.cpp
        mweb_state_hash_binding_test.cpp
        mweb_tx_wire_test.cpp
        peer_block_pow_carry_test.cpp
        per_peer_ingest_test.cpp
        pool_rate_head_select_test.cpp
        restart_reorg_supersede_test.cpp
        self_connection_ban_test.cpp
        share_fetch_failover_test.cpp
        share_message_unpack_bounds_test.cpp
        share_remove_owns_data_test.cpp
        share_test.cpp
        template_hogex_survives_truncation_test.cpp
        template_topology_spend_test.cpp
        utxo_order_test.cpp
        version_switch_floor_test.cpp
        wirecompat_runtime_test.cpp
    )
    target_link_libraries(share_test PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
    )
    target_link_libraries(share_test PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    # #1131 source-structural KAT: verified.remove(bad) must borrow (owns_data=false),
    # not own — folded into this EXISTING allowlisted target (no new executable).
    target_compile_definitions(share_test PRIVATE
        LTC_SHARE_TRACKER_SRC="${CMAKE_CURRENT_SOURCE_DIR}/../share_tracker.hpp"
        C2POOL_IMPL_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../..")   # #1129 5-lane structural guard

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    gtest_add_tests(share_test "" AUTO)
endif()

if (BUILD_TESTING)
    # G3a populated-block production harness (PR #679, LTC parent + DOGE merged-aux).
    # Standalone check()-based main() -- depends only on the header-only
    # core::version_gate SSOT; ctest-registered here so the G3a gate is non-hollow.
    add_executable(ltc_g3a_populated_test g3a_populated_block_regtest_test.cpp)
    target_include_directories(ltc_g3a_populated_test PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/btclibs)
    add_test(NAME LtcG3aPopulated COMMAND ltc_g3a_populated_test)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# ci-allowlist-exempt: ltc_embedded_bootstrap_gate  -- LIVE network gate; built +
# run ONLY by .github/workflows/ltc-embedded-bootstrap-live-gate.yml (real DNS +
# P2P egress). It MUST NOT run inside the hermetic offline `share_test` suite or
# the default build.yml --target list, so it is exempt from the allowlist
# drift-guard by design (a standalone live harness, per the checker's escape
# hatch) and is only defined when its own workflow sets LTC_LIVE_BOOTSTRAP_GATE.
#
# embedded_bootstrap_live_test.cpp: proves the DEFAULT-ON embedded LTC bootstrap
# (main_ltc.cpp `embedded_ltc = true`): DNS-seed resolve -> TCP connect ->
# version/verack -> getheaders -> HeaderChain tip ADVANCES past genesis, against
# the REAL LTC P2P network with no LAN daemon and no hardcoded IP. Fixture name
# is deliberately NOT *LiveTest, so `ctest --exclude-regex 'LiveTest\.'` does not
# silently skip it. The five test/test_phase*_live.cpp harnesses fail all three
# of the acceptance conditions (LAN IP default, *LiveTest name, ctest-excluded);
# this target is the first coverage of the reuse-source bootstrap path.
option(LTC_LIVE_BOOTSTRAP_GATE
       "Build the LTC embedded-bootstrap live network gate (real egress)" OFF)
if (LTC_LIVE_BOOTSTRAP_GATE AND BUILD_TESTING AND GTest_FOUND)
    add_executable(ltc_embedded_bootstrap_gate embedded_bootstrap_live_test.cpp)
    target_link_libraries(ltc_embedded_bootstrap_gate PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)
    target_include_directories(ltc_embedded_bootstrap_gate PRIVATE
        ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/btclibs)
    add_test(NAME LtcEmbeddedBootstrapGate COMMAND ltc_embedded_bootstrap_gate)
    set_tests_properties(LtcEmbeddedBootstrapGate PROPERTIES
        LABELS "live;bootstrap" TIMEOUT 240)
endif()
