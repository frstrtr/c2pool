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
    add_executable(share_test share_test.cpp f11_donation_invariance_test.cpp emergency_decay_overflow_test.cpp wirecompat_runtime_test.cpp desired_version_tally_test.cpp auto_ratchet_sim_test.cpp auto_ratchet_tail_guard_test.cpp auto_ratchet_blocked_by_test.cpp chain_walk_window_test.cpp doge_template_underfill_test.cpp broadcast_tx_completeness_test.cpp broadcast_lock_discipline_test.cpp compact_block_merkle_test.cpp share_remove_owns_data_test.cpp share_message_unpack_bounds_test.cpp restart_reorg_supersede_test.cpp peer_block_pow_carry_test.cpp head_retention_test.cpp share_fetch_failover_test.cpp pool_rate_head_select_test.cpp template_topology_spend_test.cpp)
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
