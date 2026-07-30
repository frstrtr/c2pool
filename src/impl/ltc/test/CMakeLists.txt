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
    add_executable(share_test share_test.cpp f11_donation_invariance_test.cpp emergency_decay_overflow_test.cpp wirecompat_runtime_test.cpp desired_version_tally_test.cpp auto_ratchet_sim_test.cpp auto_ratchet_tail_guard_test.cpp chain_walk_window_test.cpp doge_template_underfill_test.cpp broadcast_tx_completeness_test.cpp broadcast_lock_discipline_test.cpp compact_block_merkle_test.cpp)
    target_link_libraries(share_test PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
    )
    target_link_libraries(share_test PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

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
