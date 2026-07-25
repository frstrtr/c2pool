if (BUILD_TESTING AND (GTest_FOUND OR GTEST_FOUND))
    # known_txs_eviction_test.cpp: recency-preserving bounded eviction of the
    # node-level known-tx relay cache (core/known_txs_eviction.hpp), the shared
    # helper that replaces the wholesale m_known_txs.clear() in all four of the
    # LTC/DGB/BCH/BTC node lanes. Header-only over core (uint256), so it is FOLDED
    # into the EXISTING allowlisted core_test target rather than a new
    # add_executable — a standalone target is not in build.yml's --target list, so
    # CI never builds it and CTest reports the cases "Not Run" (the #769 trap). One
    # KAT covers all four coins since they consume one shared core helper.
    add_executable(core_test pack_test.cpp events_test.cpp chain_test.cpp packet_test.cpp block_broadcast_test.cpp broadcast_convergence_matrix_test.cpp core_merkle_branches_test.cpp version_gate_test.cpp filesystem_test.cpp web_server_submitblock_test.cpp known_txs_eviction_test.cpp)
    target_link_libraries(core_test PRIVATE GTest::gtest_main core c2pool_merged_mining GTest::gtest)
    target_link_libraries(core_test PRIVATE c2pool_payout c2pool_hashrate ltc_coin)  # OBJECT-lib SCC direct-naming (#22/#39)

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    # add_test(NAME pack_test COMMAND pack_test)
    gtest_add_tests(core_test "" AUTO)
else()
    message(STATUS "Skipping core tests - GTest not found")
endif()