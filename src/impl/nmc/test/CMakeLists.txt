# NMC module tests (P1). Mirrors the dgb header-only guard registration in
# src/impl/dgb/test/CMakeLists.txt: gated on BUILD_TESTING + GTest, registered
# via gtest_add_tests for the CI --target allowlist.
#
# nmc_auxpow_merkle_test pins the aux_merkle_root walk in coin/header_chain.hpp
# (the AuxPow merge-mining merkle-branch walk). It links core because the walk
# folds nodes with core::Hash / PackStream; it does NOT link any node/pool/
# share OBJECT lib (none exist for NMC yet -- P0/P1 is coin-tree only).
#
# Each target MUST appear in BOTH this registration AND the build.yml
# --target allowlist, or it becomes a NOT_BUILT sentinel that reds master.
if (BUILD_TESTING AND GTest_FOUND)
    add_executable(nmc_auxpow_merkle_test auxpow_merkle_test.cpp)
    target_link_libraries(nmc_auxpow_merkle_test PRIVATE
        GTest::gtest_main GTest::gtest
        core nlohmann_json::nlohmann_json)
    # core pulls stratum_server.cpp (hashrate refs); link the same OBJECT-lib
    # SCC the sibling dgb merkle test links so core resolves. No node/pool/
    # share/coin libs are needed -- this KAT only folds with core::Hash.
    target_link_libraries(nmc_auxpow_merkle_test PRIVATE
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage)
    # P1b: the check_proof KATs construct AuxPow, whose parent_coinbase member
    # is an nmc::coin::MutableTransaction with an out-of-line ctor -> link the
    # nmc_coin lib (transaction.cpp). Still no node/pool/share libs (none exist).
    target_link_libraries(nmc_auxpow_merkle_test PRIVATE nmc_coin)

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    gtest_add_tests(nmc_auxpow_merkle_test "" AUTO)
endif()
