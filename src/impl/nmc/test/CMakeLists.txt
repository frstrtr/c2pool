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

    # P1 PC: embedded template builder KATs. Header-only builder
    # (template_builder.hpp / rpc_data.hpp); links the same SCC the sibling
    # merkle test does (core + nmc_coin for the out-of-line transaction ctor).
    add_executable(nmc_template_builder_test nmc_template_builder_test.cpp)
    target_link_libraries(nmc_template_builder_test PRIVATE
        GTest::gtest_main GTest::gtest
        core nlohmann_json::nlohmann_json)
    target_link_libraries(nmc_template_builder_test PRIVATE
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage)
    target_link_libraries(nmc_template_builder_test PRIVATE nmc_coin)

    # P1 card 237: wire-vector KAT. Round-trips the canonical CAuxPow layout
    # against a REAL Namecoin mainnet block (757000). Same SCC as the sibling
    # tests (core + nmc_coin for the out-of-line MutableTransaction ctor).
    add_executable(nmc_auxpow_wire_test auxpow_wire_test.cpp)
    target_link_libraries(nmc_auxpow_wire_test PRIVATE
        GTest::gtest_main GTest::gtest
        core nlohmann_json::nlohmann_json)
    target_link_libraries(nmc_auxpow_wire_test PRIVATE
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage)
    target_link_libraries(nmc_auxpow_wire_test PRIVATE nmc_coin)

    # PE-2e (#251): won-block reconstructor -- the forced-won-share seam +
    # captured-template path (coin/reconstruct_won_block.hpp + block_assembly.hpp).
    # Header-only (pulls BlockType + aux_merkle_root); same SCC the sibling tests
    # link (core + nmc_coin for the out-of-line MutableTransaction ctor).
    add_executable(nmc_reconstruct_won_block_test reconstruct_won_block_test.cpp)
    target_link_libraries(nmc_reconstruct_won_block_test PRIVATE
        GTest::gtest_main GTest::gtest
        core nlohmann_json::nlohmann_json)
    target_link_libraries(nmc_reconstruct_won_block_test PRIVATE
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage)
    target_link_libraries(nmc_reconstruct_won_block_test PRIVATE nmc_coin)

    # P1 PB: Namecoin name-operation relay KATs (coin/mempool.hpp name_* path +
    # fee flow through template_builder.hpp). Same SCC the sibling tests link
    # (core + nmc_coin for the out-of-line MutableTransaction ctor).
    add_executable(nmc_mempool_name_test nmc_mempool_name_test.cpp)
    target_link_libraries(nmc_mempool_name_test PRIVATE
        GTest::gtest_main GTest::gtest
        core nlohmann_json::nlohmann_json)
    target_link_libraries(nmc_mempool_name_test PRIVATE
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage)
    target_link_libraries(nmc_mempool_name_test PRIVATE nmc_coin)

    # PE item 3: dual-path won-aux-block broadcaster contract KAT. Header-only
    # dispatcher (coin/block_broadcast.hpp) -- pulls only core/log.hpp, so it
    # links the same SCC the sibling tests do (core resolves stratum_server refs
    # via the c2pool_* object libs). No nmc_coin needed (no transaction ctor).
    add_executable(nmc_block_broadcast_test nmc_block_broadcast_test.cpp)
    target_link_libraries(nmc_block_broadcast_test PRIVATE
        GTest::gtest_main GTest::gtest
        core nlohmann_json::nlohmann_json)
    target_link_libraries(nmc_block_broadcast_test PRIVATE
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage)

    # PE item 3 (host half): host-level dual-path won-aux broadcaster regression
    # lock. Reconstructs the run-loop binding (set_block_relay -> submit_block_raw
    # + set_fallback_backend -> AuxChainRPC::submit_aux_block) with fakes and
    # locks DELIVERY through both legs -- net-new vs the presence-only helper KAT
    # above. Same header-only dispatcher, so the same SCC (core + c2pool_* object
    # libs); no nmc_coin (no transaction ctor).
    add_executable(nmc_host_dualpath_test nmc_host_dualpath_test.cpp)
    target_link_libraries(nmc_host_dualpath_test PRIVATE
        GTest::gtest_main GTest::gtest
        core nlohmann_json::nlohmann_json)
    target_link_libraries(nmc_host_dualpath_test PRIVATE
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage)

    # PF (fallback-path conformance): locks that the RETAINED external-daemon
    # fallback is the .140 namecoind submitauxblock RPC (a real daemon that can
    # ack), NOT the embedded backend daemon-less submit_aux_block (structurally
    # false). Mis-wiring the fallback to the embedded self-leg silently loses a
    # won block when P2P is down -- this test makes that RED. Same header-only
    # dispatcher SCC (core + c2pool_* object libs); no nmc_coin (no transaction ctor).
    add_executable(nmc_fallback_path_conformance_test nmc_fallback_path_conformance_test.cpp)
    target_link_libraries(nmc_fallback_path_conformance_test PRIVATE
        GTest::gtest_main GTest::gtest
        core nlohmann_json::nlohmann_json)
    target_link_libraries(nmc_fallback_path_conformance_test PRIVATE
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage)

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    gtest_add_tests(nmc_auxpow_merkle_test "" AUTO)
    gtest_add_tests(nmc_template_builder_test "" AUTO)
    gtest_add_tests(nmc_auxpow_wire_test "" AUTO)
    gtest_add_tests(nmc_reconstruct_won_block_test "" AUTO)
    gtest_add_tests(nmc_mempool_name_test "" AUTO)
    gtest_add_tests(nmc_block_broadcast_test "" AUTO)
    gtest_add_tests(nmc_host_dualpath_test "" AUTO)
    gtest_add_tests(nmc_fallback_path_conformance_test "" AUTO)
endif()
