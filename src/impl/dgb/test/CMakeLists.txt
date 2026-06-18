# DGB module tests. Mirrors src/impl/ltc/test/CMakeLists.txt — links the dgb
# OBJECT lib (pool/share TU) so the share codec + consensus params are build-
# verified into a test executable. Gated on BUILD_TESTING + GTest like the
# sibling coins; registered via gtest_add_tests for the CI --target allowlist.
if (BUILD_TESTING AND GTest_FOUND)
    add_executable(dgb_share_test share_test.cpp)
    target_link_libraries(dgb_share_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
    )
    # OBJECT-lib SCC direct-naming (#22/#39) — mirror the ltc test link set.
    target_link_libraries(dgb_share_test PRIVATE
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    gtest_add_tests(dgb_share_test "" AUTO)

    # --- #82 broadcaster-gate: CoinNode submit/seam contract -----------------
    # Links the dgb OBJECT lib (coin_node.cpp) like dgb_share_test so the live
    # CoinNode::submit_block_hex !m_rpc guard + embedded WorkView slice are
    # build- and run-verified. Pins the external-digibyted RPC fallback half of
    # the won-block dispatch (web_server -> ICoinNode::submit_block_hex).
    add_executable(dgb_coin_node_seam_test coin_node_seam_test.cpp)
    target_link_libraries(dgb_coin_node_seam_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_coin_node_seam_test "" AUTO)

    # --- #82 broadcaster-gate: dual-path won-block dispatcher ----------------
    # Header-only contract test for coin/block_broadcast.hpp (the dispatcher the
    # run-loop wires tracker().m_on_block_found to). Links core for the ICoinNode
    # seam + LOG_* symbols; needs no dgb OBJECT lib (uses a fake ICoinNode).
    add_executable(dgb_block_broadcast_test block_broadcast_test.cpp)
    target_link_libraries(dgb_block_broadcast_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_block_broadcast_test "" AUTO)

    # --- M3 RPC-transport standalone regression guards ---------------------
    # Header-only guards over the external-daemon RPC coin-layer SSOTs
    # (rpc_request.hpp request-shape + version floor + genesis identity, and
    # softfork_check.hpp softfork-name collection). They link no OBJECT lib —
    # only GTest + nlohmann_json — so they stay buildable even while the
    # transport rpc.cpp wiring is deferred (Option-B scope). Each MUST appear
    # in BOTH this ctest registration AND the build.yml --target allowlist,
    # or it becomes a #143-style NOT_BUILT sentinel that reds master.
    foreach(dgb_guard rpc_request_test softfork_check_test genesis_check_test algo_select_test digishield_walk_test header_chain_test)
        add_executable(${dgb_guard} ${dgb_guard}.cpp)
        target_link_libraries(${dgb_guard} PRIVATE
            GTest::gtest_main GTest::gtest nlohmann_json::nlohmann_json)
        gtest_add_tests(${dgb_guard} "" AUTO)
    endforeach()
endif()
