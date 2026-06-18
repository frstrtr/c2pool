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

    # --- #82 broadcaster-gate: faithful as_block FRAMING -----------------------
    # Pins coin/block_assembly.hpp (share->block reassembly: merkle_root
    # reconstruction from the gentx hash + the share`s merkle_link, then
    # [gentx]++other_txs framing through the live BlockType submitblock codec).
    # Links the dgb OBJECT lib like dgb_share_test because block_assembly.hpp
    # reuses dgb::check_merkle_link (share_check.hpp) as the merkle SSOT. MUST
    # appear in BOTH this registration AND the build.yml --target allowlist.
    add_executable(dgb_block_assembly_test block_assembly_test.cpp)
    target_link_libraries(dgb_block_assembly_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_block_assembly_test "" AUTO)

    # --- M3 RPC-transport standalone regression guards ---------------------
    # Header-only guards over the external-daemon RPC coin-layer SSOTs
    # (rpc_request.hpp request-shape + version floor + genesis identity, and
    # softfork_check.hpp softfork-name collection). They link no OBJECT lib —
    # only GTest + nlohmann_json — so they stay buildable even while the
    # transport rpc.cpp wiring is deferred (Option-B scope). Each MUST appear
    # in BOTH this ctest registration AND the build.yml --target allowlist,
    # or it becomes a #143-style NOT_BUILT sentinel that reds master.

    # --- #82 SSOT gentx coinbase assembler KAT ----------------------------
    # coin/gentx_coinbase.hpp uses core primitives (PackStream/BaseScript/Hash/
    # uint256), so it links the same proven set as dgb_share_test rather than
    # the header-only guard foreach above. Oracle ground-truth vectors. MUST
    # also be in the build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_gentx_coinbase_test gentx_coinbase_test.cpp)
    target_link_libraries(dgb_gentx_coinbase_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_gentx_coinbase_test "" AUTO)

    foreach(dgb_guard rpc_request_test softfork_check_test genesis_check_test algo_select_test digishield_walk_test header_chain_test)
        add_executable(${dgb_guard} ${dgb_guard}.cpp)
        target_link_libraries(${dgb_guard} PRIVATE
            GTest::gtest_main GTest::gtest nlohmann_json::nlohmann_json)
        gtest_add_tests(${dgb_guard} "" AUTO)
    endforeach()
endif()
