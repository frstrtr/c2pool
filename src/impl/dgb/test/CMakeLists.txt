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

    # --- embedded-ingest HeaderSample builder ---------------------------------
    # Pins coin/header_sample_build.hpp: a parsed BlockHeaderType -> HeaderSample
    # (block_hash = sha256d(80-byte header), target = SetCompact(nBits)), the
    # boundary that feeds HeaderChain::validate_and_append and lights up
    # tip_hash() -> previousblockhash. Links the dgb OBJECT lib like
    # dgb_block_assembly_test because it pulls block.hpp (BlockHeaderType codec)
    # + core Hash/pack. MUST appear in BOTH this registration AND the build.yml
    # --target allowlist.
    add_executable(dgb_header_sample_build_test header_sample_build_test.cpp)
    target_link_libraries(dgb_header_sample_build_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_header_sample_build_test "" AUTO)

    # --- #82: won-block reconstructor BODY (as_block composition) ----------
    # Pins coin/reconstruct_won_block.hpp: the single composition the dispatch
    # handler injects as its WonBlockReconstructor (resolve_other_tx_hashes ->
    # assemble_other_txs -> assemble_won_block). Links the dgb OBJECT lib like
    # dgb_block_assembly_test because it pulls block_assembly.hpp (BlockType /
    # MutableTransaction / check_merkle_link). MUST appear in BOTH this
    # registration AND the build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_reconstruct_won_block_test reconstruct_won_block_test.cpp)
    target_link_libraries(dgb_reconstruct_won_block_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_reconstruct_won_block_test "" AUTO)

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

    # --- #172 share-path gentx KAT (collapse consumption proof) ------------
    # Proves generate_share_transaction (the verification SSOT call site #172
    # rewired) EMITS assemble_gentx_coinbase framing for a real v36 share, via
    # a round-trip equivalence (the op_return ref_hash is share-derived, so it
    # cannot be pinned to a fixed oracle vector). Links the dgb OBJECT lib like
    # dgb_share_test. MUST also be in the build.yml --target allowlist (#143).
    add_executable(dgb_gentx_share_path_test gentx_share_path_test.cpp)
    target_link_libraries(dgb_gentx_share_path_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_gentx_share_path_test "" AUTO)

    # --- #82 sub-slice 1: transaction_hash_refs -> other_tx hash walk -------
    # coin/other_tx_resolver.hpp is the won-block reconstructor`s connecting
    # tissue (faithful get_other_tx_hashes ancestry resolution). It pulls
    # uint256 (SetHex TU) via share_types.hpp, so it links the proven dgb OBJECT-lib SCC set (like dgb_block_assembly_test)
    # rather than the header-only guard foreach (linking bare `core` drags in
    # web_server.cpp, whose symbols live in the SCC libs). The tracker ops are
    # injected, so no dgb pool state is exercised. MUST also appear in the
    # build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_other_tx_resolver_test other_tx_resolver_test.cpp)
    target_link_libraries(dgb_other_tx_resolver_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_other_tx_resolver_test "" AUTO)

    # --- #82 sub-slice 2: other_tx hashes -> MutableTransaction other_txs ---
    # coin/other_tx_assembler.hpp is the won-block reconstructor`s bridge from
    # the resolved other_tx hash list (sub-slice 1) to the deserialized txs that
    # assemble_won_block frames (faithful as_block known_txs[h] lookup). Links
    # the dgb OBJECT lib like dgb_block_assembly_test because the end-to-end KAT
    # frames through dgb::check_merkle_link + the live BlockType codec. MUST also
    # appear in the build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_other_tx_assembler_test other_tx_assembler_test.cpp)
    target_link_libraries(dgb_other_tx_assembler_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_other_tx_assembler_test "" AUTO)

    # --- #82: gentx-bytes -> MutableTransaction unpack (inverse of #173) ----
    # coin/gentx_unpack.hpp turns the share's SSOT non-witness gentx bytes back
    # into the MutableTransaction reconstruct_won_block injects at tx index 0.
    # Pulls PackStream/Hash/uint256 + transaction.hpp, so it links the proven
    # dgb OBJECT-lib SCC set like dgb_gentx_coinbase_test. Oracle round-trip +
    # inverse-pairing KAT. MUST also appear in the build.yml --target allowlist
    # (#143 NOT_BUILT trap).
    add_executable(dgb_gentx_unpack_test gentx_unpack_test.cpp)
    target_link_libraries(dgb_gentx_unpack_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_gentx_unpack_test "" AUTO)
    # --- #82 miner-facing path: DGBWorkSource (IWorkSource) Stage 4a skeleton -
    # Constructs dgb::stratum::DGBWorkSource over the live coin deps and pins
    # the IWorkSource contract + real-now surface (config/atomics/workers).
    # Links dgb_stratum + the same proven SCC set as the sibling dgb tests.
    # MUST also be in the build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_work_source_test work_source_test.cpp)
    target_link_libraries(dgb_work_source_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb dgb_stratum
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain
        nlohmann_json::nlohmann_json)
    gtest_add_tests(dgb_work_source_test "" AUTO)

    # dgb_template_builder_test: guards the build_work_template SSOT
    # (Stage 4c extraction). Pure JSON-shaping function -> guard-weight
    # linkage: the only out-of-line dep reachable through template_builder.hpp
    # -> rpc_data.hpp -> core/uint256.hpp is declarations only (no uint256
    # method is invoked), so GTest + nlohmann_json suffice. MUST also be in the build.yml
    # --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_template_builder_test template_builder_test.cpp)
    target_link_libraries(dgb_template_builder_test PRIVATE
        GTest::gtest_main GTest::gtest
        nlohmann_json::nlohmann_json)
    gtest_add_tests(dgb_template_builder_test "" AUTO)

    # dgb_embedded_coin_node_test: guards EmbeddedCoinNode, the SECOND caller
    # of the build_work_template SSOT (proves the embedded + stratum work
    # paths cannot diverge). Pulls header_chain.hpp + embedded_coinbase_value.hpp
    # + core/pow.hpp -> links the same proven SCC set as dgb_work_source_test.
    # MUST also be in BOTH build.yml --target allowlists (#143 NOT_BUILT trap).
    add_executable(dgb_embedded_coin_node_test embedded_coin_node_test.cpp)
    target_link_libraries(dgb_embedded_coin_node_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb dgb_stratum
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain
        nlohmann_json::nlohmann_json)
    gtest_add_tests(dgb_embedded_coin_node_test "" AUTO)


    foreach(dgb_guard rpc_request_test softfork_check_test genesis_check_test algo_select_test digishield_walk_test)
        add_executable(${dgb_guard} ${dgb_guard}.cpp)
        target_link_libraries(${dgb_guard} PRIVATE
            GTest::gtest_main GTest::gtest nlohmann_json::nlohmann_json)
        gtest_add_tests(${dgb_guard} "" AUTO)
    endforeach()
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

    # --- #82 dual-path won-block broadcaster contract ----------------------
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

    # --- #82 broadcaster-gate: won-block DISPATCH handler --------------------
    # Header-only contract test for coin/won_block_dispatch.hpp (the handler the
    # run-loop wires tracker().m_on_block_found to: reconstruct share->block,
    # then fire broadcast_won_block dual-path). Links core for the ICoinNode seam
    # + LOG_* symbols; uses a fake ICoinNode + stub reconstructor, no OBJECT lib.
    add_executable(dgb_won_block_dispatch_test won_block_dispatch_test.cpp)
    target_link_libraries(dgb_won_block_dispatch_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_won_block_dispatch_test "" AUTO)


    # header_chain_test compiles the btclibs Scrypt PoW TU set DIRECTLY (the
    # same crypto/*.cpp sources btclibs builds, with the same default flags) so
    # the M3 7b digest conversion is exercised against the REAL
    # scrypt_1024_1_1_256 hash, not a synthetic digest. Only the scrypt + SHA256
    # family is pulled in -- NOT the full btclibs archive (its siphash.o needs
    # the removed base_uint<256> symbol) and NOT core/the dgb OBJECT lib. This
    # is linking against an existing scrypt.cpp, no shared source modified: the
    # single DGB smoke gate holds, no shared-base flag owed. Same target name,
    # so it stays in BOTH build.yml --target allowlists unchanged.
    set(_dgb_scrypt_tus
        ${CMAKE_SOURCE_DIR}/src/btclibs/crypto/scrypt.cpp
        ${CMAKE_SOURCE_DIR}/src/btclibs/crypto/sha256.cpp
        ${CMAKE_SOURCE_DIR}/src/btclibs/crypto/sha256_sse4.cpp
        ${CMAKE_SOURCE_DIR}/src/btclibs/crypto/sha256_sse41.cpp
        ${CMAKE_SOURCE_DIR}/src/btclibs/crypto/sha256_avx2.cpp
        ${CMAKE_SOURCE_DIR}/src/btclibs/crypto/sha256_shani.cpp)
    add_executable(header_chain_test header_chain_test.cpp ${_dgb_scrypt_tus})
    target_include_directories(header_chain_test PRIVATE ${CMAKE_SOURCE_DIR}/src/btclibs)
    target_link_libraries(header_chain_test PRIVATE
        GTest::gtest_main GTest::gtest nlohmann_json::nlohmann_json)
    gtest_add_tests(header_chain_test "" AUTO)
endif()
