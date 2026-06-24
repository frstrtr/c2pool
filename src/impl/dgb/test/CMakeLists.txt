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

    # --- embedded P2P header-download ingest connector ------------------------
    # Pins coin/header_ingest.hpp: wire_header_ingest subscribes a HeaderChain
    # to dgb::interfaces::Node::new_headers (the feed coin/p2p_node.hpp fires)
    # and routes each announced header through make_header_sample ->
    # validate_and_append. Proves the LIVE wire path advances the chain (and no
    # other path does) without adding consensus policy of its own. Links the dgb
    # OBJECT lib like dgb_header_sample_build_test because it pulls block.hpp
    # (BlockHeaderType codec via node_interface.hpp) + core Hash/pack. MUST
    # appear in BOTH this registration AND the build.yml --target allowlist.
    add_executable(dgb_header_ingest_test header_ingest_test.cpp)
    target_link_libraries(dgb_header_ingest_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_header_ingest_test "" AUTO)

    # dgb_mempool_ingest_test: guards c2pool::dgb::wire_mempool_ingest, the
    # connector routing the embedded P2P `tx` relay (new_tx) into the Mempool
    # (tx analog of wire_header_ingest). Compiles the tx serialization codec, so
    # it links the full dgb_coin SCC set rather than the scrypt-only guard set.
    # MUST also be in BOTH build.yml --target allowlists (#143 NOT_BUILT trap).
    add_executable(dgb_mempool_ingest_test mempool_ingest_test.cpp)
    target_link_libraries(dgb_mempool_ingest_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb dgb_stratum
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain
        nlohmann_json::nlohmann_json)
    gtest_add_tests(dgb_mempool_ingest_test "" AUTO)

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

    # --- #82: won-block reconstruct CLOSURE (run-loop WonBlockReconstructor) -
    # Pins coin/reconstruct_closure.hpp: make_reconstruct_closure composes the
    # share-field + gentx-regen seams + reconstruct_won_block under a fail-closed
    # catch (the closure main_dgb.cpp binds in place of the nullopt stub). Links
    # the dgb OBJECT lib like dgb_reconstruct_won_block_test (pulls block_assembly
    # via the closure). MUST also appear in the build.yml --target allowlist.
    add_executable(dgb_reconstruct_closure_test reconstruct_closure_test.cpp)
    target_link_libraries(dgb_reconstruct_closure_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_reconstruct_closure_test "" AUTO)

    # --- #82 broadcaster-gate BINDING KAT: forced won share -> dual path ------
    # Drives a forced won share through the REAL from-template reconstruct
    # closure wired into make_on_block_found, asserting BOTH broadcast arms
    # (P2P relay + submitblock fallback) carry the byte-identical faithful block.
    # Links the dgb OBJECT lib like dgb_reconstruct_closure_test (pulls
    # reconstruct_won_block / block_assembly via the closure). MUST also appear
    # in the build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_forced_won_share_dualpath_test forced_won_share_dualpath_test.cpp)
    target_link_libraries(dgb_forced_won_share_dualpath_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_forced_won_share_dualpath_test "" AUTO)

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

    # --- Phase B: per-connection Stratum coinbase assembler + split KAT -----
    # Pins coin/connection_coinbase.hpp: build_connection_coinbase_parts builds
    # the per-connection gentx via the assemble_gentx_coinbase SSOT and splits
    # it into coinb1/coinb2 around the OP_RETURN 8-byte extranonce slot. Proves
    # bytes==oracle (same NOSEG vector as dgb_gentx_coinbase_test) AND the
    # split invariant coinb1||en1||en2||coinb2 == full gentx. Links the dgb
    # OBJECT-lib SCC set like dgb_gentx_coinbase_test. MUST appear in BOTH this
    # registration AND the build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_connection_coinbase_test connection_coinbase_test.cpp)
    target_link_libraries(dgb_connection_coinbase_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_connection_coinbase_test "" AUTO)

    # --- Phase B: PPLNS weights -> consensus-sorted payout outputs KAT ------
    # Pins coin/pplns_payout_split.hpp: compute_pplns_payout_split reproduces
    # steps 2-3 of share_check.hpp generate_share_transaction (the verification
    # SSOT) satoshi-for-satoshi -- the bridge that lets build_connection_coinbase
    # draw the SAME PPLNS amount split the share check enforces. Header-only over
    # uint288, registered with the proven dgb link set for parity with sibling
    # coinbase KATs. MUST also be in the build.yml --target allowlist (#143 trap).
    add_executable(dgb_pplns_payout_split_test pplns_payout_split_test.cpp)
    target_link_libraries(dgb_pplns_payout_split_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_pplns_payout_split_test "" AUTO)

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

    # --- Phase B: per-connection PPLNS-inputs producer-assembly KAT ---------
    # conn_pplns_producer.hpp binds the verifier ref-hash primitive
    # (compute_ref_hash_for_work, #336) onto the per-connection coinbase inputs.
    # Links the dgb OBJECT-lib SCC set like dgb_gentx_share_path_test (pulls
    # share_check.hpp). MUST also be in the build.yml --target allowlist (#143).
    add_executable(dgb_conn_pplns_producer_test conn_pplns_producer_test.cpp)
    target_link_libraries(dgb_conn_pplns_producer_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_conn_pplns_producer_test "" AUTO)

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

    # dgb_embedded_tx_select_test: guards make_mempool_tx_source
    # (embedded_tx_select.cpp), the production Mempool -> GBT transactions[]
    # {data,txid,hash,fee} + fee-total shaper EmbeddedCoinNode injects. Compiles
    # the tx serialization codec, so it links the same proven SCC set as
    # dgb_embedded_coin_node_test. MUST also be in BOTH build.yml --target
    # allowlists (#143 NOT_BUILT trap).
    add_executable(dgb_embedded_tx_select_test embedded_tx_select_test.cpp)
    target_link_libraries(dgb_embedded_tx_select_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb dgb_stratum
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain
        nlohmann_json::nlohmann_json)
    gtest_add_tests(dgb_embedded_tx_select_test "" AUTO)

    # dgb_template_other_txs_test: pins coin/template_other_txs.hpp, the producer
    # bridge decoding the embedded template transactions[] (make_mempool_tx_source
    # GBT data) back into the MutableTransaction vector the won-block reconstructor
    # frames as [gentx] ++ other_txs. Compiles the tx codec AND the reconstruct
    # closure, so it links the embedded_tx_select SCC set + pool/sharechain. MUST
    # also be in BOTH build.yml --target allowlists (#143 NOT_BUILT trap).
    add_executable(dgb_template_other_txs_test template_other_txs_test.cpp)
    target_link_libraries(dgb_template_other_txs_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb dgb_stratum
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain
        nlohmann_json::nlohmann_json)
    gtest_add_tests(dgb_template_other_txs_test "" AUTO)

    # dgb_coinbase_value_parity_test: END-TO-END GBT-parity KAT. Drives a
    # populated Mempool through the production make_mempool_tx_source ->
    # EmbeddedCoinNode -> build_work_template path and asserts coinbasevalue ==
    # subsidy(next_height) + sum(mempool fees) (the digibyted GBT figure) at
    # every reward era. Compiles the tx serialization codec like
    # dgb_embedded_tx_select_test, so it links the same proven SCC set. MUST
    # also be in BOTH build.yml --target allowlists (#143 NOT_BUILT trap).
    add_executable(dgb_coinbase_value_parity_test coinbase_value_parity_test.cpp)
    target_link_libraries(dgb_coinbase_value_parity_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb dgb_stratum
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain
        nlohmann_json::nlohmann_json)
    gtest_add_tests(dgb_coinbase_value_parity_test "" AUTO)


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

    # --- Stage 4b/4c: DGB-Scrypt PoW digest CALL (coin/scrypt_pow.hpp) --------
    # Pins scrypt_pow_hash = scrypt_1024_1_1_256(80-byte header) decoded via
    # u256::from_le_bytes, plus the satisfaction-gate byte order (pow_hash <=
    # target) header_chain.hpp compares. Reuses the SAME _dgb_scrypt_tus set as
    # header_chain_test (real scrypt, not synthetic) -- header-only u256, no core
    # / no dgb OBJECT lib, the standalone-guard discipline dgb_arith256.hpp keeps.
    # Same target name, so it stays in BOTH build.yml --target allowlists.
    add_executable(dgb_scrypt_pow_test scrypt_pow_test.cpp ${_dgb_scrypt_tus})
    target_include_directories(dgb_scrypt_pow_test PRIVATE ${CMAKE_SOURCE_DIR}/src/btclibs)
    target_link_libraries(dgb_scrypt_pow_test PRIVATE
        GTest::gtest_main GTest::gtest)
    gtest_add_tests(dgb_scrypt_pow_test "" AUTO)

    # --- Stage 4b/4c: DGB-Scrypt nonce grinder (coin/nonce_grinder.hpp) -------
    # Pins grind_won_nonce: increments the 80-byte header nonce until
    # scrypt_pow_hash(header) <= target (the EXACT header_chain.hpp satisfaction
    # gate), calling THROUGH the #286 scrypt_pow.hpp digest SSOT -- never a
    # bypass hash -- so the nonce it finds is one node B accepts. Asserts it
    # terminates well inside the test budget, writes the winning nonce LE into
    # [76..79], and fails closed (nullopt) when no nonce satisfies in budget.
    # Reuses the SAME _dgb_scrypt_tus real-scrypt set as dgb_scrypt_pow_test --
    # header-only u256, no core / no dgb OBJECT lib. Same standalone-guard
    # discipline; MUST stay in BOTH build.yml --target allowlists (#143 trap).
    add_executable(dgb_nonce_grinder_test nonce_grinder_test.cpp ${_dgb_scrypt_tus})
    target_include_directories(dgb_nonce_grinder_test PRIVATE ${CMAKE_SOURCE_DIR}/src/btclibs)
    target_link_libraries(dgb_nonce_grinder_test PRIVATE
        GTest::gtest_main GTest::gtest)
    gtest_add_tests(dgb_nonce_grinder_test "" AUTO)

    # --- Stage 4b/4c: grind -> reconstruct -> submit seam (coin/regrind_block.hpp)
    # Pins regrind_block_nonce: grinds the header nonce of an ALREADY-FRAMED
    # reconstructed-block blob until its DGB-Scrypt PoW satisfies the parent
    # target, writing the winning nonce back into header [76..79] IN PLACE --
    # the wiring between reconstruct (merkle root fixed) and a node-B
    # ProcessNewBlock ACCEPT. Asserts the re-ground header satisfies the EXACT
    # pow <= target gate via the #286 SSOT, that ONLY [76..79] mutate (merkle
    # region [36..67] + tx tail byte-preserved), and fail-closed (nullopt,
    # bytes UNCHANGED) on a runt blob or exhausted budget. Reuses the SAME
    # _dgb_scrypt_tus real-scrypt set; header-only u256, no core / no OBJECT
    # lib. MUST stay in BOTH build.yml --target allowlists (#143 trap).
    add_executable(dgb_regrind_block_test regrind_block_test.cpp ${_dgb_scrypt_tus})
    target_include_directories(dgb_regrind_block_test PRIVATE ${CMAKE_SOURCE_DIR}/src/btclibs)
    target_link_libraries(dgb_regrind_block_test PRIVATE
        GTest::gtest_main GTest::gtest)
    gtest_add_tests(dgb_regrind_block_test "" AUTO)
    # --- #82 gate: grind->reconstruct->submit JOINT (coin/won_block_finalize.hpp)
    # Pins finalize_won_block_pow: takes a faithfully reconstructed block (header
    # at [0..79], merkle_root already set -- merkle FIRST) and grinds the nonce
    # at [76..79] THROUGH grind_won_nonce -> scrypt_pow_hash (#286 SSOT) until the
    # DGB-Scrypt PoW satisfies the parent target, splicing the winning nonce back
    # and regenerating the RPC-fallback hex in lockstep with the P2P-arm bytes.
    # Asserts: finalized header pow<=target via the same SSOT; nonce spliced LE
    # into [76..79]; hex == bytes; ONLY the 4 nonce bytes mutate (merkle + tx tail
    # untouched); fail-closed (nullopt) on a sub-80-byte input. Reuses the SAME
    # _dgb_scrypt_tus real-scrypt set as dgb_nonce_grinder_test -- header-only
    # u256, no core / no dgb OBJECT lib. Same standalone-guard discipline; MUST
    # stay in BOTH build.yml --target allowlists (#143 trap).
    add_executable(dgb_won_block_finalize_test won_block_finalize_test.cpp ${_dgb_scrypt_tus})
    target_include_directories(dgb_won_block_finalize_test PRIVATE ${CMAKE_SOURCE_DIR}/src/btclibs)
    target_link_libraries(dgb_won_block_finalize_test PRIVATE
        GTest::gtest_main GTest::gtest)
    gtest_add_tests(dgb_won_block_finalize_test "" AUTO)

    # --- #82 Stage 4d: mining_submit decision SSOT (coin/submit_classify.hpp) --
    # Pins classify_submission: the three-way pow_hash ladder (WonBlock /
    # ShareAccept / Reject) with BOTH boundaries inclusive, mirroring DigiByte
    # Core CheckProofOfWork (hash>target = the only reject) and p2pool-merged-v36
    # share-accept. Tighten-first order so block beats share; safety KAT proves an
    # inverted (malformed) target pair can only mis-Reject, never spurious-WonBlock.
    # Pure header-only u256 -- no scrypt, no core, no dgb OBJECT lib. MUST stay in
    # BOTH build.yml --target allowlists (#143 trap).
    add_executable(dgb_submit_classify_test submit_classify_test.cpp)
    target_link_libraries(dgb_submit_classify_test PRIVATE
        GTest::gtest_main GTest::gtest)
    gtest_add_tests(dgb_submit_classify_test "" AUTO)

    # --- DGB+DOGE (D0) aux-pow parent-coinbase serialization PARITY BASELINE ----
    # Pins the pre-templating wire image of the shared aux module struct
    # doge::coin::CMerkleTx (src/impl/doge/coin/auxpow.hpp) anchored to master
    # f732061bc, so the v36-standardize Scrypt value-type extraction can prove
    # its parent-coinbase type swap is byte-neutral. Links the ltc OBJECT lib
    # (member type ltc::coin::MutableTransaction) + dgb (neutral stand-in type
    # for the cross-type byte-identity assert) — the -DAUX_DOGE consumption path
    # legitimately couples to ltc. Test-only; consumes the shared module, does
    # not modify it. MUST appear in BOTH this registration AND the build.yml
    # --target allowlist.
    add_executable(dgb_aux_parent_coinbase_parity_test aux_parent_coinbase_parity_test.cpp)
    target_link_libraries(dgb_aux_parent_coinbase_parity_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb ltc_coin
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_aux_parent_coinbase_parity_test "" AUTO)
    # --- #271 per-job template-retention seam (coin/template_capture.hpp) ------
    # dgb_template_capture_test: pins the PRODUCTION captured_template_txs_fn the
    # won-block reconstructor's template_other_txs_fn is built from (via the #299
    # make_template_other_txs_fn bridge) -- capture(share,txs[]) -> provide(share)
    # replays the exact template, a MISS replays empty (coinbase-only valid, NOT
    # fail-closed), and composed through the bridge a HIT decodes to the same
    # MutableTransaction vector deserialize_template_other_txs yields directly.
    # Replaces main_dgb's interim mempool re-selection lambda (static-mempool-
    # only). Compiles the tx codec + bridge, so it links the same embedded_tx_
    # select SCC set as dgb_template_other_txs_test. MUST also be in BOTH build.yml
    # --target allowlists (#143 NOT_BUILT trap).
    add_executable(dgb_template_capture_test template_capture_test.cpp)
    target_link_libraries(dgb_template_capture_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb dgb_stratum
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain
        nlohmann_json::nlohmann_json)
    gtest_add_tests(dgb_template_capture_test "" AUTO)

    # dgb_redistribute_test: pins src/impl/dgb/redistribute.hpp, the node-local
    # Redistribute V2 policy ported byte-for-byte from src/impl/ltc (namespace
    # flip only) -- mode/spec parsing, hybrid format round-trip, stratum-password
    # options, and the deterministic FEE/DONATE/empty-PPLNS pick branches. The
    # header consumes share_tracker + share_check + config_pool, so it links the
    # same set as dgb_share_test. CONSENSUS-SAFE (only the locally-stamped
    # pubkey_hash), bucket-2 cross-coin standardization. MUST also be in BOTH
    # build.yml --target allowlists (#143 NOT_BUILT trap).
    add_executable(dgb_redistribute_test redistribute_test.cpp)
    target_link_libraries(dgb_redistribute_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_redistribute_test "" AUTO)


    # --- DGB+DOGE (phase DB) — DGB-as-parent AuxPoW commitment binding KAT -----
    # Instantiates the TEMPLATED shared aux module (PR #313) with the DGB parent
    # coinbase type: doge::coin::CAuxPow<dgb::coin::MutableTransaction>. Proves
    # the DB binding round-trips byte-stable AND is wire byte-identical to the
    # ltc default for identical commitment content (the DGB analog of #313's
    # named LTC acceptance gate). Links ltc_coin like dgb_aux_parent_coinbase_
    # parity_test — the -DAUX_DOGE consumption path legitimately couples to ltc.
    # Test-only; consumes the shared module, does not modify it. Built on the
    # #313 branch until #313 lands. MUST appear in BOTH this registration AND the
    # build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_aux_doge_db_commitment_bind_test aux_doge_db_commitment_bind_test.cpp)
    target_link_libraries(dgb_aux_doge_db_commitment_bind_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb ltc_coin
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_aux_doge_db_commitment_bind_test "" AUTO)

    # --- DGB+DOGE (phase DC) -- DGB-as-parent AuxPoW PROOF byte-parity + dual ---
    # Proves the neutral producer build_auxpow_proof (c2pool/merged) is byte-
    # identical to the typed doge::coin::CAuxPow<dgb::coin::MutableTransaction>
    # the DOGE-win handler assembles, round-trips that proof through parse_aux_
    # header<..., dgb::coin::MutableTransaction> (EVERY call site binds the DGB
    # parent type EXPLICITLY -- the LTC default would silently mis-serialize), and
    # pins the independent dual-target share-check. Links c2pool_merged_mining
    # (build_auxpow_proof) + ltc_coin like the DB/parity siblings -- the -DAUX_DOGE
    # consumption path legitimately couples to ltc. Test-only; consumes the shared
    # module + merged primitive, modifies neither. MUST appear in BOTH this
    # registration AND the build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_aux_doge_dc_proof_test aux_doge_dc_proof_test.cpp)
    target_link_libraries(dgb_aux_doge_dc_proof_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb ltc_coin
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_aux_doge_dc_proof_test "" AUTO)

    # --- DGB+DOGE (M3) -- bind_aux_doge_parsers() PRODUCTION-binding KAT --------
    # Proves the production dgb node seam coin/node.hpp's bind_aux_doge_parsers()
    # is NON-HOLLOW: it instantiates a dgb::coin::Node, calls the (now real) bind
    # body, and drives a canonical DGB-parent AuxPoW blob THROUGH the bound member
    # -- ODR-USING parse_aux_header<dgb::coin::MutableTransaction> + CAuxPow<dgb::
    # coin::MutableTransaction> in the PRODUCTION dgb object library, not merely in
    # fixtures. Links the production dgb lib + ltc_coin like the DB/DC siblings --
    # the -DAUX_DOGE consumption path legitimately couples to ltc. Test-only;
    # consumes the shared module, modifies nothing in src/impl/doge. MUST appear in
    # BOTH this registration AND the build.yml --target allowlist (#143 NOT_BUILT).
    add_executable(dgb_aux_doge_bind_parsers_test aux_doge_bind_parsers_test.cpp)
    target_link_libraries(dgb_aux_doge_bind_parsers_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb ltc_coin
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_aux_doge_bind_parsers_test "" AUTO)

    # dgb_share_target_genesis_test: FENCED KAT pinning ShareTracker::compute_
    # share_target genesis/unknown-prev clamp to [MAX_TARGET/30, MAX_TARGET] vs
    # the DGB oracle data.py generate_transaction. Links the same proven set as
    # dgb_share_test (ShareTracker pulls in the pool/share TU). MUST also be in
    # the build.yml --target allowlist (#143).
    add_executable(dgb_share_target_genesis_test share_target_genesis_test.cpp)
    target_link_libraries(dgb_share_target_genesis_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_share_target_genesis_test "" AUTO)

    # dgb_g1_oracle_byte_parity_test: FENCED greenlight-gate G1 KAT. Pins the
    # assembled make_coin_params() net/consensus constants AND bucket-1
    # isolation primitives (PREFIX/IDENTIFIER) against oracle-transcribed
    # literals from frstrtr/p2pool-dgb-scrypt (non-circular). MUST also be in
    # the build.yml --target allowlist (#143).
    add_executable(dgb_g1_oracle_byte_parity_test g1_oracle_byte_parity_test.cpp)
    target_link_libraries(dgb_g1_oracle_byte_parity_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_g1_oracle_byte_parity_test "" AUTO)

    # dgb_pool_msg_wire_test: FENCED conformance KAT for the pool P2P wire-message
    # layer (messages.hpp) — command-name parity, scalar LE byte pins, and
    # serialize/read-back field equality vs p2pool-merged-v36 message numbering.
    # First coverage of this layer in the repo. Same proven link set as
    # dgb_share_test (messages.hpp pulls coin/block + sharechain share). MUST
    # also be in the build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_pool_msg_wire_test dgb_pool_msg_wire_test.cpp)
    target_link_libraries(dgb_pool_msg_wire_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_pool_msg_wire_test "" AUTO)

    # dgb_get_shares_walk_test: FENCED, additive KAT pinning the pool share-
    # exchange GetShares walk (SHAREREQ -> SHAREREPLY) in get_shares_walk.hpp vs
    # the p2pool node.py handle_get_shares oracle (parents cap, per-hash walk
    # bound, stop-hash break, missing-hash + rejected-share skip). Pure header +
    # fake chain -> links only core (uint256). MUST also be in the build.yml
    # --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_get_shares_walk_test get_shares_walk_test.cpp)
    target_link_libraries(dgb_get_shares_walk_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_get_shares_walk_test "" AUTO)

    # dgb_download_stops_test: FENCED, additive KAT pinning the requester-side
    # SHAREREQ stops-list in download_stops.hpp vs the p2pool node.py
    # download_shares oracle (heads | nth-parent at min(max(0,height-1),10),
    # null-parent skip, dedup, [:100] cap). Pure header + fakes -> links only
    # core (uint256). MUST also be in the build.yml --target allowlist
    # (#143 NOT_BUILT trap).
    add_executable(dgb_download_stops_test download_stops_test.cpp)
    target_link_libraries(dgb_download_stops_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_download_stops_test "" AUTO)

    # dgb_think_p1_walk_bounds_test: FENCED, additive KAT pinning the think()
    # Phase-1 desired-set walk bounds in think_p1_walk_bounds.hpp vs the p2pool
    # data.py think() oracle (walk_count clamp min(5,max(0,h-CL)) / unrooted full
    # height; inclusive prune threshold 2*CL+10). Pure arithmetic -> links only
    # core. MUST also be in the build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_think_p1_walk_bounds_test think_p1_walk_bounds_test.cpp)
    target_link_libraries(dgb_think_p1_walk_bounds_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_think_p1_walk_bounds_test "" AUTO)

    # dgb_think_p1_desired_emit_test: FENCED, additive KAT pinning the think()
    # Phase-1 desired-emit decision in think_p1_desired_emit.hpp vs the p2pool
    # data.py think() oracle (no-parent -> prune-zone(2*CL+10 inclusive) ->
    # dedup -> emit ladder), plus a non-circular delegation anchor vs the verbatim
    # pre-delegation inline ladder. Pure arithmetic/bools -> links only core. MUST
    # also be in the build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_think_p1_desired_emit_test think_p1_desired_emit_test.cpp)
    target_link_libraries(dgb_think_p1_desired_emit_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_think_p1_desired_emit_test "" AUTO)

    # dgb_think_p6_desired_cutoff_test: FENCED, additive KAT pinning the think()
    # Phase-6 desired-shares timestamp cutoff in think_p6_desired_cutoff.hpp vs
    # the p2pool data.py think() tail oracle (min(now,best_ts)-3600 / 24h no-best
    # fallback; inclusive keep predicate), plus a non-circular delegation anchor
    # vs the verbatim pre-delegation inline cutoff/keep expressions. Pure
    # arithmetic -> links only core. MUST also be in the build.yml --target
    # allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_think_p6_desired_cutoff_test think_p6_desired_cutoff_test.cpp)
    target_link_libraries(dgb_think_p6_desired_cutoff_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_think_p6_desired_cutoff_test "" AUTO)

    # dgb_expected_time_to_block_test: FENCED, additive KAT pinning the
    # EXPECTED-TIME-TO-BLOCK diagnostic arithmetic in expected_time_to_block.hpp
    # vs the p2pool main.py status-loop oracle (average_attempts(target) /
    # real_att_s, with the uint64-overflow 1e18 sentinel). Pure header
    # (<cstdint> only) -> links only GTest. node.cpp NOT yet rewired (delegation
    # is the byte-identity follow-on). MUST also be in the build.yml --target
    # allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_expected_time_to_block_test expected_time_to_block_test.cpp)
    target_link_libraries(dgb_expected_time_to_block_test PRIVATE
        GTest::gtest_main GTest::gtest)
    gtest_add_tests(dgb_expected_time_to_block_test "" AUTO)

    # dgb_tail_score_endpoints_test: FENCED, additive KAT pinning the
    # TAIL-HASHRATE-SCORE chain-walk endpoint arithmetic in
    # coin/tail_score_endpoints.hpp vs the p2pool-dgb-scrypt data.py:843-855
    # ShareTracker.score() oracle (end-point offset CHAIN_LENGTH*15//16, trailing
    # walk CHAIN_LENGTH//16, short-chain guard, unresolvable-block 1e6 fallback,
    # work/(block_span*BLOCK_PERIOD) divide). Pure header (uint288) -> links core.
    # share_tracker.hpp NOT yet rewired (delegation is the byte-identity
    # follow-on). MUST also be in the build.yml --target allowlist (#143
    # NOT_BUILT trap).
    add_executable(dgb_tail_score_endpoints_test tail_score_endpoints_test.cpp)
    target_link_libraries(dgb_tail_score_endpoints_test PRIVATE
        GTest::gtest_main GTest::gtest
        core
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage)
    gtest_add_tests(dgb_tail_score_endpoints_test "" AUTO)
    # dgb_pool_attempts_per_second_test: FENCED, additive KAT pinning the pure
    # arithmetic core of ShareTracker::get_pool_attempts_per_second lifted into
    # coin/pool_attempts_per_second.hpp vs the p2pool data.py oracle
    # (attempts // max(1, near_ts - far_ts), with the dist>=2 + endpoint guards).
    # Links core for uint288. share_tracker.hpp NOT yet rewired (delegation is the
    # byte-identity follow-on). MUST also be in the build.yml --target allowlist
    # (#143 NOT_BUILT trap).
    add_executable(dgb_pool_attempts_per_second_test pool_attempts_per_second_test.cpp)
    target_link_libraries(dgb_pool_attempts_per_second_test PRIVATE
        GTest::gtest_main GTest::gtest
        core c2pool_hashrate c2pool_merged_mining c2pool_payout c2pool_storage)
    gtest_add_tests(dgb_pool_attempts_per_second_test "" AUTO)
    # dgb_binomial_conf_interval_test: FENCED, additive KAT pinning the pure
    # Wilson-score confidence-interval arithmetic of p2pool util/math.py:133
    # binomial_conf_interval (+ ierf/erf A&S-7.1.26 helpers) lifted into
    # coin/binomial_conf_interval.hpp. DIAGNOSTICS-ONLY stale-rate display math
    # (main.py format_binomial_conf), no consensus surface; golden endpoints are
    # non-circular Python-oracle output. Pure header (<cmath>/<array>) -> links
    # only GTest. No call site rewired. MUST also be in the build.yml --target
    # allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_binomial_conf_interval_test binomial_conf_interval_test.cpp)
    target_link_libraries(dgb_binomial_conf_interval_test PRIVATE
        GTest::gtest_main GTest::gtest)
    gtest_add_tests(dgb_binomial_conf_interval_test "" AUTO)
    # dgb_desired_version_tally_test: FENCED, additive KAT pinning the
    # version->work / version->count accumulation core lifted into
    # coin/desired_version_tally.hpp vs the p2pool-dgb-scrypt data.py:918-922
    # get_desired_version_counts oracle (res[dv] += target_to_average_attempts(
    # share.target)). The work-weighted map is the CONSENSUS 60%-by-work switch
    # input (share_check step 2 / #288 AutoRatchet tail guard); the flat-count
    # accumulator is diagnostics-only and pinned just to lock the documented
    # divergence. The work-equivalence anchor uses chain::target_to_average_attempts
    # over 2^k-1 targets (hand-derived ttaa), so links core for uint288 +
    # target_utils. share_tracker.hpp NOT yet rewired (delegation is the
    # byte-identity follow-on). MUST also be in the build.yml --target allowlist
    # (#143 NOT_BUILT trap).
    add_executable(dgb_desired_version_tally_test desired_version_tally_test.cpp)
    target_link_libraries(dgb_desired_version_tally_test PRIVATE
        GTest::gtest_main GTest::gtest
        core
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage)
    gtest_add_tests(dgb_desired_version_tally_test "" AUTO)
    # dgb_pool_efficiency_test: FENCED, additive KAT pinning the pool
    # EFFICIENCY / REAL-HASHRATE diagnostics arithmetic in pool_efficiency.hpp vs
    # the p2pool main.py status-loop oracle (stale_prop = (orphan+doa)/total;
    # real_att_s = pool_hs / (1 - stale_prop) with the near-all-stale guard).
    # Pure header (<cstdint> only) -> links only GTest. node.cpp NOT yet rewired
    # (delegation is the byte-identity follow-on). MUST also be in the build.yml
    # --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_pool_efficiency_test pool_efficiency_test.cpp)
    target_link_libraries(dgb_pool_efficiency_test PRIVATE
        GTest::gtest_main GTest::gtest)
    gtest_add_tests(dgb_pool_efficiency_test "" AUTO)

    # dgb_auto_ratchet_tail_guard_test: FENCED, additive conformance KAT for the
    # AutoRatchet WORK-WEIGHTED 60% tail-guard SSOT (auto_ratchet_tail_guard.hpp)
    # vs the p2pool-dgb-scrypt switch rule data.py:1399
    # (SWITCHED iff target_weight >= floor(total_weight*60/100)). Non-circular:
    # hand-derived oracle values + a verbatim replica of the live inline to pin
    # the one floor-boundary divergence. uint288 arithmetic -> links core.
    # auto_ratchet.hpp NOT rewired (delegation is the byte-id follow-on). MUST
    # also be in the build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_auto_ratchet_tail_guard_test auto_ratchet_tail_guard_test.cpp)
    target_link_libraries(dgb_auto_ratchet_tail_guard_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_auto_ratchet_tail_guard_test "" AUTO)

    # dgb_think_p4_head_keys_test: FENCED, additive KAT pinning the think()
    # Phase-4 head-score KEY construction in think_p4_head_keys.hpp vs the
    # p2pool data.py think() oracle (selection key (adjusted_work,-reason,-ts)
    # with a min(punish,1) one-share work deduction iff naughty; traditional
    # key (work_score,-ts,-reason)), plus a non-circular reference-scan anchor
    # vs the verbatim pre-delegation inline arithmetic. Pure key build -> links
    # only core. MUST also be in the build.yml --target allowlist (#143 trap).
    add_executable(dgb_think_p4_head_keys_test think_p4_head_keys_test.cpp)
    target_link_libraries(dgb_think_p4_head_keys_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_think_p4_head_keys_test "" AUTO)

    # dgb_think_p3_best_head_test: FENCED, additive KAT pinning the think()
    # Phase-3 per-tail best-head selection in think_p3_best_head.hpp vs the
    # p2pool data.py think() oracle (max(verified.tails[t], key=get_work),
    # first-max tiebreak: skip unverified, first-seen wins, strict-greater
    # replace), plus a non-circular reference-scan anchor vs the verbatim
    # pre-delegation inline loop. Pure selection -> links only core. MUST also
    # be in the build.yml --target allowlist (#143 NOT_BUILT trap).
    add_executable(dgb_think_p3_best_head_test think_p3_best_head_test.cpp)
    target_link_libraries(dgb_think_p3_best_head_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_think_p3_best_head_test "" AUTO)

    # dgb_think_p2_walk_bounds_test: FENCED, additive KAT pinning the think()
    # Phase-2 verification-extension walk bounds in think_p2_walk_bounds.hpp vs
    # the p2pool data.py:2098-2103 oracle (want=max(CL-h,0); can=last_height if
    # unrooted else max(last_height-1-CL,0); get=min(want,can)). Pure arithmetic
    # -> links only core. MUST also be in build.yml --target allowlist (#143).
    add_executable(dgb_think_p2_walk_bounds_test think_p2_walk_bounds_test.cpp)
    target_link_libraries(dgb_think_p2_walk_bounds_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_think_p2_walk_bounds_test "" AUTO)

    # dgb_think_p5_best_share_punish_test: FENCED, additive KAT pinning the
    # think() Phase-5 best-share punish walk in think_p5_best_share_punish.hpp
    # vs the p2pool data.py:2142-2166 best-share resolution oracle (walk back off
    # naughty heads, dive to deepest non-naughty descendant, report punishment),
    # plus hand-derived non-circular fake-chain anchors. Pure graph traversal ->
    # links only core. MUST also be in the build.yml --target allowlist (#143
    # NOT_BUILT trap).
    add_executable(dgb_think_p5_best_share_punish_test think_p5_best_share_punish_test.cpp)
    target_link_libraries(dgb_think_p5_best_share_punish_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)
    gtest_add_tests(dgb_think_p5_best_share_punish_test "" AUTO)

endif()
