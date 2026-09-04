# c2pool-bch coin-module tests (V36). Built when -DCOIN_BCH=ON AND BUILD_TESTING.
# Harness: plain int main() with assert/iostream (CTest treats exit 0 as PASS) —
# matches the existing ABLA seam tests; no GTest dependency.
#
# Link set mirrors src/impl/ltc/test (OBJECT-lib SCC direct-naming, #22/#39):
# `core` is a monolithic OBJECT lib whose objects (stratum_server/web_server)
# reference pool/payout/hashrate/storage symbols, so every consumer must name the
# whole SCC directly. We deliberately link NO coin lib (no bch/ltc/btc) — the ABLA
# tests are header-only over coin/*.hpp + <core/*> (uint256/leveldb/log), so the
# per-coin isolation invariant stays clean.
if(BUILD_TESTING)
    set(BCH_ABLA_TESTS
        abla_floor_invariant_test
        abla_block_feed_test
        abla_block_feed_gap_test
        header_sync_test          # M5: headers-first IBD continuation policy (pure)
        header_sync_progress_test # M5: sync-to-peer-tip convergence + steady-state-follow soak (pure)
        block_download_test       # M5: windowed headers-first block download (pure)
        genesis_conformance_test  # M5: genesis-hash pin vs BCHN v29.0.0 chainparams (pure)
        abla_growth_soak_test     # M5: dynamic ABLA budget-GROWTH proof above 32 MB floor (pure)
        coinbase_kat_segwit_predicate_test # KAT: DGB<->BCH coinbase pairing -- gated-segwit-OFF predicate pin (pure)
        asert_kat_test            # M5: ASERT DAA known-answer vs BCHN @89a591f gold properties + mainnet anchor (pure)
        muldiv_kat_test           # ABLA: 128-bit muldiv native(__int128)==portable(boost uint128) equivalence -- MSVC-portability guard (pure)
        g1_oracle_byte_parity_test # G1: oracle byte-parity vs p2pool-merged-v36 bitcoincash[_testnet].py (pure)
        g1_share_serialization_parity_test # G1: share-serialization byte-parity vs jtoomim oracle wire (pure)
        g0_canonical_pin_test      # G0: canonical-pin vs p2poolBCH @6603b79 baseline + v35->v36 transition rule (pure)
        g2_ratchet_gate_kat_test   # G2: 60%-by-WORK version-switch accept gate + mint-cannot-outrun-accept (pure)
        coinbase_author_kat_test  # KAT G2: v36 coinbase output-assembly byte-parity vs p2pool-merged-v36 oracle (pure)
        donation_flip_kat_test    # KAT G2-C3: donation P2PK<->P2SH byte-correctness across the v35<->v36 flip (pure)
        cashaddr_kat_test         # M4: CashAddr codec KAT -- encode/decode roundtrip + PolyMod/version-byte parity vs BCHN vectors, prefix/checksum rejection (pure)
        share_tx_refs_kat_test    # #905: bch::new_tx_hashes accessor -- send-side flat-probe regression pin (v17/v33 nested, v34+ none) (pure)
        idle_watchdog_kat_test    # compact-relay: progress-gated block-download stall watchdog -- at-tip anti-churn + IBD stall-drop predicate (pure)
        seed_tier_kat_test        # Option-A discovery ladder: build_ladder tier-3 ordering/dedup + should_run_ladder explicit-peer-bypass gate + CandidateWalk tail-walk/wrap + EmergencyReArm backoff/re-entry/recovery (pure)
        graph_db_shutdown_persist_test # B-STATS.944: graph_db stat-log save-on-clean-shutdown -- Saved N == Loaded N across a graceful stop (site 3/3) (pure over core web_server)
        known_txs_evict_wiring_test # B-BCH.EVICT: clean_tracker() live-pass known_txs cap-enforcement wiring gate (wired bounded / unwired grows-past-cap perturbation) (pure over core::evict_known_txs_to_cap)
        seed_tier_recovery_gate_test # IMPLEMENTED!=PROVEN: drives live resolve_candidates() ladder recovery over a real io_context -- DNS->fixed->http-peer, each tier a SOURCE + each failure a NEGATIVE CONTROL (loopback DNS + in-proc HTTP stub + closed port; network-free)
        found_block_verify_test    # #995 BCH arm: found-block confirm/orphan verdict logic (resolve_status confirmed/orphaned/pending branches) feeding MiningInterface::set_block_verify_fn (pure over coin/block_confirm.hpp)
    )
    foreach(t IN LISTS BCH_ABLA_TESTS)
        add_executable(bch_${t} ${t}.cpp)
        target_include_directories(bch_${t} PRIVATE ${CMAKE_SOURCE_DIR}/src)
        target_link_libraries(bch_${t} PRIVATE
            core pool sharechain
            c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
            btclibs)
        add_test(NAME bch_${t} COMMAND bch_${t})
    endforeach()

    # #1131 source-structural KAT (BCH-lane mirror of dash/btc/ltc): the think-P1
    # bad-share removal must borrow from `verified` (owns_data=false) so only the
    # owning `chain` destroys the share. Its own executable (BCH tree is plain
    # main()+CHECK, no GTest to fold into); needs the share_tracker.hpp path.
    add_executable(bch_share_remove_owns_data_test share_remove_owns_data_test.cpp)
    target_include_directories(bch_share_remove_owns_data_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_compile_definitions(bch_share_remove_owns_data_test PRIVATE
        BCH_SHARE_TRACKER_SRC="${CMAKE_CURRENT_SOURCE_DIR}/../share_tracker.hpp")
    add_test(NAME bch_share_remove_owns_data_test COMMAND bch_share_remove_owns_data_test)

    # block_connector_test exercises the full-block -> mempool reconciliation
    # path, so it constructs MutableTransaction objects whose ctors are out-of-line
    # in coin/transaction.cpp. Add that single TU to this test only; the link set
    # and header-only-over-coin/*.hpp isolation posture are otherwise identical
    # (still no impl_bch coin lib -> per-coin isolation stays clean).
    add_executable(bch_block_connector_test
        block_connector_test.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/transaction.cpp)
    target_include_directories(bch_block_connector_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(bch_block_connector_test PRIVATE
        core pool sharechain
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
        btclibs)
    add_test(NAME bch_block_connector_test COMMAND bch_block_connector_test)

    # block_ordering_test: BIP130 ordering edge cases (slice 2) over the same
    # connector seam; same link set + transaction.cpp TU as block_connector_test.
    add_executable(bch_block_ordering_test
        block_ordering_test.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/transaction.cpp)
    target_include_directories(bch_block_ordering_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(bch_block_ordering_test PRIVATE
        core pool sharechain
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
        btclibs)
    add_test(NAME bch_block_ordering_test COMMAND bch_block_ordering_test)

    # coinbase_kat_bytevector_test: DGB<->BCH coinbase pairing slice 2 -- the
    # byte-vector half. Serializes a full BCH coinbase via coin/transaction.hpp
    # and pins it against p2poolBCH util/pack ground-truth, so it constructs a
    # MutableTransaction (out-of-line ctor) -> add that one TU, same link set as
    # block_connector_test. (Slice 1 = coinbase_kat_segwit_predicate_test, pure.)
    add_executable(bch_coinbase_kat_bytevector_test
        coinbase_kat_bytevector_test.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/transaction.cpp)
    target_include_directories(bch_coinbase_kat_bytevector_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(bch_coinbase_kat_bytevector_test PRIVATE
        core pool sharechain
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
        btclibs)
    add_test(NAME bch_coinbase_kat_bytevector_test COMMAND bch_coinbase_kat_bytevector_test)

    # cashtokens_transparency_test: M5 conform pass -- pins the CHIP-2022-02
    # CashTokens "transparent carry" invariant (M1 s4). Builds a token-prefixed
    # (0xef) TxOut, proves the SHA256d serializer treats the prefix as opaque
    # locking bytecode: lossless serialize/deserialize round-trip, verbatim byte
    # survival, and binding into the tx_id pre-image. Same MutableTransaction TU
    # + link set as the byte-vector KAT.
    add_executable(bch_cashtokens_transparency_test
        cashtokens_transparency_test.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/transaction.cpp)
    target_include_directories(bch_cashtokens_transparency_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(bch_cashtokens_transparency_test PRIVATE
        core pool sharechain
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
        btclibs)
    add_test(NAME bch_cashtokens_transparency_test COMMAND bch_cashtokens_transparency_test)

    # utxo_connect_test: M5 (a) -- the now-live UTXO-connect leg. connect_block()
    # applies a best-chain block to a wired UTXO view, then revalidate_inputs()
    # (Phase 4) sweeps mempool txs whose inputs the connect left unspendable
    # (double-spend rejection). Same link set + transaction.cpp TU as the other
    # connector tests; still no impl_bch coin lib -> per-coin isolation holds.
    add_executable(bch_utxo_connect_test
        utxo_connect_test.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/transaction.cpp)
    target_include_directories(bch_utxo_connect_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(bch_utxo_connect_test PRIVATE
        core pool sharechain
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
        btclibs)
    add_test(NAME bch_utxo_connect_test COMMAND bch_utxo_connect_test)

    # reorg_connect_test: M5 reorg/disconnect leg -- retained BlockUndo + a
    # best-chain branch switch. Disconnects the orphaned branch (restore spent
    # inputs, remove created outputs, return its txs to the mempool) and re-applies
    # the new branch from the remembered-block ring. Same link set as the other
    # connector tests; no impl_bch coin lib -> per-coin isolation holds.
    add_executable(bch_reorg_connect_test
        reorg_connect_test.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/transaction.cpp)
    target_include_directories(bch_reorg_connect_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(bch_reorg_connect_test PRIVATE
        core pool sharechain
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
        btclibs)
    add_test(NAME bch_reorg_connect_test COMMAND bch_reorg_connect_test)

    # reorg_rerequest_test: M5 reorg recovery leg -- the COMPLEMENT of
    # reorg_connect_test. When the new branch's intermediate blocks are NOT
    # in the remembered ring (headers-first race, or a reorg deeper than the
    # ring retains), the connector hands the missing new-branch hashes to a
    # set_block_requester() sink (wired to BlockDownloadWindow::enqueue) so
    # they are re-getdata'd and the reorg completes on re-delivery, instead
    # of stranding the UTXO at the fork. Same link set + transaction.cpp TU;
    # no impl_bch coin lib -> per-coin isolation holds.
    add_executable(bch_reorg_rerequest_test
        reorg_rerequest_test.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/transaction.cpp)
    target_include_directories(bch_reorg_rerequest_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(bch_reorg_rerequest_test PRIVATE
        core pool sharechain
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
        btclibs)
    add_test(NAME bch_reorg_rerequest_test COMMAND bch_reorg_rerequest_test)

    # compact_block_connector_test: M5 (b) -- BIP152 compact-block depth on the
    # connector seam. on_compact_block reconstructs from prefilled + mempool; a
    # missing tx drives a getblocktxn round that on_block_txn closes out before
    # the normal block-connect/mempool reconciliation. Uses btclibs for SipHash;
    # same link set + transaction.cpp TU; no impl_bch coin lib -> isolation holds.
    add_executable(bch_compact_block_connector_test
        compact_block_connector_test.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/transaction.cpp)
    target_include_directories(bch_compact_block_connector_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(bch_compact_block_connector_test PRIVATE
        core pool sharechain
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
        btclibs)
    add_test(NAME bch_compact_block_connector_test COMMAND bch_compact_block_connector_test)

    # embedded_daemon_assembly_test: network-free assembly of the full
    # EmbeddedDaemon graph (Node + EmbeddedCoinNode + AblaRuntime + CoinNode
    # seam) plus the operator-approved cold-start anchor LIVE PIN (floor-
    # equivalent). Same link set + transaction.cpp TU as the connector tests.
    add_executable(bch_embedded_daemon_assembly_test
        embedded_daemon_assembly_test.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/transaction.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/coin_node.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/p2p_connection.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/p2p_node.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/rpc.cpp)
    target_include_directories(bch_embedded_daemon_assembly_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(bch_embedded_daemon_assembly_test PRIVATE
        core pool sharechain
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
        btclibs)
    add_test(NAME bch_embedded_daemon_assembly_test COMMAND bch_embedded_daemon_assembly_test)

    # M5 embedded-daemon body tests (#156): EmbeddedDaemon / EmbeddedCoinNode /
    # CoinNode-seam coverage that was authored alongside the body but never wired
    # into CMake -> it built locally yet never ran in CI (authored-but-unrun =
    # false-green). Same TU + link set as bch_embedded_daemon_assembly_test (each
    # constructs the real Node/EmbeddedCoinNode/CoinNode graph, so it needs the
    # out-of-line coin_node/p2p/rpc/transaction TUs). No impl_bch coin lib ->
    # per-coin isolation holds.
    set(BCH_EMBEDDED_BODY_TESTS
        embedded_getwork_test          # EmbeddedCoinNode::getwork() contract: sync gate + GBT + ABLA at-tip/stale floor
        embedded_seam_workview_test    # EmbeddedDaemon real-seam + network-free assemble() split
        embedded_block_broadcast_test  # dual-path won-block broadcaster (gate A submitblock-RPC + B BIP152 P2P)
        coin_node_seam_test            # CoinNode seam: embedded-primary / external-RPC-fallback invariants
    )
    foreach(t IN LISTS BCH_EMBEDDED_BODY_TESTS)
        add_executable(bch_${t}
            ${t}.cpp
            ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/transaction.cpp
            ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/coin_node.cpp
            ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/p2p_connection.cpp
            ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/p2p_node.cpp
            ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/rpc.cpp
            # M5 pool-node body TUs (mirror the shipping c2pool-bch target in
            # src/c2pool/CMakeLists.txt): NodeImpl out-of-line methods + the two
            # p2pool p2p protocol dispatchers + the stratum work source, so an
            # embedded body test can construct the real pool-node graph and reach
            # the Node/protocol/BCHWorkSource symbols -- enabler for the #911
            # is_wire_advertisable guard test-coverage gap. Additive, src/impl/bch
            # only -> per-coin isolation holds.
            ${CMAKE_SOURCE_DIR}/src/impl/bch/node.cpp
            ${CMAKE_SOURCE_DIR}/src/impl/bch/protocol_actual.cpp
            ${CMAKE_SOURCE_DIR}/src/impl/bch/protocol_legacy.cpp
            ${CMAKE_SOURCE_DIR}/src/impl/bch/stratum/work_source.cpp)
        target_include_directories(bch_${t} PRIVATE ${CMAKE_SOURCE_DIR}/src)
        target_link_libraries(bch_${t} PRIVATE
            core pool sharechain
            c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
            btclibs)
        add_test(NAME bch_${t} COMMAND bch_${t})
    endforeach()

    # g2_block_assembly_roundtrip_test: the won-block assembly + pre-broadcast
    # self-check gate that closes the G2 zero-blocks failure (155-byte body,
    # zero-output generation transaction, bad-txnmrklroot on ~774k solutions).
    # Needs coin/transaction.cpp for the MutableTransaction ctors, same as
    # block_connector_test; link set and header-only-over-coin/*.hpp posture are
    # otherwise identical, so per-coin isolation stays clean.
    #
    # #887 fold-in: the same file now also drives BCHWorkSource::mining_submit
    # to pin that a WON BLOCK is written to the sharechain as well (block
    # dispatch first, share write strictly after). That needs bch_stratum
    # (work_source.cpp) and its bch_coin dependency. FOLDED into this EXISTING
    # allowlisted target rather than a new add_executable -- a new one would
    # silently report "Not Run" (see merged PR #868). Still bch-only, so the
    # per-coin isolation invariant holds.
    # F2/F3 share-broadcast gate KATs ride bch_embedded_block_broadcast_test (an
    # already-allowlisted --target). The bch test tree has no GTest harness and a
    # standalone target would need a build.yml entry this repo's CI token cannot
    # add, which CTest would then report as a silently-passing NOT_BUILT sentinel.
    target_sources(bch_embedded_block_broadcast_test PRIVATE broadcast_gate_test.cpp)

    add_executable(bch_g2_block_assembly_roundtrip_test
        g2_block_assembly_roundtrip_test.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/transaction.cpp)
    target_include_directories(bch_g2_block_assembly_roundtrip_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(bch_g2_block_assembly_roundtrip_test PRIVATE
        core pool sharechain
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
        bch_stratum bch_coin
        btclibs)
    add_test(NAME bch_g2_block_assembly_roundtrip_test COMMAND bch_g2_block_assembly_roundtrip_test)
endif()
