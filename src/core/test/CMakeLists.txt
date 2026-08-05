if (BUILD_TESTING AND (GTest_FOUND OR GTEST_FOUND))
    # known_txs_eviction_test.cpp: recency-preserving bounded eviction of the
    # node-level known-tx relay cache (core/known_txs_eviction.hpp), the shared
    # helper that replaces the wholesale m_known_txs.clear() in all four of the
    # LTC/DGB/BCH/BTC node lanes. Header-only over core (uint256), so it is FOLDED
    # into the EXISTING allowlisted core_test target rather than a new
    # add_executable — a standalone target is not in build.yml's --target list, so
    # CI never builds it and CTest reports the cases "Not Run" (the #769 trap). One
    # KAT covers all four coins since they consume one shared core helper.
    #
    # tx_advertiser_test.cpp: SEND side of the p2pool have_tx / losing_tx tx-pool
    # advertisement (core/tx_advertiser.hpp) — the per-peer advertised-set delta
    # model, the have-before-losing ordering, and the wire chunk bound. Same
    # reasoning as above: header-only over core, so it is FOLDED into the
    # EXISTING allowlisted core_test target (never a new add_executable — that is
    # the #769 "Not Run" trap), and one KAT covers every coin because all five
    # node lanes consume this one shared helper.
    #
    # socket_write_queue_test.cpp: the core::Socket OUTBOUND WRITE QUEUE (#863).
    # Drives a real loopback TCP pair with a small send buffer and submits
    # overlapping composed writes from off-io threads; without the queue those
    # writes splice bytes mid-message and the assertions fail. One KAT covers
    # every coin because all five node lanes share this one socket layer. Same
    # reasoning as above: FOLDED into the EXISTING allowlisted core_test target,
    # never a new add_executable (the #769 "Not Run" trap).
    #
    # known_txs_backing_test.cpp: the coin-generic share-broadcast tx-completeness
    # gate and the mark-only-what-was-sent de-dup rule (core/known_txs_backing.hpp),
    # hoisted out of impl/dash/known_txs_retention.hpp so every node lane consumes
    # ONE definition instead of each growing a copy. Same reasoning again:
    # header-only over core, so it is FOLDED into the EXISTING allowlisted
    # core_test target, never a new add_executable (the #769 "Not Run" trap).
    # random_choice_guard_test.cpp: the #869 addrme peer-relay guard. Covers the
    # core/random.hpp empty-container backstop plus a source KAT pinning the
    # !m_peers.empty() / !m_connections.empty() relay predicates across all five
    # per-coin protocol_legacy.cpp / protocol_actual.cpp addrme+addrs handlers.
    # Same reasoning as above: FOLDED into the EXISTING allowlisted core_test
    # target, never a new add_executable.
    # p2p_message_stats_test.cpp: the p2p wire observability layer
    # (core/p2p_message_stats.hpp) -- command -> message-type mapping including
    # the NUL-padded wire form, the per-direction counters, and the embedded-
    # timestamp saturation detector that backs the DASH deploy criterion.
    # Header-only over core, and BOTH instrumentation points
    # (pool::NodeBridge::handle inbound, pool::Peer::write outbound) are shared
    # code every coin lane routes through, so one KAT covers all coins. Same
    # reasoning as above: FOLDED into the EXISTING allowlisted core_test target,
    # never a new add_executable (the #769 "Not Run" trap).
    #
    # netaddress_resolution_test.cpp: the #910 DNS-named-addnode defect. Pins the
    # Write_IPV4 wire bytes for dotted quads and for genuine loopback (a p2p
    # surface shared with canonical python p2pool — a byte change would be a
    # compat break), proves a hostname never serializes to 127.0.0.1 and does
    # serialize to the A record the outbound-connect resolver memoised, and
    # carries a source KAT pinning the is_wire_advertisable() guard into all ten
    # per-coin getaddrs handlers. Same reasoning as above: FOLDED into the
    # EXISTING allowlisted core_test target, never a new add_executable.
    add_executable(core_test pack_test.cpp events_test.cpp chain_test.cpp packet_test.cpp block_broadcast_test.cpp broadcast_convergence_matrix_test.cpp core_merkle_branches_test.cpp version_gate_test.cpp filesystem_test.cpp web_server_submitblock_test.cpp web_server_current_payouts_test.cpp web_server_local_hashps_test.cpp web_server_relay_block_test.cpp known_txs_eviction_test.cpp tx_advertiser_test.cpp socket_write_queue_test.cpp known_txs_backing_test.cpp random_choice_guard_test.cpp p2p_message_stats_test.cpp netaddress_resolution_test.cpp)
    target_compile_definitions(core_test PRIVATE C2POOL_SRC_ROOT="${CMAKE_SOURCE_DIR}/src")
    target_link_libraries(core_test PRIVATE GTest::gtest_main core c2pool_merged_mining GTest::gtest)
    target_link_libraries(core_test PRIVATE c2pool_payout c2pool_hashrate ltc_coin)  # OBJECT-lib SCC direct-naming (#22/#39)

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    # add_test(NAME pack_test COMMAND pack_test)
    gtest_add_tests(core_test "" AUTO)
else()
    message(STATUS "Skipping core tests - GTest not found")
endif()