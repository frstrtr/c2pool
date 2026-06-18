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
endif()
