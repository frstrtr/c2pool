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
endif()
