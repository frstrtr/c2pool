if (BUILD_TESTING AND GTest_FOUND)
    # btc twin of ltc share_test — uniquely named to avoid the CMP0002 target
    # collision with src/impl/ltc/test (both subdirs build in the same tree).
    add_executable(btc_share_test share_test.cpp f11_donation_invariance_test.cpp f10b_version_punish_removal_test.cpp g01_share_format_parity_test.cpp)
    target_link_libraries(btc_share_test PRIVATE
        GTest::gtest_main GTest::gtest
        core btc
    )
    target_link_libraries(btc_share_test PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage btc_coin btclibs pool sharechain ${SECP256K1_LIBRARIES})  # OBJECT-lib SCC direct-naming (#22/#39), btc twin

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    gtest_add_tests(btc_share_test "" AUTO)
    # btc_auto_ratchet_tail_guard_test: FENCED additive KAT suite pinning the
    # AutoRatchet staged V35->V36 gate logic (auto_ratchet.hpp, NOT rewired).
    # Pure-arithmetic mirror; core + OBJECT-lib SCC deps (stratum_server.o). MUST also be in build.yml
    # --target allowlist (#137/#143 NOT_BUILT trap).
    add_executable(btc_auto_ratchet_tail_guard_test auto_ratchet_tail_guard_test.cpp)
    target_link_libraries(btc_auto_ratchet_tail_guard_test PRIVATE
        GTest::gtest_main GTest::gtest
        core c2pool_merged_mining c2pool_payout c2pool_hashrate ltc_coin)  # OBJECT-lib SCC direct-naming (#22/#39), mirrors core_test
    gtest_add_tests(btc_auto_ratchet_tail_guard_test "" AUTO)

endif()
