if (BUILD_TESTING AND GTest_FOUND)
    add_executable(share_test share_test.cpp f11_donation_invariance_test.cpp emergency_decay_overflow_test.cpp wirecompat_runtime_test.cpp desired_version_tally_test.cpp auto_ratchet_sim_test.cpp auto_ratchet_tail_guard_test.cpp)
    target_link_libraries(share_test PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
    )
    target_link_libraries(share_test PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    gtest_add_tests(share_test "" AUTO)
endif()