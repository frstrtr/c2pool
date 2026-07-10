if (BUILD_TESTING AND GTest_FOUND)
    add_executable(share_test share_test.cpp f11_donation_invariance_test.cpp emergency_decay_overflow_test.cpp)
    target_link_libraries(share_test PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
    )
    target_link_libraries(share_test PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    gtest_add_tests(share_test "" AUTO)
endif()
if (BUILD_TESTING)
    # G2 fill-budget KAT: self-contained header-only unit (no gtest/core
    # deps) -- faithful port of p2pool test_g2_fillbudget.py, own main().
    add_executable(fill_budget_kat_test fill_budget_kat_test.cpp)
    add_test(NAME fill_budget_kat COMMAND fill_budget_kat_test)
endif()
