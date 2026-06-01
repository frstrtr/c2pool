if (BUILD_TESTING AND GTest_FOUND)
    add_executable(sharechain_test share_test.cpp)
    target_link_libraries(sharechain_test PRIVATE
        GTest::gtest_main GTest::gtest
        $<LINK_GROUP:RESCAN,core,sharechain,pool,ltc,btclibs,ltc_coin,c2pool_storage,c2pool_payout,c2pool_hashrate,c2pool_merged_mining>
    )

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    gtest_add_tests(sharechain_test "" AUTO)
endif()