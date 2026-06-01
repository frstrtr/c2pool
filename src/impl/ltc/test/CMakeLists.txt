if (BUILD_TESTING AND GTest_FOUND)
    add_executable(share_test share_test.cpp)
    target_link_libraries(share_test PRIVATE
        GTest::gtest_main GTest::gtest
        $<LINK_GROUP:RESCAN,core,sharechain,pool,ltc,btclibs,c2pool_payout,c2pool_hashrate,c2pool_merged_mining>
    )

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    gtest_add_tests(share_test "" AUTO)
endif()