if (BUILD_TESTING AND GTest_FOUND)
    add_executable(test_coin_broadcaster test_coin_broadcaster.cpp)
    target_link_libraries(test_coin_broadcaster PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_merged_mining
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    include(GoogleTest)
    gtest_add_tests(test_coin_broadcaster "" AUTO)
endif()
