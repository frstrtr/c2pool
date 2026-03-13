if (BUILD_TESTING AND GTest_FOUND)
    add_executable(test_coin_broadcaster test_coin_broadcaster.cpp)
    target_link_libraries(test_coin_broadcaster PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_merged_mining
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_share_messages test_share_messages.cpp)
    target_link_libraries(test_share_messages PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_hardening test_hardening.cpp)
    target_link_libraries(test_hardening PRIVATE
        GTest::gtest_main GTest::gtest
        core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_redistribute_address test_redistribute_address.cpp)
    target_link_libraries(test_redistribute_address PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        c2pool_payout c2pool_merged_mining c2pool_hashrate
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_phase0_live test_phase0_live.cpp)
    target_link_libraries(test_phase0_live PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_merged_mining
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_header_chain test_header_chain.cpp)
    target_link_libraries(test_header_chain PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_phase1_live test_phase1_live.cpp)
    target_link_libraries(test_phase1_live PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_merged_mining
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_mempool test_mempool.cpp)
    target_link_libraries(test_mempool PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_phase2_live test_phase2_live.cpp)
    target_link_libraries(test_phase2_live PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_merged_mining
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    include(GoogleTest)
    gtest_add_tests(test_coin_broadcaster "" AUTO)
    gtest_add_tests(test_share_messages "" AUTO)
    gtest_add_tests(test_hardening "" AUTO)
    gtest_add_tests(test_redistribute_address "" AUTO)
    gtest_add_tests(test_phase0_live "" AUTO)
    gtest_add_tests(test_header_chain "" AUTO)
    gtest_add_tests(test_phase1_live "" AUTO)
    gtest_add_tests(test_mempool "" AUTO)
    gtest_add_tests(test_phase2_live "" AUTO)
endif()
