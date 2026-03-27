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
        core ltc
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

    add_executable(test_template_builder test_template_builder.cpp)
    target_link_libraries(test_template_builder PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_phase3_live test_phase3_live.cpp)
    target_link_libraries(test_phase3_live PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_merged_mining
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_phase4_embedded test_phase4_embedded.cpp)
    target_link_libraries(test_phase4_embedded PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_phase4_live test_phase4_live.cpp)
    target_link_libraries(test_phase4_live PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_merged_mining
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_threading test_threading.cpp)
    target_link_libraries(test_threading PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    add_executable(test_weights test_weights.cpp)
    target_link_libraries(test_weights PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )

    include(GoogleTest)
    gtest_add_tests(test_weights "" AUTO)
    gtest_add_tests(test_threading "" AUTO)
    gtest_add_tests(test_coin_broadcaster "" AUTO)
    gtest_add_tests(test_share_messages "" AUTO)
    gtest_add_tests(test_hardening "" AUTO)
    gtest_add_tests(test_redistribute_address "" AUTO)
    gtest_add_tests(test_phase0_live "" AUTO)
    gtest_add_tests(test_header_chain "" AUTO)
    gtest_add_tests(test_phase1_live "" AUTO)
    gtest_add_tests(test_mempool "" AUTO)
    gtest_add_tests(test_phase2_live "" AUTO)
    gtest_add_tests(test_template_builder "" AUTO)
    gtest_add_tests(test_phase3_live "" AUTO)
    gtest_add_tests(test_phase4_embedded "" AUTO)
    gtest_add_tests(test_phase4_live "" AUTO)

    add_executable(test_doge_chain test_doge_chain.cpp)
    target_link_libraries(test_doge_chain PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_add_tests(test_doge_chain "" AUTO)

    add_executable(test_compact_blocks test_compact_blocks.cpp)
    target_link_libraries(test_compact_blocks PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_add_tests(test_compact_blocks "" AUTO)

    add_executable(test_redistribute test_redistribute.cpp)
    target_link_libraries(test_redistribute PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_add_tests(test_redistribute "" AUTO)

    add_executable(test_auto_ratchet test_auto_ratchet.cpp)
    target_link_libraries(test_auto_ratchet PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_add_tests(test_auto_ratchet "" AUTO)

    add_executable(test_stratum_extensions test_stratum_extensions.cpp)
    target_link_libraries(test_stratum_extensions PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_hashrate
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_add_tests(test_stratum_extensions "" AUTO)

    add_executable(test_multiaddress_pplns test_multiaddress_pplns.cpp)
    target_link_libraries(test_multiaddress_pplns PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_merged_mining
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_add_tests(test_multiaddress_pplns "" AUTO)

    add_executable(test_pplns_stress test_pplns_stress.cpp)
    target_link_libraries(test_pplns_stress PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_merged_mining
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_add_tests(test_pplns_stress "" AUTO)

    add_executable(test_hash_link test_hash_link.cpp)
    target_link_libraries(test_hash_link PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_add_tests(test_hash_link "" AUTO)

    add_executable(test_decay_pplns test_decay_pplns.cpp)
    target_link_libraries(test_decay_pplns PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_add_tests(test_decay_pplns "" AUTO)

    add_executable(test_pplns_consensus test_pplns_consensus.cpp)
    target_link_libraries(test_pplns_consensus PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_add_tests(test_pplns_consensus "" AUTO)

    add_executable(test_v36_script_sorting test_v36_script_sorting.cpp)
    target_link_libraries(test_v36_script_sorting PRIVATE
        GTest::gtest_main GTest::gtest
    )
    gtest_add_tests(test_v36_script_sorting "" AUTO)

    add_executable(test_v36_cross_impl_refhash test_v36_cross_impl_refhash.cpp)
    target_link_libraries(test_v36_cross_impl_refhash PRIVATE
        GTest::gtest_main GTest::gtest
        core
    )
    gtest_add_tests(test_v36_cross_impl_refhash "" AUTO)

    add_executable(test_mweb_builder test_mweb_builder.cpp)
    target_link_libraries(test_mweb_builder PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_add_tests(test_mweb_builder "" AUTO)
endif()
