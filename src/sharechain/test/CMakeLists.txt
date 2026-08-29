if (BUILD_TESTING AND GTest_FOUND)
    add_executable(sharechain_test share_test.cpp share_variants_clone_ownership_test.cpp)
    target_link_libraries(sharechain_test PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
    )
    target_link_libraries(sharechain_test PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    # #1130 source-structural KAT reads the shipped node.cpp / protocol_*.cpp
    # of all five lanes; give it the src/impl path.
    target_compile_definitions(sharechain_test PRIVATE
        C2POOL_IMPL_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../impl")

    gtest_add_tests(sharechain_test "" AUTO)
endif()