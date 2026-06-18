# DGB module tests. Mirrors src/impl/ltc/test/CMakeLists.txt — links the dgb
# OBJECT lib (pool/share TU) so the share codec + consensus params are build-
# verified into a test executable. Gated on BUILD_TESTING + GTest like the
# sibling coins; registered via gtest_add_tests for the CI --target allowlist.
if (BUILD_TESTING AND GTest_FOUND)
    add_executable(dgb_share_test share_test.cpp)
    target_link_libraries(dgb_share_test PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb
    )
    # OBJECT-lib SCC direct-naming (#22/#39) — mirror the ltc test link set.
    target_link_libraries(dgb_share_test PRIVATE
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain)

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    gtest_add_tests(dgb_share_test "" AUTO)
endif()
