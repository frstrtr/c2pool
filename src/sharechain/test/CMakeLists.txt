if (BUILD_TESTING)
    add_executable(sharechain_test share_test.cpp)
    target_link_libraries(sharechain_test PRIVATE GTest::gtest_main GTest::gtest core sharechain)

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    gtest_add_tests(sharechain_test "" AUTO)
endif()