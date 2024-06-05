if (BUILD_TESTING)
    add_executable(pack_test pack_test.cpp)
    target_link_libraries(pack_test PRIVATE GTest::gtest_main core GTest::gtest )

    include(GoogleTest)
    include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
    # add_test(NAME pack_test COMMAND pack_test)
    gtest_add_tests(pack_test "" AUTO)
endif()