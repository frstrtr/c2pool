include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

set(UTIL_TESTS_SOURCE python_test.cpp)
add_executable(util_test ${UTIL_TESTS_SOURCE})

target_link_libraries(util_test gtest gtest_main)
target_link_libraries(util_test util)
# target_include_directories(runUtilTests PUBLIC ${Python3_INCLUDE_DIRS})
