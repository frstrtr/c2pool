include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

set(UTIL_TESTS_SOURCE python_test.cpp)
add_executable(util_test ${UTIL_TESTS_SOURCE})
set_target_properties(util_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

target_link_libraries(util_test gtest gtest_main)
target_link_libraries(util_test util)
# target_include_directories(runUtilTests PUBLIC ${Python3_INCLUDE_DIRS})
