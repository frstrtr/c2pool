include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

set(UTIL_TESTS_SOURCE deferred_test.cpp)
add_executable(util_test ${UTIL_TESTS_SOURCE})
set_target_properties(util_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

target_link_libraries(util_test gtest gtest_main)
target_link_libraries(util_test libdevcore)
