include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

set(UTIL_TESTS_SOURCE pack_test.cpp pystruct_test.cpp)

add_executable(runUtilTests ${UTIL_TESTS_SOURCE})

target_compile_definitions(runUtilTests PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")
target_link_libraries(runUtilTests gtest gtest_main)
target_link_libraries(runUtilTests util)