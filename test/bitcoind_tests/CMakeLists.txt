include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

set(BITCOIND_TESTS_SOURCE data_test.cpp rpcjson_test.cpp)
add_executable(BitcoindTests ${BITCOIND_TESTS_SOURCE})

target_compile_definitions(BitcoindTests PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")
target_link_libraries(BitcoindTests gtest gtest_main)
target_link_libraries(BitcoindTests networks bitcoind)
