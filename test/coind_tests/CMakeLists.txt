include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

set(COIND_TESTS_SOURCE data_test.cpp data_test2.cpp) #rpcjson_test.cpp data_test.cpp p2p_test.cpp)

#if (EXISTS ${CMAKE_CURRENT_LIST_DIR}/pass.h)
#    message("exist coind pass file in tests!")
#    add_compile_definitions(PASS_EXIST)
#    set(COIND_TESTS_SOURCE ${COIND_TESTS_SOURCE} pass.h)
#endif()

add_executable(coind_test ${COIND_TESTS_SOURCE})
set_target_properties(coind_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

target_link_libraries(coind_test gtest gtest_main)
target_link_libraries(coind_test libdevcore networks libcoind btclibs util)

add_executable(tx_test tx_test.cpp)
target_link_libraries(tx_test gtest gtest_main)
target_link_libraries(tx_test libdevcore networks libcoind btclibs util)


add_executable(stratum_test_exec stratum_test_exec.cpp)
target_link_libraries(stratum_test_exec devcore networks libcoind)

add_executable(addr_convert_test addr_convert_test.cpp)
target_link_libraries(addr_convert_test gtest gtest_main)
target_link_libraries(addr_convert_test libdevcore networks libcoind)