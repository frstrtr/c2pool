include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

set(LIBNET_TESTS_SOURCE messages_test.cpp handshake_test.cpp worker_test.cpp)
add_executable(libnet_test ${LIBNET_TESTS_SOURCE})
set_target_properties(libnet_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

target_link_libraries(libnet_test gtest gtest_main)
target_link_libraries(libnet_test libnet libcoind)
