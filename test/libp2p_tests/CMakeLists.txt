include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

set(LIBP2P_TEST_SRC handler_test.cpp)
add_executable(libp2p_test ${LIBP2P_TEST_SRC})
set_target_properties(libp2p_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

target_link_libraries(libp2p_test gtest gtest_main)
target_link_libraries(libp2p_test libp2p libdevcore)
