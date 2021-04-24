#include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})


set(BTCLIBS_TESTS_SOURCE uint_test.cpp hashing_test.cpp crypto_test.cpp)
add_executable(btclibs_test ${BTCLIBS_TESTS_SOURCE})

# target_compile_definitions(runBtclibsTests PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")
target_link_libraries(btclibs_test gtest gtest_main)
target_link_libraries(btclibs_test btclibs Secp256k1)