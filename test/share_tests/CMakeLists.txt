include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

#TODO: shareTypes
#TODO: trackerTest
#set(SHARE_TESTS_SOURCE shareTypes_test.cpp share_test.cpp tracker_test.cpp shareStore_test.cpp)
set(SHARE_TESTS_SOURCE tracker_test.cpp share_test.cpp)
add_executable(sharechains_test ${SHARE_TESTS_SOURCE})
set_target_properties(sharechains_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")


target_compile_definitions(sharechains_test PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")
target_link_libraries(sharechains_test gtest gtest_main)
target_link_libraries(sharechains_test btclibs networks sharechains univalue)