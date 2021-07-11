include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

#TODO: shareTypes
#TODO: trackerTest
set(SHARE_TESTS_SOURCE shareTypes_test.cpp share_test.cpp tracker_test.cpp shareStore_test.cpp)
add_executable(sharechains_test ${SHARE_TESTS_SOURCE})
set_target_properties(sharechains_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")


target_compile_definitions(sharechains_test PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")
target_link_libraries(sharechains_test gtest gtest_main)
target_link_libraries(sharechains_test btclibs networks sharechain)
# target_include_directories(runUtilTests PUBLIC ${Python3_INCLUDE_DIRS})

# if(WIN32)
#     target_link_libraries(runUtilTests ws2_32) #возник баг, без этого не компилится boost код.
#     target_link_libraries(runUtilTests wsock32) #возник баг, без этого не компилится boost код.
# endif()