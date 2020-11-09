include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

#TODO: shareTypes
#TODO: trackerTest
set(SHARE_TESTS_SOURCE shareTypes_test.cpp share_test.cpp #[[tracker_test.cpp]] shareStore_test.cpp)
add_executable(runShareTests ${SHARE_TESTS_SOURCE})


target_compile_definitions(runShareTests PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")
target_link_libraries(runShareTests gtest gtest_main)
target_link_libraries(runShareTests btclibs networks sharechain)
# target_include_directories(runUtilTests PUBLIC ${Python3_INCLUDE_DIRS})

# if(WIN32)
#     target_link_libraries(runUtilTests ws2_32) #возник баг, без этого не компилится boost код.
#     target_link_libraries(runUtilTests wsock32) #возник баг, без этого не компилится boost код.
# endif()