include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})


#set(UTIL_TESTS_SOURCE pack_test.cpp pystruct_test.cpp)
set(MESSAGES_TESTS_SOURCE messages_test.cpp)
add_executable(runUtilTests ${MESSAGES_TESTS_SOURCE})

target_compile_definitions(runUtilTests PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")
target_link_libraries(runUtilTests gtest gtest_main)
target_link_libraries(runUtilTests util)
target_include_directories(runUtilTests PUBLIC ${Python3_INCLUDE_DIRS})

if(WIN32)
    target_link_libraries(runUtilTests ws2_32) #возник баг, без этого не компилится boost код.
    target_link_libraries(runUtilTests wsock32) #возник баг, без этого не компилится boost код.
endif()