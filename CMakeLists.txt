cmake_minimum_required(VERSION 3.15)
project(cpool)

set(CMAKE_CXX_STANDARD 20)

set(SOURCE_FILES src/main.cpp)
set(UTILS src/util)

FIND_PACKAGE(Boost 1.72.0 REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

find_package(Python3 #[[Libs]] REQUIRED Development)

add_executable(cpool ${SOURCE_FILES})



include_directories(${UTILS})

add_subdirectory(${UTILS})
add_subdirectory(lib/googletest)
add_subdirectory(test)

if(WIN32)
    target_link_libraries(cpool ws2_32) #возник баг, без этого не компилится boost код.
    target_link_libraries(cpool wsock32) #возник баг, без этого не компилится boost код.
endif()

target_compile_definitions(cpool PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")
target_link_libraries(cpool LINK_PUBLIC ${Boost_LIBRARIES} )
#target_link_libraries(cpool ${UTILS})