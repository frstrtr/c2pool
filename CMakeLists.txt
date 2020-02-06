cmake_minimum_required(VERSION 3.15)
project(cpool)

set(CMAKE_CXX_STANDARD 20)

set(SOURCE_FILES src/main.cpp)
set(UTILS src/util)
add_executable(cpool ${SOURCE_FILES})

include_directories(${UTILS})

add_subdirectory(${UTILS})
add_subdirectory(lib/googletest)
add_subdirectory(test)


target_link_libraries(cpool ${UTILS})