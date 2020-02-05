# cmake_minimum_required(VERSION <specify CMake version here>)
project(cpool)

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(lib/googletest)
include_directories(lib/googletest/googletest/include)

add_executable(cpool src/main.cpp)

target_link_libraries(cpool gtest gtest_main)