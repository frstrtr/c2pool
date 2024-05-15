cmake_minimum_required(VERSION 3.22)
project(c2pool CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
project(c2pool)

find_package(Boost REQUIRED)
find_package(nlohmann_json REQUIRED)

include_directories(src)

add_subdirectory(src)
add_subdirectory(benchmark)
add_subdirectory(temp)