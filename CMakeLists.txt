cmake_minimum_required(VERSION 3.22)
project(c2pool CXX)
set(CMAKE_CXX_STANDARD 17)
project(c2pool)

find_package(Boost REQUIRED)
find_package(nlohmann_json REQUIRED)

include_directories(src)

add_subdirectory(src)