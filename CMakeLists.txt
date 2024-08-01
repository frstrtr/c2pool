cmake_minimum_required(VERSION 3.22)
project(c2pool CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# set(BUILD_SHARED_LIBS OFF)
# set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
# if(NOT CMAKE_BUILD_TYPE)
#   set(CMAKE_BUILD_TYPE Release)
# endif()

# set(CMAKE_CXX_FLAGS "-Wall")
# set(CMAKE_CXX_FLAGS_DEBUG "-g")
# set(CMAKE_CXX_FLAGS_RELEASE "-O2")

find_package(GTest REQUIRED)
find_package(Boost REQUIRED)
find_package(nlohmann_json REQUIRED)

include(CTest)
include_directories(include)
include_directories(src)

add_subdirectory(src)
add_subdirectory(test)
add_subdirectory(benchmark)
add_subdirectory(temp)