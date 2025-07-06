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

# Handle CMake 3.30+ policy for FindBoost removal
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

# Find optional GTest for testing
find_package(GTest QUIET)

# Try modern BoostConfig first, fallback to FindBoost for older systems
find_package(Boost REQUIRED COMPONENTS log log_setup thread filesystem system)

find_package(nlohmann_json REQUIRED)

# Find LevelDB for persistent storage
find_library(LEVELDB_LIBRARIES leveldb)
find_path(LEVELDB_INCLUDE_DIRS leveldb/db.h)
if(NOT LEVELDB_LIBRARIES OR NOT LEVELDB_INCLUDE_DIRS)
    message(FATAL_ERROR "LevelDB not found. Please install leveldb development package.")
endif()
message(STATUS "LevelDB found: ${LEVELDB_LIBRARIES}")
message(STATUS "LevelDB includes: ${LEVELDB_INCLUDE_DIRS}")

# Enable testing only if GTest is found
if(GTest_FOUND OR GTEST_FOUND)
    enable_testing()
    include(CTest)
    message(STATUS "GTest found - testing enabled")
else()
    message(STATUS "GTest not found - testing disabled")
endif()
include_directories(include)
include_directories(src)

add_subdirectory(src)
add_subdirectory(test)
# add_subdirectory(benchmark)
# add_subdirectory(temp)