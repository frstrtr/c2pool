cmake_minimum_required(VERSION 3.22)
project(c2pool C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
    # Suppress common MSVC warnings for POSIX names and unsafe CRT functions
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS _WINSOCK_DEPRECATED_NO_WARNINGS)
endif()

# Handle CMake 3.30+ policy for FindBoost removal
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

# Find optional GTest for testing
find_package(GTest QUIET)

# Try modern BoostConfig first, fallback to FindBoost for older systems
# system is header-only since Boost 1.69; only request it if the config provides it
find_package(Boost REQUIRED COMPONENTS log log_setup thread filesystem)
find_package(Boost QUIET OPTIONAL_COMPONENTS system)

find_package(nlohmann_json REQUIRED)

# Threading (needed by LevelDB on some platforms)
find_package(Threads REQUIRED)

# Find LevelDB for persistent storage
# Try system library first (Linux), then Conan/vcpkg package (Windows)
find_library(LEVELDB_LIBRARIES leveldb)
find_path(LEVELDB_INCLUDE_DIRS leveldb/db.h)
if(LEVELDB_LIBRARIES AND LEVELDB_INCLUDE_DIRS)
    message(STATUS "LevelDB found: ${LEVELDB_LIBRARIES}")
    message(STATUS "LevelDB includes: ${LEVELDB_INCLUDE_DIRS}")
else()
    find_package(leveldb REQUIRED)
    message(STATUS "LevelDB found via find_package (Conan/vcpkg)")
    set(LEVELDB_LIBRARIES leveldb::leveldb)
    set(LEVELDB_INCLUDE_DIRS "")
endif()

# Find libsecp256k1 for ECDSA signature verification
# Try system library first (Linux), then Conan/vcpkg package (Windows)
find_library(SECP256K1_LIBRARIES secp256k1)
find_path(SECP256K1_INCLUDE_DIRS secp256k1.h)
if(SECP256K1_LIBRARIES AND SECP256K1_INCLUDE_DIRS)
    message(STATUS "secp256k1 found: ${SECP256K1_LIBRARIES}")
    message(STATUS "secp256k1 includes: ${SECP256K1_INCLUDE_DIRS}")
else()
    find_package(secp256k1 REQUIRED)
    message(STATUS "secp256k1 found via find_package (Conan/vcpkg)")
    set(SECP256K1_LIBRARIES secp256k1::secp256k1)
    set(SECP256K1_INCLUDE_DIRS "")
endif()

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

# Make secp256k1 headers available globally (needed by btclibs, impl/)
if(SECP256K1_INCLUDE_DIRS)
    include_directories(${SECP256K1_INCLUDE_DIRS})
endif()

add_subdirectory(src)
add_subdirectory(test)
# add_subdirectory(benchmark)
# add_subdirectory(temp)