# share-dice: provably-fair core + verifier + play-money simulator + KATs.
#
# STANDALONE / DEFAULT-OFF / PLAY-MONEY. This is its own CMake project and is
# NOT added to the c2pool root build and NOT to any Qt build (nothing under
# ui/ references it, ui/ has no aggregating CMakeLists). It does not compile
# into the pool node and touches no money-path/consensus code.
#
# It reuses ONLY c2pool's vendored SHA-256 (src/btclibs/crypto/sha256.cpp),
# compiled here on the portable code path (no USE_ASM / no bitcoin-config.h),
# so SHA is never hand-rolled and no node/Qt/Boost dependency is pulled in.
#
# Build & test standalone (from the repo root):
#   cmake -S ui/share-dice -B build/share-dice
#   cmake --build build/share-dice
#   ctest --test-dir build/share-dice --output-on-failure

cmake_minimum_required(VERSION 3.16)
project(share_dice LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Locate the c2pool source tree (two levels up: ui/share-dice -> repo root).
get_filename_component(C2POOL_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../../src" ABSOLUTE)
set(SHA256_SRC "${C2POOL_SRC}/btclibs/crypto/sha256.cpp")

if(NOT EXISTS "${SHA256_SRC}")
    message(FATAL_ERROR "share-dice: expected c2pool SHA-256 at ${SHA256_SRC}")
endif()

# Provably-fair engine + verifier + overlay, reusing c2pool's SHA-256.
add_library(share_dice STATIC
    src/engine.cpp
    "${SHA256_SRC}")
target_include_directories(share_dice PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${C2POOL_SRC}")            # for <btclibs/crypto/sha256.h>, <btclibs/compat/*>
# Portable SHA path only: do NOT define USE_ASM or HAVE_CONFIG_H here.

# Play-money simulator CLI.
add_executable(share-dice-sim src/sim_main.cpp)
target_link_libraries(share-dice-sim PRIVATE share_dice)

# KATs.
enable_testing()
add_executable(share-dice-test test/share_dice_test.cpp)
target_link_libraries(share-dice-test PRIVATE share_dice)
add_test(NAME share-dice-test COMMAND share-dice-test)
