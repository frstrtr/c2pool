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
    # Enable C++ unwind semantics (/EHsc). Boost headers (asio, log, signals2)
    # reference the inline boost::throw_exception, which links as an unresolved
    # external (LNK2019) unless exceptions are enabled. The pinned Conan MSVC
    # toolchain does not guarantee CMake's default /EHsc, so set it explicitly
    # for every MSVC target — the coin binaries and the CI boost_sentinel alike.
    add_compile_options(/EHsc)
endif()

# Handle CMake 3.30+ policy for FindBoost removal
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

# Find optional GTest for testing
find_package(GTest QUIET)

# Try modern BoostConfig first, fallback to FindBoost for older systems
# system is header-only since Boost 1.69; only request it if the config provides it
find_package(Boost REQUIRED COMPONENTS log log_setup thread filesystem exception)
find_package(Boost QUIET OPTIONAL_COMPONENTS system)

find_package(nlohmann_json REQUIRED)
find_package(yaml-cpp REQUIRED)  # hoisted to root so yaml-cpp::yaml-cpp is visible to src/c2pool OBJECT libs (sibling of src/core)

# Optional dashd ZMQ `hashblock` INSTANT tip-notify (DASH fallback-arm hardening
# on top of the #770 3 s poll). libzmq is an OPTIONAL dependency: when present
# the c2pool-dash --coin-zmq-hashblock path is compiled (C2POOL_ZMQ define);
# when absent c2pool-dash builds + runs exactly as the poll-only path. The conan
# recipe (zeromq/4.3.5) exposes the CMake target `libzmq` via package `ZeroMQ`.
option(C2POOL_WITH_ZMQ "Build dashd ZMQ hashblock instant tip-notify (optional; needs libzmq)" ON)
set(C2POOL_ZMQ_AVAILABLE OFF)
set(C2POOL_ZMQ_TARGET "")
if(C2POOL_WITH_ZMQ)
    find_package(ZeroMQ QUIET)
    if(TARGET libzmq)
        set(C2POOL_ZMQ_AVAILABLE ON)
        set(C2POOL_ZMQ_TARGET libzmq)
    elseif(TARGET libzmq-static)
        set(C2POOL_ZMQ_AVAILABLE ON)
        set(C2POOL_ZMQ_TARGET libzmq-static)
    elseif(TARGET zmq)
        set(C2POOL_ZMQ_AVAILABLE ON)
        set(C2POOL_ZMQ_TARGET zmq)
    endif()
    if(C2POOL_ZMQ_AVAILABLE)
        message(STATUS "dashd ZMQ hashblock tip-notify: ENABLED (libzmq via ${C2POOL_ZMQ_TARGET})")
    else()
        message(STATUS "dashd ZMQ hashblock tip-notify: DISABLED (libzmq not found; c2pool-dash builds poll-only)")
    endif()
else()
    message(STATUS "dashd ZMQ hashblock tip-notify: DISABLED (C2POOL_WITH_ZMQ=OFF)")
endif()

# Threading (needed by LevelDB on some platforms)
find_package(Threads REQUIRED)

# Find LevelDB for persistent storage
# Try system shared lib first. If only static .a is found (Conan cross-compile),
# use find_package which properly links transitive deps (snappy, crc32c).
find_library(LEVELDB_LIB_PATH NAMES leveldb)
find_path(LEVELDB_INC_PATH leveldb/db.h)
if(LEVELDB_LIB_PATH AND LEVELDB_INC_PATH AND LEVELDB_LIB_PATH MATCHES "\\.(so|dylib)")
    set(LEVELDB_LIBRARIES ${LEVELDB_LIB_PATH})
    set(LEVELDB_INCLUDE_DIRS ${LEVELDB_INC_PATH})
    message(STATUS "LevelDB found (shared): ${LEVELDB_LIBRARIES}")
else()
    find_package(leveldb QUIET)
    if(TARGET leveldb::leveldb)
        message(STATUS "LevelDB found via find_package (Conan/vcpkg)")
        set(LEVELDB_LIBRARIES leveldb::leveldb)
        set(LEVELDB_INCLUDE_DIRS "")
    elseif(LEVELDB_LIB_PATH AND LEVELDB_INC_PATH)
        # Shared lib on non-standard path (Homebrew)
        set(LEVELDB_LIBRARIES ${LEVELDB_LIB_PATH})
        set(LEVELDB_INCLUDE_DIRS ${LEVELDB_INC_PATH})
        message(STATUS "LevelDB found: ${LEVELDB_LIBRARIES}")
    else()
        message(FATAL_ERROR "LevelDB not found. Install leveldb-dev or add to Conan.")
    endif()
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

# ── E1 Phase-L: optional dashbls (BLS12-381) backend for type-6 quorum-
# commitment verification ────────────────────────────────────────────────────
# dashpay/bls-signatures ("dashbls", relic-backed, Apache-2.0) — the SAME
# library dashd wraps in src/bls/bls.h. OPT-IN and DASH-ONLY: only the DASH impl
# (dash_bls_verify) + its KAT consume it, never the shared core the Windows
# main_ltc launcher builds ([[reference_windows_ci_conan_flake]]: Windows CI
# builds only the LTC launcher, so DASH-only BLS code cannot break it). When the
# option is OFF (default) or the library is not found, dash_bls_verify compiles a
# fail-closed stub and the DKG-window serve path keeps the pre-Phase-L
# null-commitment posture exactly — no dashbls dependency enters any build.
#
# Build the library once for the CI factory with scripts/build_dashbls.sh (builds
# dash's OWN src/dashbls subtree at the v23.1.7 tag — byte-identical to dashd);
# point cmake at it with -DDASHBLS_ROOT=<prefix>.
option(C2POOL_DASH_BLS "Link dashbls (BLS12-381) for E1 Phase-L real quorum-commitment verify" OFF)
set(C2POOL_DASH_BLS_AVAILABLE OFF)
if(C2POOL_DASH_BLS)
    # Honour a DASHBLS_ROOT hint (the build-factory install prefix), else search
    # the system paths. dashbls installs: include/dashbls/*.hpp,
    # lib/libdashbls.a, lib/librelic_s.a, lib/mimalloc-2.0/libmimalloc-secure.a.
    find_path(DASHBLS_INCLUDE_DIR dashbls/bls.hpp
        HINTS ${DASHBLS_ROOT} ENV DASHBLS_ROOT PATH_SUFFIXES include)
    find_library(DASHBLS_LIB       NAMES dashbls bls-dash
        HINTS ${DASHBLS_ROOT} ENV DASHBLS_ROOT PATH_SUFFIXES lib)
    find_library(DASHBLS_RELIC_LIB NAMES relic_s relic
        HINTS ${DASHBLS_ROOT} ENV DASHBLS_ROOT PATH_SUFFIXES lib)
    find_library(DASHBLS_MIMALLOC_LIB NAMES mimalloc-secure mimalloc
        HINTS ${DASHBLS_ROOT} ENV DASHBLS_ROOT PATH_SUFFIXES lib lib/mimalloc-2.0 lib/mimalloc-2.1)
    find_library(DASHBLS_GMP_LIB NAMES gmp)
    # NOTE: the autotools install (scripts/build_dashbls.sh, the only build
    # path dash's v23.1.7 src/dashbls subtree supports) folds relic + mimalloc
    # INTO libdashbls.a — so the separate relic/mimalloc libs are OPTIONAL and
    # only linked when present (the legacy standalone-CMake layout).
    if(DASHBLS_INCLUDE_DIR AND DASHBLS_LIB AND DASHBLS_GMP_LIB)
        set(C2POOL_DASH_BLS_AVAILABLE ON)
        set(DASHBLS_LIBRARIES ${DASHBLS_LIB})
        if(DASHBLS_RELIC_LIB)
            list(APPEND DASHBLS_LIBRARIES ${DASHBLS_RELIC_LIB})
        endif()
        if(DASHBLS_MIMALLOC_LIB)
            list(APPEND DASHBLS_LIBRARIES ${DASHBLS_MIMALLOC_LIB})
        endif()
        list(APPEND DASHBLS_LIBRARIES ${DASHBLS_GMP_LIB})
        message(STATUS "dashbls found (E1 Phase-L BLS verify ENABLED): ${DASHBLS_LIB}")
        message(STATUS "dashbls includes: ${DASHBLS_INCLUDE_DIR}")
    else()
        message(WARNING "C2POOL_DASH_BLS=ON but dashbls not found "
            "(need dashbls + relic + gmp; run scripts/build_dashbls.sh and pass "
            "-DDASHBLS_ROOT=<prefix>). Falling back to fail-closed null-serve.")
    endif()
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

# Boost.Asio build compat (build-only, no behaviour change): force-include the
# handler_invoke_helpers shim ahead of every C++ TU so a legacy system Boost
# leaking boost/asio/impl/system_executor.hpp cannot break the conan-pinned
# build on any coin, regardless of ccache eviction. See core/boost_asio_compat.hpp.
# MSVC/Windows carries no legacy *system* Boost under /usr/include, so it has
# nothing to leak and does not need (or resolve) this force-include. Gating to
# non-MSVC avoids C1083 on the MSVC path while keeping the Linux/macOS fix.
if(NOT MSVC)
  add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:-include;core/boost_asio_compat.hpp>")
endif()

# Make secp256k1 headers available globally (needed by btclibs, impl/)
if(SECP256K1_INCLUDE_DIRS)
    include_directories(${SECP256K1_INCLUDE_DIRS})
endif()

add_subdirectory(src)
add_subdirectory(test)
# Boost header-integrity + version sentinel (CI compile-gate; testing-only).
if(GTest_FOUND OR GTEST_FOUND)
    add_subdirectory(ci/sentinel)
endif()
# add_subdirectory(benchmark)
# add_subdirectory(temp)