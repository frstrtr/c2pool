cmake_minimum_required(VERSION 3.21)

# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-qt — Family A (Bitcoin-script) cross-coin address CONVERT + CONSTRUCT
# core, phase M2-A (#193). Design docs/design/c2wallet-qt.md §4.1, requirement 5.
#
# DELIBERATELY Qt-FREE and READ-ONLY (address derivation only — no keys, no
# signing). It reuses, never re-implements (design §2.4 reuse table):
#   * the #961 engine  src/core/address_utils.{hpp,cpp}
#     (classify_address_for_coin + the Own/Foreign/Invalid trichotomy);
#   * the BCH CashAddr codec  src/impl/bch/coin/cashaddr.hpp (header-only);
#   * the M1-A hdkeys codecs (base58 / bech32 / bech32m encoders, hash160) via
#     the c2wallet-hdkeys static library.
# No Qt, no networking — it inherits the M0 network-incapable property and its
# KATs run without the Qt app.
#
# Standalone use (what CI / a developer runs for just this target):
#   cmake -S ui/c2wallet-qt/src/family/bitcoin/construct -B build-convert \
#         -DC2WALLET_QT_BUILD_TESTS=ON
#   cmake --build build-convert --target c2wallet-convert-test
#   ctest --test-dir build-convert --output-on-failure
# ═══════════════════════════════════════════════════════════════════════════

if(NOT DEFINED PROJECT_NAME)
    project(c2wallet_convert LANGUAGES C CXX)
    set(_convert_standalone ON)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Repo root: construct -> bitcoin -> family -> src -> c2wallet-qt -> ui -> <root>
get_filename_component(C2POOL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../.." ABSOLUTE)
set(C2POOL_SRC "${C2POOL_ROOT}/src")

# The M1-A hdkeys library supplies the reused btclibs closure (base58/bech32/
# hash primitives) plus the M1-A address encoders and hash160. Bring it in when
# building standalone; the top-level ui/CMakeLists adds it before this subdir.
if(NOT TARGET c2wallet-hdkeys)
    add_subdirectory(${C2POOL_ROOT}/ui/c2wallet-qt/src/family/bitcoin/hdkeys
                     ${CMAKE_CURRENT_BINARY_DIR}/hdkeys-build)
endif()

# The #961 engine — the only ADDITIONAL reused c2pool source this module
# compiles (its btclibs dependencies resolve from c2wallet-hdkeys at link time).
add_library(c2wallet-convert STATIC
    Convert.cpp
    ConvertCoins.cpp
    BchTranscode.cpp
    AddressConstruct.cpp
    ${C2POOL_SRC}/core/address_utils.cpp
)

target_include_directories(c2wallet-convert PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${C2POOL_SRC}
    ${C2POOL_SRC}/btclibs
    ${C2POOL_SRC}/btclibs/util
    ${C2POOL_SRC}/btclibs/crypto
    ${C2POOL_SRC}/btclibs/compat
)

target_link_libraries(c2wallet-convert PUBLIC c2wallet-hdkeys)

option(C2WALLET_QT_BUILD_TESTS "Build the convert/construct KAT test" OFF)
if(C2WALLET_QT_BUILD_TESTS OR _convert_standalone)
    enable_testing()
    add_executable(c2wallet-convert-test tests/test_convert.cpp)
    target_link_libraries(c2wallet-convert-test PRIVATE c2wallet-convert)
    add_test(NAME convert_kats COMMAND c2wallet-convert-test)
endif()
