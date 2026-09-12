cmake_minimum_required(VERSION 3.21)

# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-qt — Family A (Bitcoin-script) HD-key core, phase M1-A (#193).
#
# DELIBERATELY Qt-FREE. This module is the offline signer's key layer (BIP39/32,
# derivation presets, WIF/raw-hex import, key generation, address candidates).
# It links only:
#   * a minimal closure of c2pool's vendored btclibs (hash primitives, base58) —
#     reused, never re-implemented (design §2.4 reuse table);
#   * the system libsecp256k1 (design §2.4: "system-linked; headers incl.
#     extrakeys"), for EC pubkey derivation, BIP32 tweak-add and the BIP341
#     key-path taptweak.
# No Qt, no networking — so it builds and its KATs run without the Qt app, and
# it inherits the M0 network-incapable property by construction.
#
# Standalone use (what CI / a developer runs for just this target):
#   cmake -S ui/c2wallet-qt/src/family/bitcoin/hdkeys -B build-hdkeys \
#         -DC2WALLET_QT_BUILD_TESTS=ON
#   cmake --build build-hdkeys --target c2wallet-hdkeys-test
#   ctest --test-dir build-hdkeys --output-on-failure
# ═══════════════════════════════════════════════════════════════════════════

if(NOT DEFINED PROJECT_NAME)
    project(c2wallet_hdkeys LANGUAGES C CXX)
    set(_hdkeys_standalone ON)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Repo root: hdkeys -> bitcoin -> family -> src -> c2wallet-qt -> ui -> <root>
get_filename_component(C2POOL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../.." ABSOLUTE)
set(C2POOL_SRC "${C2POOL_ROOT}/src")

# ── System libsecp256k1 (extrakeys + recovery + schnorrsig headers) ─────────
find_library(SECP256K1_LIB NAMES secp256k1)
if(NOT SECP256K1_LIB)
    message(FATAL_ERROR "libsecp256k1 not found (apt install libsecp256k1-dev)")
endif()

# ── Reused c2pool sources (leaf closure only) ───────────────────────────────
set(REUSED_SOURCES
    ${C2POOL_SRC}/btclibs/crypto/sha256.cpp
    ${C2POOL_SRC}/btclibs/crypto/sha512.cpp
    ${C2POOL_SRC}/btclibs/crypto/ripemd160.cpp
    ${C2POOL_SRC}/btclibs/crypto/hmac_sha512.cpp
    ${C2POOL_SRC}/btclibs/base58.cpp
    ${C2POOL_SRC}/btclibs/hash.cpp
    ${C2POOL_SRC}/btclibs/uint256.cpp
    ${C2POOL_SRC}/btclibs/util/strencodings.cpp
    ${C2POOL_SRC}/btclibs/util/str.cpp
)

set(HDKEYS_SOURCES
    HexUtil.cpp
    Csprng.cpp
    Secp.cpp
    Bip39.cpp
    wordlist_english.cpp
    Bip32.cpp
    CoinParams.cpp
    Derivation.cpp
    Address.cpp
    KeyImport.cpp
    ${C2POOL_ROOT}/ui/c2wallet-qt/src/secure/SecureString.cpp
)

add_library(c2wallet-hdkeys STATIC ${HDKEYS_SOURCES} ${REUSED_SOURCES})

target_include_directories(c2wallet-hdkeys PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${C2POOL_SRC}
    ${C2POOL_SRC}/btclibs
    ${C2POOL_SRC}/btclibs/util
    ${C2POOL_SRC}/btclibs/crypto
    ${C2POOL_SRC}/btclibs/compat
)
# btclibs' base58/hash pull nlohmann/json headers transitively via core_io in
# some builds; the leaf files we compile here do not, but guard the include if
# the header tree is present so a full-repo configure is unaffected.
target_link_libraries(c2wallet-hdkeys PUBLIC ${SECP256K1_LIB})

# Belt: keep the portable SHA256 path (no USE_ASM) so this tiny module never
# needs per-file -march juggling; correctness is byte-identical.

option(C2WALLET_QT_BUILD_TESTS "Build the hdkeys KAT test" OFF)
if(C2WALLET_QT_BUILD_TESTS OR _hdkeys_standalone)
    enable_testing()
    add_executable(c2wallet-hdkeys-test tests/test_hdkeys.cpp)
    target_link_libraries(c2wallet-hdkeys-test PRIVATE c2wallet-hdkeys)
    add_test(NAME hdkeys_kats COMMAND c2wallet-hdkeys-test)
endif()
