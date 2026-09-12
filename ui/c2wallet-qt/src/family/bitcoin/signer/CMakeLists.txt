cmake_minimum_required(VERSION 3.21)

# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-qt — Family A (Bitcoin-script) SIGNING core, phases M3-A + M4-A (#193).
# Design docs/design/c2wallet-qt.md §4.1 (spend matrix + "Wrapped & nested
# scripts") and §5.3 (self-verify-before-emit; RFC6979/low-S/DER; oversize).
#
# HIGH money-path: this module produces spendable signatures. It is DELIBERATELY
# Qt-FREE and NETWORK-FREE (inherits the M0 network-incapable property), so its
# KATs build and run without the Qt app.
#
# It REUSES, never re-implements (design §2.4 reuse table):
#   * the vendored dashscript interpreter — CScript, EvalScript/VerifyScript,
#     and the legacy SignatureHash (SigVersion::BASE) — compiled here from the
#     SAME leaf closure the in-tree dash_scriptcheck target uses
#     (src/impl/dash/coin/vendor/dashscript/*), plus its vendored SHA/RIPEMD/
#     Hash and CPubKey ECDSA-verify;
#   * the system libsecp256k1 (design §2.4: system-linked) for ECDSA signing AND
#     BIP340/341/342 Schnorr (schnorrsig + extrakeys — x-only, keypair tweak);
#   * the M0 secure/SecureString zeroizing containers for the private scalars.
# NEW code (design §4.1: "NEW code"): the BIP143 v0 sighash + witness
# (de)serialization + the wrapping / multi-party-combine assembly (M3-A); AND
# the full BIP341/342 taproot module (Taproot.*) — taptweak, tap-tree merkle
# folding, control block, bech32m, BIP341 sighash, OP_CHECKSIGADD multisig, and
# a minimal BIP341/342 verifier for the taproot self-check (M4-A).
#
# Standalone use (what CI / a developer runs for just this target):
#   cmake -S ui/c2wallet-qt/src/family/bitcoin/signer -B build-signer \
#         -DC2WALLET_QT_BUILD_TESTS=ON
#   cmake --build build-signer --target c2wallet-taproot-test
#   ctest --test-dir build-signer --output-on-failure
# ═══════════════════════════════════════════════════════════════════════════

if(NOT DEFINED PROJECT_NAME)
    project(c2wallet_signer LANGUAGES C CXX)
    set(_signer_standalone ON)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Repo root: signer -> bitcoin -> family -> src -> c2wallet-qt -> ui -> <root>
get_filename_component(C2POOL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../.." ABSOLUTE)
set(C2WALLET_SRC "${C2POOL_ROOT}/ui/c2wallet-qt/src")
set(DASHSCRIPT "${C2POOL_ROOT}/src/impl/dash/coin/vendor/dashscript")

# ── System libsecp256k1 (ECDSA sign/verify + Schnorr sign/verify) ───────────
find_library(SECP256K1_LIB NAMES secp256k1)
if(NOT SECP256K1_LIB)
    message(FATAL_ERROR "libsecp256k1 not found (apt install libsecp256k1-dev)")
endif()

# ── The vendored dashscript leaf closure (identical to dash_scriptcheck's,
#    minus the pure-C wrapper we don't need) — the interpreter, script, legacy
#    SignatureHash, CPubKey, tx primitives, and its vendored hash crypto. ──────
set(DASHSCRIPT_SOURCES
    ${DASHSCRIPT}/script/interpreter.cpp
    ${DASHSCRIPT}/script/script.cpp
    ${DASHSCRIPT}/script/script_error.cpp
    ${DASHSCRIPT}/pubkey.cpp
    ${DASHSCRIPT}/primitives/transaction.cpp
    ${DASHSCRIPT}/uint256.cpp
    ${DASHSCRIPT}/hash.cpp
    ${DASHSCRIPT}/util/strencodings.cpp
    ${DASHSCRIPT}/util/string.cpp
    ${DASHSCRIPT}/support/cleanse.cpp
    ${DASHSCRIPT}/crypto/sha256.cpp
    ${DASHSCRIPT}/crypto/sha512.cpp
    ${DASHSCRIPT}/crypto/ripemd160.cpp
    ${DASHSCRIPT}/crypto/sha1.cpp
    ${DASHSCRIPT}/crypto/hmac_sha256.cpp
    ${DASHSCRIPT}/crypto/hmac_sha512.cpp
)

set(SIGNER_SOURCES
    Crypto.cpp
    Scripts.cpp
    Bip143.cpp
    Taproot.cpp
    Signer.cpp
    ${C2WALLET_SRC}/secure/SecureString.cpp
    ${DASHSCRIPT_SOURCES}
)

add_library(c2wallet-signer STATIC ${SIGNER_SOURCES})

# The vendored files resolve dashcore's OWN <script/script.h>, <uint256.h>,
# <crypto/*>, <primitives/*>, <config/*> from the dashscript root (BEFORE, so
# they never pick up c2pool's btclibs — which this target deliberately does not
# link). The signer's own headers + the c2wallet src root (for <secure/...>).
target_include_directories(c2wallet-signer BEFORE PUBLIC
    ${DASHSCRIPT}
)
target_include_directories(c2wallet-signer PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${C2WALLET_SRC}
)

# Same knobs the in-tree dash_scriptcheck uses: build the vendored files in
# their bitcoin-internal config, portable SHA256 (no SSE4/asm sources here), and
# drop EllSwift (BIP324) — unused by signing, and its runtime symbol is absent
# from older libsecp256k1.
target_compile_definitions(c2wallet-signer PRIVATE
    BUILD_BITCOIN_INTERNAL DISABLE_OPTIMIZED_SHA256 HAVE_CONFIG_H
    C2POOL_SCRIPTCHECK_NO_ELLSWIFT)

target_link_libraries(c2wallet-signer PUBLIC ${SECP256K1_LIB})

option(C2WALLET_QT_BUILD_TESTS "Build the signer KAT tests" OFF)
if(C2WALLET_QT_BUILD_TESTS OR _signer_standalone)
    enable_testing()
    add_executable(c2wallet-signer-test tests/test_signer.cpp)
    target_link_libraries(c2wallet-signer-test PRIVATE c2wallet-signer)
    add_test(NAME signer_kats COMMAND c2wallet-signer-test)

    add_executable(c2wallet-taproot-test tests/test_taproot.cpp)
    target_link_libraries(c2wallet-taproot-test PRIVATE c2wallet-signer)
    add_test(NAME taproot_kats COMMAND c2wallet-taproot-test)
endif()
