cmake_minimum_required(VERSION 3.21)

# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-qt — Family A (Bitcoin/DASH) special-tx core, phase M3-A-DASH (#193).
# Design docs/design/c2wallet-qt.md §4.1.1 (governance-proposal collateral tx
# builder) + §4.1.2 (message sign/verify). Ported byte-exact from the operator's
# frstrtr/dash-proposal-collateral (see PROVENANCE below).
#
# HIGH money-path: sign_collateral() produces a spendable tx that burns 1 DASH.
# DELIBERATELY Qt-FREE and NETWORK-FREE — inherits the M0 network-incapable
# property; its KATs build and run without the Qt app.
#
# It REUSES, never re-implements (design §2.4):
#   * the M3-A signer (c2wallet-signer) for the legacy SIGHASH_ALL preimage,
#     RFC6979/low-S/DER ECDSA, per-input self-verify through the vendored
#     dashscript interpreter, and the oversize refusal;
#   * the M1-A hdkeys core (c2wallet-hdkeys) for BIP39 seed, BIP32/44
#     derivation, secp256k1 pubkey, base58 and hash160;
#   * the system libsecp256k1 recovery module for the recoverable message sig.
#
# ── TWO LIBS ON PURPOSE ──────────────────────────────────────────────────────
# The signer pulls the vendored dashscript header tree (its own <uint256.h>,
# <hash.h>, <script/*>) added BEFORE the include path; hdkeys pulls c2pool's
# btclibs tree (which also has <hash.h>, <uint256.h>). To keep the two trees
# from meeting in one translation unit, the DASH sources are split:
#   c2wallet-dash-common  — btclibs closure only  (hash/address/key/message)
#   c2wallet-dash-tx      — dashscript closure only (the tx assembly via signer)
# Neither pulls the other's header tree; both link cleanly into one binary
# because static-archive symbol resolution is lazy (the collision is at the
# header level, not the object level).
#
# PROVENANCE / LICENSE: the collateral-hash, tx-assembly and message-signing
# LOGIC is ported from frstrtr/dash-proposal-collateral (Python, MIT,
# Copyright (c) 2026 Alec, "proven vs mainnet"), relicensed by the operator into
# c2pool's AGPL-3.0-or-later on inclusion. The gobject-hash byte layout is itself
# a re-expression of Dash Core (dashpay/dash) governance/common.cpp GetHash().
#
# Standalone use (what CI / a developer runs for just this target):
#   cmake -S ui/c2wallet-qt/src/family/bitcoin/dash -B build-dash \
#         -DC2WALLET_QT_BUILD_TESTS=ON
#   cmake --build build-dash --target c2wallet-dash-test
#   ctest --test-dir build-dash --output-on-failure
# ═══════════════════════════════════════════════════════════════════════════

if(NOT DEFINED PROJECT_NAME)
    project(c2wallet_dash LANGUAGES C CXX)
    set(_dash_standalone ON)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Reuse the M3-A signer and the M1-A hdkeys cores. Guarded so a full-repo
# configure that already added them does not add them twice.
if(NOT TARGET c2wallet-hdkeys)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../hdkeys ${CMAKE_BINARY_DIR}/_dash_hdkeys)
endif()
if(NOT TARGET c2wallet-signer)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../signer ${CMAKE_BINARY_DIR}/_dash_signer)
endif()

# ── btclibs-closure lib: hash / address / key-scan / message ────────────────
add_library(c2wallet-dash-common STATIC
    GovCollateral.cpp
    DashAddress.cpp
    KeyScan.cpp
    DashMessage.cpp
)
target_include_directories(c2wallet-dash-common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# PRIVATE on purpose: this lib's .cpp need the hdkeys (btclibs) include tree,
# but its headers are std-only, so the btclibs tree MUST NOT propagate to
# c2wallet-dash-tx (below) — btclibs and dashscript share the compat/endian.h
# include guard, and leaking btclibs into the dashscript TU guard-skips
# le16toh_internal. The static-lib link dependency still reaches the final exe.
target_link_libraries(c2wallet-dash-common PRIVATE c2wallet-hdkeys)

# ── dashscript-closure lib: the tx assembly, via the M3-A signer ────────────
add_library(c2wallet-dash-tx STATIC CollateralTx.cpp)
target_include_directories(c2wallet-dash-tx PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# c2wallet-signer FIRST so the dashscript <hash.h>/<uint256.h> win for this TU;
# c2wallet-dash-common provides the std-only address/key/gov declarations it
# calls (definitions resolve from the btclibs lib at final link).
target_link_libraries(c2wallet-dash-tx PUBLIC c2wallet-signer c2wallet-dash-common)

option(C2WALLET_QT_BUILD_TESTS "Build the DASH special-tx KAT test" OFF)
if(C2WALLET_QT_BUILD_TESTS OR _dash_standalone)
    enable_testing()
    add_executable(c2wallet-dash-test tests/test_dash.cpp)
    # signer first on the link line (matches the proven link order).
    target_link_libraries(c2wallet-dash-test PRIVATE c2wallet-dash-tx c2wallet-dash-common)
    add_test(NAME dash_kats COMMAND c2wallet-dash-test)

    # The "drive the proven Python as the oracle" leg: proto_hash_oracle.py (the
    # stdlib-only reference port) recomputes the gobject hashes and asserts the
    # C++ test binary emits byte-identical values. Skipped if python3 is absent.
    find_program(PYTHON3_EXECUTABLE NAMES python3 python)
    if(PYTHON3_EXECUTABLE)
        add_test(NAME gov_hash_python_oracle
                 COMMAND ${PYTHON3_EXECUTABLE}
                         ${CMAKE_CURRENT_SOURCE_DIR}/tests/proto_hash_oracle.py
                         --cpp-bin $<TARGET_FILE:c2wallet-dash-test>)
    endif()
endif()
