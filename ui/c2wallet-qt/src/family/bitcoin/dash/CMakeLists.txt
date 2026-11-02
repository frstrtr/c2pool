cmake_minimum_required(VERSION 3.21)

# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-qt — Family A (Bitcoin/DASH) special-tx core, phase M3-A-DASH (#193).
# Design docs/design/c2wallet-qt.md §4.1.1 (governance-proposal collateral tx
# builder) + §4.1.2 (message sign/verify). Ported byte-exact from the operator's
# frstrtr/dash-proposal-collateral (see PROVENANCE below).
#
# HIGH money-path: sign_collateral() produces a spendable tx that burns 1 DASH,
# and the zero-fee inject builders (FeeMode::InjectOnlyZeroFee, SweepTx) spend
# every mature UTXO of an address for a c2pool node's own block.
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
#   c2wallet-dash-plan    — btclibs closure, KEY-FREE (address/intake/planner/
#                           manifest/gov hash); the online companion links it
#   c2wallet-dash-common  — btclibs closure, key code (key scan/message/model);
#                           links c2wallet-dash-plan PUBLIC
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

# ── key-free plan lib (scan & plan slice S-A) ─────────────────────────────
# c2wallet-dash-plan: address decode, UTXO intake/screening, the sweep planner /
# unsigned serializer / loader-file emit, the manifest and the gobject hash. No
# key code; the online companion links it (DashPlan.cmake, shared with
# src/companion/CMakeLists.txt).
if(NOT TARGET c2wallet-dash-plan)
    include(${CMAKE_CURRENT_SOURCE_DIR}/DashPlan.cmake)
endif()

# ── btclibs-closure lib: key-scan / message / the inject page model ────────
# The key-bearing half of the btclibs closure. It links c2wallet-dash-plan
# PUBLIC, so every consumer links the same closure as before the split.
add_library(c2wallet-dash-common STATIC
    KeyScan.cpp
    DashMessage.cpp
    # slice 2: PageDashInject's std-only model (all but sign()).
    # DashInjectModel.cpp plans a collateral through plan_collateral
    # (CollateralTx.cpp, c2wallet-dash-tx): a consumer of the model links BOTH
    # libs, c2wallet-dash-tx first, as the signer app and c2wallet-dash-test do.
    DashInjectModel.cpp
)
target_include_directories(c2wallet-dash-common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# PRIVATE on purpose: this lib's .cpp need the hdkeys (btclibs) include tree,
# but its headers are std-only, so the btclibs tree MUST NOT propagate to
# c2wallet-dash-tx (below) — btclibs and dashscript share the compat/endian.h
# include guard, and leaking btclibs into the dashscript TU guard-skips
# le16toh_internal. The static-lib link dependency still reaches the final exe.
target_link_libraries(c2wallet-dash-common PUBLIC c2wallet-dash-plan PRIVATE c2wallet-hdkeys)

# ── dashscript-closure lib: the tx assembly, via the M3-A signer ────────────
# (collateral build + sign, and the signing half of the sweep builder)
# DashInjectSign.cpp is DashInjectModel::sign(): it calls the signers above and
# includes only std-only headers itself.
add_library(c2wallet-dash-tx STATIC CollateralTx.cpp SweepSign.cpp DashInjectSign.cpp)
target_include_directories(c2wallet-dash-tx PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# c2wallet-signer FIRST so the dashscript <hash.h>/<uint256.h> win for this TU;
# c2wallet-dash-common provides the std-only address/key/gov declarations it
# calls (definitions resolve from the btclibs lib at final link).
target_link_libraries(c2wallet-dash-tx PUBLIC c2wallet-signer c2wallet-dash-common)

option(C2WALLET_QT_BUILD_TESTS "Build the DASH special-tx KAT test" OFF)
if(C2WALLET_QT_BUILD_TESTS OR _dash_standalone)
    enable_testing()
    # The inject KATs (K9) round-trip the emitted loader file through the M5-A
    # artifact library's SignedContainer / accept_as_signed. Test-only link.
    if(NOT TARGET c2wallet-artifact)
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../artifact ${CMAKE_BINARY_DIR}/_dash_artifact)
    endif()
    add_executable(c2wallet-dash-test tests/test_dash.cpp)
    # signer first on the link line (matches the proven link order).
    target_link_libraries(c2wallet-dash-test PRIVATE c2wallet-dash-tx c2wallet-dash-common
                          c2wallet-artifact)
    # Slice-2 KATs read the real (public) getaddressutxos fixture from disk.
    target_compile_definitions(c2wallet-dash-test PRIVATE
        C2W_DASH_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
    add_test(NAME dash_kats COMMAND c2wallet-dash-test)

    # Slice S-A: the key-free plan library on its own. The KATs (P1 on the real
    # fixture, P2 the byte-cap boundary) link ONLY c2wallet-dash-plan, and the
    # key-free guard runs over both the archive and that linked binary. The
    # negative control runs the same guard over a probe binary that links the
    # funding-key scan (KeyScan.cpp) and nothing else of the key layer: it
    # must FAIL, which proves the guard sees the key code the split keeps out
    # of the plan library (the token list before the split passed it).
    add_executable(c2wallet-dash-plan-test tests/test_dash_plan.cpp)
    target_link_libraries(c2wallet-dash-plan-test PRIVATE c2wallet-dash-plan)
    target_compile_definitions(c2wallet-dash-plan-test PRIVATE
        C2W_DASH_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
    add_test(NAME dash_plan_kats COMMAND c2wallet-dash-plan-test)
    set(_c2w_key_free_guard "${CMAKE_CURRENT_SOURCE_DIR}/../../../../ci/check_key_free.sh")
    add_test(NAME dash_plan_key_free_guard
             COMMAND "${_c2w_key_free_guard}" "$<TARGET_FILE:c2wallet-dash-plan>")
    add_test(NAME dash_plan_test_key_free_guard
             COMMAND "${_c2w_key_free_guard}" "$<TARGET_FILE:c2wallet-dash-plan-test>")
    add_executable(c2wallet-dash-key-scan-probe tests/key_scan_probe.cpp)
    target_link_libraries(c2wallet-dash-key-scan-probe PRIVATE c2wallet-dash-common)
    add_test(NAME dash_key_scan_probe_key_free_guard_negative_control
             COMMAND "${_c2w_key_free_guard}" "$<TARGET_FILE:c2wallet-dash-key-scan-probe>")
    set_tests_properties(dash_key_scan_probe_key_free_guard_negative_control PROPERTIES WILL_FAIL TRUE)

    # The "drive the proven Python as the oracle" leg: proto_hash_oracle.py (the
    # stdlib-only reference port) recomputes the gobject hashes and asserts the
    # C++ test binary emits byte-identical values. Skipped if python3 is absent.
    find_program(PYTHON3_EXECUTABLE NAMES python3 python)
    if(PYTHON3_EXECUTABLE)
        add_test(NAME gov_hash_python_oracle
                 COMMAND ${PYTHON3_EXECUTABLE}
                         ${CMAKE_CURRENT_SOURCE_DIR}/tests/proto_hash_oracle.py
                         --cpp-bin $<TARGET_FILE:c2wallet-dash-test>)
        # Slice 2: the online exporter (ui/c2wallet-qt/tools/export_utxos.py) run
        # against a mock dash-cli serving the public fixture, its output then
        # imported through DashInjectModel.
        add_test(NAME export_utxos_roundtrip
                 COMMAND ${PYTHON3_EXECUTABLE} -I
                         ${CMAKE_CURRENT_SOURCE_DIR}/tests/export_roundtrip.py
                         --cpp-bin $<TARGET_FILE:c2wallet-dash-test>
                         --exporter ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tools/export_utxos.py
                         --fixture ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/xdgf-getaddressutxos-tip2563986.json)
    endif()
endif()
