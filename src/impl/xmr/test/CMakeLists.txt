# ─────────────────────────────────────────────────────────────────────────────
# Family B (XMR / RandomX lane) — FOUNDATION self-checks.
#
# Every target here is self-contained: STL + (for the primitives selfcheck) the
# vendored Monero C crypto. NONE needs libsodium, the RandomX library, cppzmq,
# boost, gtest, or a monerod. They are their own harnesses (nonzero exit on
# failure) so they run anywhere the toolchain exists, mirroring the
# src/sharechain/v37/test pattern.
#
# Each target below is listed in the .github/workflows/build.yml --target
# allowlist (the test-allowlist drift-guard, tools/ci/check_test_target_allowlist.py,
# audits this file against it and fails closed on drift).
#
# Dependency-gated harnesses that CANNOT build in CI without external libs are
# NOT declared as add_executable here — they ship as plain source with their own
# provenance notes and run in proto X0/X1:
#   * test/rx_probe.cpp            — needs librandomx.a (light-mode RandomX probe)
#   * ../pow/randomx_verify_kat.cpp — needs librandomx.a (official RandomX vectors)
#   * ../settle/_compile_check/     — W5 coinbase driver against a stubbed-crypto shim
#   * ../coin/vendor/crypto-ops.c, ../coin/xmr_derivation.cpp — need libsodium ed25519
# The X0 KAT harness (x0_harness.py + x0-kat-*.json + x0_vectors/) is Python and
# is exercised out of band against a public monerod; it is not a CMake target.
# ─────────────────────────────────────────────────────────────────────────────

if (BUILD_TESTING)
    # 1) Monero primitive selfcheck (X1): vendored C (keccak/hash/tree-hash) +
    #    authored xmr_blob.cpp. Exercises the consensus-critical paths that do
    #    NOT need libsodium — Keccak-midstate resume == one-shot, the v2
    #    RCTTypeNull coinbase tx-hash, tree_root/tree_branch + verify, the
    #    128-bit check_hash, seed_height epoch math, and the PoW/CARROT fences.
    add_executable(xmr_primitives_selfcheck
        xmr_primitives_selfcheck.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../coin/xmr_blob.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../coin/vendor/keccak.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../coin/vendor/hash.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../coin/vendor/tree-hash.c)
    target_include_directories(xmr_primitives_selfcheck PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../coin
        ${CMAKE_CURRENT_SOURCE_DIR}/../coin/vendor
        ${CMAKE_CURRENT_SOURCE_DIR}/../coin/compat)
    target_compile_definitions(xmr_primitives_selfcheck PRIVATE _GNU_SOURCE)
    target_compile_features(xmr_primitives_selfcheck PRIVATE c_std_11 cxx_std_20)
    add_test(NAME xmr_primitives_selfcheck COMMAND xmr_primitives_selfcheck)

    # 2) monerod-adapter mainchain index (X2): seed reach (>=2112), reorg/orphan
    #    classification, confirmation depth, fee-sorted backlog prune. STL-only,
    #    header-only index; the check source lives next to it in ../node/.
    add_executable(xmr_node_index_check
        ${CMAKE_CURRENT_SOURCE_DIR}/../node/xmr_node_index_check.cpp)
    target_include_directories(xmr_node_index_check PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../node)
    target_compile_features(xmr_node_index_check PRIVATE cxx_std_20)
    add_test(NAME xmr_node_index_check COMMAND xmr_node_index_check)

    # 3) Family-B receipt envelope (X4) + the inverted keyed_heavy admission order
    #    (dedup -> expiry -> structural/binding -> R-1 target -> RandomX LAST),
    #    with the wire-size caps (typ 615 / max 756 / cap 768 B). STL-only.
    add_executable(xmr_receipt_admission_check xmr_receipt_admission_check.cpp)
    target_include_directories(xmr_receipt_admission_check PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../receipt)
    target_compile_features(xmr_receipt_admission_check PRIVATE cxx_std_20)
    add_test(NAME xmr_receipt_admission_check COMMAND xmr_receipt_admission_check)

    # 4) W3 carrier wire codec (byte-exact, one-canon) + the RandomX DoS budget
    #    (per-peer token bucket, global backstop, ban-on-invalid-PoW, HW-flap
    #    guard). STL-only; pulls the sibling receipt headers via ../receipt.
    add_executable(xmr_wire_dos_check xmr_wire_dos_check.cpp)
    target_include_directories(xmr_wire_dos_check PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../wire
        ${CMAKE_CURRENT_SOURCE_DIR}/../receipt)
    target_compile_features(xmr_wire_dos_check PRIVATE cxx_std_20)
    add_test(NAME xmr_wire_dos_check COMMAND xmr_wire_dos_check)

    # 5) CryptoNote / XMRig stratum dialect (X5): login/job/submit build+parse,
    #    76-B blob, nonce offset 39, per-worker extra-nonce, two-stage submit.
    #    STL-only; skeleton logic + 53 KATs with fake seams (no socket/engine).
    add_executable(xmr_stratum_selftest
        ${CMAKE_CURRENT_SOURCE_DIR}/../stratum/xmr_stratum_selftest.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../stratum/xmr_stratum.cpp)
    target_include_directories(xmr_stratum_selftest PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../stratum)
    target_compile_features(xmr_stratum_selftest PRIVATE cxx_std_20)
    add_test(NAME xmr_stratum_selftest COMMAND xmr_stratum_selftest)

    # 6) License/provenance gate: compiling this TU fires the three static_asserts
    #    in impl/xmr/xmr_provenance.hpp (ported rows pinned; p2pool copyleft
    #    preserved; licence set closed to {BSD-3, GPL-3.0-only, AGPL-3.0}).
    add_executable(xmr_provenance_gate xmr_provenance_gate.cpp)
    target_compile_features(xmr_provenance_gate PRIVATE cxx_std_20)
    add_test(NAME xmr_provenance_gate COMMAND xmr_provenance_gate)
endif()
