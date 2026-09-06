# ─────────────────────────────────────────────────────────────────────────────
# Family B (XMR / RandomX lane) — self-checks + X1 Known-Answer Tests.
#
# Two tiers:
#   * FOUNDATION self-checks (unchanged): STL-only or vendored-C harnesses that
#     are their own drivers (nonzero exit on failure), mirroring
#     src/sharechain/v37/test.
#   * X1 KAT targets (NEW): the light Monero-crypto KATs, which link the
#     `xmr_coin` library (../coin/CMakeLists.txt) instead of re-listing vendored
#     sources, plus the heavy RandomX verify KAT gated behind XMR_BUILD_RANDOMX.
#
# DRIFT-GUARD: every add_executable below MUST appear as a `--target` token in
# .github/workflows/build.yml (tools/ci/check_test_target_allowlist.py audits
# this file by regex and fails closed on drift), or carry an inline
# `# ci-allowlist-exempt: <target> -- <reason>`. The three LIGHT X1 targets
# (xmr_crypto_kats, xmr_ed25519_derivation_kat, xmr_difficulty_kat) are added to
# BOTH build.yml legs by this wave. The heavy xmr_randomx_verify_kat is
# ci-allowlist-EXEMPT (see its block below): the foundation vendored only the
# RandomX *headers* (randomx.h/configuration.h) — there is no buildable RandomX
# source/CMakeLists yet — so it cannot be turned on in CI in this wave; a later
# wave vendors the tevador/RandomX source (submodule) and flips it into build.yml.
#
# Dependency-gated harnesses still NOT declared as add_executable (plain source
# only): ../settle/_compile_check/ (W5 stubbed-crypto driver) and this dir's
# rx_probe.cpp (light-mode RandomX probe). The X0 python harness (x0_harness.py
# + x0-kat-*.json + x0_vectors/) is exercised out of band, not a CMake target.
# ─────────────────────────────────────────────────────────────────────────────

if (BUILD_TESTING)
    # =========================================================================
    # FOUNDATION self-checks (verbatim from the X-lane foundation, PR #1500).
    # =========================================================================

    # 1) Monero primitive selfcheck: vendored C (keccak/hash/tree-hash) +
    #    authored xmr_blob.cpp. (Kept self-contained; see the fan-in note in
    #    ../coin/CMakeLists.txt about optionally migrating this to link xmr_coin.)
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

    # 2) monerod-adapter mainchain index. STL-only, header-only index.
    add_executable(xmr_node_index_check
        ${CMAKE_CURRENT_SOURCE_DIR}/../node/xmr_node_index_check.cpp)
    target_include_directories(xmr_node_index_check PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../node)
    target_compile_features(xmr_node_index_check PRIVATE cxx_std_20)
    add_test(NAME xmr_node_index_check COMMAND xmr_node_index_check)

    # 3) Family-B receipt envelope + inverted keyed_heavy admission order. STL-only.
    add_executable(xmr_receipt_admission_check xmr_receipt_admission_check.cpp)
    target_include_directories(xmr_receipt_admission_check PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../receipt)
    target_compile_features(xmr_receipt_admission_check PRIVATE cxx_std_20)
    add_test(NAME xmr_receipt_admission_check COMMAND xmr_receipt_admission_check)

    # 4) W3 carrier wire codec + RandomX DoS budget. STL-only.
    add_executable(xmr_wire_dos_check xmr_wire_dos_check.cpp)
    target_include_directories(xmr_wire_dos_check PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../wire
        ${CMAKE_CURRENT_SOURCE_DIR}/../receipt)
    target_compile_features(xmr_wire_dos_check PRIVATE cxx_std_20)
    add_test(NAME xmr_wire_dos_check COMMAND xmr_wire_dos_check)

    # 5) CryptoNote / XMRig stratum dialect. STL-only skeleton + KATs.
    add_executable(xmr_stratum_selftest
        ${CMAKE_CURRENT_SOURCE_DIR}/../stratum/xmr_stratum_selftest.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../stratum/xmr_stratum.cpp)
    target_include_directories(xmr_stratum_selftest PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../stratum)
    target_compile_features(xmr_stratum_selftest PRIVATE cxx_std_20)
    add_test(NAME xmr_stratum_selftest COMMAND xmr_stratum_selftest)

    # 6) License/provenance gate (constexpr static_asserts). NON-SAN leg only in
    #    build.yml: UBSan rejects its constexpr pointer comparison.
    add_executable(xmr_provenance_gate xmr_provenance_gate.cpp)
    target_compile_features(xmr_provenance_gate PRIVATE cxx_std_20)
    add_test(NAME xmr_provenance_gate COMMAND xmr_provenance_gate)

    # =========================================================================
    # X1 Known-Answer Tests (NEW) — link the xmr_coin library.
    # =========================================================================

    # 7) crypto-kats: Keccak-256 / cn_fast_hash, CryptoNote tree-hash + branch
    #    verify, and the varint (LEB128) codec. Vectors: Keccak("") constant,
    #    REAL Monero block 3,000,000 (X0 ground truth), canonical LEB128.
    add_executable(xmr_crypto_kats xmr_crypto_kats.cpp)
    target_link_libraries(xmr_crypto_kats PRIVATE xmr_coin)
    target_compile_features(xmr_crypto_kats PRIVATE cxx_std_20)
    add_test(NAME xmr_crypto_kats COMMAND xmr_crypto_kats)

    # 8) ed25519: CryptoNote stealth-address derivation (generate_key_derivation
    #    / derive_public_key / derivation_to_scalar). Vectors: the OFFICIAL
    #    monero-project tests/crypto/tests.txt consensus vectors. Links the
    #    vendored crypto-ops.c via xmr_coin — resolves crypto_verify_32 against
    #    the authored ../coin/compat/sodium shim (no libsodium in the repo).
    add_executable(xmr_ed25519_derivation_kat xmr_ed25519_derivation_kat.cpp)
    target_link_libraries(xmr_ed25519_derivation_kat PRIVATE xmr_coin)
    target_compile_features(xmr_ed25519_derivation_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_ed25519_derivation_kat COMMAND xmr_ed25519_derivation_kat)

    # 9) difficulty: pins the lane's boost-free xmr::coin::check_hash BYTE-FOR-BYTE
    #    against the vendored cryptonote::check_hash boost oracle (difficulty.cpp)
    #    across 64/128-bit overflow-boundary vectors. Needs the boost headers the
    #    oracle's difficulty.h pulls (xmr_coin keeps boost PRIVATE, so add here).
    add_executable(xmr_difficulty_kat xmr_difficulty_kat.cpp)
    target_link_libraries(xmr_difficulty_kat PRIVATE xmr_coin)
    target_compile_features(xmr_difficulty_kat PRIVATE cxx_std_20)
    if (TARGET Boost::headers)
        target_link_libraries(xmr_difficulty_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(xmr_difficulty_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(xmr_difficulty_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    add_test(NAME xmr_difficulty_kat COMMAND xmr_difficulty_kat)

    # 10) randomx-verify: OFFICIAL tevador/RandomX engine vectors (../pow/
    #     randomx_verify_kat.cpp, suite A) against the REAL vendored library.
    #     HEAVY: 256 MiB Argon2d cache + a light VM per key. OOM-hostile, and its
    #     asm/JIT + intentional unaligned reads do not survive -fsanitize, so it
    #     is OFF by default and NOT built locally. It is NOT enabled in CI in this
    #     wave either: the foundation vendored only the RandomX *headers*
    #     (third_party/randomx/randomx.h + configuration.h) — there is no RandomX
    #     source/CMakeLists to compile yet, so -DXMR_BUILD_RANDOMX=ON would fail
    #     to configure. A later wave vendors the tevador/RandomX source (submodule
    #     at consensus pin 12f2c2ff), flips this target into build.yml's non-san
    #     --target leg, and drops the exempt below.
    #
    #     The drift-guard SEES this add_executable (regex, ignores the if()), so
    #     until it is in build.yml it is declared exempt (fail-closed escape hatch):
    # ci-allowlist-exempt: xmr_randomx_verify_kat -- heavy RandomX (256 MiB Argon2d cache + JIT); CI-gated behind XMR_BUILD_RANDOMX, OFF until the tevador/RandomX source is vendored in a later wave (foundation ships headers only)
    option(XMR_BUILD_RANDOMX
        "Build the heavy RandomX verify KAT (librandomx from tevador/RandomX pin 12f2c2ff)" OFF)
    if (XMR_BUILD_RANDOMX)
        # Primary: full tevador/RandomX source vendored/submoduled under
        # ../third_party/randomx (later wave); fall back to FetchContent at the
        # foundation's consensus pin. Either path defines the `randomx` lib.
        if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/randomx/CMakeLists.txt)
            add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../third_party/randomx
                             ${CMAKE_CURRENT_BINARY_DIR}/randomx_build)
        else()
            include(FetchContent)
            FetchContent_Declare(randomx
                GIT_REPOSITORY https://github.com/tevador/RandomX.git
                GIT_TAG        12f2c2ff  # consensus pin (see third_party/randomx/PROVENANCE.txt)
            )
            FetchContent_MakeAvailable(randomx)
        endif()
        add_executable(xmr_randomx_verify_kat
            ${CMAKE_CURRENT_SOURCE_DIR}/../pow/randomx_verify_kat.cpp)
        target_link_libraries(xmr_randomx_verify_kat PRIVATE xmr_coin randomx)
        target_include_directories(xmr_randomx_verify_kat PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../pow
            ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/randomx)
        target_compile_features(xmr_randomx_verify_kat PRIVATE cxx_std_20)
        # --engine runs suite (A) (the RandomX vectors); suite (B) runs always.
        add_test(NAME xmr_randomx_verify_kat COMMAND xmr_randomx_verify_kat --engine)
    endif()
endif()
