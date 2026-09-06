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

    # 2) X2 (W2) monerod adapter KAT. SUPERSEDES the foundation's header-only
    #    xmr_node_index_check scaffold: the finalized adapter links the xmr_node
    #    library (../node: RPC + ZMQ decoders) and drives the whole seam through
    #    the MockMonerodTransport — minijson parse, get_miner_data tip/reorg,
    #    >=2112 seed reach via ::xmr::coin::rx_seedheight (primitive-reuse, no
    #    duplicated 2048/64), ZMQ 3-topic decode, submit_block round-trip.
    #    STL-only + xmr_node; NO RandomX, NO monerod, NO libzmq. Src/ root on the
    #    path so the "impl/xmr/node/…" and "impl/xmr/coin/…" includes resolve.
    add_executable(xmr_x2_node_kat x2_adapter_kat.cpp)
    target_link_libraries(xmr_x2_node_kat PRIVATE xmr_node)
    target_include_directories(xmr_x2_node_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_compile_features(xmr_x2_node_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_x2_node_kat COMMAND xmr_x2_node_kat)

    # 3) X4 (W2) receipt-envelope KAT. SUPERSEDES the foundation's
    #    xmr_receipt_admission_check scaffold: exercises the FINALIZED admission
    #    pipeline (xmr_admission.hpp) + the real verify bodies
    #    (xmr_receipt_verify.cpp) over X1's coin primitives (xmr_blob via
    #    xmr_coin). RandomX is CI-gated INSIDE the test (rx_check null ->
    #    stage-5 SkippedCIGated), so this target carries NO RandomX dependency
    #    and runs in the ordinary lane. Links xmr_coin for the coinbase
    #    serializer used by KAT-2.
    add_executable(xmr_receipt_kat
        xmr_receipt_kat.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../receipt/xmr_receipt_verify.cpp)
    target_link_libraries(xmr_receipt_kat PRIVATE xmr_coin)
    target_include_directories(xmr_receipt_kat PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../receipt
        ${CMAKE_CURRENT_SOURCE_DIR}/../coin)
    target_compile_features(xmr_receipt_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_receipt_kat COMMAND xmr_receipt_kat)

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

    # 6b) X6 (W5) coinbase-settlement KAT. Finalizes the OWED -> miner_tx
    #     executor (../settle/xmr_coinbase.cpp): deterministic-r reproducibility
    #     (same inputs -> same R and same P_i set; changed lane_commitment /
    #     prev_id / height -> a fresh r), R = r*G anchored to an OFFICIAL monero
    #     generate_keys vector, a stealth one-time key against monero-project
    #     tests/crypto/tests.txt (generate_key_derivation + derive_public_key)
    #     plus a coinbase-path reproduction of every P_i, exact-sum (Sum(vout) ==
    #     base_reward+fees to the piconero incl. residual sink -- HF13, no burn),
    #     the weight-aware output cap, and the CARROT/FCMP++ fence trip
    #     (major_version 17 -> CarrotFence, no coinbase). Compiles the settle TU
    #     and links xmr_coin for the REAL vendored ed25519 (ge_*) + keccak; the
    #     src/ root resolves the "impl/xmr/..." and read-only "sharechain/v37/..."
    #     (v37_descriptor_xmr.hpp value-consumer) includes. NO RandomX, monerod,
    #     libsodium or boost -- runs in the ordinary lane.
    add_executable(xmr_coinbase_kat
        xmr_coinbase_kat.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../settle/xmr_coinbase.cpp)
    target_link_libraries(xmr_coinbase_kat PRIVATE xmr_coin)
    target_include_directories(xmr_coinbase_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_compile_features(xmr_coinbase_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_coinbase_kat COMMAND xmr_coinbase_kat)

    # 6c) X8 END-TO-END integration KAT. Stitches the whole XMR-lane path the
    #     per-slice KATs each cover only in isolation: block-template context feeds
    #     the coinbase inputs; the settle leg (../settle/xmr_coinbase.cpp) builds
    #     the canonical miner_tx from a finality-gated OWED ledger (exact-sum, no
    #     burn; owed outputs are real 8rA stealth keys); the stratum front-end
    #     (../stratum/xmr_stratum.cpp) serves the coinbase-framed hashing blob, a
    #     miner grinds it and submits a share that the deterministic W3 PoW oracle
    #     accepts (the blob the miner signs is byte-identical to the receipt's);
    #     the carrier wire (../wire, header-only) encodes/decodes the receipt
    #     byte-for-byte; and the receipt verifier (../receipt/xmr_receipt_verify.cpp)
    #     accepts the well-formed carrier and REJECTS a tampered one at the
    #     STRUCTURAL stage, before RandomX. The single stitch: the settle
    #     owed_digest (lane_commitment) IS the receipt side-data info_digest, so the
    #     coinbase's tx_extra 0x03 leaf == the leaf the receipt path recomputes.
    #     Links xmr_coin for the REAL vendored ed25519 (ge_*) + keccak; the src/
    #     root resolves the "impl/xmr/..." and read-only "sharechain/v37/..."
    #     includes. RandomX is CI-gated INSIDE the test (deterministic oracle, no
    #     256-MiB cache / JIT) so this target carries NO RandomX dependency and runs
    #     in the ordinary lane on BOTH build.yml legs. NO monerod, libsodium, boost.
    add_executable(xmr_e2e_kat
        xmr_e2e_kat.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../settle/xmr_coinbase.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../receipt/xmr_receipt_verify.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../stratum/xmr_stratum.cpp)
    target_link_libraries(xmr_e2e_kat PRIVATE xmr_coin)
    target_include_directories(xmr_e2e_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../receipt
        ${CMAKE_CURRENT_SOURCE_DIR}/../stratum
        ${CMAKE_CURRENT_SOURCE_DIR}/../wire)
    target_compile_features(xmr_e2e_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_e2e_kat COMMAND xmr_e2e_kat)

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

    # 9b) cross-impl goldens: the LOAD-BEARING Family-B golden regression gate
    #     (the analogue of the Bitcoin-family proto/ decay-table golden). It
    #     recomputes the deterministic XMR-lane outputs — difficulty check_hash
    #     boundaries, CryptoNote stealth one-time keys, deterministic coinbase
    #     r/R=r*G/mm-root, receipt cheap-id + info digest, and the wire carrier
    #     codec bytes — through the merged primitives and byte-compares each to
    #     the frozen cross-impl-goldens/xmr_lane_goldens_golden.hpp (emitted by
    #     cross-impl-goldens/gen_xmr_goldens.cpp, which is a dev tool, NOT a CMake
    #     target — mirroring tools/gen_decay_canonical.py). LIGHT: links xmr_coin
    #     (keccak/ed25519/boost-free check_hash) + the header-only receipt/wire
    #     codec; NO RandomX / libsodium / boost. Negative-controlled internally.
    #     Added to BOTH build.yml light legs by this wave (drift-guard clean).
    add_executable(xmr_goldens_kat
        ${CMAKE_CURRENT_SOURCE_DIR}/cross-impl-goldens/xmr_goldens_kat.cpp)
    target_link_libraries(xmr_goldens_kat PRIVATE xmr_coin)
    target_include_directories(xmr_goldens_kat PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/cross-impl-goldens
        ${CMAKE_CURRENT_SOURCE_DIR}/../receipt
        ${CMAKE_CURRENT_SOURCE_DIR}/../wire)
    target_compile_features(xmr_goldens_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_goldens_kat COMMAND xmr_goldens_kat)

    # 9c) Milestone-A miner->block end-to-end smoke (Track A2 / Family-B). Binds
    #     the X5 stratum seams (ITemplateSource / IPowVerifier / IShareSink) to
    #     the live-node components and drives the whole block-winning path:
    #       accepted network-block share -> read the finality-gated OWED ledger
    #       (W4 OwedLedger) -> build the X6 canonical coinbase (settle/xmr_coinbase,
    #       FCMP-fenced, exact-sum, real 8rA stealth one-time keys) -> submit_block
    #       via the X2 IMonerodTransport (MockMonerodTransport). It ALSO exercises
    #       the F1 finalize driver (per-height, in-order on_block_finalized, never
    #       the live tip) and an FCMP-fence negative control (a post-CARROT
    #       major_version is REFUSED, no submit fired). PoW is a deterministic
    #       known-answer mock: NO RandomX / monerod / libsodium (sanitizer-safe,
    #       OOM-safe). Links xmr_coin for the vendored ed25519 (ge_*) + keccak and
    #       compiles the ref10 point-check backend with V37_XMR_HAVE_MONERO_CRYPTO
    #       so XMR descriptors validate live (SAFETY (4)). Its own harness (nonzero
    #       exit on any failed stage). Listed on BOTH build.yml legs + drift-guard
    #       clean (see .github/workflows/build.yml).
    add_executable(xmr_miner_block_path_smoke
        miner_block_path_smoke.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../settle/xmr_coinbase.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../stratum/xmr_stratum.cpp
        ${CMAKE_SOURCE_DIR}/src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp)
    target_link_libraries(xmr_miner_block_path_smoke PRIVATE xmr_coin)
    target_include_directories(xmr_miner_block_path_smoke PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../mbp
        ${CMAKE_CURRENT_SOURCE_DIR}/../stratum
        ${CMAKE_CURRENT_SOURCE_DIR}/../coin)
    target_compile_definitions(xmr_miner_block_path_smoke PRIVATE V37_XMR_HAVE_MONERO_CRYPTO)
    target_compile_features(xmr_miner_block_path_smoke PRIVATE cxx_std_20)
    add_test(NAME xmr_miner_block_path_smoke COMMAND xmr_miner_block_path_smoke)

    # 10) randomx-verify: the REAL RandomX engine, now vendored and wired.
    #     ../pow/randomx_verify_kat.cpp runs three suites against librandomx.a
    #     built from the vendored tevador/RandomX source (third_party/randomx/src,
    #     consensus pin 12f2c2ff):
    #       (A) OFFICIAL tevador/RandomX rx/0 (v1) engine vectors,
    #       (B) the pure-arithmetic difficulty/seed-height rule (always),
    #       (C) a REAL Monero mainnet block (3,000,000) verified end-to-end
    #           through the production LightVerifier (X0-proven path).
    #     HEAVY: 256 MiB Argon2d cache + a light VM per key. Its asm/JIT +
    #     intentional unaligned reads do NOT survive -fsanitize, and 256 MiB is
    #     OOM-hostile on a laptop, so XMR_BUILD_RANDOMX defaults OFF: it is NOT
    #     built locally and NOT built on the sanitizer leg. It IS built and run on
    #     the NON-sanitizer Linux x86_64 leg, which passes -DXMR_BUILD_RANDOMX=ON
    #     and lists xmr_randomx_verify_kat in its --target set (see
    #     .github/workflows/build.yml). Because it is now a real build.yml target
    #     the drift-guard finds it there — no ci-allowlist-exempt entry is needed
    #     (the previous exempt, valid while only headers were vendored, is dropped).
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
        # --engine runs suites (A) RandomX vectors + (C) the real block 3,000,000
        # end-to-end verify; suite (B) arithmetic runs always.
        add_test(NAME xmr_randomx_verify_kat COMMAND xmr_randomx_verify_kat --engine)
    endif()
endif()
