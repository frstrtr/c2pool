# ─────────────────────────────────────────────────────────────────────────────
# Wave 0 KATs for the native-minimal Monero node.
#
# All three are STL-only: no RandomX, no monerod, no libzmq, no boost. They run
# in the ordinary lane on both CI legs (the sanitizer leg is where the fuzz KAT
# earns its keep).
#
# DRIFT-GUARD: tools/ci/check_test_target_allowlist.py audits
# src/impl/<coin>/test/CMakeLists.txt; this tree sits one level deeper
# (src/impl/xmr/native/test/) and is outside that glob, so the three targets
# below are added to BOTH `--target` lists in .github/workflows/build.yml by
# hand. A target that is registered with add_test but never built reports as
# "***Not Run" and exits non-zero -- the #1539 lesson -- so if you add a target
# here, add it to build.yml in the same change.
# ─────────────────────────────────────────────────────────────────────────────

if (BUILD_TESTING)

    # 1) The contracts KAT. Compiles every contract header and every fake in one
    #    translation unit (the collision fence), drives the fakes through their
    #    interfaces, and checks the pinned semantics: to_miner_data leaves the
    #    backlog empty, the admission-evidence bitmask is orthogonal, the
    #    100-id object-request cap holds, readiness is fail-closed, a relay
    #    verdict that reached nobody says why, and the hard-fork table plus the
    #    RandomX seed-epoch rules hold at their edges.
    add_executable(xmr_native_contracts_kat contracts_kat.cpp)
    target_include_directories(xmr_native_contracts_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_compile_features(xmr_native_contracts_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_native_contracts_kat COMMAND xmr_native_contracts_kat)

    # 2) The consensus tx-weight golden over real stagenet transactions. The
    #    independent pin is monerod's own block_weight per captured block; see
    #    xmr_tx_weight_golden.hpp for the capture metadata and
    #    gen_tx_weight_golden.py for the regeneration path.
    add_executable(xmr_native_tx_weight_kat xmr_tx_weight_kat.cpp)
    target_include_directories(xmr_native_tx_weight_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_features(xmr_native_tx_weight_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_native_tx_weight_kat COMMAND xmr_native_tx_weight_kat)

    # 3) BlobReader unit checks plus the deterministic fuzz pass (structured
    #    random input, then mutations of the real transaction corpus).
    add_executable(xmr_native_blob_reader_fuzz_kat xmr_blob_reader_fuzz_kat.cpp)
    target_include_directories(xmr_native_blob_reader_fuzz_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_features(xmr_native_blob_reader_fuzz_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_native_blob_reader_fuzz_kat COMMAND xmr_native_blob_reader_fuzz_kat)

endif()
