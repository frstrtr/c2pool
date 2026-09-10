# ─────────────────────────────────────────────────────────────────────────────
# KATs for the native-minimal Monero node: three from Wave 0, four from the
# Wave 1 levin codec (C1a).
#
# All of them are STL-only: no RandomX, no monerod, no libzmq, no boost. They
# run in the ordinary lane on both CI legs (the sanitizer leg is where the two
# fuzz KATs earn their keep).
#
# DRIFT-GUARD: tools/ci/check_test_target_allowlist.py audits
# src/impl/<coin>/test/CMakeLists.txt; this tree sits one level deeper
# (src/impl/xmr/native/test/) and is outside that glob, so the targets
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

    # -----------------------------------------------------------------------
    # Wave 1, component C1a: the Monero levin codec (../p2p/). Four targets,
    # all STL-only, all registered in BOTH `--target` lists in build.yml -- see
    # the DRIFT-GUARD note at the top of this file.
    #
    #   4) xmr_levin_codec_kat    -- the 33-byte bucket header: layout goldens,
    #      the frame classification table, the inbound per-command size caps.
    #   5) xmr_epee_storage_kat   -- portable storage: the size-mark varint, the
    #      type-tag matrix, SORTED key order (monerod's section is a std::map),
    #      and every bound the decoder puts on what a peer can make us allocate.
    #   6) xmr_levin_messages_kat -- 1001/1002/1003/1007 and 2001..2010, with
    #      goldens derived from monerod's KV serialization maps, including which
    #      fields KV_SERIALIZE_OPT omits at their defaults.
    #   7) xmr_levin_fuzz_kat     -- the bounded deterministic fuzz pass over a
    #      generated corpus plus structured random trees; asserts that canonical
    #      re-encoding is idempotent, which makes the two directions each
    #      other's oracle. This is the one that earns its keep on the sanitizer
    #      leg. `--dump-corpus <dir>` exports the seeds for an external
    #      libFuzzer run, so the corpus never has to be committed as binaries.
    # -----------------------------------------------------------------------
    foreach(_c1a_kat
            xmr_levin_codec_kat
            xmr_epee_storage_kat
            xmr_levin_messages_kat
            xmr_levin_fuzz_kat)
        add_executable(${_c1a_kat} ${_c1a_kat}.cpp)
        target_include_directories(${_c1a_kat} PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_features(${_c1a_kat} PRIVATE cxx_std_20)
        add_test(NAME ${_c1a_kat} COMMAND ${_c1a_kat})
    endforeach()

endif()
