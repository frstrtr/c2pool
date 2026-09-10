# ─────────────────────────────────────────────────────────────────────────────
# KATs for the native-minimal Monero node: three from Wave 0, four from the
# Wave 1 levin codec (C1a), two from the Wave 1 consensus state (C2a) and one
# from the Wave 1 trust-anchor bundle (C2b).
#
# The Wave 0, C1a and C2b targets are STL-only: no RandomX, no monerod, no
# libzmq, no boost. The two C2a targets additionally link `xmr_coin` (keccak,
# tree hash, vendored difficulty) and boost's header-only multiprecision --
# still a LIGHT link (no RandomX, no libsodium, no monerod). All run in the
# ordinary lane on both CI legs (the sanitizer leg is where the two fuzz KATs
# earn their keep).
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

    # ─────────────────────────────────────────────────────────────────────────
    # Wave 1 / C2a: the consensus state (block identity, weights, reward,
    # emission, difficulty, hard-fork policy).
    #
    # Both targets link `xmr_coin`, unlike the three Wave 0 KATs above, and the
    # reason is worth stating: identity needs a keccak and a tree hash, and the
    # difficulty adapter needs the vendored monerod retarget (R-U128). Both
    # already exist in this repository behind xmr_coin, and a second copy of
    # either is a divergence waiting to happen. xmr_coin's PUBLIC include
    # directories are what make "vendor/difficulty.h" and its compat shims
    # resolve. It is a LIGHT link -- no RandomX, no libsodium, no monerod --
    # exactly like the xmr_difficulty_kat and xmr_goldens_kat targets that have
    # been on both CI legs since X1.
    #
    # Same drift-guard rule as above: both are added to BOTH --target lists in
    # .github/workflows/build.yml by the change that adds them here, because a
    # registered-but-unbuilt target reports "***Not Run" and fails ctest.
    # ─────────────────────────────────────────────────────────────────────────

    # 4) Block identity against monerod: id, coinbase hash, tree root, hashing
    #    blob, over whole captured block blobs, plus the negative controls.
    add_executable(xmr_native_block_id_kat xmr_block_id_kat.cpp)
    target_include_directories(xmr_native_block_id_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xmr_native_block_id_kat PRIVATE xmr_coin)
    target_compile_features(xmr_native_block_id_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_native_block_id_kat COMMAND xmr_native_block_id_kat)

    # 5) The consensus state over 600 consecutive stagenet heights: difficulty,
    #    long-term weight, reward, emission, rollback, connect(), and the
    #    R-HFFUSE code-rolling hard-fork policy.
    add_executable(xmr_native_consensus_state_kat xmr_consensus_state_kat.cpp)
    target_include_directories(xmr_native_consensus_state_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xmr_native_consensus_state_kat PRIVATE xmr_coin)
    target_compile_features(xmr_native_consensus_state_kat PRIVATE cxx_std_20)
    # boost::multiprecision is header-only here: the vendored retarget types its
    # difficulty as uint128_t, and the KAT uses boost as an independent third
    # opinion on the 128-bit reward arithmetic.
    if (TARGET Boost::headers)
        target_link_libraries(xmr_native_consensus_state_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(xmr_native_consensus_state_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(xmr_native_consensus_state_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    add_test(NAME xmr_native_consensus_state_kat COMMAND xmr_native_consensus_state_kat)

    # -----------------------------------------------------------------------
    # Wave 1, component C2b: the trust-anchor bundle (../anchor/). One target,
    # STL-only, registered in BOTH `--target` lists in build.yml.
    #
    # The trust-anchor KAT (WF-C2b): SHA-256 known answers, the .inc format
    #    round-trip and each of its documented refusals, every AnchorStatus in
    #    contracts/anchor.hpp reached by mutating one field, load_anchor's four
    #    gates including a tampered file on disk, generate_anchor against an
    #    honest and a dishonest model daemon, and the REAL embedded stagenet
    #    bundle -- whose digest is recomputed with the C++ canonical writer,
    #    which is what pins tools/xmr-anchor-gen/xmr_anchor_gen.py to it.
    #
    #    It writes two small temporary .inc files into the working directory and
    #    removes them again; ctest runs it inside the build tree.
    add_executable(xmr_native_anchor_self_check_kat xmr_anchor_self_check_kat.cpp)
    target_include_directories(xmr_native_anchor_self_check_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src)
    target_compile_features(xmr_native_anchor_self_check_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_native_anchor_self_check_kat COMMAND xmr_native_anchor_self_check_kat)

    # ─────────────────────────────────────────────────────────────────────────
    # Wave 1 / C2c: the chain index (../chain/xmr_chain_index.hpp and its
    # neighbours): fork choice on recomputed cumulative difficulty, the bounded
    # journaled reorg, the proof-of-work gate and its seed schedule, burial for
    # the v37 section 3 clock, the io-thread serving reads, and snapshot resume.
    #
    # Links `xmr_coin` for the same reason the two C2a targets do -- block
    # identity needs a keccak and a tree hash, and the difficulty adapter needs
    # the vendored monerod retarget -- and boost's header-only multiprecision
    # comes with it. Still a LIGHT link: no RandomX, no libsodium, no monerod.
    # The RandomX verifier is reached through a duck-typed adapter, so the
    # whole index is built and tested on a leg that links no RandomX at all.
    #
    # Same drift-guard rule as every target above: it is added to BOTH --target
    # lists in .github/workflows/build.yml by the change that adds it here,
    # because a registered-but-unbuilt target reports "***Not Run" and fails
    # ctest (#1539).
    # ─────────────────────────────────────────────────────────────────────────
    add_executable(xmr_native_chain_index_kat xmr_chain_index_kat.cpp)
    target_include_directories(xmr_native_chain_index_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xmr_native_chain_index_kat PRIVATE xmr_coin)
    target_compile_features(xmr_native_chain_index_kat PRIVATE cxx_std_20)
    if (TARGET Boost::headers)
        target_link_libraries(xmr_native_chain_index_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(xmr_native_chain_index_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(xmr_native_chain_index_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    add_test(NAME xmr_native_chain_index_kat COMMAND xmr_native_chain_index_kat)

endif()
