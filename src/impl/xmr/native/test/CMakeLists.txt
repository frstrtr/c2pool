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
    # Wave 1 / C3: the relayed txpool (../txpool/) and the non-input consensus
    # it admits on (../rct/).
    #
    # Both targets link `xmr_native_txpool`, which transitively links `xmr_coin`
    # for the vendored ed25519 group operations and Keccak. This is the HEAVIEST
    # pair in this file: xmr_native_rct_verify_kat builds a 2048-entry
    # Bulletproof+ generator table once and then verifies real stagenet range
    # proofs, so it costs seconds rather than milliseconds. It is still a LIGHT
    # LINK in the sense that matters -- no RandomX, no libsodium, no monerod and
    # no network -- and it runs in the ordinary lane on both CI legs.
    #
    #   xmr_native_rct_verify_kat -- ruling R-VAL's evidence, proven both ways:
    #      real stagenet Bulletproof+ transactions verify (and their ids and
    #      weights reproduce the daemon's own numbers), and mutating a
    #      commitment, a fee, a pseudo-output, a proof element or a key image
    #      makes exactly the check aimed at it fail. Plus the fail-closed
    #      refusal of the pre-HF15 rct types in the same corpus.
    #   xmr_native_txpool_kat     -- the pool: admission evidence, the
    #      structural refusal table with monerod's drop/no-drop split, sighting
    #      and Dandelion++ stem semantics, the snapshot contract, first-seen-wins
    #      on a key-image conflict (including the tx_extra twin that makes any
    #      other rule a censorship vector), mined and chain-conflict eviction,
    #      the byte cap, the age cap, and the pin that outranks both.
    #
    # Same drift-guard rule as everything above: both are added to BOTH
    # `--target` lists in .github/workflows/build.yml by the change that adds
    # them here, because a registered-but-unbuilt target reports "***Not Run"
    # and fails ctest (the #1539 lesson).
    # ─────────────────────────────────────────────────────────────────────────
    foreach(_c3_kat
            xmr_native_rct_verify_kat
            xmr_native_txpool_kat)
        # The sources are named after the component, not the target prefix.
        string(REPLACE "xmr_native_" "xmr_" _c3_src ${_c3_kat})
        add_executable(${_c3_kat} ${_c3_src}.cpp)
        target_include_directories(${_c3_kat} PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_libraries(${_c3_kat} PRIVATE xmr_native_txpool)
        target_compile_features(${_c3_kat} PRIVATE cxx_std_20)
        add_test(NAME ${_c3_kat} COMMAND ${_c3_kat})
    endforeach()

    # -----------------------------------------------------------------------
    # Wave 1, component C1b: the levin TRANSPORT (../p2p/levin_socket.hpp,
    # levin_invoke_queue.hpp, xmr_handshake.hpp, xmr_levin_link.hpp). Two
    # targets, both registered in BOTH `--target` lists in build.yml -- see the
    # DRIFT-GUARD note at the top of this file.
    #
    #   xmr_levin_socket_kat -- LevinSocket over real TCP on 127.0.0.1: the
    #     33-byte-header-then-bounded-body read loop, the single-composed-write
    #     FIFO queue (the issue #863 splice), the pre/post-handshake cap flip,
    #     the owner lock-per-async-op lifetime guard written as the actual
    #     use-after-free shape (which is what makes it worth running under
    #     ASan on the sanitizer leg), and the io-thread fence that keeps
    #     RandomX off this thread.
    #   xmr_levin_link_kat -- the 1001 HANDSHAKE and 1002 TIMED_SYNC exchanges
    #     against a hand-rolled monerod stand-in on loopback, every handshake
    #     refusal, the FIFO reply matcher (levin has no request id), the
    #     2003/2006 expect-response latch, and one assertion apiece for the
    #     three C1-lens corrections (sorted epee keys, SIGNATURE_B byte order,
    #     TIMED_SYNC response shape). Its `--live <host>:<port>` mode dials a
    #     real daemon and is deliberately NOT what ctest runs.
    #
    # Unlike every target above these link boost::asio (header-only in the
    # pinned Boost 1.90) plus a thread library. That is still a LIGHT link: no
    # RandomX, no libsodium, no monerod, no compiled Boost component.
    # -----------------------------------------------------------------------
    foreach(_c1b_kat
            xmr_levin_socket_kat
            xmr_levin_link_kat)
        add_executable(${_c1b_kat} ${_c1b_kat}.cpp)
        target_include_directories(${_c1b_kat} PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_features(${_c1b_kat} PRIVATE cxx_std_20)
        if (TARGET Boost::headers)
            target_link_libraries(${_c1b_kat} PRIVATE Boost::headers)
        elseif (TARGET Boost::boost)
            target_link_libraries(${_c1b_kat} PRIVATE Boost::boost)
        elseif (DEFINED Boost_INCLUDE_DIRS)
            target_include_directories(${_c1b_kat} PRIVATE ${Boost_INCLUDE_DIRS})
        endif()
        if (TARGET Threads::Threads)
            target_link_libraries(${_c1b_kat} PRIVATE Threads::Threads)
        endif()
        add_test(NAME ${_c1b_kat} COMMAND ${_c1b_kat})
        # Loopback TCP plus compressed deadlines: comfortably under a minute on
        # a loaded runner, but never unbounded.
        set_tests_properties(${_c1b_kat} PROPERTIES TIMEOUT 300)
    endforeach()

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

    # ─────────────────────────────────────────────────────────────────────────
    # REORG-FOLLOW: the same index, booted the way a regtest node boots -- ONE
    # row at height 0 and nothing below it -- following a heavier branch that
    # forked below its tip, while running.
    #
    # A SEPARATE TARGET RATHER THAN MORE CASES IN THE FILE ABOVE, on purpose.
    # That fixture seeds a full 735-row difficulty window because it replays
    # stagenet from an anchor, so every fork point it reaches is already
    # covered and its reorg suite passed while a from-genesis node could not
    # reorganise at all. The young-chain state is not reachable from that
    # fixture; it needs its own boot, and keeping the two apart is what stops
    # the next person from "simplifying" this one onto the anchored seed and
    # quietly deleting the coverage.
    #
    # Same light link (xmr_coin + header-only boost, no RandomX, no daemon) and
    # the same drift-guard rule: added to BOTH --target lists in
    # .github/workflows/build.yml by the change that adds it here (#1539).
    # ─────────────────────────────────────────────────────────────────────────
    add_executable(xmr_native_reorg_follow_kat xmr_reorg_follow_kat.cpp)
    target_include_directories(xmr_native_reorg_follow_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xmr_native_reorg_follow_kat PRIVATE xmr_coin)
    target_compile_features(xmr_native_reorg_follow_kat PRIVATE cxx_std_20)
    if (TARGET Boost::headers)
        target_link_libraries(xmr_native_reorg_follow_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(xmr_native_reorg_follow_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(xmr_native_reorg_follow_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    add_test(NAME xmr_native_reorg_follow_kat COMMAND xmr_native_reorg_follow_kat)

    # ─────────────────────────────────────────────────────────────────────────
    # Wave 1 / C1c: the peer manager and DoS (../p2p/chain_seeds.hpp,
    # chain_locator.hpp, xmr_peer_store.hpp, xmr_dial_plan.hpp, xmr_p2p_dos.hpp,
    # xmr_peer_pool.hpp). Four targets: three STL-only, one on boost::asio.
    #
    #   xmr_native_chain_locator_kat -- the seed tables and THE GENESIS
    #     TERMINUS. monerod's find_blockchain_supplement drops the connection
    #     when a locator's last id is not the genesis id, with no error frame,
    #     so every path that can build a locator is checked to end in genesis --
    #     including the cold-index path, where the index has no ids at all. The
    #     stagenet id itself was verified live against a stagenet daemon.
    #   xmr_native_peer_store_kat -- white/gray/anchor and the tier ratchet (only
    #     our own handshake promotes), backoff-is-not-a-ban, the /16 ban carry,
    #     candidate ordering, gray eviction, refill, the /16 connection cap in
    #     both directions, rotation with its age floor, and primary election
    #     with hysteresis. Injected clock throughout: a 24 h ban is tested in
    #     microseconds.
    #   xmr_native_p2p_dos_kat -- the token buckets and the fault table.
    #     Exhaustion is a DEFER (drop plus one point), not a ban; the
    #     transaction bucket counts transactions rather than frames; a completed
    #     hash below target is the whole ban threshold on its own.
    #   xmr_native_peer_pool_kat -- the pool against hand-rolled monerod
    #     stand-ins on loopback: dial, handshake, peerlist learning, the 100-id
    #     chunking of a 250-id span and its reassembly into ONE on_objects, the
    #     genesis terminus applied on the way out, the 2006/2003 serving
    #     obligation (the state_normal trap), push traffic in and broadcast out.
    #     Its `--live <host>:<port>` mode dials a real daemon read-only and is
    #     deliberately NOT what ctest runs.
    #
    # Wave 1 / C4: the template source seam (../template/). Two targets.
    #
    #   xmr_native_template_kat
    #     The seam itself: NativeMinerDataSource over the real ChainStateView
    #     and a canned txpool, MonerodMinerDataSource over a fake transport
    #     replaying a REAL captured get_miner_data, the readiness matrix, the
    #     difficulty sanity band, the epoch/rebuild rule, the body pins and the
    #     arm resolver. Its centrepiece is the P-TPL parity table: the seven
    #     get_miner_data fields the native arm derives, compared against the
    #     values a synced stagenet monerod reported at that height.
    #
    #     Links `xmr_coin` for the same reason the C2a/C2c targets do (keccak,
    #     tree hash, the vendored difficulty retarget), and `xmr_node` for the
    #     PRODUCTION get_miner_data parser -- the monerod arm has to be the real
    #     decode path, hex-string difficulty and all, or "this arm is the old
    #     path" would be a claim about a re-typed struct instead. Both are LIGHT
    #     links: no RandomX, no libsodium, no libzmq, no monerod, no network.
    #     ctest passes no arguments; `--parity-json <file>` is the opt-in mode
    #     that swaps in a freshly captured response and is deliberately NOT what
    #     ctest runs.
    #
    #   xmr_native_template_coinbase_kat
    #     The other half of the C4 claim: the option-B K_fair settlement
    #     coinbase is unchanged by the rebind. Builds the X6 coinbase from the
    #     native derivation (../../settle/xmr_coinbase.cpp -- the same executor
    #     and the same file the daemon-ful path uses) and pins the owed payee
    #     set, the exact-sum residual sink, the owed_digest under the tx_extra
    #     0x03 merge-mining tag, the byte-identity of the two arms' coinbases
    #     and the pre-CARROT fence. Same shape and cost as the existing
    #     xmr_coinbase_kat target, which has been on both CI legs since X6.
    #
    # Same drift-guard rule as every target above: all six (C1c's four, C4's
    # two) are added to BOTH
    # `--target` lists in .github/workflows/build.yml by the change that adds
    # them here, because a registered-but-unbuilt target reports "***Not Run"
    # and fails ctest (the #1539 lesson).
    # ─────────────────────────────────────────────────────────────────────────
    foreach(_c1c_kat
            xmr_native_chain_locator_kat
            xmr_native_peer_store_kat
            xmr_native_p2p_dos_kat)
        string(REPLACE "xmr_native_" "xmr_" _c1c_src ${_c1c_kat})
        add_executable(${_c1c_kat} ${_c1c_src}.cpp)
        target_include_directories(${_c1c_kat} PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_features(${_c1c_kat} PRIVATE cxx_std_20)
        add_test(NAME ${_c1c_kat} COMMAND ${_c1c_kat})
    endforeach()

    add_executable(xmr_native_peer_pool_kat xmr_peer_pool_kat.cpp)
    target_include_directories(xmr_native_peer_pool_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_features(xmr_native_peer_pool_kat PRIVATE cxx_std_20)
    if (TARGET Boost::headers)
        target_link_libraries(xmr_native_peer_pool_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(xmr_native_peer_pool_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(xmr_native_peer_pool_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    if (TARGET Threads::Threads)
        target_link_libraries(xmr_native_peer_pool_kat PRIVATE Threads::Threads)
    endif()
    add_test(NAME xmr_native_peer_pool_kat COMMAND xmr_native_peer_pool_kat)
    # Loopback TCP with compressed deadlines: seconds on an idle runner, but
    # never unbounded.
    set_tests_properties(xmr_native_peer_pool_kat PROPERTIES TIMEOUT 300)

    add_executable(xmr_native_template_kat xmr_native_template_kat.cpp)
    target_include_directories(xmr_native_template_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xmr_native_template_kat PRIVATE xmr_coin xmr_node)
    target_compile_features(xmr_native_template_kat PRIVATE cxx_std_20)
    if (TARGET Boost::headers)
        target_link_libraries(xmr_native_template_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(xmr_native_template_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(xmr_native_template_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    add_test(NAME xmr_native_template_kat COMMAND xmr_native_template_kat)

    # ─────────────────────────────────────────────────────────────────────────
    # Wave 1 / C6: the monerod-parity oracle (../parity/). One target.
    #
    #   xmr_native_parity_kat -- the M4 gate, proven both ways. The agreeing
    #     half runs the three seams over a read-only stagenet capture with the
    #     native side DERIVED (C2a's retarget and emission driving C2c's index
    #     and C4's NativeMinerDataSource) rather than copied, and that capture
    #     corroborates the INDEPENDENT one the C4 component took days earlier:
    #     the two agree on the block id and on the difficulty where they overlap,
    #     which neither could fake alone. The disagreeing half is the reason the
    #     target exists: every required EQUALITY field of every seam is perturbed
    #     by ONE UNIT and must FAIL, then REMOVED and must FAIL again, because a
    #     comparison that did not happen is not one that passed.
    #
    #     Links `xmr_coin` (keccak, tree hash, the vendored difficulty retarget)
    #     and `xmr_node` (the PRODUCTION get_miner_data parser -- the monerod arm
    #     has to be the real decode path, or "we match the daemon" would be a
    #     claim about a re-typed struct). Both are LIGHT links: no RandomX, no
    #     libsodium, no libzmq, no monerod, no network. It writes and removes one
    #     small JSON file in the working directory; ctest runs it inside the
    #     build tree with no arguments (`--verbose` prints every sample line).
    #
    # Same drift-guard rule as every target above: it is added to BOTH
    # `--target` lists in .github/workflows/build.yml by the change that adds it
    # here, because a registered-but-unbuilt target reports "***Not Run" and
    # fails ctest (the #1539 lesson).
    # ─────────────────────────────────────────────────────────────────────────
    add_executable(xmr_native_parity_kat xmr_parity_kat.cpp)
    target_include_directories(xmr_native_parity_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xmr_native_parity_kat PRIVATE xmr_coin xmr_node)
    target_compile_features(xmr_native_parity_kat PRIVATE cxx_std_20)
    if (TARGET Boost::headers)
        target_link_libraries(xmr_native_parity_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(xmr_native_parity_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(xmr_native_parity_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    add_test(NAME xmr_native_parity_kat COMMAND xmr_native_parity_kat)

    # ─────────────────────────────────────────────────────────────────────────
    # M1 / C3 + C6: the P-POOL seam (../parity/xmr_txpool_parity.hpp).
    #
    #   xmr_native_txpool_parity_kat -- the OFFLINE REPLAY of the live M1 run.
    #     A real monerod's /get_transaction_pool answer is checked in
    #     (xmr_txpool_parity_golden.hpp, captured from the isolated regtest
    #     rig); the KAT parses it with the same MonerodTxpoolRpc the live probe
    #     uses, feeds every entry's tx_blob into a real RelayedTxPool through
    #     IRelayedTxSink, and runs the same compare_txpools over the two sides.
    #     Every {weight, fee, blob_size} on the native side is recomputed here,
    #     now, by C3's decoder; every one on the daemon side is a number a real
    #     daemon printed. It also pins the judgement itself -- a perturbed
    #     weight, fee or size FAILS, an unanswered required field FAILS rather
    #     than being skipped, and disjoint pools produce NO samples rather than
    #     agreement -- plus the coverage tally that makes an uncompared daemon
    #     id visible, eviction as the probe observes it (mined, and key-image
    #     conflict), and the C1 DoS buckets absorbing a transaction-relay flood
    #     without the pool admitting a frame the guard refused.
    #
    #     Links `xmr_native_txpool` only: no RandomX, no network, no monerod.
    #
    # Same drift-guard rule as every target above: it is added to BOTH
    # `--target` lists in .github/workflows/build.yml by the change that adds it
    # here, because a registered-but-unbuilt target reports "***Not Run" and
    # fails ctest (the #1539 lesson).
    # ─────────────────────────────────────────────────────────────────────────
    add_executable(xmr_native_txpool_parity_kat xmr_txpool_parity_kat.cpp)
    target_include_directories(xmr_native_txpool_parity_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xmr_native_txpool_parity_kat PRIVATE xmr_native_txpool)
    target_compile_features(xmr_native_txpool_parity_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_native_txpool_parity_kat COMMAND xmr_native_txpool_parity_kat)

    add_executable(xmr_native_template_coinbase_kat
        xmr_native_template_coinbase_kat.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../settle/xmr_coinbase.cpp)
    target_include_directories(xmr_native_template_coinbase_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xmr_native_template_coinbase_kat PRIVATE xmr_coin)
    target_compile_features(xmr_native_template_coinbase_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_native_template_coinbase_kat COMMAND xmr_native_template_coinbase_kat)

    # ------------------------------------------------------------------
    # C5 -- the dual-arm found-block relay.
    #
    #   xmr_native_block_relay_kat -- the 2008 frame (encoded here, decoded
    #   back with the C1a codec), the arm orders, the fail-closed RandomX
    #   gate, the never-silent-drop rule, the partial-block refusal, the 2009
    #   responder and the redundant-broadcast carrier's admission ladder.
    #
    # Links xmr_coin (keccak / tree root, for the block and transaction ids
    # the relay re-derives before anything goes out) and xmr_node (the
    # BlockCandidate bridge in xmr_block_relay_submit_bridge.hpp compiles the
    # existing monerod submit surface). No RandomX -- the gate is an injected
    # closure precisely so this component builds and tests without it -- and
    # no sockets: the broadcast port is the contracts fake.
    add_executable(xmr_native_block_relay_kat xmr_native_block_relay_kat.cpp)
    target_include_directories(xmr_native_block_relay_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xmr_native_block_relay_kat PRIVATE xmr_coin xmr_node)
    target_compile_features(xmr_native_block_relay_kat PRIVATE cxx_std_20)
    if (TARGET Boost::headers)
        target_link_libraries(xmr_native_block_relay_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(xmr_native_block_relay_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(xmr_native_block_relay_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    if (TARGET Threads::Threads)
        target_link_libraries(xmr_native_block_relay_kat PRIVATE Threads::Threads)
    endif()
    add_test(NAME xmr_native_block_relay_kat COMMAND xmr_native_block_relay_kat)

    # ------------------------------------------------------------------
    # M0 -- the assembly (../node/).
    #
    #   xmr_native_node_kat -- everything about the wire-up that can be judged
    #   without a daemon: the worker loops and their bounded queues, the
    #   enqueue-and-return adapters (including the deferred txpool verdict,
    #   which must not be invented), the RandomX io-thread WITNESS that makes
    #   the node's foreign-call counter trustworthy, the genesis row derived
    #   from a real monerod genesis blob against monerod's own published
    #   numbers for it, the pre-boot advertisement that keeps a peer from
    #   closing us before the boot fetch lands, and the sync driver schedule.
    #
    # Links xmr_coin (block identity: keccak + tree hash) and boost's
    # header-only multiprecision, which the vendored difficulty retarget types
    # its difficulty as -- the same LIGHT link as the chain-index KAT. No
    # RandomX, no sockets, no daemon; the node binary itself is what needs
    # those, and it is built (never run) by CI as xmr_native_node.
    add_executable(xmr_native_node_kat xmr_native_node_kat.cpp)
    target_include_directories(xmr_native_node_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xmr_native_node_kat PRIVATE xmr_coin)
    target_compile_features(xmr_native_node_kat PRIVATE cxx_std_20)
    if (TARGET Boost::headers)
        target_link_libraries(xmr_native_node_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(xmr_native_node_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(xmr_native_node_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    if (TARGET Threads::Threads)
        target_link_libraries(xmr_native_node_kat PRIVATE Threads::Threads)
    endif()
    add_test(NAME xmr_native_node_kat COMMAND xmr_native_node_kat)
    # It parks a worker thread on a spin-wait to fill a queue; bounded, but
    # never let it be unbounded on a loaded runner.
    set_tests_properties(xmr_native_node_kat PROPERTIES TIMEOUT 120)

    # ------------------------------------------------------------------
    # M2h -- the P-TPL backlog CONSTRAINT, and the two accounting findings
    # folded with it.
    #
    #   xmr_native_backlog_famine_kat -- the blind spot, reproduced and then
    #   closed. Its centrepiece runs compare_seam TWICE over the SAME pair of
    #   arm observations (six EQUALITY fields, identical, agreeing) and gets
    #   CLEAN without the new constraint and FAIL with it, which is the only
    #   honest way to show that the previous judge could not have caught a
    #   native arm serving empty templates forever. It then drives the real
    #   ParityOracle over both behaviours -- pre-restack (native 0, shadow 5:
    #   must refuse) and post-restack (native carrying the backlog: must stay
    #   clean, including the propagation-skew and quiet-chain cases that a
    #   naive gate would false-positive on) -- and covers the arm-attribution
    #   counter and the daemon arm's cache expiry.
    #
    # Links xmr_coin (block identity) and xmr_node (the PRODUCTION
    # get_miner_data parser, which suite F drives rather than re-implementing)
    # -- the same LIGHT link as xmr_native_parity_kat. No RandomX, no sockets,
    # no daemon.
    #
    # DRIFT-GUARD: also listed in BOTH `--target` lists in
    # .github/workflows/build.yml. A target registered with add_test but never
    # built reports "***Not Run" and exits 8 -- the #1539 lesson.
    add_executable(xmr_native_backlog_famine_kat xmr_backlog_famine_kat.cpp)
    target_include_directories(xmr_native_backlog_famine_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(xmr_native_backlog_famine_kat PRIVATE xmr_coin xmr_node)
    target_compile_features(xmr_native_backlog_famine_kat PRIVATE cxx_std_20)
    if (TARGET Boost::headers)
        target_link_libraries(xmr_native_backlog_famine_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(xmr_native_backlog_famine_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(xmr_native_backlog_famine_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    if (TARGET Threads::Threads)
        target_link_libraries(xmr_native_backlog_famine_kat PRIVATE Threads::Threads)
    endif()
    add_test(NAME xmr_native_backlog_famine_kat COMMAND xmr_native_backlog_famine_kat)

endif()
