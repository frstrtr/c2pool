# V37Engine (Track A2 / W0 node scaffold) — standalone unit test.
#
# Stdlib-only, the same convention as src/sharechain/v37/test/: no gtest, no
# core/Boost link; the suite is its own harness (returns nonzero on failure)
# so it runs anywhere the toolchain exists, including outside the conan/boost
# dependency tree. Threads for the single executor thread and the concurrent-
# reader F1 race test.
#
# Hand-wired on purpose (no file(GLOB) auto-discovery in this repo — see the
# note in ../../CMakeLists.txt). MITIGATION NOTE: add_subdirectory/add_test here
# is NECESSARY but is NOT itself the hollow-green mitigation. A CTest registered
# in CMake but ABSENT from the build.yml `cmake --build --target` list is never
# compiled in CI, so CTest reports it NOT_BUILT and the run silently passes (the
# DGB #137 / #769 unregistered-KAT class; identical to PR #1467's executor test).
# The real mitigation is TWO-PART, both now in place:
#   (1) v37_scaffold_test is listed in the build.yml --target lists (BOTH the
#       Linux x86_64 leg and the ASan+UBSan leg), so CI actually builds + runs it;
#   (2) tools/ci/check_test_target_allowlist.py's drift-guard glob now covers
#       src/c2pool/**/test/, so any future add_test here that is missing from
#       build.yml fails the guard at PR time instead of hollow-greening.
if (BUILD_TESTING)
    add_executable(v37_scaffold_test v37_scaffold_test.cpp)
    target_compile_features(v37_scaffold_test PRIVATE cxx_std_20)
    target_include_directories(v37_scaffold_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_scaffold_test Threads::Threads)
    add_test(NAME v37_scaffold_test COMMAND v37_scaffold_test)

    # Track A2 / W2 — RDWR receipt-ingestion KAT (src/c2pool/v37/w2_*.hpp).
    # Same stdlib-only shape as the scaffold suite. HOLLOW-GREEN GUARD (the same
    # two-part mitigation as above): this target is ALSO listed in the build.yml
    # --target lists (BOTH the Linux x86_64 leg and the ASan+UBSan leg) so CI
    # actually compiles + runs it, not just registers it as a NOT_BUILT CTest
    # sentinel (the DGB #137 / #769 / PR #1467 / #1477 unregistered-KAT class).
    add_executable(v37_w2_ingestion_test v37_w2_ingestion_test.cpp)
    target_compile_features(v37_w2_ingestion_test PRIVATE cxx_std_20)
    target_include_directories(v37_w2_ingestion_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_w2_ingestion_test Threads::Threads)
    add_test(NAME v37_w2_ingestion_test COMMAND v37_w2_ingestion_test)

    # Track A2 / W4 prerequisites — the OI-W4-1 identity view + OI-W4-3
    # read-at-version ring on the V37Engine/executor snapshot surface
    # (src/sharechain/v37/v37_lane_executor.hpp + src/c2pool/v37/v37_engine.hpp).
    # Same stdlib-only shape as the scaffold/W2 suites. HOLLOW-GREEN GUARD (the
    # same two-part mitigation as above): this target is ALSO listed in the
    # build.yml --target lists (BOTH the Linux x86_64 leg and the ASan+UBSan
    # leg) so CI actually compiles + runs it, not just registers it as a
    # NOT_BUILT CTest sentinel (the DGB #137 / #769 / PR #1467 / #1477 class).
    add_executable(v37_w4_prereq_test v37_w4_prereq_test.cpp)
    target_compile_features(v37_w4_prereq_test PRIVATE cxx_std_20)
    target_include_directories(v37_w4_prereq_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_w4_prereq_test Threads::Threads)
    add_test(NAME v37_w4_prereq_test COMMAND v37_w4_prereq_test)

    # Track A2 / W4 — per-lane settlement (src/c2pool/v37/w4_settlement.hpp):
    # the consensus split, the per-chain fold over the burial-gated prefix, the
    # KEYED_CRDT OWED ledger (SETTLED-terminal, D_conf-gated), K_fair + h_min,
    # O5.5 persisted high-water, the O2 incarnation-keyed consistent cut, and the
    # D-B flagged geometry seam. Drives the real V37Engine and reproduces the
    # rev3-falsifiers acceptance SHAPES (proto/rev3-falsifiers golden 3692d922).
    # Same stdlib-only shape as the scaffold/W2/W4-prereq suites. HOLLOW-GREEN
    # GUARD (the same two-part mitigation as above): this target is ALSO listed
    # in the build.yml --target lists (BOTH the Linux x86_64 leg and the
    # ASan+UBSan leg) so CI actually compiles + runs it, not just registers it
    # as a NOT_BUILT CTest sentinel (the DGB #137 / #769 / PR #1467 / #1477 class).
    add_executable(v37_w4_settlement_test v37_w4_settlement_test.cpp)
    target_compile_features(v37_w4_settlement_test PRIVATE cxx_std_20)
    target_include_directories(v37_w4_settlement_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_w4_settlement_test Threads::Threads)
    add_test(NAME v37_w4_settlement_test COMMAND v37_w4_settlement_test)

    # Track A2 / W5 — coinbase assembly (src/c2pool/v37/w5_coinbase.hpp): the
    # OLDEST-OWED-FIRST K_fair selection (whitepaper erratum E-1 — NOT
    # largest-first) consumed from W4's OwedLedger::propose_coinbase, the
    # byte-denominated h_min dust floor + carry-forward, the fixed output/byte
    # budget, the D_conf buried gate, and the §13 state-root-in-coinbase with an
    # O(log n) balance proof verified by the shipped ::v37::Lane::verify_proof.
    # Same stdlib-only shape as the scaffold/W2/W4 suites. HOLLOW-GREEN GUARD
    # (the same two-part mitigation as above): this target is ALSO listed in the
    # build.yml --target lists (BOTH the Linux x86_64 leg and the ASan+UBSan
    # leg) so CI actually compiles + runs it, not just registers it as a
    # NOT_BUILT CTest sentinel (the DGB #137 / #769 / PR #1467 / #1477 class).
    add_executable(v37_w5_coinbase_test v37_w5_coinbase_test.cpp)
    target_compile_features(v37_w5_coinbase_test PRIVATE cxx_std_20)
    target_include_directories(v37_w5_coinbase_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_w5_coinbase_test Threads::Threads)
    add_test(NAME v37_w5_coinbase_test COMMAND v37_w5_coinbase_test)

    # Track A2 / R1 — coinbase-budget non-empty regression pin
    # (src/c2pool/v37/w5_coinbase.hpp + w4_settlement.hpp::propose_coinbase). Pins
    # that a DEFAULT-constructed CoinbaseBudget (slot_budget_C == 0) assembles a
    # NON-EMPTY coinbase — the R1 fix that makes a 0 count-cap mean UNBOUNDED
    # (symmetric with the byte budget), plus the armed h_min dust floor and the
    # digest-neutrality of assemble()/propose_coinbase() (owed_digest + §13 root
    # byte-identical, budget-independent). Same stdlib-only self-harness shape.
    # SAME HOLLOW-GREEN GUARD as the sibling suites: this target is ALSO listed in
    # the build.yml --target lists (BOTH the Linux x86_64 leg and the ASan+UBSan
    # leg) so CI compiles + runs it, not just registers a NOT_BUILT CTest sentinel
    # (the DGB #137 / #769 / PR #1467 / #1477 unregistered-KAT class).
    add_executable(v37_r1_coinbase_budget_test v37_r1_coinbase_budget_test.cpp)
    target_compile_features(v37_r1_coinbase_budget_test PRIVATE cxx_std_20)
    target_include_directories(v37_r1_coinbase_budget_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_r1_coinbase_budget_test Threads::Threads)
    add_test(NAME v37_r1_coinbase_budget_test COMMAND v37_r1_coinbase_budget_test)

    # Track A2 / W3 — carrier-relay KAT (src/c2pool/v37/w3_relay.hpp). Same
    # stdlib-only shape; it additionally forks child processes over 127.0.0.1
    # loopback sockets for the multi-process propagation smoke (POSIX sockets +
    # fork, no Boost/ASIO). SAME HOLLOW-GREEN GUARD as above: this target is ALSO
    # listed in the build.yml --target lists (BOTH the Linux x86_64 leg and the
    # ASan+UBSan leg) so CI actually compiles + runs it, not just registers it as
    # a NOT_BUILT CTest sentinel (the DGB #137 / #769 / PR #1467 / #1477 class).
    add_executable(v37_w3_relay_test v37_w3_relay_test.cpp)
    target_compile_features(v37_w3_relay_test PRIVATE cxx_std_20)
    target_include_directories(v37_w3_relay_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_w3_relay_test Threads::Threads)
    add_test(NAME v37_w3_relay_test COMMAND v37_w3_relay_test)

    # Track A2 / DROPS — sub-threshold work estimator KAT
    # (src/c2pool/v37/v37_subthreshold_estimator.hpp). The "raindrops -> bucket"
    # DROPS half: crediting a worker's below-target work as the unbiased estimate
    # Hhat = (K-1)*D_K, D_K = 2^256/(h_(K)+1), behind the EXPERIMENTAL gate
    # SubthresholdParams::enabled (DEFAULT OFF). Ships the CORRECTED sybil-neutral
    # rule (the E-2 fix) ONLY; the broken clamp is a negative reference the KAT
    # proves is rejected. Gate ON is a consensus change (RDWR-OQ2) NOT activated
    # here: the KAT pins gate-off byte-identity of BOTH the owed_digest (w4) and
    # the add-only receipt/share carrier. Stdlib-only (no Threads: integer math +
    # a deterministic splitmix64 Monte-Carlo). SAME HOLLOW-GREEN GUARD as the
    # sibling suites: this target is ALSO listed in the build.yml --target lists
    # (BOTH the Linux x86_64 leg and the ASan+UBSan leg) so CI actually compiles +
    # runs it, not just registers it as a NOT_BUILT CTest sentinel (the DGB #137 /
    # #769 / PR #1467 / #1477 unregistered-KAT class). The frozen golden JSON is
    # copied next to the binary (and the test runs there via WORKING_DIRECTORY) so
    # the stamp-verification case (case 10) reads it in-CI regardless of cwd.
    add_executable(v37_subthreshold_estimator_test v37_subthreshold_estimator_test.cpp)
    target_compile_features(v37_subthreshold_estimator_test PRIVATE cxx_std_20)
    target_include_directories(v37_subthreshold_estimator_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    add_custom_command(TARGET v37_subthreshold_estimator_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_CURRENT_SOURCE_DIR}/subthreshold_estimator_golden_v1.json
                $<TARGET_FILE_DIR:v37_subthreshold_estimator_test>/subthreshold_estimator_golden_v1.json)
    add_test(NAME v37_subthreshold_estimator_test
             COMMAND v37_subthreshold_estimator_test
             WORKING_DIRECTORY $<TARGET_FILE_DIR:v37_subthreshold_estimator_test>)
    # Track A2 / W6 — persistence, restart-recovery, and the >D rebuild path
    # (src/c2pool/v37/w6_persistence.hpp): the ISettleStore seam + all §2.3
    # record codecs, the F2 fail-closed open census (union-of-prefixes +
    # lhead-vs-levt), the SettlementJournal single-writer crash-consistency path
    # (F1 per-height monotone bin_height), the RecoveryDriver (§4.1 steps 1-9),
    # and the ReplayDriver + PrefixResolver >D slow path (F4 lane-genesis
    # truncation). Stdlib-only by construction: this TU NEVER links leveldb
    # (LevelDBSettleStore is behind W6_ENABLE_LEVELDB in the header); the
    # persistence layer is exercised through the ISettleStore seam driven by a
    # deterministic FaultSettleStore double, plus the CM-1/G1-G2-G3/F1 falsifier
    # arms (guard-off arms MUST exhibit the violation, else VACUOUS-fail). SAME
    # HOLLOW-GREEN GUARD as the suites above: this target is ALSO listed in the
    # build.yml --target lists (BOTH the Linux x86_64 leg and the ASan+UBSan leg)
    # so CI actually compiles + runs it, not just registers it as a NOT_BUILT
    # CTest sentinel (the DGB #137 / #769 / PR #1467 / #1477 unregistered-KAT class).
    add_executable(v37_w6_persistence_test v37_w6_persistence_test.cpp)
    target_compile_features(v37_w6_persistence_test PRIVATE cxx_std_20)
    target_include_directories(v37_w6_persistence_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_w6_persistence_test Threads::Threads)
    add_test(NAME v37_w6_persistence_test COMMAND v37_w6_persistence_test)

    # Track A2 / RDWR-OQ2 ACTIVATION — the sub-threshold estimator WIRED into the
    # real W4 OwedLedger credit/fold path (src/c2pool/v37/w4_settlement.hpp) behind
    # the ::v37::LaneParams::subthreshold gate. Proves the PRIME safety invariant
    # at the wiring level: gate OFF (the default) => the composed owed_digest, the
    # add-only receipt/share carrier, AND the lane digest are BYTE-IDENTICAL to
    # master on a shared fixed schedule; gate ON is the RDWR-OQ2 consensus
    # activation (owed_digest changes; goldens re-stamped, pinned here). Stdlib-only
    # (integer math + deterministic splitmix64 MC), same self-harness shape as the
    # sibling suites. SAME HOLLOW-GREEN GUARD: this target is ALSO listed in the
    # build.yml --target lists (BOTH the Linux x86_64 leg and the ASan+UBSan leg)
    # so CI actually compiles + runs it, not just registers it as a NOT_BUILT CTest
    # sentinel (the DGB #137 / #769 / PR #1467 / #1477 unregistered-KAT class). The
    # frozen golden JSON is copied next to the binary (WORKING_DIRECTORY) so the
    # stamp-verification case reads it in-CI regardless of cwd.
    add_executable(v37_w4_estimator_wiring_test v37_w4_estimator_wiring_test.cpp)
    target_compile_features(v37_w4_estimator_wiring_test PRIVATE cxx_std_20)
    target_include_directories(v37_w4_estimator_wiring_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    add_custom_command(TARGET v37_w4_estimator_wiring_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_CURRENT_SOURCE_DIR}/w4_estimator_wiring_golden_v1.json
                $<TARGET_FILE_DIR:v37_w4_estimator_wiring_test>/w4_estimator_wiring_golden_v1.json)
    add_test(NAME v37_w4_estimator_wiring_test
             COMMAND v37_w4_estimator_wiring_test
             WORKING_DIRECTORY $<TARGET_FILE_DIR:v37_w4_estimator_wiring_test>)

    # Track A2 / Milestone A — the live XmrNode daemon smoke
    # (src/c2pool/v37/xmr/xmr_node_smoke.hpp). Stands the WHOLE single-node
    # stagenet daemon up against a monerod STUB (MockMonerodTransport — no
    # RandomX, no libzmq, no sockets, no live monerod) and asserts the four
    # milestone invariants: (S1) construction/donor order — the W6 settlement
    # store + RecoveryDriver are built BEFORE V37Engine::start(); (S2) BOTH
    # descriptor backends live + fail-closed without one; (S3) the X2 adapter
    # Extend/Reorg stream drives the node; (S4) the F1 CONTRACT —
    # OwedLedger::on_block_finalized is called once per coin-height, IN ORDER,
    # with bin_height = the high-water AT THE STEP (H+D_conf), NEVER the live
    # tip; (S5) consensus DIGEST unchanged (lane digest + owed_digest
    # byte-identical to a bare-library replay); (S6) restart recovery round-trip
    # + F2 fail-closed on a torn store. Links the X2 adapter lib (xmr_node) for
    # the RPC/ZMQ decoder symbols + Threads for the engine executor thread; NO
    # crypto link (a test point-check backend is injected). Its own harness
    # (nonzero exit on any failed check). SAME HOLLOW-GREEN GUARD as the sibling
    # suites: listed in the build.yml --target lists (BOTH the Linux x86_64 leg
    # and the ASan+UBSan leg) so CI compiles + runs it, and audited by the
    # src/c2pool/**/test drift-guard.
    add_executable(v37_xmr_node_smoke v37_xmr_node_smoke.cpp)
    target_compile_features(v37_xmr_node_smoke PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_node_smoke PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_node_smoke PRIVATE xmr_node Threads::Threads)
    add_test(NAME v37_xmr_node_smoke COMMAND v37_xmr_node_smoke)
    # ── Track A2 / Milestone A-BTC — the live BITCOIN-FAMILY node CI gates ────
    # The single-node c2pool-v37-btc daemon (XbtcNode) wires the MERGED v37
    # engine (V37Engine / OwedLedger / W5 native coinbase) to the mature v36 coin
    # plumbing behind ICoinBackend. These three targets are the NON-HOLLOW gates.
    # SAME two-part hollow-green guard as the sibling suites: each is ALSO listed
    # in the build.yml --target lists (BOTH the Linux x86_64 leg AND the
    # ASan+UBSan leg — all three are sanitizer-clean, verified
    # -fsanitize=address,undefined -fno-sanitize-recover=all), and the
    # src/c2pool/**/test/ drift-guard (check_test_target_allowlist.py) fails
    # closed on any add_test here missing from build.yml. Header-only lifecycle +
    # MockCoinBackend: link only Threads (no coin lib, no Boost — HARD SAFETY 6).

    # (1) the live lifecycle smoke — open-before-start, mainnet fence, F1 per-
    #     height finalize, on_block_won W5 coinbase+submit, reorg drill,
    #     W6 restart round-trip + F2 fail-closed (13 checks).
    add_executable(v37_btc_node_smoke v37_btc_node_smoke.cpp)
    target_compile_features(v37_btc_node_smoke PRIVATE cxx_std_20)
    target_include_directories(v37_btc_node_smoke PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_btc_node_smoke Threads::Threads)
    add_test(NAME v37_btc_node_smoke COMMAND v37_btc_node_smoke)

    # (2) the drift-guard (HARD SAFETY 1): the lane digest the node publishes and
    #     the owed digest after an F1 schedule are BYTE-IDENTICAL to a bare
    #     ::v37::Roundabout / a fresh OwedLedger — the node changes no consensus
    #     digest, it only SEQUENCES merged-engine calls.
    add_executable(v37_btc_digest_drift_kat v37_btc_digest_drift_kat.cpp)
    target_compile_features(v37_btc_digest_drift_kat PRIVATE cxx_std_20)
    target_include_directories(v37_btc_digest_drift_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_btc_digest_drift_kat Threads::Threads)
    add_test(NAME v37_btc_digest_drift_kat COMMAND v37_btc_digest_drift_kat)

    # (3) the F1 finalize-driver KAT over the COIN-AGNOSTIC settle_finalize_driver
    #     (src/c2pool/v37/settle_finalize_driver.hpp — the driver shared byte-for-
    #     byte with Milestone A-XMR). Proves in-order/per-height catch-up ==
    #     real-time, restart-safe, O5.5 shorter-branch refusal, AND the FALSIFIER:
    #     a jump-to-tip driver FORKS the owed_digest (7 checks). Stdlib-only.
    add_executable(f1_finalize_kat_btc f1_finalize_kat_btc.cpp)
    target_compile_features(f1_finalize_kat_btc PRIVATE cxx_std_20)
    target_include_directories(f1_finalize_kat_btc PRIVATE ${CMAKE_SOURCE_DIR}/src)
    add_test(NAME f1_finalize_kat_btc COMMAND f1_finalize_kat_btc)

    # Track A2 / RDWR-OQ2 V37.1 CONSENSUS ACTIVATION — proves the SHIPPED default
    # is now V37.1 (the gate ON under the sybil-neutral Combined rule) via the
    # add-only LaneParams version marker (LaneParams::v37_0()/v37_1()/shipped(),
    # SHIPPED_CONSENSUS_VERSION==1), that the ACTIVE credit rule is the E-2
    # corrected combined estimator Hhat_comb=(S+K-1)*D'_K and NEVER the broken
    # clamp (kept only as the module's NEVER_CONSENSUS witness), and that the
    # activation is NON-DESTRUCTIVE: gate-OFF (V37.0, LaneParams::v37_0())
    # owed_digest is BYTE-IDENTICAL to master AND to the pre-existing V37.0 golden,
    # gate-ON (V37.1) owed_digest == the NEW pinned V37.1 golden, and the two
    # differ (non-vacuous). Stdlib-only, same self-harness shape. SAME HOLLOW-GREEN
    # GUARD: this target is ALSO listed in the build.yml --target lists (BOTH the
    # Linux x86_64 leg and the ASan+UBSan leg) so CI compiles + runs it, not just
    # registers it as a NOT_BUILT CTest sentinel. Its frozen golden JSON is copied
    # next to the binary so the stamp case reads it in-CI regardless of cwd.
    add_executable(v37_1_activation_test v37_1_activation_test.cpp)
    target_compile_features(v37_1_activation_test PRIVATE cxx_std_20)
    target_include_directories(v37_1_activation_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    add_custom_command(TARGET v37_1_activation_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_CURRENT_SOURCE_DIR}/v371_activation_golden_v1.json
                $<TARGET_FILE_DIR:v37_1_activation_test>/v371_activation_golden_v1.json)
    add_test(NAME v37_1_activation_test
             COMMAND v37_1_activation_test
             WORKING_DIRECTORY $<TARGET_FILE_DIR:v37_1_activation_test>)

    # ── Track A2 / X9 O-2 — the XMR serve-side wiring gates (network-free) ────
    # v37_xmr_o2_live_submit_selfcheck: the block-blob assembler + submit_block
    # ack parser (incl. result.block_id) + LiveBlockSubmitter over the monerod
    # STUB, pinned by a REAL golden (keccak256(varint(len)||hashing_blob) of the
    # Monero mainnet genesis block == its published id), and the IShareSink ->
    # FoundBlockQueue hand-off. Links xmr_node (RPC bodies/parsers) + xmr_coin
    # (vendored keccak + varint). No RandomX, no sockets.
    add_executable(v37_xmr_o2_live_submit_selfcheck v37_xmr_o2_live_submit_selfcheck.cpp)
    target_compile_features(v37_xmr_o2_live_submit_selfcheck PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_o2_live_submit_selfcheck PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_link_libraries(v37_xmr_o2_live_submit_selfcheck PRIVATE xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_o2_live_submit_selfcheck COMMAND v37_xmr_o2_live_submit_selfcheck)
    # v37_xmr_o2_finalize_connect_selfcheck: queued win -> XmrNode::
    # on_network_block_won (amount-honest FOUND) -> restart inside the D_conf
    # window -> pending-FOUND sidecar re-drive -> FINALIZE at bin_height =
    # H_b + D_conf -> finalW nets to 0; late-FOUND / malformed / all-zero bid
    # refusals; orphan disposition. Same shape as v37_xmr_node_smoke (monerod
    # STUB, injected test point-check backend). SAME HOLLOW-GREEN GUARD: both
    # targets are listed in the build.yml --target lists (BOTH the Linux x86_64
    # leg and the ASan+UBSan leg) so CI compiles + runs them.
    add_executable(v37_xmr_o2_finalize_connect_selfcheck v37_xmr_o2_finalize_connect_selfcheck.cpp)
    target_compile_features(v37_xmr_o2_finalize_connect_selfcheck PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_o2_finalize_connect_selfcheck PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_o2_finalize_connect_selfcheck PRIVATE xmr_node Threads::Threads)
    add_test(NAME v37_xmr_o2_finalize_connect_selfcheck COMMAND v37_xmr_o2_finalize_connect_selfcheck)
    # v37_xmr_cba_native_booking_kat (D6a): the coinbase-authority booking reads
    # lane blocks from the NATIVE chain index (xmr/xmr_cba_block_source.hpp), not
    # monerod get_block -- a native hit makes 0 RPCs, a miss HOLDS (never a silent
    # monerod fallback), the compare oracle counts but never decides -- and, end to
    # end through FinalizeConnect, a not-yet-held block is retried then HELD, never
    # refused. Same monerod-STUB shape as the finalize-connect selfcheck. SAME
    # HOLLOW-GREEN GUARD: listed in BOTH build.yml --target lists.
    add_executable(v37_xmr_cba_native_booking_kat v37_xmr_cba_native_booking_kat.cpp)
    target_compile_features(v37_xmr_cba_native_booking_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_cba_native_booking_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_cba_native_booking_kat PRIVATE xmr_node Threads::Threads)
    add_test(NAME v37_xmr_cba_native_booking_kat COMMAND v37_xmr_cba_native_booking_kat)
    # v37_xmr_coldboot_refetch_kat (COLD-BOOT): a fresh boot from an anchor far
    # behind the tip evicts the oldest post-anchor bodies before they are booked;
    # the booking asks them back (native index re-ask-by-id, bounded) and books
    # byte-identical to a node that never evicted (REAL ChainIndex, 3000 blocks,
    # cache 64, p2p-first FinalizeConnect), plus the fresh-store boot cursor
    # seed. Builds on the pre-fix tree and FAILS there. SAME HOLLOW-GREEN GUARD:
    # listed in BOTH build.yml --target lists.
    add_executable(v37_xmr_coldboot_refetch_kat v37_xmr_coldboot_refetch_kat.cpp)
    target_compile_features(v37_xmr_coldboot_refetch_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_coldboot_refetch_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_coldboot_refetch_kat PRIVATE xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_coldboot_refetch_kat COMMAND v37_xmr_coldboot_refetch_kat)
    set_tests_properties(v37_xmr_coldboot_refetch_kat PROPERTIES TIMEOUT 600)
    # v37_xmr_coldboot_gap_kat (COLD-BOOT-2): a post-anchor gap LONGER than the
    # row retention (3000 blocks vs the shipped 2048 rows / 1024 bodies) is
    # booked AS it downloads (the settlement's finalize cursor paces the
    # index's download), every block in chain order, identical to an
    # uninterrupted reference; a row the index trimmed before booking HOLDS
    # (Unknown), never a silent drop; a refetch burst keeps the tip-side bodies
    # the snapshot needs; a restart resumes from the recovered cursor (re-walk
    # and snapshot-resume shapes), never jumps it. Builds on the pre-fix tree and
    # FAILS there. SAME HOLLOW-GREEN GUARD: listed in BOTH build.yml --target lists.
    add_executable(v37_xmr_coldboot_gap_kat v37_xmr_coldboot_gap_kat.cpp)
    target_compile_features(v37_xmr_coldboot_gap_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_coldboot_gap_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_coldboot_gap_kat PRIVATE xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_coldboot_gap_kat COMMAND v37_xmr_coldboot_gap_kat)
    set_tests_properties(v37_xmr_coldboot_gap_kat PROPERTIES TIMEOUT 900)
    # v37_xmr_coldboot_follow_kat (COLD-BOOT-3): the catch-up pacing is a
    # catch-up device, never a standing limit -- a HELD finalize cursor (an
    # undecidable block) with the tip > 2 x window past it keeps FOLLOWING the
    # chain after a snapshot restart and on a fresh boot (pacing lifted: synced
    # latch / resume latch / stall bound), the cursor stays held, 0 late, 0
    # undecided; an unheld cold boot is still paced. Builds on the pre-fix tree
    # and FAILS there. SAME HOLLOW-GREEN GUARD: listed in BOTH build.yml --target lists.
    add_executable(v37_xmr_coldboot_follow_kat v37_xmr_coldboot_follow_kat.cpp)
    target_compile_features(v37_xmr_coldboot_follow_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_coldboot_follow_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_coldboot_follow_kat PRIVATE xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_coldboot_follow_kat COMMAND v37_xmr_coldboot_follow_kat)
    set_tests_properties(v37_xmr_coldboot_follow_kat PROPERTIES TIMEOUT 900)
    # v37_xmr_coldboot_evq_kat (COLD-BOOT-3): the REAL NativeNode's mainchain-event
    # queue never drops silently -- a 9000-block download burst is back-pressured
    # below the 8192 cap (0 dropped, sequence identical to a no-burst reference);
    # a push burst past the cap is alarmed, counted and re-driven from the index
    # (dropped == redriven + unrecoverable). Builds on the pre-fix tree and FAILS
    # there. SAME HOLLOW-GREEN GUARD: listed in BOTH build.yml --target lists.
    add_executable(v37_xmr_coldboot_evq_kat v37_xmr_coldboot_evq_kat.cpp)
    target_compile_features(v37_xmr_coldboot_evq_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_coldboot_evq_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_coldboot_evq_kat PRIVATE xmr_node xmr_native_txpool xmr_coin Threads::Threads)
    if (TARGET Boost::headers)
        target_link_libraries(v37_xmr_coldboot_evq_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(v37_xmr_coldboot_evq_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(v37_xmr_coldboot_evq_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    add_test(NAME v37_xmr_coldboot_evq_kat COMMAND v37_xmr_coldboot_evq_kat)
    set_tests_properties(v37_xmr_coldboot_evq_kat PROPERTIES TIMEOUT 900)

    # v37_xmr_race_rebook_kat (RACE-DIVERGE): a depth-1 same-height flip-flop
    # X -> Y -> X that completes inside ONE tick re-books X (the stale m_pending
    # entry left by the Orphan event must not dedup the D2-0 re-delivery), so the
    # node ends byte-identical (owed_digest) to one that followed X directly.
    # Same monerod-STUB shape. SAME HOLLOW-GREEN GUARD: listed in BOTH build.yml
    # --target lists.
    add_executable(v37_xmr_race_rebook_kat v37_xmr_race_rebook_kat.cpp)
    target_compile_features(v37_xmr_race_rebook_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_race_rebook_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_race_rebook_kat PRIVATE xmr_node Threads::Threads)
    add_test(NAME v37_xmr_race_rebook_kat COMMAND v37_xmr_race_rebook_kat)
    # v37_xmr_relay_repair_hold_kat (RC-HOLD): a GAP-2 relay repair of the
    # winner's cut that outlasts the booking retry bound is UNDECIDED -> HELD
    # (R4 gate kept, repair continues), never refused on a retry count; two nodes
    # whose repairs finish at different attempts end byte-identical; a DECIDED
    # mismatch (credit-cut MISMATCH / lane-root-refused) is still refused. Same
    # monerod-STUB shape. SAME HOLLOW-GREEN GUARD: listed in BOTH build.yml
    # --target lists.
    add_executable(v37_xmr_relay_repair_hold_kat v37_xmr_relay_repair_hold_kat.cpp)
    target_compile_features(v37_xmr_relay_repair_hold_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_relay_repair_hold_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_relay_repair_hold_kat PRIVATE xmr_node Threads::Threads)
    add_test(NAME v37_xmr_relay_repair_hold_kat COMMAND v37_xmr_relay_repair_hold_kat)

    # v37_xmr_relay_native_feed_kat (D6b): under --arm-order p2p-first the receipt
    # relay's chain view (headers, tip, reorgs) is fed from the NATIVE chain
    # index (xmr/relay/xmr_relay_chain_feed.hpp), not monerod
    # get_block_headers_range / get_block_header_by_height: the notes
    # equal the daemon arm's over the same chain (across an epoch edge), a
    # same-height reorg re-notes at once, a missing seed/row is a counted skip,
    # and the compare oracle only counts. Header-only. SAME HOLLOW-GREEN GUARD:
    # listed in BOTH build.yml --target lists.
    add_executable(v37_xmr_relay_native_feed_kat v37_xmr_relay_native_feed_kat.cpp)
    target_compile_features(v37_xmr_relay_native_feed_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_relay_native_feed_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    add_test(NAME v37_xmr_relay_native_feed_kat COMMAND v37_xmr_relay_native_feed_kat)
    # v37_xmr_minority_converge_selfcheck (D2, operator ruling D2 = A): the PURE
    # pieces of xmr/xmr_minority_converge.hpp -- the builder key, the minority
    # detection rule, the refold (re-derivation) driven through the production
    # XmrFinalizeDriver + OwedLedger + MemSettleStore, the marker/observation
    # codecs. No node, no network. Listed in BOTH build.yml --target lists.
    add_executable(v37_xmr_minority_converge_selfcheck v37_xmr_minority_converge_selfcheck.cpp)
    target_compile_features(v37_xmr_minority_converge_selfcheck PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_minority_converge_selfcheck PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_minority_converge_selfcheck PRIVATE xmr_node Threads::Threads)
    add_test(NAME v37_xmr_minority_converge_selfcheck COMMAND v37_xmr_minority_converge_selfcheck)
    # v37_xmr_minority_workweight_kat (D2, operator ruling D-1 = C): production
    # FinalizeConnect nodes in lockstep (the D2Rig) + the production
    # LaneSuspendState -- a byzantine PAIR with < 50% of the window's work never
    # halts an honest node, the minority trigger is work-weighted (40% no, 60%
    # yes), DIVERGED is alarm-only. Listed in BOTH build.yml --target lists.
    add_executable(v37_xmr_minority_workweight_kat v37_xmr_minority_workweight_kat.cpp)
    target_compile_features(v37_xmr_minority_workweight_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_minority_workweight_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_minority_workweight_kat PRIVATE xmr_node Threads::Threads)
    add_test(NAME v37_xmr_minority_workweight_kat COMMAND v37_xmr_minority_workweight_kat)
    # v37_xmr_lane_suspend_selfcheck (R-C rework-2): the stratum side of LANE
    # SUSPEND over a loopback socket -- the suspend EDGE withdraws the job
    # (sessions dropped), a login while suspended is PARKED, the resume edge
    # serves it. Stub template source + verifier: no RandomX, no monerod.
    add_executable(v37_xmr_lane_suspend_selfcheck
        v37_xmr_lane_suspend_selfcheck.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/stratum/xmr_stratum.cpp)
    target_compile_features(v37_xmr_lane_suspend_selfcheck PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_lane_suspend_selfcheck PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_lane_suspend_selfcheck PRIVATE xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_lane_suspend_selfcheck COMMAND v37_xmr_lane_suspend_selfcheck)
    # v37_xmr_stratum_resume_kat (STRATUM-RESUME, cold-boot smoke D3): a login
    # parked while there is no template / the lane is SUSPENDED is kept open and
    # completed with a login result + job on the first template (notify, resume
    # edge, or the idle-tick re-probe) -- never expired into "No job available",
    # which leaves xmrig idle on an open connection for good. Fake template
    # provider (unavailable -> available) + stub verifier over loopback: no
    # RandomX, no monerod. Listed in BOTH build.yml --target lists.
    add_executable(v37_xmr_stratum_resume_kat
        v37_xmr_stratum_resume_kat.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/stratum/xmr_stratum.cpp)
    target_compile_features(v37_xmr_stratum_resume_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_stratum_resume_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_stratum_resume_kat PRIVATE xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_stratum_resume_kat COMMAND v37_xmr_stratum_resume_kat)
    # v37_xmr_test_suspend_knob_kat (FAULT-KNOB, TEST-ONLY): the
    # --test-suspend-lane-seconds / SIGUSR2 knob that forces a lane suspension
    # on a live node -- off by default, refused on mainnet, arm/fire/release
    # through LaneSuspendState (cause `test`), and end to end through the real
    # StratumListener::set_lane_suspended() (parked login served on release).
    # RESUME-FRESH (FK7/FK8): the first job after a release is at the current tip
    # (xmr/xmr_lane_resume_fresh.hpp), and a failed rebuild holds the gate.
    # Stub template source + verifier over loopback: no RandomX, no monerod.
    # Listed in BOTH build.yml --target lists.
    add_executable(v37_xmr_test_suspend_knob_kat
        v37_xmr_test_suspend_knob_kat.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/stratum/xmr_stratum.cpp)
    target_compile_features(v37_xmr_test_suspend_knob_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_test_suspend_knob_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_xmr_test_suspend_knob_kat PRIVATE xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_test_suspend_knob_kat COMMAND v37_xmr_test_suspend_knob_kat)
    # v37_xmr_o2_randomx_kat: the runtime IPowVerifier (O2RandomXVerifier over
    # the production LightVerifier + librandomx) reproducing the X8 KAT vector
    # (mainnet block 3,000,000 PoW) through the MERGED XmrStratumServer's
    # handle_login/handle_submit, plus the exact 128-bit network gate, the
    # strict no-Argon2d-on-submit invariant, the seed mailbox and the
    # fail-closed disabled/compiled-out modes. HEAVY (2 x 256 MiB caches) and
    # JIT: like xmr_randomx_verify_kat it is built ONLY under XMR_BUILD_RANDOMX
    # (the non-sanitizer CI leg) and is listed in that leg's --target list.
    if (XMR_BUILD_RANDOMX AND TARGET randomx)
        add_executable(v37_xmr_o2_randomx_kat
            v37_xmr_o2_randomx_kat.cpp
            ${CMAKE_SOURCE_DIR}/src/impl/xmr/stratum/xmr_stratum.cpp)
        target_compile_features(v37_xmr_o2_randomx_kat PRIVATE cxx_std_20)
        target_include_directories(v37_xmr_o2_randomx_kat PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/impl/xmr/third_party/randomx)
        target_compile_definitions(v37_xmr_o2_randomx_kat PRIVATE V37_XMR_O2_WITH_RANDOMX)
        target_link_libraries(v37_xmr_o2_randomx_kat PRIVATE xmr_coin randomx Threads::Threads)
        add_test(NAME v37_xmr_o2_randomx_kat COMMAND v37_xmr_o2_randomx_kat)
    endif()

    # ------------------------------------------------------------------
    # M2 — the option-B settlement coinbase, built from the NATIVE arm.
    #
    #   v37_xmr_m2_native_settlement_kat
    #     Runs the thing that actually serves miners: the C4 seam bound to
    #     NativeMinerDataSource, XmrSettlementTemplateProvider above it, and the
    #     whole-block assembler under that -- then judges the result by
    #     RE-PARSING the assembled block's miner_tx (K_fair owed order, exact-sum
    #     residual sink, owed_digest under the tx_extra 0x03 tag), proves the two
    #     arms build the same block from the miner_tx onward, and proves the
    #     native template path never touches the transport.
    #
    #     Heaviest of the v37 consumer KATs and deliberately so: it links
    #     `xmr_template` (the p2pool whole-block template port), compiles the X6
    #     executor (settle/xmr_coinbase.cpp) and the ed25519 point-check
    #     registrar, because a settlement coinbase that is not actually derived
    #     is not the thing M2 claims to have preserved. Both are already on the
    #     non-sanitizer leg through c2pool-v37-xmr; the sanitizer leg picks them
    #     up here, which is the point -- the option-B assembler had no ASan/UBSan
    #     coverage before this target.
    #
    #     SAME HOLLOW-GREEN GUARD as its siblings: ALSO listed in BOTH build.yml
    #     `--target` lists (the Linux x86_64 leg and the ASan+UBSan leg), because
    #     a registered-but-unbuilt target reports "***Not Run" and fails ctest
    #     with exit 8 -- a red that is not a test failure (the #1539 lesson).
    # ------------------------------------------------------------------
    add_executable(v37_xmr_m2_native_settlement_kat
        v37_xmr_m2_native_settlement_kat.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/settle/xmr_coinbase.cpp
        ${CMAKE_SOURCE_DIR}/src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp)
    target_compile_features(v37_xmr_m2_native_settlement_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_m2_native_settlement_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/native/test
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    # V37_XMR_HAVE_MONERO_CRYPTO makes the descriptor point check LIVE, so the
    # payees in the fixture are validated rather than waved through. Link
    # xmr_template EXACTLY ONCE and never define
    # XMR_BLOCK_ASSEMBLY_IMPLEMENT_PRIMITIVES here (that ODR path is KAT-only
    # and belongs to the target that does not link the library).
    target_compile_definitions(v37_xmr_m2_native_settlement_kat PRIVATE V37_XMR_HAVE_MONERO_CRYPTO)
    target_link_libraries(v37_xmr_m2_native_settlement_kat PRIVATE xmr_template xmr_node xmr_coin)
    add_test(NAME v37_xmr_m2_native_settlement_kat COMMAND v37_xmr_m2_native_settlement_kat)

    # ------------------------------------------------------------------
    # R1 -- the on-chain credit cut (armed coinbase shape).
    #
    #   v37_xmr_credit_cut_kat
    #     The consumer-tree KAT xmr_block_assembly.hpp names: static_asserts the
    #     impl-tree parse bound CREDIT_CUT_TAIL_BYTES against credit::kTailBytes,
    #     pins the 44-byte "V37C"|P|spine tail format, and builds the ARMED and
    #     the UNARMED settlement coinbase from ONE fixture (monerod arm over the
    #     captured C4 get_miner_data, no backlog => deterministic bytes): +44
    #     exactly, one-byte 0x02 varint, r/R + 0x03 root + every vout byte-
    #     identical, the cut reads back through the coinbase-authority decoder,
    #     the K_fair shape gate accepts both, the per-extra_nonce patch never
    #     touches the tail -- and the two miner_tx prefixes against a FROZEN
    #     golden (the R1 coinbase-shape golden bump, operator-approved
    #     2026-09-21; regenerate with V37_XMR_CREDIT_CUT_KAT_PRINT=1).
    #     Same link shape + the same HOLLOW-GREEN GUARD as M2 above (listed in
    #     BOTH build.yml --target lists).
    # ------------------------------------------------------------------
    add_executable(v37_xmr_credit_cut_kat
        v37_xmr_credit_cut_kat.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/settle/xmr_coinbase.cpp
        ${CMAKE_SOURCE_DIR}/src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp)
    target_compile_features(v37_xmr_credit_cut_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_credit_cut_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/native/test
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_compile_definitions(v37_xmr_credit_cut_kat PRIVATE V37_XMR_HAVE_MONERO_CRYPTO)
    target_link_libraries(v37_xmr_credit_cut_kat PRIVATE xmr_template xmr_node xmr_coin)
    add_test(NAME v37_xmr_credit_cut_kat COMMAND v37_xmr_credit_cut_kat)

    # v37_xmr_coinbase_extra_kat (MM-PARSE): a valid mainnet coinbase whose
    # tx_extra does not start with 0x01 (block 3765869: 03 merge-mining tag
    # first) parses (any-order field walk, opaque tx_extra kept), the coinbase
    # authority decides it NOT-LANE from the bytes, and FinalizeConnect passes
    # it instead of HOLDING the finalize gate for ever; our own lane coinbase
    # parses byte-identically and still books; a missing body is still HELD.
    # SAME HOLLOW-GREEN GUARD: listed in BOTH build.yml --target lists.
    add_executable(v37_xmr_coinbase_extra_kat
        v37_xmr_coinbase_extra_kat.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/settle/xmr_coinbase.cpp
        ${CMAKE_SOURCE_DIR}/src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp)
    target_compile_features(v37_xmr_coinbase_extra_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_coinbase_extra_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/native/test
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_compile_definitions(v37_xmr_coinbase_extra_kat PRIVATE V37_XMR_HAVE_MONERO_CRYPTO)
    target_link_libraries(v37_xmr_coinbase_extra_kat PRIVATE xmr_template xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_coinbase_extra_kat COMMAND v37_xmr_coinbase_extra_kat)

    # v37_xmr_stranger_mm_tail_kat (MM-PARSE-2): a stranger's coinbase that
    # ends in the same 03 21 00 <root> merge-mining tail as ours (mainnet
    # block 3700900, p2pool shape: 01 R | 02 4-byte nonce | 03 21 00 root) is a
    # DECIDED not-lane block for every caller of the coinbase authority, never
    # lane-root-unknown (retried, HELD, then refused with alarm + liability +
    # a lineage vote); a foreign pool tag stays POOL-LINEAGE's Foreign, our tag
    # with an unknown root still waits, our block still books. Through
    # FinalizeConnect as well. SAME HOLLOW-GREEN GUARD: in BOTH build.yml
    # --target lists.
    add_executable(v37_xmr_stranger_mm_tail_kat
        v37_xmr_stranger_mm_tail_kat.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/settle/xmr_coinbase.cpp
        ${CMAKE_SOURCE_DIR}/src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp)
    target_compile_features(v37_xmr_stranger_mm_tail_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_stranger_mm_tail_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/native/test
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_compile_definitions(v37_xmr_stranger_mm_tail_kat PRIVATE V37_XMR_HAVE_MONERO_CRYPTO)
    target_link_libraries(v37_xmr_stranger_mm_tail_kat PRIVATE xmr_template xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_stranger_mm_tail_kat COMMAND v37_xmr_stranger_mm_tail_kat)

    # ------------------------------------------------------------------
    # POOL-LINEAGE -- the block-level pool id (operator ruling 2026-09-25).
    #
    #   v37_xmr_pool_lineage_kat
    #     pool_tag = sha256d('V37PT' || lane_tag || pool_genesis_id) (formula,
    #     S1 lane_tag input, per-network default genesis, --pool-genesis
    #     parse); the V37C tail's versioned "V37P" field (37 B, before V37C,
    #     V37C/V37D still parse, strict version); classify own -> lane block,
    #     other tag / untagged tail -> ordinary, malformed -> strict reject;
    #     REAL assembled blocks: the coinbase delta vs the untagged shape is
    #     exactly the field, the coinbase-authority decoder books OUR block and
    #     answers "not-lane:" for another pool's and a pre-lineage block (the
    #     ungated decoder reproduces the D-1 cross-pool match); the widest
    #     payload (two-byte 0x02 varint) assembles; the relay HELLO carries the
    #     genesis (+32 B) and refuses another as TAG_MISMATCH field=pool_genesis.
    #     Listed in BOTH build.yml --target lists.
    # ------------------------------------------------------------------
    add_executable(v37_xmr_pool_lineage_kat
        v37_xmr_pool_lineage_kat.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/settle/xmr_coinbase.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt/xmr_receipt_verify.cpp
        ${CMAKE_SOURCE_DIR}/src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp)
    target_compile_features(v37_xmr_pool_lineage_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_pool_lineage_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/native/test
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_compile_definitions(v37_xmr_pool_lineage_kat PRIVATE V37_XMR_HAVE_MONERO_CRYPTO)
    target_link_libraries(v37_xmr_pool_lineage_kat PRIVATE xmr_template xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_pool_lineage_kat COMMAND v37_xmr_pool_lineage_kat)

    # ------------------------------------------------------------------
    # The v36 fee model on the XMR lane (xmr/xmr_fee_model.hpp).
    #
    #   v37_xmr_fee_model_kat
    #     The donation address (CN base58 + keccak checksum) == the pinned
    #     (B, A) constants; give-author as a receipt-carried u16 folded by an
    #     exact two-push weight split (two nodes with different give-author %
    #     fold a shared stream identically -> byte-identical miner_tx); the
    #     node-owner fee as identity substitution at receipt mint; the
    #     MANDATORY 1-piconero donation marker + donation residual sink on real
    #     assembled blocks (C4 capture), exact-sum, and REFUSE-IF-ABSENT on both
    #     the serve property and the receive-side booking. No finder output.
    #     Same link shape + HOLLOW-GREEN GUARD as the credit-cut KAT above
    #     (listed in BOTH build.yml --target lists).
    # ------------------------------------------------------------------
    add_executable(v37_xmr_fee_model_kat
        v37_xmr_fee_model_kat.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/settle/xmr_coinbase.cpp
        ${CMAKE_SOURCE_DIR}/src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp)
    target_compile_features(v37_xmr_fee_model_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_fee_model_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/native/test
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_compile_definitions(v37_xmr_fee_model_kat PRIVATE V37_XMR_HAVE_MONERO_CRYPTO)
    target_link_libraries(v37_xmr_fee_model_kat PRIVATE xmr_template xmr_node xmr_coin)
    add_test(NAME v37_xmr_fee_model_kat COMMAND v37_xmr_fee_model_kat)

    # ------------------------------------------------------------------
    # SAME-BLOCK PAY-NOW (operator ruling 09-25, xmr/xmr_paynow.hpp):
    # a pool block pays the miners whose work it credits out of what the
    # owed pass leaves (<= each one's own E_b), the donation output carries
    # only its marker, and the block is booked NET of that pay-now. The X6
    # split + allocation, the V37N commitment, the net-at-FOUND booking on a
    # real OwedLedger (no negative EffectiveOwed, exact conservation, orphan
    # nets nothing) and the settlement source end-to-end. Same link shape as
    # the fee-model KAT (listed in BOTH build.yml --target lists).
    # ------------------------------------------------------------------
    add_executable(v37_xmr_paynow_kat
        v37_xmr_paynow_kat.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/settle/xmr_coinbase.cpp
        ${CMAKE_SOURCE_DIR}/src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp)
    target_compile_features(v37_xmr_paynow_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_paynow_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_compile_definitions(v37_xmr_paynow_kat PRIVATE V37_XMR_HAVE_MONERO_CRYPTO)
    target_link_libraries(v37_xmr_paynow_kat PRIVATE xmr_template xmr_node xmr_coin)
    add_test(NAME v37_xmr_paynow_kat COMMAND v37_xmr_paynow_kat)

    # ------------------------------------------------------------------
    # SAME-BLOCK PAY-NOW on POOL-LINEAGE: one lane coinbase carries both the
    # V37N pay-now base and the V37P pool tag in the canonical order
    # V37N | V37D | V37P | V37C (V37C last); every field reads back (codec,
    # the settlement source's tail, REAL assembled blocks, the widest
    # 151-byte payload); the pool tag classifies BEFORE any pay-now booking:
    # our block books net of its pay-now, another pool's / an untagged block
    # with a V37N field is ordinary and never netted. Same link shape as the
    # pool-lineage KAT (listed in BOTH build.yml --target lists).
    # ------------------------------------------------------------------
    add_executable(v37_xmr_paynow_lineage_kat
        v37_xmr_paynow_lineage_kat.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/settle/xmr_coinbase.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt/xmr_receipt_verify.cpp
        ${CMAKE_SOURCE_DIR}/src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp)
    target_compile_features(v37_xmr_paynow_lineage_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_paynow_lineage_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/native/test
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_compile_definitions(v37_xmr_paynow_lineage_kat PRIVATE V37_XMR_HAVE_MONERO_CRYPTO)
    target_link_libraries(v37_xmr_paynow_lineage_kat PRIVATE xmr_template xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_paynow_lineage_kat COMMAND v37_xmr_paynow_lineage_kat)

    # ------------------------------------------------------------------
    # GAP-2 stage 1 -- the real c2pool-to-c2pool XMR receipt relay
    # (src/c2pool/v37/xmr/relay/, docs/xmr-lane/gap2-sharechain-relay-design.md).
    #
    #   xmr_relay_wire_kat          FB_HELLO/FB_RECEIPTS/FB_BLOCK_WON goldens,
    #                               total/bounded decoders, namespace pins,
    #                               side_data_v2 / rbind / lane_params_digest
    #                               goldens, base58 address decode.
    #   xmr_receipt_bind_v2_kat     mint -> structural check; every tamper is
    #                               caught before RandomX; the exact PoW rule;
    #                               REAL RandomX grind + verify under
    #                               XMR_BUILD_RANDOMX (skipped otherwise).
    #   v37_xmr_relay_multinode_kat three nodes over loopback TCP: HELLO gate,
    #                               flood + dedup, canonical digests, reconnect
    #                               backfill (GETORDER/GETFRAMES), winner-order
    #                               repair, DoS (unknown opcodes kept, structural
    #                               strike without RandomX, ban on invalid PoW).
    #   v37_xmr_relay_repair_ctx_kat the relay-repair defect: a winner-side
    #                               order holding receipts mined on an ORPHANED
    #                               Monero block the repairing node never saw
    #                               (never Ready pre-fix); FB_GETCTX/FB_CTX
    #                               codec, verify_block_ctx, bounded retries +
    #                               failover, reconnect, recursive resolution,
    #                               a lying context rejected.
    #   v37_xmr_relay_native_ctx_kat RC-CTX: on the P2P-first arm a receipt's
    #                               Monero context resolves from the embedded
    #                               native node (best-chain rows, retained and
    #                               alternative bodies), FB_GETCTX is served
    #                               from native bodies, and issued-template
    #                               contexts survive a restart (journal).
    #   v37_xmr_relay_fd_kat        RELAY-FD: a dropped relay connection
    #                               releases its descriptor (a partition no
    #                               longer leaks one per redial), unwound
    #                               readers are reaped, the accept loop backs
    #                               off on EMFILE and the relay heals after a
    #                               partition_for().
    #   v37_xmr_drops_enrol_repl_kat ENROL-REPL: the carried DROPS delta (below).
    #   v37_xmr_relay_pool_id_kat   POOL-ID: the roundabout S1 lane_tag in
    #                               HELLO; another pool's node (geometry /
    #                               chain_id / consensus version) is refused
    #                               as TAG_MISMATCH in both directions and
    #                               nothing crosses; same pool unchanged.
    #   v37_xmr_relay_noise_kat     SMOKE-NOISE: a dial target whose links end
    #                               before HELLO (refused by a partitioned
    #                               peer / silent peer) backs off instead of
    #                               being redialed + re-timed-out every ~1 s;
    #                               the compared lane-set digest is order-free
    #                               and equal after a partition heal and after
    #                               a durable-log restart (the lane digest is
    #                               node-local order by design).
    # ------------------------------------------------------------------
    foreach(_gap2_kat xmr_relay_wire_kat xmr_receipt_bind_v2_kat v37_xmr_relay_multinode_kat v37_xmr_relay_repair_ctx_kat v37_xmr_relay_native_ctx_kat v37_xmr_relay_fd_kat v37_xmr_relay_pool_id_kat v37_xmr_drops_enrol_repl_kat v37_xmr_relay_noise_kat)
        add_executable(${_gap2_kat}
            ${_gap2_kat}.cpp
            ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt/xmr_receipt_verify.cpp
            ${CMAKE_SOURCE_DIR}/src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp)
        target_compile_features(${_gap2_kat} PRIVATE cxx_std_20)
        target_include_directories(${_gap2_kat} PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt
            ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
            ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
        target_compile_definitions(${_gap2_kat} PRIVATE V37_XMR_HAVE_MONERO_CRYPTO)
        target_link_libraries(${_gap2_kat} PRIVATE xmr_coin Threads::Threads)
        add_test(NAME ${_gap2_kat} COMMAND ${_gap2_kat})
    endforeach()
    # ENROL-REPL (DROPS defect 2): v37_xmr_drops_enrol_repl_kat -- the XMR DROPS
    # enrolment book is node-local, so a lane block books the WINNER's composed
    # delta carried on FB_BLOCK_WON v0x02 (never each node's own-book
    # composition). Two nodes enrolled 8 tips apart book 50 wins through
    # XmrFinalizeDriver with EQUAL owed_digest (RED on the base: each composes
    # its own); the v0x02 codec (flip-0 decoder refuses it; malformed trailers
    # refused); a mismatched / inconsistent carried delta books EMPTY on every
    # node; source pins on the shell / node / relay. ALSO on BOTH build.yml
    # --target lists.
    target_compile_definitions(v37_xmr_drops_enrol_repl_kat PRIVATE
        V37_XMR_SHELL_SRC="${CMAKE_SOURCE_DIR}/src/c2pool/v37/main_v37_xmr.cpp"
        V37_XMR_SRC_DIR="${CMAKE_SOURCE_DIR}/src/c2pool/v37/xmr")
    # ------------------------------------------------------------------
    # SEAM-1 (rbind in the coinbase 0x02 region) + fee-model rulings S3/S4.
    #
    #   v37_xmr_fee_rbind_kat
    #     real assembled templates with a per-job binder: payload =
    #     [extra_nonce | rbind 32 | pad | tail], canonical re-derivation, the
    #     patched Keccak fast path == a full re-hash, no binder => byte-
    #     identical; relay mint -> check_structural(rbind) accepts, every
    #     payee / give-author / cross-job swap refused at Bind; S3 ingest
    #     (different give-author % -> identical lanes, donation == sum of the
    #     receipts' u16, gate OFF = master, durable reload); S4 digest fold
    #     (OFF keeps master's golden, ON refuses at HELLO); Family-A
    #     WorkEvent::donation PoW-committed. Listed in BOTH build.yml
    #     --target lists.
    # ------------------------------------------------------------------
    add_executable(v37_xmr_fee_rbind_kat
        v37_xmr_fee_rbind_kat.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/settle/xmr_coinbase.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt/xmr_receipt_verify.cpp
        ${CMAKE_SOURCE_DIR}/src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp)
    target_compile_features(v37_xmr_fee_rbind_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_fee_rbind_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_compile_definitions(v37_xmr_fee_rbind_kat PRIVATE V37_XMR_HAVE_MONERO_CRYPTO)
    target_link_libraries(v37_xmr_fee_rbind_kat PRIVATE xmr_template xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_fee_rbind_kat COMMAND v37_xmr_fee_rbind_kat)

    # ------------------------------------------------------------------
    # DON-NET: one fee-model donation identity per Monero network.
    #
    #   v37_xmr_fee_network_kat
    #     per network (mainnet / testnet / stagenet / regtest) the donation
    #     address decodes to its pinned keys and network byte, the four
    #     identities are distinct and mainnet is unchanged; the HELLO
    #     lane_params_digest is network-independent with the gate OFF, the
    #     mainnet gate-ON digest is unchanged and a node folding another
    #     network's identity is refused at HELLO; give-author pushes and the
    #     one donation output use this network's identity and are refused
    #     against another's. Listed in BOTH build.yml --target lists.
    # ------------------------------------------------------------------
    add_executable(v37_xmr_fee_network_kat
        v37_xmr_fee_network_kat.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/settle/xmr_coinbase.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt/xmr_receipt_verify.cpp
        ${CMAKE_SOURCE_DIR}/src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp)
    target_compile_features(v37_xmr_fee_network_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_fee_network_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/receipt
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_compile_definitions(v37_xmr_fee_network_kat PRIVATE V37_XMR_HAVE_MONERO_CRYPTO)
    target_link_libraries(v37_xmr_fee_network_kat PRIVATE xmr_template xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_fee_network_kat COMMAND v37_xmr_fee_network_kat)

    if (XMR_BUILD_RANDOMX AND TARGET randomx)
        target_link_libraries(xmr_receipt_bind_v2_kat PRIVATE randomx)
        target_include_directories(xmr_receipt_bind_v2_kat PRIVATE ${CMAKE_SOURCE_DIR}/src/impl/xmr/third_party/randomx)
        target_compile_definitions(xmr_receipt_bind_v2_kat PRIVATE GAP2_WITH_RANDOMX)
    endif()

    # ------------------------------------------------------------------
    # M3 — R-ARMORDER, the switchable FIND path.
    #
    #   v37_xmr_m3_arm_order_kat
    #     Pins BOTH positions of the switch against one counting monerod
    #     transport. daemon-first must still build the X2 adapter and TOUCH the
    #     daemon (a zero there would be the default path having broken, not M3
    #     having worked); p2p-first must build no adapter and make EXACTLY ZERO
    #     touches across bring-up and a complete FOUND -> SETTLED driven by a
    #     pumped native chain. It also pins the fail-closed rules: the arm-order
    #     preconditions as a pure function, bring_up refusing p2p-first with no
    #     canonical test installed, and the levin publisher refusing to push a
    #     FOUND event for a block that reached no peer.
    #
    #     No sockets, no RandomX, no live daemon -- it links xmr_node for the
    #     node + X2 adapter and xmr_coin for the keccak and block parsing C5
    #     needs, and injects a test point-check rather than the ref10 registrar.
    #
    #     SAME HOLLOW-GREEN GUARD as its siblings: ALSO listed in BOTH build.yml
    #     `--target` lists (the Linux x86_64 leg and the ASan+UBSan leg), because
    #     a registered-but-unbuilt target reports "***Not Run" and fails ctest
    #     with exit 8 -- a red that is not a test failure (the #1539 lesson).
    # ------------------------------------------------------------------
    add_executable(v37_xmr_m3_arm_order_kat v37_xmr_m3_arm_order_kat.cpp)
    target_compile_features(v37_xmr_m3_arm_order_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_m3_arm_order_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/native/test
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_link_libraries(v37_xmr_m3_arm_order_kat PRIVATE xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_m3_arm_order_kat COMMAND v37_xmr_m3_arm_order_kat)

    # ------------------------------------------------------------------
    # --native-solo -- the FULLY self-contained (peerless, daemonless) find.
    #
    #   v37_xmr_daemonless_selfmine_kat
    #     M3 removed the daemon from the find path but not the NETWORK: the
    #     genesis blob was asked for over levin, and a found block was booked
    #     only once a peer had received it. This pins the two seams that remove
    #     the last peer -- the locally assembled genesis blob (checked by the
    #     SAME id gate the wire path uses, against monerod's own captured bytes)
    #     and the publisher's opt-in own-index booking -- together with every
    #     place they must still refuse: a flipped nonce byte, a foreign genesis,
    #     an index that said no, a disabled RandomX gate, and solo on any
    #     network but regtest.
    #
    #     The load-bearing NEGATIVE is that solo OFF is unchanged: zero peers
    #     still books nothing, whatever our own index did. Without that case,
    #     turning solo on would be indistinguishable from removing the gate.
    #
    #     No sockets, no daemon, no RandomX, no threads.
    #
    #     SAME HOLLOW-GREEN GUARD as its siblings: ALSO listed in BOTH build.yml
    #     `--target` lists (the Linux x86_64 leg and the ASan+UBSan leg), because
    #     a registered-but-unbuilt target reports "***Not Run" and fails ctest
    #     with exit 8 -- a red that is not a test failure (the #1539 lesson).
    # ------------------------------------------------------------------
    add_executable(v37_xmr_daemonless_selfmine_kat v37_xmr_daemonless_selfmine_kat.cpp)
    target_compile_features(v37_xmr_daemonless_selfmine_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_daemonless_selfmine_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/native/test
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_link_libraries(v37_xmr_daemonless_selfmine_kat PRIVATE xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_daemonless_selfmine_kat COMMAND v37_xmr_daemonless_selfmine_kat)

    # ------------------------------------------------------------------
    # The daemonless publish arm when the first push reaches NOBODY.
    #
    #   v37_xmr_p2p_publish_retry_kat
    #     A found block whose 2008 reached no peer used to be counted and
    #     dropped. It is now parked and re-announced on a bounded backoff from
    #     the relay's retained book: the first re-announce that reaches a peer
    #     pushes THE FoundBlockEvent (exactly once), a block our own best chain
    #     no longer carries is dropped without another frame, and one that runs
    #     out of attempts or window is ABANDONED at ERROR -- never booked. Solo,
    #     refused blocks and first-time deliveries are pinned unchanged.
    #
    #     Injected clock; no sockets, no daemon, no RandomX, no threads.
    #
    #     SAME HOLLOW-GREEN GUARD: ALSO listed in BOTH build.yml `--target`
    #     lists (Linux x86_64 and ASan+UBSan), or ctest reports "***Not Run".
    # ------------------------------------------------------------------
    add_executable(v37_xmr_p2p_publish_retry_kat v37_xmr_p2p_publish_retry_kat.cpp)
    target_compile_features(v37_xmr_p2p_publish_retry_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_p2p_publish_retry_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/native/test
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_link_libraries(v37_xmr_p2p_publish_retry_kat PRIVATE xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_p2p_publish_retry_kat COMMAND v37_xmr_p2p_publish_retry_kat)

    # ------------------------------------------------------------------
    # c2pool#1551 -- the SAME-HEIGHT double-block refusal, decided prefer-own
    # within bounds.
    #
    #   v37_xmr_prefer_own_race_kat
    #     Pins the credit table for a height carrying two blocks, one of them
    #     ours: unburied refuses everybody, buried credits ours ONLY if the
    #     chain kept it, an orphan of ours credits NOTHING, a stranger's block
    #     credits NOTHING, and a height credits at most once (R-7).
    #
    #     The property that makes the bound real is run, not asserted in prose:
    #     the same fixture is decided under BOTH tie-break policies and the
    #     verdicts must be identical while the nominations differ -- so
    #     prefer-own demonstrably moves the lever and cannot reach the ledger.
    #
    #     Suites E and F drive the REAL XmrNode + FinalizeConnect over a pumped
    #     native chain: E is one node winning, losing and sitting out a fork; F
    #     is two nodes racing each other at one height, where the winner credits
    #     once, the loser fabricates nothing, and the fleet-wide credited set has
    #     exactly one entry. No sockets, no RandomX, no daemon.
    #
    #     SAME HOLLOW-GREEN GUARD as its siblings: ALSO listed in BOTH build.yml
    #     `--target` lists (the Linux x86_64 leg and the ASan+UBSan leg), because
    #     a registered-but-unbuilt target reports "***Not Run" and fails ctest
    #     with exit 8 -- a red that is not a test failure (the #1539 lesson).
    # ------------------------------------------------------------------
    add_executable(v37_xmr_prefer_own_race_kat v37_xmr_prefer_own_race_kat.cpp)
    target_compile_features(v37_xmr_prefer_own_race_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_prefer_own_race_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_link_libraries(v37_xmr_prefer_own_race_kat PRIVATE xmr_node xmr_coin Threads::Threads)
    add_test(NAME v37_xmr_prefer_own_race_kat COMMAND v37_xmr_prefer_own_race_kat)

    # ------------------------------------------------------------------
    # MAINNET READINESS -- the pool binary's own native-node plumbing.
    #
    #   v37_xmr_mainnet_readiness_kat
    #     Three knobs the embedded node has always had were unreachable from
    #     c2pool-v37-xmr, each in the same way: the node field existed, the
    #     standalone xmr_native_node tool exposed it, and the pool binary's argv
    #     loop had no arm for it -- so the flag was not a flag and the default
    #     happened instead. This KAT pins the PARSE and the FORWARD as the one
    #     code path the daemon actually runs on:
    #
    #       A  apply_native_node_flag(): the three gate 4 window flags,
    #          --native-seeds/--seeds and the snapshot pair parse; absent flags
    #          leave the node's own defaults; a malformed one (no value, not a
    #          number, or a zero that would disarm gate 4) REFUSES.
    #       B  native_template_config_of(): every parsed knob arrives in
    #          NativeTemplateConfig, the defaults are equal to
    #          AnchorConfirmConfig's own so the two sets cannot drift, and NO
    #          configuration -- including a hand-zeroed one built in code --
    #          forwards a confirm config that is not sane().
    #       C  the mainnet seed sets: four DNS seed hosts on 18080 (monerod
    #          guards them with `if MAINNET`, and so do we), the two test
    #          networks correctly with none, and --seeds accepted as an address
    #          source for the p2p-first precondition.
    #       D  the snapshot's DISK half (node/xmr_chain_snapshot_store.hpp):
    #          save -> envelope -> temp+rename write -> read -> decode -> load
    #          round-trips an index to the same tip, frontier and template
    #          inputs, and every corruption -- short, tampered, truncated,
    #          foreign network, foreign anchor, wrong magic, wrong version,
    #          lying length -- is REFUSED so the node stays on its anchor boot.
    #       E  gate 4 is STILL fail-closed through that config: a tampered
    #          anchor id cannot be confirmed by the genuine block, the forwarded
    #          peer bound is the bound that is enforced, and the deadline
    #          refuses. There is no flag that turns the gate off.
    #
    #     The index codec itself is xmr_native_chain_index_kat's and gate 4's
    #     blob-level judgement is xmr_native_anchor_gate4_kat's; this file is
    #     about the wiring between them and the pool binary. No sockets, no
    #     daemon, no RandomX.
    #
    #     SAME HOLLOW-GREEN GUARD as its siblings: ALSO listed in BOTH build.yml
    #     `--target` lists (the Linux x86_64 leg and the ASan+UBSan leg), because
    #     a registered-but-unbuilt target reports "***Not Run" and fails ctest
    #     with exit 8 -- a red that is not a test failure (the #1539 lesson).
    # ------------------------------------------------------------------
    add_executable(v37_xmr_mainnet_readiness_kat v37_xmr_mainnet_readiness_kat.cpp)
    target_compile_features(v37_xmr_mainnet_readiness_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_mainnet_readiness_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_link_libraries(v37_xmr_mainnet_readiness_kat PRIVATE xmr_node xmr_coin Threads::Threads)
    if (TARGET Boost::headers)
        target_link_libraries(v37_xmr_mainnet_readiness_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(v37_xmr_mainnet_readiness_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(v37_xmr_mainnet_readiness_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    add_test(NAME v37_xmr_mainnet_readiness_kat COMMAND v37_xmr_mainnet_readiness_kat)

    # PINNED SNAPSHOT -- v37_xmr_pinned_snapshot_kat
    #   The release's bootstrap is a PINNED snapshot (operator ruling 09-24):
    #   the compiled-in format-2 anchors (stagenet H_a 2213803, mainnet H_a
    #   3765865) and the output-set snapshots they commit to, both pinned by
    #   sha256 in anchor/xmr_anchor_pinned.hpp and listed in
    #   docs/xmr-lane/PINNED-SNAPSHOTS.md. Pins: both bundles load from the
    #   binary with the documented height/id/roots and hash (file and
    #   compiled-in bytes) to the documented sha256; the doc lists every value;
    #   an output set with no --native-anchor selects the pinned anchor; a
    #   truncated or byte-flipped snapshot refuses naming the expected sha256
    #   and height. Reads the repo (C2POOL_SOURCE_DIR); no sockets, no daemon.
    #   Listed in both build.yml --target lists.
    add_executable(v37_xmr_pinned_snapshot_kat v37_xmr_pinned_snapshot_kat.cpp)
    target_compile_features(v37_xmr_pinned_snapshot_kat PRIVATE cxx_std_20)
    target_compile_definitions(v37_xmr_pinned_snapshot_kat PRIVATE
        C2POOL_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
    target_include_directories(v37_xmr_pinned_snapshot_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_link_libraries(v37_xmr_pinned_snapshot_kat PRIVATE xmr_node xmr_coin Threads::Threads)
    if (TARGET Boost::headers)
        target_link_libraries(v37_xmr_pinned_snapshot_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(v37_xmr_pinned_snapshot_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(v37_xmr_pinned_snapshot_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    add_test(NAME v37_xmr_pinned_snapshot_kat COMMAND v37_xmr_pinned_snapshot_kat)

    # CLI-STRICT -- v37_xmr_cli_strict_kat
    #   c2pool-v37-xmr used to IGNORE an unknown flag and fill a missing value
    #   from a default, so `--version` (no such flag then) or any typo started a
    #   live node on defaults. Runs the BUILT daemon (its path is the argument)
    #   with a scratch HOME/cwd: every bad invocation (unknown flag, typo,
    #   positional, missing value, malformed number/enum) exits 2 with one line
    #   naming it and pointing at --help and creates nothing; --version/-V exit
    #   0 in < 1 s with the version and both pinned snapshot heights; every
    #   accepted flag (the parse loop, apply_native_node_flag, the repo rig/doc
    #   invocations) still parses. Every row that a broken build could turn into
    #   a live run is pinned to regtest on 127.0.0.1 port 1; no real network.
    #   Listed in both build.yml --target lists.
    if (TARGET c2pool-v37-xmr)
        add_executable(v37_xmr_cli_strict_kat v37_xmr_cli_strict_kat.cpp)
        target_compile_features(v37_xmr_cli_strict_kat PRIVATE cxx_std_20)
        target_include_directories(v37_xmr_cli_strict_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
        add_dependencies(v37_xmr_cli_strict_kat c2pool-v37-xmr)
        add_test(NAME v37_xmr_cli_strict_kat
                 COMMAND v37_xmr_cli_strict_kat $<TARGET_FILE:c2pool-v37-xmr>)
    endif()

    # D6d -- v37_xmr_d6d_native_seed_tip_kat
    #   Under --arm-order p2p-first the embedded native node is the tip, the
    #   RandomX seed (hash + height, 2048-block epochs, 64-block lag) and the
    #   difficulty/height source, so it is handed NO monerod endpoint unless
    #   --native-parity-monerod opts the C6 parity judge back in as a
    #   compare-only oracle. Pins the forward (native_template_config_of), the
    #   wire (a started NativeTemplateBackend driven through the status cadence
    #   against a counting fake monerod: p2p-first = 0 requests; daemon-first and
    #   the explicit judge = the get_miner_data/get_info/get_last_block_header
    #   trio every tick) and the seed-epoch arithmetic the index keys on. No
    #   hashing, no real daemon, no peers; listed in both build.yml --target lists.
    add_executable(v37_xmr_d6d_native_seed_tip_kat v37_xmr_d6d_native_seed_tip_kat.cpp)
    target_compile_features(v37_xmr_d6d_native_seed_tip_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_d6d_native_seed_tip_kat PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/vendor
        ${CMAKE_SOURCE_DIR}/src/impl/xmr/coin/compat)
    target_link_libraries(v37_xmr_d6d_native_seed_tip_kat PRIVATE xmr_node xmr_native_txpool xmr_coin Threads::Threads)
    if (TARGET Boost::headers)
        target_link_libraries(v37_xmr_d6d_native_seed_tip_kat PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(v37_xmr_d6d_native_seed_tip_kat PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(v37_xmr_d6d_native_seed_tip_kat PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    add_test(NAME v37_xmr_d6d_native_seed_tip_kat COMMAND v37_xmr_d6d_native_seed_tip_kat)

    # Track A2 CONSUMER half — multi-node carrier accounting over a REAL socket.
    # Proves the gap the Phase-B single-node daemon had: node B accounts node A's
    # shares. Wires the SAME production consumer code the daemon does — the W3
    # CarrierRelay on the carrier_net.hpp socket transport, admitted through
    # carrier_ingest.hpp into a live V37Engine — across two nodes on loopback TCP,
    # and asserts a carrier mined on A appears as accounted weight in B's OWN
    # engine snapshot (plus duplex reception + relay-dedup no-double-count). POSIX
    # sockets + Threads (no Boost). SAME HOLLOW-GREEN GUARD as the sibling suites:
    # ALSO listed in the build.yml --target lists (BOTH the Linux x86_64 leg and
    # the ASan+UBSan leg) so CI compiles + runs it, not just registers a NOT_BUILT
    # CTest sentinel, and audited by the src/c2pool/**/test/ drift-guard.
    add_executable(v37_a2_multinode_test v37_a2_multinode_test.cpp)
    target_compile_features(v37_a2_multinode_test PRIVATE cxx_std_20)
    target_include_directories(v37_a2_multinode_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_a2_multinode_test Threads::Threads)
    add_test(NAME v37_a2_multinode_test COMMAND v37_a2_multinode_test)

    # Track A2 / W3-B5 — carrier-wire BYTE FREEZE golden KAT. Pins the frozen
    # CarrierWire v0x01 layout (golden bytes for a fixed carrier) so the send-side
    # can rely on the wire being byte-identical across nodes and builds. stdlib
    # only, no threads. SAME HOLLOW-GREEN GUARD as the sibling suites: ALSO on the
    # build.yml --target lists (both the Linux leg and the ASan+UBSan leg) so CI
    # compiles + runs it, and audited by the src/c2pool/**/test/ drift-guard.
    add_executable(v37_w3_wire_freeze_kat v37_w3_wire_freeze_kat.cpp)
    target_compile_features(v37_w3_wire_freeze_kat PRIVATE cxx_std_20)
    target_include_directories(v37_w3_wire_freeze_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    add_test(NAME v37_w3_wire_freeze_kat COMMAND v37_w3_wire_freeze_kat)

    # Track A2 step (b)(2) — the LIVE IMainchainIndex (carrier_index.hpp) KAT: horizon
    # vs tip (I-1), bounded tri-state Unknown retry (I-2), per-hash Have cache (I-3),
    # the synthetic model's byte-for-byte parity with the multinode-test resolver,
    # the backend-binding templates against a DashRpcCoinBackend-shaped fake (D6
    # display-order probe asserted), and an end-to-end W2 ReceiptAdmitter::admit over
    # the live index. stdlib + Threads (it sleeps; no sockets, no Boost). SAME
    # HOLLOW-GREEN GUARD as the sibling suites: ALSO on the build.yml --target lists
    # (both the Linux leg and the ASan+UBSan leg) so CI compiles + runs it, and
    # audited by the src/c2pool/**/test/ drift-guard.
    add_executable(v37_a2_live_index_test v37_a2_live_index_test.cpp)
    target_compile_features(v37_a2_live_index_test PRIVATE cxx_std_20)
    target_include_directories(v37_a2_live_index_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_a2_live_index_test Threads::Threads)
    add_test(NAME v37_a2_live_index_test COMMAND v37_a2_live_index_test)

    # Track A2 step (b)(3) — SEND-SIDE: own stratum wins (share-level, per-miner
    # identity) queued off the hot path and flooded as frozen carriers; node B
    # accounts them under the miner's identity. POSIX sockets + Threads. SAME
    # HOLLOW-GREEN GUARD as the siblings: ALSO on BOTH build.yml --target lists.
    add_executable(v37_a2_sendside_test v37_a2_sendside_test.cpp)
    target_compile_features(v37_a2_sendside_test PRIVATE cxx_std_20)
    target_include_directories(v37_a2_sendside_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_a2_sendside_test Threads::Threads)
    add_test(NAME v37_a2_sendside_test COMMAND v37_a2_sendside_test)

    # Track A2 / W4 — R3 incremental OWED-ledger acceleration: DIGEST-NEUTRALITY
    # oracle KAT (src/c2pool/v37/w4_owed_incremental.hpp). Drives OwedLedger via
    # its public API and compares owed_digest / effective_owed / propose_coinbase
    # byte-for-byte against an independent shadow of the pre-R3 algorithm across a
    # long random FOUND/FINALIZE/ORPHAN schedule + adversarial zero-prune / found→
    # orphan round-trip. Stdlib + Threads (w4 pulls in v37_engine). SAME HOLLOW-
    # GREEN GUARD as the sibling suites: ALSO listed on BOTH build.yml --target
    # lists so CI compiles + runs it, not a NOT_BUILT CTest sentinel.
    add_executable(v37_w4_owed_incremental_test v37_w4_owed_incremental_test.cpp)
    target_compile_features(v37_w4_owed_incremental_test PRIVATE cxx_std_20)
    target_include_directories(v37_w4_owed_incremental_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_w4_owed_incremental_test Threads::Threads)
    add_test(NAME v37_w4_owed_incremental_test COMMAND v37_w4_owed_incremental_test)

    # Track A2 / S-1 — LIVE FOLD-WIRING KAT (btc/btc_node.hpp on_block_won ->
    # settle::fold_eb -> FoundBlock -> the F1 driver -> owed_digest). Pins that
    # the live DRIVER path, on a FIXED event stream, moves owed_digest OFF the
    # empty sha256d("V37O") anchor b4db1ded…; that two independent stacks fed
    # that stream CONVERGE on the same digest; that credit and payout stay
    # DISTINCT maps; and — the regression pin — that the pre-S-1 "assembly as
    # credit" shape reproduces the anchor. Also pins that both refuse-LOUD paths
    # (reward == 0, non-ratified geometry) still REGISTER the block. Stdlib +
    # Threads (the engine's executor thread), MockCoinBackend + MemSettleStore:
    # no coin lib, no sockets, no clocks. SAME HOLLOW-GREEN GUARD as the sibling
    # suites: ALSO listed on BOTH build.yml --target lists (the Linux x86_64 leg
    # and the ASan+UBSan leg) so CI compiles + RUNS it instead of registering a
    # NOT_BUILT CTest sentinel (the DGB #137 / #769 / c2pool#1539 unregistered-
    # KAT class), and audited by the src/c2pool/**/test/ drift-guard.
    add_executable(v37_s1_live_wiring_kat v37_s1_live_wiring_kat.cpp)
    target_compile_features(v37_s1_live_wiring_kat PRIVATE cxx_std_20)
    target_include_directories(v37_s1_live_wiring_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_s1_live_wiring_kat Threads::Threads)
    add_test(NAME v37_s1_live_wiring_kat COMMAND v37_s1_live_wiring_kat)

    # Track A2 / S-1c — CROSS-NODE owed_digest CONVERGENCE KAT. S-1 made the
    # node that MINED a block credit E_b; its PEERS still knew nothing about the
    # block, so two nodes on the byte-identical carrier stream committed to
    # DIFFERENT owed ledgers (A non-empty, B at the b4db1ded... anchor) — a
    # settlement fork. This pins the fix: the winner names its fold in the wire
    # v0x02 flat cut descriptor (w3_relay.hpp CutDescriptor), the receiver
    # re-runs settle::fold_eb at THAT prefix through XbtcNode::on_peer_block_won
    # and drives the EXISTING on_block_found/on_block_finalized API, and both
    # nodes FINALIZE at the same bin_height on the same owed_digest. Also pins
    # the defect itself (case 3: no descriptor -> A != B), the CUT RULE being
    # load-bearing (fold(P) != fold(P+1)), every fail-closed refusal, the
    # double-drive guard, and the v0x02 wire bytes. Stdlib + Threads (the
    # engine's executor thread), MockCoinBackend + MemSettleStore: no coin lib,
    # no sockets, no clocks. SAME HOLLOW-GREEN GUARD as the sibling suites: ALSO
    # listed on BOTH build.yml --target lists (the Linux x86_64 leg and the
    # ASan+UBSan leg) so CI compiles + RUNS it instead of registering a NOT_BUILT
    # CTest sentinel (the DGB #137 / #769 / c2pool#1539 unregistered-KAT class),
    # and audited by the src/c2pool/**/test/ drift-guard.
    add_executable(v37_s1c_convergence_kat v37_s1c_convergence_kat.cpp)
    target_compile_features(v37_s1c_convergence_kat PRIVATE cxx_std_20)
    target_include_directories(v37_s1c_convergence_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_s1c_convergence_kat Threads::Threads)
    add_test(NAME v37_s1c_convergence_kat COMMAND v37_s1c_convergence_kat)

    # STEP-0 hotfix -- k_floor is a LaneParam (src/sharechain/v37/v37_lane.hpp
    # LaneParams::k_floor). The W5 no-dust floor decides the canonical coinbase,
    # so it is consensus: it used to be a node-code literal in btc_node.hpp (a
    # silent owed_digest fork vector). The KAT pins: the constants (f_ref = 10,
    # neutral 0), the digest-neutral-at-zero lane digest against the PRE-hotfix
    # golden, the KFL1 commitment in the lane digest and the roundabout lane
    # tag, the explicit S-1c refusal (cut_digest_mismatch) of a peer on another
    # floor, identical coinbases on the same floor, and the floor being
    # load-bearing over one ledger. Stdlib + Threads, MockCoinBackend +
    # MemSettleStore. ALSO on BOTH build.yml --target lists (hollow-green rule).
    add_executable(v37_kfloor_laneparam_kat v37_kfloor_laneparam_kat.cpp)
    target_compile_features(v37_kfloor_laneparam_kat PRIVATE cxx_std_20)
    target_include_directories(v37_kfloor_laneparam_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_kfloor_laneparam_kat Threads::Threads)
    add_test(NAME v37_kfloor_laneparam_kat COMMAND v37_kfloor_laneparam_kat)

    # Track A2 / W4-W6 — the OWED-EVENT MMR: an append-only authenticated record
    # log (src/c2pool/v37/record_log.hpp, instanced by owed_event_log.hpp) built
    # on the SHIPPED ::v37::Lane MMR statics, maintained inside OwedLedger, made
    # durable by w6, and committed into the w5 StateCommitment tree only behind a
    # gate that is OFF by default. The KAT pins, in one binary: the mirrored leaf
    # rule against a hand-built digest and against w5's own mirror; the
    # primitive's inclusion + prefix proofs (verified by ::v37::Lane::mmr_verify)
    # and its fail-closed codec; the record-log goldens over a fixed schedule and
    # the leaf_count == ledger_seq invariant; convergence by construction (two
    # independent ledgers, same events, identical root) with a non-vacuous
    # negative control; a journal + recovery round-trip including a corrupted and
    # an absent head; and the gate itself — gate OFF reproduces goldens minted on
    # PRISTINE MASTER byte-for-byte, gate ON produces the pinned new root. It
    # passes in BOTH build modes (with and without -DV37_OWED_EVENT_MMR_COMMIT=1).
    # Stdlib + Threads (w4 pulls in v37_engine). SAME HOLLOW-GREEN GUARD as the
    # sibling suites: ALSO listed on BOTH build.yml --target lists so CI compiles
    # + runs it, not a NOT_BUILT CTest sentinel.
    # Track A2 CONSUMER-tree relay ROBUSTNESS — the bounded carrier RE-OFFER
    # (a carrier that reached no peer is re-offered when a peer (re)connects, and
    # is admitted EXACTLY ONCE because W2's dedup window refuses the duplicate:
    # REJECT_DEDUP, zero pushes, next_pos / raw_total / lane digest / owed_digest
    # byte-identical) and the PER-DESCRIPTOR write lock in carrier_net.hpp (a peer
    # that stopped reading no longer stalls the send to every other peer, and
    # concurrent writers never interleave a frame on one connection). Both halves
    # are DELIVERY-side: no PoW, no descriptor, no lane order, no digest, and no
    # wire-version change. It also pins the horizon bound that keeps a re-offer
    # inside the W2 dedup window — the only way a re-offer could ever become a
    # second credit. stdlib + POSIX sockets + Threads. SAME HOLLOW-GREEN GUARD as
    # the sibling suites: ALSO listed on BOTH build.yml --target lists (the Linux
    # x86_64 leg and the ASan+UBSan leg) so CI compiles + RUNS it instead of
    # registering a NOT_BUILT CTest sentinel (the DGB #137 / #769 / c2pool#1539
    # unregistered-KAT class), and audited by the src/c2pool/**/test/ drift-guard.
    add_executable(v37_carrier_relay_robustness_kat v37_carrier_relay_robustness_kat.cpp)
    target_compile_features(v37_carrier_relay_robustness_kat PRIVATE cxx_std_20)
    target_include_directories(v37_carrier_relay_robustness_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_carrier_relay_robustness_kat Threads::Threads)
    add_test(NAME v37_carrier_relay_robustness_kat COMMAND v37_carrier_relay_robustness_kat)

    # Track A2 / STAGE 1 SUPPLY - the unified bounded FrameVault (ONE store of
    # verbatim carrier frames, indexed by lane POSITION and by carrier hash,
    # retained to the lane WINDOW horizon, with the c2pool#1655 re-offer riding
    # it as a shallow recent sub-view) plus the >= 0x80 CONTROL OPCODE channel
    # (GETORDER-at-cut / ORDER / GETFRAMES / FRAMES) demuxed in carrier_net.hpp
    # BEFORE handle_inbound. It pins: the (chain, pos) -> carrier-hash index that
    # exists nowhere else in the tree; a serve -> fetch -> verify round-trip over
    # real sockets returning the exact ordered ids and the exact bytes; a LYING
    # peer (right id, wrong bytes) fail-closed on the recomputed hash; a MISSING
    # id fail-closed; a silent peer bounded by request_timeout; the vault entry /
    # byte / window-horizon caps and the per-peer token bucket; a flapping peer
    # that cannot evict another peer's retained bytes; and backward tolerance in
    # BOTH directions - an OLD peer (the verbatim pre-Stage-1 reader loop,
    # reproduced over a raw socket) meets an opcode, answers REJECT_BAD_VERSION,
    # KEEPS the socket and admits the very next carrier. It also proves ZERO
    # consensus movement: the opcodes are absent from kAcceptedVersions, the
    # frozen v0x01 / v0x02 encodings are byte-identical, and a full round-trip
    # moves neither lane digest nor owed_digest. SUPPLY ONLY - nothing here
    # admits a fetched frame or folds (that is Stage 2). stdlib + POSIX sockets
    # + Threads. SAME HOLLOW-GREEN GUARD as the sibling suites: ALSO listed on
    # BOTH build.yml --target lists (the Linux x86_64 leg and the ASan+UBSan leg)
    # so CI compiles + RUNS it instead of registering a NOT_BUILT CTest sentinel
    # (the DGB #137 / #769 / c2pool#1539 unregistered-KAT class), and audited by
    # the src/c2pool/**/test/ drift-guard.
    add_executable(v37_convergence_supply_kat v37_convergence_supply_kat.cpp)
    target_compile_features(v37_convergence_supply_kat PRIVATE cxx_std_20)
    target_include_directories(v37_convergence_supply_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_convergence_supply_kat Threads::Threads)
    add_test(NAME v37_convergence_supply_kat COMMAND v37_convergence_supply_kat)

    # ── Track A2 / Stage 2 APPLY: the repair at the cut-miss arm ────────────
    # v37_convergence_apply_kat stands up TWO in-process nodes on a real socket
    # transport, drops ONE of the winner's shares on the second node, and proves
    # (a) the pre-Stage-2 DEFECT (cut_miss -> REFUSED -> owed(A) != owed(B)),
    # (b) that a REPLAY of the winner's own ordered records, fetched over the
    #     Stage-1 supply channel and gated on the winner's own cut_spine_digest,
    #     lets the S3 re-drive fold E_b at that exact prefix so the two
    #     owed_digests become BYTE-EQUAL across the settling block, and
    # (c) that a repair which cannot verify still REFUSES and moves owed by zero,
    #     and (d, CA-9) that a SECOND distinct refused win armed while a repair is
    #     in flight against the ONE peer that can serve it neither orphans nor
    #     zombies that repair: the live job keeps its peer binding, the second cut
    #     is QUEUED and re-armed when the peer falls free, and BOTH blocks credit.
    # Consumer tree only: settle::fold_eb and OwedLedger::owed_digest() are
    # untouched and no frozen wire golden moves. stdlib + POSIX sockets +
    # Threads. SAME HOLLOW-GREEN GUARD as its siblings: ALSO listed on BOTH
    # build.yml --target lists so CI compiles AND runs it.
    add_executable(v37_convergence_apply_kat v37_convergence_apply_kat.cpp)
    target_compile_features(v37_convergence_apply_kat PRIVATE cxx_std_20)
    target_include_directories(v37_convergence_apply_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_convergence_apply_kat Threads::Threads)
    add_test(NAME v37_convergence_apply_kat COMMAND v37_convergence_apply_kat)

    # ── Track A2 / the SUSTAINED-LOAD SOAK over the merged closer ───────
    # v37_convergence_soak drives the SAME rig the apply KAT assembles — one
    # XbtcNode + BlockEventDriver + CarrierIngest + CarrierRelay + FrameVault +
    # SupplyService/SupplyRequester + RepairDriver per node — but under a long
    # RANDOMISED multi-miner schedule instead of eleven fixed scenarios: shares
    # dropped and reordered per node, peers flapping, block win after block win,
    # for thousands of settling blocks. It asserts CONTINUOUSLY that
    #   (SK-A) no peer win is ever folded at a prefix that is not the winner's
    #          and a refused win moves owed_digest by zero bytes,
    #   (SK-B) any two nodes holding the same settled-block set hold the same
    #          owed_digest BYTE-EQUAL,
    #   (SK-C) no RepairDriver job, peer binding or queued cut survives a
    #          quiescence checkpoint (no zombie),
    #   (SK-D) the frame vault stays inside its caps and the deferred / held
    #          queues stay inside theirs,
    #   (SK-E) no block is ever credited twice (sum finalW == sum registered
    #          credit over the blocks the node settled),
    # and — since the H-1..H-4 gate fixes — it is a GATE, not only a measurement:
    #   (SK-3a..d) on a LOSSY schedule the run must produce real cut-misses, a
    #          repair must actually credit blocks that were refused on the first
    #          pass, at least SOAK_MIN_REPAIR_PCT% (default 90) of the pairs some
    #          candidate could have served WHOLE must be repaired, and the
    #          candidate walk must be exercised. Stub RepairDriver::arm out and
    #          this FAILS; the first cut of the soak stayed green. On a LOSSLESS
    #          schedule the complementary property is asserted instead (every
    #          peer win credited on the first pass), so a clean run cannot
    #          false-fail it.
    #   (SK-A1) never a SUFFIX repair: every credit a replay produced had a
    #          candidate holding the winner's cut that still retained position 0.
    #   (SK-7)  the owed_digest byte comparison is FATAL by default, and SK-7a
    #          fails a run in which it was never sampled at all.
    # It also MEASURES the liveness envelope — the largest lane prefix at which a
    # repair completed, and the VIRTUAL seconds of serve budget the largest one
    # consumed. The CTest registration below pins a SHORT deterministic
    # budget so CI stays fast; the same binary is the long soak with bigger
    # SOAK_ROUNDS / SOAK_SECONDS (see the banner in the .cpp for every knob).
    # Consumer tree only: no file under src/sharechain/v37 is touched,
    # settle::fold_eb and OwedLedger::owed_digest() are read and never changed,
    # and every option it sets (SupplyServeOptions, FrameVaultOptions) is one
    # the daemon already exposes. stdlib + Threads. SAME HOLLOW-GREEN GUARD as
    # its siblings: ALSO listed on BOTH build.yml --target lists so CI compiles
    # AND runs it instead of registering a NOT_BUILT CTest sentinel.
    add_executable(v37_convergence_soak v37_convergence_soak.cpp)
    target_compile_features(v37_convergence_soak PRIVATE cxx_std_20)
    target_include_directories(v37_convergence_soak PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_convergence_soak Threads::Threads)
    add_test(NAME v37_convergence_soak COMMAND v37_convergence_soak)
    set_tests_properties(v37_convergence_soak PROPERTIES
        TIMEOUT 300
        ENVIRONMENT "SOAK_SEED=20260918;SOAK_ROUNDS=600;SOAK_SECONDS=60;SOAK_PROGRESS=0")

    add_executable(v37_owed_event_mmr_kat v37_owed_event_mmr_kat.cpp)
    target_compile_features(v37_owed_event_mmr_kat PRIVATE cxx_std_20)
    target_include_directories(v37_owed_event_mmr_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_owed_event_mmr_kat Threads::Threads)
    add_test(NAME v37_owed_event_mmr_kat COMMAND v37_owed_event_mmr_kat)

    # V37.1 (Shape A) NATIVE-RIDGE ACTIVATION REGRESSION KAT. It landed with the
    # activation commit but carries NO add_executable at all, and the CI
    # drift-guard tools/ci/check_test_target_allowlist.py audits TARGETS against
    # the build.yml allowlist, not SOURCES — so it never saw the file, and the
    # 5d42f290... ridge golden (the anchor every later consensus golden, the
    # DROPS mint below included, is built on top of) has been UNENFORCED in CI
    # since the flip. Registered here. It drives the pinned 9000-push activation
    # schedule through the REAL Lane and OwedLedger on all four ratified lanes and
    # pins the gate-ON owed_digest, the gate-OFF control, the empty-ledger anchor,
    # the per-lane ridge SHAPE, the ND-R10 record-only migration cell, and that
    # the golden does not ride the one ND-R6 number (nr.coverage_blocks) that is
    # still OWED. Stdlib-only. SAME HOLLOW-GREEN GUARD as the sibling suites: ALSO
    # listed on BOTH build.yml --target lists (the Linux x86_64 leg and the
    # ASan+UBSan leg) so CI compiles + RUNS it instead of registering a NOT_BUILT
    # CTest sentinel (the DGB #137 / #769 / c2pool#1539 unregistered-KAT class).
    add_executable(v37_1_ridge_activation_test v37_1_ridge_activation_test.cpp)
    target_compile_features(v37_1_ridge_activation_test PRIVATE cxx_std_20)
    target_include_directories(v37_1_ridge_activation_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_1_ridge_activation_test Threads::Threads)
    add_test(NAME v37_1_ridge_activation_test COMMAND v37_1_ridge_activation_test)

    # RDWR-OQ2 DROPS ACTIVATION — the gate-ON owed_digest MINT over the CORRECTED
    # replace-not-add composition, its regression KAT, and the conformance pins
    # for the three consumer seams that make DROPS reachable on a live node.
    # Drives the byte-identical V37.1 activation schedule through the REAL Lane,
    # fold_eb and OwedLedger on all four ratified lanes, adding one new fully
    # specified input: a simulated sub-threshold hash stream handed to the REAL
    # seam OwedLedger::on_block_found_with_estimator(). Pins:
    #   (a) the canon already declares the gate ON for every lane under the
    #       corrected sybil-neutral Hhat_comb;
    #   (b) the gate-OFF anchors 66078202... / 6cf1127c... / 5d42f290... are
    #       byte-identical with the harvest PRESENT and the gate off, and stay
    #       there under the K >= 3 and J >= K refusals (non-vacuous: the SAME
    #       harvest moves the ON arm);
    #   (c) the NEW gate-ON golden d85dff58... per lane and its all-lanes fold,
    #       reproduced THREE ways — the engine seam, an independently shadowed
    #       ledger state, and a from-spec re-derivation that never calls the
    #       seam — and asserted NOT to be the superseded additive mint 34e4b38e...;
    #   (d) NO DOUBLE COUNT: the composed credit is ~1.0x the work performed
    #       where the REJECTED additive composition is ~1.9x on the same draws,
    #       and a 2000-identity sybil split gains nothing;
    #   (e) the three consumer seams — T1 the node lane factory (and the V37.1
    #       ridge coupling the flip carries), T2 the W2 sub-target harvest
    #       (measurement only: no push, no lane work, bindings still enforced),
    #       T3 the estimate-into-fold point;
    #   (f) DROPS-R1 (DENOMINATION), now RULED AND CLOSED: the estimate is put
    #       through the ORDINARY share -> E_b conversion — the Q62 weight unit a
    #       push applies plus split_reward's own floor(reward * w / SUM w) — so a
    #       COMPOSED row of work W is credited the SAME satoshi as a REAL SHARE
    #       row of work W at the same cut (asserted to the satoshi), and the
    #       ~3299x pre-ruling blowup is measured and gone;
    #   (g) R-SYBIL (EX-ANTE ENROLMENT): the selective "opt in for this interval
    #       iff Hhat > S*T" rule measured across a 1 / 4 / 20 / 200 / 2000-way
    #       split beside the SHIPPED seam on the same draws — the selective curve
    #       reaches 1.32x while the shipped curve stays flat at ~0.92..1.02x,
    #       never above it, with NEGATIVE rows composed for exactly the intervals
    #       a selective attacker would have opted out of; plus the ex-ante rule at
    #       its only entry point (enrol-from-now and back-dating both REFUSED);
    #   (h) the SHARE-COUNT PRODUCER: ShareCountBook fed from the W2 emit stream,
    #       its arm-point fail-closed frontier, and the enrolled-payee row it
    #       synthesises so a withheld raindrop cannot dodge a bad interval;
    #   (i) DROPS-R3: the carried-delta fold reproduces the winner's own ledger.
    # Stdlib-only, ~2 s. SAME HOLLOW-GREEN GUARD: ALSO on BOTH build.yml lists.
    add_executable(v37_drops_activation_kat v37_drops_activation_kat.cpp)
    target_compile_features(v37_drops_activation_kat PRIVATE cxx_std_20)
    target_include_directories(v37_drops_activation_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_drops_activation_kat Threads::Threads)
    add_test(NAME v37_drops_activation_kat COMMAND v37_drops_activation_kat)

    # DROPS STEP 2 — THE LIVE-SHELL WIRING. The package above shipped four
    # consumer seams and a verified gate-ON mint that NO LIVE SHELL CALLED: the
    # BTC/DASH main constructed no DropHarvester / EnrollmentBook /
    # ShareCountBook and never called set_drop_harvest / set_drop_harvester /
    # set_pre_harvest / set_enrollment_book, and the XMR node had no T3 hook at
    # all — so after the operator flip every node would have been gate-ON and
    # DORMANT. This KAT drives v37_drops_wiring.hpp, the object those shells now
    # call, and pins:
    #   W-ARITY    the RULED arity 1 (DECOUPLE: DROPS alone, the V37.1 ridge left
    #              to its own flag day) AND that W4 RATIFIES the geometry arity 1
    #              builds — without which the flip would refuse every E_b fold and
    #              DROPS would be dormant for a second, quieter reason;
    #   W-DORMANT  gate OFF is master byte for byte: make_drops_wiring() is
    #              nullopt on a default build whatever the geometry, and a fold
    #              handed a FULL harvest, a valid price and a populated enrolment
    #              book under LaneParams{} lands on the SAME owed_digest as a fold
    #              handed nothing (non-vacuous: the same harvest under the gate-ON
    #              geometry moves it);
    #   W-TIP      now_interval comes from the chain TIP, is monotone across a
    #              reorg, is UNKNOWN (and enrolment REFUSED) before the first tip,
    #              and records committed_at == tip / effective_from == tip + 1;
    #   W-STALE    ★ the residual the package left open. The ex-ante rule is
    #              enforced only by the caller-supplied now_interval, so a shell
    #              passing a STALE now (the burial frontier, which lags the tip by
    #              D_conf) re-opens the selective-enrolment attack. Pinned
    #              STRUCTURALLY by static_assert on the member signatures —
    #              enroll_at_tip(payee) takes NO interval and the book is
    #              const-only, so the stale call does not compile — and then
    #              MEASURED on real draws (unconditional 0.92x vs selective
    #              1.18x), with the shipped tip-sourced book composing exactly
    #              NOTHING for every already-drawn interval;
    #   W-E2E      the whole path on the REAL objects: the REAL W2 admitter
    #              harvesting raindrops through the wiring's DropSink, the REAL
    #              ShareCountBook teed onto the REAL emit stream, declare_into at
    #              the burial frontier, take_buried, subthreshold_credit under the
    #              REAL price and REAL ex-ante book, OwedLedger fold, owed_digest
    #              MOVES — over the four payee shapes a live lane produces
    #              (drop-only, covered, enrolled-but-silent, not enrolled);
    #   W-LOCK     a liveness + counter smoke over the wiring's lock, since Step 2
    #              is what first makes these objects reachable from three threads.
    # Stdlib-only, ~1 s. SAME HOLLOW-GREEN GUARD: ALSO on BOTH build.yml lists.
    add_executable(v37_drops_step2_wiring_kat v37_drops_step2_wiring_kat.cpp)
    target_compile_features(v37_drops_step2_wiring_kat PRIVATE cxx_std_20)
    target_include_directories(v37_drops_step2_wiring_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_drops_step2_wiring_kat Threads::Threads)
    add_test(NAME v37_drops_step2_wiring_kat COMMAND v37_drops_step2_wiring_kat)

    # ★ DROPS-JK (operator ruling 09-25) — v37_drops_jk_keep_share_credit_kat.
    # An interval with J < K near-misses is NOT ESTIMABLE: it keeps its share
    # credit and its DROPS delta is 0 (the reference apply_credit() answer),
    # where the base composed it as Hhat := 0 and REPLACED the payee's real
    # share credit away (net sub-threshold credit NEGATIVE for every enrolled
    # payee on the XDW regtest verify). Pins, on the arity-1 (XMR / decoupled)
    # and every arity-2 lane geometry: no delta for S > 0 / J < K (RED on the
    # base), the composed credit equal to E_b for every J < K payee, J >= K
    # composed exactly as from-spec, a J < K-only harvest leaving owed_digest
    # unmoved, agreement with the reference on which rows compose, gate OFF
    # unchanged, and 0 negative J < K compositions over a measured stream.
    # Stdlib-only, <1 s. SAME HOLLOW-GREEN GUARD: ALSO on BOTH build.yml lists.
    add_executable(v37_drops_jk_keep_share_credit_kat v37_drops_jk_keep_share_credit_kat.cpp)
    target_compile_features(v37_drops_jk_keep_share_credit_kat PRIVATE cxx_std_20)
    target_include_directories(v37_drops_jk_keep_share_credit_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_drops_jk_keep_share_credit_kat Threads::Threads)
    add_test(NAME v37_drops_jk_keep_share_credit_kat COMMAND v37_drops_jk_keep_share_credit_kat)

    # ★ DROPS on the XMR lane — v37_xmr_drops_wiring_kat. main_v37_xmr.cpp built
    # no DropsWiring and called none of XmrNode's T3 seams, so a flipped XMR node
    # was gate-ON and DORMANT. Pins the shell's wiring (X-SHELL: RED on the base),
    # gate-OFF dormancy, the ★ enrolment clock = the NATIVE TIP (never the burial
    # frontier), the exact Monero-difficulty -> lz normalisation, the rescaled
    # R1 price, and the end-to-end composed credit. Stdlib-only, ~1 s. ALSO on
    # BOTH build.yml --target lists (hollow-green guard).
    add_executable(v37_xmr_drops_wiring_kat v37_xmr_drops_wiring_kat.cpp)
    target_compile_features(v37_xmr_drops_wiring_kat PRIVATE cxx_std_20)
    target_include_directories(v37_xmr_drops_wiring_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_compile_definitions(v37_xmr_drops_wiring_kat PRIVATE
        V37_XMR_SHELL_SRC="${CMAKE_SOURCE_DIR}/src/c2pool/v37/main_v37_xmr.cpp")
    target_link_libraries(v37_xmr_drops_wiring_kat Threads::Threads)
    add_test(NAME v37_xmr_drops_wiring_kat COMMAND v37_xmr_drops_wiring_kat)

    # ★ DROPS ACTIVATION AT ARITY 1 — the gate-ON owed_digest a DECOUPLED fleet
    # actually reproduces, minted and pinned BESIDE the arity-2 golden above.
    #
    # WHY A SECOND GOLDEN. v37_node_lane_activation.hpp records the operator
    # ruling DECOUPLE: kActivationArity == 1, so a flipped node's lane geometry
    # is LaneParams::for_version(1) — the ONE-argument factory, which names no
    # parent LaneKind and therefore carries NO ridge and NO window dimensions
    # (mrr / nr / win positions all UINT64_MAX, nr_version and win_version 0).
    # The activation mint 5e653e4b... above was composed over for_version(1,
    # LaneKind) with the ridge ACTIVE at 4096, and the ridge moves the lane's
    # payout map, hence E_b, hence owed_digest. So 5e653e4b... is NOT the fleet
    # value at arity 1. The header says that in prose; this KAT supplies the
    # number and pins it:
    #   arity-1 gate-ON owed_digest (identical on all four ratified lanes)
    #     cd8f3dddf3f39aef786a82b54d1569c77eb567aaf65f4448f9d9557468d9ab67
    #   arity-1 all-lanes fold, sha256d("V37DROPS1" || BTC || LTC || DASH || DOGE)
    #     64d357d5be6d83a7178318c13468eb99c7af88e2b82b25671a4b023fb8701965
    #
    # ★ ADD-ONLY. 5e653e4b... and its fold 1b853a05... are NOT moved, replaced or
    # re-minted: case A2-UNMOVED re-derives BOTH from this file's own copy of the
    # schedule and harvest (which is also what proves the copy has not drifted),
    # and the gate-OFF anchors 66078202... / 6cf1127c... / 5d42f290... are
    # asserted byte-identical. Neither golden may be edited without the other.
    #
    # ALSO PINS:
    #   - the arity-1 gate-OFF anchor is 6cf1127c... (the PRE-V37.1 control), not
    #     5d42f290... — that difference IS the decoupling, and the arms are
    #     non-vacuous: the same harvest that leaves drops-OFF / harvest-EMPTY /
    #     K = 2 / J < K at 6cf1127c... moves the ON arm;
    #   - W4 RATIFIES the arity-1 geometry, without which the flip would refuse
    #     every E_b fold and DROPS would be dormant for a second, quieter reason;
    #   - THREE independent reproductions of the arity-1 value on every lane: the
    #     engine seam (OwedLedger), an independently shadowed (finalW,
    #     first_eligible) state hashed by the estimator module's own
    #     owed_digest(), and a from-spec re-derivation that never calls
    #     subthreshold_credit();
    #   - ARITY-COST: the two goldens differ, the E_b half does NOT (both arities
    #     split the same four rewards), and — measured rather than assumed — the
    #     estimator's own contribution is NOT arity-invariant either, because the
    #     ridge moves SUM weight and therefore the price the R1 denomination
    #     divides by.
    # Stdlib-only, ~2 s. SAME HOLLOW-GREEN GUARD: ALSO on BOTH build.yml lists.
    add_executable(v37_drops_arity1_activation_kat v37_drops_arity1_activation_kat.cpp)
    target_compile_features(v37_drops_arity1_activation_kat PRIVATE cxx_std_20)
    target_include_directories(v37_drops_arity1_activation_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(v37_drops_arity1_activation_kat Threads::Threads)
    add_test(NAME v37_drops_arity1_activation_kat COMMAND v37_drops_arity1_activation_kat)

    # ★★ THE LIVE-GEOMETRY LEG — the SAME source compiled a second time so the
    # mint is read from the node lane FACTORY instead of from a restatement of
    # it. The default target above names the arity-1 geometry explicitly
    # (for_version(1)), which is what makes its goldens invariant to the
    # kActivationArity constant — but it leaves one thing unproved: that
    # node_lane_params() actually hands a flipped node that geometry. Here case
    # ARITY1-LIVEGEOM reads node_lane_params(lane) directly, asserts it is
    # field-for-field for_version(1) with every position OFF on all four lanes
    # (and that the no-LaneKind XMR arm lands on the same geometry), and DRIVES
    # THE WHOLE MINT FROM IT. Both targets print the same seven pinned values.
    #
    # ★★ THIS IS NOT THE FLIP AND DOES NOT TAKE IT. V37_ACTIVATE_CONSENSUS_V1=1
    # is scoped PRIVATE to this one TEST EXECUTABLE. No product target, no
    # default, no cache variable and no build.yml option carries it; the shipped
    # default in v37_node_lane_activation.hpp stays 0, the default target above
    # asserts kActivateConsensusV1 == false, and a normal build of c2pool is
    # byte-identical to master. The consensus flip remains exactly what the
    # header says it is: the operator's hand, fleet-wide, at a ruled height. This
    # target exists so that hand knows the number it will land on.
    add_executable(v37_drops_arity1_activation_kat_livegeom
                   v37_drops_arity1_activation_kat.cpp)
    target_compile_features(v37_drops_arity1_activation_kat_livegeom PRIVATE cxx_std_20)
    target_include_directories(v37_drops_arity1_activation_kat_livegeom
                               PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_compile_definitions(v37_drops_arity1_activation_kat_livegeom
                               PRIVATE V37_ACTIVATE_CONSENSUS_V1=1)
    target_link_libraries(v37_drops_arity1_activation_kat_livegeom Threads::Threads)
    add_test(NAME v37_drops_arity1_activation_kat_livegeom
             COMMAND v37_drops_arity1_activation_kat_livegeom)

    # V37 roundabout split S1-S5 (NEW standalone modules under
    # src/c2pool/v37/roundabout/): their KATs live beside the headers and are
    # pulled in here with an explicit binary dir, so src/c2pool/CMakeLists.txt
    # stays untouched. SAME HOLLOW-GREEN GUARD: every v37_rb_* target is ALSO on
    # BOTH build.yml --target lists.
    add_subdirectory(${CMAKE_SOURCE_DIR}/src/c2pool/v37/roundabout/test
                     ${CMAKE_CURRENT_BINARY_DIR}/roundabout)

    # V37 payout economics (NEW standalone modules under src/c2pool/v37/payout/):
    # KATs beside the headers, pulled in with an explicit binary dir. SAME
    # HOLLOW-GREEN GUARD: every v37_payout_* target is ALSO on BOTH build.yml
    # --target lists.
    add_subdirectory(${CMAKE_SOURCE_DIR}/src/c2pool/v37/payout/test
                     ${CMAKE_CURRENT_BINARY_DIR}/payout)

    # V37 payout economics — CarriageGate + FeeFloorGate KAT (its own test dir
    # beside the header, src/c2pool/v37/payout/carriage.hpp). SAME HOLLOW-GREEN
    # GUARD: v37_payout_carriage_kat is ALSO on BOTH build.yml --target lists.
    add_subdirectory(${CMAKE_SOURCE_DIR}/src/c2pool/v37/payout/carriage/test
                     ${CMAKE_CURRENT_BINARY_DIR}/payout_carriage)

    # Build hygiene -- v37_xmr_boost_origin_kat
    #   The top level force-includes core/boost_asio_compat.hpp (-> <boost/
    #   version.hpp>) into EVERY C++ TU, including targets that link no Boost
    #   (vendored randomx, xmr_node's monero_rpc.cpp, the POSIX-only KATs). This
    #   KAT's main TU links NO Boost on purpose and must still see exactly the
    #   Boost that the Boost::headers TUs (the OBJECT probe) and find_package
    #   see: no host/system Boost mixed in, no "boost/version.hpp: No such file"
    #   on a host without system Boost. SAME HOLLOW-GREEN GUARD: listed in BOTH
    #   build.yml --target lists.
    add_library(v37_xmr_boost_origin_probe OBJECT v37_xmr_boost_origin_probe.cpp)
    target_compile_features(v37_xmr_boost_origin_probe PRIVATE cxx_std_20)
    if (TARGET Boost::headers)
        target_link_libraries(v37_xmr_boost_origin_probe PRIVATE Boost::headers)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(v37_xmr_boost_origin_probe PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    if (DEFINED Boost_VERSION_STRING AND NOT Boost_VERSION_STRING STREQUAL "")
        set(_v37_boost_origin_expect "${Boost_VERSION_STRING}")
    else()
        set(_v37_boost_origin_expect "${Boost_VERSION}")
    endif()
    add_executable(v37_xmr_boost_origin_kat v37_xmr_boost_origin_kat.cpp
                   $<TARGET_OBJECTS:v37_xmr_boost_origin_probe>)
    target_compile_features(v37_xmr_boost_origin_kat PRIVATE cxx_std_20)
    target_compile_definitions(v37_xmr_boost_origin_kat PRIVATE
        C2POOL_EXPECT_BOOST_VERSION_STRING="${_v37_boost_origin_expect}")
    add_test(NAME v37_xmr_boost_origin_kat COMMAND v37_xmr_boost_origin_kat)
endif()
