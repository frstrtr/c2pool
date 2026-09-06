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
endif()
