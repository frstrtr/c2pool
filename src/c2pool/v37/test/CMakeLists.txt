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
endif()
