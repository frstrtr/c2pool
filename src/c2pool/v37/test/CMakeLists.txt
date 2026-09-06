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
endif()
