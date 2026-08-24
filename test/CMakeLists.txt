if (BUILD_TESTING AND GTest_FOUND)
    # include(GoogleTest) MUST precede any gtest_discover_tests() call below:
    # it sets _GOOGLETEST_DISCOVER_TESTS_SCRIPT (path to GoogleTestAddTests.cmake).
    # In PRE_TEST mode the generated <tgt>[1]_include.cmake includes that script
    # to define gtest_discover_tests_impl; if the var is unset the include path is
    # empty and ctest dies "Unknown CMake command gtest_discover_tests_impl" (exit
    # 8). The clean-build-dir step (8d05ef2b) removed the cached _tests.cmake that
    # had masked this, surfacing it on test_dgb_subsidy (the first PRE_TEST call).
    include(GoogleTest)

    # DGB block subsidy oracle-conformance (card #156). config_coin.hpp
    # subsidy() is header-only/static; no dgb runtime link required.
    add_executable(test_dgb_subsidy test_dgb_subsidy.cpp)
    target_link_libraries(test_dgb_subsidy PRIVATE
        GTest::gtest_main GTest::gtest
        btclibs
        yaml-cpp::yaml-cpp
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_discover_tests(test_dgb_subsidy DISCOVERY_MODE PRE_TEST)

    # DGB embedded-path coinbasevalue SSOT (forward-only #82 wiring TODO):
    # embedded_coinbase_value.hpp routes CoinParams::subsidy_func(height)+fees
    # into the coinbasevalue and preserves the external-daemon GBT fallback.
    # Header-only like test_dgb_subsidy (config_coin.hpp subsidy is static); no
    # dgb runtime link. MUST also be in the build.yml --target allowlist (#143).
    add_executable(test_dgb_coinbase_value test_dgb_coinbase_value.cpp)
    target_link_libraries(test_dgb_coinbase_value PRIVATE
        GTest::gtest_main GTest::gtest
        btclibs
        yaml-cpp::yaml-cpp
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_discover_tests(test_dgb_coinbase_value DISCOVERY_MODE PRE_TEST)

    add_executable(test_coin_broadcaster test_coin_broadcaster.cpp)
    target_link_libraries(test_coin_broadcaster PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_coin_broadcaster PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_share_messages test_share_messages.cpp)
    target_link_libraries(test_share_messages PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_share_messages PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_hardening test_hardening.cpp)
    target_link_libraries(test_hardening PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_hardening PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_utxo test_utxo.cpp)
    target_link_libraries(test_utxo PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_utxo PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_discover_tests(test_utxo DISCOVERY_MODE PRE_TEST)  # defer discovery to ctest runtime; fixes -j(nproc) build-time discovery race vs v37_test (PR #84)

    add_executable(test_redistribute_address test_redistribute_address.cpp)
    target_link_libraries(test_redistribute_address PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        c2pool_payout c2pool_merged_mining c2pool_hashrate
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_redistribute_address PRIVATE ltc_coin c2pool_storage pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    # ci-allowlist-exempt: test_phase0_live  -- live-only harness (needs a running coin daemon); not CI-built by design
    # ci-allowlist-exempt: test_phase1_live  -- live-only harness (needs a running coin daemon); not CI-built by design
    # ci-allowlist-exempt: test_phase2_live  -- live-only harness (needs a running coin daemon); not CI-built by design
    # ci-allowlist-exempt: test_phase3_live  -- live-only harness (needs a running coin daemon); not CI-built by design
    # ci-allowlist-exempt: test_phase4_live  -- live-only harness (needs a running coin daemon); not CI-built by design
    add_executable(test_phase0_live test_phase0_live.cpp)
    target_link_libraries(test_phase0_live PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_phase0_live PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_header_chain test_header_chain.cpp)
    target_link_libraries(test_header_chain PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_header_chain PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_phase1_live test_phase1_live.cpp)
    target_link_libraries(test_phase1_live PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_phase1_live PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_mempool test_mempool.cpp)
    target_link_libraries(test_mempool PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_mempool PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_phase2_live test_phase2_live.cpp)
    target_link_libraries(test_phase2_live PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_phase2_live PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_template_builder test_template_builder.cpp)
    target_link_libraries(test_template_builder PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_template_builder PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_phase3_live test_phase3_live.cpp)
    target_link_libraries(test_phase3_live PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_phase3_live PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_phase4_embedded test_phase4_embedded.cpp)
    target_link_libraries(test_phase4_embedded PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_phase4_embedded PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_phase4_live test_phase4_live.cpp)
    target_link_libraries(test_phase4_live PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_merged_mining
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_phase4_live PRIVATE c2pool_payout c2pool_hashrate ltc_coin c2pool_storage pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_threading test_threading.cpp)
    target_link_libraries(test_threading PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_threading PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    add_executable(test_weights test_weights.cpp)
    target_link_libraries(test_weights PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_weights PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)

    include(GoogleTest)
    gtest_add_tests(test_weights "" AUTO)
    gtest_add_tests(test_threading "" AUTO)
    gtest_add_tests(test_coin_broadcaster "" AUTO)
    gtest_add_tests(test_share_messages "" AUTO)
    gtest_add_tests(test_hardening "" AUTO)
    gtest_add_tests(test_redistribute_address "" AUTO)
    gtest_add_tests(test_phase0_live "" AUTO)
    gtest_add_tests(test_header_chain "" AUTO)
    gtest_add_tests(test_phase1_live "" AUTO)
    gtest_add_tests(test_mempool "" AUTO)
    gtest_add_tests(test_phase2_live "" AUTO)
    gtest_add_tests(test_template_builder "" AUTO)
    gtest_add_tests(test_phase3_live "" AUTO)
    gtest_add_tests(test_phase4_embedded "" AUTO)
    gtest_add_tests(test_phase4_live "" AUTO)

    add_executable(test_doge_chain test_doge_chain.cpp)
    target_link_libraries(test_doge_chain PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_doge_chain PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_doge_chain "" AUTO)

    # DASH X11 PoW known-answer test (PR-0 foundation, S2 slice). Links only the
    # additive dash_x11 primitive + core (uint256); no ltc/pool SCC dependency.
    add_executable(test_dash_x11_kat test_dash_x11_kat.cpp)
    target_link_libraries(test_dash_x11_kat PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_x11_kat PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_x11_kat "" AUTO)

    # DASH consensus known-answer test (PR-0 foundation, S3 slice): SPV
    # HeaderChain + DarkGravityWave v3 retarget. header_chain.hpp pulls in the
    # additive dash_x11 primitive (hash_x11.hpp) + core (uint256/leveldb/pack/log);
    # no ltc/pool SCC dependency. Mirrors the test_dash_x11_kat link set.
    add_executable(test_dash_header_chain test_dash_header_chain.cpp)
    target_link_libraries(test_dash_header_chain PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_header_chain PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_header_chain "" AUTO)

    # DASH block-replay test (PR-0 foundation, S5 slice): BIP 152 compact-block
    # reassembly over the vendored blockencodings port. Links the additive
    # dash_block_replay static lib (coin/vendor/blockencodings.cpp) on top of
    # the test_dash_header_chain link set; no ltc/pool SCC dependency.
    #
    # test_dash_tx_version_gate.cpp is FOLDED into this target (same CI-fold
    # rationale as test_dash_mn_state: build.yml allowlists this executable,
    # a standalone target would be a NOT_BUILT CTest sentinel): the dashd
    # nVersion==3 extra-payload gate KAT over the real mainnet block 842284
    # fixture — the [BULK] MERKLE-BIND FAIL livelock the bulk-replay lane
    # wedged on. DASH_FIXTURE_DIR feeds its fixture loader.
    add_executable(test_dash_block_replay test_dash_block_replay.cpp
                   test_dash_tx_version_gate.cpp)
    target_compile_definitions(test_dash_block_replay PRIVATE
        DASH_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
    target_link_libraries(test_dash_block_replay PRIVATE
        GTest::gtest_main GTest::gtest
        dash_block_replay dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_block_replay PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_block_replay "" AUTO)

    # DASH V36 conformance -- merkle-root-equality precondition (S6 slice).
    # share_check.hpp (check_merkle_link) + coinbase_builder.hpp
    # (merkle_branches_raw) are header-only over the dash_x11 + core link set;
    # no ltc/pool SCC dependency. Mirrors the test_dash_header_chain link set.
    add_executable(test_dash_conformance test_dash_conformance.cpp)
    target_link_libraries(test_dash_conformance PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_conformance PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_conformance "" AUTO)

    # DASH share-v16 BYTE-PARITY KAT (T1c gate): round-trips REAL captured
    # p2pool-dash oracle-gate wire bytes (test/data/dash_oracle_corpus.hpp)
    # through the production load_share/DashFormatter path and demands byte
    # identity — the real-corpus test the 2026-07-21 audit flagged as missing.
    # Mirrors the test_dash_conformance link set.
    add_executable(test_dash_oracle_byte_parity test_dash_oracle_byte_parity.cpp)
    target_link_libraries(test_dash_oracle_byte_parity PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_oracle_byte_parity PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_oracle_byte_parity "" AUTO)

    # DASH min-protocol-version ratchet gate KAT (#643, option a): pure, header-only
    # policy object; no socket/ltc/pool dependency. Mirrors the test_dash_conformance link set.
    add_executable(test_dash_min_protocol_gate test_dash_min_protocol_gate.cpp)
    target_link_libraries(test_dash_min_protocol_gate PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_min_protocol_gate PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_min_protocol_gate "" AUTO)

    # DASH serve-gate journal per-cause time KAT (h=2518004 count-vs-time trap):
    # pure, header-only policy object; no socket/ltc/pool dependency. Mirrors
    # the test_dash_min_protocol_gate link set.
    add_executable(test_dash_serve_gate_journal test_dash_serve_gate_journal.cpp test_dash_serve_gate_ledger.cpp)
    target_link_libraries(test_dash_serve_gate_journal PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_serve_gate_journal PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_serve_gate_journal "" AUTO)
    # Force-build the daemonless tx-serve self-validation KAT (defined in
    # src/c2pool/CMakeLists.txt) whenever this target builds. That KAT exe is NOT in
    # the fixed --target allowlist in .github/workflows/build.yml and we have no
    # workflow scope to add it; test_dash_serve_gate_journal IS allowlisted in BOTH
    # the Linux and AsAN CI jobs, so this dependency makes CI build the KAT and CTest
    # find it instead of reporting it NOT_BUILT / Not Run.
    add_dependencies(test_dash_serve_gate_journal dash_tx_serve_self_validation_kat)
    add_dependencies(test_dash_serve_gate_journal dash_arrival_instrumentation_kat)  # PR-0 coin-P2P KAT: not in build.yml --target allowlist; piggyback on allowlisted anchor so CI builds it (avoids NOT_BUILT/Not-Run)
    add_dependencies(test_dash_serve_gate_journal dash_latency_scoring_kat)  # coin-P2P KAT: not in build.yml --target allowlist; piggyback on allowlisted anchor so CI builds it (avoids NOT_BUILT/Not-Run)
    add_dependencies(test_dash_serve_gate_journal dash_fresh_datum_race_kat)  # coin-P2P KAT: not in build.yml --target allowlist; piggyback on allowlisted anchor so CI builds it (avoids NOT_BUILT/Not-Run)
    add_dependencies(test_dash_serve_gate_journal dash_proactive_rotation_kat)  # coin-P2P KAT: not in build.yml --target allowlist; piggyback on allowlisted anchor so CI builds it (avoids NOT_BUILT/Not-Run)
    add_dependencies(test_dash_serve_gate_journal dash_asn_diversity_kat)  # coin-P2P KAT: not in build.yml --target allowlist; piggyback on allowlisted anchor so CI builds it (avoids NOT_BUILT/Not-Run)
    add_dependencies(test_dash_serve_gate_journal dash_getmnlistd_tracker_kat)  # coin-P2P KAT: not in build.yml --target allowlist; piggyback on allowlisted anchor so CI builds it (avoids NOT_BUILT/Not-Run)

    # DASH serve-gate LEDGER cross-restart never-a-reject accounting KAT: the
    # CUMULATIVE, persisted companion to ServeGateJournal (the journal wipes on
    # restart; the ledger survives via write-through JSON). Pure-policy header +
    # JSON companion; the KAT does a real atomic save->load round-trip through a
    # temp file. Same link set as the journal KAT.

    # DASH S8 pool-node leaf 4 — share_tracker.hpp KAT: DensePPLNSWindow decayed
    # weight ring buffer (compute_v36_weights), decay table, donation split,
    # window slides. PoW-independent consensus core; socket-free, chain-free.
    # Mirrors the test_dash_conformance link set.
    add_executable(test_dash_share_tracker test_dash_share_tracker.cpp test_dash_share_remove_owns_data.cpp)
    target_link_libraries(test_dash_share_tracker PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_share_tracker PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    target_compile_definitions(test_dash_share_tracker PRIVATE  # #1131 source-structural KAT: borrow, don't own, on verified.remove(bad)
        DASH_SHARE_TRACKER_SRC="${CMAKE_CURRENT_SOURCE_DIR}/../src/impl/dash/share_tracker.hpp")
    gtest_add_tests(test_dash_share_tracker "" AUTO)

    # DASH S8 pool-node leaf 5 (FINAL) slice A — node.hpp skeleton KAT: NodeImpl
    # default-constructible/concrete, empty fresh tracker, lock-free snapshot
    # publish/getters, tracker()/read_tracker()/tracker_shared_lock() accessors.
    # Rig-free (no io_context/sockets). Needs pool (BaseNode) + c2pool_storage
    # (SharechainStorage) on top of the dash_x11 + core link set.
    # test_dash_dashboard_found_block.cpp is FOLDED into this already-allowlisted
    # target as a second TU rather than added as a standalone executable: a new
    # target would need a build.yml --target edit and, until it had one, would
    # trip CI's NOT_BUILT sentinel (the drift-guard audit, #883/#893). It needs
    # exactly this link set — NodeImpl + ShareTracker + core MiningInterface.
    # test_dash_addrme.cpp (#882): the addrme origination + Legacy self-probe
    # KATs. Drives the REAL NodeImpl::handle_version and the REAL
    # dash::Legacy::handle(message_addrme) over a REAL loopback TCP socket, so it
    # needs exactly this link set (NodeImpl + the `dash` OBJECT lib carrying
    # protocol_legacy.cpp + core Socket/Packet). FOLDED in as a third TU for the
    # same reason as the second: a standalone target would need a build.yml
    # --target edit and would trip CI's NOT_BUILT sentinel until it had one
    # (#769/#883/#893).
    # test_dash_block_confirm_lane.cpp: the post-broadcast found-block
    # confirmation / orphan lane (daemonless resolve_status verdict + the
    # MiningInterface pending→confirmed / pending→orphaned status flip). FOLDED
    # in as another TU for the same reason as the found-block TU above — a
    # standalone target would need a build.yml --target edit and trip CI's
    # NOT_BUILT sentinel until it had one. Needs exactly this link set (core
    # MiningInterface; the resolver is header-only).
    # test_dash_dashboard_views.cpp: the sharechain WINDOW / DELTA / SHARE-DETAIL
    # read-model KATs (dashboard_views.hpp). FOLDED in as another TU for the same
    # reason as the TUs above — a standalone target would need a build.yml
    # --target edit and would trip CI's NOT_BUILT sentinel until it had one
    # (#143/#883/#893). Needs exactly this link set: a real dash::NodeImpl +
    # ShareTracker, and core's address_utils for the DASH base58 rendering.
    # test_dash_dashboard_pplns.cpp: the PPLNS payout read-model KATs
    # (dashboard_pplns.hpp) — the pool-wide split behind /current_payouts and
    # the per-share split on an individual share's page. FOLDED in for the same
    # reason; needs the same link set plus the header-only mint/producer weight
    # walk and coinbase allocator, both already reachable from `dash`.
    add_executable(test_dash_node test_dash_node.cpp test_dash_dashboard_found_block.cpp test_dash_addrme.cpp test_dash_block_confirm_lane.cpp test_dash_dashboard_views.cpp test_dash_dashboard_pplns.cpp test_dash_shutdown_order.cpp)
    target_link_libraries(test_dash_node PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_node PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining c2pool_storage pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    # #889: the block-winning-mint KATs drive the REAL NodeImpl::add_local_share
    # against the REAL m_tracker_mutex held exclusively by another thread, so
    # this target now needs the `dash` OBJECT lib (node.cpp) it previously only
    # type-checked against. No new add_executable — folded into the existing
    # allowlisted target. `dash`'s own deps (core pool sharechain c2pool_storage
    # dash_x11 btclibs json boost secp256k1) are already on this line or come in
    # transitively; nothing outside src/impl/dash is added.
    target_link_libraries(test_dash_node PRIVATE dash sharechain)
    gtest_add_tests(test_dash_node "" AUTO)

    # #1133 teardown-order guard reads the shipped node.hpp + main_dash.cpp
    # source (dgb RACE913 DGB_NODE_SRC idiom) so the fix-site assertions are
    # deterministic red/green on a nondeterministic destruction-order UB.
    target_compile_definitions(test_dash_node PRIVATE
        DASH_NODE_HPP_SRC="${CMAKE_CURRENT_SOURCE_DIR}/../src/impl/dash/node.hpp"
        DASH_MAIN_SRC="${CMAKE_CURRENT_SOURCE_DIR}/../src/c2pool/main_dash.cpp")

    # DASH S8 per-miner work-target MODULATION KAT (work.py:308-326 oracle pin):
    # pool-share cap (1.67%) + dust-threshold ease + average_attempts_to_target.
    # Header-only (stratum/work_target.hpp over core/target_utils + config_pool);
    # pure, socket-free. Mirrors the test_dash_conformance link set.
    add_executable(test_dash_work_target test_dash_work_target.cpp)
    target_link_libraries(test_dash_work_target PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_work_target PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_work_target "" AUTO)

    # #859: LTC producer-target helper (average_attempts_to_target saturation).
    # Header-only (impl/ltc/work_target.hpp over core/uint256.hpp); pure,
    # socket-free. Mirrors the test_dash_work_target link set (minus dash_x11).
    add_executable(test_ltc_work_target test_ltc_work_target.cpp)
    target_link_libraries(test_ltc_work_target PRIVATE
        GTest::gtest_main GTest::gtest
        core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_ltc_work_target PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_ltc_work_target "" AUTO)

    # Header-only (stratum/work_job_targets.hpp over work_target.hpp + config_pool);
    # pure, socket-free. get_work() job-target assembly KAT.
    add_executable(test_dash_work_job_targets test_dash_work_job_targets.cpp)
    target_link_libraries(test_dash_work_job_targets PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_work_job_targets PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_work_job_targets "" AUTO)
    add_executable(test_dash_job_notify_roundtrip test_dash_job_notify_roundtrip.cpp)
    target_link_libraries(test_dash_job_notify_roundtrip PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_job_notify_roundtrip PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_job_notify_roundtrip "" AUTO)

    add_executable(test_dash_share_messages test_dash_share_messages.cpp)
    target_link_libraries(test_dash_share_messages PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_share_messages PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_share_messages "" AUTO)

    # Featured developer-node banner (signed authority subtype 0x06): freshest-
    # wins / replay-protection / persistence (core::FeaturedNodeStore) + the
    # ECDSA sign-then-verify render gate (dash share-message crypto). Consensus-
    # neutral presentation feature; no share/target/payout link needed.
    add_executable(test_dash_featured_node test_featured_node.cpp)
    target_link_libraries(test_dash_featured_node PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_featured_node PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_featured_node "" AUTO)

    add_executable(test_dash_stratum_binding test_dash_stratum_binding.cpp)
    target_link_libraries(test_dash_stratum_binding PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_stratum_binding PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_stratum_binding "" AUTO)

    # DASH G1 difficulty / vardiff PARITY KAT: share-diff floor byte-exactness +
    # per-share min_work (target_to_average_attempts) oracle pin. Header-only over
    # core/target_utils + config_pool; pure, socket-free. Mirrors the work_target
    # link set.
    add_executable(test_dash_difficulty_parity test_dash_difficulty_parity.cpp)
    target_link_libraries(test_dash_difficulty_parity PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_difficulty_parity PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_difficulty_parity "" AUTO)

    # share_init_verify gentx hash_link byte-parity vs oracle (coinbase_payload
    # VarStr prefix). Header-only over the dash_x11 + core link set; mirrors the
    # test_dash_conformance link set.
    # test_dash_share_producer.cpp (mint campaign slice 1): producer-side
    # prospective share_info assembly, ref_hash/hash_link producers, oracle
    # retarget + gentx byte goldens. Compiled into this EXISTING allowlisted
    # target so the CI build.yml allowlist stays untouched (proven pattern).
    # test_dash_mint_runloop.cpp (mint campaign slice 3): the run-loop mint
    # pipeline -- producer job -> coinb1/coinb2 split -> real X11 solve ->
    # mint_from_inputs -> tracker insert -> wire round-trip -> best-share
    # election -> PPLNS oracle-window pin. Same allowlisted target (proven
    # pattern), no build.yml change.
    # test_dash_share_download.cpp (#754 share-download leg): sharereq wire
    # byte-parity vs the python oracle layout, DownloadGate de-dup/retry/
    # cycle-reset, build_stops, and the download-gate proof -- a mocked
    # sharereply's shares (RawShare round-trip, child->parent order) insert +
    # verify and ROOT a previously-unrooted live-pushed tip. Same allowlisted
    # target (proven pattern), no build.yml change.
    # test_dash_v36_share.cpp (Phase A DASH v36 share-type): byte-parity of the
    # standardized cross-coin v36 prefix vs the non-segwit (BCH) v36 shape,
    # round-trip through the version-36 ShareVariants dispatch, merged-fields-
    # inert convention, and v16 backward-compat. Same allowlisted target (proven
    # pattern), no build.yml change (avoids the #769 new-target/allowlist trap).
    add_executable(test_dash_share_hash_link
        test_dash_share_hash_link.cpp
        test_dash_share_producer.cpp
        test_dash_share_producer_bind.cpp
        test_dash_mint_runloop.cpp
        test_dash_share_download.cpp
        test_dash_v36_share.cpp
        test_dash_known_txs_retention.cpp)
    target_link_libraries(test_dash_share_hash_link PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_share_hash_link PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_share_hash_link "" AUTO)

    # test_dash_known_txs_retention.cpp: pure retention/eviction semantics of the
    # known-tx pool that backs share broadcast (register_template_txs) — rolling
    # window, evict-only-after-a-tx-falls-out-of-ALL-retained-sets, the F1
    # template-identity dedup (N payout scripts on one template => ONE slot, not
    # N), recency refresh, and the F3/F2 broadcast gate. Header-only over
    # impl/dash/known_txs_retention.hpp + core (uint256). FOLDED into the
    # EXISTING allowlisted target test_dash_share_hash_link above (added to its
    # sources) — avoids the #769 new-target/allowlist trap (a standalone target
    # is not in build.yml's --target list, so CI never builds it and CTest
    # reports the tests "Not Run"). Its gtest cases run under that target.

    # DASH block-subsidy + UTXO adapter (S7 foundation slice): GetBlockSubsidy /
    # masternode + platform reward split (subsidy.hpp) consumed through the
    # header-only utxo_adapter view shim. Both are header-only over
    # block/transaction + core/coin (utxo_view_cache/db); no ltc/pool SCC
    # dependency. Mirrors the test_dash_conformance link set.
    add_executable(test_dash_subsidy test_dash_subsidy.cpp)
    target_link_libraries(test_dash_subsidy PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_subsidy PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_subsidy "" AUTO)

    # E-SUPERBLOCK: daemonless superblock payee sourcing KATs. Pins the reused
    # dashcore superblock logic (CSuperblock::ParsePaymentSchedule +
    # CSuperblockManager::GetSuperblockPayments + CalcSuperblockBudget) against
    # FROM-WIRE testnet vectors + the store/selection fail-closed discipline +
    # the build_embedded_workdata superblock-output wiring. Header-only over
    # impl/dash/coin (governance_object/store, superblock, embedded_gbt) + core
    # (address_to_script); same link set as test_dash_subsidy.
    add_executable(test_dash_superblock test_dash_superblock.cpp)
    target_link_libraries(test_dash_superblock PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_superblock PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_superblock "" AUTO)


    # DASH external-dashd RPC creds-resolution KAT (launcher slice 4): dash.conf
    # rpcuser/rpcpassword/rpcport parse + --coin-rpc endpoint override + armed()
    # gating that main_dash --run consults before ARMing the submitblock fallback.
    # Header-only over impl/dash/coin/rpc_conf.hpp (pure std); no ltc/pool SCC dep.
    add_executable(test_dash_rpc_conf test_dash_rpc_conf.cpp)
    target_link_libraries(test_dash_rpc_conf PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_rpc_conf PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_rpc_conf "" AUTO)

    # DASHD-CUT arm-authority + reconnect-thrash KAT (hotel-reserve 2026-08-15).
    # SEAM 1 resolve_dashd_arm() (pure, cut-mode disarm), SEAM 2 sync-reconnect
    # backoff (no ~30/s hot spin against a dead dashd), SEAM 3 cache-invalidation
    # decoupled from reconnect FAILURE. Links the real dash_rpc lib (coin/rpc.cpp)
    # to drive NodeRPC::sync_reconnect against dead + live loopback endpoints.
    add_executable(test_dash_dashd_cut_arm test_dash_dashd_cut_arm.cpp)
    target_link_libraries(test_dash_dashd_cut_arm PRIVATE
        GTest::gtest_main GTest::gtest
        dash_rpc dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_dashd_cut_arm PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_dashd_cut_arm "" AUTO)

    # DASH in-memory mempool (S7 leaf): storage + UTXO-fee + LRU eviction +
    # double-spend conflict removal + feerate-sorted selection. Header-only over
    # block/transaction/utxo_adapter + core/coin; no ltc/pool SCC dependency.
    # Direct prerequisite for the embedded_gbt template builder (S7 main).
    # Second TU: test_dash_replay_utxo_fold.cpp — the W3 FULL-HISTORY REPLAY
    # standalone UTXO fold (coin/replay_utxo_fold.hpp): dashd WriteVarInt /
    # CompactSize primitive KATs, the hash_serialized_2 stream vs an
    # independently hand-assembled preimage (incl. the v23.1.x ApplyHash
    # ternary quirk, pinned), strict fold rules (zero-value coins kept,
    # OP_RETURN excluded, missing-input/gap/BIP30/cold-start fail-closed,
    # genesis short-circuit), resumable cursor across reopen, versioned-format
    # fail-loud, 100-block undo window retention, disconnect/reconnect set-
    # hash identity. Same target, no new allowlist entry.
    # test_dash_mempool_validity_gate.cpp also rides the test_dash_embedded_gbt
    # target above, but that target currently FAILS TO LINK (a pre-existing
    # #154-era gap: test_dash_replay_v19_type4_punish.cpp needs opkey_* from
    # bls_verify.cpp). Fold the gate suite into this LINKING target too so the
    # readiness-gate KATs — including the tip-context propagation split — are
    # actually built and run. Header-only over mempool_validity_gate.hpp +
    # nlohmann/json; no new SCC dependency, no new build.yml --target (#769).
    add_executable(test_dash_mempool test_dash_mempool.cpp test_dash_replay_utxo_fold.cpp
        test_dash_mempool_validity_gate.cpp)
    target_link_libraries(test_dash_mempool PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_mempool PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_mempool "" AUTO)

    # DASH SimplifiedMNList (DIP-0004, S7 leaf): vendored CSimplifiedMNListEntry /
    # CSimplifiedMNList wire + CalcHash (SER_GETHASH) + memcmp sort + merkle root.
    # Header-only over core/uint256 + core/pack + core/hash; no ltc/pool SCC
    # dependency. Base leaf of the embedded_gbt dependency chain (S7 main).
    add_executable(test_dash_simplifiedmns test_dash_simplifiedmns.cpp)
    target_link_libraries(test_dash_simplifiedmns PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_simplifiedmns PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_simplifiedmns "" AUTO)

    # DASH daemonless-fold SIMD-SHA256 reward-safety KAT (dashd-cut replay
    # speedup): proves SHA256AutoDetect()-dispatched SIMD/SHA-NI reproduces the
    # merkleRootMNList byte-for-byte vs the scalar transform (self-check input
    # unchanged), that a one-entry mutation still changes the root (poison
    # intact), and reports the scalar->SIMD speedup. Mirrors the
    # test_dash_simplifiedmns link set.
    add_executable(test_dash_sml_simd_sha256 test_dash_sml_simd_sha256.cpp)
    target_link_libraries(test_dash_sml_simd_sha256 PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_sml_simd_sha256 PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_sml_simd_sha256 "" AUTO)

    # Header-only LLMQ quorum-tail verification leaf over core/uint256 +
    # core/pack; no ltc/pool SCC dependency. Sits between the
    # SimplifiedMNList leaf (#309) and embedded_gbt main (S7).
    add_executable(test_dash_quorum test_dash_quorum.cpp)
    target_link_libraries(test_dash_quorum PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_quorum PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_quorum "" AUTO)

    # Header-only merkleRootQuorums (CbTx) computation leaf over the
    # QuorumManager active set; no ltc/pool SCC dependency. Sits between
    # the LLMQ quorum-tail leaf (#321) and embedded_gbt main (S7).
    add_executable(test_dash_quorum_root test_dash_quorum_root.cpp)
    target_link_libraries(test_dash_quorum_root PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_quorum_root PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_quorum_root "" AUTO)

    # Live-path ChainLock acquisition + verification KAT, against a REAL mainnet
    # ChainLock (tip 2515965) and the real LLMQ_400_60 candidate set.
    # DELIBERATELY *NOT* inside the C2POOL_DASH_BLS gate: the request-id, DKG-
    # window scan-set and quorum-SELECTION halves need no BLS backend, and they
    # are the pieces most likely to drift silently (in particular the memcmp-vs-
    # bignum score-ordering trap, which selects a DIFFERENT quorum if broken).
    # Those run in EVERY build; the BLS crypto KATs — including the tampered-
    # signature negative — are #ifdef C2POOL_DASH_BLS-gated in the source and
    # exercise only when the backend is linked. dash_bls_verify compiles
    # unconditionally (fail-closed stub without the backend), so this always links.
    # Second TU (#143 Variant B): test_dash_credit_pool_idx.cpp — the
    # CreditPool INDEX follower (credit_pool_idx.hpp): the CRangesSet port,
    # the dashd "plwdtx" request-id preimage, the era-laddered LimitAmount
    # arithmetic, the 576-block latelyUnlocked window, the per-block
    # cbTx-balance cross-check with fail-closed wipe, the CreditPoolIdxDb
    # R/w/C/S schema + restore adjudication, and the five task KATs
    # (flag-OFF byte-identity, gap⇒fail-closed, duplicate-index exclusion,
    # verified-sig inclusion + committed-balance exactness, tampered-sig
    # rejection). FOLDED into THIS target on purpose: it is the only
    # build.yml-allowlisted dash target that links dash_bls_verify (the
    # ARM-3 quorumSig verify needs the same VerifyInsecure port the
    # ChainLock KATs lock), and a new add_executable would be a NOT_BUILT
    # sentinel (#143 trap). The BLS-crypto halves (KAT 4/5 real-signature)
    # are #ifdef C2POOL_DASH_BLS — exercised by the linux-dash-bls leg; the
    # fold/schema/fail-closed halves run in EVERY build.
    add_executable(test_dash_chainlock_verify test_dash_chainlock_verify.cpp
                   test_dash_credit_pool_idx.cpp)
    target_link_libraries(test_dash_chainlock_verify PRIVATE
        GTest::gtest_main GTest::gtest
        dash_bls_verify dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_chainlock_verify PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_chainlock_verify "" AUTO)

    # G4 isdlock intake (acquire -> BLS-verify -> use, all fail-closed):
    #   * p2p::Handler REGISTRY membership gate (the DIP-24 qrinfo silent-drop
    #     failure mode; a de-registered isdlock fails RED here, not at DEBUG
    #     in production);
    #   * wire-codec KAT against hand-assembled dashd InstantSendLock bytes;
    #   * requestId KAT vs an INDEPENDENT digest + the ROTATED
    #     SelectQuorumForSigning arm (llmq_60_75) incl. upstream's shift quirk;
    #   * the G4 red/green: a VERIFIED isdlock through the REAL maintainer
    #     path excludes a conflicting tx from the selected template and keeps
    #     a non-conflicting one; no verifier / refusing verifier => no change;
    #   * BLS-gated (C2POOL_DASH_BLS): real threshold sig verifies end-to-end,
    #     every tampered bit is rejected and never reaches add_islock.
    # W5-B DSTX intake (acquire -> BLS-verify -> zero-fee prioritised
    # admission, all fail-closed):
    #   * p2p::Handler REGISTRY membership gate (the DIP-24 qrinfo
    #     silent-drop failure mode; a de-registered dstx fails RED here);
    #   * wire-codec KAT against hand-assembled dashd CCoinJoinBroadcastTx
    #     bytes + byte-exact re-encode;
    #   * GetSignatureHash pre-image KAT vs an INDEPENDENTLY hand-assembled
    #     byte stream (also pins pack(tx) network serialization);
    #   * IsValidStructure refusal matrix;
    #   * the USE red/green: plain zero-fee admission stays OUT (min-feerate
    #     floor, master's behaviour) vs the REAL verified maintainer path
    #     ranking it FIRST on the +0.1 COIN modified fee while total_fees
    #     stays BASE (coinbasevalue parity);
    #   * fail-closed: no verifier / bad BLS sig through the real
    #     verify_govvote_operator_sig entry point admits nothing.
    add_executable(test_dash_dstx test_dash_dstx.cpp)
    target_link_libraries(test_dash_dstx PRIVATE
        GTest::gtest_main GTest::gtest
        dash_block_replay   # full p2p Handler instantiation (registry gate)
        dash_bls_verify dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_dstx PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_dstx "" AUTO)

    add_executable(test_dash_isdlock test_dash_isdlock.cpp)
    target_link_libraries(test_dash_isdlock PRIVATE
        GTest::gtest_main GTest::gtest
        dash_block_replay   # full p2p Handler instantiation (registry gate)
                            # ODR-uses CBlockHeaderAndShortTxIDs::
                            # FillShortTxIDSelector(), same as test_dash_p2p_node
        dash_bls_verify dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_isdlock PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_isdlock "" AUTO)

    # KNOWN COVERAGE GAP (surfaced by the top-level drift-guard, #883 follow-up):
    # the three targets below are gated behind C2POOL_DASH_BLS, but no workflow
    # in .github/workflows/ enables that flag yet, so they are never built or run
    # in CI. Integrator decision 2026-07-26: restore coverage (fail-closed shape
    # kept). Coverage is being closed by PR #890 (ci/dash-bls-enable), which
    # builds+ships DASH with the real BLS backend linked. These exemptions are
    # SELF-RETIRING: remove all three in a one-line follow-up once #890 lands.
    # Do NOT remove them before then without adding an equivalent BLS-ON CI job.
    # ci-allowlist-exempt: test_dash_bls_verify  -- C2POOL_DASH_BLS-gated; coverage restored by PR #890 (ci/dash-bls-enable) — remove exemption when #890 lands
    # ci-allowlist-exempt: test_dash_quorum_members  -- C2POOL_DASH_BLS-gated; coverage restored by PR #890 (ci/dash-bls-enable) — remove exemption when #890 lands
    # ci-allowlist-exempt: test_dash_quorum_member_source  -- C2POOL_DASH_BLS-gated; coverage restored by PR #890 (ci/dash-bls-enable) — remove exemption when #890 lands
    if(C2POOL_DASH_BLS)  # gate the BLS-backend-requiring Phase-L test executables to the BLS-ON build
    # E1 Phase-L: type-6 quorum-commitment BLS verify KAT. Links dash_bls_verify
    # (which carries the C2POOL_DASH_BLS define + dashbls include/libs PUBLIC when
    # the backend was found; a fail-closed stub otherwise). The BuildCommitmentHash
    # byte-exactness + fail-closed KATs run in EVERY build; the BLS crypto KATs are
    # #ifdef C2POOL_DASH_BLS-gated in the source and only exercise when linked.
    add_executable(test_dash_bls_verify test_dash_bls_verify.cpp)
    target_link_libraries(test_dash_bls_verify PRIVATE
        GTest::gtest_main GTest::gtest
        dash_bls_verify core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_bls_verify PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_discover_tests(test_dash_bls_verify DISCOVERY_MODE PRE_TEST)

    # E1 Phase-L member-set selection: deterministic ComputeQuorumMembers over
    # the SML AS OF the WORK block (base - 8, per v23.1.7 GetAllQuorumMembers —
    # #814 review R2) reproduces dashd's exact ordered member set + operator
    # keys + legacy/basic scheme flag (llmq_50_60 AND the Evo-only llmq_25_67
    # platform type — #814 R4), the DIP-4 authentication legs check out against
    # real wire data (#814 R3), and the computed set makes #812's
    # verify_final_commitment ACCEPT the REAL from-wire commitments (the whole
    # point — real-commitment serving instead of null-serve).
    # Real testnet vectors in test/data/dash_quorum_members_kat.hpp. The member
    # selection + fail-closed + DIP-4 KATs run in EVERY build; the verify-accept
    # + partial-bitset KATs are #ifdef C2POOL_DASH_BLS-gated (same as bls_verify).
    add_executable(test_dash_quorum_members test_dash_quorum_members.cpp)
    target_link_libraries(test_dash_quorum_members PRIVATE
        GTest::gtest_main GTest::gtest
        dash_bls_verify core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_quorum_members PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_discover_tests(test_dash_quorum_members DISCOVERY_MODE PRE_TEST)

    # E1 Phase-L member-set SOURCING PLUMBING (quorum_member_source.hpp): the
    # #814 re-review findings — R1 send-once-per-work-block dedup + strict
    # consume (no duplicate replies leaking past the demux), R2 work-block
    # fetch incl. a churn-in-(base-8, base] vector, R3 DIP-4 tampered-snapshot
    # REJECT (the one serve-a-bad path), R4 platform sourcing via the Evo-only
    # filter, R5 null-CL fallback modifier with no walk-back, plus the request
    # guards (dkgInterval alignment, rotated refusal) and the pending reap.
    # Uses the same real testnet vectors end-to-end (dedup'd request -> real
    # snapshot -> dashd's exact member sets for BOTH shared-base types).
    add_executable(test_dash_quorum_member_source test_dash_quorum_member_source.cpp)
    target_link_libraries(test_dash_quorum_member_source PRIVATE
        GTest::gtest_main GTest::gtest
        dash_bls_verify core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_quorum_member_source PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_quorum_member_source "" AUTO)
    # R3 — governance-vote BLS operator-key verify KAT. Links dash_bls_verify
    # (the ONLY test that does): the real from-wire DELETE-signal vote verifies
    # against the real MN operator key; tamper/wrong-key/wrong-digest/wrong-size
    # reject; the synthetic end-to-end pins the fail-closed threshold ladder.
    # BLS-backend-gated like the three tests above: the crypto path needs the
    # dashbls backend, so it is declared inside C2POOL_DASH_BLS and built in the
    # linux-dash-bls leg. gtest_discover_tests PRE_TEST (not AUTO) discovers the
    # DashGovVoteBLS.* cases from the built binary at test time, so they are
    # never phantom-registered into the default-OFF build_ci leg -- the #818
    # drift that reddened Linux x86_64 (cases registered at configure time by
    # source-scan while the binary is never built, so ctest cannot find it).
    add_executable(test_dash_govvote_bls test_dash_govvote_bls.cpp)
    target_link_libraries(test_dash_govvote_bls PRIVATE
        GTest::gtest_main GTest::gtest
        dash_bls_verify
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_govvote_bls PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)
    gtest_discover_tests(test_dash_govvote_bls DISCOVERY_MODE PRE_TEST)

    endif()  # C2POOL_DASH_BLS: the BLS-crypto KATs need the dashbls backend (built in the linux-dash-bls job); skipped in the default OFF build

    # DASH masternode state-machine (S7 leaf): vendored ProTx wire
    # (providertx.hpp) + MNState persistence (mn_state_db.hpp) +
    # apply_block RebuildListFromBlock + find_expected_payee / pick_paid_mn
    # over the SimplifiedMNList leaf (#309). Last absent header before the
    # embedded_gbt capstone. Header-only over core/uint256 + core/pack +
    # core/hash; no ltc/pool SCC dependency.
    # Second TU (W1, dash/replay): test_dash_replay_fold.cpp — the DML fold
    # engine (replay_fold_engine.hpp): dashd RebuildListFromBlock transcription
    # KAT'd against REAL mainnet chain bytes (the h=2516756 PoSe REVIVE, the
    # h=2516412 case-D punish/ban, 4-block quiet sequence), the per-block
    # committed-cbTx-root self-check hard stop, and the versioned full-state
    # snapshot v3 (save/load/resume/fail-loud). FOLDED into this EXISTING
    # allowlisted target on purpose — a new add_executable would not be in the
    # build.yml --target list and would silently report "Not Run" (#143
    # NOT_BUILT trap). Needs dash_x11 for the block-identity hash — already in
    # this target's link set.
    # Third TU (W5, dash/replay): test_dash_replay_run.cpp — the Phase-1
    # replay PROVING harness. Data-driven and SKIPPED unless
    # C2POOL_REPLAY_PRESTATE + C2POOL_REPLAY_CORPUS are set, so it is inert in
    # CI; pointed at an anchor prestate and a contiguous block corpus it folds
    # the range and asserts the committed-cbTx-root equality at every block.
    # Fourth TU (THE SEAM): test_dash_replay_quorum_seam.cpp — W4's derived
    # quorum membership feeding W1's MembersFn (coin/replay_quorum_bridge.hpp):
    # the pre-anchor seed guards, the DIP-0024 cycle-2513088 derivation matched
    # against dashd's own `quorum info`, and h=2513130 (the height the first
    # live daemonless replay stopped at) folding to its own committed root
    # through the derived member sets.
    # Both folded into this SAME allowlisted target for the #143 NOT_BUILT
    # reason.
    # Fifth TU (THE SERVE SEAM): test_dash_replay_payee_publish.cpp — the
    # fold's root-checked masternode list feeding the PAYEE queue that gates
    # serving (coin/replay_payee_publish.hpp): the proven-current publish, the
    # ReplayMNState->MNState dialect change, and the fail-closed guard — a
    # diverged, poisoned, unchecked or behind-the-tip fold must NOT publish.
    # Same allowlisted target, same #143 NOT_BUILT reason.
    # Sixth TU (dashd evodb port): test_dash_mn_diff_store.cpp — the MN
    # diff/snapshot store (coin/mn_diff_store.hpp): the dmn_D4/dmn_S3
    # mechanism over ReplayMNState — CDeterministicMNStateDiff bitmask
    # semantics, BuildDiff/ApplyDiff refusals, the GetListForBlockInternal
    # backward-walk with the fail-closed missing-row inversion, 'F'
    # wipe-on-mismatch and the startup newest-pair verify. Same allowlisted
    # target, same #143 NOT_BUILT reason. Links leveldb (via core).
    # Seventh TU (OPTIONAL, default-OFF V20 getmnlistdiff seed):
    # test_dash_replay_mnlist_seed.cpp — the path-ii escape hatch for #154
    # (mnlist_seed.hpp). Proves the arming policy (source must be
    # "getmnlistdiff", height required and >= the V20 floor, file required,
    # height/network must match the snapshot) and the REUSED reward-safety root
    # gate (seed_engine_from_prestate): a valid getmnlistdiff seed loads +
    # verifies + is fold-ready at H, and a seed whose committed root != computed
    # FAILS CLOSED. Folded into this SAME allowlisted target for the #143/#769
    # NOT_BUILT reason (a standalone add_executable is not in build.yml's
    # --target list and would silently report "Not Run").
    add_executable(test_dash_mn_state test_dash_mn_state.cpp
                   test_dash_mn_diff_store.cpp
                   test_dash_replay_fold.cpp
                   test_dash_replay_run.cpp
                   test_dash_replay_quorum_seam.cpp
                   test_dash_replay_payee_publish.cpp
                   test_dash_replay_mnlist_seed.cpp)
    target_link_libraries(test_dash_mn_state PRIVATE
        GTest::gtest_main GTest::gtest
        dash_bls_verify dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_mn_state PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    # The seam TU's issue-#90 arming KAT seeds the mainnet anchor's full
    # 88-commitment active set from dash_mainnet_active_quorums_2513685.txt —
    # the same fixture the W4 engine suite uses. Test-only define; no source
    # in this target reads it otherwise.
    target_compile_definitions(test_dash_mn_state PRIVATE
        DASH_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
    gtest_add_tests(test_dash_mn_state "" AUTO)

    # DASH embedded getblocktemplate bit-parity capstone (S7 main): fuses the
    # landed S7 leaves -- subsidy.hpp + mempool get_sorted_txs_with_fees +
    # mn_state_machine find_expected_payee/script_to_address payee projection +
    # DIP-0027 platform-burn ordering + the CCbTx (merkleRootMNList /
    # merkleRootQuorums / bestCL* / creditPool) wire encoder, plus the
    # gbt_xcheck / cbtx_xcheck dashd-RPC cross-check comparators. Oracle =
    # frstrtr/p2pool-dash getwork (pre-v35). Header-only over the dash leaves +
    # core (links core for script_to_address in address_utils.cpp). Last S7
    # capstone; node-backed end-to-end parity deferred to a live-harness leaf.
    #
    # CI-fold (build.yml "Build tests" allowlists this target but not the extra
    # byte-parity/oracle-shadow executables): the real-dashd CbTx byte-parity +
    # from-wire merkle-root parity proofs AND the embedded oracle-shadow
    # validator KATs are COMPILED INTO this already-built+CI-run executable
    # (distinct TEST() suites), so they actually run in CI. The oracle-shadow
    # fold also avoids a new build.yml --target (push bot lacks `workflow` scope
    # -> a standalone target would be a NOT_BUILT sentinel). Do NOT re-add
    # standalone add_executable/gtest_add_tests for any of them — CTest would
    # register unbuilt executables (ctest "Not Run" exit 8, the Linux x86_64 red).
    # DASH_FIXTURE_DIR is needed by the from-wire fixture loader (mnlistdiff)
    # and by the qrinfo / rotated-quorum suites, which read the real 602'189-byte
    # testnet qrinfo capture. test_dash_rotated_quorum_members.cpp is folded here
    # for the same reason as test_dash_qrinfo.cpp: this target IS in the build.yml
    # "Build tests" --target allowlist, and a standalone target would be a
    # NOT_BUILT sentinel (the push bot lacks `workflow` scope, #769).
    # test_dash_mn_confirm_rollover.cpp / test_dash_collateral_spend_filter.cpp
    # (sml_projection.hpp): the two silent block-loss defects of the committed
    # merkleRootMNList — the height-driven confirmedHash rollover
    # (specialtxman.cpp:206-215) and MN-collateral spends by normal type-0 txs
    # (specialtxman.cpp:457-464). Folded here for the same reason as the other
    # leaves above: this target IS in the build.yml "Build tests" --target
    # allowlist, and a standalone target would be a NOT_BUILT sentinel (#769).
    add_executable(test_dash_embedded_gbt
        test_dash_embedded_gbt.cpp
        test_dash_embedded_cbtx_byte_parity.cpp
        test_dash_mnlistdiff_root_parity.cpp
        test_dash_qrinfo.cpp
        test_dash_rotated_quorum_members.cpp
        test_dash_dkg_commitments.cpp
        test_dash_qc_episode_classifier.cpp
        test_dash_sml_quorum_db.cpp
        test_dash_embedded_oracle_shadow.cpp
        test_dash_embedded_shadow_compare.cpp
        test_dash_mn_confirm_rollover.cpp
        test_dash_collateral_spend_filter.cpp
        # test_dash_root_memo.cpp: D2 of the 2026-08-07/08 hotel freeze —
        # NodeCoinState-level memo of the projected-SML root + quorum root
        # (epoch-invalidated). Pins: warm emit_ok does no hashing (T1),
        # any SML/quorum mutation invalidates (T2 — the stale-root/lost-
        # block pin), memoized == fresh byte-for-byte (T3). Folded here per
        # the same #769 rule as the rollover suite above.
        test_dash_root_memo.cpp
        # test_dash_operator_split.cpp: incident h=2516595 bad-cb-payee — the
        # MN operator-reward split KATs (builder dual-output + serve-gate
        # cause=mn-payout-split-unprovable + ResetOperatorFields mirror +
        # pass-3 split observation). Folded here per the same #769 rule.
        test_dash_operator_split.cpp
        # test_dash_replay_quorum_engine.cpp: W4 of the FULL-HISTORY REPLAY
        # mode (replay_quorum_engine.hpp) — quorum state from replayed mined
        # qfcommits: 3101-block mainnet merkleRootQuorums byte-parity replay
        # (dash_mainnet_quorum_scan_* + dash_mainnet_active_quorums_*),
        # rotated-member + snapshot-PRODUCER KATs against a real mainnet
        # qrinfo (dash_mainnet_qrinfo_2516785.bin) and dashd's own `quorum
        # info` member lists. Folded here per the same #769 rule; reads
        # DASH_FIXTURE_DIR.
        test_dash_replay_quorum_engine.cpp
        # test_dash_mined_commitment_index.cpp: PR-2 FORWARD
        # (mined_commitment_index.hpp) — dashd's mined-commitment store
        # (v23.1.7 llmq/blockprocessor.cpp ProcessBlock/ProcessCommitment/
        # HasMinedCommitment/GetMinedCommitmentsUntilBlock) rebuilt from OUR
        # OWN block replay: 3101-block mainnet merkleRootQuorums byte-parity
        # over the DERIVED active set, plus the arm/contiguity/null-skip
        # guards and the money-path has_mined seam. Reuses the same
        # dash_mainnet_quorum_scan_* / _active_quorums_ fixtures as the W4
        # suite above, and is folded into this target for the same #769
        # reason (the push bot cannot add a build.yml --target).
        test_dash_mined_commitment_index.cpp)
    target_compile_definitions(test_dash_embedded_gbt PRIVATE
        DASH_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
    target_link_libraries(test_dash_embedded_gbt PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_embedded_gbt PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_embedded_gbt "" AUTO)

    # DASH underfill guard: port of the LTC/DOGE "near-empty template on a
    # non-empty mempool" template-builder guard to the DASH embedded GBT path
    # (embedded_gbt.hpp), for the mining-hotel deployment. Predicate KATs at
    # the pinned 50 kB floor/slack + build_embedded_workdata wiring via the
    # SAFE-ADDITIVE underfill_tripped seam (log-only guard; masternode
    # burn/payee projection asserted unchanged). Same link set as the
    # embedded_gbt capstone.
    add_executable(test_dash_underfill_guard test_dash_underfill_guard.cpp)
    target_link_libraries(test_dash_underfill_guard PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_underfill_guard PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_underfill_guard "" AUTO)

    # BTC underfill guard: port of the LTC/DOGE "near-empty template on a
    # non-empty mempool" template-builder guard to the BTC embedded template
    # path (src/impl/btc/coin/template_builder.hpp). Predicate KATs at the
    # pinned 50 kB floor/slack + build_template wiring via the SAFE-ADDITIVE
    # underfill_tripped seam (log-only guard; GBT projection asserted
    # unchanged). Chain fixture = in-memory fast-start checkpoint (the BCH
    # embedded_getwork_test shape). Link set mirrors test_template_builder
    # (the LTC twin) with the btc OBJECT libs. MUST also be in the build.yml
    # --target allowlist or CTest reports a NOT_BUILT sentinel.
    add_executable(test_btc_underfill_guard test_btc_underfill_guard.cpp)
    target_link_libraries(test_btc_underfill_guard PRIVATE
        GTest::gtest_main GTest::gtest
        core btc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_btc_underfill_guard PRIVATE btc_stratum c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage btc_coin btclibs pool sharechain ${SECP256K1_LIBRARIES})  # OBJECT-lib SCC direct-naming (#22/#39), btc twin; btc_stratum owns BTCWorkSource (zombie-reap opt-in KAT)
    gtest_add_tests(test_btc_underfill_guard "" AUTO)

    # DGB underfill guard: same LTC/DOGE guard ported to the DGB embedded
    # template path. DGB's build_work_template() is a pure shaper with no
    # mempool access, so the guard evaluates in make_mempool_tx_source()
    # (coin/embedded_tx_select.cpp) — the one mempool-visible point feeding
    # BOTH template callers (stratum work source + EmbeddedCoinNode);
    # predicate/thresholds pinned in coin/template_builder.hpp. Compiles the
    # tx serialization codec, so it links the same proven SCC set as
    # dgb_embedded_tx_select_test. MUST also be in the build.yml --target
    # allowlist or CTest reports a NOT_BUILT sentinel.
    add_executable(test_dgb_underfill_guard test_dgb_underfill_guard.cpp)
    target_link_libraries(test_dgb_underfill_guard PRIVATE
        GTest::gtest_main GTest::gtest
        core dgb dgb_stratum
        c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage
        dgb_coin pool sharechain
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    gtest_add_tests(test_dgb_underfill_guard "" AUTO)

    # BCH underfill guard: same LTC/DOGE guard ported to the BCH embedded
    # template path (src/impl/bch/coin/template_builder.hpp; ABLA floor
    # sizelimit + CTOR body asserted unchanged when the guard trips). Gated on
    # COIN_BCH exactly like the bch_coin library it links (src/impl/bch is a
    # -DCOIN_BCH=ON leg; the target cannot exist outside it). MUST also be in
    # the build.yml BCH-leg --target allowlist or CTest reports a NOT_BUILT
    # sentinel.
    if(COIN_BCH)
        add_executable(test_bch_underfill_guard test_bch_underfill_guard.cpp)
        target_link_libraries(test_bch_underfill_guard PRIVATE
            GTest::gtest_main GTest::gtest
            core bch_coin
            nlohmann_json::nlohmann_json
            ${Boost_LIBRARIES}
        )
        target_link_libraries(test_bch_underfill_guard PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage btclibs pool sharechain)  # OBJECT-lib SCC direct-naming (#22/#39)
        gtest_add_tests(test_bch_underfill_guard "" AUTO)
    endif()

    # DASH embedded-vs-dashd work-source selector (S8 embedded_gbt live-wire
    # capstone): select_dash_work() prefers the locally-assembled embedded
    # template (build_embedded_workdata) and falls back to dashd
    # getblocktemplate when the coin-state bundle is not viable. Routing +
    # retained-fallback KAT; harness-free (embedded builder injected as a stub,
    # oracle-parity already pinned by test_dash_embedded_gbt). Same link set as
    # the embedded_gbt capstone (work_source.hpp includes embedded_gbt.hpp).
    add_executable(test_dash_work_source test_dash_work_source.cpp)
    target_link_libraries(test_dash_work_source PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_work_source PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_work_source "" AUTO)

    # NodeCoinState: node-held embedded coin-state holder over the
    # work_source selector link set (mn_state_machine + mempool header-only);
    # no ltc/pool SCC dependency. Mirrors the test_dash_work_source link set.
    # D-DASH.ORACLE-OWNERSHIP rides this EXISTING allowlisted target rather than
    # a new add_executable — a fresh target absent from the build.yml --target
    # allowlist becomes the silently-passing NOT_BUILT sentinel (#143). It is a
    # source-structural guard over embedded_oracle_shadow.hpp + main_dash.cpp,
    # so it needs no link deps of its own; the compile definitions hand it the
    # paths to the SHIPPED sources.
    # D-DASH.WORKSOURCE-OWNERSHIP (#1134) is its SERVE-path sibling and rides the
    # same target for the same reason — it guards stratum/work_source.{cpp,hpp}
    # by source text, so it adds no link deps either.
    # D-DASH.SML-RESYNC rides it too (#143): the watchdog is header-only over
    # core/uint256.hpp, so it adds no link deps either.
    add_executable(test_dash_node_coin_state
        test_dash_node_coin_state.cpp
        test_dash_oracle_shadow_ownership.cpp
        test_dash_work_source_ownership.cpp
        test_dash_sml_resync_watchdog.cpp)
    target_link_libraries(test_dash_node_coin_state PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_node_coin_state PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    target_compile_definitions(test_dash_node_coin_state PRIVATE
        DASH_ORACLE_SHADOW_SRC="${CMAKE_CURRENT_SOURCE_DIR}/../src/impl/dash/coin/embedded_oracle_shadow.hpp"
        DASH_MAIN_SRC="${CMAKE_CURRENT_SOURCE_DIR}/../src/c2pool/main_dash.cpp"
        DASH_WORK_SOURCE_SRC="${CMAKE_CURRENT_SOURCE_DIR}/../src/impl/dash/stratum/work_source.cpp"
        DASH_WORK_SOURCE_HDR="${CMAKE_CURRENT_SOURCE_DIR}/../src/impl/dash/stratum/work_source.hpp")
    gtest_add_tests(test_dash_node_coin_state "" AUTO)

    # bestCL template gate: dashcore's CheckCbTxBestChainlock rule (consensus-
    # exact) vs the original freshness proxy, plus the fail-closed fences
    # (missing prev-block committed CL, unverified advance, unjustified
    # provenance). DELIBERATELY NOT BLS-gated: the gate is a pure state
    # decision over heights + provenance and must be exercised on EVERY build,
    # including a BLS-dark one — proving the relaxation cannot degenerate into
    # a no-op there is the whole point of two of its cases. Same header-only
    # link set as test_dash_node_coin_state.
    add_executable(test_dash_bestcl_gate test_dash_bestcl_gate.cpp)
    target_link_libraries(test_dash_bestcl_gate PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_bestcl_gate PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_bestcl_gate "" AUTO)

    # DASHWorkSource (dash::stratum): concrete core::stratum::IWorkSource for
    # DASH X11 -- 4b construction + contract KAT. Links the dash_stratum OBJECT
    # lib (work_source.cpp) on top of the header-only coin selector link set.
    # Includes coin/zmq_tip_notify.cpp directly (NOT the C2POOL_ZMQ-guarded
    # subscriber — only the pure TipHashDedup / frame-decode helpers) so the
    # ZMQ hashblock instant-tip-notify KAT links without libzmq.
    # SERVE-STALENESS SENTINEL rides this EXISTING allowlisted target rather
    # than adding two of its own: a fresh add_executable absent from the
    # build.yml --target allowlist is the #143 NOT_BUILT sentinel that "passes"
    # by never being built (same reasoning as test_dash_node_coin_state above).
    #   * ..._seam.cpp   -- the RED witness: compiles on master, fails there,
    #                       because nothing publishes a serve_staleness block.
    #   * ..._unit.cpp   -- the detector itself, driven off injected clock and
    #                       height providers, including the deleted-guard
    #                       mutation case.
    add_executable(test_dash_stratum_work_source
        test_dash_stratum_work_source.cpp
        # test_dash_tx_serve_referee.cpp: internal-consistency referee unit KAT
        # (tx_serve_referee.hpp). Folded into this already-built target (it links
        # the full dash_stratum set the referee header needs) per the #769 rule.
        test_dash_tx_serve_referee.cpp
        test_dash_submit_gate_scaling.cpp
        test_dash_serve_staleness_seam.cpp
        test_dash_serve_staleness_unit.cpp
        test_dash_gbt_quorum_staleness.cpp
        ${CMAKE_SOURCE_DIR}/src/impl/dash/coin/zmq_tip_notify.cpp)
    target_link_libraries(test_dash_stratum_work_source PRIVATE
        GTest::gtest_main GTest::gtest
        dash_stratum dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_stratum_work_source PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    target_compile_definitions(test_dash_stratum_work_source PRIVATE
        DASH_WORK_SOURCE_SRC="${CMAKE_CURRENT_SOURCE_DIR}/../src/impl/dash/stratum/work_source.cpp"
        DASH_MAIN_SRC="${CMAKE_CURRENT_SOURCE_DIR}/../src/c2pool/main_dash.cpp")
    gtest_add_tests(test_dash_stratum_work_source "" AUTO)

    # CoinStateMaintainer: drives NodeCoinState off async tip/MN/mempool update
    # events (readiness gate: MN+tip required before publish). Same link set as
    # test_dash_node_coin_state -- header-only over the work_source selector set.
    # Second TU: test_dash_mn_gap_repair.cpp — the diff-store gap-repair seam
    # (mn_gap_repair.hpp) at its money-path caller: an APPLY GAP against a
    # MOVING tip repaired from real MnDiffStore rows byte-identical to a
    # contiguous fold; the unrepairable-gap fail-closed floor (wipe + demote +
    # re-seed ask) unchanged; and the consumer half of the G7 split (below-tip
    # seed catch-up / refusal-to-arm). Links leveldb via core.
    # Third TU (PR-C3): test_dash_connectblock_ordering.cpp — the ConnectBlock
    # fold-before-publish ordering guard at the NodeCoinState::set_tip seam
    # (flag default-OFF, byte-identical master when off). Folded into this
    # ALREADY-ALLOWLISTED target rather than a fresh add_executable so it is
    # actually built + run in CI: a new target absent from the build.yml
    # --target list is the #143 NOT_BUILT sentinel that "passes" by never
    # being compiled. It is header-only over node_coin_state.hpp, so it adds no
    # link deps beyond this target's existing set.
    add_executable(test_dash_coin_state_maintainer test_dash_coin_state_maintainer.cpp
                   test_dash_mn_gap_repair.cpp
                   test_dash_connectblock_ordering.cpp)
    target_link_libraries(test_dash_coin_state_maintainer PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_coin_state_maintainer PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_coin_state_maintainer "" AUTO)

    # NodeImpl embedded coin-state HOLD KAT -- constructs a real NodeImpl, so
    # it links the full node object set (pool + storage), NOT just the
    # header-only coin-state libs the two suites above use.
    add_executable(test_dash_node_embedded_wire test_dash_node_embedded_wire.cpp)
    target_link_libraries(test_dash_node_embedded_wire PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_node_embedded_wire PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining c2pool_storage pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    # #950: handle_version() in node.hpp now calls NodeImpl::send_standing_remember,
    # whose definition lives in node.cpp — the same shape as #889 on
    # test_dash_node above. A target that includes node.hpp and instantiates the
    # handler must link the `dash` OBJECT lib or the reference is undefined at
    # link time. `dash`'s own deps are already on this line or arrive
    # transitively; nothing outside src/impl/dash is added.
    target_link_libraries(test_dash_node_embedded_wire PRIVATE dash sharechain)
    gtest_add_tests(test_dash_node_embedded_wire "" AUTO)
    # get_work() consumer capstone: fuses NodeCoinState::select_work() (embedded
    # template source) with assemble_work_job_targets(); same OBJECT-lib SCC.
    add_executable(test_dash_get_work test_dash_get_work.cpp)
    target_link_libraries(test_dash_get_work PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_get_work PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining c2pool_storage pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    # #950: every target that includes node.hpp and instantiates handle_version
    # links NodeImpl::send_standing_remember, defined in node.cpp — see the
    # test_dash_node_embedded_wire note above and the #889 precedent. Targets
    # that only type-check against the header do not need this; these do.
    target_link_libraries(test_dash_get_work PRIVATE dash sharechain)
    gtest_add_tests(test_dash_get_work "" AUTO)

    # Reception wire (legs 1-3): interfaces::Node reception Events ->
    # CoinStateMaintainer. Proves the wire_*_ingest() subscriptions fold off the
    # real Events (no direct poke), honour dispose(), and reach the embedded
    # template. Same header-only link set as the maintainer suite (no NodeImpl
    # -> no pool/storage dep).
    # Second TU (E2a): test_dash_live_feed_bridge.cpp — the live-feed bridge
    # (live_feed.hpp) translating raw coin-P2P wire events into the derived
    # ingest events (new_headers->HeaderChain, full_block->block_connected) + the
    # pure tip_advance_from_chain gate. Same target/link set; no new allowlist.
    # Third TU (E2c): test_dash_mn_seed.cpp — the RPC protx-list MN-set seed
    # (mn_seed.hpp): payoutAddress->scriptPayout byte-exact round trip,
    # fail-closed abort on undecodable payees, and the seed->leg-4-event->
    # populated()-flips->embedded-template-pays-the-correct-MN capstone. Same
    # target/link set (core already carries address_utils); no new allowlist.
    # Fourth TU (E2d): test_dash_mn_checkpoint.cpp — the release-pinned MN-set
    # checkpoint (mn_checkpoint.hpp) + its forward-replay bridge
    # (mn_checkpoint_lane.hpp): format/digest/fail-closed parsing, equivalence
    # with the E2c RPC seed on the same captured dashd JSON, the real
    # 1519544..1519546 replay, every terminal fail-closed path, and the
    # end-to-end publish -> leg-4 -> populated() flip with negative controls.
    # FOLDED into this EXISTING allowlisted target on purpose — a new
    # add_executable would not be in the build.yml --target list and would
    # silently report "Not Run" (#143 NOT_BUILT trap). No #ifdef guards in that
    # TU either, so every registered case actually executes (#895).
    # Fifth TU: test_dash_lane_diag.cpp — the embedded/replay DIAGNOSTIC
    # primitives (coin/lane_diag.hpp) plus the two lane-level properties they
    # exist for: the progress throttle never degenerates to a per-block flood,
    # and the stall watchdog fires from a path pump() CANNOT skip (the
    # 2026-08-04 11-12 minute silent freeze on .211 and contabo, where the
    # probe sat below the early-return that the freeze itself produced). Also
    # pins masternode-list SOURCE attribution end-to-end through the leg-4
    # event. FOLDED into this EXISTING allowlisted target for the same reason
    # the E2d TU was: a new add_executable would not be in the build.yml
    # --target list and would silently report "Not Run" (#143 NOT_BUILT trap).
    # test_dash_154_parity_kat.cpp — the #154 byte-parity KATs: the golden
    # self-derived checkpoint at 2522504 (2991 registered MNs) parses + digest,
    # and the V20 hash-modifier off-by-8 (pre/post-V20 form selected by the WORK
    # block's deployment state). BLS-independent (the opkey point-compare KAT is
    # in test_dash_bls_verify.cpp), so it links with THIS target's dash_x11+core
    # set and is folded here for the same #143/#769 NOT_BUILT reason as the E2d
    # checkpoint TU above (a standalone add_executable is not in build.yml's
    # --target list and would silently report "Not Run").
    add_executable(test_dash_node_reception_wire test_dash_node_reception_wire.cpp
                   test_dash_live_feed_bridge.cpp
                   test_dash_mn_seed.cpp
                   test_dash_mn_checkpoint.cpp
                   test_dash_154_parity_kat.cpp
                   test_dash_lane_diag.cpp
                   test_dash_header_checkpoint_coincide.cpp
                   test_dash_anchor_header_merkle_root.cpp)
    target_link_libraries(test_dash_node_reception_wire PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_node_reception_wire PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_node_reception_wire "" AUTO)

    # DASH CSimplifiedMNListDiff (mnlistdiff wire, S8.1 leaf): vendored diff
    # round-trip + dashcore field-layout pin + apply_diff semantics. Header-only
    # over the SimplifiedMNList leaf + coin/transaction; no ltc/pool SCC dep.
    # Feeds the embedded_gbt SML-update path (S8 block-submission lane).
    add_executable(test_dash_smldiff test_dash_smldiff.cpp)
    target_link_libraries(test_dash_smldiff PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_smldiff PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_smldiff "" AUTO)

    # Dash coin-daemon P2P wire-message KATs (S8 block-submission lane). Pins
    # the Dash-only messages (block/headers/clsig/getmnlistd/mnlistdiff) atop
    # the smldiff leaf; no ltc/pool SCC dep beyond the OBJECT libs.
    add_executable(test_dash_p2p_messages test_dash_p2p_messages.cpp)
    target_link_libraries(test_dash_p2p_messages PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_p2p_messages PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_p2p_messages "" AUTO)
    add_executable(test_dash_poolnode_messages test_dash_poolnode_messages.cpp)
    target_link_libraries(test_dash_poolnode_messages PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_poolnode_messages PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_poolnode_messages "" AUTO)

    add_executable(test_dash_p2p_connection test_dash_p2p_connection.cpp)
    target_link_libraries(test_dash_p2p_connection PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_p2p_connection PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_p2p_connection "" AUTO)

    # Dash coin-daemon P2P node (S8 socket-node skeleton leaf). Pins the node
    # lifecycle (attach/teardown), the outbound-request->inbound-reply exchange
    # through Connection, and the real-timer idle-timeout path. Header-only over
    # the dash_x11 + core link set; same set as the p2p_connection leaf.
    # Second TU (E1): test_dash_coin_p2p_client.cpp — the OPT-IN outbound-dial
    # client (p2p_client.hpp): handshake state machine, dial-plan rotation, and
    # the byte-exact version/verack handshake drive. Same target, no new
    # allowlist entry needed.
    # Third TU: test_dash_coin_peer_manager.cpp — the DASH-ISOLATED CoinPeerManager
    # (coin/coin_peer_manager.hpp): source scoring (daemon penalty / addr-crawl
    # bonus), selection ordering, /16 Sybil group caps, anchor persistence, and
    # the pinned protected local node. Same target, no new allowlist entry.
    # Fourth and fifth TUs on this target:
    #  * test_dash_coin_p2p_pool.cpp — the MULTI-PEER POOL: concurrency, per-peer
    #    state isolation (a pong from one peer must never close another's ping),
    #    independent reaping, inv fan-in collapsing to ONE getdata, the BOUNDED
    #    dedup set proven by eviction, refill after a loss, broadcast relay.
    #  * test_dash_qrinfo_wire.cpp — the DIP-24 rotated lane driven from RAW WIRE
    #    BYTES through p2p::Handler::parse() into QuorumMemberSource.
    # THIS TARGET, not test_dash_embedded_gbt: the qrinfo gate is Handler REGISTRY
    # membership, which needs the full p2p Handler instantiated, which ODR-uses
    # CBlockHeaderAndShortTxIDs::FillShortTxIDSelector() out of dash_block_replay
    # — only linked here. No new build.yml --target entry needed (test_dash_p2p_node
    # is already allowlisted; the push bot lacks `workflow` scope, #769, so a
    # standalone target would be a NOT_BUILT sentinel).
    # Sixth TU: test_dash_coin_peer_rearm.cpp — the emergency seed RE-ARM
    # (never-re-arm defect fix): saturating exponential backoff schedule/floor/
    # overflow, the single-latch re-entry guard (N ticks -> one re-arm), and the
    # recovery reset. Same target, no new allowlist entry.
    # Seventh TU: test_dash_replay_bulk_fetch.cpp — the W2 FULL-HISTORY REPLAY
    # bulk block-fetch lane (coin/replay_bulk_fetch.hpp): multi-peer range
    # partitioning, timeout/notfound/peer-loss re-request, in-order
    # deliver-then-PRUNE into the W1 consumer seam, merkle-bind rejection,
    # tip-lane strict priority, resumable cursor (verified hash, fail-closed
    # mismatch), genesis→anchor header-backfill join, capture segment cache.
    # Same target, no new allowlist entry.
    # DASH_FIXTURE_DIR: the wire suite replays the real 602'189-byte testnet capture.
    # Eighth TU: test_dash_spork.cpp — the SPORK listener (registry-membership
    # gate per the qrinfo #1077 rule + signature verification vs the
    # chainparams spork key + assume-active SporkState). Folded here for the
    # same #769 reason as every TU above: this target IS in the build.yml
    # "Build tests" --target allowlist, and a standalone target would be a
    # NOT_BUILT sentinel.
    # Ninth TU: test_dash_bulk_local_primary_kat.cpp — #154 daemonless bulk-fetch
    # dashd-parity KAT (LEVER 1 protected-local primary stays bulk-eligible +
    # LEVER 2 throughput-weighted per-peer inflight). Folded here for the same
    # #769 reason as every TU above: this target IS in the build.yml "Build tests"
    # --target allowlist AND already compiles coin/replay_bulk_fetch.hpp, so its
    # link set resolves BulkBlockScheduler/bulkpolicy with no new deps; a
    # standalone executable was a NOT_BUILT/"Not Run" CTest sentinel.
    add_executable(test_dash_p2p_node test_dash_p2p_node.cpp test_dash_coin_p2p_client.cpp test_dash_coin_peer_manager.cpp test_dash_coin_p2p_pool.cpp test_dash_qrinfo_wire.cpp test_dash_coin_peer_rearm.cpp test_dash_replay_bulk_fetch.cpp test_dash_spork.cpp test_dash_bulk_local_primary_kat.cpp)
    target_compile_definitions(test_dash_p2p_node PRIVATE
        DASH_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
    target_link_libraries(test_dash_p2p_node PRIVATE
        GTest::gtest_main GTest::gtest
        dash_block_replay   # E1: coin/vendor/blockencodings.cpp — the full p2p Handler
                            # (cmpctblock codec) the CoinClient instantiates ODR-uses
                            # CBlockHeaderAndShortTxIDs::FillShortTxIDSelector().
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_p2p_node PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_p2p_node "" AUTO)

    add_executable(test_dash_node_interface test_dash_node_interface.cpp)
    target_link_libraries(test_dash_node_interface PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_node_interface PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_node_interface "" AUTO)

    add_executable(test_dash_config test_dash_config.cpp)
    target_link_libraries(test_dash_config PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_config PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_config "" AUTO)

    # DASH v36-native MINT-side accept-floor auto-ratchet (#357 gap-closer, FENCED/
    # UNWIRED). Pins the pure dash::ratchet_min_protocol_version + the full-window
    # apply_min_protocol_ratchet_decision guard, and the weighted-vs-plain-count
    # divergence assert. Header-only over core (uint288); mirrors the test_dash_config
    # link set.
    add_executable(test_dash_auto_ratchet test_dash_auto_ratchet.cpp)
    target_link_libraries(test_dash_auto_ratchet PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_auto_ratchet PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining c2pool_storage pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    # #950: every target that includes node.hpp and instantiates handle_version
    # links NodeImpl::send_standing_remember, defined in node.cpp — see the
    # test_dash_node_embedded_wire note above and the #889 precedent. Targets
    # that only type-check against the header do not need this; these do.
    target_link_libraries(test_dash_auto_ratchet PRIVATE dash sharechain)
    gtest_add_tests(test_dash_auto_ratchet "" AUTO)

    add_executable(test_dash_peer test_dash_peer.cpp)
    target_link_libraries(test_dash_peer PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_peer PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_peer "" AUTO)

    # additive: pure persisted activation-latch (header-only version_activation_latch.hpp);
    # mirrors the test_dash_config link set (nlohmann_json + core), no ltc/pool SCC dependency.
    add_executable(test_dash_version_activation_latch test_dash_version_activation_latch.cpp)
    target_link_libraries(test_dash_version_activation_latch PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_version_activation_latch PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_version_activation_latch "" AUTO)

    # additive: C-startup-invariant (header-only embedded_startup_invariant.hpp);
    # pure predicate over startup booleans, GTest-only, no coin/pool SCC dependency.
    add_executable(test_dash_embedded_startup_invariant test_dash_embedded_startup_invariant.cpp)
    target_link_libraries(test_dash_embedded_startup_invariant PRIVATE
        GTest::gtest_main GTest::gtest)
    gtest_add_tests(test_dash_embedded_startup_invariant "" AUTO)

    add_executable(test_dash_donation_combined test_dash_donation_combined.cpp)
    target_link_libraries(test_dash_donation_combined PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_donation_combined PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_donation_combined "" AUTO)

    add_executable(test_dash_broadcaster test_dash_broadcaster.cpp)
    target_link_libraries(test_dash_broadcaster PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_broadcaster PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_broadcaster "" AUTO)
    # DASH external-dashd-RPC request-shape guard (launcher slice 3). Pins the
    # oracle-conformed RPC contract: version-floor + the DASH<->DGB GBT
    # divergence (X11 / no segwit -> NO algo param, NO injected segwit rule) +
    # the DASH genesis-identity hashes. Header-only over coin/rpc_request.hpp;
    # links ONLY gtest + nlohmann (no boost::beast/jsonrpccxx transport), like
    # the dgb rpc_request_test guard. MUST appear in BOTH this registration AND
    # the build.yml --target allowlists (#143 NOT_BUILT trap).
    add_executable(test_dash_rpc_request test_dash_rpc_request.cpp)
    target_link_libraries(test_dash_rpc_request PRIVATE
        GTest::gtest_main GTest::gtest
        nlohmann_json::nlohmann_json)
    gtest_add_tests(test_dash_rpc_request "" AUTO)

    # test_dash_won_block_dualpath.cpp is FOLDED into this already-allowlisted
    # target (was a standalone test_dash_won_block_dualpath executable that CI's
    # build.yml --target allowlist never built -> NOT_BUILT/CTest "Could not find
    # executable" red). Separate TU, own anon namespace + distinct
    # DashWonBlockDualPath suite, gtest_main-provided main() -> no symbol clash.
    add_executable(test_dash_broadcaster_full test_dash_broadcaster_full.cpp test_dash_won_block_dualpath.cpp test_dash_won_block_dispatch.cpp)
    target_link_libraries(test_dash_broadcaster_full PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_broadcaster_full PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_broadcaster_full "" AUTO)

    add_executable(test_dash_g3_assembled test_dash_g3_assembled.cpp)
    target_link_libraries(test_dash_g3_assembled PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_g3_assembled PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_g3_assembled "" AUTO)

    add_executable(test_dash_block_relay test_dash_block_relay.cpp)
    target_link_libraries(test_dash_block_relay PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_block_relay PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_block_relay "" AUTO)

    add_executable(test_dash_embedded_relay_e2e test_dash_embedded_relay_e2e.cpp)
    target_link_libraries(test_dash_embedded_relay_e2e PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_embedded_relay_e2e PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_embedded_relay_e2e "" AUTO)

    # DASH block PRODUCER KAT (launcher slice 5): merkle fold + compact-bits
    # target + full-block serialize + X11 nonce search (block_producer.hpp).
    # Network-free; builds a real coinbase via coinbase_builder over the
    # dash_x11 + core link set. Mirrors the test_dash_conformance link set;
    # MUST appear in BOTH this registration AND the build.yml --target lists.
    add_executable(test_dash_block_producer test_dash_block_producer.cpp)
    target_link_libraries(test_dash_block_producer PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_block_producer PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_block_producer "" AUTO)
    add_executable(test_dash_block_relay_plan test_dash_block_relay_plan.cpp)
    target_link_libraries(test_dash_block_relay_plan PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_block_relay_plan PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_block_relay_plan "" AUTO)
    add_executable(test_dash_block_relay_binding test_dash_block_relay_binding.cpp)
    target_link_libraries(test_dash_block_relay_binding PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_block_relay_binding PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_block_relay_binding "" AUTO)

    add_executable(test_dash_block_relay_dual_arm test_dash_block_relay_dual_arm.cpp)
    target_link_libraries(test_dash_block_relay_dual_arm PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_block_relay_dual_arm PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_block_relay_dual_arm "" AUTO)

    # S8 broadcaster dual-path GATE KAT: one forced won block fans out down BOTH
    # arms (embedded P2P primary + submitblock RPC backup) byte-identically, and
    # a no-arm block reaches NEITHER sink (fail-loud). Mirrors
    # dgb_forced_won_share_dualpath_test. Its source (test_dash_won_block_dualpath.cpp)
    # is FOLDED into the test_dash_broadcaster_full target above (which IS in the
    # build.yml --target allowlist) so CI actually builds+runs it -- a standalone
    # target here was never allowlisted and tripped the NOT_BUILT/CTest
    # "Could not find executable" red.

    add_executable(test_dash_coinbase_parity test_dash_coinbase_parity.cpp)
    target_link_libraries(test_dash_coinbase_parity PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_coinbase_parity PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_coinbase_parity "" AUTO)

    # PPLNS coinbase payout muldiv: native(__int128) == portable(boost uint128)
    # byte-parity -- MSVC-portability guard for coinbase_builder.hpp step 3-4
    # (fixes c2pool-dash Windows v0.2.1 build). Pure header math; consensus.
    add_executable(test_dash_coinbase_muldiv test_dash_coinbase_muldiv.cpp)
    target_link_libraries(test_dash_coinbase_muldiv PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_coinbase_muldiv PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_discover_tests(test_dash_coinbase_muldiv DISCOVERY_MODE PRE_TEST)

    add_executable(test_dash_cb_payee test_dash_cb_payee.cpp)
    target_link_libraries(test_dash_cb_payee PRIVATE
        GTest::gtest_main GTest::gtest
        core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_cb_payee PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_cb_payee "" AUTO)

    # S8 stratum job-notify round-trip: the mining.notify merkle_branch folds an
    # extranonce2-substituted coinbase (index 0) to the header merkle_root. Same
    # link set as the other dash_x11 header-only KATs. Fenced/non-consensus;
    # binds real merkle_branches_raw(); oracle work.py:474/493, dash_data.py:189/216.
    add_executable(test_dash_stratum_notify_roundtrip test_dash_stratum_notify_roundtrip.cpp)
    target_link_libraries(test_dash_stratum_notify_roundtrip PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_stratum_notify_roundtrip PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_stratum_notify_roundtrip "" AUTO)

    add_executable(test_dash_stratum_extranonce_split test_dash_stratum_extranonce_split.cpp)
    target_link_libraries(test_dash_stratum_extranonce_split PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_stratum_extranonce_split PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_stratum_extranonce_split "" AUTO)
    add_executable(test_dash_stratum_submit_reassembly test_dash_stratum_submit_reassembly.cpp)
    target_link_libraries(test_dash_stratum_submit_reassembly PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_stratum_submit_reassembly PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_stratum_submit_reassembly "" AUTO)

    add_executable(test_compact_blocks test_compact_blocks.cpp)
    target_link_libraries(test_compact_blocks PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_compact_blocks PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_compact_blocks "" AUTO)

    add_executable(test_redistribute test_redistribute.cpp)
    target_link_libraries(test_redistribute PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_redistribute PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_redistribute "" AUTO)

    add_executable(test_auto_ratchet test_auto_ratchet.cpp)
    target_link_libraries(test_auto_ratchet PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_auto_ratchet PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_auto_ratchet "" AUTO)

    add_executable(test_stratum_extensions test_stratum_extensions.cpp)
    target_link_libraries(test_stratum_extensions PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_hashrate
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_stratum_extensions PRIVATE c2pool_payout ltc_coin c2pool_storage c2pool_merged_mining pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_stratum_extensions "" AUTO)

    # Mining-hotel interim fix KATs: strict per-node miner cap (refused
    # connections + counter), FIFO+TTL job eviction under a 600-notify stale
    # storm, and the flat-RSS shared-payload pointer-identity scaffold.
    # Loopback-only (synthetic IWorkSource, ephemeral test port) — no daemon /
    # RPC / sharechain. DASH byte-parity note: the notify/coinbase/share BYTE
    # checks live in the dash lane against the frstrtr/p2pool-dash oracle
    # (share version 16→36), not here.
    add_executable(test_stratum_hotel_interim test_stratum_hotel_interim.cpp)
    target_link_libraries(test_stratum_hotel_interim PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_hashrate
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_stratum_hotel_interim PRIVATE c2pool_payout ltc_coin c2pool_storage c2pool_merged_mining pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_stratum_hotel_interim "" AUTO)

    add_executable(test_multiaddress_pplns test_multiaddress_pplns.cpp)
    target_link_libraries(test_multiaddress_pplns PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_merged_mining
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_multiaddress_pplns PRIVATE c2pool_payout c2pool_hashrate ltc_coin c2pool_storage pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_multiaddress_pplns "" AUTO)

    add_executable(test_pplns_stress test_pplns_stress.cpp)
    target_link_libraries(test_pplns_stress PRIVATE
        GTest::gtest_main GTest::gtest
        c2pool_merged_mining
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_pplns_stress PRIVATE c2pool_payout c2pool_hashrate ltc_coin c2pool_storage pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_pplns_stress "" AUTO)

    add_executable(test_hash_link test_hash_link.cpp)
    target_link_libraries(test_hash_link PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_hash_link PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_hash_link "" AUTO)

    add_executable(test_decay_pplns test_decay_pplns.cpp)
    target_link_libraries(test_decay_pplns PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_decay_pplns PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_decay_pplns "" AUTO)

    add_executable(test_pplns_consensus test_pplns_consensus.cpp)
    target_link_libraries(test_pplns_consensus PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_pplns_consensus PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_pplns_consensus "" AUTO)

    add_executable(test_v36_script_sorting test_v36_script_sorting.cpp)
    target_link_libraries(test_v36_script_sorting PRIVATE
        GTest::gtest_main GTest::gtest
    )
    gtest_add_tests(test_v36_script_sorting "" AUTO)

    add_executable(test_v36_cross_impl_refhash test_v36_cross_impl_refhash.cpp)
    target_link_libraries(test_v36_cross_impl_refhash PRIVATE
        GTest::gtest_main GTest::gtest
        core
    )
    target_link_libraries(test_v36_cross_impl_refhash PRIVATE c2pool_payout c2pool_hashrate ltc_coin c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_v36_cross_impl_refhash "" AUTO)

    add_executable(test_mweb_builder test_mweb_builder.cpp)
    target_link_libraries(test_mweb_builder PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_mweb_builder PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_mweb_builder "" AUTO)

    add_executable(test_address_resolution test_address_resolution.cpp)
    target_link_libraries(test_address_resolution PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_address_resolution PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_address_resolution "" AUTO)

    add_executable(test_compute_share_target test_compute_share_target.cpp)
    target_link_libraries(test_compute_share_target PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_compute_share_target PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_compute_share_target "" AUTO)
    add_executable(test_web_honesty_regression test_web_honesty_regression.cpp)
    target_link_libraries(test_web_honesty_regression PRIVATE
        GTest::gtest_main GTest::gtest
        core ltc
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_web_honesty_regression PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_web_honesty_regression "" AUTO)
    target_compile_definitions(test_web_honesty_regression PRIVATE  # folded #912 static-HTML KAT
        DASHBOARD_HTML_PATH="${CMAKE_SOURCE_DIR}/web-static/dashboard.html"
        # WebStaticMergedGating KATs read the sibling web-static pages
        # (miners/miner/loading) for standalone-coin merged-UI gating.
        WEB_STATIC_DIR="${CMAKE_SOURCE_DIR}/web-static")


    # L-KR1Z1S drop_tails release-order race guard (self-contained ASan stand-in,
    # #759 pattern). Compiles + runs its own harness in three modes under
    # AddressSanitizer: green PASS (fixed discipline survives concurrent prune),
    # deadcode RED (models the main_ltc.cpp:5011 caller-unlock revert), uaf RED
    # (models the node.cpp:1038 under-lock-deref revert). It does NOT link
    # NodeImpl/main_ltc. Script-based add_test => no build target, so it stays off
    # the build.yml --target allowlist (#143) and needs no link into the suite.
    add_test(NAME LtcKr1z1sDropTailGuard
             COMMAND ${CMAKE_COMMAND} -E env CXX=${CMAKE_CXX_COMPILER}
                     bash ${CMAKE_CURRENT_SOURCE_DIR}/kr1z1s/kr1z1s_droptail_guard.sh)
    set_tests_properties(LtcKr1z1sDropTailGuard PROPERTIES
        TIMEOUT 180 LABELS "ltc;threading;asan-stand-in")
endif()

