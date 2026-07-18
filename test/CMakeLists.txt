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
    add_executable(test_dash_block_replay test_dash_block_replay.cpp)
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

    # DASH S8 pool-node leaf 4 — share_tracker.hpp KAT: DensePPLNSWindow decayed
    # weight ring buffer (compute_v36_weights), decay table, donation split,
    # window slides. PoW-independent consensus core; socket-free, chain-free.
    # Mirrors the test_dash_conformance link set.
    add_executable(test_dash_share_tracker test_dash_share_tracker.cpp)
    target_link_libraries(test_dash_share_tracker PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_share_tracker PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_share_tracker "" AUTO)

    # DASH S8 pool-node leaf 5 (FINAL) slice A — node.hpp skeleton KAT: NodeImpl
    # default-constructible/concrete, empty fresh tracker, lock-free snapshot
    # publish/getters, tracker()/read_tracker()/tracker_shared_lock() accessors.
    # Rig-free (no io_context/sockets). Needs pool (BaseNode) + c2pool_storage
    # (SharechainStorage) on top of the dash_x11 + core link set.
    add_executable(test_dash_node test_dash_node.cpp)
    target_link_libraries(test_dash_node PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_node PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining c2pool_storage pool)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_node "" AUTO)

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
    add_executable(test_dash_share_hash_link
        test_dash_share_hash_link.cpp
        test_dash_share_producer.cpp)
    target_link_libraries(test_dash_share_hash_link PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_share_hash_link PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39): core stratum/web_server TUs
    gtest_add_tests(test_dash_share_hash_link "" AUTO)

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

    # DASH in-memory mempool (S7 leaf): storage + UTXO-fee + LRU eviction +
    # double-spend conflict removal + feerate-sorted selection. Header-only over
    # block/transaction/utxo_adapter + core/coin; no ltc/pool SCC dependency.
    # Direct prerequisite for the embedded_gbt template builder (S7 main).
    add_executable(test_dash_mempool test_dash_mempool.cpp)
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

    # DASH masternode state-machine (S7 leaf): vendored ProTx wire
    # (providertx.hpp) + MNState persistence (mn_state_db.hpp) +
    # apply_block RebuildListFromBlock + find_expected_payee / pick_paid_mn
    # over the SimplifiedMNList leaf (#309). Last absent header before the
    # embedded_gbt capstone. Header-only over core/uint256 + core/pack +
    # core/hash; no ltc/pool SCC dependency.
    add_executable(test_dash_mn_state test_dash_mn_state.cpp)
    target_link_libraries(test_dash_mn_state PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_mn_state PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
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
    add_executable(test_dash_embedded_gbt test_dash_embedded_gbt.cpp)
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
    target_link_libraries(test_btc_underfill_guard PRIVATE c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage btc_coin btclibs pool sharechain ${SECP256K1_LIBRARIES})  # OBJECT-lib SCC direct-naming (#22/#39), btc twin
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
    add_executable(test_dash_node_coin_state test_dash_node_coin_state.cpp)
    target_link_libraries(test_dash_node_coin_state PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_node_coin_state PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_node_coin_state "" AUTO)

    # DASHWorkSource (dash::stratum): concrete core::stratum::IWorkSource for
    # DASH X11 -- 4b construction + contract KAT. Links the dash_stratum OBJECT
    # lib (work_source.cpp) on top of the header-only coin selector link set.
    add_executable(test_dash_stratum_work_source test_dash_stratum_work_source.cpp)
    target_link_libraries(test_dash_stratum_work_source PRIVATE
        GTest::gtest_main GTest::gtest
        dash_stratum dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_stratum_work_source PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_stratum_work_source "" AUTO)

    # CoinStateMaintainer: drives NodeCoinState off async tip/MN/mempool update
    # events (readiness gate: MN+tip required before publish). Same link set as
    # test_dash_node_coin_state -- header-only over the work_source selector set.
    add_executable(test_dash_coin_state_maintainer test_dash_coin_state_maintainer.cpp)
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
    gtest_add_tests(test_dash_get_work "" AUTO)

    # Reception wire (legs 1-3): interfaces::Node reception Events ->
    # CoinStateMaintainer. Proves the wire_*_ingest() subscriptions fold off the
    # real Events (no direct poke), honour dispose(), and reach the embedded
    # template. Same header-only link set as the maintainer suite (no NodeImpl
    # -> no pool/storage dep).
    add_executable(test_dash_node_reception_wire test_dash_node_reception_wire.cpp)
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
    add_executable(test_dash_p2p_node test_dash_p2p_node.cpp test_dash_coin_p2p_client.cpp)
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
    target_link_libraries(test_dash_auto_ratchet PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
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

    add_executable(test_dash_broadcaster_full test_dash_broadcaster_full.cpp)
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
    gtest_add_tests(test_dash_coinbase_muldiv "" AUTO)

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

endif()

