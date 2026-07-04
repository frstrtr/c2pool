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

    add_executable(test_dash_share_messages test_dash_share_messages.cpp)
    target_link_libraries(test_dash_share_messages PRIVATE
        GTest::gtest_main GTest::gtest
        dash_x11 core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_share_messages PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_share_messages "" AUTO)

    # share_init_verify gentx hash_link byte-parity vs oracle (coinbase_payload
    # VarStr prefix). Header-only over the dash_x11 + core link set; mirrors the
    # test_dash_conformance link set.
    add_executable(test_dash_share_hash_link test_dash_share_hash_link.cpp)
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
    add_executable(test_dash_p2p_node test_dash_p2p_node.cpp)
    target_link_libraries(test_dash_p2p_node PRIVATE
        GTest::gtest_main GTest::gtest
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

    add_executable(test_dash_cb_payee test_dash_cb_payee.cpp)
    target_link_libraries(test_dash_cb_payee PRIVATE
        GTest::gtest_main GTest::gtest
        core
        nlohmann_json::nlohmann_json
        ${Boost_LIBRARIES}
    )
    target_link_libraries(test_dash_cb_payee PRIVATE c2pool_payout c2pool_hashrate c2pool_merged_mining)  # OBJECT-lib SCC direct-naming (#22/#39)
    gtest_add_tests(test_dash_cb_payee "" AUTO)

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

