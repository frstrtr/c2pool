// src/core/param_catalog.inc  -- DECLARATIVE, Qt-free, generated data.
// One canonical param per C2P_PARAM; per-binary spellings via C2P_ALIAS.
// DO NOT hand-edit spellings without also updating the mains: the
// ci/check_param_catalog.py tripwire enforces main<->catalog consistency.
//
// C2P_PARAM(canon, section, type, mutability, applic_mask, default_kind, default_literal, validator, help)
// C2P_ALIAS(canon, binary, spelling, style)
#ifndef C2P_PARAM
#define C2P_PARAM(canon, section, type, mut, applic, dkind, dlit, val, help)
#endif
#ifndef C2P_ALIAS
#define C2P_ALIAS(canon, binary, spelling, style)
#endif

C2P_PARAM("meta.version", Meta, BOOL, COMPILE_TIME_READONLY, C_ALL, LIT, "false", NONE, "print version and exit")
  C2P_ALIAS("meta.version", BIN_DASH, "--version", FLAG)
  C2P_ALIAS("meta.version", BIN_DGB, "--version", FLAG)
  C2P_ALIAS("meta.version", BIN_BCH, "--version", FLAG)

C2P_PARAM("meta.help", Meta, BOOL, COMPILE_TIME_READONLY, C_ALL, LIT, "false", NONE, "print help and exit")
  C2P_ALIAS("meta.help", BIN_DASH, "--help", FLAG)
  C2P_ALIAS("meta.help", BIN_LTC, "--help", FLAG)
  C2P_ALIAS("meta.help", BIN_LTC, "-h", SHORT)
  C2P_ALIAS("meta.help", BIN_BTC, "--help", FLAG)
  C2P_ALIAS("meta.help", BIN_BTC, "-h", SHORT)
  C2P_ALIAS("meta.help", BIN_DGB, "--help", FLAG)
  C2P_ALIAS("meta.help", BIN_BCH, "--help", FLAG)

C2P_PARAM("meta.data_dir", Meta, PATH, RESTART, C_ALL, LIT, "", NONE, "data directory (pre-scanned; roots DB/logs)")
  C2P_ALIAS("meta.data_dir", BIN_DASH, "--data-dir", VALUE)
  C2P_ALIAS("meta.data_dir", BIN_LTC, "--data-dir", VALUE)
  C2P_ALIAS("meta.data_dir", BIN_BTC, "--data-dir", VALUE)
  C2P_ALIAS("meta.data_dir", BIN_DGB, "--data-dir", VALUE)
  C2P_ALIAS("meta.data_dir", BIN_BCH, "--data-dir", VALUE)

// Control-plane (M0b): the monolithic settings-file path override and the
// resolved-config diagnostic. Both are COMPILE_TIME_READONLY so the loader
// refuses them from inside a settings file (you cannot set the settings path
// from the settings file) and so the scanner never mirrors them into the
// resolved-config dump (they are not resolved config).
C2P_PARAM("meta.settings_path", Meta, PATH, COMPILE_TIME_READONLY, C_ALL, LIT, "", NONE, "explicit settings-file path (default <data-dir>/c2pool.toml)")
  C2P_ALIAS("meta.settings_path", BIN_DASH, "--settings", VALUE)
  C2P_ALIAS("meta.settings_path", BIN_LTC, "--settings", VALUE)
  C2P_ALIAS("meta.settings_path", BIN_BTC, "--settings", VALUE)
  C2P_ALIAS("meta.settings_path", BIN_DGB, "--settings", VALUE)
  C2P_ALIAS("meta.settings_path", BIN_BCH, "--settings", VALUE)

C2P_PARAM("meta.dump_resolved_config", Meta, BOOL, COMPILE_TIME_READONLY, C_ALL, LIT, "false", NONE, "print the fully resolved config with per-key source, then exit")
  C2P_ALIAS("meta.dump_resolved_config", BIN_DASH, "--dump-resolved-config", FLAG)
  C2P_ALIAS("meta.dump_resolved_config", BIN_LTC, "--dump-resolved-config", FLAG)
  C2P_ALIAS("meta.dump_resolved_config", BIN_BTC, "--dump-resolved-config", FLAG)
  C2P_ALIAS("meta.dump_resolved_config", BIN_DGB, "--dump-resolved-config", FLAG)
  C2P_ALIAS("meta.dump_resolved_config", BIN_BCH, "--dump-resolved-config", FLAG)

C2P_PARAM("meta.ack_money_settings", Meta, BOOL, COMPILE_TIME_READONLY, C_ALL, LIT, "false", NONE, "compute+print the money-ack hash for the resolved settings file, then exit")
  C2P_ALIAS("meta.ack_money_settings", BIN_DASH, "--ack-money-settings", FLAG)
  C2P_ALIAS("meta.ack_money_settings", BIN_LTC, "--ack-money-settings", FLAG)
  C2P_ALIAS("meta.ack_money_settings", BIN_BTC, "--ack-money-settings", FLAG)
  C2P_ALIAS("meta.ack_money_settings", BIN_DGB, "--ack-money-settings", FLAG)
  C2P_ALIAS("meta.ack_money_settings", BIN_BCH, "--ack-money-settings", FLAG)

C2P_PARAM("meta.run", Meta, BOOL, RESTART, C_DASH|C_DGB, LIT, "false", NONE, "run the node")
  C2P_ALIAS("meta.run", BIN_DASH, "--run", FLAG)
  C2P_ALIAS("meta.run", BIN_DGB, "--run", FLAG)

C2P_PARAM("meta.selftest", Meta, BOOL, RESTART, C_DASH|C_DGB|C_BCH, LIT, "false", NONE, "run self-test")
  C2P_ALIAS("meta.selftest", BIN_DASH, "--selftest", FLAG)
  C2P_ALIAS("meta.selftest", BIN_DGB, "--selftest", FLAG)
  C2P_ALIAS("meta.selftest", BIN_BCH, "--selftest", FLAG)

C2P_PARAM("meta.mine_block", Meta, BOOL, RESTART, C_DASH, LIT, "false", NONE, "one-shot CPU miner harness")
  C2P_ALIAS("meta.mine_block", BIN_DASH, "--mine-block", FLAG)

C2P_PARAM("meta.blockchain", Meta, ENUM_STR, RESTART, C_LTC, LIT, "ltc", ENUM_MEMBER, "select chain (ltc/doge/...)")
  C2P_ALIAS("meta.blockchain", BIN_LTC, "--net", VALUE)
  C2P_ALIAS("meta.blockchain", BIN_LTC, "--blockchain", VALUE)

C2P_PARAM("meta.mode_integrated", Meta, BOOL, RESTART, C_LTC, LIT, "true", NONE, "integrated mode (default on)")
  C2P_ALIAS("meta.mode_integrated", BIN_LTC, "--integrated", FLAG)

C2P_PARAM("meta.mode_solo", Meta, BOOL, RESTART, C_LTC, LIT, "false", NONE, "solo mode")
  C2P_ALIAS("meta.mode_solo", BIN_LTC, "--solo", FLAG)

C2P_PARAM("meta.mode_custodial", Meta, BOOL, RESTART, C_LTC, LIT, "false", NONE, "custodial mode")
  C2P_ALIAS("meta.mode_custodial", BIN_LTC, "--custodial", FLAG)

C2P_PARAM("meta.mode_sharechain", Meta, BOOL, RESTART, C_LTC, LIT, "false", NONE, "sharechain mode")
  C2P_ALIAS("meta.mode_sharechain", BIN_LTC, "--sharechain", FLAG)

C2P_PARAM("meta.mode_standalone", Meta, BOOL, RESTART, C_LTC, LIT, "false", NONE, "standalone mode")
  C2P_ALIAS("meta.mode_standalone", BIN_LTC, "--standalone", FLAG)

C2P_PARAM("meta.mode_genesis", Meta, BOOL, RESTART, C_LTC, LIT, "false", NONE, "genesis mode")
  C2P_ALIAS("meta.mode_genesis", BIN_LTC, "--genesis", FLAG)

C2P_PARAM("meta.wait_for_peers", Meta, BOOL, RESTART, C_LTC, LIT, "false", NONE, "wait for peers on startup")
  C2P_ALIAS("meta.wait_for_peers", BIN_LTC, "--wait-for-peers", FLAG)

C2P_PARAM("meta.startup_mode", Meta, ENUM_STR, RESTART, C_LTC, LIT, "wait", ENUM_MEMBER, "startup mode auto/genesis/wait")
  C2P_ALIAS("meta.startup_mode", BIN_LTC, "--startup-mode", VALUE)

C2P_PARAM("meta.startup_timeout", Meta, INT64, RESTART, C_LTC, LIT, "60", NONE, "startup timeout seconds")
  C2P_ALIAS("meta.startup_timeout", BIN_LTC, "--startup-timeout", VALUE)

C2P_PARAM("meta.config_yaml", Meta, PATH, RESTART, C_LTC, LIT, "", NONE, "DEPRECATED legacy YAML config overlay")
  C2P_ALIAS("meta.config_yaml", BIN_LTC, "--config", VALUE)

C2P_PARAM("meta.ibd", Meta, BOOL, RESTART, C_BCH, LIT, "false", NONE, "initial block download harness")
  C2P_ALIAS("meta.ibd", BIN_BCH, "--ibd", FLAG)

C2P_PARAM("meta.with_peer_verify", Meta, BOOL, RESTART, C_BCH, LIT, "false", NONE, "peer-verify harness")
  C2P_ALIAS("meta.with_peer_verify", BIN_BCH, "--with-peer-verify", FLAG)

C2P_PARAM("meta.pool", Meta, BOOL, RESTART, C_BCH, LIT, "false", NONE, "pool mode harness")
  C2P_ALIAS("meta.pool", BIN_BCH, "--pool", FLAG)

C2P_PARAM("meta.near_tip", Meta, BOOL, RESTART, C_BCH, LIT, "false", NONE, "near-tip harness")
  C2P_ALIAS("meta.near_tip", BIN_BCH, "--near-tip", FLAG)

C2P_PARAM("meta.auto_kick", Meta, BOOL, RESTART, C_BCH, LIT, "false", NONE, "auto-kick harness")
  C2P_ALIAS("meta.auto_kick", BIN_BCH, "--auto-kick", FLAG)

C2P_PARAM("meta.max_seconds", Meta, INT64, RESTART, C_BCH, LIT, "0", NONE, "harness max seconds")
  C2P_ALIAS("meta.max_seconds", BIN_BCH, "--max-seconds", VALUE)

C2P_PARAM("network.testnet", Network, BOOL, MONEY_RESTART, C_DASH|C_LTC|C_BTC|C_BCH, LIT, "false", NONE, "testnet network identity")
  C2P_ALIAS("network.testnet", BIN_DASH, "--testnet", FLAG)
  C2P_ALIAS("network.testnet", BIN_LTC, "--testnet", FLAG)
  C2P_ALIAS("network.testnet", BIN_BTC, "--testnet", FLAG)
  C2P_ALIAS("network.testnet", BIN_BCH, "--testnet", FLAG)

C2P_PARAM("network.regtest", Network, BOOL, MONEY_RESTART, C_DASH|C_BTC|C_DGB|C_BCH, LIT, "false", NONE, "regtest network identity")
  C2P_ALIAS("network.regtest", BIN_DASH, "--regtest", FLAG)
  C2P_ALIAS("network.regtest", BIN_BTC, "--regtest", FLAG)
  C2P_ALIAS("network.regtest", BIN_DGB, "--regtest", FLAG)
  C2P_ALIAS("network.regtest", BIN_BCH, "--regtest", FLAG)

C2P_PARAM("network.testnet4", Network, BOOL, MONEY_RESTART, C_BTC|C_BCH, LIT, "false", NONE, "testnet4 network identity")
  C2P_ALIAS("network.testnet4", BIN_BTC, "--testnet4", FLAG)
  C2P_ALIAS("network.testnet4", BIN_BCH, "--testnet4", FLAG)

C2P_PARAM("network.doge_testnet4alpha", Network, BOOL, MONEY_RESTART, C_LTC|C_DOGE, LIT, "false", NONE, "doge testnet4alpha identity")
  C2P_ALIAS("network.doge_testnet4alpha", BIN_LTC, "--doge-testnet4alpha", FLAG)

C2P_PARAM("network.coin_genesis", Network, STRING, MONEY_RESTART, C_DGB, LIT, "", HASH256, "coin genesis hash override")
  C2P_ALIAS("network.coin_genesis", BIN_DGB, "--coin-genesis", VALUE)

C2P_PARAM("sharechain.listen", Sharechain, HOSTPORT, RESTART, C_ALL, FROM_POOL_CONFIG, "", HOSTPORT_V, "sharechain P2P bind [HOST:]PORT")
  C2P_ALIAS("sharechain.listen", BIN_DASH, "--listen", VALUE)
  C2P_ALIAS("sharechain.listen", BIN_LTC, "--p2pool-port", VALUE)
  C2P_ALIAS("sharechain.listen", BIN_LTC, "--p2p-port", VALUE)
  C2P_ALIAS("sharechain.listen", BIN_LTC, "--port", VALUE)
  C2P_ALIAS("sharechain.listen", BIN_BTC, "--sharechain-port", VALUE)
  C2P_ALIAS("sharechain.listen", BIN_DGB, "--sharechain-port", VALUE)
  C2P_ALIAS("sharechain.listen", BIN_BCH, "--p2p-port", VALUE)

C2P_PARAM("sharechain.addnodes", Sharechain, LIST_HOSTPORT, RESTART, C_DASH|C_BTC, LIT, "", HOSTPORT_V, "persistent outbound sharechain peers")
  C2P_ALIAS("sharechain.addnodes", BIN_DASH, "--addnode", VALUE)
  C2P_ALIAS("sharechain.addnodes", BIN_BTC, "--sharechain-addnode", VALUE)

C2P_PARAM("sharechain.connects", Sharechain, LIST_HOSTPORT, RESTART, C_DASH, LIT, "", HOSTPORT_V, "connect-only sharechain peers")
  C2P_ALIAS("sharechain.connects", BIN_DASH, "--connect", VALUE)

C2P_PARAM("sharechain.legacy_peer", Sharechain, HOSTPORT, RESTART, C_BTC, LIT, "", HOSTPORT_V, "legacy single sharechain peer")
  C2P_ALIAS("sharechain.legacy_peer", BIN_BTC, "--p2pool", VALUE)

C2P_PARAM("sharechain.seeds", Sharechain, LIST_HOSTPORT, RESTART, C_LTC, LIT, "", HOSTPORT_V, "seed nodes (repeatable)")
  C2P_ALIAS("sharechain.seeds", BIN_LTC, "-n", SHORT)

C2P_PARAM("sharechain.no_p2p_relay", Sharechain, BOOL, RESTART, C_DASH|C_DGB, LIT, "false", NONE, "suppress embedded won-block relay")
  C2P_ALIAS("sharechain.no_p2p_relay", BIN_DASH, "--no-p2p-relay", FLAG)
  C2P_ALIAS("sharechain.no_p2p_relay", BIN_DGB, "--no-p2p-relay", FLAG)

C2P_PARAM("sharechain.max_conns", Sharechain, INT64, RESTART, C_LTC, LIT, "0", NONE, "max connections")
  C2P_ALIAS("sharechain.max_conns", BIN_LTC, "--max-conns", VALUE)

C2P_PARAM("sharechain.outgoing_conns", Sharechain, INT64, RESTART, C_LTC, LIT, "0", NONE, "outgoing connections")
  C2P_ALIAS("sharechain.outgoing_conns", BIN_LTC, "--outgoing-conns", VALUE)

C2P_PARAM("sharechain.disable_upnp", Sharechain, BOOL, RESTART, C_LTC, LIT, "false", NONE, "disable UPnP")
  C2P_ALIAS("sharechain.disable_upnp", BIN_LTC, "--disable-upnp", FLAG)

C2P_PARAM("sharechain.p2p_max_peers", Sharechain, INT64, RESTART, C_LTC, LIT, "30", NONE, "p2p max peers")
  C2P_ALIAS("sharechain.p2p_max_peers", BIN_LTC, "--p2p-max-peers", VALUE)

C2P_PARAM("sharechain.ban_duration", Sharechain, INT64, LIVE, C_LTC, LIT, "300", NONE, "ban duration seconds")
  C2P_ALIAS("sharechain.ban_duration", BIN_LTC, "--ban-duration", VALUE)

C2P_PARAM("sharechain.network_id", Sharechain, HEX, MONEY_RESTART, C_LTC|C_BTC, LIT, "", HEX_EVEN, "private sharechain identifier (forks chain)")
  C2P_ALIAS("sharechain.network_id", BIN_LTC, "--network-id", VALUE)
  C2P_ALIAS("sharechain.network_id", BIN_LTC, "--chain-id", VALUE)
  C2P_ALIAS("sharechain.network_id", BIN_BTC, "--network-id", VALUE)

C2P_PARAM("sharechain.prefix", Sharechain, HEX, MONEY_RESTART, C_LTC|C_BTC, LIT, "", HEX_EVEN, "private sharechain prefix")
  C2P_ALIAS("sharechain.prefix", BIN_LTC, "--prefix", VALUE)
  C2P_ALIAS("sharechain.prefix", BIN_BTC, "--prefix", VALUE)

C2P_PARAM("coin_p2p.connect", CoinP2P, LIST_HOSTPORT, RESTART, C_DASH|C_BCH, LIT, "", HOSTPORT_V, "explicit coin-network dial")
  C2P_ALIAS("coin_p2p.connect", BIN_DASH, "--coin-p2p-connect", VALUE)
  C2P_ALIAS("coin_p2p.connect", BIN_BCH, "--peer", VALUE)

C2P_PARAM("coin_p2p.discover", CoinP2P, BOOL, RESTART, C_DASH|C_BTC|C_DGB, LIT, "false", NONE, "scored/diverse coin-P2P discovery")
  C2P_ALIAS("coin_p2p.discover", BIN_DASH, "--coin-p2p-discover", FLAG)
  C2P_ALIAS("coin_p2p.discover", BIN_BTC, "--coin-p2p-discover", FLAG)
  C2P_ALIAS("coin_p2p.discover", BIN_DGB, "--coin-p2p-discover", FLAG)

C2P_PARAM("coin_p2p.magic", CoinP2P, HEX, MONEY_RESTART, C_DASH|C_DGB, LIT, "", HEX8_MAGIC, "wire magic override (regtest)")
  C2P_ALIAS("coin_p2p.magic", BIN_DASH, "--coin-p2p-magic", VALUE)
  C2P_ALIAS("coin_p2p.magic", BIN_DGB, "--coin-magic", VALUE)

C2P_PARAM("coin_p2p.peers", CoinP2P, INT64, RESTART, C_DASH, LIT, "8", NONE, "coin-P2P pool peer count (cap 16)")
  C2P_ALIAS("coin_p2p.peers", BIN_DASH, "--coin-p2p-peers", VALUE)

C2P_PARAM("coin_p2p.zmq_hashblock", CoinP2P, STRING, RESTART, C_DASH, LIT, "", NONE, "opt-in dashd ZMQ hashblock endpoint")
  C2P_ALIAS("coin_p2p.zmq_hashblock", BIN_DASH, "--coin-zmq-hashblock", VALUE)

C2P_PARAM("coin_p2p.producer_target", CoinP2P, HOSTPORT, RESTART, C_DGB, LIT, "", HOSTPORT_V, "embedded P2P producer target")
  C2P_ALIAS("coin_p2p.producer_target", BIN_DGB, "--coin-daemon", VALUE)

C2P_PARAM("coin_p2p.doge_address", CoinP2P, STRING, RESTART, C_LTC|C_DOGE, LIT, "", NONE, "doge coin-P2P address")
  C2P_ALIAS("coin_p2p.doge_address", BIN_LTC, "--doge-p2p-address", VALUE)

C2P_PARAM("coin_p2p.doge_port", CoinP2P, INT64, RESTART, C_LTC|C_DOGE, LIT, "0", NONE, "doge coin-P2P port")
  C2P_ALIAS("coin_p2p.doge_port", BIN_LTC, "--doge-p2p-port", VALUE)

C2P_PARAM("coin_p2p.address", CoinP2P, STRING, RESTART, C_LTC, LIT, "", NONE, "coind P2P address")
  C2P_ALIAS("coin_p2p.address", BIN_LTC, "--coind-p2p-address", VALUE)

C2P_PARAM("coin_p2p.port", CoinP2P, INT64, RESTART, C_LTC, LIT, "-1", NONE, "coind P2P port (-1 auto,0 off)")
  C2P_ALIAS("coin_p2p.port", BIN_LTC, "--coind-p2p-port", VALUE)
  C2P_ALIAS("coin_p2p.port", BIN_LTC, "--bitcoind-p2p-port", VALUE)

C2P_PARAM("daemon_rpc.endpoint", DaemonRpc, HOSTPORT, RESTART, C_DASH|C_BTC|C_DGB, LIT, "", HOSTPORT_V, "coin daemon RPC endpoint (empty=daemonless)")
  C2P_ALIAS("daemon_rpc.endpoint", BIN_DASH, "--coin-rpc", VALUE)
  C2P_ALIAS("daemon_rpc.endpoint", BIN_DASH, "--coin-daemon", VALUE)
  C2P_ALIAS("daemon_rpc.endpoint", BIN_BTC, "--bitcoind", VALUE)

C2P_PARAM("daemon_rpc.submit_endpoint", DaemonRpc, HOSTPORT, RESTART, C_BTC|C_DGB, LIT, "", HOSTPORT_V, "submitblock backup RPC endpoint")
  C2P_ALIAS("daemon_rpc.submit_endpoint", BIN_BTC, "--coin-rpc", VALUE)
  C2P_ALIAS("daemon_rpc.submit_endpoint", BIN_DGB, "--coin-rpc", VALUE)

C2P_PARAM("daemon_rpc.auth_file", DaemonRpc, PATH, RESTART, C_DASH|C_BTC|C_DGB|C_BCH, LIT, "", NONE, "daemon RPC credentials file")
  C2P_ALIAS("daemon_rpc.auth_file", BIN_DASH, "--coin-rpc-auth", VALUE)
  C2P_ALIAS("daemon_rpc.auth_file", BIN_BTC, "--coin-rpc-auth", VALUE)
  C2P_ALIAS("daemon_rpc.auth_file", BIN_DGB, "--coin-rpc-auth", VALUE)
  C2P_ALIAS("daemon_rpc.auth_file", BIN_BCH, "--rpc-conf", VALUE)

C2P_PARAM("daemon_rpc.host", DaemonRpc, STRING, RESTART, C_LTC, LIT, "127.0.0.1", NONE, "coind RPC host")
  C2P_ALIAS("daemon_rpc.host", BIN_LTC, "--coind-address", VALUE)
  C2P_ALIAS("daemon_rpc.host", BIN_LTC, "--rpchost", VALUE)
  C2P_ALIAS("daemon_rpc.host", BIN_LTC, "--bitcoind-address", VALUE)

C2P_PARAM("daemon_rpc.port", DaemonRpc, INT64, RESTART, C_LTC, LIT, "0", NONE, "coind RPC port (0=auto)")
  C2P_ALIAS("daemon_rpc.port", BIN_LTC, "--coind-rpc-port", VALUE)
  C2P_ALIAS("daemon_rpc.port", BIN_LTC, "--rpcport", VALUE)
  C2P_ALIAS("daemon_rpc.port", BIN_LTC, "--bitcoind-rpc-port", VALUE)

C2P_PARAM("daemon_rpc.user", DaemonRpc, STRING, RESTART, C_LTC, LIT, "", NONE, "coind RPC user")
  C2P_ALIAS("daemon_rpc.user", BIN_LTC, "--rpcuser", VALUE)

C2P_PARAM("daemon_rpc.password", DaemonRpc, STRING, RESTART, C_LTC, LIT, "", NONE, "coind RPC password (never persisted to file)")
  C2P_ALIAS("daemon_rpc.password", BIN_LTC, "--rpcpassword", VALUE)

C2P_PARAM("stratum.bind", Stratum, HOSTPORT, RESTART, C_ALL, LIT, "0.0.0.0:0", HOSTPORT_V, "stratum bind [HOST:]PORT (0=off)")
  C2P_ALIAS("stratum.bind", BIN_DASH, "--stratum", VALUE)
  C2P_ALIAS("stratum.bind", BIN_LTC, "--worker-port", VALUE)
  C2P_ALIAS("stratum.bind", BIN_LTC, "--stratum-port", VALUE)
  C2P_ALIAS("stratum.bind", BIN_LTC, "-w", SHORT)
  C2P_ALIAS("stratum.bind", BIN_BTC, "--stratum", VALUE)
  C2P_ALIAS("stratum.bind", BIN_DGB, "--stratum", VALUE)
  C2P_ALIAS("stratum.bind", BIN_BCH, "--stratum", VALUE)

C2P_PARAM("stratum.advertise_host", Stratum, STRING, LIVE, C_DASH, LIT, "", NONE, "stratum advertise host")
  C2P_ALIAS("stratum.advertise_host", BIN_DASH, "--stratum-advertise", VALUE)

C2P_PARAM("stratum.min_diff", Stratum, DOUBLE, LIVE, C_LTC, LIT, "0.0005", NONE, "stratum min difficulty")
  C2P_ALIAS("stratum.min_diff", BIN_LTC, "--stratum-min-diff", VALUE)

C2P_PARAM("stratum.max_diff", Stratum, DOUBLE, LIVE, C_LTC, LIT, "65536", NONE, "stratum max difficulty")
  C2P_ALIAS("stratum.max_diff", BIN_LTC, "--stratum-max-diff", VALUE)

C2P_PARAM("stratum.target_time", Stratum, DOUBLE, LIVE, C_LTC, LIT, "3.0", NONE, "stratum vardiff target seconds")
  C2P_ALIAS("stratum.target_time", BIN_LTC, "--stratum-target-time", VALUE)

C2P_PARAM("stratum.vardiff", Stratum, TRISTATE_BOOL, LIVE, C_LTC, NONE, "", NONE, "vardiff (default on; --no-vardiff disables)")
  C2P_ALIAS("stratum.vardiff", BIN_LTC, "--no-vardiff", FLAG_NO_PREFIX)

C2P_PARAM("stratum.max_coinbase_outputs", Stratum, INT64, LIVE, C_LTC, LIT, "0", NONE, "max coinbase outputs")
  C2P_ALIAS("stratum.max_coinbase_outputs", BIN_LTC, "--max-coinbase-outputs", VALUE)

C2P_PARAM("stratum.max_connections", Stratum, INT64, LIVE, C_LTC, LIT, "0", NONE, "max stratum connections")
  C2P_ALIAS("stratum.max_connections", BIN_LTC, "--max-stratum-connections", VALUE)

C2P_PARAM("web.port", WebOps, UINT16, RESTART, C_ALL, FROM_POOL_CONFIG, "", PORT_RANGE, "dashboard/web bind port (0=off)")
  C2P_ALIAS("web.port", BIN_DASH, "--web-port", VALUE)
  C2P_ALIAS("web.port", BIN_DASH, "--http-port", VALUE)
  C2P_ALIAS("web.port", BIN_LTC, "--web-port", VALUE)
  C2P_ALIAS("web.port", BIN_LTC, "--http-port", VALUE)
  C2P_ALIAS("web.port", BIN_BTC, "--http", VALUE_HOSTPORT_COMBINED)
  C2P_ALIAS("web.port", BIN_DGB, "--http", VALUE_HOSTPORT_COMBINED)
  C2P_ALIAS("web.port", BIN_BCH, "--http", VALUE_HOSTPORT_COMBINED)

C2P_PARAM("web.host", WebOps, STRING, RESTART, C_DASH|C_LTC, LIT, "0.0.0.0", NONE, "web bind host")
  C2P_ALIAS("web.host", BIN_DASH, "--web-host", VALUE)
  C2P_ALIAS("web.host", BIN_LTC, "--http-host", VALUE)

C2P_PARAM("web.external_ip", WebOps, STRING, LIVE, C_DASH|C_LTC, LIT, "", NONE, "miner-facing host for stratum URL")
  C2P_ALIAS("web.external_ip", BIN_DASH, "--external-ip", VALUE)
  C2P_ALIAS("web.external_ip", BIN_DASH, "--public-host", VALUE)
  C2P_ALIAS("web.external_ip", BIN_LTC, "--external-ip", VALUE)

C2P_PARAM("web.dashboard_dir", WebOps, PATH, RESTART, C_DASH|C_LTC, LIT, "web-static", NONE, "dashboard static asset dir")
  C2P_ALIAS("web.dashboard_dir", BIN_DASH, "--dashboard-dir", VALUE)
  C2P_ALIAS("web.dashboard_dir", BIN_LTC, "--dashboard-dir", VALUE)

C2P_PARAM("web.cors_origin", WebOps, STRING, LIVE, C_LTC, LIT, "", NONE, "CORS origin")
  C2P_ALIAS("web.cors_origin", BIN_LTC, "--cors-origin", VALUE)

C2P_PARAM("web.analytics_id", WebOps, STRING, LIVE, C_LTC, LIT, "", NONE, "analytics id")
  C2P_ALIAS("web.analytics_id", BIN_LTC, "--analytics-id", VALUE)

C2P_PARAM("global.rss_limit_mb", Global, INT64, LIVE, C_LTC, LIT, "4000", NONE, "RSS limit MB (abort over)")
  C2P_ALIAS("global.rss_limit_mb", BIN_LTC, "--rss-limit-mb", VALUE)

C2P_PARAM("global.storage_save_interval", Global, INT64, LIVE, C_LTC, LIT, "300", NONE, "storage save interval seconds")
  C2P_ALIAS("global.storage_save_interval", BIN_LTC, "--storage-save-interval", VALUE)

C2P_PARAM("global.payout_window", Global, INT64, MONEY_LIVE, C_LTC, LIT, "86400", NONE, "PPLNS payout window seconds")
  C2P_ALIAS("global.payout_window", BIN_LTC, "--payout-window", VALUE)

C2P_PARAM("global.log_level", Global, ENUM_STR, LIVE, C_LTC, LIT, "info", ENUM_MEMBER, "log verbosity")
  C2P_ALIAS("global.log_level", BIN_LTC, "--log-level", VALUE)
  C2P_ALIAS("global.log_level", BIN_LTC, "--debug", FLAG)
  C2P_ALIAS("global.log_level", BIN_LTC, "--loglevel-trace", FLAG)
  C2P_ALIAS("global.log_level", BIN_LTC, "--loglevel-debug", FLAG)
  C2P_ALIAS("global.log_level", BIN_LTC, "--loglevel-info", FLAG)
  C2P_ALIAS("global.log_level", BIN_LTC, "--loglevel-warning", FLAG)
  C2P_ALIAS("global.log_level", BIN_LTC, "--loglevel-error", FLAG)
  C2P_ALIAS("global.log_level", BIN_LTC, "--loglevel-critical", FLAG)

C2P_PARAM("global.log_file", Global, PATH, RESTART, C_LTC, LIT, "debug.log", NONE, "log file path")
  C2P_ALIAS("global.log_file", BIN_LTC, "--log-file", VALUE)

C2P_PARAM("global.log_rotation_mb", Global, INT64, LIVE, C_LTC, LIT, "100", NONE, "log rotation MB")
  C2P_ALIAS("global.log_rotation_mb", BIN_LTC, "--log-rotation-mb", VALUE)

C2P_PARAM("global.log_max_mb", Global, INT64, LIVE, C_LTC, LIT, "1000", NONE, "log max MB")
  C2P_ALIAS("global.log_max_mb", BIN_LTC, "--log-max-mb", VALUE)

C2P_PARAM("global.message_blob_hex", Global, HEX, LIVE, C_DASH|C_LTC, LIT, "", HEX_EVEN, "authority message blob hex")
  C2P_ALIAS("global.message_blob_hex", BIN_DASH, "--message-blob-hex", VALUE)
  C2P_ALIAS("global.message_blob_hex", BIN_DASH, "--transition-message", VALUE)
  C2P_ALIAS("global.message_blob_hex", BIN_LTC, "--message-blob-hex", VALUE)

C2P_PARAM("money.give_author_pct", Money, DOUBLE, MONEY_RESTART, C_DASH|C_LTC|C_BTC, FROM_POOL_CONFIG, "", PCT_0_100, "author/dev donation percent")
  C2P_ALIAS("money.give_author_pct", BIN_DASH, "--give-author", VALUE)
  C2P_ALIAS("money.give_author_pct", BIN_DASH, "--dev-donation", VALUE)
  C2P_ALIAS("money.give_author_pct", BIN_LTC, "--give-author", VALUE)
  C2P_ALIAS("money.give_author_pct", BIN_LTC, "--dev-donation", VALUE)
  C2P_ALIAS("money.give_author_pct", BIN_BTC, "--give-author", VALUE)
  C2P_ALIAS("money.give_author_pct", BIN_BTC, "--dev-donation", VALUE)

C2P_PARAM("money.node_owner_fee_pct", Money, DOUBLE, MONEY_RESTART, C_DASH|C_LTC|C_BTC, LIT, "0", PCT_0_100, "node-owner fee percent")
  C2P_ALIAS("money.node_owner_fee_pct", BIN_DASH, "--fee", VALUE)
  C2P_ALIAS("money.node_owner_fee_pct", BIN_DASH, "-f", SHORT)
  C2P_ALIAS("money.node_owner_fee_pct", BIN_LTC, "--fee", VALUE)
  C2P_ALIAS("money.node_owner_fee_pct", BIN_LTC, "-f", SHORT)
  C2P_ALIAS("money.node_owner_fee_pct", BIN_LTC, "--node-owner-fee", VALUE)
  C2P_ALIAS("money.node_owner_fee_pct", BIN_BTC, "--fee", VALUE)
  C2P_ALIAS("money.node_owner_fee_pct", BIN_BTC, "-f", SHORT)

C2P_PARAM("money.node_owner_address", Money, STRING, MONEY_RESTART, C_DASH|C_LTC|C_BTC|C_DGB, LIT, "", ADDR_COIN, "node-owner fee destination address")
  C2P_ALIAS("money.node_owner_address", BIN_DASH, "--node-owner-address", VALUE)
  C2P_ALIAS("money.node_owner_address", BIN_LTC, "--node-owner-address", VALUE)
  C2P_ALIAS("money.node_owner_address", BIN_BTC, "--node-owner-address", VALUE)
  C2P_ALIAS("money.node_owner_address", BIN_DGB, "--node-owner-address", VALUE)

C2P_PARAM("money.payout_address", Money, STRING, MONEY_RESTART, C_LTC, LIT, "", ADDR_COIN, "solo payout address")
  C2P_ALIAS("money.payout_address", BIN_LTC, "--address", VALUE)
  C2P_ALIAS("money.payout_address", BIN_LTC, "--solo-address", VALUE)

C2P_PARAM("money.node_owner_script", Money, HEX, MONEY_RESTART, C_LTC, LIT, "", HEX_EVEN, "node-owner output script")
  C2P_ALIAS("money.node_owner_script", BIN_LTC, "--node-owner-script", VALUE)

C2P_PARAM("money.merged_operator_address", Money, STRING, MONEY_RESTART, C_LTC|C_DOGE, LIT, "", ADDR_COIN, "merged (doge) fee address")
  C2P_ALIAS("money.merged_operator_address", BIN_LTC, "--node-owner-merged-address", VALUE)
  C2P_ALIAS("money.merged_operator_address", BIN_LTC, "--merged-operator-address", VALUE)

C2P_PARAM("money.payout_pubkey_hash", Money, HEX, MONEY_RESTART, C_DASH, LIT, "", HEX_EVEN, "P2PKH for mine-block")
  C2P_ALIAS("money.payout_pubkey_hash", BIN_DASH, "--payout-pubkey-hash", VALUE)

C2P_PARAM("money.auto_detect_wallet", Money, TRISTATE_BOOL, MONEY_RESTART, C_LTC, NONE, "", NONE, "auto-detect wallet (default on)")
  C2P_ALIAS("money.auto_detect_wallet", BIN_LTC, "--auto-detect-wallet", FLAG)
  C2P_ALIAS("money.auto_detect_wallet", BIN_LTC, "--no-auto-detect-wallet", FLAG_NO_PREFIX)

C2P_PARAM("money.redistribute", Money, ENUM_STR, MONEY_RESTART, C_DASH|C_LTC|C_DGB, LIT, "pplns", ENUM_MEMBER, "unnamed-share redistribution")
  C2P_ALIAS("money.redistribute", BIN_DASH, "--redistribute", VALUE)
  C2P_ALIAS("money.redistribute", BIN_LTC, "--redistribute", VALUE)
  C2P_ALIAS("money.redistribute", BIN_DGB, "--redistribute", VALUE)

C2P_PARAM("money.coinbase_text", Money, STRING, MONEY_RESTART, C_DASH|C_LTC, LIT, "", NONE, "coinbase attribution text")
  C2P_ALIAS("money.coinbase_text", BIN_DASH, "--coinbase-text", VALUE)
  C2P_ALIAS("money.coinbase_text", BIN_LTC, "--coinbase-text", VALUE)

C2P_PARAM("merged.spec", Merged, MERGED_SPEC, RESTART, C_BTC|C_LTC|C_NMC, LIT, "", NONE, "merged-mining spec SYMBOL:CHAIN:HOST:PORT:USER:PASS")
  C2P_ALIAS("merged.spec", BIN_LTC, "--merged", VALUE)
  C2P_ALIAS("merged.spec", BIN_BTC, "--merged", VALUE)

C2P_PARAM("merged.coind_address", Merged, STRING, RESTART, C_LTC|C_DOGE, LIT, "", NONE, "merged coind address")
  C2P_ALIAS("merged.coind_address", BIN_LTC, "--merged-coind-address", VALUE)

C2P_PARAM("merged.coind_rpc_port", Merged, INT64, RESTART, C_LTC|C_DOGE, LIT, "0", NONE, "merged coind RPC port")
  C2P_ALIAS("merged.coind_rpc_port", BIN_LTC, "--merged-coind-rpc-port", VALUE)

C2P_PARAM("merged.coind_rpc_user", Merged, STRING, RESTART, C_LTC|C_DOGE, LIT, "", NONE, "merged coind RPC user")
  C2P_ALIAS("merged.coind_rpc_user", BIN_LTC, "--merged-coind-rpc-user", VALUE)

C2P_PARAM("merged.coind_rpc_password", Merged, STRING, RESTART, C_LTC|C_DOGE, LIT, "", NONE, "merged coind RPC password")
  C2P_ALIAS("merged.coind_rpc_password", BIN_LTC, "--merged-coind-rpc-password", VALUE)

C2P_PARAM("merged.coind_p2p_port", Merged, INT64, RESTART, C_LTC|C_DOGE, LIT, "0", NONE, "merged coind P2P port")
  C2P_ALIAS("merged.coind_p2p_port", BIN_LTC, "--merged-coind-p2p-port", VALUE)

C2P_PARAM("merged.coind_p2p_address", Merged, STRING, RESTART, C_LTC|C_DOGE, LIT, "", NONE, "merged coind P2P address")
  C2P_ALIAS("merged.coind_p2p_address", BIN_LTC, "--merged-coind-p2p-address", VALUE)

C2P_PARAM("embedded.ltc_enabled", Embedded, TRISTATE_BOOL, RESTART, C_LTC, NONE, "", NONE, "embedded LTC SPV (default on)")
  C2P_ALIAS("embedded.ltc_enabled", BIN_LTC, "--embedded-ltc", FLAG)
  C2P_ALIAS("embedded.ltc_enabled", BIN_LTC, "--no-embedded-ltc", FLAG_NO_PREFIX)

C2P_PARAM("embedded.doge_enabled", Embedded, TRISTATE_BOOL, RESTART, C_LTC|C_DOGE, NONE, "", NONE, "embedded DOGE SPV (default on)")
  C2P_ALIAS("embedded.doge_enabled", BIN_LTC, "--embedded-doge", FLAG)
  C2P_ALIAS("embedded.doge_enabled", BIN_LTC, "--no-embedded-doge", FLAG_NO_PREFIX)

C2P_PARAM("embedded.header_checkpoint", Embedded, STRING, RESTART, C_LTC, LIT, "", NONE, "LTC header checkpoint H:HASH")
  C2P_ALIAS("embedded.header_checkpoint", BIN_LTC, "--header-checkpoint", VALUE)

C2P_PARAM("embedded.doge_header_checkpoint", Embedded, STRING, RESTART, C_LTC|C_DOGE, LIT, "", NONE, "DOGE header checkpoint H:HASH")
  C2P_ALIAS("embedded.doge_header_checkpoint", BIN_LTC, "--doge-header-checkpoint", VALUE)

C2P_PARAM("embedded.anchor", Embedded, STRING, RESTART, C_BCH, LIT, "", NONE, "BCH anchor H:HASH")
  C2P_ALIAS("embedded.anchor", BIN_BCH, "--anchor", VALUE)

C2P_PARAM("embedded.mainnet", Embedded, TRISTATE_BOOL, MONEY_RESTART, C_DASH, NONE, "", NONE, "gate-lift: embedded template on MAINNET")
  C2P_ALIAS("embedded.mainnet", BIN_DASH, "--embedded-mainnet", FLAG)

C2P_PARAM("embedded.utxo", Embedded, BOOL, RESTART, C_DASH, LIT, "false", NONE, "E2b UTXO/fee lane")
  C2P_ALIAS("embedded.utxo", BIN_DASH, "--embedded-utxo", FLAG)

C2P_PARAM("embedded.utxo_immature_serve_empty", Embedded, BOOL, RESTART, C_DASH, LIT, "false", NONE, "serve coinbase-only until mature")
  C2P_ALIAS("embedded.utxo_immature_serve_empty", BIN_DASH, "--embedded-utxo-immature-serve-empty", FLAG)

C2P_PARAM("embedded.superblock", Embedded, BOOL, RESTART, C_DASH, LIT, "false", NONE, "daemonless superblock payee sourcing")
  C2P_ALIAS("embedded.superblock", BIN_DASH, "--embedded-superblock", FLAG)

C2P_PARAM("embedded.govsync", Embedded, BOOL, RESTART, C_DASH, LIT, "false", NONE, "observe-only governance store")
  C2P_ALIAS("embedded.govsync", BIN_DASH, "--embedded-govsync", FLAG)

C2P_PARAM("embedded.serve_mempool_txs", Embedded, TRISTATE_BOOL, RESTART, C_DASH, NONE, "", NONE, "fee-carrying templates (daemonless default ON)")
  C2P_ALIAS("embedded.serve_mempool_txs", BIN_DASH, "--embedded-serve-mempool-txs", FLAG_OPT_EQFALSE)

C2P_PARAM("embedded.tx_serve_own_set", Embedded, TRISTATE_BOOL, MONEY_RESTART, C_DASH, NONE, "", NONE, "serve-time self-validation referee (default ON)")
  C2P_ALIAS("embedded.tx_serve_own_set", BIN_DASH, "--embedded-tx-serve-own-set", FLAG_OPT_EQFALSE)

C2P_PARAM("embedded.mempool_ingest", Embedded, TRISTATE_BOOL, RESTART, C_DASH, NONE, "", NONE, "coin-P2P MSG_TX pull (default ON)")
  C2P_ALIAS("embedded.mempool_ingest", BIN_DASH, "--embedded-mempool-ingest", FLAG_OPT_EQFALSE)

C2P_PARAM("embedded.ingest_isdlock", Embedded, TRISTATE_BOOL, RESTART, C_DASH, NONE, "", NONE, "MSG_ISDLOCK feed (default ON)")
  C2P_ALIAS("embedded.ingest_isdlock", BIN_DASH, "--embedded-ingest-isdlock", FLAG_OPT_EQFALSE)

C2P_PARAM("embedded.ingest_dstx", Embedded, TRISTATE_BOOL, RESTART, C_DASH, NONE, "", NONE, "CoinJoin DSTX lane (default ON)")
  C2P_ALIAS("embedded.ingest_dstx", BIN_DASH, "--embedded-ingest-dstx", FLAG_OPT_EQFALSE)

C2P_PARAM("embedded.accrue_asset_locks", Embedded, BOOL, RESTART, C_DASH, LIT, "false", NONE, "type-8 asset-lock fold")
  C2P_ALIAS("embedded.accrue_asset_locks", BIN_DASH, "--embedded-accrue-asset-locks", FLAG)

C2P_PARAM("embedded.accrue_asset_unlocks", Embedded, BOOL, RESTART, C_DASH, LIT, "false", NONE, "type-9 asset-unlock fold")
  C2P_ALIAS("embedded.accrue_asset_unlocks", BIN_DASH, "--embedded-accrue-asset-unlocks", FLAG)

C2P_PARAM("embedded.null_arm", Embedded, TRISTATE_BOOL, MONEY_RESTART, C_DASH, NONE, "", NONE, "optimistic null commitment (money/consensus)")
  C2P_ALIAS("embedded.null_arm", BIN_DASH, "--embedded-null-arm", FLAG_OPT_EQFALSE)

C2P_PARAM("embedded.fresh_datum_race", Embedded, TRISTATE_BOOL, LIVE, C_DASH, NONE, "", NONE, "race freshest getmnlistd (default ON)")
  C2P_ALIAS("embedded.fresh_datum_race", BIN_DASH, "--embedded-fresh-datum-race", FLAG_OPT_EQFALSE)

C2P_PARAM("embedded.fresh_datum_race_k", Embedded, INT64, LIVE, C_DASH, LIT, "2", NONE, "race K netgroups")
  C2P_ALIAS("embedded.fresh_datum_race_k", BIN_DASH, "--embedded-fresh-datum-race-k", VALUE)

C2P_PARAM("embedded.getmnlistd_tracker", Embedded, TRISTATE_BOOL, LIVE, C_DASH, NONE, "", NONE, "10s slot re-ask tracker (default ON)")
  C2P_ALIAS("embedded.getmnlistd_tracker", BIN_DASH, "--embedded-getmnlistd-tracker", FLAG_OPT_EQFALSE)

C2P_PARAM("embedded.asn_diversity", Embedded, TRISTATE_BOOL, LIVE, C_DASH, NONE, "", NONE, "require >=2 ASNs in racing set")
  C2P_ALIAS("embedded.asn_diversity", BIN_DASH, "--embedded-asn-diversity", FLAG_OPT_EQFALSE)

C2P_PARAM("embedded.proactive_rotate", Embedded, BOOL, LIVE, C_DASH, LIT, "false", NONE, "low-rate peer rotation")
  C2P_ALIAS("embedded.proactive_rotate", BIN_DASH, "--embedded-proactive-rotate", FLAG)

C2P_PARAM("embedded.peer_latency_score", Embedded, TRISTATE_BOOL, LIVE, C_DASH, NONE, "", NONE, "latency tie-break")
  C2P_ALIAS("embedded.peer_latency_score", BIN_DASH, "--embedded-peer-latency-score", FLAG_OPT_EQFALSE)

C2P_PARAM("embedded.fold_live", Embedded, PATH, RESTART, C_DASH, LIT, "", NONE, "PR-C1 fold store live path (pairs with expect)")
  C2P_ALIAS("embedded.fold_live", BIN_DASH, "--embedded-fold-live", VALUE)

C2P_PARAM("embedded.fold_live_expect", Embedded, HEX, RESTART, C_DASH, LIT, "", HEX_EVEN, "fold-live hash_serialized_2 expect")
  C2P_ALIAS("embedded.fold_live_expect", BIN_DASH, "--embedded-fold-live-expect", VALUE)

C2P_PARAM("embedded.fold_checkscripts", Embedded, BOOL, RESTART, C_DASH, LIT, "false", NONE, "consensus-exact input-script check")
  C2P_ALIAS("embedded.fold_checkscripts", BIN_DASH, "--embedded-fold-checkscripts", FLAG)

C2P_PARAM("embedded.utxo_fold_fees", Embedded, PATH, RESTART, C_DASH, LIT, "", NONE, "W5 fold fee pricing path (pairs with expect)")
  C2P_ALIAS("embedded.utxo_fold_fees", BIN_DASH, "--embedded-utxo-fold-fees", VALUE)

C2P_PARAM("embedded.utxo_fold_expect", Embedded, HEX, RESTART, C_DASH, LIT, "", HEX_EVEN, "fold-fees hash expect")
  C2P_ALIAS("embedded.utxo_fold_expect", BIN_DASH, "--embedded-utxo-fold-expect", VALUE)

C2P_PARAM("embedded.creditpool_publish_at_serve_tip", Embedded, BOOL, MONEY_RESTART, C_DASH, LIT, "false", NONE, "PR-5 creditpool publish (MONEY)")
  C2P_ALIAS("embedded.creditpool_publish_at_serve_tip", BIN_DASH, "--embedded-mined-commitment-index", FLAG)

C2P_PARAM("embedded.no_dashd_mn_seed", Embedded, BOOL, RESTART, C_DASH, LIT, "false", NONE, "cut E2c protx-list seed")
  C2P_ALIAS("embedded.no_dashd_mn_seed", BIN_DASH, "--embedded-no-dashd-mn-seed", FLAG)

C2P_PARAM("embedded.fold_only_proof", Embedded, BOOL, RESTART, C_DASH, LIT, "false", NONE, "strict fold-only payee population")
  C2P_ALIAS("embedded.fold_only_proof", BIN_DASH, "--embedded-fold-only-proof", FLAG)

C2P_PARAM("embedded.mn_bridge_max", Embedded, INT64, RESTART, C_DASH, LIT, "0", NONE, "anchor staleness bound")
  C2P_ALIAS("embedded.mn_bridge_max", BIN_DASH, "--embedded-mn-bridge-max", VALUE)

C2P_PARAM("embedded.mn_bridge_no_cursor", Embedded, BOOL, RESTART, C_DASH, LIT, "false", NONE, "disable bridge cursor")
  C2P_ALIAS("embedded.mn_bridge_no_cursor", BIN_DASH, "--embedded-mn-bridge-no-cursor", FLAG)

C2P_PARAM("embedded.oracle_shadow", Embedded, BOOL, RESTART, C_DASH, LIT, "false", NONE, "observe-only dashd cross-check")
  C2P_ALIAS("embedded.oracle_shadow", BIN_DASH, "--embedded-oracle-shadow", FLAG)

C2P_PARAM("embedded.shadow_compare", Embedded, BOOL, RESTART, C_DASH, LIT, "false", NONE, "observe-only serve-vs-dashd diff")
  C2P_ALIAS("embedded.shadow_compare", BIN_DASH, "--embedded-shadow-compare", FLAG)

C2P_PARAM("embedded.oracle_graduation_blocks", Embedded, INT64, LIVE, C_DASH, LIT, "5000", NONE, "oracle graduation block count")
  C2P_ALIAS("embedded.oracle_graduation_blocks", BIN_DASH, "--oracle-graduation-blocks", VALUE)

C2P_PARAM("embedded.oracle_class_coverage", Embedded, INT64, LIVE, C_DASH, LIT, "20", NONE, "oracle class coverage")
  C2P_ALIAS("embedded.oracle_class_coverage", BIN_DASH, "--oracle-class-coverage", VALUE)

C2P_PARAM("embedded.bestcl_policy", Embedded, ENUM_STR, MONEY_RESTART, C_DASH, LIT, "freshness", ENUM_MEMBER, "bestCL policy freshness|consensus-exact")
  C2P_ALIAS("embedded.bestcl_policy", BIN_DASH, "--bestcl-policy", VALUE)

C2P_PARAM("embedded.serve_gate_state_file", Embedded, PATH, RESTART, C_DASH, LIT, "", NONE, "cross-restart serve-gate accounting file")
  C2P_ALIAS("embedded.serve_gate_state_file", BIN_DASH, "--serve-gate-state-file", VALUE)

C2P_PARAM("embedded.regtest_force_won_block", Embedded, BOOL, MONEY_RESTART, C_DASH, LIT, "false", NONE, "fail-closed regtest E5 harness")
  C2P_ALIAS("embedded.regtest_force_won_block", BIN_DASH, "--regtest-force-won-block", FLAG)

C2P_PARAM("embedded.regtest_force_won_share", Embedded, BOOL, MONEY_RESTART, C_DGB, LIT, "false", NONE, "regtest-only forced won share")
  C2P_ALIAS("embedded.regtest_force_won_share", BIN_DGB, "--regtest-force-won-share", FLAG)

C2P_PARAM("embedded.dev_relax_algo_softforks", Embedded, BOOL, MONEY_RESTART, C_DGB, LIT, "false", NONE, "dev-only softfork relax (mainnet fail-closed)")
  C2P_ALIAS("embedded.dev_relax_algo_softforks", BIN_DGB, "--dev-relax-algo-softforks", FLAG)

C2P_PARAM("tx_ingestion.pin_local_tx_hex", TxIngestion, PATH, MONEY_RESTART, C_DASH, LIT, "", NONE, "PIN donation-tx blob path")
  C2P_ALIAS("tx_ingestion.pin_local_tx_hex", BIN_DASH, "--pin-local-tx-hex", VALUE)

C2P_PARAM("tx_ingestion.pin_splice_xcheck_arm", TxIngestion, BOOL, MONEY_RESTART, C_DASH, LIT, "false", NONE, "PIN splice cross-check arm")
  C2P_ALIAS("tx_ingestion.pin_splice_xcheck_arm", BIN_DASH, "--pin-splice-xcheck-arm", FLAG)

C2P_PARAM("tx_ingestion.pin_splice_block_budget", TxIngestion, INT64, MONEY_RESTART, C_DASH, LIT, "0", NONE, "PIN splice block budget")
  C2P_ALIAS("tx_ingestion.pin_splice_block_budget", BIN_DASH, "--pin-splice-block-budget", VALUE)

C2P_PARAM("replay.utxo_db", Replay, PATH, RESTART, C_DASH, LIT, "", NONE, "standalone fold status utility")
  C2P_ALIAS("replay.utxo_db", BIN_DASH, "--replay-utxo-db", VALUE)

C2P_PARAM("replay.utxo_hash", Replay, BOOL, RESTART, C_DASH, LIT, "false", NONE, "compute hash_serialized_2")
  C2P_ALIAS("replay.utxo_hash", BIN_DASH, "--replay-utxo-hash", FLAG)

C2P_PARAM("replay.utxo_expect", Replay, HEX, RESTART, C_DASH, LIT, "", HEX_EVEN, "gate compare hash")
  C2P_ALIAS("replay.utxo_expect", BIN_DASH, "--replay-utxo-expect", VALUE)

C2P_PARAM("replay.bulk", Replay, BOOL, RESTART, C_DASH, LIT, "false", NONE, "bulk replay")
  C2P_ALIAS("replay.bulk", BIN_DASH, "--replay-bulk", FLAG)

C2P_PARAM("replay.bulk_capture", Replay, PATH, RESTART, C_DASH, LIT, "", NONE, "bulk capture dir (implies bulk)")
  C2P_ALIAS("replay.bulk_capture", BIN_DASH, "--replay-bulk-capture", VALUE)

C2P_PARAM("replay.bulk_start", Replay, INT64, RESTART, C_DASH, LIT, "0", NONE, "bulk start height")
  C2P_ALIAS("replay.bulk_start", BIN_DASH, "--replay-bulk-start", VALUE)

C2P_PARAM("replay.fold_prestate", Replay, PATH, RESTART, C_DASH, LIT, "", NONE, "fold prestate path (implies bulk)")
  C2P_ALIAS("replay.fold_prestate", BIN_DASH, "--replay-fold-prestate", VALUE)

C2P_PARAM("replay.fold_quorums", Replay, BOOL, RESTART, C_DASH, LIT, "false", NONE, "fold quorums")
  C2P_ALIAS("replay.fold_quorums", BIN_DASH, "--replay-fold-quorums", FLAG)

C2P_PARAM("replay.fold_qsnapshot", Replay, PATH, RESTART, C_DASH, LIT, "", NONE, "fold qsnapshot path")
  C2P_ALIAS("replay.fold_qsnapshot", BIN_DASH, "--replay-fold-qsnapshot", VALUE)

C2P_PARAM("replay.fold_worklists", Replay, PATH, RESTART, C_DASH, LIT, "", NONE, "fold worklists path")
  C2P_ALIAS("replay.fold_worklists", BIN_DASH, "--replay-fold-worklists", VALUE)

C2P_PARAM("replay.mnlist_seed_height", Replay, INT64, RESTART, C_DASH, LIT, "0", NONE, "mnlist seed height (implies bulk)")
  C2P_ALIAS("replay.mnlist_seed_height", BIN_DASH, "--replay-mnlist-seed-height", VALUE)

C2P_PARAM("replay.mnlist_seed_source", Replay, STRING, RESTART, C_DASH, LIT, "", NONE, "mnlist seed source")
  C2P_ALIAS("replay.mnlist_seed_source", BIN_DASH, "--replay-mnlist-seed-source", VALUE)

C2P_PARAM("replay.mnlist_seed_file", Replay, PATH, RESTART, C_DASH, LIT, "", NONE, "mnlist seed file")
  C2P_ALIAS("replay.mnlist_seed_file", BIN_DASH, "--replay-mnlist-seed-file", VALUE)

C2P_PARAM("replay.mined_commitment_index", Replay, BOOL, RESTART, C_DASH, LIT, "false", NONE, "replay mined commitment index")
  C2P_ALIAS("replay.mined_commitment_index", BIN_DASH, "--replay-mined-commitment-index", FLAG)

C2P_PARAM("utility.submit_block", Meta, HEX, RESTART, C_DASH, LIT, "", HEX_EVEN, "one-shot submitblock hex")
  C2P_ALIAS("utility.submit_block", BIN_DASH, "--submit-block", VALUE)

C2P_PARAM("utility.submit_block_file", Meta, PATH, RESTART, C_DASH, LIT, "", NONE, "one-shot submitblock file")
  C2P_ALIAS("utility.submit_block_file", BIN_DASH, "--submit-block-file", VALUE)

C2P_PARAM("utility.dump_mn_checkpoint", Meta, STRING, RESTART, C_DASH, LIT, "", NONE, "dump MN checkpoint H FILE")
  C2P_ALIAS("utility.dump_mn_checkpoint", BIN_DASH, "--dump-mn-checkpoint", TWO_ARGS)

C2P_PARAM("utility.max_nonce", Meta, INT64, RESTART, C_DASH, LIT, "4294967295", NONE, "mine-block max nonce")
  C2P_ALIAS("utility.max_nonce", BIN_DASH, "--max-nonce", VALUE)

#undef C2P_PARAM
#undef C2P_ALIAS
