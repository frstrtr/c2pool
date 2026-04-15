#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace core {

/// Aggregated runtime configuration for the c2pool daemon.
///
/// Populated from CLI args + config file in main(), then passed to
/// WebServer/MiningInterface so it can be exposed via GET /config.
/// RPC credentials are intentionally excluded from serialization.
struct RuntimeConfig {
    // Mode
    bool testnet = false;
    bool integrated = false;
    bool sharechain = false;
    bool solo = false;
    bool custodial = false;
    std::string blockchain = "litecoin";

    // Ports
    int p2p_port = 9326;
    int stratum_port = 9327;
    int http_port = 8080;
    std::string http_host = "0.0.0.0";
    std::string external_ip;

    // Coin daemon (host/port only -- credentials excluded for security)
    std::string rpc_host = "127.0.0.1";
    int rpc_port = 0;
    std::string coind_p2p_address;
    int coind_p2p_port = 0;

    // Embedded SPV
    bool embedded_ltc = true;
    bool embedded_doge = true;
    bool doge_testnet4alpha = false;

    // Payout
    std::string payout_address;
    std::string node_owner_address;
    std::string node_owner_merged_address;
    double node_owner_fee = 0.0;
    double dev_donation = 0.0;
    std::string redistribute_mode = "pplns";
    int payout_window = 86400;
    bool auto_detect_wallet = true;

    // Stratum tuning
    double stratum_min_diff = 0.0005;
    double stratum_max_diff = 65536.0;
    double stratum_target_time = 3.0;
    bool vardiff_enabled = true;
    int max_coinbase_outputs = 4000;

    // Network
    std::vector<std::string> seed_nodes;
    int max_outgoing_conns = 0;
    int p2p_max_peers = 30;
    int ban_duration = 300;

    // Logging
    std::string log_level = "info";
    std::string log_file;
    int log_rotation_mb = 100;
    int log_max_mb = 50;

    // Performance
    int rss_limit_mb = 4000;
    int storage_save_interval = 300;

    // Merged mining
    std::vector<std::string> merged_chain_specs;

    // Advanced
    std::string coinbase_text;
    std::string cors_origin;
    std::string dashboard_dir;

    /// Serialize to JSON for the /config REST endpoint.
    /// Intentionally omits RPC credentials and auth tokens.
    nlohmann::json to_json() const;
};

} // namespace core
