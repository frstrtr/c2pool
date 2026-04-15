#include "runtime_config.hpp"

namespace core {

nlohmann::json RuntimeConfig::to_json() const
{
    nlohmann::json j;

    // Mode
    j["testnet"] = testnet;
    j["integrated"] = integrated;
    j["sharechain"] = sharechain;
    j["solo"] = solo;
    j["custodial"] = custodial;
    j["blockchain"] = blockchain;

    // Ports
    j["p2p_port"] = p2p_port;
    j["stratum_port"] = stratum_port;
    j["http_port"] = http_port;
    j["http_host"] = http_host;
    if (!external_ip.empty())
        j["external_ip"] = external_ip;

    // Coin daemon (host/port only -- credentials excluded)
    j["rpc_host"] = rpc_host;
    j["rpc_port"] = rpc_port;
    if (!coind_p2p_address.empty())
        j["coind_p2p_address"] = coind_p2p_address;
    if (coind_p2p_port > 0)
        j["coind_p2p_port"] = coind_p2p_port;

    // Embedded SPV
    j["embedded_ltc"] = embedded_ltc;
    j["embedded_doge"] = embedded_doge;
    j["doge_testnet4alpha"] = doge_testnet4alpha;

    // Payout
    if (!payout_address.empty())
        j["payout_address"] = payout_address;
    if (!node_owner_address.empty())
        j["node_owner_address"] = node_owner_address;
    if (!node_owner_merged_address.empty())
        j["node_owner_merged_address"] = node_owner_merged_address;
    j["node_owner_fee"] = node_owner_fee;
    j["dev_donation"] = dev_donation;
    j["redistribute_mode"] = redistribute_mode;
    j["payout_window"] = payout_window;
    j["auto_detect_wallet"] = auto_detect_wallet;

    // Stratum tuning
    j["stratum_min_diff"] = stratum_min_diff;
    j["stratum_max_diff"] = stratum_max_diff;
    j["stratum_target_time"] = stratum_target_time;
    j["vardiff_enabled"] = vardiff_enabled;
    j["max_coinbase_outputs"] = max_coinbase_outputs;

    // Network
    j["seed_nodes"] = seed_nodes;
    j["max_outgoing_conns"] = max_outgoing_conns;
    j["p2p_max_peers"] = p2p_max_peers;
    j["ban_duration"] = ban_duration;

    // Logging
    j["log_level"] = log_level;
    if (!log_file.empty())
        j["log_file"] = log_file;
    j["log_rotation_mb"] = log_rotation_mb;
    j["log_max_mb"] = log_max_mb;

    // Performance
    j["rss_limit_mb"] = rss_limit_mb;
    j["storage_save_interval"] = storage_save_interval;

    // Merged mining
    j["merged_chains"] = merged_chain_specs;

    // Advanced
    if (!coinbase_text.empty())
        j["coinbase_text"] = coinbase_text;
    if (!cors_origin.empty())
        j["cors_origin"] = cors_origin;
    if (!dashboard_dir.empty())
        j["dashboard_dir"] = dashboard_dir;

    return j;
}

} // namespace core
