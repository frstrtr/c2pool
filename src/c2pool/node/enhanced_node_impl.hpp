#pragma once

// Coin-agnostic template for the enhanced c2pool node.
// Parameterized over Config, ShareChain, Peer, ShareType so it works for any
// Bitcoin-family coin (LTC, Dash, DOGE, BTC...).  The concrete aliases live in
// impl/<coin>/enhanced_node.hpp (and in this directory's enhanced_node.hpp for
// LTC's backward-compat alias).

#include <memory>
#include <map>
#include <string>
#include <vector>
#include <ctime>
#include <functional>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include <c2pool/storage/sharechain_storage.hpp>
#include <c2pool/hashrate/tracker.hpp>
#include <c2pool/difficulty/adjustment_engine.hpp>
#include <core/mining_node_interface.hpp>
#include <core/message.hpp>
#include <core/common.hpp>
#include <core/log.hpp>
#include <core/netaddress.hpp>
#include <core/uint256.hpp>

namespace c2pool {
namespace node {

template <typename Config, typename ShareChain, typename Peer, typename ShareType>
class EnhancedC2PoolNodeT : public core::IMiningNode
{
protected:
    std::unique_ptr<storage::SharechainStorage> m_storage;
    uint64_t m_shares_since_save = 0;
    difficulty::DifficultyAdjustmentEngine m_difficulty_adjustment_engine;
    std::unique_ptr<hashrate::HashrateTracker> m_hashrate_tracker;

    boost::asio::io_context* m_context = nullptr;
    Config* m_config = nullptr;
    ShareChain* m_chain = nullptr;
    std::map<NetService, std::shared_ptr<Peer>> m_connections;

public:
    explicit EnhancedC2PoolNodeT(bool /*testnet*/ = false)
    {
        m_hashrate_tracker = std::make_unique<hashrate::HashrateTracker>();
        m_hashrate_tracker->set_difficulty_bounds(0.001, 65536.0);
        // NodeImpl opens LevelDB for sharechain persist; we don't open a second
        // store here (would fail with LOCK already held).
        LOG_INFO << "Enhanced C2Pool node initialized with default configuration";
        LOG_INFO << "  - Automatic difficulty adjustment";
        LOG_INFO << "  - Real-time hashrate tracking";
        LOG_INFO << "  - Persistent storage (managed by NodeImpl)";
    }

    EnhancedC2PoolNodeT(boost::asio::io_context* ctx, Config* config)
        : m_context(ctx), m_config(config)
    {
        m_hashrate_tracker = std::make_unique<hashrate::HashrateTracker>();
        m_hashrate_tracker->set_difficulty_bounds(0.001, 65536.0);
        LOG_INFO << "Enhanced C2Pool node initialized with:";
        LOG_INFO << "  - Automatic difficulty adjustment";
        LOG_INFO << "  - Real-time hashrate tracking";
        LOG_INFO << "  - Persistent storage (managed by NodeImpl)";
    }

    ~EnhancedC2PoolNodeT() override = default;

    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service)
    {
        LOG_INFO << "Enhanced C2Pool node received message: " << rmsg->m_command
                 << " from " << service.to_string();
    }

    std::string get_mining_work(const std::string& address)
    {
        auto current_difficulty = m_hashrate_tracker->get_current_difficulty();
        auto pool_target = m_difficulty_adjustment_engine.get_pool_target();
        nlohmann::json work = {
            {"target", pool_target.ToString()},
            {"difficulty", current_difficulty},
            {"address", address},
            {"timestamp", static_cast<uint64_t>(std::time(nullptr))}
        };
        return work.dump();
    }

    bool submit_mining_work(const std::string& work_data)
    {
        try {
            auto work = nlohmann::json::parse(work_data);
            double difficulty = work.value("difficulty", 1.0);
            m_hashrate_tracker->record_share_submission(difficulty, true);
            LOG_INFO << "Mining work submitted with difficulty " << difficulty;
            return true;
        } catch (const std::exception& e) {
            LOG_ERROR << "Failed to submit mining work: " << e.what();
            return false;
        }
    }

    nlohmann::json get_mining_stats()
    {
        nlohmann::json stats;
        stats["hashrate"] = get_hashrate_stats();
        stats["difficulty"] = get_difficulty_stats();
        stats["mining_shares"] = {
            {"total", get_total_mining_shares()},
            {"since_save", m_shares_since_save}
        };
        stats["network"] = {
            {"connected_peers", get_connected_peers_count()}
        };
        return stats;
    }

    double get_current_difficulty()
    {
        return m_hashrate_tracker->get_current_difficulty();
    }

    void add_shares_to_chain(const std::vector<ShareType>& shares)
    {
        m_shares_since_save += shares.size();
        if (m_shares_since_save >= 100 && m_storage && m_chain) {
            LOG_INFO << "Saving sharechain due to threshold (" << m_shares_since_save << " new shares)";
            m_storage->save_sharechain(*m_chain);
            m_shares_since_save = 0;
        }
    }

    void listen(int port)
    {
        LOG_INFO << "Enhanced C2Pool node starting to listen on port " << port;
    }

    void shutdown()
    {
        LOG_INFO << "Shutting down Enhanced C2Pool node, saving sharechain...";
        if (m_storage && m_chain) {
            m_storage->save_sharechain(*m_chain);
            m_storage->log_storage_stats();
        }
    }

    void log_sharechain_stats() override
    {
        uint64_t total = get_total_mining_shares();
        LOG_INFO << "Enhanced C2Pool Sharechain stats:";
        LOG_INFO << "  Total mining_shares: " << total;
        LOG_INFO << "  Connected peers: " << get_connected_peers_count();
        LOG_INFO << "  Storage: " << (m_storage && m_storage->is_available() ? "enabled" : "disabled");

        if (m_hashrate_tracker) {
            auto stats = m_hashrate_tracker->get_statistics();
            LOG_INFO << "  Current difficulty: " << stats["current_difficulty"];
            LOG_INFO << "  Current hashrate: " << stats["current_hashrate"] << " H/s";
            LOG_INFO << "  Total mining_shares submitted: " << stats["total_shares_submitted"];
            LOG_INFO << "  Total mining_shares accepted: " << stats["total_shares_accepted"];
            LOG_INFO << "  Acceptance rate (last hour): " << stats["acceptance_rate_1h"] << "%";
        }

        LOG_INFO << "  Difficulty Adjustment Stats:";
        auto diff_stats = m_difficulty_adjustment_engine.get_difficulty_stats();
        LOG_INFO << "    Pool difficulty: " << diff_stats["pool_difficulty"];
        LOG_INFO << "    Network difficulty: " << diff_stats["network_difficulty"];
        LOG_INFO << "    Mining_shares since adjustment: " << diff_stats["shares_since_adjustment"];
        LOG_INFO << "    Target mining_shares per adjustment: " << diff_stats["target_shares_per_adjustment"];
    }

    void track_mining_share_submission(const std::string& session_id, double difficulty) override
    {
        if (m_hashrate_tracker)
            m_hashrate_tracker->record_share_submission(difficulty, true);
        LOG_DEBUG_OTHER << "Tracked mining_share submission for session " << session_id
                        << " with difficulty " << difficulty;
    }

    nlohmann::json get_difficulty_stats() const override
    {
        return m_difficulty_adjustment_engine.get_difficulty_stats();
    }

    nlohmann::json get_hashrate_stats() const override
    {
        if (m_hashrate_tracker)
            return m_hashrate_tracker->get_statistics();
        return nlohmann::json{{"global_hashrate", 0.0}};
    }

    void add_local_mining_share(const uint256& /*hash*/, const uint256& /*prev_hash*/, const uint256& /*target*/) override
    {
        // Handled by the real share creation pipeline (create_local_share + broadcast).
        // This stub satisfies the IMiningNode interface.
    }

    // Optional overrides — used by coin targets that own their own tracker
    // (c2pool-dash passes DashNodeImpl accessors). Leave unset and the
    // defaults below fall back to m_chain/m_connections.
    void set_total_shares_fn(std::function<uint64_t()> fn) { m_total_shares_fn = std::move(fn); }
    void set_connected_peers_fn(std::function<size_t()> fn) { m_connected_peers_fn = std::move(fn); }

    uint64_t get_total_mining_shares() const override
    {
        if (m_total_shares_fn) return m_total_shares_fn();
        return m_chain ? static_cast<uint64_t>(m_chain->size()) : 0;
    }

    size_t get_connected_peers_count() const override
    {
        if (m_connected_peers_fn) return m_connected_peers_fn();
        return m_connections.size();
    }

    nlohmann::json get_stale_stats() const override
    {
        nlohmann::json result;
        result["orphan_count"] = 0;
        result["doa_count"] = 0;
        result["stale_count"] = 0;
        result["stale_prop"] = 0.0;
        return result;
    }

    storage::SharechainStorage* get_storage() const { return m_storage.get(); }
    hashrate::HashrateTracker* get_hashrate_tracker() const { return m_hashrate_tracker.get(); }
    difficulty::DifficultyAdjustmentEngine& get_difficulty_engine() { return m_difficulty_adjustment_engine; }

private:
    std::function<uint64_t()> m_total_shares_fn;
    std::function<size_t()>   m_connected_peers_fn;
};

} // namespace node
} // namespace c2pool
