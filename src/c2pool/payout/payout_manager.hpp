#pragma once

#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <chrono>
#include <nlohmann/json.hpp>

namespace c2pool {
namespace payout {

/**
 * @brief Structure to track miner contributions for payout calculation
 */
struct MinerContribution {
    std::string address;                // Payout address
    double total_difficulty;            // Sum of accepted share difficulties
    uint64_t share_count;              // Number of accepted shares
    uint64_t last_share_time;          // Timestamp of last share
    double estimated_hashrate;         // Estimated miner hashrate
    
    MinerContribution() : total_difficulty(0.0), share_count(0), 
                         last_share_time(0), estimated_hashrate(0.0) {}
    
    MinerContribution(const std::string& addr) 
        : address(addr), total_difficulty(0.0), share_count(0),
          last_share_time(0), estimated_hashrate(0.0) {}
};

/**
 * @brief Manages payout calculations and coinbase construction
 */
class PayoutManager {
public:
    PayoutManager(double pool_fee_percent = 1.0, uint64_t payout_window_seconds = 86400);
    ~PayoutManager() = default;
    
    // Mining share tracking
    void record_share_contribution(const std::string& miner_address, double difficulty);
    
    // Coinbase construction
    std::string build_coinbase_output(uint64_t block_reward_satoshis, const std::string& primary_address = "");
    std::vector<std::pair<std::string, uint64_t>> calculate_payout_distribution(uint64_t total_reward_satoshis);
    
    // Payout management
    void set_pool_fee_percent(double fee_percent);
    void set_primary_pool_address(const std::string& address);
    double get_miner_contribution_percent(const std::string& address);
    nlohmann::json get_payout_statistics();
    
    // Cleanup and maintenance
    void cleanup_old_contributions(uint64_t cutoff_time);
    size_t get_active_miners_count() const;
    
private:
    mutable std::mutex contributions_mutex_;
    std::map<std::string, MinerContribution> miner_contributions_;
    
    double pool_fee_percent_;              // Pool fee (e.g., 1.0 for 1%)
    std::string primary_pool_address_;     // Primary pool payout address
    uint64_t payout_window_seconds_;       // Time window for contribution calculation
    
    // Helper methods
    double calculate_total_difficulty() const;
    std::string address_to_script_hex(const std::string& address) const;
    uint64_t get_current_timestamp() const;
    
    // Constants
    static constexpr uint64_t MINIMUM_PAYOUT_SATOSHIS = 100000; // 0.001 LTC
    static constexpr size_t MAX_COINBASE_OUTPUTS = 10; // Limit coinbase outputs
};

} // namespace payout
} // namespace c2pool
