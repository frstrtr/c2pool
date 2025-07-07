#include "payout_manager.hpp"
#include <algorithm>
#include <ctime>
#include <sstream>
#include <iomanip>

namespace c2pool {
namespace payout {

PayoutManager::PayoutManager(double pool_fee_percent, uint64_t payout_window_seconds)
    : pool_fee_percent_(pool_fee_percent)
    , payout_window_seconds_(payout_window_seconds)
{
}

void PayoutManager::record_share_contribution(const std::string& miner_address, double difficulty) {
    std::lock_guard<std::mutex> lock(contributions_mutex_);
    
    uint64_t current_time = get_current_timestamp();
    
    auto& contribution = miner_contributions_[miner_address];
    if (contribution.address.empty()) {
        contribution.address = miner_address;
    }
    
    contribution.total_difficulty += difficulty;
    contribution.share_count++;
    contribution.last_share_time = current_time;
    
    // Update estimated hashrate (simplified calculation)
    if (contribution.share_count > 1) {
        uint64_t time_window = std::min(current_time - (current_time - 300), uint64_t(300)); // 5 min window
        contribution.estimated_hashrate = contribution.total_difficulty / time_window * 4294967296.0; // 2^32 for difficulty scaling
    }
    
    // Clean up old contributions periodically
    if (miner_contributions_.size() % 10 == 0) {
        cleanup_old_contributions(current_time - payout_window_seconds_);
    }
}

std::string PayoutManager::build_coinbase_output(uint64_t block_reward_satoshis, const std::string& primary_address) {
    std::lock_guard<std::mutex> lock(contributions_mutex_);
    
    // Use provided primary address or stored pool address
    std::string pool_address = primary_address.empty() ? primary_pool_address_ : primary_address;
    
    // If no specific payout distribution is needed, use single address
    if (miner_contributions_.empty() || pool_address.empty()) {
        // Fallback to a simple single-output coinbase
        if (pool_address.empty()) {
            pool_address = "n4HFXoG2xEKFyzpGarucZzAd98seabNTPq"; // Default testnet address for testing
        }
        
        std::stringstream coinb2;
        coinb2 << "ffffffff01";
        
        // Amount (little endian, 8 bytes)
        coinb2 << std::hex << std::setfill('0') << std::setw(16) 
               << ((block_reward_satoshis & 0xFF00000000000000ULL) >> 56)
               << ((block_reward_satoshis & 0x00FF000000000000ULL) >> 48)
               << ((block_reward_satoshis & 0x0000FF0000000000ULL) >> 40)
               << ((block_reward_satoshis & 0x000000FF00000000ULL) >> 32)
               << ((block_reward_satoshis & 0x00000000FF000000ULL) >> 24)
               << ((block_reward_satoshis & 0x0000000000FF0000ULL) >> 16)
               << ((block_reward_satoshis & 0x000000000000FF00ULL) >> 8)
               << (block_reward_satoshis & 0x00000000000000FFULL);
        
        // Script for P2PKH (most common)
        coinb2 << "1976a914";
        
        // Address hash160 (placeholder - would need proper address decoding)
        coinb2 << "89abcdefabbaabbaabbaabbaabbaabbaabbaabba";
        
        // OP_EQUALVERIFY OP_CHECKSIG
        coinb2 << "88ac";
        
        return coinb2.str();
    }
    
    // Calculate payout distribution
    auto payouts = calculate_payout_distribution(block_reward_satoshis);
    
    // Build multi-output coinbase (simplified version)
    std::stringstream coinb2;
    coinb2 << "ffffffff";
    
    // Number of outputs (max MAX_COINBASE_OUTPUTS)
    size_t output_count = std::min(payouts.size(), MAX_COINBASE_OUTPUTS);
    coinb2 << std::hex << std::setfill('0') << std::setw(2) << output_count;
    
    // Add each output
    for (size_t i = 0; i < output_count; ++i) {
        const auto& payout = payouts[i];
        
        // Amount (8 bytes, little endian)
        uint64_t amount = payout.second;
        for (int byte = 0; byte < 8; ++byte) {
            coinb2 << std::hex << std::setfill('0') << std::setw(2) 
                   << ((amount >> (byte * 8)) & 0xFF);
        }
        
        // Script (simplified P2PKH)
        std::string script_hex = address_to_script_hex(payout.first);
        coinb2 << script_hex;
    }
    
    return coinb2.str();
}

std::vector<std::pair<std::string, uint64_t>> PayoutManager::calculate_payout_distribution(uint64_t total_reward_satoshis) {
    std::lock_guard<std::mutex> lock(contributions_mutex_);
    
    std::vector<std::pair<std::string, uint64_t>> payouts;
    
    // Calculate pool fee
    uint64_t pool_fee_satoshis = static_cast<uint64_t>(total_reward_satoshis * pool_fee_percent_ / 100.0);
    uint64_t miner_reward_satoshis = total_reward_satoshis - pool_fee_satoshis;
    
    // Calculate total difficulty
    double total_difficulty = calculate_total_difficulty();
    if (total_difficulty == 0.0) {
        // No contributions, everything goes to pool
        if (!primary_pool_address_.empty()) {
            payouts.emplace_back(primary_pool_address_, total_reward_satoshis);
        }
        return payouts;
    }
    
    // Add pool fee payout
    if (pool_fee_satoshis > 0 && !primary_pool_address_.empty()) {
        payouts.emplace_back(primary_pool_address_, pool_fee_satoshis);
    }
    
    // Distribute rewards based on contribution percentage
    for (const auto& [address, contribution] : miner_contributions_) {
        if (contribution.total_difficulty > 0) {
            double contribution_percent = contribution.total_difficulty / total_difficulty;
            uint64_t miner_payout = static_cast<uint64_t>(miner_reward_satoshis * contribution_percent);
            
            // Only include payouts above minimum threshold
            if (miner_payout >= MINIMUM_PAYOUT_SATOSHIS) {
                payouts.emplace_back(address, miner_payout);
            }
        }
    }
    
    // Sort by payout amount (descending) to prioritize larger payouts
    std::sort(payouts.begin(), payouts.end(), 
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    return payouts;
}

void PayoutManager::set_pool_fee_percent(double fee_percent) {
    std::lock_guard<std::mutex> lock(contributions_mutex_);
    pool_fee_percent_ = std::max(0.0, std::min(100.0, fee_percent));
}

void PayoutManager::set_primary_pool_address(const std::string& address) {
    std::lock_guard<std::mutex> lock(contributions_mutex_);
    primary_pool_address_ = address;
}

double PayoutManager::get_miner_contribution_percent(const std::string& address) {
    std::lock_guard<std::mutex> lock(contributions_mutex_);
    
    double total_difficulty = calculate_total_difficulty();
    if (total_difficulty == 0.0) return 0.0;
    
    auto it = miner_contributions_.find(address);
    if (it == miner_contributions_.end()) return 0.0;
    
    return (it->second.total_difficulty / total_difficulty) * 100.0;
}

nlohmann::json PayoutManager::get_payout_statistics() {
    std::lock_guard<std::mutex> lock(contributions_mutex_);
    
    nlohmann::json stats;
    stats["pool_fee_percent"] = pool_fee_percent_;
    stats["active_miners"] = miner_contributions_.size();
    stats["total_difficulty"] = calculate_total_difficulty();
    stats["payout_window_hours"] = payout_window_seconds_ / 3600.0;
    
    nlohmann::json miner_stats = nlohmann::json::array();
    double total_difficulty = calculate_total_difficulty();
    
    for (const auto& [address, contribution] : miner_contributions_) {
        nlohmann::json miner;
        miner["address"] = address;
        miner["total_difficulty"] = contribution.total_difficulty;
        miner["share_count"] = contribution.share_count;
        miner["estimated_hashrate"] = contribution.estimated_hashrate;
        
        // Calculate contribution percent directly (avoid deadlock)
        double contribution_percent = 0.0;
        if (total_difficulty > 0.0) {
            contribution_percent = (contribution.total_difficulty / total_difficulty) * 100.0;
        }
        miner["contribution_percent"] = contribution_percent;
        
        miner_stats.push_back(miner);
    }
    stats["miners"] = miner_stats;
    
    return stats;
}

void PayoutManager::cleanup_old_contributions(uint64_t cutoff_time) {
    // Remove contributions older than cutoff time
    auto it = miner_contributions_.begin();
    while (it != miner_contributions_.end()) {
        if (it->second.last_share_time < cutoff_time) {
            it = miner_contributions_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t PayoutManager::get_active_miners_count() const {
    std::lock_guard<std::mutex> lock(contributions_mutex_);
    return miner_contributions_.size();
}

double PayoutManager::calculate_total_difficulty() const {
    double total = 0.0;
    for (const auto& [address, contribution] : miner_contributions_) {
        total += contribution.total_difficulty;
    }
    return total;
}

std::string PayoutManager::address_to_script_hex(const std::string& address) const {
    // Simplified script generation - in production would need proper address decoding
    // For now, return a standard P2PKH script template
    
    // P2PKH script: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    // 0x76 0xa9 0x14 <20 bytes> 0x88 0xac
    
    std::stringstream script;
    script << "1976a914";
    
    // This is a placeholder - in production, you'd decode the address to get the hash160
    // For testing, use a fixed hash
    script << "89abcdefabbaabbaabbaabbaabbaabbaabbaabba";
    
    script << "88ac";
    
    return script.str();
}

uint64_t PayoutManager::get_current_timestamp() const {
    return static_cast<uint64_t>(std::time(nullptr));
}

} // namespace payout
} // namespace c2pool
