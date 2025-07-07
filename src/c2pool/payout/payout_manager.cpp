#include "payout_manager.hpp"
#include <algorithm>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <boost/process.hpp>
#include <nlohmann/json.hpp>
#include <core/log.hpp>

namespace c2pool {
namespace payout {

// DeveloperPayoutConfig implementation
DeveloperPayoutConfig::DeveloperPayoutConfig() {
    // C2Pool developer addresses for mainnet
    mainnet_addresses[Blockchain::LITECOIN] = "LhKRu8BydWjKAG6GyKHPz5Qf9xX9rVRVQg";  // LTC mainnet
    mainnet_addresses[Blockchain::BITCOIN] = "bc1qc2pool0dev0payment0addr0for0btc0mining";  // BTC mainnet
    mainnet_addresses[Blockchain::DOGECOIN] = "DQc2pool0dev0payment0addr0for0doge0mining";  // DOGE mainnet
    
    // C2Pool developer addresses for testnet
    testnet_addresses[Blockchain::LITECOIN] = "tltc1qc2pool0dev0testnet0addr0for0ltc0testing";  // LTC testnet
    testnet_addresses[Blockchain::BITCOIN] = "tb1qc2pool0dev0testnet0addr0for0btc0testing";  // BTC testnet
    testnet_addresses[Blockchain::DOGECOIN] = "nQc2pool0dev0testnet0addr0for0doge0testing";  // DOGE testnet
    
    // Other blockchains (placeholder addresses - would be real in production)
    mainnet_addresses[Blockchain::ETHEREUM] = "0xC2Pool0Dev0Payment0Addr0For0ETH0Mining";
    mainnet_addresses[Blockchain::MONERO] = "4C2Pool0Dev0Payment0Addr0For0XMR0Mining";
    mainnet_addresses[Blockchain::ZCASH] = "zc2pool0dev0payment0addr0for0zec0mining";
    
    testnet_addresses[Blockchain::ETHEREUM] = "0xC2Pool0Dev0Testnet0Addr0For0ETH0Testing";
    testnet_addresses[Blockchain::MONERO] = "5C2Pool0Dev0Testnet0Addr0For0XMR0Testing";
    testnet_addresses[Blockchain::ZCASH] = "ztc2pool0dev0testnet0addr0for0zec0testing";
}

std::string DeveloperPayoutConfig::get_developer_address(Blockchain blockchain, Network network) const {
    const auto& address_map = (network == Network::TESTNET) ? testnet_addresses : mainnet_addresses;
    auto it = address_map.find(blockchain);
    return (it != address_map.end()) ? it->second : "";
}

double DeveloperPayoutConfig::get_total_developer_fee() const {
    // Always include minimum attribution fee + user donation
    return std::max(default_fee_percent, configured_fee_percent);
}

bool DeveloperPayoutConfig::is_valid_developer_address(const std::string& address, Blockchain blockchain, Network network) const {
    return address == get_developer_address(blockchain, network);
}

// NodeOwnerPayoutConfig implementation
bool NodeOwnerPayoutConfig::is_valid() const {
    if (!enabled) return true;
    return !payout_address.empty() && fee_percent >= 0.0 && fee_percent <= 50.0;
}

void NodeOwnerPayoutConfig::set_payout_address(const std::string& address, Blockchain blockchain, Network network) {
    payout_address = address;
    validated_blockchain = blockchain;
    validated_network = network;
    address_validated = true;
    enabled = !address.empty();
}

// PayoutAllocation implementation
bool PayoutAllocation::is_valid() const {
    return total_reward > 0 && 
           miner_amount > 0 && 
           miner_amount <= total_reward &&
           (miner_amount + developer_amount + node_owner_amount) == total_reward &&
           !developer_address.empty();
}

// PayoutManager implementation
PayoutManager::PayoutManager(double pool_fee_percent, uint64_t payout_window_seconds)
    : pool_fee_percent_(pool_fee_percent)
    , payout_window_seconds_(payout_window_seconds)
    , blockchain_(Blockchain::LITECOIN)
    , network_(Network::MAINNET)
    , address_validator_()
{
}

PayoutManager::PayoutManager(Blockchain blockchain, Network network, double pool_fee_percent, uint64_t payout_window_seconds)
    : pool_fee_percent_(pool_fee_percent)
    , payout_window_seconds_(payout_window_seconds)
    , blockchain_(blockchain)
    , network_(network)
    , address_validator_(blockchain, network)
{
    LOG_INFO << "Initializing C2Pool Payout Manager";
    LOG_INFO << "  Blockchain: " << static_cast<int>(blockchain);
    LOG_INFO << "  Network: " << (network == Network::TESTNET ? "testnet" : "mainnet");
    LOG_INFO << "  Developer attribution: " << developer_config_.get_total_developer_fee() << "%";
    
    // Try to auto-detect wallet address if enabled
    if (node_owner_config_.auto_detect_from_wallet) {
        try_detect_wallet_address();
    }
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

// Developer payout system methods
PayoutAllocation PayoutManager::calculate_payout(uint64_t block_reward) const {
    PayoutAllocation allocation;
    allocation.total_reward = block_reward;
    
    // Calculate percentages
    allocation.developer_percent = developer_config_.get_total_developer_fee();
    allocation.node_owner_percent = node_owner_config_.enabled ? node_owner_config_.fee_percent : 0.0;
    allocation.miner_percent = 100.0 - allocation.developer_percent - allocation.node_owner_percent;
    
    // Ensure miner gets at least 49% (sanity check)
    if (allocation.miner_percent < 49.0) {
        LOG_WARNING << "Total fees exceed 51% of block reward, adjusting...";
        double total_fees = allocation.developer_percent + allocation.node_owner_percent;
        double scale_factor = 51.0 / total_fees;  // Scale down to max 51%
        
        allocation.developer_percent *= scale_factor;
        allocation.node_owner_percent *= scale_factor;
        allocation.miner_percent = 100.0 - allocation.developer_percent - allocation.node_owner_percent;
    }
    
    // Calculate amounts
    allocation.developer_amount = static_cast<uint64_t>(block_reward * allocation.developer_percent / 100.0);
    allocation.node_owner_amount = static_cast<uint64_t>(block_reward * allocation.node_owner_percent / 100.0);
    allocation.miner_amount = block_reward - allocation.developer_amount - allocation.node_owner_amount;
    
    // Set addresses
    allocation.developer_address = get_developer_address();
    allocation.node_owner_address = get_node_owner_address();
    
    return allocation;
}

void PayoutManager::set_developer_donation(double percent) {
    if (percent < 0.0 || percent > 50.0) {
        LOG_WARNING << "Developer donation must be between 0% and 50%, got: " << percent << "%";
        return;
    }
    
    developer_config_.configured_fee_percent = percent;
    LOG_INFO << "Developer donation set to " << percent << "% (total fee: " << developer_config_.get_total_developer_fee() << "%)";
}

void PayoutManager::set_node_owner_fee(double percent) {
    if (percent < 0.0 || percent > 50.0) {
        LOG_WARNING << "Node owner fee must be between 0% and 50%, got: " << percent << "%";
        return;
    }
    
    node_owner_config_.fee_percent = percent;
    node_owner_config_.enabled = (percent > 0.0);
    LOG_INFO << "Node owner fee set to " << percent << "%";
}

void PayoutManager::set_node_owner_address(const std::string& address) {
    if (address.empty()) {
        node_owner_config_.enabled = false;
        node_owner_config_.payout_address.clear();
        LOG_INFO << "Node owner payout disabled (no address provided)";
        return;
    }
    
    // Validate the address
    auto validation_result = address_validator_.validate_address(address);
    if (validation_result.is_valid) {
        node_owner_config_.set_payout_address(address, blockchain_, network_);
        LOG_INFO << "Node owner payout address set: " << address;
        LOG_INFO << "  Address type: " << static_cast<int>(validation_result.type);
        LOG_INFO << "  Fee: " << node_owner_config_.fee_percent << "%";
    } else {
        LOG_ERROR << "Invalid node owner address: " << address;
        LOG_ERROR << "  Error: " << validation_result.error_message;
        node_owner_config_.enabled = false;
    }
}

void PayoutManager::enable_auto_wallet_detection(bool enabled) {
    node_owner_config_.auto_detect_from_wallet = enabled;
    if (enabled) {
        try_detect_wallet_address();
    }
}

std::string PayoutManager::get_developer_address() const {
    return developer_config_.get_developer_address(blockchain_, network_);
}

std::string PayoutManager::get_node_owner_address() const {
    return node_owner_config_.enabled ? node_owner_config_.payout_address : "";
}

bool PayoutManager::has_node_owner_fee() const {
    return node_owner_config_.enabled && node_owner_config_.fee_percent > 0.0;
}

bool PayoutManager::validate_configuration() const {
    std::vector<std::string> errors = get_validation_errors();
    return errors.empty();
}

std::vector<std::string> PayoutManager::get_validation_errors() const {
    std::vector<std::string> errors;
    
    // Check developer configuration
    std::string dev_addr = get_developer_address();
    if (dev_addr.empty()) {
        errors.push_back("No developer address configured for this blockchain/network");
    }
    
    // Check node owner configuration
    if (node_owner_config_.enabled) {
        if (!node_owner_config_.is_valid()) {
            errors.push_back("Invalid node owner configuration");
        }
        
        if (node_owner_config_.payout_address.empty()) {
            errors.push_back("Node owner fee enabled but no address provided");
        }
    }
    
    // Check total fee sanity
    double total_fees = developer_config_.get_total_developer_fee() + 
                       (node_owner_config_.enabled ? node_owner_config_.fee_percent : 0.0);
    if (total_fees > 51.0) {
        errors.push_back("Total fees exceed 51% of block reward");
    }
    
    return errors;
}

bool PayoutManager::try_detect_wallet_address() {
    LOG_INFO << "Attempting to auto-detect wallet address from core wallet...";
    
    // Try RPC first
    if (detect_wallet_address_rpc()) {
        return true;
    }
    
    // Try wallet file detection
    if (detect_wallet_address_file()) {
        return true;
    }
    
    LOG_INFO << "Could not auto-detect wallet address. Use --node-owner-address to set manually.";
    return false;
}

bool PayoutManager::detect_wallet_address_rpc() {
    try {
        std::string command;
        std::string address;
        
        // Determine RPC command based on blockchain
        switch (blockchain_) {
            case Blockchain::LITECOIN:
                command = network_ == Network::TESTNET ? "litecoin-cli -testnet" : "litecoin-cli";
                break;
            case Blockchain::BITCOIN:
                command = network_ == Network::TESTNET ? "bitcoin-cli -testnet" : "bitcoin-cli";
                break;
            case Blockchain::DOGECOIN:
                command = network_ == Network::TESTNET ? "dogecoin-cli -testnet" : "dogecoin-cli";
                break;
            default:
                LOG_INFO << "Auto-detection not supported for this blockchain yet";
                return false;
        }
        
        // Try to get a receiving address
        std::string full_command = command + " getnewaddress \"c2pool_node_owner\"";
        
        namespace bp = boost::process;
        bp::ipstream pipe_stream;
        bp::child rpc_process(full_command, bp::std_out > pipe_stream, bp::std_err > bp::null);
        
        std::string line;
        if (std::getline(pipe_stream, line) && !line.empty()) {
            // Remove whitespace and quotes
            address = line;
            address.erase(0, address.find_first_not_of(" \t\r\n\""));
            address.erase(address.find_last_not_of(" \t\r\n\"") + 1);
            
            rpc_process.wait();
            
            if (rpc_process.exit_code() == 0 && !address.empty()) {
                LOG_INFO << "Auto-detected wallet address from RPC: " << address;
                set_node_owner_address(address);
                return true;
            }
        }
        
        rpc_process.wait();
        
    } catch (const std::exception& e) {
        LOG_INFO << "RPC auto-detection failed: " << e.what();
    }
    
    return false;
}

bool PayoutManager::detect_wallet_address_file() {
    // This is a simplified approach - in a real implementation,
    // you'd parse the wallet.dat file or look for address files
    LOG_INFO << "File-based address detection not implemented yet";
    return false;
}

std::string PayoutManager::execute_core_rpc(const std::string& method, const std::string& params) const {
    // Implementation for RPC calls to core wallet
    // This is a placeholder - real implementation would use proper RPC client
    return "";
}

} // namespace payout
} // namespace c2pool
