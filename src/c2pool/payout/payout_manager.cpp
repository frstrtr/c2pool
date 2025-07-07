#include "payout_manager.hpp"
#include <algorithm>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <filesystem>
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
    // If user has not configured any donation, we'll use minimal attribution instead of percentage
    if (configured_fee_percent == 0.0 && minimal_attribution_mode) {
        return 0.0;  // Will be handled by get_developer_amount() for minimal attribution
    }
    // Use configured donation or default fee, whichever is higher
    return std::max(default_fee_percent, configured_fee_percent);
}

uint64_t DeveloperPayoutConfig::get_developer_amount(uint64_t block_reward) const {
    if (configured_fee_percent == 0.0 && minimal_attribution_mode) {
        // Use minimal attribution (1 satoshi) for software marking
        return MINIMAL_ATTRIBUTION_SATOSHIS;
    }
    
    // Use percentage-based calculation for donations
    double percentage = get_total_developer_fee();
    return static_cast<uint64_t>(block_reward * percentage / 100.0);
}

bool DeveloperPayoutConfig::use_minimal_attribution() const {
    return configured_fee_percent == 0.0 && minimal_attribution_mode;
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

void NodeOwnerPayoutConfig::set_payout_script(const std::string& script_hex, Blockchain blockchain, Network network) {
    payout_script_hex = script_hex;
    validated_blockchain = blockchain;
    validated_network = network;
    
    // Try to derive address from script
    std::string derived_address = generate_address_from_script(blockchain, network);
    if (!derived_address.empty()) {
        payout_address = derived_address;
        address_validated = true;
        enabled = true;
        address_source = AddressSource::SCRIPT_DERIVED;
    }
}

std::string NodeOwnerPayoutConfig::generate_address_from_script(Blockchain blockchain, Network network) const {
    if (payout_script_hex.empty()) {
        return "";
    }
    
    try {
        // This is a simplified implementation
        // In a real implementation, you would:
        // 1. Parse the script hex
        // 2. Create a P2SH address from the script hash
        // 3. Format according to blockchain and network type
        
        LOG_INFO << "Generating address from script for " 
                 << (blockchain == Blockchain::LITECOIN ? "LTC" : "BTC")
                 << " " << (network == Network::TESTNET ? "testnet" : "mainnet");
                 
        // Placeholder implementation - would need proper script-to-address conversion
        std::string prefix;
        switch (blockchain) {
            case Blockchain::LITECOIN:
                prefix = (network == Network::TESTNET) ? "tltc1" : "ltc1";
                break;
            case Blockchain::BITCOIN:
                prefix = (network == Network::TESTNET) ? "tb1" : "bc1";
                break;
            default:
                LOG_WARNING << "Script-to-address conversion not implemented for this blockchain";
                return "";
        }
        
        // Generate a placeholder P2SH address based on script hash
        // TODO: Implement proper script-to-address conversion using real cryptographic hashing
        std::string script_hash = payout_script_hex.substr(0, 32); // Simplified
        
        // Create a more realistic bech32-style address for testing
        // Note: This is still a placeholder, not a cryptographically valid address
        if (blockchain == Blockchain::LITECOIN && network == Network::TESTNET) {
            // Use a realistic testnet LTC bech32 format
            return "tltc1qw508d6qejxtdg4y5r3zarvary0c5xw7k" + script_hash.substr(0, 8);
        } else if (blockchain == Blockchain::LITECOIN && network == Network::MAINNET) {
            return "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7k" + script_hash.substr(0, 8);
        } else if (blockchain == Blockchain::BITCOIN && network == Network::TESTNET) {
            return "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7k" + script_hash.substr(0, 8);
        } else if (blockchain == Blockchain::BITCOIN && network == Network::MAINNET) {
            return "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7k" + script_hash.substr(0, 8);
        }
        
        return prefix + "qw508d6qejxtdg4y5r3zarvary0c5xw7k" + script_hash.substr(0, 8);
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to generate address from script: " << e.what();
        return "";
    }
}

bool NodeOwnerPayoutConfig::save_to_config_file(const std::string& config_dir, Blockchain blockchain, Network network) const {
    if (payout_address.empty()) {
        return false;
    }
    
    try {
        std::filesystem::create_directories(config_dir);
        std::string config_file = config_dir + "/node_owner_addresses.json";
        
        nlohmann::json config;
        
        // Load existing config if it exists
        if (std::filesystem::exists(config_file)) {
            std::ifstream file(config_file);
            if (file.is_open()) {
                file >> config;
                file.close();
            }
        }
        
        // Create blockchain and network keys
        std::string blockchain_key;
        switch (blockchain) {
            case Blockchain::LITECOIN: blockchain_key = "litecoin"; break;
            case Blockchain::BITCOIN: blockchain_key = "bitcoin"; break;
            case Blockchain::ETHEREUM: blockchain_key = "ethereum"; break;
            case Blockchain::MONERO: blockchain_key = "monero"; break;
            case Blockchain::ZCASH: blockchain_key = "zcash"; break;
            case Blockchain::DOGECOIN: blockchain_key = "dogecoin"; break;
            default: blockchain_key = "unknown"; break;
        }
        
        std::string network_key;
        switch (network) {
            case Network::MAINNET: network_key = "mainnet"; break;
            case Network::TESTNET: network_key = "testnet"; break;
            case Network::REGTEST: network_key = "regtest"; break;
            default: network_key = "unknown"; break;
        }
        
        // Store address and metadata
        config[blockchain_key][network_key]["address"] = payout_address;
        config[blockchain_key][network_key]["fee_percent"] = fee_percent;
        config[blockchain_key][network_key]["timestamp"] = std::time(nullptr);
        
        if (!payout_script_hex.empty()) {
            config[blockchain_key][network_key]["script_hex"] = payout_script_hex;
        }
        
        // Save to file
        std::ofstream file(config_file);
        if (file.is_open()) {
            file << config.dump(2);
            file.close();
            LOG_INFO << "Saved node owner address to config: " << config_file;
            return true;
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to save node owner config: " << e.what();
    }
    
    return false;
}

bool NodeOwnerPayoutConfig::load_from_config_file(const std::string& config_dir, Blockchain blockchain, Network network) {
    try {
        std::string config_file = config_dir + "/node_owner_addresses.json";
        
        if (!std::filesystem::exists(config_file)) {
            return false;
        }
        
        std::ifstream file(config_file);
        if (!file.is_open()) {
            return false;
        }
        
        nlohmann::json config;
        file >> config;
        file.close();
        
        // Create blockchain and network keys
        std::string blockchain_key;
        switch (blockchain) {
            case Blockchain::LITECOIN: blockchain_key = "litecoin"; break;
            case Blockchain::BITCOIN: blockchain_key = "bitcoin"; break;
            case Blockchain::ETHEREUM: blockchain_key = "ethereum"; break;
            case Blockchain::MONERO: blockchain_key = "monero"; break;
            case Blockchain::ZCASH: blockchain_key = "zcash"; break;
            case Blockchain::DOGECOIN: blockchain_key = "dogecoin"; break;
            default: return false;
        }
        
        std::string network_key;
        switch (network) {
            case Network::MAINNET: network_key = "mainnet"; break;
            case Network::TESTNET: network_key = "testnet"; break;
            case Network::REGTEST: network_key = "regtest"; break;
            default: return false;
        }
        
        // Check if address exists for this blockchain/network
        if (config.contains(blockchain_key) && config[blockchain_key].contains(network_key)) {
            auto& net_config = config[blockchain_key][network_key];
            
            if (net_config.contains("address") && !net_config["address"].get<std::string>().empty()) {
                payout_address = net_config["address"].get<std::string>();
                
                if (net_config.contains("fee_percent")) {
                    // Only load fee from config if not already set (i.e., fee_percent is 0)
                    if (fee_percent == 0.0) {
                        fee_percent = net_config["fee_percent"].get<double>();
                    }
                }
                
                if (net_config.contains("script_hex")) {
                    payout_script_hex = net_config["script_hex"].get<std::string>();
                }
                
                address_validated = true;
                enabled = true;
                address_source = AddressSource::CONFIG_FILE;
                
                LOG_INFO << "Loaded node owner address from config: " << payout_address;
                return true;
            }
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to load node owner config: " << e.what();
    }
    
    return false;
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
    
    // Try to resolve node owner address from various sources
    if (node_owner_config_.fee_percent > 0 && node_owner_config_.payout_address.empty()) {
        try_load_node_owner_from_config();
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
    
    // Calculate developer amount first (might be minimal attribution)
    allocation.developer_amount = developer_config_.get_developer_amount(block_reward);
    
    // Calculate node owner amount
    allocation.node_owner_percent = node_owner_config_.enabled ? node_owner_config_.fee_percent : 0.0;
    allocation.node_owner_amount = static_cast<uint64_t>(block_reward * allocation.node_owner_percent / 100.0);
    
    // Calculate miner amount (everything minus fees)
    allocation.miner_amount = block_reward - allocation.developer_amount - allocation.node_owner_amount;
    
    // Calculate percentages for logging
    allocation.developer_percent = (allocation.developer_amount * 100.0) / block_reward;
    allocation.miner_percent = (allocation.miner_amount * 100.0) / block_reward;
    
    // Ensure miner gets at least 49% (sanity check for large donations only)
    if (allocation.miner_percent < 49.0 && !developer_config_.use_minimal_attribution()) {
        LOG_WARNING << "Total fees exceed 51% of block reward, adjusting...";
        double total_fees_percent = allocation.developer_percent + allocation.node_owner_percent;
        double scale_factor = 51.0 / total_fees_percent;  // Scale down to max 51%
        
        allocation.developer_percent *= scale_factor;
        allocation.node_owner_percent *= scale_factor;
        allocation.miner_percent = 100.0 - allocation.developer_percent - allocation.node_owner_percent;
        
        // Recalculate amounts
        allocation.developer_amount = static_cast<uint64_t>(block_reward * allocation.developer_percent / 100.0);
        allocation.node_owner_amount = static_cast<uint64_t>(block_reward * allocation.node_owner_percent / 100.0);
        allocation.miner_amount = block_reward - allocation.developer_amount - allocation.node_owner_amount;
    }
    
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
    
    // If fee is set but no address is available, try to load from config
    if (percent > 0.0 && node_owner_config_.payout_address.empty()) {
        try_load_node_owner_from_config();
    }
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
        node_owner_config_.address_source = NodeOwnerPayoutConfig::AddressSource::CLI_ARGUMENT;
        LOG_INFO << "Node owner payout address set: " << address;
        LOG_INFO << "  Address type: " << static_cast<int>(validation_result.type);
        LOG_INFO << "  Fee: " << node_owner_config_.fee_percent << "%";
    } else {
        LOG_ERROR << "Invalid node owner address: " << address;
        LOG_ERROR << "  Error: " << validation_result.error_message;
        node_owner_config_.enabled = false;
    }
}

void PayoutManager::set_node_owner_script(const std::string& script_hex) {
    if (script_hex.empty()) {
        LOG_INFO << "No node owner script provided";
        return;
    }
    
    LOG_INFO << "Setting node owner script: " << script_hex.substr(0, 32) << "...";
    
    // Validate script hex format
    if (script_hex.length() % 2 != 0) {
        LOG_ERROR << "Invalid script hex: odd length";
        return;
    }
    
    // Check if all characters are valid hex
    for (char c : script_hex) {
        if (!std::isxdigit(c)) {
            LOG_ERROR << "Invalid script hex: non-hexadecimal character '" << c << "'";
            return;
        }
    }
    
    // Set the script and try to derive address
    node_owner_config_.set_payout_script(script_hex, blockchain_, network_);
    
    if (!node_owner_config_.payout_address.empty()) {
        LOG_INFO << "Derived node owner address from script: " << node_owner_config_.payout_address;
        LOG_INFO << "  Fee: " << node_owner_config_.fee_percent << "%";
        
        // Save to config if enabled
        if (node_owner_config_.store_generated_address) {
            std::string config_dir = std::string(getenv("HOME") ? getenv("HOME") : ".") + "/.c2pool";
            node_owner_config_.save_to_config_file(config_dir, blockchain_, network_);
        }
    } else {
        LOG_ERROR << "Failed to derive address from script";
    }
}

std::string PayoutManager::get_node_owner_config_path() const {
    // Get home directory and create config path
    const char* home = getenv("HOME");
    if (!home) {
        return "./node_owner_addresses.json";
    }
    
    std::string config_dir = std::string(home) + "/.c2pool";
    
    // Create directory if it doesn't exist
    std::filesystem::create_directories(config_dir);
    
    return config_dir + "/node_owner_addresses.json";
}

std::string PayoutManager::get_developer_address() const {
    // Return the developer address for the current blockchain/network
    switch (blockchain_) {
        case address::Blockchain::BITCOIN:
            switch (network_) {
                case address::Network::MAINNET:
                    return "bc1qdev123..."; // TODO: Replace with actual developer address
                case address::Network::TESTNET:
                    return "tb1qdev123..."; // TODO: Replace with actual developer testnet address
                case address::Network::REGTEST:
                    return "bcrt1qdev123..."; // TODO: Replace with actual developer regtest address
            }
            break;
        case address::Blockchain::LITECOIN:
            switch (network_) {
                case address::Network::MAINNET:
                    return "ltc1qdev123..."; // TODO: Replace with actual developer address
                case address::Network::TESTNET:
                    return "tltc1qdev123..."; // TODO: Replace with actual developer testnet address
                case address::Network::REGTEST:
                    return "rltc1qdev123..."; // TODO: Replace with actual developer regtest address
            }
            break;
        default:
            LOG_WARNING << "Unknown blockchain type for developer address";
            break;
    }
    
    return ""; // Fallback
}

std::string PayoutManager::get_node_owner_address() const {
    if (!node_owner_config_.payout_address.empty()) {
        return node_owner_config_.payout_address;
    }
    
    LOG_WARNING << "Node owner address not set";
    return "";
}

bool PayoutManager::try_detect_wallet_address() {
    // This method would typically connect to the wallet RPC and request a new address
    // For now, we'll implement a placeholder that logs the attempt
    
    LOG_INFO << "Attempting to detect wallet address for node owner payout...";
    
    // TODO: Implement actual wallet RPC connection
    // Example implementation:
    // 1. Connect to wallet RPC
    // 2. Call getnewaddress or getaddressesbylabel
    // 3. Set the address in node_owner_config_
    // 4. Save to config if enabled
    
    // Placeholder logic - in real implementation this would make RPC calls
    try {
        // Example: auto wallet_client = get_wallet_rpc_client();
        // auto new_address = wallet_client.get_new_address("node_owner");
        // node_owner_config_.set_payout_address(new_address, "wallet");
        
        LOG_WARNING << "Wallet RPC integration not yet implemented";
        LOG_INFO << "To set a node owner address, use --node-owner-address or --node-owner-script";
        
        return false; // Could not detect wallet address
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to detect wallet address: " << e.what();
        return false;
    }
}

void PayoutManager::enable_auto_wallet_detection(bool enable) {
    node_owner_config_.auto_detect_from_wallet = enable;
    LOG_INFO << "Auto wallet detection " << (enable ? "enabled" : "disabled");
}

bool PayoutManager::validate_configuration() const {
    validation_errors_.clear();
    
    // Check developer fee configuration
    double dev_fee = developer_config_.get_total_developer_fee();
    if (dev_fee < 0 || dev_fee > 100) {
        validation_errors_.push_back("Developer fee must be between 0 and 100 percent");
    }
    
    // Check node owner fee configuration
    if (node_owner_config_.fee_percent < 0 || node_owner_config_.fee_percent > 100) {
        validation_errors_.push_back("Node owner fee must be between 0 and 100 percent");
    }
    
    // Check if node owner fee is set but no address is available
    if (node_owner_config_.fee_percent > 0 && node_owner_config_.payout_address.empty()) {
        validation_errors_.push_back("Node owner fee is set but no payout address is configured");
    }
    
    // Check total fee doesn't exceed 100%
    double total_fee = dev_fee + node_owner_config_.fee_percent;
    if (total_fee > 100) {
        validation_errors_.push_back("Total fees (developer + node owner) cannot exceed 100%");
    }
    
    return validation_errors_.empty();
}

std::vector<std::string> PayoutManager::get_validation_errors() const {
    return validation_errors_;
}

bool PayoutManager::has_node_owner_fee() const {
    return node_owner_config_.fee_percent > 0;
}

bool PayoutManager::try_load_node_owner_from_config() {
    std::string config_dir = std::string(getenv("HOME") ? getenv("HOME") : ".") + "/.c2pool";
    bool loaded = node_owner_config_.load_from_config_file(config_dir, blockchain_, network_);
    
    if (loaded && !node_owner_config_.payout_address.empty()) {
        LOG_INFO << "Loaded node owner address from config: " << node_owner_config_.payout_address;
        LOG_INFO << "  Source: config file";
        return true;
    } else {
        LOG_INFO << "No node owner address found in config file";
        return false;
    }
}

} // namespace payout
} // namespace c2pool
