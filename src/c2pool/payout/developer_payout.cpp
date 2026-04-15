#include "developer_payout.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <algorithm>
// popen()-based command execution — no boost::process dependency
#include <nlohmann/json.hpp>
#include <core/filesystem.hpp>

namespace c2pool {
namespace payout {

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

PayoutManager::PayoutManager(Blockchain blockchain, Network network)
    : blockchain_(blockchain), network_(network), address_validator_(blockchain, network) {
    
    LOG_INFO << "Initializing C2Pool Payout Manager";
    LOG_INFO << "  Blockchain: " << static_cast<int>(blockchain);
    LOG_INFO << "  Network: " << (network == Network::TESTNET ? "testnet" : "mainnet");
    LOG_INFO << "  Developer attribution: " << developer_config_.get_total_developer_fee() << "%";
    
    // Try to auto-detect wallet address if enabled
    if (node_owner_config_.auto_detect_from_wallet) {
        try_detect_wallet_address();
    }
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

PayoutManager::PayoutAllocation PayoutManager::calculate_payout(uint64_t block_reward) const {
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
        
        std::string cmd = full_command + " 2>/dev/null";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) throw std::runtime_error("popen failed");
        char buf[256];
        std::string line;
        if (fgets(buf, sizeof(buf), pipe))
            line = buf;
        int status = pclose(pipe);

        // Remove whitespace and quotes
        address = line;
        address.erase(0, address.find_first_not_of(" \t\r\n\""));
        address.erase(address.find_last_not_of(" \t\r\n\"") + 1);

        if (status == 0 && !address.empty()) {
            LOG_INFO << "Auto-detected wallet address from RPC: " << address;
            set_node_owner_address(address);
            return true;
        }
        
    } catch (const std::exception& e) {
        LOG_INFO << "RPC auto-detection failed: " << e.what();
    }
    
    return false;
}

bool PayoutManager::detect_wallet_address_file() {
    // Look for a c2pool address file in standard locations.
    // This avoids parsing wallet.dat (which requires BDB and is complex).
    // Users can create ~/.c2pool/node_address.txt with their payout address.
    const std::vector<std::string> paths = {
        (core::filesystem::config_path() / "node_address.txt").string(),
        "node_address.txt",
    };
    for (const auto& path : paths) {
        std::ifstream f(path);
        if (f.is_open()) {
            std::string address;
            if (std::getline(f, address) && !address.empty()) {
                // Trim whitespace
                address.erase(0, address.find_first_not_of(" \t\r\n"));
                address.erase(address.find_last_not_of(" \t\r\n") + 1);
                if (address.size() >= 20) {
                    LOG_INFO << "Loaded node owner address from " << path << ": " << address;
                    set_node_owner_address(address);
                    return true;
                }
            }
        }
    }
    return false;
}

std::string PayoutManager::execute_core_rpc(const std::string& method, const std::string& params) const {
    // Implementation for RPC calls to core wallet
    // This is a placeholder - real implementation would use proper RPC client
    return "";
}

void PayoutManager::record_payout(const PayoutAllocation& allocation) {
    stats_.total_blocks_mined++;
    stats_.total_developer_fees += allocation.developer_amount;
    stats_.total_node_owner_fees += allocation.node_owner_amount;
    stats_.total_miner_rewards += allocation.miner_amount;
    
    // Update averages
    stats_.average_developer_fee_percent = 
        (stats_.average_developer_fee_percent * (stats_.total_blocks_mined - 1) + allocation.developer_percent) 
        / stats_.total_blocks_mined;
        
    stats_.average_node_owner_fee_percent = 
        (stats_.average_node_owner_fee_percent * (stats_.total_blocks_mined - 1) + allocation.node_owner_percent) 
        / stats_.total_blocks_mined;
}

bool PayoutManager::PayoutAllocation::is_valid() const {
    return total_reward > 0 && 
           miner_amount > 0 && 
           miner_amount <= total_reward &&
           (miner_amount + developer_amount + node_owner_amount) == total_reward &&
           !developer_address.empty();
}

} // namespace payout
} // namespace c2pool
