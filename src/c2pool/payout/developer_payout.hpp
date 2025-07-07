#pragma once

#include <string>
#include <memory>
#include <vector>
#include <map>

#include <core/address_validator.hpp>
#include <core/log.hpp>

namespace c2pool {
namespace payout {

using Blockchain = c2pool::address::Blockchain;
using Network = c2pool::address::Network;
using BlockchainAddressValidator = c2pool::address::BlockchainAddressValidator;

/// Developer payout configuration for C2Pool attribution
struct DeveloperPayoutConfig {
    // C2Pool developer addresses for different blockchains
    std::map<Blockchain, std::string> mainnet_addresses;
    std::map<Blockchain, std::string> testnet_addresses;
    
    // Default developer fee (0.5% minimum for attribution)
    double default_fee_percent = 0.5;  // 0.5% minimum attribution fee
    double configured_fee_percent = 0.0;  // User-configured donation
    
    // Enabled/disabled state
    bool enabled = true;
    bool attribution_required = true;  // Always add developer attribution
    
    DeveloperPayoutConfig();
    
    std::string get_developer_address(Blockchain blockchain, Network network) const;
    double get_total_developer_fee() const;
    bool is_valid_developer_address(const std::string& address, Blockchain blockchain, Network network) const;
};

/// Node owner payout configuration
struct NodeOwnerPayoutConfig {
    std::string payout_address;
    double fee_percent = 0.0;  // Default 0% node owner fee
    bool enabled = false;
    bool auto_detect_from_wallet = true;  // Try to get address from core wallet
    
    // Validation
    bool is_valid() const;
    void set_payout_address(const std::string& address, Blockchain blockchain, Network network);
    
private:
    bool address_validated = false;
    Blockchain validated_blockchain;
    Network validated_network;
};

/// Combined payout manager for developer and node owner fees
class PayoutManager {
public:
    PayoutManager(Blockchain blockchain, Network network);
    ~PayoutManager() = default;
    
    // Configuration methods
    void set_developer_donation(double percent);
    void set_node_owner_fee(double percent);
    void set_node_owner_address(const std::string& address);
    void enable_auto_wallet_detection(bool enabled);
    
    // Payout calculation
    struct PayoutAllocation {
        double miner_percent;
        double developer_percent;
        double node_owner_percent;
        
        std::string developer_address;
        std::string node_owner_address;
        
        // Calculated amounts (in satoshis/smallest unit)
        uint64_t total_reward;
        uint64_t miner_amount;
        uint64_t developer_amount;
        uint64_t node_owner_amount;
        
        bool is_valid() const;
    };
    
    PayoutAllocation calculate_payout(uint64_t block_reward) const;
    
    // Address management
    std::string get_developer_address() const;
    std::string get_node_owner_address() const;
    bool has_node_owner_fee() const;
    
    // Validation
    bool validate_configuration() const;
    std::vector<std::string> get_validation_errors() const;
    
    // Auto-detection from core wallet
    bool try_detect_wallet_address();
    
    // Statistics
    struct PayoutStats {
        uint64_t total_blocks_mined = 0;
        uint64_t total_developer_fees = 0;
        uint64_t total_node_owner_fees = 0;
        uint64_t total_miner_rewards = 0;
        
        double average_developer_fee_percent = 0.0;
        double average_node_owner_fee_percent = 0.0;
    };
    
    PayoutStats get_stats() const { return stats_; }
    void record_payout(const PayoutAllocation& allocation);
    
    // Configuration getters
    const DeveloperPayoutConfig& get_developer_config() const { return developer_config_; }
    const NodeOwnerPayoutConfig& get_node_owner_config() const { return node_owner_config_; }
    
private:
    Blockchain blockchain_;
    Network network_;
    BlockchainAddressValidator address_validator_;
    
    DeveloperPayoutConfig developer_config_;
    NodeOwnerPayoutConfig node_owner_config_;
    PayoutStats stats_;
    
    // Core wallet integration
    bool detect_wallet_address_rpc();
    bool detect_wallet_address_file();
    std::string execute_core_rpc(const std::string& method, const std::string& params = "") const;
};

} // namespace payout
} // namespace c2pool
