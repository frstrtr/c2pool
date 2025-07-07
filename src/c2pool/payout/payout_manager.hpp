#pragma once

#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <chrono>
#include <nlohmann/json.hpp>
#include <core/address_validator.hpp>

// Bring address validation types into scope
using Blockchain = c2pool::address::Blockchain;
using Network = c2pool::address::Network;
using BlockchainAddressValidator = c2pool::address::BlockchainAddressValidator;

namespace c2pool {
namespace payout {

/// Developer payout configuration for C2Pool attribution
struct DeveloperPayoutConfig {
    // C2Pool developer addresses for different blockchains
    std::map<Blockchain, std::string> mainnet_addresses;
    std::map<Blockchain, std::string> testnet_addresses;
    
    // Default developer fee (minimal attribution when no donation)
    double default_fee_percent = 0.5;  // 0.5% default attribution fee
    double configured_fee_percent = 0.0;  // User-configured donation
    bool minimal_attribution_mode = true;  // Use minimal satoshi amount when donation is 0
    
    // Minimal attribution amounts (in satoshis/smallest units)
    static constexpr uint64_t MINIMAL_ATTRIBUTION_SATOSHIS = 1;  // 1 satoshi for attribution
    static constexpr uint64_t MINIMAL_ATTRIBUTION_THRESHOLD = 1000000000;  // 10 LTC threshold for minimal mode
    
    // Enabled/disabled state
    bool enabled = true;
    bool attribution_required = true;  // Always add developer attribution
    
    DeveloperPayoutConfig();
    
    std::string get_developer_address(Blockchain blockchain, Network network) const;
    double get_total_developer_fee() const;
    uint64_t get_developer_amount(uint64_t block_reward) const;
    bool use_minimal_attribution() const;
    bool is_valid_developer_address(const std::string& address, Blockchain blockchain, Network network) const;
};

/// Node owner payout configuration
struct NodeOwnerPayoutConfig {
    std::string payout_address;
    std::string payout_script_hex;      // Optional: P2SH script for address generation
    double fee_percent = 0.0;           // Default 0% node owner fee
    bool enabled = false;
    bool auto_detect_from_wallet = true;  // Try to get address from core wallet
    bool auto_generate_if_missing = true; // Generate new address if none found
    bool store_generated_address = true;  // Store generated addresses to config file
    
    // Address sources (priority order)
    enum class AddressSource {
        CLI_ARGUMENT,      // --node-owner-address
        CONFIG_FILE,       // node_owner_addresses.json
        WALLET_RPC,        // Core wallet RPC
        GENERATED_NEW,     // Newly generated
        SCRIPT_DERIVED     // Derived from payout_script_hex
    };
    
    AddressSource address_source = AddressSource::CLI_ARGUMENT;
    
    // Validation and setup
    bool is_valid() const;
    void set_payout_address(const std::string& address, Blockchain blockchain, Network network);
    void set_payout_script(const std::string& script_hex, Blockchain blockchain, Network network);
    
    // Address generation and management
    std::string generate_address_from_script(Blockchain blockchain, Network network) const;
    bool save_to_config_file(const std::string& config_dir, Blockchain blockchain, Network network) const;
    bool load_from_config_file(const std::string& config_dir, Blockchain blockchain, Network network);
    
private:
    bool address_validated = false;
    Blockchain validated_blockchain;
    Network validated_network;
};

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

/// Combined payout allocation structure
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

/**
 * @brief Manages payout calculations and coinbase construction
 */
class PayoutManager {
public:
    PayoutManager(double pool_fee_percent = 1.0, uint64_t payout_window_seconds = 86400);
    PayoutManager(Blockchain blockchain, Network network, double pool_fee_percent = 1.0, uint64_t payout_window_seconds = 86400);
    ~PayoutManager() = default;
    
    // Mining share tracking
    void record_share_contribution(const std::string& miner_address, double difficulty);
    
    // Coinbase construction
    std::string build_coinbase_output(uint64_t block_reward_satoshis, const std::string& primary_address = "");
    std::vector<std::pair<std::string, uint64_t>> calculate_payout_distribution(uint64_t total_reward_satoshis);
    
    // Developer payout system
    PayoutAllocation calculate_payout(uint64_t block_reward) const;
    void set_developer_donation(double percent);
    void set_node_owner_fee(double percent);
    void set_node_owner_address(const std::string& address);
    void set_node_owner_script(const std::string& script_hex);
    void enable_auto_wallet_detection(bool enabled);
    
    // Address management
    std::string get_developer_address() const;
    std::string get_node_owner_address() const;
    bool has_node_owner_fee() const;
    
    // Validation
    bool validate_configuration() const;
    std::vector<std::string> get_validation_errors() const;
    
    // Auto-detection from core wallet
    bool try_detect_wallet_address();
    
    // Enhanced node owner address management
    bool resolve_node_owner_address();
    bool try_load_node_owner_from_config();
    bool try_generate_node_owner_address();
    bool try_derive_address_from_script();
    std::string get_node_owner_config_path() const;
    bool prompt_user_for_node_owner_address();
    
    // Payout management
    void set_pool_fee_percent(double fee_percent);
    void set_primary_pool_address(const std::string& address);
    double get_miner_contribution_percent(const std::string& address);
    nlohmann::json get_payout_statistics();
    
    // Configuration getters
    const DeveloperPayoutConfig& get_developer_config() const { return developer_config_; }
    const NodeOwnerPayoutConfig& get_node_owner_config() const { return node_owner_config_; }
    
    // Cleanup and maintenance
    void cleanup_old_contributions(uint64_t cutoff_time);
    size_t get_active_miners_count() const;
    
private:
    mutable std::mutex contributions_mutex_;
    std::map<std::string, MinerContribution> miner_contributions_;
    
    double pool_fee_percent_;              // Pool fee (e.g., 1.0 for 1%)
    std::string primary_pool_address_;     // Primary pool payout address
    uint64_t payout_window_seconds_;       // Time window for contribution calculation
    
    // Developer payout system
    Blockchain blockchain_;
    Network network_;
    BlockchainAddressValidator address_validator_;
    
    DeveloperPayoutConfig developer_config_;
    NodeOwnerPayoutConfig node_owner_config_;
    
    // Validation
    mutable std::vector<std::string> validation_errors_;
    
    // Helper methods
    double calculate_total_difficulty() const;
    std::string address_to_script_hex(const std::string& address) const;
    uint64_t get_current_timestamp() const;
    
    // Core wallet integration
    bool detect_wallet_address_rpc();
    bool detect_wallet_address_file();
    std::string execute_core_rpc(const std::string& method, const std::string& params = "") const;
    
    // Constants
    static constexpr uint64_t MINIMUM_PAYOUT_SATOSHIS = 100000; // 0.001 LTC
    static constexpr size_t MAX_COINBASE_OUTPUTS = 10; // Limit coinbase outputs
};

} // namespace payout
} // namespace c2pool
