#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>

namespace c2pool {
namespace address {

/**
 * Blockchain-specific address validation system
 * Supports multiple cryptocurrencies with their specific address formats
 */

enum class Blockchain {
    LITECOIN,
    BITCOIN, 
    ETHEREUM,
    MONERO,
    ZCASH,
    DOGECOIN,
    UNKNOWN
};

enum class Network {
    MAINNET,
    TESTNET,
    REGTEST
};

enum class AddressType {
    LEGACY_P2PKH,           // Pay to Public Key Hash (1xxx, Lxxx, mxxx)
    LEGACY_P2SH,            // Pay to Script Hash (3xxx, Mxxx, 2xxx)
    BECH32_NATIVE_SEGWIT,   // Native SegWit (bc1xxx, ltc1xxx, tltc1xxx)
    BECH32_TAPROOT,         // Taproot (bc1pxxx)
    ETHEREUM_STYLE,         // Ethereum/ERC-20 (0xxxx)
    MONERO_INTEGRATED,      // Monero integrated addresses
    MONERO_STANDARD,        // Monero standard addresses
    ZCASH_SHIELDED,         // Zcash shielded addresses
    INVALID
};

struct AddressValidationResult {
    bool is_valid = false;
    Blockchain blockchain = Blockchain::UNKNOWN;
    Network network = Network::MAINNET;
    AddressType type = AddressType::INVALID;
    std::string error_message;
    std::vector<unsigned char> decoded_data;
    
    // Additional metadata
    std::string normalized_address;  // Checksummed version for some chains
    bool requires_memo = false;      // For some blockchain addresses
};

/**
 * Blockchain-specific validation configuration
 */
struct BlockchainConfig {
    Blockchain blockchain;
    Network network;
    
    // Legacy address version bytes
    std::vector<unsigned char> p2pkh_versions;
    std::vector<unsigned char> p2sh_versions;
    
    // Bech32 prefixes
    std::vector<std::string> bech32_prefixes;
    
    // Address length constraints
    size_t min_length = 25;
    size_t max_length = 100;
    
    // Custom validation function
    std::function<bool(const std::string&)> custom_validator;
};

class BlockchainAddressValidator {
private:
    std::map<Blockchain, std::map<Network, BlockchainConfig>> m_configs;
    Blockchain m_primary_blockchain = Blockchain::LITECOIN;
    Network m_primary_network = Network::TESTNET;
    
    void initialize_litecoin_configs();
    void initialize_bitcoin_configs();
    void initialize_ethereum_configs();
    void initialize_monero_configs();
    void initialize_zcash_configs();
    void initialize_dogecoin_configs();
    
    // Validation helpers
    bool validate_base58check(const std::string& address, const BlockchainConfig& config, AddressValidationResult& result) const;
    bool validate_bech32(const std::string& address, const BlockchainConfig& config, AddressValidationResult& result) const;
    bool validate_ethereum_address(const std::string& address, AddressValidationResult& result) const;
    bool validate_monero_address(const std::string& address, AddressValidationResult& result) const;
    bool validate_zcash_address(const std::string& address, AddressValidationResult& result) const;
    
    // Format detection
    Blockchain detect_blockchain_from_address(const std::string& address) const;
    AddressType detect_address_type(const std::string& address, Blockchain blockchain) const;
    
public:
    BlockchainAddressValidator();
    BlockchainAddressValidator(Blockchain primary_blockchain, Network primary_network);
    
    /**
     * Main validation entry point
     * Validates address according to blockchain-specific rules
     */
    AddressValidationResult validate_address(const std::string& address) const;
    
    /**
     * Strict validation - only accept addresses for the configured primary blockchain/network
     */
    AddressValidationResult validate_address_strict(const std::string& address) const;
    
    /**
     * Multi-blockchain validation - accept any valid address but identify its blockchain
     */
    AddressValidationResult validate_address_multi(const std::string& address) const;
    
    /**
     * Configuration methods
     */
    void set_primary_blockchain(Blockchain blockchain, Network network);
    void add_custom_blockchain_config(const BlockchainConfig& config);
    
    /**
     * Utility methods
     */
    std::string get_blockchain_name(Blockchain blockchain) const;
    std::string get_network_name(Network network) const;
    std::string get_address_type_name(AddressType type) const;
    
    /**
     * Get expected address formats for current configuration
     */
    std::vector<std::string> get_expected_address_formats() const;
    
    /**
     * Generate example addresses for testing (if available)
     */
    std::vector<std::string> generate_example_addresses() const;
};

/**
 * Utility functions for common blockchain operations
 */
namespace utils {
    bool is_hex_string(const std::string& str);
    bool is_base58_string(const std::string& str);
    std::string to_checksum_address(const std::string& eth_address);
    std::vector<unsigned char> decode_base58(const std::string& str);
    bool verify_checksum(const std::vector<unsigned char>& data);
}

} // namespace address
} // namespace c2pool
