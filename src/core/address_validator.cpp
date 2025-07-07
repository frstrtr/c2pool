#include "address_validator.hpp"
#include <core/log.hpp>
#include <btclibs/base58.h>
#include <btclibs/hash.h>
#include <algorithm>
#include <regex>
#include <iomanip>
#include <sstream>

namespace c2pool {
namespace address {

BlockchainAddressValidator::BlockchainAddressValidator() 
    : m_primary_blockchain(Blockchain::LITECOIN), m_primary_network(Network::TESTNET)
{
    initialize_litecoin_configs();
    initialize_bitcoin_configs();
    initialize_ethereum_configs();
    initialize_monero_configs();
    initialize_zcash_configs();
    initialize_dogecoin_configs();
}

BlockchainAddressValidator::BlockchainAddressValidator(Blockchain primary_blockchain, Network primary_network)
    : m_primary_blockchain(primary_blockchain), m_primary_network(primary_network)
{
    initialize_litecoin_configs();
    initialize_bitcoin_configs();
    initialize_ethereum_configs();
    initialize_monero_configs();
    initialize_zcash_configs();
    initialize_dogecoin_configs();
}

void BlockchainAddressValidator::initialize_litecoin_configs() {
    // Litecoin Mainnet
    BlockchainConfig ltc_mainnet;
    ltc_mainnet.blockchain = Blockchain::LITECOIN;
    ltc_mainnet.network = Network::MAINNET;
    ltc_mainnet.p2pkh_versions = {48};      // L addresses (0x30)
    ltc_mainnet.p2sh_versions = {50, 5};    // M addresses (0x32) and 3 addresses (0x05)
    ltc_mainnet.bech32_prefixes = {"ltc1"};
    ltc_mainnet.min_length = 26;
    ltc_mainnet.max_length = 62;
    
    // Litecoin Testnet
    BlockchainConfig ltc_testnet;
    ltc_testnet.blockchain = Blockchain::LITECOIN;
    ltc_testnet.network = Network::TESTNET;
    ltc_testnet.p2pkh_versions = {111};     // m/n addresses (0x6F)
    ltc_testnet.p2sh_versions = {196, 58};  // 2 addresses (0xC4) and Q addresses (0x3A)
    ltc_testnet.bech32_prefixes = {"tltc1"};
    ltc_testnet.min_length = 26;
    ltc_testnet.max_length = 62;
    
    // Litecoin Regtest
    BlockchainConfig ltc_regtest;
    ltc_regtest.blockchain = Blockchain::LITECOIN;
    ltc_regtest.network = Network::REGTEST;
    ltc_regtest.p2pkh_versions = {111};     // Same as testnet
    ltc_regtest.p2sh_versions = {196, 58};  // Same as testnet
    ltc_regtest.bech32_prefixes = {"rltc1"};
    ltc_regtest.min_length = 26;
    ltc_regtest.max_length = 62;
    
    m_configs[Blockchain::LITECOIN][Network::MAINNET] = ltc_mainnet;
    m_configs[Blockchain::LITECOIN][Network::TESTNET] = ltc_testnet;
    m_configs[Blockchain::LITECOIN][Network::REGTEST] = ltc_regtest;
}

void BlockchainAddressValidator::initialize_bitcoin_configs() {
    // Bitcoin Mainnet
    BlockchainConfig btc_mainnet;
    btc_mainnet.blockchain = Blockchain::BITCOIN;
    btc_mainnet.network = Network::MAINNET;
    btc_mainnet.p2pkh_versions = {0};       // 1 addresses
    btc_mainnet.p2sh_versions = {5};        // 3 addresses
    btc_mainnet.bech32_prefixes = {"bc1"};
    btc_mainnet.min_length = 26;
    btc_mainnet.max_length = 62;
    
    // Bitcoin Testnet
    BlockchainConfig btc_testnet;
    btc_testnet.blockchain = Blockchain::BITCOIN;
    btc_testnet.network = Network::TESTNET;
    btc_testnet.p2pkh_versions = {111};     // m/n addresses
    btc_testnet.p2sh_versions = {196};      // 2 addresses
    btc_testnet.bech32_prefixes = {"tb1"};
    btc_testnet.min_length = 26;
    btc_testnet.max_length = 62;
    
    m_configs[Blockchain::BITCOIN][Network::MAINNET] = btc_mainnet;
    m_configs[Blockchain::BITCOIN][Network::TESTNET] = btc_testnet;
}

void BlockchainAddressValidator::initialize_ethereum_configs() {
    // Ethereum (same for mainnet/testnet - differentiated by chain ID)
    BlockchainConfig eth_config;
    eth_config.blockchain = Blockchain::ETHEREUM;
    eth_config.network = Network::MAINNET;
    eth_config.min_length = 42;  // 0x + 40 hex chars
    eth_config.max_length = 42;
    eth_config.custom_validator = [](const std::string& addr) {
        return addr.length() == 42 && addr.substr(0, 2) == "0x" && 
               utils::is_hex_string(addr.substr(2));
    };
    
    m_configs[Blockchain::ETHEREUM][Network::MAINNET] = eth_config;
    m_configs[Blockchain::ETHEREUM][Network::TESTNET] = eth_config;
}

void BlockchainAddressValidator::initialize_monero_configs() {
    // Monero
    BlockchainConfig xmr_mainnet;
    xmr_mainnet.blockchain = Blockchain::MONERO;
    xmr_mainnet.network = Network::MAINNET;
    xmr_mainnet.min_length = 95;
    xmr_mainnet.max_length = 106;
    xmr_mainnet.custom_validator = [](const std::string& addr) {
        // Monero addresses start with 4 (standard) or 8 (integrated)
        return (addr[0] == '4' || addr[0] == '8') && utils::is_base58_string(addr);
    };
    
    BlockchainConfig xmr_testnet;
    xmr_testnet.blockchain = Blockchain::MONERO;
    xmr_testnet.network = Network::TESTNET;
    xmr_testnet.min_length = 95;
    xmr_testnet.max_length = 106;
    xmr_testnet.custom_validator = [](const std::string& addr) {
        // Monero testnet addresses start with 9 or A
        return (addr[0] == '9' || addr[0] == 'A') && utils::is_base58_string(addr);
    };
    
    m_configs[Blockchain::MONERO][Network::MAINNET] = xmr_mainnet;
    m_configs[Blockchain::MONERO][Network::TESTNET] = xmr_testnet;
}

void BlockchainAddressValidator::initialize_zcash_configs() {
    // Zcash
    BlockchainConfig zec_mainnet;
    zec_mainnet.blockchain = Blockchain::ZCASH;
    zec_mainnet.network = Network::MAINNET;
    zec_mainnet.p2pkh_versions = {28};      // t1 addresses
    zec_mainnet.p2sh_versions = {189};      // t3 addresses
    zec_mainnet.min_length = 35;
    zec_mainnet.max_length = 95;
    zec_mainnet.custom_validator = [](const std::string& addr) {
        // Zcash shielded addresses start with zc or zs
        return (addr.length() >= 2 && (addr.substr(0, 2) == "zc" || addr.substr(0, 2) == "zs")) ||
               utils::is_base58_string(addr);
    };
    
    m_configs[Blockchain::ZCASH][Network::MAINNET] = zec_mainnet;
}

void BlockchainAddressValidator::initialize_dogecoin_configs() {
    // Dogecoin
    BlockchainConfig doge_mainnet;
    doge_mainnet.blockchain = Blockchain::DOGECOIN;
    doge_mainnet.network = Network::MAINNET;
    doge_mainnet.p2pkh_versions = {30};     // D addresses
    doge_mainnet.p2sh_versions = {22};      // 9/A addresses
    doge_mainnet.min_length = 25;
    doge_mainnet.max_length = 34;
    
    m_configs[Blockchain::DOGECOIN][Network::MAINNET] = doge_mainnet;
}

AddressValidationResult BlockchainAddressValidator::validate_address(const std::string& address) const {
    // Use strict validation for the primary blockchain/network
    return validate_address_strict(address);
}

AddressValidationResult BlockchainAddressValidator::validate_address_strict(const std::string& address) const {
    AddressValidationResult result;
    
    if (address.empty()) {
        result.error_message = "Empty address";
        return result;
    }
    
    // Get configuration for primary blockchain/network
    auto blockchain_it = m_configs.find(m_primary_blockchain);
    if (blockchain_it == m_configs.end()) {
        result.error_message = "Unsupported blockchain: " + get_blockchain_name(m_primary_blockchain);
        return result;
    }
    
    auto network_it = blockchain_it->second.find(m_primary_network);
    if (network_it == blockchain_it->second.end()) {
        result.error_message = "Unsupported network: " + get_network_name(m_primary_network);
        return result;
    }
    
    const BlockchainConfig& config = network_it->second;
    
    // Validate against the specific blockchain configuration
    result.blockchain = m_primary_blockchain;
    result.network = m_primary_network;
    
    LOG_DEBUG_OTHER << "Validating address: " << address << " for " 
                    << get_blockchain_name(m_primary_blockchain) << " " 
                    << get_network_name(m_primary_network);
    
    // Check length constraints
    if (address.length() < config.min_length || address.length() > config.max_length) {
        result.error_message = "Invalid address length for " + get_blockchain_name(m_primary_blockchain);
        return result;
    }
    
    // Try blockchain-specific validation
    switch (m_primary_blockchain) {
        case Blockchain::LITECOIN:
        case Blockchain::BITCOIN:
        case Blockchain::DOGECOIN:
            // Try Bech32 first
            if (validate_bech32(address, config, result)) {
                result.is_valid = true;
                return result;
            }
            // Then try Base58Check
            if (validate_base58check(address, config, result)) {
                result.is_valid = true;
                return result;
            }
            break;
            
        case Blockchain::ETHEREUM:
            if (validate_ethereum_address(address, result)) {
                result.is_valid = true;
                return result;
            }
            break;
            
        case Blockchain::MONERO:
            if (validate_monero_address(address, result)) {
                result.is_valid = true;
                return result;
            }
            break;
            
        case Blockchain::ZCASH:
            if (validate_zcash_address(address, result)) {
                result.is_valid = true;
                return result;
            }
            break;
            
        default:
            result.error_message = "Blockchain validation not implemented";
            return result;
    }
    
    result.error_message = "Invalid " + get_blockchain_name(m_primary_blockchain) + " address format";
    return result;
}

AddressValidationResult BlockchainAddressValidator::validate_address_multi(const std::string& address) const {
    AddressValidationResult result;
    
    if (address.empty()) {
        result.error_message = "Empty address";
        return result;
    }
    
    // Detect blockchain from address format
    Blockchain detected_blockchain = detect_blockchain_from_address(address);
    
    if (detected_blockchain == Blockchain::UNKNOWN) {
        result.error_message = "Unknown address format";
        return result;
    }
    
    // Try to validate against all networks for the detected blockchain
    auto blockchain_it = m_configs.find(detected_blockchain);
    if (blockchain_it == m_configs.end()) {
        result.error_message = "Unsupported blockchain";
        return result;
    }
    
    for (const auto& [network, config] : blockchain_it->second) {
        result.blockchain = detected_blockchain;
        result.network = network;
        
        // Try validation with this network config
        bool valid = false;
        switch (detected_blockchain) {
            case Blockchain::LITECOIN:
            case Blockchain::BITCOIN:
            case Blockchain::DOGECOIN:
                valid = validate_bech32(address, config, result) || 
                       validate_base58check(address, config, result);
                break;
            case Blockchain::ETHEREUM:
                valid = validate_ethereum_address(address, result);
                break;
            case Blockchain::MONERO:
                valid = validate_monero_address(address, result);
                break;
            case Blockchain::ZCASH:
                valid = validate_zcash_address(address, result);
                break;
            default:
                continue;
        }
        
        if (valid) {
            result.is_valid = true;
            return result;
        }
    }
    
    result.error_message = "Invalid address for detected blockchain: " + get_blockchain_name(detected_blockchain);
    return result;
}

bool BlockchainAddressValidator::validate_base58check(const std::string& address, const BlockchainConfig& config, AddressValidationResult& result) const {
    std::vector<unsigned char> decoded;
    
    // Use the existing DecodeBase58Check function
    if (!DecodeBase58Check(address, decoded, 25)) {
        result.error_message = "Invalid Base58Check encoding";
        return false;
    }
    
    if (decoded.size() != 21) {
        result.error_message = "Invalid address payload length";
        return false;
    }
    
    unsigned char version_byte = decoded[0];
    
    // Check P2PKH versions
    for (unsigned char version : config.p2pkh_versions) {
        if (version_byte == version) {
            result.type = AddressType::LEGACY_P2PKH;
            result.decoded_data = decoded;
            result.normalized_address = address;
            return true;
        }
    }
    
    // Check P2SH versions
    for (unsigned char version : config.p2sh_versions) {
        if (version_byte == version) {
            result.type = AddressType::LEGACY_P2SH;
            result.decoded_data = decoded;
            result.normalized_address = address;
            return true;
        }
    }
    
    result.error_message = "Invalid version byte for " + get_blockchain_name(config.blockchain) + 
                          " " + get_network_name(config.network);
    return false;
}

bool BlockchainAddressValidator::validate_bech32(const std::string& address, const BlockchainConfig& config, AddressValidationResult& result) const {
    // Check if address has a valid bech32 prefix
    for (const std::string& prefix : config.bech32_prefixes) {
        if (address.length() >= prefix.length() && address.substr(0, prefix.length()) == prefix) {
            // Basic bech32 format validation (simplified)
            if (address.length() >= prefix.length() + 10 && address.length() <= prefix.length() + 55) {
                // Check for valid bech32 characters (0-9, a-z except 1, b, i, o)
                std::string bech32_chars = "023456789acdefghjklmnpqrstuvwxyz";
                std::string data_part = address.substr(prefix.length());
                
                for (char c : data_part) {
                    if (bech32_chars.find(c) == std::string::npos) {
                        result.error_message = "Invalid bech32 character";
                        return false;
                    }
                }
                
                result.type = AddressType::BECH32_NATIVE_SEGWIT;
                result.normalized_address = address;
                return true;
            }
        }
    }
    
    return false;
}

bool BlockchainAddressValidator::validate_ethereum_address(const std::string& address, AddressValidationResult& result) const {
    if (address.length() != 42 || address.substr(0, 2) != "0x") {
        result.error_message = "Invalid Ethereum address format";
        return false;
    }
    
    std::string hex_part = address.substr(2);
    if (!utils::is_hex_string(hex_part)) {
        result.error_message = "Invalid hex characters in Ethereum address";
        return false;
    }
    
    result.type = AddressType::ETHEREUM_STYLE;
    result.normalized_address = utils::to_checksum_address(address);
    return true;
}

bool BlockchainAddressValidator::validate_monero_address(const std::string& address, AddressValidationResult& result) const {
    if (address.length() < 95 || address.length() > 106) {
        result.error_message = "Invalid Monero address length";
        return false;
    }
    
    if (!utils::is_base58_string(address)) {
        result.error_message = "Invalid Base58 characters in Monero address";
        return false;
    }
    
    if (address[0] == '4') {
        result.type = AddressType::MONERO_STANDARD;
    } else if (address[0] == '8') {
        result.type = AddressType::MONERO_INTEGRATED;
        result.requires_memo = true;
    } else if (address[0] == '9' || address[0] == 'A') {
        result.type = AddressType::MONERO_STANDARD;
        result.network = Network::TESTNET;
    } else {
        result.error_message = "Invalid Monero address prefix";
        return false;
    }
    
    result.normalized_address = address;
    return true;
}

bool BlockchainAddressValidator::validate_zcash_address(const std::string& address, AddressValidationResult& result) const {
    // Zcash has multiple address types
    if (address.length() >= 2 && (address.substr(0, 2) == "zc" || address.substr(0, 2) == "zs")) {
        // Shielded addresses
        result.type = AddressType::ZCASH_SHIELDED;
        result.normalized_address = address;
        return true;
    }
    
    // Transparent addresses (use Base58Check)
    std::vector<unsigned char> decoded;
    if (DecodeBase58Check(address, decoded, 25) && decoded.size() == 21) {
        unsigned char version_byte = decoded[0];
        if (version_byte == 28) {
            result.type = AddressType::LEGACY_P2PKH;
        } else if (version_byte == 189) {
            result.type = AddressType::LEGACY_P2SH;
        } else {
            result.error_message = "Invalid Zcash address version";
            return false;
        }
        
        result.decoded_data = decoded;
        result.normalized_address = address;
        return true;
    }
    
    result.error_message = "Invalid Zcash address format";
    return false;
}

Blockchain BlockchainAddressValidator::detect_blockchain_from_address(const std::string& address) const {
    if (address.empty()) return Blockchain::UNKNOWN;
    
    // Ethereum-style addresses
    if (address.length() == 42 && address.substr(0, 2) == "0x") {
        return Blockchain::ETHEREUM;
    }
    
    // Bech32 prefixes
    if (address.length() >= 4) {
        std::string prefix = address.substr(0, 4);
        if (prefix == "ltc1") return Blockchain::LITECOIN;
        if (prefix == "bc1" || prefix == "tb1") return Blockchain::BITCOIN;
    }
    
    if (address.length() >= 5) {
        std::string prefix = address.substr(0, 5);
        if (prefix == "tltc1" || prefix == "rltc1") return Blockchain::LITECOIN;
    }
    
    // Monero addresses
    if (address.length() >= 95 && (address[0] == '4' || address[0] == '8' || address[0] == '9' || address[0] == 'A')) {
        return Blockchain::MONERO;
    }
    
    // Zcash shielded addresses
    if (address.length() >= 2 && (address.substr(0, 2) == "zc" || address.substr(0, 2) == "zs")) {
        return Blockchain::ZCASH;
    }
    
    // Legacy addresses - harder to distinguish, try Base58Check
    std::vector<unsigned char> decoded;
    if (DecodeBase58Check(address, decoded, 25) && decoded.size() == 21) {
        unsigned char version = decoded[0];
        
        // Bitcoin
        if (version == 0 || version == 5) return Blockchain::BITCOIN;
        if (version == 111 || version == 196) return Blockchain::BITCOIN; // Testnet
        
        // Litecoin
        if (version == 48 || version == 50) return Blockchain::LITECOIN;
        if (version == 111 || version == 196) return Blockchain::LITECOIN; // Testnet (same as Bitcoin)
        
        // Dogecoin
        if (version == 30 || version == 22) return Blockchain::DOGECOIN;
        
        // Zcash
        if (version == 28 || version == 189) return Blockchain::ZCASH;
    }
    
    return Blockchain::UNKNOWN;
}

void BlockchainAddressValidator::set_primary_blockchain(Blockchain blockchain, Network network) {
    m_primary_blockchain = blockchain;
    m_primary_network = network;
}

std::string BlockchainAddressValidator::get_blockchain_name(Blockchain blockchain) const {
    switch (blockchain) {
        case Blockchain::LITECOIN: return "Litecoin";
        case Blockchain::BITCOIN: return "Bitcoin";
        case Blockchain::ETHEREUM: return "Ethereum";
        case Blockchain::MONERO: return "Monero";
        case Blockchain::ZCASH: return "Zcash";
        case Blockchain::DOGECOIN: return "Dogecoin";
        default: return "Unknown";
    }
}

std::string BlockchainAddressValidator::get_network_name(Network network) const {
    switch (network) {
        case Network::MAINNET: return "mainnet";
        case Network::TESTNET: return "testnet";
        case Network::REGTEST: return "regtest";
        default: return "unknown";
    }
}

std::string BlockchainAddressValidator::get_address_type_name(AddressType type) const {
    switch (type) {
        case AddressType::LEGACY_P2PKH: return "Legacy P2PKH";
        case AddressType::LEGACY_P2SH: return "Legacy P2SH";
        case AddressType::BECH32_NATIVE_SEGWIT: return "Bech32 Native SegWit";
        case AddressType::BECH32_TAPROOT: return "Bech32 Taproot";
        case AddressType::ETHEREUM_STYLE: return "Ethereum Style";
        case AddressType::MONERO_STANDARD: return "Monero Standard";
        case AddressType::MONERO_INTEGRATED: return "Monero Integrated";
        case AddressType::ZCASH_SHIELDED: return "Zcash Shielded";
        default: return "Invalid";
    }
}

std::vector<std::string> BlockchainAddressValidator::get_expected_address_formats() const {
    std::vector<std::string> formats;
    
    auto blockchain_it = m_configs.find(m_primary_blockchain);
    if (blockchain_it == m_configs.end()) return formats;
    
    auto network_it = blockchain_it->second.find(m_primary_network);
    if (network_it == blockchain_it->second.end()) return formats;
    
    const BlockchainConfig& config = network_it->second;
    
    // Add expected formats based on configuration
    for (const std::string& prefix : config.bech32_prefixes) {
        formats.push_back(prefix + "... (Bech32)");
    }
    
    std::string blockchain_name = get_blockchain_name(m_primary_blockchain);
    if (!config.p2pkh_versions.empty()) {
        formats.push_back(blockchain_name + " Legacy P2PKH");
    }
    if (!config.p2sh_versions.empty()) {
        formats.push_back(blockchain_name + " Legacy P2SH");
    }
    
    return formats;
}

namespace utils {

bool is_hex_string(const std::string& str) {
    return std::all_of(str.begin(), str.end(), [](char c) {
        return std::isxdigit(c);
    });
}

bool is_base58_string(const std::string& str) {
    std::string base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    return std::all_of(str.begin(), str.end(), [&](char c) {
        return base58_chars.find(c) != std::string::npos;
    });
}

std::string to_checksum_address(const std::string& eth_address) {
    // Simplified EIP-55 checksum implementation
    std::string addr = eth_address;
    std::transform(addr.begin() + 2, addr.end(), addr.begin() + 2, ::tolower);
    return addr; // TODO: Implement full EIP-55 checksumming
}

} // namespace utils

} // namespace address
} // namespace c2pool
