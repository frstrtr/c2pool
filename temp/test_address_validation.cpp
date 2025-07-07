
#include <iostream>
#include <vector>
#include <string>
#include <core/address_validator.hpp>

using namespace c2pool::address;

int main() {
    // Initialize validator for Litecoin testnet
    BlockchainAddressValidator validator(Blockchain::LITECOIN, Network::TESTNET);
    
    std::vector<std::pair<std::string, std::string>> test_addresses = {
        {"tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds58ajt0", "LTC testnet bech32"},
        {"2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br", "LTC testnet P2SH"},  
        {"mzBc4XEFSdzCDcTxAgf6EZXgsZWpztR", "LTC testnet legacy P2PKH"},
        {"LaMT348PWRnrqeeWArpwQDAVWs71DTuLP9", "LTC mainnet legacy (should fail)"},
        {"ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9", "LTC mainnet bech32 (should fail)"},
        {"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "BTC address (should fail)"},
        {"invalid_address", "Invalid string (should fail)"}
    };
    
    std::cout << "Address Validation Test Results:\n";
    std::cout << "================================\n";
    
    for (const auto& test_case : test_addresses) {
        const std::string& address = test_case.first;
        const std::string& description = test_case.second;
        
        std::cout << "\nTesting: " << description << "\n";
        std::cout << "Address: " << address << "\n";
        
        auto result = validator.validate_address_strict(address);
        
        if (result.is_valid) {
            std::cout << "Result: ✅ VALID\n";
            std::cout << "Type: " << validator.get_address_type_name(result.type) << "\n";
            std::cout << "Network: " << validator.get_network_name(result.network) << "\n";
        } else {
            std::cout << "Result: ❌ INVALID\n";
            std::cout << "Error: " << result.error_message << "\n";
        }
    }
    
    return 0;
}
