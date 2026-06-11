#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>

#include <array>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace dgb
{

/// DigiByte Scrypt P2Pool network configuration.
/// Constants match frstrtr/p2pool-merged-v36 p2pool/networks/digibyte.py
class PoolConfig : protected core::Fileconfig
{
protected:
    std::ofstream& get_default(std::ofstream& file) override;
    void load() override;

public:
    PoolConfig(const std::filesystem::path& path) : core::Fileconfig(path) {}

    // -----------------------------------------------------------------------
    // Static DGB Scrypt p2pool network constants
    // Source: p2pool-merged-v36/p2pool/networks/digibyte.py
    // -----------------------------------------------------------------------
    static constexpr uint16_t P2P_PORT                  = 5024;
    static constexpr uint32_t SPREAD                    = 30;
    static constexpr uint32_t TARGET_LOOKBEHIND         = 200;
    static constexpr uint32_t MINIMUM_PROTOCOL_VERSION  = 3600;
    static constexpr uint32_t SEGWIT_ACTIVATION_VERSION = 17;
    static constexpr uint32_t BLOCK_MAX_SIZE            = 1000000;
    static constexpr uint32_t BLOCK_MAX_WEIGHT          = 4000000;

    // Mainnet constants
    static constexpr uint32_t SHARE_PERIOD              = 25;      // seconds
    static constexpr uint32_t CHAIN_LENGTH              = 8640;    // ~24 hours at 25s
    static constexpr uint32_t REAL_CHAIN_LENGTH         = 8640;

    // Testnet constants
    static constexpr uint32_t TESTNET_SHARE_PERIOD      = 4;
    static constexpr uint32_t TESTNET_CHAIN_LENGTH      = 400;
    static constexpr uint32_t TESTNET_REAL_CHAIN_LENGTH  = 400;

    static inline bool is_testnet = false;

    static uint32_t share_period()      { return is_testnet ? TESTNET_SHARE_PERIOD : SHARE_PERIOD; }
    static uint32_t chain_length()      { return is_testnet ? TESTNET_CHAIN_LENGTH : CHAIN_LENGTH; }
    static uint32_t real_chain_length()  { return is_testnet ? TESTNET_REAL_CHAIN_LENGTH : REAL_CHAIN_LENGTH; }

    // MAX_TARGET: share difficulty floor
    static uint256 max_target()
    {
        static const uint256 MAINNET_MAX = [] {
            uint256 t;
            t.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            return t;
        }();
        static const uint256 TESTNET_MAX = [] {
            uint256 t;
            t.SetHex("0ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb");
            return t;
        }();
        return is_testnet ? TESTNET_MAX : MAINNET_MAX;
    }

    // -----------------------------------------------------------------------
    // Donation scripts — version-gated migration (pillar 4)
    //   pre-V36 : farsider350 2-of-3 bare multisig (DGB v35 canonical donation)
    //   V36+    : shared COMBINED P2SH 1-of-2 (byte-identical to LTC network)
    // get_donation_script(version) selects per share version, matching the
    // donation transition in p2pool-merged-v36. Source of truth for the v35
    // bytes: farsider350 p2pool-dgb-scrypt-350 p2pool/data.py:66 DONATION_SCRIPT.
    // -----------------------------------------------------------------------

    // Pre-V36 DONATION_SCRIPT (OP_2 <3x33B pubkey> OP_3 OP_CHECKMULTISIG)
    static constexpr std::array<uint8_t, 105> DONATION_SCRIPT = {
        0x52,                                   // OP_2
        0x21, 0x02, 0xd9, 0x22, 0x34, 0x77, 0x7b, 0x63,  // push33 pubkey 1
              0xf6, 0xdb, 0xc0, 0xa0, 0x38, 0x2b, 0xbc, 0xb5, 0x4e, 0x0b, 0xef, 0xb0, 0x1f, 0x6a, 0x4b, 0x06,
              0x21, 0x22, 0xfa, 0xda, 0xb0, 0x44, 0xaf, 0x6c, 0x06, 0x88,
        0x21, 0x03, 0xb2, 0x7b, 0xbc, 0x50, 0x19, 0xd3,  // push33 pubkey 2
              0x54, 0x35, 0x86, 0x48, 0x2a, 0x99, 0x5e, 0x8f, 0x57, 0xc6, 0xad, 0x50, 0x6a, 0x4d, 0xaf, 0xa6,
              0xbf, 0x7c, 0xc8, 0x95, 0x33, 0xb8, 0xdc, 0xb2, 0xdf, 0x1b,
        0x21, 0x02, 0x91, 0x1f, 0xf8, 0x7e, 0x79, 0x2e,  // push33 pubkey 3
              0xc7, 0x5b, 0x3a, 0x30, 0xdc, 0x11, 0x5d, 0xfd, 0x06, 0xec, 0x27, 0xc9, 0x3b, 0x27, 0x03, 0x4a,
              0xa8, 0xe7, 0xce, 0xfb, 0xee, 0x64, 0x77, 0xe5, 0xd0, 0x34,
        0x53, 0xae                              // OP_3 OP_CHECKMULTISIG
    };

    // V36+ combined donation (P2SH 1-of-2 multisig, same as LTC network)
    static constexpr std::array<uint8_t, 23> COMBINED_DONATION_SCRIPT = {
        0xa9, 0x14,
        0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
        0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71,
        0x36, 0xbe, 0x8e, 0x85,
        0x87
    };

    static std::vector<unsigned char> get_donation_script(int64_t share_version)
    {
        if (share_version >= 36)
            return {COMBINED_DONATION_SCRIPT.begin(), COMBINED_DONATION_SCRIPT.end()};
        return {DONATION_SCRIPT.begin(), DONATION_SCRIPT.end()};
    }

    // P2Pool network framing (from p2pool-merged-v36/p2pool/networks/digibyte.py)
    static inline const std::string DEFAULT_PREFIX_HEX     = "1bfe01eff652e4b7";
    static inline const std::string TESTNET_PREFIX_HEX     = "1bfe01eff652e4b7";  // same for testnet
    static inline const std::string IDENTIFIER_HEX         = "1bfe01eff5ba4e38";
    static inline const std::string TESTNET_IDENTIFIER_HEX = "1bfe01eff5ba4e38";

    static const std::string& identifier_hex() {
        return is_testnet ? TESTNET_IDENTIFIER_HEX : IDENTIFIER_HEX;
    }

    static inline const std::set<std::string> SOFTFORKS_REQUIRED = {
        "csv", "segwit"
    };

    // Bootstrap peers for the DGB Scrypt p2pool network
    static inline const std::vector<std::string> DEFAULT_BOOTSTRAP_HOSTS = {
        // Will be populated as DGB p2pool nodes come online
    };

    // -----------------------------------------------------------------------
    // Runtime config loaded from pool.yaml
    // -----------------------------------------------------------------------
    std::vector<std::byte> m_prefix;
    std::string m_worker;
    std::vector<NetService> m_bootstrap_addrs;
};

} // namespace dgb
