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
    static constexpr uint32_t MINIMUM_PROTOCOL_VERSION  = 3301;   // digibyte.py:27 (was 3600 = LTC-copy bug)
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
    //   pre-V36 : GLOBAL P2Pool DONATION_SCRIPT (P2PK, original author forrestv)
    //   V36+    : GLOBAL COMBINED_DONATION_SCRIPT (P2SH 1-of-2 forrestv+maintainer)
    // CANONICAL: p2pool-merged-v36 @ 42ccca53 data.py:118 (P2PK) / :131 (COMBINED).
    // DGB networks/digibyte.py defines NO per-network donation -> DGB inherits the
    // GLOBAL script identically to LTC/DOGE (required for v36 gentx parity).
    // Supersedes legacy farsider350 p2pool-dgb-scrypt-350 2-of-3 P2MS, which is the
    // standalone-network donation, NOT the v36 compat target (integrator 06-16).
    // -----------------------------------------------------------------------

    // Pre-V36 DONATION_SCRIPT (P2PK: OP_PUSHBYTES_65 <uncompressed pubkey> OP_CHECKSIG)
    static constexpr std::array<uint8_t, 67> DONATION_SCRIPT = {
        0x41,
        0x04, 0xff, 0xd0, 0x3d, 0xe4, 0x4a, 0x6e, 0x11,
        0xb9, 0x91, 0x7f, 0x3a, 0x29, 0xf9, 0x44, 0x32,
        0x83, 0xd9, 0x87, 0x1c, 0x9d, 0x74, 0x3e, 0xf3,
        0x0d, 0x5e, 0xdd, 0xcd, 0x37, 0x09, 0x4b, 0x64,
        0xd1, 0xb3, 0xd8, 0x09, 0x04, 0x96, 0xb5, 0x32,
        0x56, 0x78, 0x6b, 0xf5, 0xc8, 0x29, 0x32, 0xec,
        0x23, 0xc3, 0xb7, 0x4d, 0x9f, 0x05, 0xa6, 0xf9,
        0x5a, 0x8b, 0x55, 0x29, 0x35, 0x26, 0x56, 0x66,
        0x4b,
        0xac
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
