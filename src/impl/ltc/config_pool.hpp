#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>

#include <array>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace ltc
{
    
class PoolConfig : protected core::Fileconfig
{
protected:
    std::ofstream& get_default(std::ofstream& file) override;
    void load() override;

public:
    PoolConfig(const std::filesystem::path& path) : core::Fileconfig(path)
    {

    }

    // -----------------------------------------------------------------------
    // Static LTC p2pool network constants (must match frstrtr/p2pool-merged-v36)
    // -----------------------------------------------------------------------
    static constexpr uint16_t P2P_PORT                  = 9326;  // must match p2pool-merged-v36
    static constexpr uint32_t SPREAD                    = 3;       // blocks (PPLNS window)
    static constexpr uint32_t TARGET_LOOKBEHIND         = 200;
    static constexpr uint32_t MINIMUM_PROTOCOL_VERSION  = 3600;
    static constexpr uint32_t SEGWIT_ACTIVATION_VERSION = 17;
    static constexpr uint32_t BLOCK_MAX_SIZE            = 1000000;
    static constexpr uint32_t BLOCK_MAX_WEIGHT          = 4000000;

    // Mainnet constants
    static constexpr uint32_t SHARE_PERIOD              = 15;      // seconds
    static constexpr uint32_t CHAIN_LENGTH              = 8640;    // 24*60*60 / 10
    static constexpr uint32_t REAL_CHAIN_LENGTH         = 8640;

    // Testnet constants (selected at runtime via is_testnet)
    static constexpr uint32_t TESTNET_SHARE_PERIOD      = 4;       // seconds
    static constexpr uint32_t TESTNET_CHAIN_LENGTH      = 400;     // 20*60//3
    static constexpr uint32_t TESTNET_REAL_CHAIN_LENGTH  = 400;

    // Runtime testnet flag — set once at startup
    static inline bool is_testnet = false;

    // Accessors that return correct value for current network
    static uint32_t share_period()      { return is_testnet ? TESTNET_SHARE_PERIOD : SHARE_PERIOD; }
    static uint32_t chain_length()      { return is_testnet ? TESTNET_CHAIN_LENGTH : CHAIN_LENGTH; }
    static uint32_t real_chain_length()  { return is_testnet ? TESTNET_REAL_CHAIN_LENGTH : REAL_CHAIN_LENGTH; }

    // MAX_TARGET: share difficulty floor (easiest allowed)
    // Mainnet: 2^256 / 2^20 - 1 (≈ 2^236)
    // Testnet: 2^256 / 20 - 1   (≈ 2^251.7)  — must match Python litecoin_testnet.py
    static uint256 max_target()
    {
        static const uint256 MAINNET_MAX = [] {
            uint256 t;
            t.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            return t;
        }();
        static const uint256 TESTNET_MAX = [] {
            // 2^256 / 20 - 1
            uint256 t;
            t.SetHex("0ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb");
            return t;
        }();
        return is_testnet ? TESTNET_MAX : MAINNET_MAX;
    }

    // -----------------------------------------------------------------------
    // Consensus-critical donation scripts
    // Must match frstrtr/p2pool-merged-v36 p2pool/data.py exactly.
    // -----------------------------------------------------------------------

    // Pre-V36 DONATION_SCRIPT (P2PK: OP_PUSHBYTES_65 <uncompressed pubkey> OP_CHECKSIG)
    // Address: LeD2fnnDJYZuyt8zgDsZ2oBGmuVcxGKCLd (Litecoin mainnet)
    static constexpr std::array<uint8_t, 67> DONATION_SCRIPT = {
        0x41, // OP_PUSHBYTES_65
        0x04, 0xff, 0xd0, 0x3d, 0xe4, 0x4a, 0x6e, 0x11,
        0xb9, 0x91, 0x7f, 0x3a, 0x29, 0xf9, 0x44, 0x32,
        0x83, 0xd9, 0x87, 0x1c, 0x9d, 0x74, 0x3e, 0xf3,
        0x0d, 0x5e, 0xdd, 0xcd, 0x37, 0x09, 0x4b, 0x64,
        0xd1, 0xb3, 0xd8, 0x09, 0x04, 0x96, 0xb5, 0x32,
        0x56, 0x78, 0x6b, 0xf5, 0xc8, 0x29, 0x32, 0xec,
        0x23, 0xc3, 0xb7, 0x4d, 0x9f, 0x05, 0xa6, 0xf9,
        0x5a, 0x8b, 0x55, 0x29, 0x35, 0x26, 0x56, 0x66,
        0x4b,
        0xac  // OP_CHECKSIG
    };

    // V36+ COMBINED_DONATION_SCRIPT (P2SH: OP_HASH160 <hash160(redeem)> OP_EQUAL)
    // 1-of-2 multisig: forrestv + frstrtr/c2pool dev key
    // Address: MLhSmVQxMusLE3pjGFvp4unFckgjeD8LUA (Litecoin mainnet)
    static constexpr std::array<uint8_t, 23> COMBINED_DONATION_SCRIPT = {
        0xa9, // OP_HASH160
        0x14, // PUSH 20 bytes
        0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
        0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71,
        0x36, 0xbe, 0x8e, 0x85,
        0x87  // OP_EQUAL
    };

    // Returns the correct donation script based on share version.
    // Pre-V36 shares use the original P2PK donation script.
    // V36+ shares use the combined P2SH 1-of-2 multisig script.
    static std::vector<unsigned char> get_donation_script(int64_t share_version)
    {
        if (share_version >= 36)
            return {COMBINED_DONATION_SCRIPT.begin(), COMBINED_DONATION_SCRIPT.end()};
        return {DONATION_SCRIPT.begin(), DONATION_SCRIPT.end()};
    }

    // Message framing prefix (mainnet): 72 08 c1 a5 3e f6 29 b0
    static inline const std::string DEFAULT_PREFIX_HEX          = "7208c1a53ef629b0";
    // Message framing prefix (testnet): ad 96 14 f6 46 6a 39 cf
    static inline const std::string TESTNET_PREFIX_HEX          = "ad9614f6466a39cf";
    // Network identifier (mainnet): e0 37 d5 b8 c6 92 34 10
    static inline const std::string IDENTIFIER_HEX              = "e037d5b8c6923410";
    // Network identifier (testnet): cc a5 e2 4e c6 40 8b 1e
    static inline const std::string TESTNET_IDENTIFIER_HEX      = "cca5e24ec6408b1e";

    static const std::string& identifier_hex() {
        return is_testnet ? TESTNET_IDENTIFIER_HEX : IDENTIFIER_HEX;
    }

    static inline const std::set<std::string> SOFTFORKS_REQUIRED = {
        "bip65", "csv", "segwit", "taproot", "mweb"
    };

    // Default bootstrap peers for the LTC p2pool mainnet
    static inline const std::vector<std::string> DEFAULT_BOOTSTRAP_HOSTS = {
        "ml.toom.im",
        "usa.p2p-spb.xyz",
        "102.160.209.121",
        "5.188.104.245",
        "20.127.82.115",
        "31.25.241.224",
        "20.113.157.65",
        "20.106.76.227",
        "15.218.180.55",
        "173.79.139.224",
        "174.60.78.162",
    };

    // -----------------------------------------------------------------------
    // Runtime config loaded from pool.yaml
    // -----------------------------------------------------------------------
    std::vector<std::byte> m_prefix;
    std::string m_worker;
    std::vector<NetService> m_bootstrap_addrs;
};

} // namespace ltc
