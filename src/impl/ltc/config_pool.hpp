#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>
#include <btclibs/util/strencodings.h>
#include <btclibs/crypto/sha256.h>
#include <core/uint256.hpp>

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
    static constexpr uint32_t MINIMUM_PROTOCOL_VERSION  = 3301;  // accept v35 (3502) and v36 (3600) peers
    static constexpr uint32_t ADVERTISED_PROTOCOL_VERSION = 3600; // our capability (V36 shares)
    static constexpr uint32_t SEGWIT_ACTIVATION_VERSION = 17;
    static constexpr uint32_t BLOCK_MAX_SIZE            = 1000000;
    static constexpr uint32_t BLOCK_MAX_WEIGHT          = 4000000;

    // Mainnet constants
    static constexpr uint32_t SHARE_PERIOD              = 15;      // seconds
    static constexpr uint32_t CHAIN_LENGTH              = 8640;    // 24*60*60 / 10
    static constexpr uint32_t REAL_CHAIN_LENGTH         = 8640;

    // DUST_THRESHOLD: minimum payout per block to justify a share output.
    // p2pool: PARENT.DUST_THRESHOLD (used in desired_target dust check).
    // Mainnet: 0.03 LTC = 3000000 litoshis (litecoin/networks/litecoin.py:35)
    // Testnet: 1.0 LTC = 100000000 litoshis (litecoin/networks/litecoin_testnet.py:33)
    static constexpr uint64_t DUST_THRESHOLD            = 3000000;  // litoshis (mainnet)
    static constexpr uint64_t TESTNET_DUST_THRESHOLD    = 100000000; // litoshis (testnet)
    static uint64_t dust_threshold() { return is_testnet ? TESTNET_DUST_THRESHOLD : DUST_THRESHOLD; }

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
    static inline const std::string DEFAULT_IDENTIFIER_HEX      = "e037d5b8c6923410";
    // Network identifier (testnet): cc a5 e2 4e c6 40 8b 1e
    static inline const std::string TESTNET_IDENTIFIER_HEX      = "cca5e24ec6408b1e";

    // Private chain overrides — set once at startup via --network-id
    static inline std::string override_identifier_hex;
    static inline std::string override_prefix_hex;

    /// Set private network identity. IDENTIFIER is the consensus secret
    /// (hashed into ref_hash). PREFIX is derived from it for transport framing.
    /// Call once at startup before any P2P or share operations.
    static void set_network_id(const std::string& network_id_hex) {
        if (network_id_hex.empty() || network_id_hex == "0" || network_id_hex == "00000000")
            return;  // public network, use defaults

        // Pad to 16 hex chars (8 bytes) if shorter
        std::string padded = network_id_hex;
        while (padded.size() < 16) padded = "0" + padded;
        if (padded.size() > 16) padded = padded.substr(0, 16);

        override_identifier_hex = padded;

        // Derive PREFIX from IDENTIFIER using simple XOR mixing
        // PREFIX = IDENTIFIER bytes XOR-rotated (fast, deterministic, non-reversible enough
        // for transport framing — the real security is in IDENTIFIER via ref_hash)
        auto id_bytes = ParseHex(padded);
        static const char* HEX = "0123456789abcdef";
        override_prefix_hex.clear();
        override_prefix_hex.reserve(16);
        for (size_t i = 0; i < 8 && i < id_bytes.size(); ++i) {
            // XOR with rotated byte + constant to ensure PREFIX != IDENTIFIER
            uint8_t b = id_bytes[i] ^ id_bytes[(i + 3) % id_bytes.size()] ^ 0x5A;
            override_prefix_hex += HEX[b >> 4];
            override_prefix_hex += HEX[b & 0x0f];
        }
    }

    static const std::string& identifier_hex() {
        if (!override_identifier_hex.empty())
            return override_identifier_hex;
        return is_testnet ? TESTNET_IDENTIFIER_HEX : DEFAULT_IDENTIFIER_HEX;
    }

    static const std::string& prefix_hex() {
        if (!override_prefix_hex.empty())
            return override_prefix_hex;
        return is_testnet ? TESTNET_PREFIX_HEX : DEFAULT_PREFIX_HEX;
    }

    /// Chain fingerprint: SHA256d(PREFIX || IDENTIFIER)[0:8]
    ///
    /// 16-byte preimage → 2^128 preimage space. 8-byte output →
    /// collision-free for all practical chain counts (birthday at 2^32 chains).
    /// Standard Bitcoin SHA256d, no custom cryptography.
    static uint64_t chain_fingerprint_u64() {
        if (override_identifier_hex.empty())
            return 0;  // public network

        auto pfx_bytes = ParseHex(override_prefix_hex);
        auto id_bytes = ParseHex(override_identifier_hex);
        std::vector<unsigned char> preimage;
        preimage.reserve(pfx_bytes.size() + id_bytes.size());
        preimage.insert(preimage.end(), pfx_bytes.begin(), pfx_bytes.end());
        preimage.insert(preimage.end(), id_bytes.begin(), id_bytes.end());

        // SHA256d: Hash = SHA256(SHA256(preimage))
        unsigned char hash1[32], hash2[32];
        CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash1);
        CSHA256().Write(hash1, 32).Finalize(hash2);

        uint64_t fp = 0;
        for (int i = 0; i < 8; ++i)
            fp |= uint64_t(hash2[i]) << (8 * i);
        return fp;
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
