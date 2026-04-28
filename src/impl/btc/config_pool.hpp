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

namespace btc
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
    // BTC p2pool network constants (jtoomim/SPB-compat — must match the live
    // BTC p2pool sharechain at p2p-spb.xyz:9333 + jtoomim-derived peers).
    // Source: ref/p2pool-btc + p2pool-jtoomim/p2pool/networks/bitcoin.py.
    // Live network probe 2026-04-28: SPB cluster runs version 77.0.0 with
    // protocol_version 3502 (one bump above jtoomim master's 3501).
    // -----------------------------------------------------------------------
    static constexpr uint16_t P2P_PORT                  = 9333;  // BTC p2pool sharechain port
    static constexpr uint32_t SPREAD                    = 3;       // blocks (PPLNS window)
    static constexpr uint32_t TARGET_LOOKBEHIND         = 200;
    // MINIMUM 3500 admits jtoomim master (3501) and SPB cluster (3502).
    // Below that lies forrestv-era v17/v32 — not interoperable with v35.
    static constexpr uint32_t MINIMUM_PROTOCOL_VERSION  = 3500;
    // Our capability — match SPB cluster's bump for forward-compat.
    static constexpr uint32_t ADVERTISED_PROTOCOL_VERSION = 3502;
    static constexpr uint32_t SEGWIT_ACTIVATION_VERSION = 33;     // jtoomim BTC bitcoin.py:35
    static constexpr uint32_t BLOCK_MAX_SIZE            = 1000000;
    static constexpr uint32_t BLOCK_MAX_WEIGHT          = 4000000;

    // Mainnet constants — jtoomim BTC bitcoin.py
    static constexpr uint32_t SHARE_PERIOD              = 30;      // seconds (BTC slower than LTC's 15)
    static constexpr uint32_t CHAIN_LENGTH              = 8640;    // 24*60*60 / 10
    static constexpr uint32_t REAL_CHAIN_LENGTH         = 8640;

    // DUST_THRESHOLD: minimum payout per share output.
    // BTC mainnet: 0.001 BTC = 100000 sat (jtoomim bitcoin/networks/bitcoin.py:32).
    // Testnet: 1.0 BTC placeholder until jtoomim BTC testnet config is consulted.
    static constexpr uint64_t DUST_THRESHOLD            = 100000;     // satoshis (BTC mainnet)
    static constexpr uint64_t TESTNET_DUST_THRESHOLD    = 100000000;  // satoshis placeholder
    static uint64_t dust_threshold() { return is_testnet ? TESTNET_DUST_THRESHOLD : DUST_THRESHOLD; }

    // Testnet constants (jtoomim BTC testnet bitcoin/networks/bitcoin_testnet.py
    // not yet probed; using BTC-mainnet defaults until live testnet network is
    // selected). Conservative copy of mainnet for now — adjust in B-testnet phase.
    static constexpr uint32_t TESTNET_SHARE_PERIOD      = 30;
    static constexpr uint32_t TESTNET_CHAIN_LENGTH      = 8640;
    static constexpr uint32_t TESTNET_REAL_CHAIN_LENGTH  = 8640;

    // Runtime testnet flag — set once at startup
    static inline bool is_testnet = false;

    // Accessors that return correct value for current network
    static uint32_t share_period()      { return is_testnet ? TESTNET_SHARE_PERIOD : SHARE_PERIOD; }
    static uint32_t chain_length()      { return is_testnet ? TESTNET_CHAIN_LENGTH : CHAIN_LENGTH; }
    static uint32_t real_chain_length()  { return is_testnet ? TESTNET_REAL_CHAIN_LENGTH : REAL_CHAIN_LENGTH; }

    // MAX_TARGET: share difficulty floor (easiest allowed share PoW).
    // BTC mainnet: 2^256 / 2^32 - 1 (≈ 2^224, bdiff 1) — jtoomim BTC bitcoin.py:18
    //              MAX_TARGET = 2**256//2**32 - 1
    // Testnet: same as mainnet for now (jtoomim BTC testnet placeholder).
    static uint256 max_target()
    {
        static const uint256 MAINNET_MAX = [] {
            uint256 t;
            // 2^256 / 2^32 - 1 = 0x00000000ffffffff...ffffffff (224 bits set).
            t.SetHex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            return t;
        }();
        static const uint256 TESTNET_MAX = [] {
            uint256 t;
            t.SetHex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            return t;
        }();
        return is_testnet ? TESTNET_MAX : MAINNET_MAX;
    }

    // -----------------------------------------------------------------------
    // Consensus-critical donation scripts
    // Must match frstrtr/p2pool-merged-v36 p2pool/data.py exactly.
    // -----------------------------------------------------------------------

    // V35 DONATION_SCRIPT (P2PK: OP_PUSHBYTES_65 <uncompressed pubkey> OP_CHECKSIG).
    // Same script bytes as forrestv/jtoomim BTC p2pool data.py:68 — the
    // uncompressed pubkey is forrestv's; encoded address differs by network
    // (1... on BTC mainnet, L... on LTC). Verified bit-identical 2026-04-28.
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
    // 1-of-2 multisig: forrestv + frstrtr/c2pool dev key.
    // LTC-specific (BTC stays at v35 per jtoomim — see plan v2 §3); kept
    // here as inert byte data so get_donation_script() compiles for both
    // BTC v35 (returns the P2PK above) and LTC v36 paths.
    // Address: MLhSmVQxMusLE3pjGFvp4unFckgjeD8LUA (LTC mainnet P2SH).
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

    // Message framing prefix — BTC mainnet (jtoomim bitcoin.py:14):
    //   PREFIX = '2472ef181efcd37b'
    static inline const std::string DEFAULT_PREFIX_HEX          = "2472ef181efcd37b";
    // Testnet placeholder until jtoomim BTC testnet prefix is probed
    static inline const std::string TESTNET_PREFIX_HEX          = "2472ef181efcd37b";
    // Network identifier — BTC mainnet (jtoomim bitcoin.py:13):
    //   IDENTIFIER = 'fc70035c7a81bc6f'
    static inline const std::string DEFAULT_IDENTIFIER_HEX      = "fc70035c7a81bc6f";
    // Testnet placeholder
    static inline const std::string TESTNET_IDENTIFIER_HEX      = "fc70035c7a81bc6f";

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

    // BTC mainnet softforks per jtoomim bitcoin.py:33 + post-2021 additions.
    // jtoomim master pre-dates Taproot activation but the bitcoind we connect
    // to enforces it; tracking it here keeps the softfork-check pass aligned
    // with bitcoind's getblockchaininfo.
    static inline const std::set<std::string> SOFTFORKS_REQUIRED = {
        "bip65", "csv", "segwit", "taproot"
    };

    // Default bootstrap peers — live BTC p2pool network (probed 2026-04-28
    // via http://p2p-spb.xyz:9334/peer_versions). Mix of the SPB-cluster
    // 77.0.0 fork + jtoomim-master-derived peers + jtoomim BTC bitcoin.py
    // BOOTSTRAP_ADDRS defaults.
    static inline const std::vector<std::string> DEFAULT_BOOTSTRAP_HOSTS = {
        // SPB cluster (4 nodes RU + USA, version 77.0.0)
        "p2p-spb.xyz",
        "ekb.p2p-spb.xyz",
        "rov.p2p-spb.xyz",
        "usa.p2p-spb.xyz",
        // jtoomim-master defaults (BOOTSTRAP_ADDRS in bitcoin.py)
        "ml.toom.im",
        "btc-fork.coinpool.pw:9335",
        "btc.p2pool.leblancnet.us",
    };

    // -----------------------------------------------------------------------
    // Runtime config loaded from pool.yaml
    // -----------------------------------------------------------------------
    std::vector<std::byte> m_prefix;
    std::string m_worker;
    std::vector<NetService> m_bootstrap_addrs;
};

} // namespace btc
