#pragma once

#include <core/config.hpp>
#include <core/version_gate.hpp>   // SSOT: core::version_gate::is_v36_active
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

// ---------------------------------------------------------------------------
// bch::PoolConfig -- BCH p2pool sharechain config. Ported from
// src/impl/btc/config_pool.hpp; all network constants resauthored from the
// p2pool-merged-v36 BCH reference (authoritative for V36 master-compat):
//   p2pool/networks/bitcoincash.py  + p2pool/bitcoin/networks/bitcoincash.py
//
// >>> BCH DIVERGENCES FROM BTC (M1 4.x) <<<
//  - NO SegWit: there is NO SEGWIT_ACTIVATION_VERSION and SOFTFORKS_REQUIRED
//    is EMPTY. BCH consensus changes (CTOR Nov-2018, ASERT DAA Nov-2020,
//    CashTokens+P2SH32 May-2023, ABLA CHIP-2023-01 May-2024) activate by MTP,
//    NOT via BIP9 versionbits / getblocktemplate "rules" -- so none are
//    GBT-signalled and none belong in the softfork-required gate.
//  - Block size: BCH carries 32 MB (BLOCK_MAX_SIZE) -- ABLA raises this over
//    time, but the p2pool template-size bookkeeping floor stays at the
//    reference value. "WEIGHT" is a p2pool bookkeeping field (4x size); BCH has
//    no witness weight.
//  - SHARE_PERIOD 60s (BTC 30s, LTC 15s); CHAIN_LENGTH 3*24*60 shares (3 days).
//  - Donation: VERSION-GATED (operator ruling 2026-06-16, V36 master-compat).
//    share_version <  36 -> BCH-native forrestv P2PK (static), byte-for-byte
//    from p2poolBCH @6603b79 (memory donation-verification-closed).
//    share_version >= 36 -> COMBINED_DONATION_SCRIPT (1-of-2 P2MS->P2SH
//    transition + AutoRatchet 95%/50% + tail-guard), byte-identical to the
//    BTC/LTC merged-path combined script -- merged-path is always COMBINED for
//    cross-coin V36 parity (project_v36_donation_transition_mechanism).
// ---------------------------------------------------------------------------

namespace bch
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
    // BCH p2pool network constants -- p2pool-merged-v36 bitcoincash.py.
    // Must match the live BCH p2pool sharechain (P2P_PORT 9349). BCH is a
    // STANDALONE parent in V36 (not merged-mined), but the share format is V36.
    // -----------------------------------------------------------------------
    static constexpr uint16_t P2P_PORT                  = 9349;  // bitcoincash.py P2P_PORT
    static constexpr uint32_t SPREAD                    = 3;       // blocks (PPLNS window)
    static constexpr uint32_t TARGET_LOOKBEHIND         = 200;
    // 3301 floor matches p2pool-merged-v36 bitcoincash.py MINIMUM_PROTOCOL_VERSION.
    static constexpr uint32_t MINIMUM_PROTOCOL_VERSION  = 3301;
    // Our capability: V36 shares (matches LTC/DOGE advertised version).
    static constexpr uint32_t ADVERTISED_PROTOCOL_VERSION = 3600;
    // NOTE: NO SEGWIT_ACTIVATION_VERSION on BCH -- SegWit was rejected at the
    // Aug-2017 fork. (BTC carries one; intentionally absent here.)
    static constexpr uint32_t BLOCK_MAX_SIZE            = 32000000;   // 32 MB (BCH)
    static constexpr uint32_t BLOCK_MAX_WEIGHT          = 128000000;  // 4x size bookkeeping

    // Mainnet constants -- bitcoincash.py
    static constexpr uint32_t SHARE_PERIOD              = 60;      // seconds (one minute)
    static constexpr uint32_t CHAIN_LENGTH              = 4320;    // 3*24*60 shares (3 days)
    static constexpr uint32_t REAL_CHAIN_LENGTH         = 4320;

    // DUST_THRESHOLD: minimum payout per share output.
    // BCH: PARENT.DUST_THRESHOLD = 0.001e8 = 100000 sat (bitcoin/networks/bitcoincash.py).
    static constexpr uint64_t DUST_THRESHOLD            = 100000;     // satoshis (BCH mainnet)
    static constexpr uint64_t TESTNET_DUST_THRESHOLD    = 100000;     // mirrors mainnet pending parent confirm
    static uint64_t dust_threshold() { return is_testnet ? TESTNET_DUST_THRESHOLD : DUST_THRESHOLD; }

    // Testnet constants -- bitcoincash_testnet.py (same cadence as mainnet).
    static constexpr uint32_t TESTNET_SHARE_PERIOD      = 60;
    static constexpr uint32_t TESTNET_CHAIN_LENGTH      = 4320;
    static constexpr uint32_t TESTNET_REAL_CHAIN_LENGTH  = 4320;

    // Runtime testnet flag -- set once at startup
    static inline bool is_testnet = false;

    // Accessors that return correct value for current network
    static uint32_t share_period()      { return is_testnet ? TESTNET_SHARE_PERIOD : SHARE_PERIOD; }
    static uint32_t chain_length()      { return is_testnet ? TESTNET_CHAIN_LENGTH : CHAIN_LENGTH; }
    static uint32_t real_chain_length()  { return is_testnet ? TESTNET_REAL_CHAIN_LENGTH : REAL_CHAIN_LENGTH; }

    // MAX_TARGET: share difficulty floor. BCH = 2**256//2**32 - 1 (bdiff 1),
    // identical to BTC (bitcoincash.py MAX_TARGET).
    static uint256 max_target()
    {
        static const uint256 MAINNET_MAX = [] {
            uint256 t;
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
    // Consensus-critical donation scripts -- VERSION-GATED per operator ruling
    // 2026-06-16 (V36 master-compat with p2pool-merged-v36).
    //
    // Pre-V36 (share_version < 36): BCH-native forrestv P2PK (static). Bytes are
    // forrestv's uncompressed pubkey, bit-identical to the BTC/LTC pre-V36 P2PK,
    // verified first-hand vs p2poolBCH @6603b79 (memory donation-verification-closed).
    // -----------------------------------------------------------------------
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

    // V36+ (share_version >= 36): COMBINED_DONATION_SCRIPT -- P2SH wrapping the
    // 1-of-2 P2MS (forrestv + maintainer) transition redeem; AutoRatchet 95%/50%
    // + tail-guard semantics are carried in the redeem script. Byte-identical to
    // the BTC/LTC merged-path combined script (coin-independent hash160) --
    // merged-path is always COMBINED for cross-coin V36 parity.
    static constexpr std::array<uint8_t, 23> COMBINED_DONATION_SCRIPT = {
        0xa9, // OP_HASH160
        0x14, // PUSH 20 bytes
        0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
        0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71,
        0x36, 0xbe, 0x8e, 0x85,
        0x87  // OP_EQUAL
    };

    // Returns the correct donation script for a share version (operator ruling
    // 2026-06-16). Pre-V36 shares use the BCH-native forrestv P2PK; V36+ shares
    // use the combined P2SH 1-of-2 multisig script. Same shape as BTC/LTC.
    static std::vector<unsigned char> get_donation_script(int64_t share_version)
    {
        if (core::version_gate::is_v36_active(share_version))
            return {COMBINED_DONATION_SCRIPT.begin(), COMBINED_DONATION_SCRIPT.end()};
        return {DONATION_SCRIPT.begin(), DONATION_SCRIPT.end()};
    }

    // Message framing -- bitcoincash.py:
    //   IDENTIFIER = 'b826c0a51ddc2d2b'   PREFIX = 'ac9a8fda9a911bce'
    static inline const std::string DEFAULT_PREFIX_HEX          = "ac9a8fda9a911bce";
    static inline const std::string DEFAULT_IDENTIFIER_HEX      = "b826c0a51ddc2d2b";
    // bitcoincash_testnet.py:
    //   IDENTIFIER = 'c9f3de8d9508faef'   PREFIX = '08c5541df85a8a65'
    static inline const std::string TESTNET_PREFIX_HEX          = "08c5541df85a8a65";
    static inline const std::string TESTNET_IDENTIFIER_HEX      = "c9f3de8d9508faef";

    // Private chain overrides -- set once at startup via --network-id
    static inline std::string override_identifier_hex;
    static inline std::string override_prefix_hex;

    /// Set private network identity. IDENTIFIER is the consensus secret
    /// (hashed into ref_hash). PREFIX is derived from it for transport framing.
    static void set_network_id(const std::string& network_id_hex) {
        if (network_id_hex.empty() || network_id_hex == "0" || network_id_hex == "00000000")
            return;  // public network, use defaults

        std::string padded = network_id_hex;
        while (padded.size() < 16) padded = "0" + padded;
        if (padded.size() > 16) padded = padded.substr(0, 16);

        override_identifier_hex = padded;

        auto id_bytes = ParseHex(padded);
        static const char* HEX = "0123456789abcdef";
        override_prefix_hex.clear();
        override_prefix_hex.reserve(16);
        for (size_t i = 0; i < 8 && i < id_bytes.size(); ++i) {
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
    static uint64_t chain_fingerprint_u64() {
        if (override_identifier_hex.empty())
            return 0;  // public network

        auto pfx_bytes = ParseHex(override_prefix_hex);
        auto id_bytes = ParseHex(override_identifier_hex);
        std::vector<unsigned char> preimage;
        preimage.reserve(pfx_bytes.size() + id_bytes.size());
        preimage.insert(preimage.end(), pfx_bytes.begin(), pfx_bytes.end());
        preimage.insert(preimage.end(), id_bytes.begin(), id_bytes.end());

        unsigned char hash1[32], hash2[32];
        CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash1);
        CSHA256().Write(hash1, 32).Finalize(hash2);

        uint64_t fp = 0;
        for (int i = 0; i < 8; ++i)
            fp |= uint64_t(hash2[i]) << (8 * i);
        return fp;
    }

    // BCH softfork-required set is EMPTY (bitcoincash.py SOFTFORKS_REQUIRED = set()).
    // BCH consensus rules are MTP-activated, NOT BIP9/GBT-signalled, so there is
    // nothing for the getblockchaininfo/GBT-rules softfork gate to enforce. The
    // gate in rpc.cpp consequently always passes for BCH -- intentional.
    static inline const std::set<std::string> SOFTFORKS_REQUIRED = {};

    // Default bootstrap peers -- bitcoincash.py BOOTSTRAP_ADDRS.
    static inline const std::vector<std::string> DEFAULT_BOOTSTRAP_HOSTS = {
        "ml.toom.im",
        "bch.p2pool.leblancnet.us",
        "siberia.mine.nu",
        "5.8.79.155",
        "18.209.181.17",
        "95.79.35.133",
        "193.29.58.47",
    };

    // -----------------------------------------------------------------------
    // Runtime config loaded from pool.yaml
    // -----------------------------------------------------------------------
    std::vector<std::byte> m_prefix;
    std::string m_worker;
    std::vector<NetService> m_bootstrap_addrs;
};

} // namespace bch
