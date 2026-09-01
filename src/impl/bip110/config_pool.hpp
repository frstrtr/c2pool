// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>
#include <btclibs/util/strencodings.h>
#include <btclibs/crypto/sha256.h>
#include <core/uint256.hpp>
#include <impl/bip110/params.hpp>

#include <array>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace bip110
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
    // BIP-110 (Bitcoin Knots BLAKE2b hard fork) c2pool sharechain constants.
    //
    // SINGLE SOURCE OF TRUTH: every identity value below DERIVES from the
    // namespace-level SHARECHAIN_* constants in params.hpp (the SSOT), so the
    // factory (make_coin_params) and this PoolConfig can never drift. BIP-110 is
    // a NEW sharechain, distinct from the BTC lane: its P2P/worker ports and
    // identifier/prefix are BIP-110-native (BTC uses 9333 / fc70035c7a81bc6f /
    // 2472ef181efcd37b), so the sharechain can never merge with, or cross-dial,
    // the live BTC p2pool network. PREFIX and IDENTIFIER are TWO INDEPENDENT
    // per-network transport constants (p2pool model) — PREFIX is never derived
    // from IDENTIFIER. This mirrors the DASH lane's isolation discipline.
    // -----------------------------------------------------------------------
    static constexpr uint16_t P2P_PORT                  = SHARECHAIN_P2P_PORT;     // 9335 BIP-110 sharechain P2P port
    static constexpr uint16_t WORKER_PORT               = SHARECHAIN_WORKER_PORT;  // 9336 BIP-110 Stratum port
    static constexpr uint32_t SPREAD                    = SHARECHAIN_SPREAD;       // blocks (PPLNS window)
    static constexpr uint32_t TARGET_LOOKBEHIND         = SHARECHAIN_TARGET_LOOKBEHIND;
    static constexpr uint32_t MINIMUM_PROTOCOL_VERSION  = SHARECHAIN_MINIMUM_PROTOCOL_VERSION;
    static constexpr uint32_t ADVERTISED_PROTOCOL_VERSION = SHARECHAIN_ADVERTISED_PROTOCOL_VERSION;
    static constexpr uint32_t SEGWIT_ACTIVATION_VERSION = SHARECHAIN_SEGWIT_ACTIVATION_VERSION;
    static constexpr uint32_t BLOCK_MAX_SIZE            = SHARECHAIN_BLOCK_MAX_SIZE;
    // RDTS reduced-data weight cap (800000 WU) while active, until the
    // 2027-09-01 MTP gate — from params.hpp RDTS_MAX_BLOCK_WEIGHT.
    static constexpr uint32_t BLOCK_MAX_WEIGHT          = RDTS_MAX_BLOCK_WEIGHT;

    // Mainnet sharechain cadence.
    static constexpr uint32_t SHARE_PERIOD              = SHARECHAIN_SHARE_PERIOD;   // seconds
    static constexpr uint32_t CHAIN_LENGTH              = SHARECHAIN_CHAIN_LENGTH;
    static constexpr uint32_t REAL_CHAIN_LENGTH         = SHARECHAIN_CHAIN_LENGTH;

    // DUST_THRESHOLD: minimum payout per share output — Bitcoin relay dust floor
    // (546 sat for a P2PKH output), unchanged by BIP-110. Testnet mirrors mainnet.
    static constexpr uint64_t DUST_THRESHOLD            = SHARECHAIN_DUST_THRESHOLD;  // satoshis
    static constexpr uint64_t TESTNET_DUST_THRESHOLD    = SHARECHAIN_DUST_THRESHOLD;
    static uint64_t dust_threshold() { return is_testnet ? TESTNET_DUST_THRESHOLD : DUST_THRESHOLD; }

    // Testnet constants — BIP-110 testnet mirrors mainnet cadence for now
    // (adjust in a testnet-bring-up phase). Values still flow from the SSOT.
    static constexpr uint32_t TESTNET_SHARE_PERIOD      = SHARECHAIN_SHARE_PERIOD;
    static constexpr uint32_t TESTNET_CHAIN_LENGTH      = SHARECHAIN_CHAIN_LENGTH;
    static constexpr uint32_t TESTNET_REAL_CHAIN_LENGTH  = SHARECHAIN_CHAIN_LENGTH;

    // Runtime testnet flag — set once at startup
    static inline bool is_testnet = false;

    // Accessors that return correct value for current network
    static uint32_t share_period()      { return is_testnet ? TESTNET_SHARE_PERIOD : SHARE_PERIOD; }
    static uint32_t chain_length()      { return is_testnet ? TESTNET_CHAIN_LENGTH : CHAIN_LENGTH; }
    static uint32_t real_chain_length()  { return is_testnet ? TESTNET_REAL_CHAIN_LENGTH : REAL_CHAIN_LENGTH; }

    // MAX_TARGET: share difficulty floor (easiest allowed share PoW). Bitcoin
    // powLimit 00000000ffff0000... is unchanged by BIP-110 (CheckProofOfWorkImpl
    // is untouched); the share floor sits at that limit. From the SSOT hex.
    static uint256 max_target()
    {
        static const uint256 MAINNET_MAX = [] {
            uint256 t;
            t.SetHex(SHARECHAIN_MAX_TARGET_HEX);
            return t;
        }();
        static const uint256 TESTNET_MAX = [] {
            uint256 t;
            t.SetHex(SHARECHAIN_MAX_TARGET_HEX);
            return t;
        }();
        return is_testnet ? TESTNET_MAX : MAINNET_MAX;
    }

    // -----------------------------------------------------------------------
    // Donation script — DEPLOY-CONFIG-DRIVEN, never a hardcoded money address in
    // source. Returns EMPTY here, matching params.hpp's donation_script_func: the
    // KAT/bring-up lane does not mint, and the deploy config supplies the payout
    // address at runtime (the BIP-110 lane's bech32 destination is provisioned by
    // the operator, NEVER a cross-coin address baked into the binary). This is the
    // per-coin-isolation rule: a source-hardcoded cross-coin donation would ship
    // one lane's money bytes into another.
    // -----------------------------------------------------------------------
    static std::vector<unsigned char> get_donation_script(int64_t /*share_version*/)
    {
        return {};
    }

    // Message framing prefix — BIP-110-native (SSOT: params.hpp SHARECHAIN_PREFIX_HEX).
    static inline const std::string DEFAULT_PREFIX_HEX          = SHARECHAIN_PREFIX_HEX;
    // Testnet mirrors mainnet (params testnet identity == mainnet).
    static inline const std::string TESTNET_PREFIX_HEX          = SHARECHAIN_PREFIX_HEX;
    // Network identifier — BIP-110-native (SSOT: params.hpp SHARECHAIN_IDENTIFIER_HEX).
    static inline const std::string DEFAULT_IDENTIFIER_HEX      = SHARECHAIN_IDENTIFIER_HEX;
    // Testnet mirrors mainnet.
    static inline const std::string TESTNET_IDENTIFIER_HEX      = SHARECHAIN_IDENTIFIER_HEX;

    // Private chain overrides — set once at startup via --network-id
    static inline std::string override_identifier_hex;
    static inline std::string override_prefix_hex;

    /// Set private network identity. IDENTIFIER and PREFIX are TWO INDEPENDENT
    /// per-network constants (p2pool model) — there is NO algebraic relationship
    /// between them, so PREFIX is never derived from IDENTIFIER. To join a custom
    /// p2pool sharechain, supply BOTH the network id and its prefix (each a
    /// separate per-network constant). If the prefix override is omitted, the
    /// compiled network-default prefix is used. Call once at startup before any
    /// P2P or share operations.
    static void set_network_id(const std::string& network_id_hex,
                               const std::string& prefix_hex_override = "") {
        if (network_id_hex.empty() || network_id_hex == "0" || network_id_hex == "00000000")
            return;  // public network, use defaults

        // Normalize a hex string to exactly 16 hex chars (8 bytes).
        auto to8 = [](std::string h) {
            while (h.size() < 16) h = "0" + h;
            if (h.size() > 16) h = h.substr(0, 16);
            return h;
        };

        override_identifier_hex = to8(network_id_hex);

        // PREFIX is an INDEPENDENT transport constant — set it directly from the
        // override and NEVER derive it from IDENTIFIER. The old XOR-rotate
        // derivation has no p2pool analog and structurally prevented c2pool from
        // joining any p2pool custom network (derived prefix != p2pool prefix).
        // When no prefix override is given, leave override_prefix_hex empty so
        // prefix_hex() falls back to the compiled network default.
        if (!prefix_hex_override.empty())
            override_prefix_hex = to8(prefix_hex_override);
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

        auto pfx_bytes = ParseHex(prefix_hex());
        auto id_bytes = ParseHex(identifier_hex());
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

    // Softforks the BIP-110 chain requires. segwit stays active; blake2b is the
    // BIP-110 activation (the pool MUST request the "blake2b" GBT rule against a
    // Knots 29.4.1 backend). Matches params.hpp p.softforks_required.
    static inline const std::set<std::string> SOFTFORKS_REQUIRED = {
        "segwit", "blake2b"
    };

    // Default bootstrap peers — EMPTY. BIP-110 is a fresh sharechain; nodes come
    // online via peer discovery (NODE-flagged coin-P2P + explicit --sharechain-
    // addnode). We deliberately ship NO seed hosts here: the live BTC p2pool seed
    // list (p2p-spb.xyz etc., port 9333) belongs to the BTC lane and must never
    // be dialed from BIP-110 (prefix mismatch → handshake refusal + addr-book
    // poisoning). Populate as BIP-110 c2pool nodes are provisioned.
    static inline const std::vector<std::string> DEFAULT_BOOTSTRAP_HOSTS = {};

    // -----------------------------------------------------------------------
    // Runtime config loaded from pool.yaml
    // -----------------------------------------------------------------------
    std::vector<std::byte> m_prefix;
    std::string m_worker;
    std::vector<NetService> m_bootstrap_addrs;
};

// ---------------------------------------------------------------------------
// Sharechain bootstrap-source selection (pure, testable seam)
//
// main_bip110 must decide which sharechain (pool P2P) peers to bootstrap from.
// The ELSE branch loads the PUBLIC seed list (DEFAULT_BOOTSTRAP_HOSTS — empty
// for BIP-110) only when NO custom --network-id/--prefix federation identity is
// set; a federation node must never dial the open network it cannot handshake
// (prefix mismatch → read_prefix disconnect), which would poison its addr book.
// This resolver makes the precedence explicit and unit-testable. Defaults (no
// custom id, no explicit peers) → PublicDefault.
// ---------------------------------------------------------------------------
enum class SharechainBootstrapMode {
    ExplicitPeers,        // --sharechain-addnode/--p2pool given: dial ONLY those
    RegtestIsolated,      // --regtest: 0 seeds, solo/local
    CustomNetSuppressed,  // custom --network-id, no explicit peers: 0 public seeds
    PublicDefault,        // public net, no explicit peers: DEFAULT_BOOTSTRAP_HOSTS
};

// Precedence: explicit peers > regtest > custom-network-id > public default.
inline SharechainBootstrapMode select_sharechain_bootstrap_mode(
    bool has_explicit_peers, bool regtest, bool has_custom_network_id)
{
    if (has_explicit_peers)   return SharechainBootstrapMode::ExplicitPeers;
    if (regtest)              return SharechainBootstrapMode::RegtestIsolated;
    if (has_custom_network_id) return SharechainBootstrapMode::CustomNetSuppressed;
    return SharechainBootstrapMode::PublicDefault;
}

} // namespace bip110
