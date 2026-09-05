// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>
#include <core/version_gate.hpp>   // SSOT: core::version_gate::is_v36_active (V36 donation-transition boundary)

#include <array>
#include <cstdint>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace dgb
{

/// DigiByte Scrypt P2Pool network configuration.
/// Source of truth: the p2pool-dgb-scrypt oracle network (operator ruling
/// 2026-06-17, "switch-oracle" / Option B). The V36-master byte-compat
/// constraint with p2pool-merged-v36 is FORMALLY WAIVED for DGB by that ruling.
class PoolConfig : protected core::Fileconfig
{
protected:
    std::ofstream& get_default(std::ofstream& file) override;
    void load() override;

public:
    PoolConfig(const std::filesystem::path& path) : core::Fileconfig(path) {}

    // -----------------------------------------------------------------------
    // Static DGB Scrypt p2pool network constants
    // Source of truth: p2pool-dgb-scrypt oracle networks/digibyte.py
    // -----------------------------------------------------------------------
    static constexpr uint16_t P2P_PORT                  = 5024;
    static constexpr uint32_t SPREAD                    = 24;
    static constexpr uint32_t TARGET_LOOKBEHIND         = 100;
    // Inbound P2P accept-floor. Oracle p2pool-dgb-scrypt networks/digibyte.py sets NO
    // MINIMUM_PROTOCOL_VERSION, so the cold handshake floor is the p2p.py:153 getattr
    // fallback = 1400. (Prior 1700 + "NEW_MIN" sourcing was fabricated -- digibyte.py
    // has no such field, and 1700 bound neither oracle anchor.)
    static constexpr uint32_t MINIMUM_PROTOCOL_VERSION    = 1400;  // oracle p2p.py:153 getattr fallback (cold)
    // Ratchet TARGET (oracle data.py:81 BaseShare.MINIMUM_PROTOCOL_VERSION): the runtime
    // floor lifts 1400->3500 once counts[share.VERSION] >= 95% of the window
    // (update_min_protocol_version, data.py:857). The runtime 95%-ratchet wiring is the
    // step-2 follow-up PR; this constant documents the target value.
    static constexpr uint32_t SHARE_MINIMUM_PROTOCOL_VERSION = 3500;
    static constexpr uint32_t ADVERTISED_PROTOCOL_VERSION = 3501;  // advertised P2P protocol capability == oracle frstrtr/p2pool-dgb-scrypt p2p.py:28 Protocol.VERSION
    static constexpr uint32_t SEGWIT_ACTIVATION_VERSION = 35;     // canonical oracle p2pool-dgb-scrypt digibyte.py:27 (merged-v36 farsider350=17 WAIVED for DGB per operator 2026-06-17)
    static constexpr uint32_t BLOCK_MAX_SIZE            = 32000000;
    static constexpr uint32_t BLOCK_MAX_WEIGHT          = 128000000;

    // Mainnet constants
    static constexpr uint32_t SHARE_PERIOD              = 15;      // seconds (oracle SHARE_PERIOD)
    static constexpr uint32_t CHAIN_LENGTH              = 2880;    // 12*60*60//15 — ~12h at 15s
    static constexpr uint32_t REAL_CHAIN_LENGTH         = 2880;

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
    //   pre-V36 : original P2Pool DONATION_SCRIPT (P2PK, author forrestv)
    //   V36+    : COMBINED P2SH 1-of-2 (forrestv + maintainer)
    // get_donation_script(version) selects per share version. Source of truth:
    // p2pool-dgb-scrypt oracle (operator ruling 2026-06-17, "switch-oracle").
    // This REVERSES the 2026-06-16 farsider350 2-of-3 P2MS overrule for DGB; the
    // oracle inherits the global forrestv P2PK v35 donation (byte-identical to LTC).
    // -----------------------------------------------------------------------

    // Pre-V36 DONATION_SCRIPT (P2PK: OP_PUSHBYTES_65 <uncompressed pubkey> OP_CHECKSIG)
    // Original P2Pool donation key (author forrestv); byte-identical to LTC/global.
    static constexpr std::array<uint8_t, 67> DONATION_SCRIPT = {
        0x41,                                   // OP_PUSHBYTES_65
        0x04, 0xff, 0xd0, 0x3d, 0xe4, 0x4a, 0x6e, 0x11,
        0xb9, 0x91, 0x7f, 0x3a, 0x29, 0xf9, 0x44, 0x32,
        0x83, 0xd9, 0x87, 0x1c, 0x9d, 0x74, 0x3e, 0xf3,
        0x0d, 0x5e, 0xdd, 0xcd, 0x37, 0x09, 0x4b, 0x64,
        0xd1, 0xb3, 0xd8, 0x09, 0x04, 0x96, 0xb5, 0x32,
        0x56, 0x78, 0x6b, 0xf5, 0xc8, 0x29, 0x32, 0xec,
        0x23, 0xc3, 0xb7, 0x4d, 0x9f, 0x05, 0xa6, 0xf9,
        0x5a, 0x8b, 0x55, 0x29, 0x35, 0x26, 0x56, 0x66,
        0x4b,
        0xac                                    // OP_CHECKSIG
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
        if (core::version_gate::is_v36_active(share_version))
            return {COMBINED_DONATION_SCRIPT.begin(), COMBINED_DONATION_SCRIPT.end()};
        return {DONATION_SCRIPT.begin(), DONATION_SCRIPT.end()};
    }

    // P2Pool network framing (p2pool-dgb-scrypt oracle; operator ruling 2026-06-17)
    static inline const std::string DEFAULT_PREFIX_HEX     = "1c0553f23ebfcffe";
    static inline const std::string TESTNET_PREFIX_HEX     = "1c0553f23ebfcffe";  // same for testnet
    static inline const std::string IDENTIFIER_HEX         = "4b62545b1a631afe";
    static inline const std::string TESTNET_IDENTIFIER_HEX = "4b62545b1a631afe";

    static const std::string& identifier_hex() {
        return is_testnet ? TESTNET_IDENTIFIER_HEX : IDENTIFIER_HEX;
    }

    static inline const std::set<std::string> SOFTFORKS_REQUIRED = {
        "nversionbips", "csv", "segwit", "reservealgo", "odo", "taproot"
    };

    // Bootstrap peers for the DGB Scrypt p2pool network.
    // 92.53.224.27 is the live kr1z1s DGB sharechain node (host p2p-spb.xyz,
    // web :5025), the anchor of the public DGB (scrypt) sharechain this lane
    // joins. Seeded at P2P_PORT (5024) by run_node / the bootstrap seam below
    // unless a host literal already carries an explicit ":port". Was empty on
    // master, so a public DGB node had 0 outbound sharechain seeds to dial and
    // never joined the chain. REWARD-SAFE: a transport address only -- PREFIX/
    // IDENTIFIER/P2P_PORT/proto/share/PPLNS/coinbase are untouched, so a node
    // JOINS the existing chain through the standard handshake; it cannot fork it.
    static inline const std::vector<std::string> DEFAULT_BOOTSTRAP_HOSTS = {
        "92.53.224.27",   // kr1z1s DGB scrypt sharechain (p2p-spb.xyz), :5024
    };

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
// FIX (contabo DGB revival, 2026-09-05): run_node (main_dgb.cpp) hand-builds
// dgb::Config WITHOUT the YAML load() that is the sole populator of
// m_bootstrap_addrs. On master DEFAULT_BOOTSTRAP_HOSTS was ALSO empty AND there
// was no --sharechain-addnode flag, so a public DGB node had 0 outbound
// sharechain seeds and never joined the kr1z1s DGB (scrypt) sharechain. This
// resolver + builder let run_node seed the addr store deterministically before
// the Node ctor reads it, WITHOUT a YAML file. Mirrors the BCH seam
// (src/impl/bch/config_pool.hpp select_sharechain_bootstrap_mode): DGB has no
// --network-id federation CLI either, so there is no custom-net precedence tier.
//
// REWARD-SAFE: this touches ONLY which transport addresses are dialed. PREFIX
// (1c0553f23ebfcffe), IDENTIFIER (4b62545b1a631afe), P2P_PORT (5024), protocol
// versions, share format, PPLNS and coinbase are UNCHANGED -- the node joins the
// existing kr1z1s DGB sharechain through the standard handshake; it cannot fork
// it.
// ---------------------------------------------------------------------------
enum class SharechainBootstrapMode {
    ExplicitPeers,    // --sharechain-addnode given: dial ONLY those peers
    RegtestIsolated,  // --regtest: 0 seeds (never dial public mainnet 5024 seeds)
    PublicDefault,    // public net, no explicit peers: DEFAULT_BOOTSTRAP_HOSTS
};

// Precedence: explicit peers > regtest > public default.
inline SharechainBootstrapMode select_sharechain_bootstrap_mode(
    bool has_explicit_peers, bool regtest)
{
    if (has_explicit_peers) return SharechainBootstrapMode::ExplicitPeers;
    if (regtest)            return SharechainBootstrapMode::RegtestIsolated;
    return SharechainBootstrapMode::PublicDefault;
}

// Pure builder: compute the sharechain bootstrap address list. No I/O, no
// config mutation -- the whole logic lives here so it is unit-testable without
// constructing a PoolConfig or touching the network.
//   ExplicitPeers   -> exactly `addnodes`, at the ports given.
//   RegtestIsolated -> empty (solo/local; a won share is never relayed to the
//                      public net).
//   PublicDefault   -> DEFAULT_BOOTSTRAP_HOSTS, each at P2P_PORT (5024) unless
//                      the host literal already carries an explicit ":port".
inline std::vector<NetService> build_sharechain_bootstrap(
    SharechainBootstrapMode mode,
    const std::vector<std::pair<std::string, uint16_t>>& addnodes)
{
    std::vector<NetService> out;
    switch (mode)
    {
    case SharechainBootstrapMode::ExplicitPeers:
        for (const auto& [host, port] : addnodes)
            out.emplace_back(host, port);
        break;
    case SharechainBootstrapMode::RegtestIsolated:
        break;  // empty by design
    case SharechainBootstrapMode::PublicDefault:
        for (const auto& host : PoolConfig::DEFAULT_BOOTSTRAP_HOSTS)
        {
            if (host.find(':') == std::string::npos)
                out.emplace_back(host, PoolConfig::P2P_PORT);
            else
                out.emplace_back(host);  // literal already HOST:PORT
        }
        break;
    }
    return out;
}

// Populate pool.m_bootstrap_addrs from the resolved mode (thin plumbing over the
// pure builder). Called by run_node BEFORE the Node ctor reads the vector.
inline void seed_sharechain_bootstrap(
    PoolConfig& pool,
    const std::vector<std::pair<std::string, uint16_t>>& addnodes,
    bool regtest)
{
    pool.m_bootstrap_addrs = build_sharechain_bootstrap(
        select_sharechain_bootstrap_mode(/*has_explicit_peers=*/!addnodes.empty(),
                                          /*regtest=*/regtest),
        addnodes);
}

} // namespace dgb