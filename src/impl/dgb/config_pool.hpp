#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>
#include <core/version_gate.hpp>   // SSOT: core::version_gate::is_v36_active (V36 donation-transition boundary)

#include <array>
#include <cstdint>
#include <set>
#include <string>
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
