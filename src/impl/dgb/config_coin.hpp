#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>

#include <cstdint>
#include <algorithm>

namespace dgb
{
namespace config
{
    // Reuse P2P/RPC data structures from LTC (identical format)
    struct P2PData
    {
        std::vector<std::byte> prefix;
        NetService address;
    };

    struct RPCData
    {
        NetService address;
        std::string userpass;
    };

} // config

/// DigiByte Scrypt coin parameters.
/// Source: p2pool-merged-v36/p2pool/bitcoin/networks/digibyte.py
///
/// DGB uses 5 algorithms rotating every 15 seconds. Scrypt is one of them.
/// When running as a P2Pool parent chain, we request getblocktemplate with
/// rules=["scrypt"] to only get Scrypt-eligible block templates.
class CoinParams
{
public:
    // -----------------------------------------------------------------------
    // Network constants
    // -----------------------------------------------------------------------

    // P2P magic bytes
    static constexpr uint8_t MAINNET_MAGIC[4]  = {0xfa, 0xc3, 0xb6, 0xda};
    static constexpr uint8_t TESTNET_MAGIC[4]  = {0xfd, 0xc8, 0xbd, 0xdd};

    // Default ports
    static constexpr uint16_t MAINNET_P2P_PORT = 12024;
    static constexpr uint16_t TESTNET_P2P_PORT = 12026;
    static constexpr uint16_t MAINNET_RPC_PORT = 14024;
    static constexpr uint16_t TESTNET_RPC_PORT = 14025;

    // Block timing: 75s total / 5 algos = 15s per algo
    static constexpr uint32_t BLOCK_PERIOD     = 15;   // seconds (Scrypt algo rotation)

    // -----------------------------------------------------------------------
    // Address encoding
    // -----------------------------------------------------------------------
    static constexpr uint8_t  ADDRESS_VERSION        = 0x1e;  // 30 — D prefix (P2PKH)
    static constexpr uint8_t  ADDRESS_P2SH_VERSION   = 0x3f;  // 63 — S prefix (P2SH)
    static constexpr uint8_t  TESTNET_ADDRESS_VERSION = 0x7e; // 126 (testnet)
    static constexpr uint8_t  TESTNET_P2SH_VERSION   = 0x8c;  // 140 (testnet P2SH)

    // Bech32 human-readable parts
    static constexpr const char* BECH32_HRP          = "dgb";
    static constexpr const char* TESTNET_BECH32_HRP  = "dgbt";

    // -----------------------------------------------------------------------
    // Scrypt PoW (identical to LTC)
    // -----------------------------------------------------------------------
    static constexpr uint32_t DUMB_SCRYPT_DIFF = 65536;  // 2^16

    // -----------------------------------------------------------------------
    // DGB subsidy schedule (3-phase decay)
    // Source: p2pool-merged-v36/p2pool/bitcoin/networks/digibyte.py
    // -----------------------------------------------------------------------
    static uint64_t subsidy(uint32_t height)
    {
        static constexpr uint64_t COIN = 100'000'000;  // 1 DGB = 10^8 satoshis

        // Phase 1: Pre-DigiShield fixed rewards
        if (height < 1440)       return 72'000 * COIN;
        if (height < 5760)       return 16'000 * COIN;
        if (height < 67'200)     return  8'000 * COIN;

        // Phase 2: -0.5% decay every 10,080 blocks
        if (height < 400'000) {
            uint64_t base = 8'000 * COIN;
            uint32_t periods = (height - 67'200) / 10'080;
            // Apply 0.995^periods via integer math
            for (uint32_t i = 0; i < periods && base > COIN; ++i)
                base = base * 995 / 1000;
            return std::max(base, COIN);
        }

        // Phase 3: -1% decay every 80,160 blocks
        uint64_t base = 2'459 * COIN;
        uint32_t periods = (height - 400'000) / 80'160;
        for (uint32_t i = 0; i < periods && base > COIN; ++i)
            base = base * 99 / 100;
        return std::max(base, COIN);
    }

    // GBT_ALGO: multi-algo coin requires specifying which algorithm
    // This is passed as a rule to getblocktemplate
    static constexpr const char* GBT_ALGO = "scrypt";
};

class CoinConfig : protected core::Fileconfig
{
protected:
    std::ofstream& get_default(std::ofstream& file) override;
    void load() override;

public:
    CoinConfig(const std::filesystem::path& path) : core::Fileconfig(path) {}

    config::P2PData m_p2p;
    config::RPCData m_rpc;

    std::string m_symbol = "DGB";
    int m_share_period{};
    bool m_testnet{false};
};

} // namespace dgb
