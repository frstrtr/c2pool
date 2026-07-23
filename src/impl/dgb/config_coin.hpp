// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>

#include <yaml-cpp/yaml.h>
#include <btclibs/util/strencodings.h>

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
} // namespace dgb

namespace YAML
{
template<> struct convert<dgb::config::P2PData>
{
    static Node encode(const dgb::config::P2PData& rhs)
    {
        Node node;
        node["prefix"] = HexStr(rhs.prefix);
        node["address"] = rhs.address;
        return node;
    }

    static bool decode(const Node& node, dgb::config::P2PData& rhs)
    {
        rhs.prefix = ParseHexBytes(node["prefix"].as<std::string>());
        rhs.address = node["address"].as<NetService>();
        return true;
    }
};

template<> struct convert<dgb::config::RPCData>
{
    static Node encode(const dgb::config::RPCData& rhs)
    {
        Node node;
        node["address"] = rhs.address;
        node["userpass"] = rhs.userpass;
        return node;
    }

    static bool decode(const Node& node, dgb::config::RPCData& rhs)
    {
        rhs.address = node["address"].as<NetService>();
        rhs.userpass = node["userpass"].as<std::string>();
        return true;
    }
};
}

namespace dgb
{

/// DigiByte Scrypt coin parameters.
/// Source of truth: p2pool-dgb-scrypt oracle bitcoin/networks/digibyte.py
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

    // Block timing: Scrypt-only parent block period (oracle PARENT.BLOCK_PERIOD).
    // DGB mints a block ~every 15s across 5 rotating algos; one algo (Scrypt)
    // lands ~every 75s, which is the period a Scrypt-only parent observes.
    static constexpr uint32_t BLOCK_PERIOD     = 75;   // seconds (Scrypt algo period)

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
    // DGB subsidy schedule -- EXACT replica of the p2pool-dgb-scrypt oracle
    // get_subsidy() (bitcoin/networks/digibyte.py, IDENTIFIER 4B62545B1A631AFE).
    // V36 conformance = parity with DGB's OWN canonical reference, so the
    // oracle behaviour IS the spec -- including COIN=1e6 (NOT 1e8) and the
    // weeks/months + 1 decay count. These are not quirks to "fix" (card #156).
    // 3-bucket: COMPAT (pre-v36 per-coin baseline, temporary for the crossing;
    // NOT a v36-native cross-coin standardization).
    //
    // Integer math mirrors the oracle bit-for-bit: each decay step is
    //   q -= q / N   (truncating division), NOT q * (N-1) / N -- the two round
    // differently for non-divisible q, and the oracle rounding is consensus.
    // -----------------------------------------------------------------------
    static uint64_t subsidy(uint32_t height)
    {
        static constexpr uint64_t COIN                         = 1'000'000;   // oracle COIN = 1e6
        static constexpr uint32_t nDiffChangeTarget            = 67'200;
        static constexpr uint32_t alwaysUpdateDiffChangeTarget = 400'000;
        static constexpr uint32_t patchBlockRewardDuration     = 10'080;
        static constexpr uint32_t workComputationChangeTarget  = 1'430'000;
        static constexpr uint32_t patchBlockRewardDuration2    = 80'160;

        uint64_t nSubsidy = COIN;
        if (height < nDiffChangeTarget) {
            // Phase 1: pre-DigiShield fixed rewards.
            nSubsidy = 8'000 * COIN;
            if (height < 1'440)
                nSubsidy = 72'000 * COIN;
            else if (height < 5'760)
                nSubsidy = 16'000 * COIN;
        } else if (height < alwaysUpdateDiffChangeTarget) {
            // Phase 2: -0.5% per (weeks+1), weeks = blocks / 10080.
            uint64_t qSubsidy = 8'000 * COIN;
            uint32_t blocks = height - nDiffChangeTarget;
            uint32_t weeks = (blocks / patchBlockRewardDuration) + 1;
            for (uint32_t i = 0; i < weeks; ++i)
                qSubsidy -= qSubsidy / 200;
            nSubsidy = qSubsidy;
        } else if (height < workComputationChangeTarget) {
            // Phase 3: -1% per (weeks+1), weeks = blocks / 80160.
            uint64_t qSubsidy = 2'459 * COIN;
            uint32_t blocks = height - alwaysUpdateDiffChangeTarget;
            uint32_t weeks = (blocks / patchBlockRewardDuration2) + 1;
            for (uint32_t i = 0; i < weeks; ++i)
                qSubsidy -= qSubsidy / 100;
            nSubsidy = qSubsidy;
        } else {
            // Phase 4: monthly decay (x98884/100000) after work-computation change.
            uint64_t qSubsidy = 2'157 * COIN / 2;
            uint32_t blocks = height - workComputationChangeTarget;
            uint32_t months = static_cast<uint32_t>(
                static_cast<uint64_t>(blocks) * 15 / (3600 * 24 * 365 / 12));
            for (uint32_t i = 0; i < months; ++i) {
                qSubsidy *= 98'884;
                qSubsidy /= 100'000;
            }
            nSubsidy = qSubsidy;
        }
        if (nSubsidy < COIN)
            nSubsidy = COIN;
        return nSubsidy;
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

    // Dev-only boot aid — DO NOT set on any real network. When true, relaxes the
    // DGB algo softfork readiness gate (reservealgo/odo/nversionbips) on
    // non-regtest, non-main chains so c2pool-dgb can boot against an isolated
    // tuned testnet for development. Off by default and absent from the
    // auto-written default config, so a real crossing-soak cannot silently inherit
    // it; never weakens the gate on mainnet. See
    // dgb::coin::compute_required_softforks / NodeRPC::check().
    bool m_dev_relax_algo_softforks{false};
};

} // namespace dgb