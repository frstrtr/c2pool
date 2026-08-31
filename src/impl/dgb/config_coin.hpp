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
    // DGB block subsidy -- EXACT port of DigiByte Core consensus
    // GetBlockSubsidy(nHeight, consensusParams) (src/validation.cpp), the
    // authoritative supply curve every DGB mainnet node validates against.
    // Ground truth is DigiByte Core, NOT the p2pool-dgb-scrypt display oracle:
    // that oracle's get_subsidy() carried COIN=1e6 and never built a coinbase
    // in python p2pool (the real value came from digibyted's GBT
    // coinbasevalue), so its 1e6 unit was a display artifact. This module,
    // however, feeds the LIVE daemonless coinbase-build path
    // (embedded_coinbase_value.hpp), where the returned value is written raw as
    // the coinbase vout in satoshis. At COIN=1e6 that underpaid the real reward
    // ~100x (built 2.53558070 DGB vs the on-chain 253.55810338 DGB at the live
    // Scrypt tip ~24.12M), which reverses the earlier card #156 "oracle IS the
    // spec" ruling: for a real coinbase the spec is DigiByte Core, and COIN is
    // 1e8 (src/consensus/amount.h). A naive x100 rescale is NOT parity -- the
    // 1e6 decay loop truncates coarser and lands thousands of sats off; the
    // decay must run at full 1e8 precision, which this port does.
    //
    // Mainnet consensus constants (src/kernel/chainparams.cpp) match DGB Core
    // exactly. Integer math mirrors Core bit-for-bit: each decay step is
    //   nSubsidy -= nSubsidy / N   (truncating division), and the Period VI
    // months count is blocks * BLOCK_TIME_SECONDS / SECONDS_PER_MONTH with
    // BLOCK_TIME_SECONDS=15 and SECONDS_PER_MONTH=60*60*24*365/12=2'628'000.
    // Floor: DigiByte Core clamps a sub-1-DGB reward to 0. This was verified
    // byte-for-byte against the released consensus (feature/8.22.0-final) and
    // the latest release (v9.26.5): both run `if (nSubsidy < COIN) nSubsidy = 0;`
    // -- the "Make sure the reward is at least 1 DGB" comment above it in Core is
    // stale, the code writes 0, not COIN. Core accepts underpay (ConnectBlock
    // rejects only overpay, "bad-cb-amount") and the floor is ~40 years out, so
    // it never bites at the live tip -- but the port mirrors Core exactly anyway.
    // -----------------------------------------------------------------------
    static uint64_t subsidy(uint32_t height)
    {
        static constexpr uint64_t COIN                         = 100'000'000; // DGB Core COIN = 1e8
        static constexpr uint32_t nDiffChangeTarget            = 67'200;
        static constexpr uint32_t alwaysUpdateDiffChangeTarget = 400'000;
        static constexpr uint32_t patchBlockRewardDuration     = 10'080;
        static constexpr uint32_t workComputationChangeTarget  = 1'430'000;
        static constexpr uint32_t patchBlockRewardDuration2    = 80'160;
        static constexpr uint64_t BLOCK_TIME_SECONDS           = 15;
        static constexpr uint64_t SECONDS_PER_MONTH            = 60ull * 60 * 24 * 365 / 12; // 2'628'000

        uint64_t nSubsidy = COIN;
        if (height < nDiffChangeTarget) {
            // Periods I-III: pre-DigiShield fixed rewards.
            if (height < 1'440)
                nSubsidy = 72'000 * COIN;
            else if (height < 5'760)
                nSubsidy = 16'000 * COIN;
            else
                nSubsidy = 8'000 * COIN;
        } else if (height < alwaysUpdateDiffChangeTarget) {
            // Period IV: -0.5% per week, weeks = blocks / 10080 + 1.
            nSubsidy = 8'000 * COIN;
            uint32_t blocks = height - nDiffChangeTarget;
            uint32_t weeks = (blocks / patchBlockRewardDuration) + 1;
            for (uint32_t i = 0; i < weeks; ++i)
                nSubsidy -= nSubsidy / 200;
        } else if (height < workComputationChangeTarget) {
            // Period V: -1% per period, weeks = blocks / 80160 + 1.
            nSubsidy = 2'459 * COIN;
            uint32_t blocks = height - alwaysUpdateDiffChangeTarget;
            uint32_t weeks = (blocks / patchBlockRewardDuration2) + 1;
            for (uint32_t i = 0; i < weeks; ++i)
                nSubsidy -= nSubsidy / 100;
        } else {
            // Period VI: monthly decay (x98884/100000) after the DigiSpeed
            // work-computation-change hard fork at block 1'430'000.
            nSubsidy = 2'157 * COIN / 2;
            uint64_t blocks = static_cast<uint64_t>(height) - workComputationChangeTarget;
            uint64_t months = blocks * BLOCK_TIME_SECONDS / SECONDS_PER_MONTH;
            for (uint64_t i = 0; i < months; ++i) {
                nSubsidy *= 98'884;
                nSubsidy /= 100'000;
            }
        }
        // DigiByte Core clamps a sub-1-DGB reward to 0 -- verified identical in
        // the released 8.22.0-final consensus and in v9.26.5 (the Core comment
        // says "at least 1 DGB" but the code assigns 0). Moot at the tip: the
        // floor is ~40 years out.
        if (nSubsidy < COIN)
            nSubsidy = 0;
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