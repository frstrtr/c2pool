// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DNS seed hostnames and hardcoded fallback IPs for Litecoin P2P networks.
/// Sources: Litecoin Core chainparams.cpp + chainparamsseeds.h

#include <core/dns_seeder.hpp>
#include <core/netaddress.hpp>
#include <cstdint>
#include <vector>

namespace ltc {
namespace coin {

/// DNS seeds for Litecoin mainnet.
inline std::vector<c2pool::dns::DnsSeed> ltc_mainnet_dns_seeds()
{
    return {
        {"seed-a.litecoin.loshan.co.uk", 9333},
        {"dnsseed.thrasher.io",          9333},
        {"dnsseed.litecointools.com",    9333},
        {"dnsseed.litecoinpool.org",     9333},
        {"dnsseed.koin-project.com",     9333},
    };
}

/// DNS seeds for Litecoin testnet.
inline std::vector<c2pool::dns::DnsSeed> ltc_testnet_dns_seeds()
{
    return {
        {"testnet-seed.litecointools.com",   19335},
        {"seed-b.litecoin.loshan.co.uk",     19335},
        {"dnsseed-testnet.thrasher.io",      19335},
    };
}

/// Hardcoded fallback peers for Litecoin mainnet.
/// Used if DNS seeds fail after 60 seconds.
/// Sourced from Litecoin Core chainparamsseeds.h + well-known nodes.
inline std::vector<NetService> ltc_mainnet_fixed_seeds()
{
    return {
        // Well-known Litecoin nodes (representative sample)
        {"173.249.7.244",    9333},
        {"88.198.54.132",    9333},
        {"5.9.65.168",       9333},
        {"80.240.23.240",    9333},
        {"176.9.30.118",     9333},
        {"94.130.12.233",    9333},
        {"162.55.99.207",    9333},
        {"95.217.1.76",      9333},
        {"148.251.155.214",  9333},
        {"78.46.78.45",      9333},
    };
}

/// Hardcoded fallback peers for Litecoin testnet.
inline std::vector<NetService> ltc_testnet_fixed_seeds()
{
    return {
        // Standard testnet seeds
        {"178.128.221.177",  19335},
        {"206.189.2.17",     19335},
    };
}

/// Get DNS seeds for the appropriate LTC network.
inline std::vector<c2pool::dns::DnsSeed> ltc_dns_seeds(bool testnet)
{
    return testnet ? ltc_testnet_dns_seeds() : ltc_mainnet_dns_seeds();
}

/// Get fixed fallback seeds for the appropriate LTC network.
inline std::vector<NetService> ltc_fixed_seeds(bool testnet)
{
    return testnet ? ltc_testnet_fixed_seeds() : ltc_mainnet_fixed_seeds();
}

// ── Seed ladder (autosense) ──────────────────────────────────────────────
//
// Ordered fallback ladder for LTC (DOGE aux rides the same ladder) P2P peer
// discovery. The node autosenses its way DOWN the ladder: it stays on the
// highest-priority rung that yields >= min_peers within settle_ms, and only
// escalates to the next rung on starvation. This lets an embedded node
// cold-start with no operator-supplied addnodes while still preferring
// explicit / DNS discovery when those are healthy.
//
// Additive-only: composes the ltc_dns_seeds() / ltc_fixed_seeds() helpers
// above. No src/core change — the running node consumes this ladder through
// the existing DnsSeeder / fixed-seed paths.

enum class SeedRung {
    ConfiguredAddnodes = 0,  ///< operator --addnode / config (highest priority)
    DnsSeeds,                ///< ltc_dns_seeds()
    FixedFallback,           ///< ltc_fixed_seeds()
    EmbeddedBootstrap,       ///< own live-bootstrap seed host (starvation floor)
};

struct SeedLadderRung {
    SeedRung rung;
    uint32_t settle_ms;   ///< grace before autosensing starvation on this rung
    uint32_t min_peers;   ///< peer count below which we escalate to the next rung
};

/// Autosense escalation ladder for LTC. DNS gets a full 60s resolve+dial
/// window (matching the fixed-seed fallback note above) before we fall to the
/// hardcoded fixed seeds; the embedded bootstrap host is only ever a floor.
inline std::vector<SeedLadderRung> ltc_seed_ladder()
{
    return {
        {SeedRung::ConfiguredAddnodes,  5000, 1},
        {SeedRung::DnsSeeds,           60000, 3},
        {SeedRung::FixedFallback,      30000, 2},
        {SeedRung::EmbeddedBootstrap,      0, 1},  // floor: no further escalation
    };
}

/// Embedded live-bootstrap seed host for the EmbeddedBootstrap rung.
/// TODO(seed-ladder): wire the deterministic own-seed host from the
/// live-bootstrap CI gate (must be our own seed host, NOT public mainnet).
/// Returns empty until that gate host is pinned — the ladder degrades
/// gracefully to FixedFallback in the meantime.
inline std::vector<NetService> ltc_embedded_bootstrap_seeds(bool /*testnet*/)
{
    return {};
}

} // namespace coin
} // namespace ltc