// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DNS seed hostnames and hardcoded fallback IPs for Bitcoin Cash P2P networks.
/// Source: ref bitcoin-cash-node/src/chainparams.cpp (vSeeds.emplace_back +
/// nDefaultPort per CChainParams subclass).
///
/// BCH shares BTC default ports on mainnet (8333) and testnet3 (18333) by fork
/// inheritance, but the DNS seed hostnames are entirely BCH-operated and
/// disjoint from Bitcoin Core's. testnet4 (28333) and the ports above are the
/// BCHN-specific values, NOT the BTC testnet4 (48333) set in btc/coin/.
///
/// Trailing-dot convention from btc/coin/chain_seeds.hpp is intentionally NOT
/// applied here: BCHN chainparams stores the hostnames bare, and the BCH DNS
/// seeders are matched against bare names by the reference daemon.

#include <core/dns_seeder.hpp>
#include <core/netaddress.hpp>
#include <vector>

namespace bch {
namespace coin {

/// DNS seeds for Bitcoin Cash mainnet (port 8333).
/// Source: bitcoin-cash-node/src/chainparams.cpp lines 210-229.
inline std::vector<c2pool::dns::DnsSeed> bch_mainnet_dns_seeds()
{
    return {
        {"seed.flowee.cash",                    8333},
        {"seed-bch.bitcoinforks.org",           8333},
        {"btccash-seeder.bitcoinunlimited.info", 8333},
        {"seed.bchd.cash",                      8333},
        {"seed.bch.loping.net",                 8333},
        {"dnsseed.electroncash.de",             8333},
        {"bchseed.c3-soft.com",                 8333},
        {"bch.bitjson.com",                     8333},
    };
}

/// DNS seeds for Bitcoin Cash testnet3 (port 18333).
/// Source: bitcoin-cash-node/src/chainparams.cpp lines 467-471.
inline std::vector<c2pool::dns::DnsSeed> bch_testnet_dns_seeds()
{
    return {
        {"testnet-seed.bchd.cash",              18333},
        {"seed.tbch.loping.net",                18333},
        {"testnet-seed.bitcoinunlimited.info",  18333},
    };
}

/// DNS seeds for Bitcoin Cash testnet4 (port 28333).
/// Source: bitcoin-cash-node/src/chainparams.cpp lines 682-688.
/// testnet4 is the preferred c2pool-bch M3 integration target — small, fresh.
inline std::vector<c2pool::dns::DnsSeed> bch_testnet4_dns_seeds()
{
    return {
        {"testnet4-seed-bch.toom.im",           28333},
        {"seed.tbch4.loping.net",               28333},
        {"testnet4-seed.flowee.cash",           28333},
        {"testnet4.bitjson.com",                28333},
    };
}

/// Hardcoded fallback peers for Bitcoin Cash mainnet (port 8333).
/// Used if DNS seeds fail after 60 seconds. Sample of the BCHN-operated DNS
/// seed hosts themselves (long-running, dual DNS+node) — replace with current
/// top-uptime peers if these become stale.
inline std::vector<NetService> bch_mainnet_fixed_seeds()
{
    return {
        {"seed.flowee.cash",          8333},
        {"seed.bch.loping.net",       8333},
        {"seed.bchd.cash",            8333},
        {"bch.bitjson.com",           8333},
    };
}

/// Hardcoded fallback peers for Bitcoin Cash testnet3.
inline std::vector<NetService> bch_testnet_fixed_seeds()
{
    return {
        {"seed.tbch.loping.net",      18333},
        {"testnet-seed.bchd.cash",    18333},
    };
}

/// Hardcoded fallback peers for Bitcoin Cash testnet4.
inline std::vector<NetService> bch_testnet4_fixed_seeds()
{
    return {
        {"seed.tbch4.loping.net",     28333},
        {"testnet4.bitjson.com",      28333},
    };
}

/// Get DNS seeds for the appropriate BCH network.
/// (testnet currently routes to testnet3 — switch to bch_testnet4_dns_seeds()
/// in the M3 live-validation step if testnet4 is the integration target.)
inline std::vector<c2pool::dns::DnsSeed> bch_dns_seeds(bool testnet)
{
    return testnet ? bch_testnet_dns_seeds() : bch_mainnet_dns_seeds();
}

/// Get fixed fallback seeds for the appropriate BCH network.
inline std::vector<NetService> bch_fixed_seeds(bool testnet)
{
    return testnet ? bch_testnet_fixed_seeds() : bch_mainnet_fixed_seeds();
}

} // namespace coin
} // namespace bch