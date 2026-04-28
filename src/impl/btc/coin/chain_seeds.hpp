#pragma once

/// DNS seed hostnames and hardcoded fallback IPs for Bitcoin P2P networks.
/// Sources:
///   - mainnet/testnet3/testnet4 DNS seeds: ref/bitcoin/src/kernel/chainparams.cpp
///   - mainnet fixed seed sample: well-known long-running BTC nodes
///
/// Trailing dot on hostnames matches bitcoind's chainparams (skips the local
/// resolv.conf search list — important when the host's first search domain
/// shadows a public TLD).

#include <core/dns_seeder.hpp>
#include <core/netaddress.hpp>
#include <vector>

namespace btc {
namespace coin {

/// DNS seeds for Bitcoin mainnet (port 8333).
/// Source: ref/bitcoin/src/kernel/chainparams.cpp lines 136-143.
inline std::vector<c2pool::dns::DnsSeed> btc_mainnet_dns_seeds()
{
    return {
        {"seed.bitcoin.sipa.be",            8333},  // Pieter Wuille
        {"dnsseed.bluematt.me",             8333},  // Matt Corallo
        {"seed.bitcoin.jonasschnelli.ch",   8333},  // Jonas Schnelli
        {"seed.btc.petertodd.net",          8333},  // Peter Todd
        {"seed.bitcoin.sprovoost.nl",       8333},  // Sjors Provoost
        {"dnsseed.emzy.de",                 8333},  // Stephan Oeste
        {"seed.bitcoin.wiz.biz",            8333},  // Jason Maurice
        {"seed.mainnet.achownodes.xyz",     8333},  // Ava Chow
    };
}

/// DNS seeds for Bitcoin testnet3 (port 18333).
/// Source: ref/bitcoin/src/kernel/chainparams.cpp lines 252-256.
inline std::vector<c2pool::dns::DnsSeed> btc_testnet_dns_seeds()
{
    return {
        {"testnet-seed.bitcoin.jonasschnelli.ch", 18333},
        {"seed.tbtc.petertodd.net",               18333},
        {"seed.testnet.bitcoin.sprovoost.nl",     18333},
        {"testnet-seed.bluematt.me",              18333},
        {"seed.testnet.achownodes.xyz",           18333},
    };
}

/// DNS seeds for Bitcoin testnet4 (port 48333).
/// Source: ref/bitcoin/src/kernel/chainparams.cpp lines 360-361.
/// testnet4 is the preferred c2pool-btc B2 integration target — fast, fresh.
inline std::vector<c2pool::dns::DnsSeed> btc_testnet4_dns_seeds()
{
    return {
        {"seed.testnet4.bitcoin.sprovoost.nl",   48333},
        {"seed.testnet4.wiz.biz",                48333},
    };
}

/// Hardcoded fallback peers for Bitcoin mainnet (port 8333).
/// Used if DNS seeds fail after 60 seconds. Sample of well-known long-running
/// BTC nodes — replace with current top-uptime peers if these become stale.
inline std::vector<NetService> btc_mainnet_fixed_seeds()
{
    return {
        // Bitcoin Core developer + community-known stable nodes
        {"seed.bitcoin.sipa.be",          8333},
        {"dnsseed.bluematt.me",           8333},
        {"seed.bitcoin.sprovoost.nl",     8333},
        {"seed.bitcoin.jonasschnelli.ch", 8333},
    };
}

/// Hardcoded fallback peers for Bitcoin testnet3.
inline std::vector<NetService> btc_testnet_fixed_seeds()
{
    return {
        {"seed.testnet.bitcoin.sprovoost.nl",   18333},
        {"testnet-seed.bitcoin.jonasschnelli.ch", 18333},
    };
}

/// Hardcoded fallback peers for Bitcoin testnet4.
inline std::vector<NetService> btc_testnet4_fixed_seeds()
{
    return {
        {"seed.testnet4.bitcoin.sprovoost.nl",   48333},
        {"seed.testnet4.wiz.biz",                48333},
    };
}

/// Get DNS seeds for the appropriate BTC network.
/// (testnet currently routes to testnet3 — switch to testnet4 in B2 if it's
/// the integration target there.)
inline std::vector<c2pool::dns::DnsSeed> btc_dns_seeds(bool testnet)
{
    return testnet ? btc_testnet_dns_seeds() : btc_mainnet_dns_seeds();
}

/// Get fixed fallback seeds for the appropriate BTC network.
inline std::vector<NetService> btc_fixed_seeds(bool testnet)
{
    return testnet ? btc_testnet_fixed_seeds() : btc_mainnet_fixed_seeds();
}

} // namespace coin
} // namespace btc
