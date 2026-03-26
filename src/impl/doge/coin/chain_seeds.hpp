#pragma once

/// DNS seed hostnames and hardcoded fallback IPs for Dogecoin P2P networks.
/// Sources: Dogecoin Core chainparams.cpp + chainparamsseeds.h

#include <core/dns_seeder.hpp>
#include <core/netaddress.hpp>
#include <vector>

namespace doge {
namespace coin {

/// DNS seeds for Dogecoin mainnet.
inline std::vector<c2pool::dns::DnsSeed> doge_mainnet_dns_seeds()
{
    return {
        {"seed.multidoge.org",        22556},
        {"seed2.multidoge.org",       22556},
        {"seed.doger.dogecoin.com",   22556},
        {"seed.dogecoin.com",         22556},
    };
}

/// DNS seeds for Dogecoin testnet3 (legacy).
/// Same port as testnet4alpha (44556) — P2P magic prefix distinguishes networks.
inline std::vector<c2pool::dns::DnsSeed> doge_testnet_dns_seeds()
{
    return {
        {"testseed.jrn.me.uk",  44556},
    };
}

/// DNS seeds for Dogecoin testnet4alpha.
/// No public seeds — testnet4alpha is a custom network.
/// Use --doge-p2p-address to connect to a known dogecoind.
inline std::vector<c2pool::dns::DnsSeed> doge_testnet4alpha_dns_seeds()
{
    return {};
}

/// Hardcoded fallback peers for Dogecoin mainnet.
inline std::vector<NetService> doge_mainnet_fixed_seeds()
{
    return {
        {"54.77.237.193",    22556},
        {"52.31.196.188",    22556},
        {"54.207.26.89",     22556},
        {"95.217.1.76",      22556},
        {"178.128.221.177",  22556},
    };
}

/// Hardcoded fallback peers for Dogecoin testnet3 (legacy).
inline std::vector<NetService> doge_testnet_fixed_seeds()
{
    return {
        {"178.128.221.177",  44556},
    };
}

/// Hardcoded fallback peers for Dogecoin testnet4alpha.
/// No public peers — testnet4alpha is a custom network.
/// Use --doge-p2p-address to connect to a known dogecoind.
inline std::vector<NetService> doge_testnet4alpha_fixed_seeds()
{
    return {};
}

/// Get DNS seeds for the appropriate DOGE network.
inline std::vector<c2pool::dns::DnsSeed> doge_dns_seeds(bool testnet, bool testnet4alpha = false)
{
    if (testnet4alpha) return doge_testnet4alpha_dns_seeds();
    return testnet ? doge_testnet_dns_seeds() : doge_mainnet_dns_seeds();
}

/// Get fixed fallback seeds for the appropriate DOGE network.
inline std::vector<NetService> doge_fixed_seeds(bool testnet, bool testnet4alpha = false)
{
    if (testnet4alpha) return doge_testnet4alpha_fixed_seeds();
    return testnet ? doge_testnet_fixed_seeds() : doge_mainnet_fixed_seeds();
}

} // namespace coin
} // namespace doge
