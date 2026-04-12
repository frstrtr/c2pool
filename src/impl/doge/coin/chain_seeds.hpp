#pragma once

/// DNS seed hostnames and hardcoded fallback IPs for Dogecoin P2P networks.
/// Sources: Dogecoin Core chainparams.cpp + chainparamsseeds.h

#include <core/dns_seeder.hpp>
#include <core/netaddress.hpp>
#include <vector>

namespace doge {
namespace coin {

/// DNS seeds for Dogecoin mainnet.
/// Note: multidoge.org and dogecoin.com seeds are dead as of 2026-04.
/// Kept for future recovery; fixed seeds below provide actual connectivity.
inline std::vector<c2pool::dns::DnsSeed> doge_mainnet_dns_seeds()
{
    return {
        {"seed.multidoge.org",        22556},
        {"seed2.multidoge.org",       22556},
        {"seed.doger.dogecoin.com",   22556},
        {"seed.dogecoin.com",         22556},
        {"seed.mophides.com",         22556},
        {"seed.dglibrary.org",        22556},
        {"seed.dogechain.info",       22556},
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
/// Updated 2026-04-12 from opreturn.net/dogecoin/node/ — all DNS seeds are dead.
inline std::vector<NetService> doge_mainnet_fixed_seeds()
{
    return {
        {"18.144.182.93",    22556},
        {"52.43.212.188",    22556},
        {"173.212.197.63",   22556},
        {"23.148.24.52",     22556},
        {"161.35.231.176",   22556},
        {"66.151.242.154",   22556},
        {"194.233.65.194",   22556},
        {"78.141.223.235",   22556},
        {"54.37.130.17",     22556},
        {"64.225.65.218",    22556},
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
