#pragma once

/// DNS seed hostnames and hardcoded fallback IPs for Litecoin P2P networks.
/// Sources: Litecoin Core chainparams.cpp + chainparamsseeds.h

#include <core/dns_seeder.hpp>
#include <core/netaddress.hpp>
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

} // namespace coin
} // namespace ltc
