// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DNS seed hostnames and hardcoded fallback IPs for Namecoin P2P networks.
/// Sources:
///   - DNS seeds: Namecoin Core chainparams.cpp (CMainParams::vSeeds).
///   - Fixed seeds: live reachable peers harvested from a synced mainnet
///     namecoind addrman (getnodeaddresses) on 2026-06-19, port 8334.
/// Mirrors src/impl/doge/coin/chain_seeds.hpp. Namecoin has a single
/// mainnet and a single testnet (no testnet4alpha variant).

#include <core/dns_seeder.hpp>
#include <core/netaddress.hpp>
#include <vector>

namespace nmc {
namespace coin {

/// DNS seeds for Namecoin mainnet (P2P port 8334).
/// From Namecoin Core chainparams.cpp. Several historical seeds are dead;
/// the fixed_seeds below (live-sourced) provide actual connectivity.
inline std::vector<c2pool::dns::DnsSeed> nmc_mainnet_dns_seeds()
{
    return {
        {"nmc.seed.quisquis.de",          8334},
        {"dnsseed.namecoin.webbtc.com",   8334},
        {"seed.nmc.markasoftware.com",    8334},
    };
}

/// DNS seeds for Namecoin testnet (P2P port 18334).
inline std::vector<c2pool::dns::DnsSeed> nmc_testnet_dns_seeds()
{
    return {
        {"dnsseed.test.namecoin.webbtc.com", 18334},
    };
}

/// Hardcoded fallback peers for Namecoin mainnet.
/// Harvested 2026-06-19 from a synced mainnet namecoind addrman, port 8334.
inline std::vector<NetService> nmc_mainnet_fixed_seeds()
{
    return {
        {"23.106.38.114",   8334},
        {"174.95.154.115",  8334},
        {"212.67.235.211",  8334},
        {"23.19.112.151",   8334},
        {"83.217.13.217",   8334},
        {"166.70.96.250",   8334},
        {"66.45.249.52",    8334},
    };
}

/// Hardcoded fallback peers for Namecoin testnet.
/// No public fixed peers wired -- connect via --nmc-p2p-address to a known
/// namecoind, consistent with the doge testnet stance.
inline std::vector<NetService> nmc_testnet_fixed_seeds()
{
    return {};
}

/// Get DNS seeds for the appropriate NMC network.
inline std::vector<c2pool::dns::DnsSeed> nmc_dns_seeds(bool testnet)
{
    return testnet ? nmc_testnet_dns_seeds() : nmc_mainnet_dns_seeds();
}

/// Get fixed fallback seeds for the appropriate NMC network.
inline std::vector<NetService> nmc_fixed_seeds(bool testnet)
{
    return testnet ? nmc_testnet_fixed_seeds() : nmc_mainnet_fixed_seeds();
}

} // namespace coin
} // namespace nmc