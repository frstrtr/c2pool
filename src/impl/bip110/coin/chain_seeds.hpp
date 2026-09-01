// SPDX-License-Identifier: AGPL-3.0-or-later
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

namespace bip110 {
namespace coin {

/// DNS seeds for the BIP-110 (BLAKE2b) hard-fork chain — port 8333 (shares
/// Bitcoin mainnet's network identity: magic f9beb4d9, default port 8333).
/// Source: Knots kernel/chainparams.cpp:163-164 — both seeds support
/// service-bit-filtered subdomains ("x10000009." = NODE_NETWORK|NODE_WITNESS|
/// NODE_BLAKE2B), so the resolver returns ONLY fork peers. The trailing dot
/// skips the local resolv.conf search list.
inline std::vector<c2pool::dns::DnsSeed> btc_mainnet_dns_seeds()
{
    return {
        {"x10000009.dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us.", 8333},
        {"x10000009.seed.bitcoin.haf.ovh.",                        8333},
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

/// Hardcoded fallback peers for the BIP-110 fork — known-good live NODE_BLAKE2B
/// nodes (reachable from legion64). Two listen on 9333, so the peer manager's
/// valid_ports MUST include {8333, 9333} or those two are silently dropped.
/// A non-fork peer that slips through is rejected at the version handshake
/// (p2p_node.hpp NODE_BLAKE2B gate) and the failover dialer walks on.
inline std::vector<NetService> btc_mainnet_fixed_seeds()
{
    return {
        {"188.155.220.143", 9333},
        {"82.4.216.186",    8333},
        {"82.64.179.13",    9333},
        {"24.87.106.85",    8333},
        {"206.172.109.226", 8333},
        {"97.95.4.197",     8333},
        {"101.100.139.249", 8333},
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
} // namespace bip110