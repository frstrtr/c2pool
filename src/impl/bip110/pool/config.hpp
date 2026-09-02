// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// bip110::pool::Config — the runtime config VIEW consumed by the namespace-copied
// sharechain NODE layer (node.hpp / node.cpp / protocol_actual.cpp).
//
// THE CONFIG SEAM (PR-A-cont2 design decision — option (a), a bip110-local
// runtime adapter that forwards to the static PoolConfig SSOT; ZERO shared edits):
//
// The BTC lane's config.hpp is `using Config = core::Config<PoolConfig,CoinConfig>`
// (src/impl/btc/config.hpp). `core::Config<Pool,Coin>` static_asserts BOTH template
// args are core::Fileconfig subclasses (src/core/config.hpp). bip110's PoolConfig
// (config_pool.hpp) is DELIBERATELY static-only and NOT a Fileconfig — that is the
// mechanism guaranteeing the empty-seed cross-pollution guard (decision card #2: no
// override_prefix_hex surface, no PublicDefault arm). Making it a Fileconfig to
// satisfy core::Config<> would re-introduce exactly the runtime override surface
// decision #2 forbids. And "consume the static accessors directly" is impossible
// without editing SHARED code: pool::BaseNode reads INSTANCE members off config_t*
// (`config->m_name`, `config->pool()->m_prefix`, src/pool/node.hpp), and BaseNode is
// shared → untouchable.
//
// The seam: pool::SharechainNode<ConfigType,...> takes ConfigType as a free type
// param, so this local Config only needs the exact member surface BaseNode + the
// copied NodeImpl read (m_name / m_regtest / m_testnet / pool()->m_prefix /
// pool()->m_bootstrap_addrs). Every value is derived from the static PoolConfig SSOT
// / params.hpp SHARECHAIN_* constants, so it can never drift. The compile-time
// constants node.cpp uses (P2P_PORT, ADVERTISED/MINIMUM_PROTOCOL_VERSION,
// chain_length(), share_period(), TARGET_LOOKBEHIND) stay direct calls on the static
// bip110::pool::PoolConfig — no adapter needed for those.
//
// The empty-seed ladder SURVIVES: m_bootstrap_addrs initializes EMPTY and
// PoolConfig::default_bootstrap_hosts() returns {} with no PublicDefault/btc-seed
// arm, so the node cannot dial 9333 / the live BTC sharechain.

#include "config_pool.hpp"          // static SSOT + params.hpp SHARECHAIN_*
#include <core/netaddress.hpp>
#include <btclibs/util/strencodings.h>   // ParseHexBytes

#include <string>
#include <vector>

namespace bip110::pool
{

// Runtime instance-member view that pool::BaseNode + the copied NodeImpl read off
// config_t*. Every value comes from the static PoolConfig SSOT / params.hpp, so it
// can never drift from the coin-params factory or the wire identity.
struct PoolConfigRuntime
{
    std::vector<std::byte>  m_prefix;           // = ParseHexBytes(SHARECHAIN_PREFIX_HEX)
    std::vector<NetService> m_bootstrap_addrs;  // EMPTY — empty-seed ladder (decision #2)

    PoolConfigRuntime()
    {
        m_prefix = ParseHexBytes(PoolConfig::prefix_hex());
        // m_bootstrap_addrs stays empty: no PublicDefault arm, no cross-lane seeds.
    }
};

struct Config
{
    std::string m_name{"bip110"};
    bool m_regtest{false};
    bool m_testnet{false};           // v36-genesis: single mainnet identity
    PoolConfigRuntime m_pool;

    PoolConfigRuntime* pool() { return &m_pool; }
    // No coin() — the copied node.hpp/node.cpp never call config->coin().
};

// The BTC lane keeps sharechain_net_name on CoinConfig (config_coin.hpp); bip110 has
// no CoinConfig, so provide the free function the copied node.hpp LevelDB-namespace
// isolation site calls. regtest FIRST (the .121-standup isolation invariant).
inline std::string sharechain_net_name(bool regtest, bool /*testnet*/)
{
    return regtest ? "bip110_regtest" : "bip110";
}

} // namespace bip110::pool
