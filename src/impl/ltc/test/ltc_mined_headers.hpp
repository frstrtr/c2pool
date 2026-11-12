// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// Test header chains that pass HeaderChain's checks: every header above the
// checkpoint has its scrypt PoW verified, whatever height a peer reports.
// Testnet parameters with the most permissive PoW limit (0x207fffff, about
// two scrypt tries per header) and a genesis at those bits: every header
// takes them (the difficulty rule's walk back ends at that genesis; a
// min-difficulty header takes the limit's own bits, the same).
// ---------------------------------------------------------------------------

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/coin/header_chain.hpp>

namespace ltc_test {

inline constexpr uint32_t kEasyBits = 0x207fffff;

/// Testnet's genesis at kEasyBits (genesis is not PoW-checked, only matched
/// against the parameters' genesis hash).
inline ltc::coin::BlockHeaderType easy_testnet_genesis()
{
    ltc::coin::BlockHeaderType g;
    g.m_version = 1;
    g.m_previous_block.SetNull();
    g.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    g.m_timestamp = 1486949366;
    g.m_bits = kEasyBits;
    g.m_nonce = 293345;
    return g;
}

inline ltc::coin::LTCChainParams easy_testnet_params()
{
    auto p = ltc::coin::make_ltc_chain_params_testnet();
    p.pow_limit.SetCompact(kEasyBits);
    p.genesis_hash = Hash(pack(easy_testnet_genesis()).get_span());
    return p;
}

/// The nonce that makes `h` pass the PoW check of `p` (from its own nonce up).
inline void mine(ltc::coin::BlockHeaderType& h, const ltc::coin::LTCChainParams& p = easy_testnet_params())
{
    while (!ltc::coin::check_pow(ltc::coin::pow_hash(h, p.pow_func), h.m_bits, p.pow_limit))
        ++h.m_nonce;
}

/// A nonce that makes `h` fail it.
inline void unmine(ltc::coin::BlockHeaderType& h, const ltc::coin::LTCChainParams& p = easy_testnet_params())
{
    while (ltc::coin::check_pow(ltc::coin::pow_hash(h, p.pow_func), h.m_bits, p.pow_limit))
        ++h.m_nonce;
}

} // namespace ltc_test
