// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// v36 sharechain helpers for the v36 generation-transaction KATs (share_check.hpp
// generate_share_transaction / verify_payout_commitment on DashV36Share,
// share_producer.hpp build_share_v36, pplns_v36.hpp v36_pplns_window).
//
// The live dash::ShareType now holds DashV36Share (live-variant slice), so the
// former test-only variant/index/chain are ALIASES of the live types: every KAT
// that uses this fixture runs over the production chain type. Anonymous
// namespace per TU.

#include <impl/dash/share.hpp>
#include <impl/dash/share_chain.hpp>   // DashFormatter, ShareHasher
#include <sharechain/sharechain.hpp>

#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <chrono>
#include <cstdint>
#include <vector>

namespace {

using V36TestShareType = dash::ShareType;
using V36TestIndex = dash::ShareIndex;

struct V36TestChain : dash::ShareChain
{
};

inline uint256 v36_tag_hash(uint8_t tag, uint8_t salt = 0xa5)
{
    std::vector<unsigned char> v(32, 0x00);
    v[0] = tag; v[1] = salt; v[31] = 0x36;
    return uint256(v);
}

inline uint256 v36_index_hash(uint32_t i)
{
    std::vector<unsigned char> v(32, 0x00);
    v[0] = static_cast<unsigned char>(i & 0xff);
    v[1] = static_cast<unsigned char>((i >> 8) & 0xff);
    v[2] = static_cast<unsigned char>((i >> 16) & 0xff);
    v[30] = 0x36; v[31] = 0x99;
    return uint256(v);
}

// Back-linked chain of DashV36Shares (the SyntheticChain idiom of
// test_dash_share_producer.cpp, v36 share type).
struct SyntheticV36Chain
{
    V36TestChain chain;

    uint256 add_hash(const uint256& h, const uint256& prev, uint32_t bits, uint32_t max_bits,
                     uint32_t timestamp, const uint160& pkh, uint16_t donation = 0,
                     uint32_t absheight = 0, uint128 abswork = uint128())
    {
        auto* s = new dash::DashV36Share();
        s->m_hash            = h;
        s->m_prev_hash       = prev;
        s->m_bits            = bits;
        s->m_max_bits        = max_bits;
        s->m_timestamp       = timestamp;
        s->m_pubkey_hash     = pkh;
        s->m_pubkey_type     = 0;
        s->m_donation        = donation;
        s->m_desired_version = 36;
        s->m_absheight       = absheight;
        s->m_abswork         = abswork;
        chain.add(s);
        return h;
    }

    uint256 add(uint8_t tag, const uint256& prev, uint32_t bits, uint32_t max_bits,
                uint32_t timestamp, const uint160& pkh, uint16_t donation = 0,
                uint32_t absheight = 0, uint128 abswork = uint128())
    {
        return add_hash(v36_tag_hash(tag), prev, bits, max_bits, timestamp, pkh, donation,
                        absheight, abswork);
    }
};

// Minimal tracker view: exposes .chain only, so generate_share_transaction /
// verify_payout_commitment take the free v36_pplns_window path.
struct V36ChainView
{
    V36TestChain& chain;
};

} // namespace
