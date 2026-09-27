// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// Test-only sharechain that admits DashV36Share, for driving the dormant v36
// generation-transaction code (share_check.hpp generate_share_transaction /
// verify_payout_commitment on DashV36Share, share_producer.hpp build_share_v36,
// pplns_v36.hpp v36_pplns_window) before the live dash::ShareType is widened.
//
// V36TestIndex mirrors dash::ShareIndex (share_chain.hpp) member for member;
// only the variant differs ({DashShare, DashV36Share} instead of {DashShare}).
// This is the same widening the live-variant slice makes; that slice retires
// or aliases this fixture. Anonymous namespace per TU.

#include <impl/dash/share.hpp>
#include <impl/dash/share_chain.hpp>   // DashFormatter, ShareHasher
#include <sharechain/sharechain.hpp>

#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <chrono>
#include <cstdint>
#include <vector>

namespace {

using V36TestShareType =
    chain::ShareVariants<dash::DashFormatter, dash::DashShare, dash::DashV36Share>;

class V36TestIndex
    : public chain::ShareIndex<uint256, V36TestShareType, dash::ShareHasher, V36TestIndex>
{
    using base_index = chain::ShareIndex<uint256, V36TestShareType, dash::ShareHasher, V36TestIndex>;

public:
    uint288 work;
    uint288 min_work;
    int64_t time_seen{0};
    int32_t naughty{0};
    bool is_block_solution{false};
    uint256 pow_hash;

    V36TestIndex() : base_index(), work(0), min_work(0) {}

    template <typename ShareT> V36TestIndex(ShareT* share) : base_index(share)
    {
        work = chain::target_to_average_attempts(chain::bits_to_target(share->m_bits));
        min_work = chain::target_to_average_attempts(chain::bits_to_target(share->m_max_bits));
        time_seen = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

struct V36TestChain : chain::ShareChain<V36TestIndex>
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
