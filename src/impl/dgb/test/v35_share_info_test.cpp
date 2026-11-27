// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// A V35 share's share_info is checked against the chain (rides
// dgb_work_source_test).
//
// The python V35 network regenerates share_info (max_bits, bits, timestamp,
// absheight, abswork, far_share_hash) from the chain and rejects the share
// unless it is equal (p2pool-dgb-scrypt data.py check()). c2pool verified only
// the generation transaction, so it could accept and build on shares python
// rejects (a fork). dgb::check_v35_share_info rejects exactly those, and, as
// python, decides only once the chain behind the share is rooted or at least
// REAL_CHAIN_LENGTH long.
// ---------------------------------------------------------------------------

#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/params.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/share_check.hpp>
#include <impl/dgb/share_tracker.hpp>

#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <functional>
#include <stdexcept>
#include <string>

namespace {

constexpr uint32_t kBits = 0x1e0fffff;
constexpr uint32_t kT0 = 1790000000u;

// A chain of `n` V35 shares (rooted at genesis when `rooted`, else hanging
// off a missing parent), 15 s apart.
struct V35Chain {
    dgb::ShareTracker tracker;
    uint256 tip;
    uint32_t tip_ts = 0, tip_absheight = 0;
    uint128 tip_abswork;
    V35Chain(int n, bool rooted)
    {
        uint256 prev;
        if (!rooted)
            prev.SetHex("99");
        uint128 abswork;
        for (int i = 0; i < n; ++i) {
            auto* s = new dgb::PaddingBugfixShare();
            uint256 h;
            h.SetHex(std::to_string(5000000 + i));
            s->m_hash = h;
            s->m_prev_hash = prev;
            s->m_desired_version = 35;
            s->m_bits = kBits;
            s->m_max_bits = kBits;
            s->m_timestamp = kT0 + 15u * static_cast<uint32_t>(i);
            s->m_absheight = static_cast<uint32_t>(i + 1);
            abswork = abswork + uint128(chain::target_to_average_attempts(chain::bits_to_target(kBits)).GetLow64());
            s->m_abswork = abswork;
            prev = h;
            tip = h;
            tip_ts = s->m_timestamp;
            tip_absheight = s->m_absheight;
            tip_abswork = abswork;
            dgb::ShareType st;
            st = s;
            tracker.add(st);
        }
    }

    // The next share as python's generate_transaction makes it.
    dgb::PaddingBugfixShare next()
    {
        dgb::PaddingBugfixShare s;
        s.m_prev_hash = tip;
        s.m_timestamp = tip_ts + 15;
        s.m_absheight = tip_absheight + 1;
        auto [h, last] = tracker.chain.get_height_and_last(tip);
        if (!(last.IsNull() && h < 99))
            s.m_far_share_hash = tracker.chain.get_nth_parent_key(tip, 99);
        const auto st = tracker.compute_share_target(tip, s.m_timestamp, dgb::PoolConfig::max_target(), 35);
        s.m_max_bits = st.max_bits;
        s.m_bits = st.bits;
        s.m_abswork = tip_abswork + uint128(chain::target_to_average_attempts(chain::bits_to_target(s.m_bits)).GetLow64());
        return s;
    }
};

bool passes(V35Chain& c, const dgb::PaddingBugfixShare& s)
{
    const auto params = dgb::make_coin_params(false);
    try {
        dgb::check_v35_share_info(s, c.tracker, params);
        return true;
    } catch (const std::invalid_argument&) {
        return false;
    }
}

} // namespace

TEST(DgbV35ShareInfo, PythonsShareInfoPassesAndEveryFieldIsChecked)
{
    V35Chain c(130, /*rooted=*/true);   // >= TARGET_LOOKBEHIND: the retarget path
    const auto good = c.next();
    ASSERT_TRUE(passes(c, good));

    const std::vector<std::pair<const char*, std::function<void(dgb::PaddingBugfixShare&)>>> bad = {
        {"max_bits", [](auto& s) { s.m_max_bits += 1; }},
        {"bits easier than the pool target", [](auto& s) {
             s.m_bits = chain::target_to_bits_upper_bound(chain::bits_to_target(s.m_max_bits) * 2);
         }},
        {"bits harder than pool/30", [](auto& s) {
             s.m_bits = chain::target_to_bits_upper_bound(chain::bits_to_target(s.m_max_bits) / 64);
         }},
        {"timestamp not after the previous", [&c](auto& s) { s.m_timestamp = c.tip_ts; }},
        {"absheight", [](auto& s) { s.m_absheight += 1; }},
        {"abswork", [](auto& s) { s.m_abswork = s.m_abswork + uint128(1); }},
        {"far_share_hash", [](auto& s) { s.m_far_share_hash.SetHex("1234"); }},
    };
    for (const auto& [name, mutate] : bad) {
        SCOPED_TRACE(name);
        auto s = good;
        mutate(s);
        if (std::string(name).rfind("bits ", 0) == 0) {
            // abswork follows the (wrong) bits, as the share would carry.
            s.m_abswork = c.tip_abswork
                + uint128(chain::target_to_average_attempts(chain::bits_to_target(s.m_bits)).GetLow64());
        }
        EXPECT_FALSE(passes(c, s)) << "python rejects this share; c2pool accepted it";
    }

    // Bits inside [pool/30, pool] are the miner's choice: python regenerates
    // the same bits, so the share passes.
    auto harder = good;
    harder.m_bits = chain::target_to_bits_upper_bound(chain::bits_to_target(good.m_max_bits) / 4);
    harder.m_abswork = c.tip_abswork
        + uint128(chain::target_to_average_attempts(chain::bits_to_target(harder.m_bits)).GetLow64());
    EXPECT_TRUE(passes(c, harder));
}

TEST(DgbV35ShareInfo, ShortRootedChainIsCheckedToo)
{
    V35Chain c(12, /*rooted=*/true);   // < TARGET_LOOKBEHIND: MAX_TARGET path, far null
    const auto good = c.next();
    EXPECT_TRUE(good.m_far_share_hash.IsNull());
    EXPECT_TRUE(passes(c, good));
    auto bad = good;
    bad.m_max_bits = 0x1d00ffff;
    EXPECT_FALSE(passes(c, bad));
}

TEST(DgbV35ShareInfo, UndecidedWhileTheChainIsShortAndUnrooted)
{
    // Python's get_height_and_last asserts the chain is rooted or REAL_CHAIN_LENGTH
    // long before it regenerates share_info: neither decides yet.
    V35Chain c(12, /*rooted=*/false);
    auto s = c.next();
    s.m_max_bits = 0x1d00ffff;
    EXPECT_TRUE(passes(c, s)) << "a share was judged on a chain python does not judge on";
}
