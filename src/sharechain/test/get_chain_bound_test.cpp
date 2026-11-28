// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ShareChain::get_chain's bounds check walks only the n steps asked for (X1
// stage A1), with the same result as the full get_height walk it replaces.
//
// Old: if (n > get_height(hash)) throw;            // a walk to the chain's end
// New: if (!has_depth(hash, n)) throw;             // at most n steps
//
// The old check is still in the class (set_legacy_get_chain_bound_for_test), so
// both run side by side on the same chain. Over seeded random forests (forks,
// disconnected segments, parents arriving after their children, every remove()
// branch, aborted removes, re-added hashes) and after every operation, for the
// heads, the tail children, the heads' parents, random present and absent
// hashes and the null hash, and for n at and around every boundary (0, 1, the
// height, the height +-1/+2, size()+-1/+2, INT32_MAX+1, UINT64_MAX):
//   * has_depth(h, n) == !(n > get_height(h));
//   * get_chain(h, n) throws in the new mode iff it throws in the old mode;
//   * when it does not throw, both modes yield the same (hash) sequence, which
//     is the first n shares of the prev-link walk.
// A prev-link cycle (not reachable through real SHA-256d hashes, built here by
// hand) is pinned too: equal for every n up to size()+3.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <random>
#include <stdexcept>
#include <vector>

#include <core/uint256.hpp>
#include <impl/ltc/share.hpp>
#include <sharechain/test/random_forest.hpp>

namespace {

using forest_test::make_hash;
using forest_test::make_share;

constexpr size_t kPrefix = 64;   // view elements compared per get_chain call

struct Outcome {
    bool threw{false};
    std::vector<uint256> seq;
};

Outcome run_get_chain(ltc::ShareChain& chain, const uint256& h, uint64_t n, bool legacy)
{
    Outcome o;
    chain.set_legacy_get_chain_bound_for_test(legacy);
    try {
        auto view = chain.get_chain(h, n);
        // Only read a bounded prefix: the view itself is unchanged by A1.
        for (auto [hash, data] : view) {
            o.seq.push_back(hash);
            if (o.seq.size() >= kPrefix)
                break;
        }
    } catch (const std::invalid_argument&) {
        o.threw = true;
    }
    chain.set_legacy_get_chain_bound_for_test(false);
    return o;
}

// What a ChainView of n yields: the first min(n, kPrefix) positions of the
// prev-link walk, while present. For n == 0 the view yields its start share
// when that is present (ChainView::begin() is the start's iterator and only
// operator++ consults the count); that is how the view has always behaved and
// A1 does not touch it.
std::vector<uint256> reference_walk(ltc::ShareChain& chain, const uint256& h, uint64_t n)
{
    std::vector<uint256> out;
    if (n == 0) {
        if (!h.IsNull() && chain.contains(h))
            out.push_back(h);
        return out;
    }
    uint256 cur = h;
    for (uint64_t i = 0; i < n && out.size() < kPrefix; ++i) {
        if (cur.IsNull() || !chain.contains(cur))
            break;
        out.push_back(cur);
        cur = chain.get_index(cur)->tail;
    }
    return out;
}

// Compares old and new for one hash over the boundary values of n.
// Returns the number of (hash, n) pairs checked.
size_t check_hash(ltc::ShareChain& chain, const uint256& h, std::mt19937_64& rng)
{
    const int32_t height = chain.get_height(h);
    const uint64_t size = chain.size();
    std::vector<uint64_t> ns = {0, 1, 2,
                                static_cast<uint64_t>(height),
                                static_cast<uint64_t>(height) + 1,
                                static_cast<uint64_t>(height) + 2,
                                size, size + 1, size + 2,
                                static_cast<uint64_t>(std::numeric_limits<int32_t>::max()) + 1,
                                std::numeric_limits<uint64_t>::max(),
                                static_cast<uint64_t>(static_cast<int64_t>(-1))};
    if (height > 0)
        ns.push_back(static_cast<uint64_t>(height) - 1);
    if (size > 0)
        ns.push_back(size - 1);
    ns.push_back(std::uniform_int_distribution<uint64_t>(0, size + 3)(rng));

    size_t checked = 0;
    for (uint64_t n : ns) {
        const bool old_ok = !(n > static_cast<uint64_t>(height));
        EXPECT_EQ(chain.has_depth(h, n), old_ok) << "h=" << h.GetHex() << " n=" << n
                                                 << " height=" << height << " size=" << size;
        const Outcome o_old = run_get_chain(chain, h, n, /*legacy=*/true);
        const Outcome o_new = run_get_chain(chain, h, n, /*legacy=*/false);
        EXPECT_EQ(o_old.threw, !old_ok);
        EXPECT_EQ(o_new.threw, o_old.threw) << "h=" << h.GetHex() << " n=" << n;
        EXPECT_EQ(o_new.seq, o_old.seq) << "h=" << h.GetHex() << " n=" << n;
        if (!o_new.threw)
            EXPECT_EQ(o_new.seq, reference_walk(chain, h, n)) << "h=" << h.GetHex() << " n=" << n;
        ++checked;
    }
    return checked;
}

// The query set: heads, tail children, heads' parents, a random sample of
// present hashes, removed (absent) hashes, fresh absent hashes, null.
template <typename Grower>
std::vector<uint256> query_hashes(Grower& g, ltc::ShareChain& chain, size_t sample)
{
    std::vector<uint256> q = g.sorted_heads();
    for (const auto& c : g.tail_children())
        q.push_back(c);
    for (const auto& [h, t] : chain.get_heads())
        if (chain.contains(h))
            q.push_back(chain.get_index(h)->tail);
    auto present = g.present_hashes();
    for (size_t i = 0; i < sample && !present.empty(); ++i)
        q.push_back(present[g.pick(present.size())]);
    for (size_t i = 0; i < 2 && !g.removed.empty(); ++i)
        q.push_back(g.removed[g.pick(g.removed.size())]);
    q.push_back(make_hash(0xabad1dea, g.next_id));
    q.push_back(uint256());
    return q;
}

}  // namespace

TEST(ShareChainGetChainBound, RandomForestsOldAndNewAgree)
{
    size_t pairs = 0, removes_ok = 0, removes_aborted = 0;
    for (uint64_t seed = 1; seed <= 12; ++seed) {
        ltc::ShareChain chain;
        forest_test::ForestGrower<ltc::ShareChain> g(chain, seed);
        auto add = [&](const uint256& h, const uint256& p, uint32_t bits) {
            chain.add(make_share(h, p, bits));
        };
        auto remove = [&](const uint256& h) { return chain.remove(h); };
        for (int op = 0; op < 150; ++op) {
            if (op > 20 && g.chance(18)) {
                if (g.remove_step(remove))
                    ++removes_ok;
                else
                    ++removes_aborted;
            } else {
                g.grow_step(add);
            }
            // Every op: heads and tail children (where the removals act);
            // every 5th op the full set (parents, a random sample, absent
            // hashes, null).
            std::vector<uint256> qs;
            if (op % 5 == 0) {
                qs = query_hashes(g, chain, 12);
            } else {
                qs = g.sorted_heads();
                for (const auto& c : g.tail_children())
                    qs.push_back(c);
            }
            for (const auto& h : qs)
                pairs += check_hash(chain, h, g.rng);
            if (::testing::Test::HasFailure())
                FAIL() << "seed " << seed << " op " << op;
        }
    }
    EXPECT_GT(removes_ok, 150u);
    EXPECT_GT(removes_aborted, 20u);
    std::printf("[ShareChainGetChainBound] %zu (hash, n) pairs agree; removes ok=%zu aborted=%zu\n",
                pairs, removes_ok, removes_aborted);
}

// A long chain with forks at depth, the LTC production shape (n ~ 2.4 x CL):
// the boundaries at the full height of every head.
TEST(ShareChainGetChainBound, LongChainWithForksAgreesAtEveryHeadBoundary)
{
    ltc::ShareChain chain;
    std::vector<uint256> main;
    uint256 prev;   // genesis
    for (uint64_t i = 0; i < 20000; ++i) {
        const uint256 h = make_hash(77, i);
        chain.add(make_share(h, prev, forest_test::bits_for(i)));
        main.push_back(h);
        prev = h;
    }
    // Four stale forks of a few shares at various depths, and a segment whose
    // parent is missing.
    uint64_t id = 1000000;
    for (size_t at : {19990u, 19000u, 12000u, 3u}) {
        uint256 p = main[at];
        for (int k = 0; k < 3; ++k) {
            const uint256 h = make_hash(77, id++);
            chain.add(make_share(h, p, 0x1e0fffff));
            p = h;
        }
    }
    {
        uint256 p = make_hash(78, 1);
        for (int k = 0; k < 50; ++k) {
            const uint256 h = make_hash(78, 100 + k);
            chain.add(make_share(h, p, 0x1e0fffff));
            p = h;
        }
    }
    std::mt19937_64 rng(5);
    size_t pairs = 0;
    for (const auto& [h, t] : chain.get_heads())
        pairs += check_hash(chain, h, rng);
    for (size_t at : {0u, 1u, 8639u, 8640u, 17290u, 19999u})
        pairs += check_hash(chain, main[at], rng);
    EXPECT_GT(pairs, 0u);
}

// A prev-link cycle cannot come out of SHA-256d share hashes, but the old
// get_height has a guard for one (it stops at size()+1 and logs), so pin that
// the new check gives the old answer there as well, for every n.
TEST(ShareChainGetChainBound, CycleGivesTheOldAnswerForEveryN)
{
    ltc::ShareChain chain;
    const uint256 a = make_hash(9, 1), b = make_hash(9, 2), c = make_hash(9, 3);
    chain.add(make_share(a, b, 0x1e0fffff));   // a -> b (missing)
    chain.add(make_share(b, c, 0x1e0fffff));   // b -> c (missing)
    chain.add(make_share(c, a, 0x1e0fffff));   // c -> a: closes a -> b -> c -> a
    ASSERT_EQ(chain.size(), 3u);
    for (const uint256& h : {a, b, c}) {
        for (uint64_t n = 0; n <= chain.size() + 3; ++n) {
            const bool old_ok = !(n > static_cast<uint64_t>(chain.get_height(h)));
            EXPECT_EQ(chain.has_depth(h, n), old_ok) << "n=" << n;
            EXPECT_EQ(run_get_chain(chain, h, n, true).threw, !old_ok) << "n=" << n;
            EXPECT_EQ(run_get_chain(chain, h, n, false).threw, !old_ok) << "n=" << n;
        }
    }
}

// The new check visits at most n shares; the old one visits the whole chain.
// Measured as wall time on a 20k-share chain for n = 1 (send_shares' call).
TEST(ShareChainGetChainBound, ShortBoundDoesNotWalkTheChain)
{
    ltc::ShareChain chain;
    uint256 prev, tip;
    for (uint64_t i = 0; i < 20000; ++i) {
        tip = make_hash(55, i);
        chain.add(make_share(tip, prev, 0x1e0fffff));
        prev = tip;
    }
    auto time_calls = [&](bool legacy) {
        chain.set_legacy_get_chain_bound_for_test(legacy);
        const auto t0 = std::chrono::steady_clock::now();
        size_t yielded = 0;
        for (int i = 0; i < 200; ++i)
            for (auto [h, d] : chain.get_chain(tip, 1))
                yielded += h == tip;
        chain.set_legacy_get_chain_bound_for_test(false);
        EXPECT_EQ(yielded, 200u);
        return std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t0).count();
    };
    const auto old_us = time_calls(true);
    const auto new_us = time_calls(false);
    std::printf("[ShareChainGetChainBound] 200 x get_chain(tip, 1) on 20k shares: old %lld us, new %lld us\n",
                static_cast<long long>(old_us), static_cast<long long>(new_us));
    EXPECT_LT(new_us * 20, old_us + 2000) << "the bound should not scale with the chain";
}
