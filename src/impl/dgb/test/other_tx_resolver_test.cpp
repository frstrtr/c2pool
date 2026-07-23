// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb_other_tx_resolver_test -- pins coin/other_tx_resolver.hpp, the won-block
// reconstructor's (#82) transaction_hash_refs -> ordered other_tx hash walk.
//
// Proves the ref-walk semantics against a SYNTHETIC ancestry (no live
// ShareTracker): the two tracker operations (nth_parent / new_transaction_hashes
// lookup) are injected, exactly as resolve_other_tx_hashes takes them, so the
// faithful p2pool get_other_tx_hashes resolution is verified in isolation:
//   * share_count == 0 indexes the won share's OWN new_transaction_hashes
//   * share_count == N walks back N generations
//   * ref ORDER is the output order (= block other_txs order)
//   * empty refs => empty list
//   * malformed refs (tx_count OOB / walk past chain end) throw, never emit a
//     wrong hash
//
// Header-only: links no dgb OBJECT lib, only core (uint256) + GTest.  MUST also
// appear in the build.yml --target allowlist (#143 NOT_BUILT trap).
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <functional>
#include <map>
#include <stdexcept>
#include <vector>

#include <core/uint256.hpp>

#include "../coin/other_tx_resolver.hpp"

using dgb::coin::resolve_other_tx_hashes;
using dgb::TxHashRefs;

namespace {

uint256 H(const char* two) // 0x"two" repeated to 64 hex chars
{
    std::string s;
    for (int i = 0; i < 32; ++i) s += two;
    uint256 h; h.SetHex(s);
    return h;
}

// A synthetic 3-share chain: won <- p1 <- p2.  Each share carries its own
// new_transaction_hashes.  parent[h] gives the immediate parent; null beyond p2.
struct Ancestry
{
    uint256 won = H("a0"), p1 = H("a1"), p2 = H("a2");
    std::map<uint256, uint256> parent;          // child -> parent
    std::map<uint256, std::vector<uint256>> nths; // share -> new_transaction_hashes

    Ancestry()
    {
        parent[won] = p1;
        parent[p1]  = p2;
        // p2 has no parent -> walking past it returns null.
        nths[won] = { H("c0"), H("c1") };
        nths[p1]  = { H("d0") };
        nths[p2]  = { H("e0"), H("e1"), H("e2") };
    }

    // nth_parent_fn: 0 => start itself; null if walk runs off the chain.
    uint256 nth_parent(const uint256& start, uint64_t n) const
    {
        uint256 cur = start;
        for (uint64_t i = 0; i < n; ++i)
        {
            auto it = parent.find(cur);
            if (it == parent.end()) return uint256(); // null
            cur = it->second;
        }
        return cur;
    }

    const std::vector<uint256>& new_tx_hashes(const uint256& h) const
    {
        return nths.at(h);
    }
};

std::function<uint256(const uint256&, uint64_t)> walk_of(const Ancestry& a)
{
    return [&a](const uint256& s, uint64_t n) { return a.nth_parent(s, n); };
}
std::function<const std::vector<uint256>&(const uint256&)> nths_of(const Ancestry& a)
{
    return [&a](const uint256& h) -> const std::vector<uint256>& { return a.new_tx_hashes(h); };
}

} // namespace

// share_count == 0 resolves against the won share's own new_transaction_hashes.
TEST(OtherTxResolver, SelfShareRefs)
{
    Ancestry a;
    std::vector<TxHashRefs> refs = { {0, 1}, {0, 0} };
    auto out = resolve_other_tx_hashes(a.won, refs, walk_of(a), nths_of(a));
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], H("c1")); // won.new_tx[1]
    EXPECT_EQ(out[1], H("c0")); // won.new_tx[0] -- ref ORDER preserved
}

// share_count == N walks N generations back before indexing.
TEST(OtherTxResolver, AncestorWalkBack)
{
    Ancestry a;
    std::vector<TxHashRefs> refs = { {1, 0}, {2, 2} };
    auto out = resolve_other_tx_hashes(a.won, refs, walk_of(a), nths_of(a));
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], H("d0")); // p1.new_tx[0]
    EXPECT_EQ(out[1], H("e2")); // p2.new_tx[2]
}

// Mixed refs across generations preserve emission order = block other_txs order.
TEST(OtherTxResolver, MixedOrderPreserved)
{
    Ancestry a;
    std::vector<TxHashRefs> refs = { {2, 0}, {0, 1}, {1, 0} };
    auto out = resolve_other_tx_hashes(a.won, refs, walk_of(a), nths_of(a));
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0], H("e0"));
    EXPECT_EQ(out[1], H("c1"));
    EXPECT_EQ(out[2], H("d0"));
}

// No refs => empty other_txs (coinbase-only block).
TEST(OtherTxResolver, EmptyRefs)
{
    Ancestry a;
    auto out = resolve_other_tx_hashes(a.won, {}, walk_of(a), nths_of(a));
    EXPECT_TRUE(out.empty());
}

// tx_count past the ancestor's new_transaction_hashes is a malformed share.
TEST(OtherTxResolver, TxCountOutOfRangeThrows)
{
    Ancestry a;
    std::vector<TxHashRefs> refs = { {1, 5} }; // p1 has only 1 new tx
    EXPECT_THROW(resolve_other_tx_hashes(a.won, refs, walk_of(a), nths_of(a)),
                 std::out_of_range);
}

// share_count past the chain end is a malformed share (null ancestor).
TEST(OtherTxResolver, WalkPastChainEndThrows)
{
    Ancestry a;
    std::vector<TxHashRefs> refs = { {3, 0} }; // only won<-p1<-p2 exist
    EXPECT_THROW(resolve_other_tx_hashes(a.won, refs, walk_of(a), nths_of(a)),
                 std::out_of_range);
}