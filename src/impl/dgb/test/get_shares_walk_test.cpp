// dgb GetShares walk — share-exchange (SHAREREQ -> SHAREREPLY) conformance KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/get_shares_walk.hpp against the p2pool node.py
// Node.handle_get_shares oracle:
//     parents = min(parents, 1000//len(hashes))
//     for share_hash in hashes:
//         for share in get_chain(share_hash, min(parents+1, get_height(share_hash))):
//             if share.hash in stops: break
//             shares.append(share)
// plus the two c2pool node-local guards (skip not-in-chain hash; skip rejected
// share) the dgb walk adds.
//
// Expectations are derived from the oracle formula / hand-walked chain spans,
// NOT from the code under test — a conformance KAT that reads its answers from
// its subject passes vacuously.
//
// The chain is a FAKE (no NodeImpl / ShareTracker / LevelDB standup): a linear
// genesis..tip vector exposing the same contains/get_height/get_chain contract
// the real sharechain::Chain does. MUST appear in BOTH this dir's CMakeLists.txt
// AND the build.yml --target allowlist, or it becomes a #143 NOT_BUILT sentinel.

#include <impl/dgb/get_shares_walk.hpp>

#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

uint256 u256(const char* hex) {
    uint256 t;
    t.SetHex(hex);
    return t;
}

struct FakeShare { int id = 0; };
struct ChainData { FakeShare share; };

// Linear chain: m_order[0] = genesis ... m_order[back] = tip. Each entry's
// FakeShare.id == its index, so a collected id sequence reads as positions.
// get_height(h) = (index of h) + 1  — shares from genesis up to and incl. h.
// get_chain(h, n) = n entries starting AT h walking toward genesis: h, parent,
//                   grandparent, ...  (p2pool get_chain walks back through parents)
class FakeChain {
public:
    std::vector<uint256> m_order;  // genesis-first

    void append(const uint256& h) { m_order.push_back(h); }

    int index_of(const uint256& h) const {
        for (int i = 0; i < (int)m_order.size(); ++i)
            if (m_order[i] == h) return i;
        return -1;
    }

    bool contains(const uint256& h) const { return index_of(h) >= 0; }

    int32_t get_height(const uint256& h) const {
        int i = index_of(h);
        return i < 0 ? 0 : (int32_t)(i + 1);
    }

    std::vector<std::pair<uint256, ChainData>> get_chain(const uint256& h, uint64_t n) const {
        std::vector<std::pair<uint256, ChainData>> out;
        int i = index_of(h);
        for (uint64_t k = 0; k < n && i - (int)k >= 0; ++k) {
            int pos = i - (int)k;
            out.push_back({ m_order[pos], ChainData{ FakeShare{ pos } } });
        }
        return out;
    }
};

// Build a 6-deep chain: ids/positions 0..5, tip = position 5.
FakeChain make_chain() {
    FakeChain c;
    for (int i = 0; i < 6; ++i)
        c.append(u256(std::to_string(10 + i).c_str()));  // distinct non-colliding hashes
    return c;
}

std::vector<int> ids(const std::vector<FakeShare>& v) {
    std::vector<int> out;
    for (const auto& s : v) out.push_back(s.id);
    return out;
}

const auto NO_REJECT = [](const uint256&) { return false; };

} // namespace

// --------------------------------------------------------------------------
// 1. parents cap — min(parents, 1000//len(hashes)). Integer division.
// --------------------------------------------------------------------------
TEST(DgbGetSharesWalk, ParentsCapMatchesOracle) {
    EXPECT_EQ(dgb::get_shares_parents_cap(5000, 1), 1000u);  // 1000//1
    EXPECT_EQ(dgb::get_shares_parents_cap(600, 2), 500u);    // 1000//2 caps below 600
    EXPECT_EQ(dgb::get_shares_parents_cap(100, 2), 100u);    // request below cap: unchanged
    EXPECT_EQ(dgb::get_shares_parents_cap(5000, 3), 333u);   // 1000//3 == 333 (floor)
    EXPECT_EQ(dgb::get_shares_parents_cap(7, 0), 7u);        // empty-request divzero guard
}

// --------------------------------------------------------------------------
// 2. per-hash walk length — min(parents+1, height).
// --------------------------------------------------------------------------
TEST(DgbGetSharesWalk, WalkCountMatchesOracle) {
    EXPECT_EQ(dgb::get_shares_walk_count(2, 10), 3u);  // parents+1 binds
    EXPECT_EQ(dgb::get_shares_walk_count(10, 2), 2u);  // height binds
    EXPECT_EQ(dgb::get_shares_walk_count(0, 5), 1u);   // parents=0 -> just the hash
}

// --------------------------------------------------------------------------
// 3. full walk, single in-chain hash — returns [tip, parent, grandparent].
// --------------------------------------------------------------------------
TEST(DgbGetSharesWalk, SingleHashWalksParentsPlusOne) {
    FakeChain c = make_chain();
    uint256 tip = c.m_order.back();  // position 5
    auto shares = dgb::collect_get_shares<FakeShare>(
        c, {tip}, /*parents=*/2, /*stops=*/{}, NO_REJECT);
    // min(parents+1, height=6) = 3 -> positions 5,4,3
    EXPECT_EQ(ids(shares), (std::vector<int>{5, 4, 3}));
}

// --------------------------------------------------------------------------
// 4. stop-hash BREAKS the walk before appending the stop (and the rest).
// --------------------------------------------------------------------------
TEST(DgbGetSharesWalk, StopHashBreaks) {
    FakeChain c = make_chain();
    uint256 tip = c.m_order.back();          // position 5
    uint256 stop = c.m_order[4];             // position 4 is a stop
    auto shares = dgb::collect_get_shares<FakeShare>(
        c, {tip}, /*parents=*/3, /*stops=*/{stop}, NO_REJECT);
    // walk yields 5 then 4(stop)->break: only [5]
    EXPECT_EQ(ids(shares), (std::vector<int>{5}));
}

// --------------------------------------------------------------------------
// 5. not-in-chain hash is SKIPPED (continue) and fires on_missing; other
//    requested hashes still walk.
// --------------------------------------------------------------------------
TEST(DgbGetSharesWalk, MissingHashSkippedOnMissingFires) {
    FakeChain c = make_chain();
    uint256 tip = c.m_order.back();
    uint256 absent = u256("deadbeef");
    int missing_calls = 0;
    auto shares = dgb::collect_get_shares<FakeShare>(
        c, {absent, tip}, /*parents=*/1, /*stops=*/{}, NO_REJECT,
        [&](const uint256& h){ EXPECT_EQ(h, absent); ++missing_calls; });
    EXPECT_EQ(missing_calls, 1);
    // tip walk: min(parents+1=2, height=6)=2 -> positions 5,4
    EXPECT_EQ(ids(shares), (std::vector<int>{5, 4}));
}

// --------------------------------------------------------------------------
// 6. locally-rejected share is SKIPPED (continue) — walk does not stop.
// --------------------------------------------------------------------------
TEST(DgbGetSharesWalk, RejectedShareSkippedNotStopped) {
    FakeChain c = make_chain();
    uint256 tip = c.m_order.back();          // position 5
    std::set<std::string> rejected{ c.m_order[4].ToString() };  // position 4 rejected
    auto is_rejected = [&](const uint256& h){ return rejected.count(h.ToString()) > 0; };
    auto shares = dgb::collect_get_shares<FakeShare>(
        c, {tip}, /*parents=*/2, /*stops=*/{}, is_rejected);
    // walk 5(keep),4(rejected->continue),3(keep): [5,3]
    EXPECT_EQ(ids(shares), (std::vector<int>{5, 3}));
}

// --------------------------------------------------------------------------
// 7. empty request -> empty reply (never reaches the walk / divzero).
// --------------------------------------------------------------------------
TEST(DgbGetSharesWalk, EmptyRequestEmptyReply) {
    FakeChain c = make_chain();
    auto shares = dgb::collect_get_shares<FakeShare>(
        c, {}, /*parents=*/10, /*stops=*/{}, NO_REJECT);
    EXPECT_TRUE(shares.empty());
}

// --------------------------------------------------------------------------
// 8. multi-hash request — parents cap applies once, each hash walks the
//    capped span.
// --------------------------------------------------------------------------
TEST(DgbGetSharesWalk, MultiHashSharedCap) {
    FakeChain c = make_chain();
    uint256 tip = c.m_order.back();   // position 5
    uint256 mid = c.m_order[2];       // position 2 (height 3)
    // parents=600, 2 hashes -> cap=min(600,500)=500 -> walk_count bounded by height
    auto shares = dgb::collect_get_shares<FakeShare>(
        c, {tip, mid}, /*parents=*/600, /*stops=*/{}, NO_REJECT);
    // tip: min(501, height=6)=6 -> 5,4,3,2,1,0 ; mid: min(501, height=3)=3 -> 2,1,0
    EXPECT_EQ(ids(shares), (std::vector<int>{5, 4, 3, 2, 1, 0, 2, 1, 0}));
}
