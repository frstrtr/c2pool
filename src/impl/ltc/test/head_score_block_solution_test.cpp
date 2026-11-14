// SPDX-License-Identifier: AGPL-3.0-or-later
// think() head selection: a share that solves a block is preferred, as in
// p2pool-merged-v36.
//
// p2pool-merged-v36 p2pool/data.py:1690-1696, Share.should_punish_reason,
// returns -1 ('block solution') when the share's PoW hash meets the block
// target of its own (parent, LTC) header, checked before the naughty test.
// think() sorts the heads of the best tail by (data.py:2933-2940)
//     ((work_at_nth_parent(h, 5) - min(punish, 1) * ata(h.target),
//       -punish, -time_seen), h)
// and takes the last (data.py:2956). A block-solving head therefore gets one
// share of work added: it beats an equal-work sibling, and a branch one share
// longer. On a tied score the share hash h (an int) decides, the larger
// winning. Phase 5 walks back only while punish > 0 (data.py:2962).
//
// c2pool set the reason from naughty only, so a block-solving head tied its
// sibling and std::sort picked one arbitrarily; a branch one share longer
// beat it outright. These cases are driven through the REAL
// ltc::ShareTracker::think() on a hand-built verified share chain, with the
// index flags in the state attempt_verify / the persisted reload leave them.
//
// A share's header bits are self-declared (share verification does not bind
// them to the LTC network), so the -1 credit is gated locally
// (block_solution_credit): header bits equal to the nBits our LTC header
// chain requires on the share's previous_block
// (ShareTracker::m_expected_block_bits -> HeaderChain::expected_bits_after),
// nullopt for an unknown / off-best-chain parent or an incomplete retarget
// window. The fixture binds a model chain (kParentBlock, next bits
// kBlockBits); the gate KATs at the end use a REAL ltc::coin::HeaderChain
// through the same oracle main_ltc binds.
//
// Folded into the EXISTING allowlisted `share_test` target (the #769 trap).

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_tracker.hpp>
#include <impl/ltc/test/ltc_mined_headers.hpp>

namespace {

uint256 hx(const std::string& tail) {
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

uint256 hn(uint64_t n) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(n));
    return hx(buf);
}

constexpr uint32_t kBits = 0x1e0fffff;      // uniform per-share work
constexpr int64_t  kSeen = 1'700'000'000;   // one wall-clock second
constexpr uint32_t kBlockBits = 0x1b0fffff; // the LTC block target (header bits)
const uint256 kParentBlock = hx("1234abcd");  // the LTC block the shares build on

void add_share(ltc::ShareTracker& t, const uint256& h, const uint256& prev) {
    auto* sh = new ltc::MergedMiningShare();
    sh->m_hash = h;
    sh->m_prev_hash = prev;
    sh->m_desired_version = 36;
    sh->m_bits = kBits;
    sh->m_max_bits = kBits;
    sh->m_min_header.m_previous_block = kParentBlock;
    sh->m_min_header.m_bits = kBlockBits;
    sh->m_min_header.m_timestamp = static_cast<uint32_t>(kSeen);
    ltc::ShareType st;
    st = sh;
    t.add(st);
    t.chain.get_index(h)->time_seen = kSeen;
}

// The block-bits oracle bound to a model LTC chain whose only known block
// is kParentBlock, on which a block must carry kBlockBits.
void bind_model_chain(ltc::ShareTracker& t) {
    t.m_expected_block_bits = [](const uint256& prev_block, int64_t) -> std::optional<uint32_t> {
        if (prev_block == kParentBlock) return kBlockBits;
        return std::nullopt;
    };
}

// Adds the share to the chain and to the verified view (parent first).
void add_verified(ltc::ShareTracker& t, const uint256& h, const uint256& prev) {
    add_share(t, h, prev);
    t.verified.add(t.chain.get_share(h));
}

// A rooted, verified trunk of `n` shares; returns its tip. Binds the model
// chain to the tracker's bits gate.
uint256 build_trunk(ltc::ShareTracker& t, int n) {
    bind_model_chain(t);
    uint256 prev;
    for (int i = 0; i < n; ++i) {
        const uint256 h = hn(0x100000 + i);
        add_verified(t, h, prev);
        prev = h;
    }
    return prev;
}

ltc::ShareIndex* idx(ltc::ShareTracker& t, const uint256& h) {
    return t.chain.get_index(h);
}

ltc::TrackerThinkResult run_think(ltc::ShareTracker& t) {
    return t.think([](uint256) { return 0; }, uint256(), 0);
}

constexpr int kTrunk = 12;

}  // namespace

// ── head_punish_reason: p2pool should_punish_reason ─────────────────────────

TEST(LtcHeadScoreBlockSolution, PunishReasonBlockSolutionFirst) {
    EXPECT_EQ(ltc::head_punish_reason(false, 0), 0);
    EXPECT_EQ(ltc::head_punish_reason(false, 1), 1);
    EXPECT_EQ(ltc::head_punish_reason(false, 4), 4);   // naughty descendant keeps its depth
    // data.py:1691-1692 is checked before the naughty test (1693-1696).
    EXPECT_EQ(ltc::head_punish_reason(true, 0), -1);
    EXPECT_EQ(ltc::head_punish_reason(true, 1), -1);
    EXPECT_EQ(ltc::head_punish_reason(true, 4), -1);
}

// make_head_score / make_traditional_score against the p2pool tuple,
// expectations derived by hand: work - min(punish,1)*attempts.
TEST(LtcHeadScoreBlockSolution, MakeScoresFollowTheP2poolTuple) {
    const uint288 w(1'000'000), a(1'000);
    const uint256 hh = hn(0x77);
    const auto plain = ltc::make_head_score(w, a, 0, kSeen, hh);
    EXPECT_EQ(plain.adjusted_work, uint288(1'000'000));
    EXPECT_EQ(plain.neg_reason, 0);
    EXPECT_EQ(plain.neg_time_seen, -kSeen);
    EXPECT_EQ(plain.hash, hh);
    const auto block = ltc::make_head_score(w, a, -1, kSeen, hh);
    EXPECT_EQ(block.adjusted_work, uint288(1'001'000));   // + one share
    EXPECT_EQ(block.neg_reason, 1);
    const auto naughty = ltc::make_head_score(w, a, 3, kSeen, hh);
    EXPECT_EQ(naughty.adjusted_work, uint288(999'000));   // - one share, not 3
    EXPECT_EQ(naughty.neg_reason, -3);
    const auto trad = ltc::make_traditional_score(w, -1, kSeen, hh);
    EXPECT_EQ(trad.work, uint288(1'000'000));            // raw work
    EXPECT_EQ(trad.neg_time_seen, -kSeen);
    EXPECT_EQ(trad.neg_reason, 1);
    EXPECT_EQ(trad.hash, hh);
}

// ── HeadScore / TraditionalScore: p2pool's key order, hash last ────────────

TEST(LtcHeadScoreBlockSolution, HashKeyDecidesOnlyAfterTheThreeP2poolKeys) {
    const uint288 w = chain::target_to_average_attempts(chain::bits_to_target(kBits));
    const uint288 w1 = w + uint288(1);
    const uint256 lo = hn(0x10), hi = hn(0x20);

    // Only the hash differs: the larger hash wins.
    EXPECT_TRUE((ltc::HeadScore{w, 0, -kSeen, lo} < ltc::HeadScore{w, 0, -kSeen, hi}));
    EXPECT_FALSE((ltc::HeadScore{w, 0, -kSeen, hi} < ltc::HeadScore{w, 0, -kSeen, lo}));
    // Each p2pool key decides before the hash, whichever hash is larger.
    EXPECT_TRUE((ltc::HeadScore{w, 0, -kSeen, hi} < ltc::HeadScore{w1, 0, -kSeen, lo}));
    EXPECT_TRUE((ltc::HeadScore{w, 0, -kSeen, hi} < ltc::HeadScore{w, 1, -kSeen, lo}));
    EXPECT_TRUE((ltc::HeadScore{w, 0, -kSeen, hi} < ltc::HeadScore{w, 0, -kSeen + 1, lo}));
    // ...and in p2pool's order: work before reason before time_seen.
    EXPECT_TRUE((ltc::HeadScore{w, 1, -kSeen + 9, hi} < ltc::HeadScore{w1, -3, -kSeen, lo}));
    EXPECT_TRUE((ltc::HeadScore{w, -1, -kSeen + 9, hi} < ltc::HeadScore{w, 0, -kSeen, lo}));
    // Equal keys: neither is less (irreflexive).
    EXPECT_FALSE((ltc::HeadScore{w, 0, -kSeen, lo} < ltc::HeadScore{w, 0, -kSeen, lo}));

    // Traditional: (work, -time_seen, -reason), hash.
    EXPECT_TRUE((ltc::TraditionalScore{w, -kSeen, 0, lo} < ltc::TraditionalScore{w, -kSeen, 0, hi}));
    EXPECT_TRUE((ltc::TraditionalScore{w, -kSeen, 0, hi} < ltc::TraditionalScore{w, -kSeen, 1, lo}));
    EXPECT_TRUE((ltc::TraditionalScore{w, -kSeen, 1, hi} < ltc::TraditionalScore{w, -kSeen + 1, 0, lo}));
    EXPECT_TRUE((ltc::TraditionalScore{w, -kSeen + 1, 1, hi} < ltc::TraditionalScore{w1, -kSeen, 0, lo}));
}

TEST(LtcHeadScoreBlockSolution, HeadScoreIsAStrictWeakOrder) {
    const uint288 w = chain::target_to_average_attempts(chain::bits_to_target(kBits));
    std::vector<ltc::HeadScore> v;
    for (int dw = 0; dw < 2; ++dw)
        for (int r : {-1, 0, 2})
            for (int ts = 0; ts < 2; ++ts)
                for (int hsh = 0; hsh < 2; ++hsh)
                    v.push_back({w + uint288(dw), r, -kSeen - ts, hn(0x40 + hsh)});
    for (const auto& a : v) {
        EXPECT_FALSE(a < a);
        for (const auto& b : v) {
            if (a < b) {
                EXPECT_FALSE(b < a);
            }
            for (const auto& c : v) {
                if (a < b && b < c) {
                    EXPECT_TRUE(a < c);
                }
            }
        }
    }
}

// ── think(): block-solving head vs an equal-work sibling ────────────────────

// Two children of the trunk tip, seen in the same second. The block-solving
// one wins whichever hash is larger and whichever arrived first.
TEST(LtcHeadScoreBlockSolution, SameSecondSiblingBlockSolutionWinsEitherOrder) {
    for (int block_hash_larger = 0; block_hash_larger < 2; ++block_hash_larger) {
        for (int block_first = 0; block_first < 2; ++block_first) {
            ltc::ShareTracker t;
            const uint256 tip = build_trunk(t, kTrunk);
            const uint256 small = hn(0xA0000), large = hn(0xB0000);
            const uint256 block = block_hash_larger ? large : small;
            const uint256 plain = block_hash_larger ? small : large;
            if (block_first) {
                add_verified(t, block, tip);
                add_verified(t, plain, tip);
            } else {
                add_verified(t, plain, tip);
                add_verified(t, block, tip);
            }
            idx(t, block)->is_block_solution = true;

            const auto r = run_think(t);
            EXPECT_EQ(r.best, block)
                << "block_hash_larger=" << block_hash_larger
                << " block_first=" << block_first;
        }
    }
}

// Seen a second later than its sibling: still wins, on the first key (+ata).
TEST(LtcHeadScoreBlockSolution, BlockSolutionSeenLaterStillWins) {
    ltc::ShareTracker t;
    const uint256 tip = build_trunk(t, kTrunk);
    const uint256 plain = hn(0xB0000), block = hn(0xA0000);
    add_verified(t, plain, tip);
    add_verified(t, block, tip);
    idx(t, block)->time_seen = kSeen + 1;
    idx(t, block)->is_block_solution = true;

    EXPECT_EQ(run_think(t).best, block);
}

// p2pool's formula: work at the 5th parent, so a block-solving head one share
// shorter than a sibling branch ties it on the first key (its +ata makes up
// the share) and wins on -punish (+1 > 0).
TEST(LtcHeadScoreBlockSolution, BlockSolutionBeatsBranchOneShareLonger) {
    ltc::ShareTracker t;
    const uint256 tip = build_trunk(t, kTrunk);
    const uint256 a1 = hn(0xC0001), a2 = hn(0xC0002);   // a1 -> a2 (longer)
    const uint256 b1 = hn(0xA0001);                      // block, smaller hash
    add_verified(t, a1, tip);
    add_verified(t, a2, a1);
    add_verified(t, b1, tip);
    idx(t, b1)->is_block_solution = true;

    EXPECT_EQ(run_think(t).best, b1);
}

// ...but only one share: a branch two shares longer still wins.
TEST(LtcHeadScoreBlockSolution, BranchTwoSharesLongerBeatsBlockSolution) {
    ltc::ShareTracker t;
    const uint256 tip = build_trunk(t, kTrunk);
    const uint256 a1 = hn(0xC0001), a2 = hn(0xC0002), a3 = hn(0xC0003);
    const uint256 b1 = hn(0xF0001);                      // block, larger hash
    add_verified(t, a1, tip);
    add_verified(t, a2, a1);
    add_verified(t, a3, a2);
    add_verified(t, b1, tip);
    idx(t, b1)->is_block_solution = true;

    EXPECT_EQ(run_think(t).best, a3);
}

// ── think(): full ties are decided by the hash, the larger winning ─────────

TEST(LtcHeadScoreBlockSolution, FullTieLargestHashWinsDeterministically) {
    for (int n : {2, 3, 17, 40}) {
        ltc::ShareTracker t;
        const uint256 tip = build_trunk(t, kTrunk);
        std::vector<uint256> sibs;
        for (int i = 0; i < n; ++i)
            sibs.push_back(hn(0xD00000 + ((i * 7919) % 1009) * 16));
        for (const auto& s : sibs)
            add_verified(t, s, tip);
        const uint256 expect = *std::max_element(sibs.begin(), sibs.end());

        const auto r = run_think(t);
        EXPECT_EQ(r.best, expect) << "n=" << n;
        // The scoring order reaching clean_tracker is the same full order.
        ASSERT_FALSE(r.top5_heads.empty());
        EXPECT_EQ(r.top5_heads.back(), expect) << "n=" << n;
        for (size_t i = 1; i < r.top5_heads.size(); ++i)
            EXPECT_TRUE(r.top5_heads[i - 1] < r.top5_heads[i]) << "n=" << n;
    }
}

// Two block-solving siblings in the same second: the hash decides between them.
TEST(LtcHeadScoreBlockSolution, TwoBlockSolutionsTieOnHash) {
    ltc::ShareTracker t;
    const uint256 tip = build_trunk(t, kTrunk);
    const uint256 lo = hn(0xA0000), hi = hn(0xB0000);
    add_verified(t, hi, tip);
    add_verified(t, lo, tip);
    idx(t, lo)->is_block_solution = true;
    idx(t, hi)->is_block_solution = true;

    EXPECT_EQ(run_think(t).best, hi);
}

// ── naughty heads: unchanged ───────────────────────────────────────────────

TEST(LtcHeadScoreBlockSolution, NaughtyHeadLosesToEqualWorkSibling) {
    ltc::ShareTracker t;
    const uint256 tip = build_trunk(t, kTrunk);
    const uint256 honest = hn(0xA0000), naughty = hn(0xB0000);
    add_verified(t, honest, tip);
    add_verified(t, naughty, tip);
    idx(t, naughty)->naughty = 1;
    idx(t, naughty)->time_seen = kSeen - 5;   // seen earlier: still loses

    const auto r = run_think(t);
    EXPECT_EQ(r.best, honest);
    // Traditional sort (work, -time_seen, -punish) has the naughty head, seen
    // first, on top: punish_aggressively, as p2pool's traditional_sort[-1][0][2].
    EXPECT_TRUE(r.punish_aggressively);
}

// A naughty branch long enough to stay best after its deduction is walked
// back (Phase 5) to its last clean ancestor, then down to the best clean
// descendant, as before.
TEST(LtcHeadScoreBlockSolution, NaughtyBestIsWalkedBack) {
    ltc::ShareTracker t;
    const uint256 tip = build_trunk(t, kTrunk);
    const uint256 n1 = hn(0xE0001), n2 = hn(0xE0002), n3 = hn(0xE0003);
    const uint256 h1 = hn(0xA0001);
    add_verified(t, n1, tip);
    add_verified(t, n2, n1);
    add_verified(t, n3, n2);
    add_verified(t, h1, tip);
    idx(t, n1)->naughty = 1;
    idx(t, n2)->naughty = 2;
    idx(t, n3)->naughty = 3;

    const auto r = run_think(t);
    EXPECT_EQ(r.best, h1);
    EXPECT_TRUE(r.punish_aggressively);        // traditional best is n3 (naughty)
}

// The same branch whose head also solves a block: reason -1 (checked first),
// so it gets +ata and is never walked back (p2pool `while punish > 0`).
TEST(LtcHeadScoreBlockSolution, NaughtyBlockSolutionHeadIsNotWalkedBack) {
    ltc::ShareTracker t;
    const uint256 tip = build_trunk(t, kTrunk);
    const uint256 n1 = hn(0xE0001), n2 = hn(0xE0002), n3 = hn(0xE0003);
    const uint256 h1 = hn(0xA0001);
    add_verified(t, n1, tip);
    add_verified(t, n2, n1);
    add_verified(t, n3, n2);
    add_verified(t, h1, tip);
    idx(t, n1)->naughty = 1;
    idx(t, n2)->naughty = 2;
    idx(t, n3)->naughty = 3;
    idx(t, n3)->is_block_solution = true;

    EXPECT_EQ(run_think(t).best, n3);
}

// The walk-back stops at a block-solving ancestor: its punish is -1, so
// p2pool neither continues (`while punish > 0`) nor descends (`if not punish`).
TEST(LtcHeadScoreBlockSolution, WalkBackStopsAtBlockSolution) {
    ltc::ShareTracker t;
    const uint256 tip = build_trunk(t, kTrunk);
    const uint256 n1 = hn(0xE0001), n2 = hn(0xE0002), n3 = hn(0xE0003);
    const uint256 h1 = hn(0xA0001);
    add_verified(t, n1, tip);
    add_verified(t, n2, n1);
    add_verified(t, n3, n2);
    add_verified(t, h1, tip);
    idx(t, n1)->naughty = 1;
    idx(t, n1)->is_block_solution = true;
    idx(t, n2)->naughty = 2;
    idx(t, n3)->naughty = 3;

    EXPECT_EQ(run_think(t).best, n1);
}

// The walk-back reaches the clean parent of the naughty run and that parent
// solved a block: its punish is -1, which Python's `if not punish:` treats as
// true-ish, so p2pool stops AT it and does not descend to the honest sibling
// (data.py:2962-2967). Only punish == 0 descends.
TEST(LtcHeadScoreBlockSolution, WalkBackToBlockSolvingCleanAncestorDoesNotDescend) {
    ltc::ShareTracker t;
    const uint256 tip = build_trunk(t, kTrunk);
    const uint256 n1 = hn(0xE0001), n2 = hn(0xE0002), n3 = hn(0xE0003);
    const uint256 h1 = hn(0xA0001);
    add_verified(t, n1, tip);
    add_verified(t, n2, n1);
    add_verified(t, n3, n2);
    add_verified(t, h1, tip);
    idx(t, tip)->is_block_solution = true;   // clean, solved a block
    idx(t, n1)->naughty = 1;
    idx(t, n2)->naughty = 2;
    idx(t, n3)->naughty = 3;

    EXPECT_EQ(run_think(t).best, tip);

    // The same walk over a clean, non-block parent descends to h1 (unchanged).
    idx(t, tip)->is_block_solution = false;
    EXPECT_EQ(run_think(t).best, h1);
}

// ── punish_aggressively: p2pool traditional_sort[-1][0][2] ─────────────────

TEST(LtcHeadScoreBlockSolution, PunishAggressivelyFollowsTraditionalBestReason) {
    {   // honest single head
        ltc::ShareTracker t;
        build_trunk(t, kTrunk);
        EXPECT_FALSE(run_think(t).punish_aggressively);
    }
    {   // block-solving single head: -punish == 1, truthy in p2pool
        ltc::ShareTracker t;
        const uint256 tip = build_trunk(t, kTrunk);
        idx(t, tip)->is_block_solution = true;
        const auto r = run_think(t);
        EXPECT_EQ(r.best, tip);
        EXPECT_TRUE(r.punish_aggressively);
    }
}

// ── merged-only (DOGE) solutions: no head bonus ────────────────────────────

// p2pool tests pow_hash against self.header['bits'] (the parent LTC header,
// data.py:1432/1691) only. A share whose PoW meets a merged chain's target but
// not the LTC block target is reported to the merged hook and stays an
// ordinary head; one meeting the LTC target is flagged and preferred.
TEST(LtcHeadScoreBlockSolution, MergedOnlySolutionEarnsNoHeadBonus) {
    const uint256 ltc_target = chain::bits_to_target(kBlockBits);
    const uint256 above_ltc = ltc_target + uint256(1);  // meets an easier aux target only

    ltc::ShareTracker t;
    const uint256 tip = build_trunk(t, kTrunk);
    const uint256 merged_only = hn(0xA0000);   // smaller hash: loses a full tie
    const uint256 plain       = hn(0xB0000);
    add_verified(t, merged_only, tip);
    add_verified(t, plain, tip);
    idx(t, merged_only)->pow_hash = above_ltc;
    idx(t, plain)->pow_hash = ~uint256();      // no target met

    std::vector<uint256> merged_checked;
    t.m_on_merged_block_check = [&](const uint256& h, const uint256&) { merged_checked.push_back(h); };
    t.scan_chain_for_blocks(merged_only, 1);
    t.scan_chain_for_blocks(plain, 1);

    ASSERT_EQ(merged_checked.size(), 2u);           // the merged hook saw both
    EXPECT_FALSE(idx(t, merged_only)->is_block_solution);
    EXPECT_EQ(run_think(t).best, plain);            // plain tie: larger hash

    // The same share meeting the LTC block target is a block solution.
    idx(t, merged_only)->pow_hash = ltc_target;
    t.scan_chain_for_blocks(merged_only, 1);
    EXPECT_TRUE(idx(t, merged_only)->is_block_solution);
    EXPECT_EQ(run_think(t).best, merged_only);
}

// ── the block flag is set with no found-block hook bound ───────────────────

// attempt_verify hands every verified share to mark_block_solution. With no
// hook bound (m_on_block_found empty) the flag head scoring reads is still
// set, so the credit can never be silently off; the hook fires only when
// bound. A merged-only PoW and a missing PoW hash set nothing.
TEST(LtcHeadScoreBlockSolution, BlockFlagSetWithNoFoundBlockHook) {
    const uint256 ltc_target = chain::bits_to_target(kBlockBits);

    ltc::ShareTracker t;
    const uint256 tip = build_trunk(t, kTrunk);
    const uint256 block = hn(0xA0000), merged_only = hn(0xB0000), no_pow = hn(0xC0000);
    for (const auto& h : {block, merged_only, no_pow})
        add_verified(t, h, tip);
    ASSERT_FALSE(static_cast<bool>(t.m_on_block_found));
    ASSERT_FALSE(static_cast<bool>(t.m_on_merged_block_check));

    EXPECT_TRUE(t.mark_block_solution(block, ltc_target));          // at the target
    EXPECT_FALSE(t.mark_block_solution(merged_only, ltc_target + uint256(1)));
    EXPECT_FALSE(t.mark_block_solution(no_pow, uint256()));
    EXPECT_TRUE(idx(t, block)->is_block_solution);
    EXPECT_FALSE(idx(t, merged_only)->is_block_solution);
    EXPECT_FALSE(idx(t, no_pow)->is_block_solution);
    // block has the smallest hash of the three same-second siblings.
    EXPECT_EQ(run_think(t).best, block);

    // With a hook bound it fires once per block solution, and only for it.
    std::vector<uint256> found;
    t.m_on_block_found = [&](const uint256& h) { found.push_back(h); };
    EXPECT_TRUE(t.mark_block_solution(block, ltc_target - uint256(1)));
    EXPECT_FALSE(t.mark_block_solution(merged_only, ~uint256()));
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0], block);
}

// attempt_verify routes its block detection through mark_block_solution and
// does not gate it on the found-block hook (on master it was inside
// `if (m_on_block_found && ...)`, so no hook meant no flag and no credit).
TEST(LtcHeadScoreBlockSolution, AttemptVerifyBlockFlagNotGatedOnHook) {
    std::ifstream in(LTC_SHARE_TRACKER_SRC);
    ASSERT_TRUE(in.good()) << LTC_SHARE_TRACKER_SRC;
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string code = ss.str();
    const size_t fn = code.find("bool attempt_verify(const uint256& share_hash)");
    ASSERT_NE(fn, std::string::npos);
    const size_t end = code.find("// Naughty propagation", fn);
    ASSERT_NE(end, std::string::npos);
    const std::string body = code.substr(fn, end - fn);
    EXPECT_NE(body.find("mark_block_solution(share_hash, pow_hash)"), std::string::npos)
        << "attempt_verify must hand the verified share to mark_block_solution";
    EXPECT_EQ(body.find("if (m_on_block_found &&"), std::string::npos)
        << "block flag gated on the found-block hook";
}

// ── the credit needs the network's header bits on a known parent ──────────

// block_solution_credit: flagged, and the header bits equal the expected
// bits our header chain computes for the parent; nullopt never credits.
TEST(LtcHeadScoreBlockSolution, BlockSolutionCreditNeedsExpectedBits) {
    EXPECT_TRUE(ltc::block_solution_credit(true, kBlockBits, kBlockBits));
    EXPECT_FALSE(ltc::block_solution_credit(true, 0x1d00ffff, kBlockBits));   // easier
    EXPECT_FALSE(ltc::block_solution_credit(true, 0x1a0fffff, kBlockBits));   // harder
    EXPECT_FALSE(ltc::block_solution_credit(true, kBlockBits, std::nullopt)); // parent unknown
    EXPECT_FALSE(ltc::block_solution_credit(false, kBlockBits, kBlockBits));  // not flagged
}

namespace {

using ltc::coin::BlockHeaderType;
using ltc::coin::HeaderChain;

constexpr uint32_t kGateT0 = 1317972665;
constexpr int64_t kGateInterval = 8;   // retarget every 8 blocks (1200 s / 150 s)
// The gate chain's block bits: target 0x7fffff << 224 (~512 scrypt tries a
// header), low enough that CalculateNextWorkRequired's target * timespan
// fits 256 bits, as Litecoin's real powLimit (2^236) guarantees. At
// 0x207fffff it overflows (in Litecoin Core as in the port).
constexpr uint32_t kGateBits = 0x1f7fffff;

BlockHeaderType gate_genesis() {
    BlockHeaderType g;
    g.m_version = 1;
    g.m_merkle_root = hx("5eed");
    g.m_timestamp = kGateT0;
    g.m_bits = kGateBits;
    g.m_nonce = 1;
    return g;
}

uint256 hash_of(const BlockHeaderType& hdr) {
    return Hash(pack(hdr).get_span());
}

// Litecoin mainnet rules (no min-difficulty), the easiest PoW limit and an
// 8-block retarget interval, so a full window is cheap to mine.
ltc::coin::LTCChainParams gate_params() {
    auto p = ltc::coin::make_ltc_chain_params_mainnet();
    p.pow_limit.SetCompact(ltc_test::kEasyBits);
    p.target_timespan = kGateInterval * 150;
    p.target_spacing = 150;
    p.genesis_hash = hash_of(gate_genesis());
    return p;
}

BlockHeaderType mined_child(const uint256& prev, uint32_t tag, uint32_t time) {
    BlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block = prev;
    h.m_merkle_root = hn(0x900000 + tag);
    h.m_timestamp = time;
    h.m_bits = kGateBits;
    h.m_nonce = tag << 16;
    ltc_test::mine(h, gate_params());
    return h;
}

// genesis g0 .. h9 on the best chain, 10 s apart (blocks far too fast), and
// s3, a sibling of h3 seen after it (off the best chain). Fewer headers than
// interval + 10, so the chain takes them without its own difficulty check.
struct GateChain {
    HeaderChain chain{gate_params()};
    std::vector<uint256> h;   // h[i] = best-chain block at height i
    uint256 s3;
    GateChain() {
        EXPECT_TRUE(chain.init());
        EXPECT_TRUE(chain.add_header(gate_genesis()));
        h.push_back(hash_of(gate_genesis()));
        for (uint32_t i = 1; i <= 9; ++i) {
            auto c = mined_child(h.back(), i, kGateT0 + 10 * i);
            EXPECT_TRUE(chain.add_header(c));
            h.push_back(hash_of(c));
        }
        auto s = mined_child(h[2], 33, kGateT0 + 31);
        EXPECT_TRUE(chain.add_header(s));
        s3 = hash_of(s);
        EXPECT_EQ(chain.height(), 9u);
    }
};

}  // namespace

// expected_bits_after over a REAL header chain, values derived by hand from
// Litecoin Core GetNextWorkRequired / CalculateNextWorkRequired.
TEST(LtcHeadScoreBlockSolution, ExpectedBitsAfterFollowsLitecoinRetarget) {
    GateChain g;
    // Not a retarget height: the parent's bits.
    EXPECT_EQ(g.chain.expected_bits_after(g.h[3], kGateT0 + 40), std::optional<uint32_t>(kGateBits));
    // Height 8, the first retarget: back interval-1 = 7 blocks to genesis.
    // Timespan 70 s clamps to 1200/4 = 300 s: target * 300 / 1200 =
    // (0x7fffff << 224) / 4, compact 0x1f1fffff.
    EXPECT_EQ(g.chain.expected_bits_after(g.h[7], kGateT0 + 80), std::optional<uint32_t>(0x1f1fffffu));
    // Unknown parent, and a parent off the best chain: nullopt.
    EXPECT_FALSE(g.chain.expected_bits_after(hx("dead"), kGateT0).has_value());
    EXPECT_FALSE(g.chain.expected_bits_after(g.s3, kGateT0 + 40).has_value());
}

// A chain from a fast-start anchor at height 96: the anchor carries no
// header, and the retarget at 104 needs height 95, below it. nullopt for
// both, never the parent's bits or powLimit; a non-retarget height above
// the anchor is answered.
TEST(LtcHeadScoreBlockSolution, ExpectedBitsAfterNeedsTheWholeWindow) {
    HeaderChain chain{gate_params()};
    ASSERT_TRUE(chain.init());
    const uint256 anchor = hx("a0c4");
    chain.set_dynamic_checkpoint(96, anchor);
    std::vector<uint256> c{anchor};   // c[i] = height 96 + i
    for (uint32_t i = 1; i <= 7; ++i) {
        auto hdr = mined_child(c.back(), 200 + i, kGateT0 + 10 * i);
        ASSERT_TRUE(chain.add_header(hdr));
        c.push_back(hash_of(hdr));
    }
    ASSERT_EQ(chain.height(), 103u);
    EXPECT_EQ(chain.expected_bits_after(c[4], kGateT0 + 50), std::optional<uint32_t>(kGateBits));
    EXPECT_FALSE(chain.expected_bits_after(c[7], kGateT0 + 80).has_value());   // window below the anchor
    EXPECT_FALSE(chain.expected_bits_after(anchor, kGateT0).has_value());       // anchor: no header
}

namespace {

// The oracle main_ltc binds in embedded mode, over a REAL header chain.
void bind_header_chain(ltc::ShareTracker& t, const HeaderChain* hc) {
    t.m_expected_block_bits = [hc](const uint256& prev_block, int64_t block_time) -> std::optional<uint32_t> {
        if (!hc) return std::nullopt;
        return hc->expected_bits_after(prev_block, block_time);
    };
}

// Two same-second siblings: `claimant` (smaller hash) declaring header parent
// `prev_block` and header `bits`, flagged a block solution from those bits as
// mark_block_solution flags it (PoW at the declared target); `plain` (larger
// hash). Returns whether think() picks the claimant.
bool claimant_wins(const HeaderChain* hc, const uint256& prev_block, uint32_t bits, bool bind = true) {
    ltc::ShareTracker t;
    const uint256 tip = build_trunk(t, kTrunk);
    if (bind)
        bind_header_chain(t, hc);
    else
        t.m_expected_block_bits = nullptr;
    const uint256 claimant = hn(0xA0000), plain = hn(0xB0000);
    add_verified(t, claimant, tip);
    add_verified(t, plain, tip);
    t.chain.get_share(claimant).invoke([&](auto* s) {
        s->m_min_header.m_previous_block = prev_block;
        s->m_min_header.m_bits = bits;
        s->m_min_header.m_timestamp = kGateT0 + 100;
    });
    EXPECT_TRUE(t.mark_block_solution(claimant, chain::bits_to_target(bits)));
    EXPECT_TRUE(t.chain.get_index(claimant)->is_block_solution);   // the flag rests on its own bits
    return run_think(t).best == claimant;
}

}  // namespace

// The network's bits on a known parent: credited, the claimant wins the race.
// Fake EASY bits (the pre-retarget 0x1f7fffff where the network requires
// 0x1f1fffff, 4x harder; or powLimit): flagged on their own target, but no
// credit; the plain sibling (larger hash) wins.
TEST(LtcHeadScoreBlockSolution, FakeEasyHeaderBitsGetNoCredit) {
    GateChain g;
    EXPECT_TRUE(claimant_wins(&g.chain, g.h[3], kGateBits));             // real, non-retarget
    EXPECT_TRUE(claimant_wins(&g.chain, g.h[7], 0x1f1fffffu));           // real, at the retarget
    EXPECT_FALSE(claimant_wins(&g.chain, g.h[7], kGateBits));            // fake: 4x easier
    EXPECT_FALSE(claimant_wins(&g.chain, g.h[3], ltc_test::kEasyBits));  // fake: powLimit
    EXPECT_FALSE(claimant_wins(&g.chain, g.h[3], 0x1d00ffffu));          // other wrong bits
}

// No credit without a known best-chain parent or without an oracle at all.
TEST(LtcHeadScoreBlockSolution, UnknownParentOrNoHeaderChainGetsNoCredit) {
    GateChain g;
    EXPECT_FALSE(claimant_wins(&g.chain, hx("dead"), kGateBits));   // unknown parent
    EXPECT_FALSE(claimant_wins(&g.chain, g.s3, kGateBits));         // off the best chain
    EXPECT_FALSE(claimant_wins(nullptr, g.h[3], kGateBits));        // oracle detached
    EXPECT_FALSE(claimant_wins(&g.chain, g.h[3], kGateBits, false)); // no oracle bound
    EXPECT_TRUE(claimant_wins(&g.chain, g.h[3], kGateBits));        // control: credited
}
