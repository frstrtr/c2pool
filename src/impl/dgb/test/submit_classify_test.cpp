// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// submit_classify_test.cpp -- KAT for the Stage 4d mining_submit decision SSOT
// (coin/submit_classify.hpp). Pins the three-way ladder + BOTH inclusive
// boundaries so the hot path (work_source.cpp mining_submit) and the dual-path
// broadcaster / sharechain-mint dispatch can never drift from the documented
// pow<=target gate, which itself mirrors DigiByte Core CheckProofOfWork and
// p2pool-merged-v36 share-accept. Pure u256 arithmetic -- no scrypt, no link.
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <impl/dgb/coin/submit_classify.hpp>

using dgb::coin::u256;
using dgb::coin::SubmitClass;
using dgb::coin::classify_submission;

namespace {

// Realistic ordering: block target is TIGHTER (smaller) than the share target.
// Use round magnitudes so the boundaries are unambiguous.
//   block_target = 1000, share_target = 1000000.
u256 block_t()  { return u256::from_u64(1000); }
u256 share_t()  { return u256::from_u64(1000000); }

u256 plus1(u256 v) { v += u256::from_u64(1); return v; }

}  // namespace

// A hash STRICTLY below the block target is a won block (rarer outcome wins).
TEST(DgbSubmitClassify, BelowBlockTargetIsWonBlock) {
    EXPECT_EQ(classify_submission(u256::from_u64(500), block_t(), share_t()),
              SubmitClass::WonBlock);
}

// Inclusive at the BLOCK boundary: pow == block_target satisfies it (won).
TEST(DgbSubmitClassify, EqualBlockTargetIsWonBlockInclusive) {
    EXPECT_EQ(classify_submission(block_t(), block_t(), share_t()),
              SubmitClass::WonBlock);
}

// One unit above the block target, still under the share target -> share mint.
TEST(DgbSubmitClassify, JustAboveBlockTargetIsShareAccept) {
    EXPECT_EQ(classify_submission(plus1(block_t()), block_t(), share_t()),
              SubmitClass::ShareAccept);
}

// Inclusive at the SHARE boundary: pow == share_target is still an accept.
TEST(DgbSubmitClassify, EqualShareTargetIsShareAcceptInclusive) {
    EXPECT_EQ(classify_submission(share_t(), block_t(), share_t()),
              SubmitClass::ShareAccept);
}

// One unit above the share target -> below share difficulty -> reject.
TEST(DgbSubmitClassify, JustAboveShareTargetIsReject) {
    EXPECT_EQ(classify_submission(plus1(share_t()), block_t(), share_t()),
              SubmitClass::Reject);
}

// pow_hash == 0 trivially satisfies every target -> won block (superset rule:
// a won block always also clears the share target; block is checked first).
TEST(DgbSubmitClassify, ZeroHashIsWonBlockNotDoubleCounted) {
    EXPECT_EQ(classify_submission(u256::from_u64(0), block_t(), share_t()),
              SubmitClass::WonBlock);
}

// Safety under an inverted (malformed) job where share_target < block_target:
// the tighten-first ladder must NEVER promote a non-block hash to WonBlock.
// Here pow=2000 is below the (looser-looking) block_t=1000? no -- it is ABOVE
// 1000, so it is not a block; with share=500 it is also above 500 -> Reject.
// The invariant under test: an inverted pair can only mis-Reject, never
// mis-WonBlock.
TEST(DgbSubmitClassify, InvertedTargetsNeverSpuriousWonBlock) {
    const u256 tight = u256::from_u64(500);    // passed as share (wrong)
    const u256 loose = u256::from_u64(1000);   // passed as block (wrong)
    // pow just above the real block magnitude (1000): not a block.
    EXPECT_NE(classify_submission(u256::from_u64(1500), loose, tight),
              SubmitClass::WonBlock);
}