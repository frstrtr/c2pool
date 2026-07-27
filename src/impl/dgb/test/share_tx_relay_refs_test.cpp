// SPDX-License-Identifier: AGPL-3.0-or-later
// DGB tx-relay dead-probe regression (#905, port of the btc #880 fix).
//
// send_shares() collects the new-tx hashes each share references so it can
// remember_tx-forward them to a peer. The pre-fix probe guarded on a TOP-LEVEL
// m_new_transaction_hashes that NO dgb share type declares (the field is nested
// in m_tx_info), so the collection was ALWAYS empty and DGB never relayed a tx
// byte to a peer for ANY share version. This pins append_share_tx_refs, the
// SSOT send_shares() now uses:
//   - v17/v33 (carry m_tx_info)  -> the referenced hashes ARE collected
//   - v34/v35/v36 (no m_tx_info) -> compiled out, vacuously empty
//
// FAILS-BEFORE: revert append_share_tx_refs to probe obj->m_new_transaction_hashes
// and the v17/v33 expectations below collapse to 0 -- the historical dead path.

#include <gtest/gtest.h>

#include <vector>

#include <core/uint256.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/coin/share_tx_relay_refs.hpp>

namespace {

uint256 mk(const char* hex) { uint256 h; h.SetHex(hex); return h; }

const char* H1 = "1111111111111111111111111111111111111111111111111111111111111111";
const char* H2 = "2222222222222222222222222222222222222222222222222222222222222222";

// v17: m_tx_info present -> referenced hashes collected in order.
TEST(DGB_tx_relay_refs, V17CollectsNestedNewTxHashes)
{
    dgb::Share s;
    s.m_tx_info.m_new_transaction_hashes = {mk(H1), mk(H2)};

    std::vector<uint256> refs;
    dgb::append_share_tx_refs(&s, refs);

    ASSERT_EQ(refs.size(), 2u);          // dead-probe regression makes this 0
    EXPECT_EQ(refs[0], mk(H1));
    EXPECT_EQ(refs[1], mk(H2));
}

// v33: same nested carrier -> collected.
TEST(DGB_tx_relay_refs, V33CollectsNestedNewTxHashes)
{
    dgb::NewShare s;
    s.m_tx_info.m_new_transaction_hashes = {mk(H1)};

    std::vector<uint256> refs;
    dgb::append_share_tx_refs(&s, refs);

    ASSERT_EQ(refs.size(), 1u);          // dead-probe regression makes this 0
    EXPECT_EQ(refs[0], mk(H1));
}

// v34/v35: no m_tx_info member -> probe compiled out, vacuously empty.
TEST(DGB_tx_relay_refs, SegwitVariantsCarryNoRefsByConstruction)
{
    dgb::SegwitMiningShare v34;
    dgb::PaddingBugfixShare v35;

    std::vector<uint256> refs;
    dgb::append_share_tx_refs(&v34, refs);
    dgb::append_share_tx_refs(&v35, refs);

    EXPECT_TRUE(refs.empty());
}

// v36 merged-mining: no m_tx_info member -> vacuously empty.
TEST(DGB_tx_relay_refs, MergedMiningShareCarriesNoRefs)
{
    dgb::MergedMiningShare v36;

    std::vector<uint256> refs;
    dgb::append_share_tx_refs(&v36, refs);

    EXPECT_TRUE(refs.empty());
}

} // namespace
