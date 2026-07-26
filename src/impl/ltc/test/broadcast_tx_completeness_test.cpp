// SPDX-License-Identifier: AGPL-3.0-or-later
//
// LTC/DOGE-lane KATs for the share-broadcast tx-completeness gate, run against
// the REAL ltc::ShareType variants (not a stand-in), plus the compile-time pin
// of the member-name bug that made the tx-forwarding path unreachable.
//
// Reward-path. A share broadcast without the bytes of a referenced new tx makes
// canonical p2pool drop the connection ("referenced unknown transaction",
// p2p.py:404) -> sharechain isolation -> our shares orphan -> PPLNS loss.
//
// Folded into the EXISTING allowlisted `share_test` target rather than a new
// add_executable, which would be absent from build.yml's --target list and would
// therefore be reported "Not Run" by CTest (the #769 trap).

#include <gtest/gtest.h>

#include <map>
#include <set>
#include <vector>

#include <core/known_txs_backing.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_tx_refs.hpp>

namespace {

uint256 H(uint64_t n) { return uint256(n); }

using KnownTxs = std::map<uint256, int>;  // hash -> stand-in "tx bytes"

// Exactly the accessor NodeImpl::send_shares uses to reach a share's new-tx
// list, so these tests exercise the shipped decision function.
const std::vector<uint256>* new_txs_of(ltc::ShareType& s)
{
    const std::vector<uint256>* out = nullptr;
    s.invoke([&](auto* obj) { out = ltc::new_tx_hashes(obj); });
    return out;
}

// ------------------------------------------------ member-spelling pin (bug) --

// The old probe in send_shares was `requires { obj->m_new_transaction_hashes; }`
// applied straight to the share object. It matches NO ltc share variant: v17 and
// v33 nest the list inside m_tx_info, and v34/v35/v36 carry no list at all. The
// whole remember_tx / forget_tx forwarding block was therefore dead code, so LTC
// never forwarded a tx byte and relayed v17/v33 shares unbacked.
TEST(LtcBroadcastTxCompleteness, FlatMemberSpellingMatchesNoShareVariant)
{
    EXPECT_FALSE(ltc::has_flat_new_tx_hashes<ltc::Share>);
    EXPECT_FALSE(ltc::has_flat_new_tx_hashes<ltc::NewShare>);
    EXPECT_FALSE(ltc::has_flat_new_tx_hashes<ltc::SegwitMiningShare>);
    EXPECT_FALSE(ltc::has_flat_new_tx_hashes<ltc::PaddingBugfixShare>);
    EXPECT_FALSE(ltc::has_flat_new_tx_hashes<ltc::MergedMiningShare>);
}

TEST(LtcBroadcastTxCompleteness, NestedSpellingIsWhereTheListActuallyLives)
{
    EXPECT_TRUE(ltc::has_nested_new_tx_hashes<ltc::Share>);       // v17
    EXPECT_TRUE(ltc::has_nested_new_tx_hashes<ltc::NewShare>);    // v33
    // v34+ carry no tx-info member: the Formatter serialises m_tx_info only for
    // version < 34.
    EXPECT_FALSE(ltc::has_nested_new_tx_hashes<ltc::SegwitMiningShare>);
    EXPECT_FALSE(ltc::has_nested_new_tx_hashes<ltc::PaddingBugfixShare>);
    EXPECT_FALSE(ltc::has_nested_new_tx_hashes<ltc::MergedMiningShare>);
}

TEST(LtcBroadcastTxCompleteness, AccessorReachesTheListOnV17AndV33)
{
    auto* s = new ltc::Share(H(100), H(99));
    s->m_tx_info.m_new_transaction_hashes = {H(1), H(2)};
    ltc::ShareType share;
    share = s;

    const auto* txs = new_txs_of(share);
    ASSERT_NE(txs, nullptr) << "the old probe returned nothing here — the bug";
    ASSERT_EQ(txs->size(), 2u);
    EXPECT_EQ((*txs)[0], H(1));
    EXPECT_EQ((*txs)[1], H(2));

    share.destroy();
}

TEST(LtcBroadcastTxCompleteness, AccessorReportsNoListOnV36)
{
    auto* s = new ltc::MergedMiningShare(H(200), H(199));
    ltc::ShareType share;
    share = s;

    EXPECT_EQ(new_txs_of(share), nullptr);

    share.destroy();
}

// --------------------------------------------------------------- F3 gate ----

TEST(LtcBroadcastTxCompleteness, UnbackableV17ShareIsNotBroadcast)
{
    // THE regression: send_shares used to omit the unheld tx and write the share
    // anyway. The gate must withhold the share instead.
    KnownTxs held{{H(1), 1}};  // H(2) deliberately absent

    auto* s = new ltc::Share(H(100), H(99));
    s->m_tx_info.m_new_transaction_hashes = {H(1), H(2)};
    std::vector<ltc::ShareType> batch(1);
    batch[0] = s;

    const std::size_t skipped =
        core::retain_backable_shares(batch, new_txs_of, held);

    EXPECT_EQ(skipped, 1u);
    EXPECT_TRUE(batch.empty())
        << "a share referencing an unheld tx must not reach the wire";

    delete s;  // the gate dropped the variant; we still own the object
}

TEST(LtcBroadcastTxCompleteness, LocallyMintedV36SharesAreNeverWithheld)
{
    // Safety invariant for the shipping line: the share versions this lane mints
    // carry no new-tx list, so the gate is a strict no-op for them even with an
    // entirely empty known-tx cache. The gate can never suppress our own shares.
    KnownTxs empty_cache;

    auto* a = new ltc::MergedMiningShare(H(200), H(199));
    auto* b = new ltc::PaddingBugfixShare(H(201), H(200));
    std::vector<ltc::ShareType> batch(2);
    batch[0] = a;
    batch[1] = b;

    const std::size_t skipped =
        core::retain_backable_shares(batch, new_txs_of, empty_cache);

    EXPECT_EQ(skipped, 0u);
    ASSERT_EQ(batch.size(), 2u);
    EXPECT_EQ(batch[0].hash(), H(200));
    EXPECT_EQ(batch[1].hash(), H(201));

    for (auto& s : batch)
        s.destroy();
}

TEST(LtcBroadcastTxCompleteness, GateKeepsTheBackableTipWhenAnAncestorIsUnbackable)
{
    KnownTxs held{{H(1), 1}};

    auto* ancestor = new ltc::Share(H(100), H(99));
    ancestor->m_tx_info.m_new_transaction_hashes = {H(7)};  // not held
    auto* tip = new ltc::Share(H(101), H(100));
    tip->m_tx_info.m_new_transaction_hashes = {H(1)};       // held

    std::vector<ltc::ShareType> batch(2);
    batch[0] = ancestor;
    batch[1] = tip;

    const std::size_t skipped =
        core::retain_backable_shares(batch, new_txs_of, held);

    EXPECT_EQ(skipped, 1u);
    ASSERT_EQ(batch.size(), 1u);
    EXPECT_EQ(batch[0].hash(), H(101)) << "the tip carries the PPLNS credit";

    delete ancestor;
    batch[0].destroy();
}

// -------------------------------------------------- F2 mark-after-send ------

// Model of NodeImpl::send_shares' reporting contract over real ltc shares:
// every early return abandons the batch and reports nothing written.
std::vector<uint256> send_shares_report(std::vector<ltc::ShareType>& batch,
                                        const KnownTxs& held,
                                        bool tracker_lock_acquired)
{
    if (!tracker_lock_acquired)
        return {};
    if (batch.empty())
        return {};
    core::retain_backable_shares(batch, new_txs_of, held);
    if (batch.empty())
        return {};
    std::vector<uint256> sent;
    for (auto& s : batch)
        sent.push_back(s.hash());
    return sent;
}

TEST(LtcBroadcastTxCompleteness, AbandonedBatchIsNotMarkedShared)
{
    // THE regression: broadcast_share inserted into m_shared_share_hashes during
    // the chain walk, before send_shares ran. A tracker-lock miss (or an empty
    // peer map) then left the share marked broadcast without a single byte
    // written, and the next walk breaks on that mark. No retry path exists and
    // the set is only ever cleared wholesale on overflow -> silent PPLNS loss.
    KnownTxs held{{H(1), 1}};

    auto* s = new ltc::Share(H(100), H(99));
    s->m_tx_info.m_new_transaction_hashes = {H(1)};
    std::vector<ltc::ShareType> batch(1);
    batch[0] = s;

    std::set<uint256> shared_share_hashes;

    auto sent = send_shares_report(batch, held, /*tracker_lock_acquired=*/false);
    core::commit_broadcast_marks(shared_share_hashes, sent);
    EXPECT_TRUE(sent.empty());
    EXPECT_EQ(shared_share_hashes.count(H(100)), 0u)
        << "a batch that never reached a socket must stay retriable";

    sent = send_shares_report(batch, held, /*tracker_lock_acquired=*/true);
    core::commit_broadcast_marks(shared_share_hashes, sent);
    EXPECT_EQ(shared_share_hashes.count(H(100)), 1u);

    batch[0].destroy();
}

TEST(LtcBroadcastTxCompleteness, GatedShareIsNotMarkedShared)
{
    KnownTxs held;  // holds nothing

    auto* s = new ltc::Share(H(100), H(99));
    s->m_tx_info.m_new_transaction_hashes = {H(2)};
    std::vector<ltc::ShareType> batch(1);
    batch[0] = s;

    std::set<uint256> shared_share_hashes;
    auto sent = send_shares_report(batch, held, true);
    core::commit_broadcast_marks(shared_share_hashes, sent);

    EXPECT_TRUE(sent.empty());
    EXPECT_EQ(shared_share_hashes.count(H(100)), 0u)
        << "a gated share must be retried once its txs arrive, not retired";

    delete s;
}

} // namespace
