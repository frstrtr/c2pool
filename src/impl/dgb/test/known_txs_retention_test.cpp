// SPDX-License-Identifier: AGPL-3.0-or-later
// F3 backable-broadcast gate + F1 template-identity retention — DGB unit KAT.
//
// Covers the two pure primitives ported from the DASH variant into
// src/impl/dgb/known_txs_retention.hpp:
//
//   retain_template_txs() — F1 template-identity dedup: N re-registrations of
//     ONE template consume ONE slot while the rolling window still holds N
//     DISTINCT templates; a tx leaves known_txs only once it is absent from
//     EVERY retained set.
//
//   all_txs_backable() — F3 broadcast gate: a share is backable (safe to send
//     without the peer's "referenced unknown transaction" disconnect) only when
//     we hold the bytes of every referenced new-tx.
//
// Non-hollow guard: DgbKnownTxsBackable.UnheldTxIsNotBackable asserts false for a share
// referencing an unheld tx; deleting the gate (all_txs_backable → always true)
// flips it red. DgbKnownTxsRetention.OneTemplateConsumesOneSlot asserts size==1 after N
// re-registrations; dropping the dedup (push every registration) flips it red.

#include <gtest/gtest.h>

#include <deque>
#include <map>
#include <set>
#include <vector>

#include <core/uint256.hpp>
#include <impl/dgb/known_txs_retention.hpp>

namespace {

// Distinct, deterministic uint256 tx hashes A..E.
uint256 h(const char* hex)
{
    uint256 v; v.SetHex(hex); return v;
}
const uint256 A = h("aa");
const uint256 B = h("bb");
const uint256 C = h("cc");
const uint256 D = h("dd");
const uint256 E = h("ee");

// A tx-bytes stand-in; the retention logic is agnostic to the payload type.
using TxMap = std::map<uint256, int>;

} // namespace

// F1: re-registering the SAME template (identical tx-hash set) N times consumes
// exactly ONE slot and refreshes recency — it must NOT collapse the window.
TEST(DgbKnownTxsRetention, OneTemplateConsumesOneSlot)
{
    std::deque<std::set<uint256>> recent;
    TxMap known;

    const std::vector<uint256> hashes{A, B};
    const std::vector<int>     txs{1, 2};

    for (int i = 0; i < 5; ++i)
        dgb::retain_template_txs(recent, known, hashes, txs, /*cap=*/3);

    EXPECT_EQ(recent.size(), 1u);      // dedup: 5 registrations -> 1 slot
    EXPECT_EQ(known.size(), 2u);       // A,B inserted once
    EXPECT_TRUE(known.count(A));
    EXPECT_TRUE(known.count(B));
}

// F1: the window holds N DISTINCT templates, and a tx is evicted only once it
// has fallen out of EVERY retained set (B survives in T2 after T1 is evicted).
TEST(DgbKnownTxsRetention, WindowHoldsDistinctTemplatesAndEvictsCorrectly)
{
    std::deque<std::set<uint256>> recent;
    TxMap known;
    const std::vector<int> two{1, 2};

    dgb::retain_template_txs(recent, known, std::vector<uint256>{A, B}, two, 3); // T1
    dgb::retain_template_txs(recent, known, std::vector<uint256>{B, C}, two, 3); // T2
    dgb::retain_template_txs(recent, known, std::vector<uint256>{C, D}, two, 3); // T3
    EXPECT_EQ(recent.size(), 3u);
    for (const auto& x : {A, B, C, D}) EXPECT_TRUE(known.count(x)) << "missing before evict";

    // T4 pushes the window past cap=3 -> oldest (T1={A,B}) evicted.
    dgb::retain_template_txs(recent, known, std::vector<uint256>{D, E}, two, 3); // T4
    EXPECT_EQ(recent.size(), 3u);
    EXPECT_FALSE(known.count(A));  // A only lived in T1 -> erased
    EXPECT_TRUE(known.count(B));   // B still retained via T2 -> kept
    EXPECT_TRUE(known.count(C));
    EXPECT_TRUE(known.count(D));
    EXPECT_TRUE(known.count(E));
}

// F3: a share whose referenced new-txs we all hold is backable; one unheld tx
// makes it NOT backable (must not be broadcast).
TEST(DgbKnownTxsBackable, UnheldTxIsNotBackable)
{
    const std::set<uint256> held{A, B};

    EXPECT_TRUE(dgb::all_txs_backable(std::vector<uint256>{A, B}, held));   // all held -> send
    EXPECT_FALSE(dgb::all_txs_backable(std::vector<uint256>{A, C}, held));  // C unheld -> withhold
    EXPECT_TRUE(dgb::all_txs_backable(std::vector<uint256>{}, held));       // no refs -> trivially backable
}
