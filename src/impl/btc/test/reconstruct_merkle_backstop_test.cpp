// SPDX-License-Identifier: AGPL-3.0-or-later
// BIP 152 compact-block reconstruction merkle backstop — BTC unit KAT.
//
// Milestone btc-cmpct-merkle. ReconstructBlock() (compact_blocks.hpp) declares a
// block "complete" once every slot is filled. Short IDs are 48-bit SipHash over
// wtxid, so a collision can silently substitute the WRONG transaction into a
// filled slot; the pre-fix code delivered that forged block straight into the
// UTXO cache. The backstop recomputes the merkle root over the reconstructed
// (non-witness) txids and, on any divergence from the header's committed
// m_merkle_root, DISCARDS instead of delivering — the caller then re-fetches the
// full block via getdata.
//
// Non-hollow guards:
//   * CollisionSubstitutesWrongTx: a slot filled with a tx whose txid differs
//     from the committed one yields merkle_mismatch=true, complete=false, and an
//     EMPTY result.block (discard-not-deliver). Deleting the merkle check flips
//     it red (complete would become true and the block would be delivered).
//   * HonestReconstructionCompletes: the correct txs verify → complete=true,
//     merkle_mismatch=false. Proves the check does not reject honest blocks.
//   * MissingTxIsNotAMerkleMismatch: a genuinely incomplete block reports
//     missing_indexes with merkle_mismatch=false, so the caller still takes the
//     getblocktxn path (not the getdata full-block fallback).
//
// Per-coin isolation: src/impl/btc/ only. p2pool-merged-v36 surface: NONE.

#include <gtest/gtest.h>

#include <impl/btc/coin/compact_blocks.hpp>
#include <impl/btc/coin/gentx_unpack.hpp>

#include <core/pack.hpp>
#include <core/hash.hpp>

#include <map>
#include <string>
#include <vector>

namespace {

using btc::coin::CompactBlock;
using btc::coin::PrefilledTransaction;
using btc::coin::MutableTransaction;
using btc::coin::BlockHeaderType;
using btc::coin::ReconstructBlock;

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> v; v.reserve(h.size() / 2);
    auto nyb = [](char c) -> int { return (c <= '9') ? c - '0' : (c | 0x20) - 'a' + 10; };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<unsigned char>((nyb(h[i]) << 4) | nyb(h[i + 1])));
    return v;
}

// Two distinct, real non-witness coinbase serializations (shared verbatim with
// the gentx_unpack KAT) — used here purely as two transactions with distinct
// txids/wtxids.
const std::string TX_A =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d03a1b2c3041122334455667788ffffffff0400f2052a010000001976a914111111111111111111111111111111111111111188ac00f90295000000001976a914222222222222222222222222222222222222222288ac0100000000000000434104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac00000000000000002a6a28abababababababababababababababababababababababababababababababab080706050403020100000000";
const std::string TX_B =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d03a1b2c3041122334455667788ffffffff050000000000000000266a24aa21a9edcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd00f2052a010000001976a914111111111111111111111111111111111111111188ac00f90295000000001976a914222222222222222222222222222222222222222288ac0100000000000000434104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac00000000000000002a6a28abababababababababababababababababababababababababababababababab080706050403020100000000";

MutableTransaction tx_from(const std::string& hex) {
    return btc::coin::unpack_gentx_coinbase(unhex(hex)).tx;
}

uint256 wtxid(const MutableTransaction& tx) {
    auto p = pack(btc::coin::TX_WITH_WITNESS(tx));
    return Hash(p.get_span());
}

// Header whose committed merkle root is computed over the given (non-witness)
// txid leaf set — i.e. the honest block's commitment.
BlockHeaderType header_committing(const std::vector<MutableTransaction>& honest_txs) {
    std::vector<uint256> txids;
    for (const auto& tx : honest_txs)
        txids.push_back(btc::coin::compute_txid(tx));
    BlockHeaderType h;
    h.m_merkle_root = btc::coin::compute_merkle_root(txids);
    h.m_bits = 0x1d00ffff;   // non-null so the header isn't "empty"
    return h;
}

// Build a 2-tx compact block: coinbase prefilled at index 0, one short-ID slot
// at index 1 pointing at `slot_tx`'s wtxid.
CompactBlock build_cb(const BlockHeaderType& header,
                      const MutableTransaction& coinbase,
                      const MutableTransaction& slot_tx) {
    CompactBlock cb;
    cb.header = header;
    cb.nonce = 0x0102030405060708ULL;
    PrefilledTransaction pt; pt.index = 0; pt.tx = coinbase;
    cb.prefilled_txns.push_back(std::move(pt));
    uint64_t k0, k1; cb.GetSipHashKeys(k0, k1);
    cb.short_ids.push_back(CompactBlock::GetShortID(k0, k1, wtxid(slot_tx)));
    return cb;
}

} // namespace

// Honest reconstruction: correct slot tx verifies against the committed root.
TEST(BtcCmpctMerkleBackstop, HonestReconstructionCompletes) {
    MutableTransaction coinbase = tx_from(TX_A);
    MutableTransaction tx1      = tx_from(TX_B);

    auto header = header_committing({coinbase, tx1});
    auto cb = build_cb(header, coinbase, tx1);

    std::map<uint256, MutableTransaction> known;
    known[wtxid(tx1)] = tx1;

    auto r = ReconstructBlock(cb, known);

    EXPECT_TRUE(r.complete);
    EXPECT_FALSE(r.merkle_mismatch);
    ASSERT_EQ(r.block.m_txs.size(), 2u);
}

// Collision: the slot is filled by a tx whose txid differs from the committed
// one. The reconstructed root diverges -> DISCARD, do not deliver.
TEST(BtcCmpctMerkleBackstop, CollisionSubstitutesWrongTx) {
    MutableTransaction coinbase = tx_from(TX_A);
    MutableTransaction honest   = tx_from(TX_B);

    // Header commits to [coinbase, honest].
    auto header = header_committing({coinbase, honest});

    // The peer's short ID (by collision) matches a DIFFERENT tx we hold: a copy
    // of `honest` with a mutated locktime -> distinct txid AND wtxid.
    MutableTransaction wrong = honest;
    wrong.locktime = 0x0badf00dU;
    ASSERT_NE(btc::coin::compute_txid(wrong), btc::coin::compute_txid(honest));

    auto cb = build_cb(header, coinbase, wrong);

    std::map<uint256, MutableTransaction> known;
    known[wtxid(wrong)] = wrong;   // only the wrong tx is available for the slot

    auto r = ReconstructBlock(cb, known);

    EXPECT_FALSE(r.complete);              // NOT delivered
    EXPECT_TRUE(r.merkle_mismatch);        // signals the getdata full-block fallback
    EXPECT_TRUE(r.block.m_txs.empty());    // discard-not-deliver: no forged block
    EXPECT_TRUE(r.missing_indexes.empty()); // all slots were filled -> not a getblocktxn case
}

// A genuinely missing tx must remain the getblocktxn path, NOT the merkle-
// mismatch getdata path — the two failure modes are distinct.
TEST(BtcCmpctMerkleBackstop, MissingTxIsNotAMerkleMismatch) {
    MutableTransaction coinbase = tx_from(TX_A);
    MutableTransaction tx1      = tx_from(TX_B);

    auto header = header_committing({coinbase, tx1});
    auto cb = build_cb(header, coinbase, tx1);

    std::map<uint256, MutableTransaction> known;   // empty: slot 1 unavailable

    auto r = ReconstructBlock(cb, known);

    EXPECT_FALSE(r.complete);
    EXPECT_FALSE(r.merkle_mismatch);
    ASSERT_EQ(r.missing_indexes.size(), 1u);
    EXPECT_EQ(r.missing_indexes[0], 1u);
}
