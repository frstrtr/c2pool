// SPDX-License-Identifier: AGPL-3.0-or-later
// DGB G3b — won-block wire framing KAT (coin/won_block_serialize.hpp).
//
// Pins the two invariants the ALREADY-HASHED stratum header imposes on the
// won-block body, both of which the previous hand-rolled framing in
// work_source.cpp mining_submit() violated on the empty-embedded-chain path:
//
//   (A) NO merkle branches in the job => the committed merkle root IS the bare
//       coinbase txid => the emitted block MUST be coinbase-only.  Appending
//       job->tx_data anyway is a deterministic bad-txnmrklroot.
//   (B) BIP144 witness form IFF the coinbase carries the BIP141 aa21a9ed
//       commitment output.  A witness-bearing coinbase without one is rejected
//       (unexpected-witness), and the commitment CANNOT be injected at submit
//       time -- it changes the coinbase txid and invalidates the header.
//
// Plus the structural guarantee the whole reconstruct rests on: the BIP144
// reserialization leaves the non-witness bytes (hence the txid) untouched.

#include <gtest/gtest.h>
#include <impl/dgb/coin/won_block_serialize.hpp>

#include <cstdint>
#include <vector>

namespace {

using dgb::coin::coinbase_has_witness_commitment;
using dgb::coin::serialize_won_block;
using dgb::coin::to_bip144_coinbase;

std::vector<uint8_t> header80() { return std::vector<uint8_t>(80, 0x11); }

// Minimal coinbase-shaped blob: version(4) || body || locktime(4).  The framer
// is byte-level (no tx codec), so a shaped blob is a faithful stand-in.
std::vector<uint8_t> coinbase_no_commitment()
{
    std::vector<uint8_t> cb = {0x01, 0x00, 0x00, 0x00};          // version = 1
    for (int i = 0; i < 40; ++i) cb.push_back(static_cast<uint8_t>(0x40 + i));
    cb.insert(cb.end(), {0x00, 0x00, 0x00, 0x00});               // locktime = 0
    return cb;
}

// Same, with a BIP141 commitment output scriptPubKey embedded in the body:
// OP_RETURN(0x6a) PUSH36(0x24) aa21a9ed <32 bytes>.
std::vector<uint8_t> coinbase_with_commitment()
{
    std::vector<uint8_t> cb = {0x01, 0x00, 0x00, 0x00};
    for (int i = 0; i < 8; ++i) cb.push_back(static_cast<uint8_t>(0x40 + i));
    cb.insert(cb.end(), {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed});
    cb.insert(cb.end(), 32, 0x7e);
    cb.insert(cb.end(), {0x00, 0x00, 0x00, 0x00});
    return cb;
}

std::vector<uint8_t> body_tx(uint8_t tag) { return std::vector<uint8_t>(24, tag); }

// ---- (A) tx-set vs commitment ---------------------------------------------

TEST(DgbWonBlockSerialize, NoBranchesDropsBodyTxsSoRootStaysCommitted)
{
    const auto cb = coinbase_no_commitment();
    const std::vector<std::vector<uint8_t>> body = {body_tx(0xa1), body_tx(0xa2)};

    const auto out = serialize_won_block(header80(), cb, body,
                                         /*segwit_active=*/false,
                                         /*committed_coinbase_only=*/true);

    EXPECT_EQ(out.tx_count, 1u);          // coinbase only -- matches the root
    EXPECT_EQ(out.dropped_txs, 2u);       // and it is REPORTED, never silent
    ASSERT_EQ(out.bytes.size(), 80u + 1u + cb.size());
    EXPECT_EQ(out.bytes[80], 0x01);       // tx-count varint
    EXPECT_TRUE(std::equal(cb.begin(), cb.end(), out.bytes.begin() + 81));
}

TEST(DgbWonBlockSerialize, WithBranchesKeepsBodyTxs)
{
    const auto cb = coinbase_no_commitment();
    const std::vector<std::vector<uint8_t>> body = {body_tx(0xb1), body_tx(0xb2)};

    const auto out = serialize_won_block(header80(), cb, body,
                                         /*segwit_active=*/false,
                                         /*committed_coinbase_only=*/false);

    EXPECT_EQ(out.tx_count, 3u);
    EXPECT_EQ(out.dropped_txs, 0u);
    EXPECT_EQ(out.bytes.size(), 80u + 1u + cb.size() + 48u);
    EXPECT_EQ(out.bytes[80], 0x03);
}

// ---- (B) witness form vs BIP141 commitment --------------------------------

TEST(DgbWonBlockSerialize, SegwitActiveWithoutCommitmentEmitsLegacy)
{
    const auto cb = coinbase_no_commitment();
    ASSERT_FALSE(coinbase_has_witness_commitment(cb));

    const auto out = serialize_won_block(header80(), cb, {},
                                         /*segwit_active=*/true,
                                         /*committed_coinbase_only=*/true);

    EXPECT_FALSE(out.witness_form);
    EXPECT_TRUE(out.witness_form_suppressed);
    // No marker/flag: the byte after the 4-byte version is the body, not 0x00.
    EXPECT_NE(out.bytes[85], 0x00);
    EXPECT_EQ(out.bytes.size(), 80u + 1u + cb.size());
}

TEST(DgbWonBlockSerialize, SegwitActiveWithCommitmentEmitsBip144)
{
    const auto cb = coinbase_with_commitment();
    ASSERT_TRUE(coinbase_has_witness_commitment(cb));

    const auto out = serialize_won_block(header80(), cb, {},
                                         /*segwit_active=*/true,
                                         /*committed_coinbase_only=*/true);

    ASSERT_TRUE(out.witness_form);
    EXPECT_FALSE(out.witness_form_suppressed);
    EXPECT_EQ(out.bytes.size(), 80u + 1u + cb.size() + 36u);
    EXPECT_EQ(out.bytes[85], 0x00);   // marker
    EXPECT_EQ(out.bytes[86], 0x01);   // flag
    // witness stack: 1 item of 32 zero bytes, immediately before the locktime.
    const size_t wit = out.bytes.size() - 4 - 34;
    EXPECT_EQ(out.bytes[wit], 0x01);
    EXPECT_EQ(out.bytes[wit + 1], 0x20);
    for (size_t i = 0; i < 32; ++i) EXPECT_EQ(out.bytes[wit + 2 + i], 0x00);
}

TEST(DgbWonBlockSerialize, SegwitInactiveNeverEmitsWitnessEvenWithCommitment)
{
    const auto cb = coinbase_with_commitment();
    const auto out = serialize_won_block(header80(), cb, {},
                                         /*segwit_active=*/false,
                                         /*committed_coinbase_only=*/true);
    EXPECT_FALSE(out.witness_form);
    EXPECT_FALSE(out.witness_form_suppressed);
    EXPECT_EQ(out.bytes.size(), 80u + 1u + cb.size());
}

// ---- structural: BIP144 reserialize preserves the txid preimage ------------

TEST(DgbWonBlockSerialize, Bip144ReserializePreservesNonWitnessBytes)
{
    const auto cb  = coinbase_with_commitment();
    const auto wcb = to_bip144_coinbase(cb);

    ASSERT_EQ(wcb.size(), cb.size() + 36u);
    std::vector<uint8_t> stripped;
    stripped.insert(stripped.end(), wcb.begin(), wcb.begin() + 4);            // version
    stripped.insert(stripped.end(), wcb.begin() + 6, wcb.end() - 4 - 34);     // vin/vout
    stripped.insert(stripped.end(), wcb.end() - 4, wcb.end());                // locktime
    EXPECT_EQ(stripped, cb);   // txid preimage unchanged -> header stays valid
}

TEST(DgbWonBlockSerialize, CommitmentScanRejectsTruncatedPrefix)
{
    std::vector<uint8_t> cb = {0x01, 0x00, 0x00, 0x00,
                               0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
    cb.insert(cb.end(), 31, 0x00);   // one byte short of the 32-byte commitment
    EXPECT_FALSE(coinbase_has_witness_commitment(cb));
}

} // namespace
