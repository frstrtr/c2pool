// SPDX-License-Identifier: AGPL-3.0-or-later
// DOGE 'headers' parsing: what the AuxPoW parser hands on when a message does
// not parse to its end, and the parent coinbase's params.
//
// doge::coin::parse_doge_headers returns the clean prefix (the entries before
// the failure that link, each to the one before it) and truncated_at, so a
// parse failure reads as a parse failure, never as a batch from another chain
// (the hash schedule cut its frontier back 19 times on such batches).
// parse_doge_headers_message (the raw headers parser seam) returns the same
// headers. The parent coinbase is read and written witness-allowed, without
// MWEB; its txid stays witness-stripped (doge::coin::parent_coinbase_txid).

#include <gtest/gtest.h>

#include "doge_headers_witness_fixtures.hpp"

#include <impl/doge/coin/auxpow.hpp>
#include <impl/doge/coin/auxpow_header.hpp>
#include <impl/ltc/coin/transaction.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <span>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;
using ltc::coin::BlockHeaderType;

// DOGE_HEADERS_WIT_5641398: count byte, then entries h5641397 [1, 882),
// h5641398 [882, 1738) (witness coinbase; flag byte at 967), h5641399
// [1738, 2634).
const Bytes FIX(doge::test::DOGE_HEADERS_WIT_5641398,
                doge::test::DOGE_HEADERS_WIT_5641398 + sizeof(doge::test::DOGE_HEADERS_WIT_5641398));
constexpr size_t E1 = 882, E2 = 1738, FLAG = 967;
const char* const H0 = "0a6813c1e49207cc3a8eab74668204b74fdd84ad66f9d8cb4bce862e11836f51";
const char* const H1 = "426e533b9fbce78bd4dbfd831cd84f8314f338caa460b533ac30016ade599a21";
const char* const H2 = "248f7d07447f1929b6ad9cd09bb95645b6344a5503ce6943cc0fe0920772eded";
const char* const TXID = "914686fec87b293b9dbe7ecfb3ed3406dfe225bf17268566cc6daaea19bc60ad";

std::string hash_hex(const BlockHeaderType& h) { return Hash(pack(h).get_span()).GetHex(); }

doge::coin::DogeHeadersParse parse(const Bytes& b) { return doge::coin::parse_doge_headers(b.data(), b.size()); }

doge::coin::CAuxPow<> witness_proof()
{
    PackStream ps(std::span<const std::byte>(reinterpret_cast<const std::byte*>(FIX.data() + E1), E2 - E1));
    doge::coin::CAuxPow<> aux;
    bool has_aux = false;
    doge::coin::parse_aux_header(ps, aux, has_aux);
    EXPECT_TRUE(has_aux);
    return aux;
}

} // namespace

TEST(DogeHeadersParse, ParentCoinbaseParams_AreCoresDefault)
{
    using Tx = ltc::coin::MutableTransaction;
    EXPECT_TRUE(doge::coin::parent_coinbase_wire_params<Tx>::value.allow_witness);
    EXPECT_FALSE(doge::coin::parent_coinbase_wire_params<Tx>::value.allow_mweb);
    EXPECT_FALSE(doge::coin::parent_coinbase_no_witness<Tx>::value.allow_witness);
}

// The helper every caller hashes the parent coinbase with: the witness-
// stripped txid (the leaf of the branch), not the wtxid.
TEST(DogeHeadersParse, ParentCoinbaseTxid_IsWitnessStripped)
{
    const auto aux = witness_proof();
    const auto& tx = aux.m_merkle_tx.m_tx;
    ASSERT_FALSE(tx.vin.at(0).scriptWitness.IsNull());
    EXPECT_EQ(doge::coin::parent_coinbase_txid(tx).GetHex(), TXID);
    EXPECT_NE(doge::coin::parent_coinbase_txid(tx), Hash(pack(ltc::coin::TX_WITH_WITNESS(tx)).get_span()));
}

TEST(DogeHeadersParse, Complete_NotTruncated)
{
    const auto r = parse(FIX);
    EXPECT_EQ(r.count, 3u);
    ASSERT_EQ(r.headers.size(), 3u);
    EXPECT_FALSE(r.truncated_at.has_value());
    EXPECT_TRUE(r.error.empty());
    EXPECT_EQ(hash_hex(r.headers[2]), H2);
}

// An entry that does not parse: the headers before it, truncated_at, and
// which entry failed, where and why.
TEST(DogeHeadersParse, EntryFails_CleanPrefixAndTruncatedAt)
{
    Bytes b = FIX;
    b[FLAG] = 0x08;  // MWEB flag on the parent coinbase: refused
    const auto r = parse(b);
    EXPECT_EQ(r.count, 3u);
    ASSERT_EQ(r.headers.size(), 1u);
    EXPECT_EQ(hash_hex(r.headers[0]), H0);
    ASSERT_TRUE(r.truncated_at.has_value());
    EXPECT_EQ(*r.truncated_at, 1u);
    EXPECT_EQ(r.failed_index, 1u);
    EXPECT_EQ(r.failed_offset, E1);
    EXPECT_NE(r.error.find("Unknown transaction optional data"), std::string::npos) << r.error;

    // The seam hands on the same headers.
    const auto v = doge::coin::parse_doge_headers_message(b.data(), b.size());
    ASSERT_EQ(v.size(), 1u);
    EXPECT_EQ(hash_hex(v[0]), H0);
}

// Entries that parsed after an undetected wrong turn are garbage: what goes
// out is cut back to the prefix that links.
TEST(DogeHeadersParse, GarbageBeforeFailure_CutToLinkedPrefix)
{
    Bytes b{0x04};                                        // 4 entries declared
    b.insert(b.end(), FIX.begin() + 1, FIX.begin() + E2);  // h5641397, h5641398
    Bytes garbage{0x01, 0x00, 0x00, 0x00};                // version 1: no AuxPoW
    garbage.insert(garbage.end(), 76, 0x11);              // parses, links to nothing
    garbage.push_back(0x00);                              // tx_count
    b.insert(b.end(), garbage.begin(), garbage.end());
    const size_t tail = b.size();
    b.insert(b.end(), 10, 0x00);                          // a truncated 4th entry

    const auto r = parse(b);
    EXPECT_EQ(r.count, 4u);
    ASSERT_EQ(r.headers.size(), 2u);
    EXPECT_EQ(hash_hex(r.headers[0]), H0);
    EXPECT_EQ(hash_hex(r.headers[1]), H1);
    ASSERT_TRUE(r.truncated_at.has_value());
    EXPECT_EQ(*r.truncated_at, 2u);
    EXPECT_EQ(r.failed_index, 3u);
    EXPECT_EQ(r.failed_offset, tail);
    EXPECT_FALSE(r.error.empty());
}

// The payload ends before the count: truncated, nothing failed to parse.
TEST(DogeHeadersParse, PayloadEndsBeforeCount_Truncated)
{
    Bytes b = FIX;
    b[0] = 0x05;
    const auto r = parse(b);
    EXPECT_EQ(r.count, 5u);
    ASSERT_EQ(r.headers.size(), 3u);
    ASSERT_TRUE(r.truncated_at.has_value());
    EXPECT_EQ(*r.truncated_at, 3u);
    EXPECT_TRUE(r.error.empty());
}

TEST(DogeHeadersParse, CountDoesNotParse_TruncatedAtZero)
{
    const Bytes b{0xfd, 0x10};  // a 3-byte CompactSize cut short
    const auto r = parse(b);
    EXPECT_TRUE(r.headers.empty());
    ASSERT_TRUE(r.truncated_at.has_value());
    EXPECT_EQ(*r.truncated_at, 0u);
    EXPECT_FALSE(r.error.empty());
}

TEST(DogeHeadersParse, Empty_NothingAndNotTruncated)
{
    const auto r = doge::coin::parse_doge_headers(nullptr, 0);
    EXPECT_TRUE(r.headers.empty());
    EXPECT_EQ(r.count, 0u);
    EXPECT_FALSE(r.truncated_at.has_value());
}
