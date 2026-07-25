// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc_template_other_txs (rides btc_share_test) -- pins
// coin/template_other_txs.hpp, the producer bridge that decodes the captured
// GBT work template's transactions[] (the conformant {data,txid,hash,fee} shape
// bitcoind's getblocktemplate emits, retained per-job by TemplateCapture / #837)
// back into the MutableTransaction vector the won-block reconstructor's
// template_other_txs_fn seam frames as [gentx] ++ other_txs (#839).
//
// This closes the decode half of the loop: the SAME txs the captured template
// carried are the txs that land in the reconstructed broadcast block, byte-
// faithfully and in template order. The header depends ONLY on transaction.hpp,
// so this KAT stands alone off master (no reconstruct-closure / TemplateCapture
// link -- those slices land separately; the run-loop composition is slice 7).
//
// Rides the already-allowlisted btc_share_test executable, so no build.yml
// --target change is needed (#143 NOT_BUILT trap). p2pool-merged-v36 surface:
// NONE. Per-coin isolation: src/impl/btc/ only.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/btc/coin/template_other_txs.hpp>
#include <impl/btc/coin/transaction.hpp>

namespace {

using btc::coin::MutableTransaction;
using btc::coin::TxIn;
using btc::coin::TxOut;
using btc::coin::TX_WITH_WITNESS;
using btc::coin::TX_NO_WITNESS;
using btc::coin::deserialize_template_tx;
using btc::coin::deserialize_template_other_txs;
using btc::coin::make_template_other_txs_fn;

// A minimal witnessless payment tx tagged by output value + prevout index, so
// two entries in one template are distinguishable after the round trip.
MutableTransaction tagged_tx(int64_t value, uint32_t index)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = index;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = value;
    tx.vout.push_back(out);
    return tx;
}

// The with-witness `data` hex the GBT template carries (== non-witness bytes for
// a witnessless tx: no segwit marker is emitted when HasWitness()==false).
// Single-expression: the temporary PackStream lives to the end of the full
// expression, so get_span() does not dangle (cf. reconstruct_test.cpp note).
std::string withwit_hex(const MutableTransaction& tx)
{
    return HexStr(pack(TX_WITH_WITNESS(tx)).get_span());
}

uint256 txid(const MutableTransaction& tx)
{
    return Hash(pack(TX_NO_WITNESS(tx)).get_span());
}

// Emulate the captured GBT transactions[]: an ordered array of {data,txid}.
nlohmann::json gbt_entry(const MutableTransaction& tx)
{
    nlohmann::json e;
    e["data"] = withwit_hex(tx);
    e["txid"] = txid(tx).GetHex();
    return e;
}

} // namespace

// --- Test 1: round-trip -- template txs decode byte-faithfully, in order ------
// Each decoded tx must re-serialize (with-witness) to the exact `data` the
// template carried and carry the exact txid, in template order.
TEST(BtcTemplateOtherTxs, RoundTripsTemplateTxs)
{
    MutableTransaction a = tagged_tx(10, 0);
    MutableTransaction b = tagged_tx(20, 1);
    nlohmann::json transactions = nlohmann::json::array({gbt_entry(a), gbt_entry(b)});

    const auto txs = deserialize_template_other_txs(transactions);
    ASSERT_EQ(txs.size(), 2u);                          // template order preserved

    EXPECT_EQ(withwit_hex(txs[0]), transactions[0]["data"].get<std::string>());
    EXPECT_EQ(txid(txs[0]).GetHex(), transactions[0]["txid"].get<std::string>());
    EXPECT_EQ(withwit_hex(txs[1]), transactions[1]["data"].get<std::string>());
    EXPECT_EQ(txid(txs[1]).GetHex(), transactions[1]["txid"].get<std::string>());
    // Distinguishable -> order really is [a, b], not swapped.
    EXPECT_EQ(txs[0].vout[0].value, 10);
    EXPECT_EQ(txs[1].vout[0].value, 20);
}

// --- Test 2: empty / absent transactions[] -> empty vector (coinbase-only) ----
TEST(BtcTemplateOtherTxs, EmptyTransactionsIsEmptyVector)
{
    EXPECT_TRUE(deserialize_template_other_txs(nlohmann::json::array()).empty());
    EXPECT_TRUE(deserialize_template_other_txs(nlohmann::json(nullptr)).empty());
}

// --- Test 3: malformed `data` (trailing byte) -> throws (fail-closed) ---------
TEST(BtcTemplateOtherTxs, TrailingBytesThrow)
{
    const std::string good = withwit_hex(tagged_tx(10, 0));
    EXPECT_NO_THROW(deserialize_template_tx(good));
    EXPECT_THROW(deserialize_template_tx(good + "ff"), std::out_of_range);   // junk byte
    // ... and it fails the whole array closed, not just the bad entry.
    nlohmann::json transactions = nlohmann::json::array();
    transactions.push_back({{"data", good + "ff"}});
    EXPECT_THROW(deserialize_template_other_txs(transactions), std::out_of_range);
}

// --- Test 4: provider factory -- the run-loop wire shape ----------------------
// make_template_other_txs_fn wraps a per-share captured-transactions[] provider
// (TemplateCapture::provider() shape) into the template_other_txs_fn seam. A hit
// decodes the retained template; a miss (empty array, TemplateCapture's
// documented miss policy) yields a coinbase-only empty vector.
TEST(BtcTemplateOtherTxs, ProviderFactoryDecodesCapturedTemplate)
{
    MutableTransaction a = tagged_tx(30, 0);
    nlohmann::json captured = nlohmann::json::array({gbt_entry(a)});

    uint256 won;   won.SetHex("00000000000000000000000000000000000000000000000000000000000000a0");
    uint256 other; other.SetHex("00000000000000000000000000000000000000000000000000000000000000b0");

    auto fn = make_template_other_txs_fn(
        [won, captured](const uint256& h) -> nlohmann::json {
            return h == won ? captured : nlohmann::json::array();   // miss -> empty
        });

    const auto hit = fn(won);
    ASSERT_EQ(hit.size(), 1u);
    EXPECT_EQ(hit[0].vout[0].value, 30);
    EXPECT_EQ(withwit_hex(hit[0]), captured[0]["data"].get<std::string>());

    EXPECT_TRUE(fn(other).empty());   // coinbase-only on capture miss
}
