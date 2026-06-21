// ---------------------------------------------------------------------------
// dgb_template_other_txs_test -- pins coin/template_other_txs.hpp, the producer
// bridge that decodes the embedded work template's transactions[] (the GBT data
// the miner is funded with, shaped by make_mempool_tx_source) back into the
// MutableTransaction vector the won-block reconstructor's template_other_txs_fn
// seam frames as [gentx] ++ other_txs.
//
// This closes the loop between the two already-pinned halves:
//   * make_mempool_tx_source (embedded_tx_select.cpp)  -- Mempool -> GBT txs[]
//   * make_reconstruct_closure_from_template (#82)      -- [gentx] ++ other_txs
// proving the SAME txs the template hands the miner are the txs that land in the
// reconstructed broadcast block, byte-faithfully and in template order.
//
// Links the full dgb_coin codec (it compiles the tx serialization) and the
// reconstruct closure. MUST be in BOTH build.yml --target allowlists (#143
// NOT_BUILT trap). Per-coin isolation: src/impl/dgb/ only.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <impl/dgb/coin/template_other_txs.hpp>
#include <impl/dgb/coin/embedded_tx_select.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/coin/transaction.hpp>
#include <impl/dgb/coin/reconstruct_closure.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

using dgb::coin::Mempool;
using dgb::coin::MutableTransaction;
using dgb::coin::TxIn;
using dgb::coin::TxOut;
using dgb::coin::TX_WITH_WITNESS;
using dgb::coin::TX_NO_WITNESS;
using dgb::coin::compute_txid;
using dgb::coin::make_mempool_tx_source;
using dgb::coin::deserialize_template_tx;
using dgb::coin::deserialize_template_other_txs;
using dgb::coin::make_template_other_txs_fn;
using dgb::coin::make_reconstruct_closure_from_template;
using dgb::coin::reconstruct_won_block_from_template;
using dgb::coin::unpack_gentx_coinbase;
using dgb::coin::SmallBlockHeaderType;
using dgb::coin::WonShareInputs;

namespace {

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

MutableTransaction make_gentx()
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;   // coinbase
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = 5000000000LL;
    tx.vout.push_back(out);
    return tx;
}

std::vector<unsigned char> noseg_bytes(const MutableTransaction& tx)
{
    auto packed = pack(TX_NO_WITNESS(tx));
    auto sp = packed.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

std::string withwit_hex(const MutableTransaction& tx)
{
    return HexStr(pack(TX_WITH_WITNESS(tx)).get_span());
}

SmallBlockHeaderType make_small_header()
{
    SmallBlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block.SetHex("00000000000000000000000000000000000000000000000000000000deadbeef");
    h.m_timestamp = 1718700000;
    h.m_bits = 0x1a0fffff;
    h.m_nonce = 0x12345678;
    return h;
}

uint256 won_hash()
{
    uint256 h; h.SetHex("00000000000000000000000000000000000000000000000000000000000000a0");
    return h;
}

} // namespace

// --- Test 1: round-trip -- the production template txs decode byte-faithfully -
// Populate a Mempool, shape it through the PRODUCTION make_mempool_tx_source,
// then decode the resulting transactions[] back through the bridge. Each decoded
// tx must re-serialize (with-witness) to the exact `data` the template carried
// and carry the exact `txid`, in template order.
TEST(DgbTemplateOtherTxs, RoundTripsProductionTemplateTxs)
{
    Mempool pool;
    MutableTransaction a = tagged_tx(10, 0);
    MutableTransaction b = tagged_tx(20, 1);
    ASSERT_TRUE(pool.add_tx(a));
    ASSERT_TRUE(pool.add_tx(b));
    pool.set_tx_fee(compute_txid(a), 700);
    pool.set_tx_fee(compute_txid(b), 300);

    auto source = make_mempool_tx_source(pool, /*max_weight=*/4'000'000);
    const auto sel = source();
    ASSERT_EQ(sel.transactions.size(), 2u);

    const auto txs = deserialize_template_other_txs(sel.transactions);
    ASSERT_EQ(txs.size(), sel.transactions.size());   // template order preserved

    for (size_t i = 0; i < txs.size(); ++i)
    {
        // Decoded tx re-serializes to the exact template `data` and `txid`.
        EXPECT_EQ(withwit_hex(txs[i]), sel.transactions[i]["data"].get<std::string>());
        EXPECT_EQ(compute_txid(txs[i]).GetHex(), sel.transactions[i]["txid"].get<std::string>());
    }
}

// --- Test 2: empty / absent transactions[] -> empty vector (coinbase-only) ----
TEST(DgbTemplateOtherTxs, EmptyTransactionsIsEmptyVector)
{
    EXPECT_TRUE(deserialize_template_other_txs(nlohmann::json::array()).empty());
    EXPECT_TRUE(deserialize_template_other_txs(nlohmann::json(nullptr)).empty());
}

// --- Test 3: malformed `data` (trailing byte) -> throws (fail-closed) ---------
TEST(DgbTemplateOtherTxs, TrailingBytesThrow)
{
    std::string good = withwit_hex(tagged_tx(10, 0));
    EXPECT_NO_THROW(deserialize_template_tx(good));
    EXPECT_THROW(deserialize_template_tx(good + "ff"), std::out_of_range);   // junk byte
}

// --- Test 4: end-to-end -- funded template txs land in the reconstructed block -
// The bridge, wired as the reconstructor's template_other_txs_fn via a per-share
// captured-transactions[] provider, reconstructs the SAME block that feeding the
// deserialized txs straight into reconstruct_won_block_from_template produces:
// [gentx] ++ the mempool-funded template txs, byte-identical.
TEST(DgbTemplateOtherTxs, ReconstructsBlockWithFundedTemplateTxs)
{
    Mempool pool;
    MutableTransaction a = tagged_tx(10, 0);
    MutableTransaction b = tagged_tx(20, 1);
    ASSERT_TRUE(pool.add_tx(a));
    ASSERT_TRUE(pool.add_tx(b));
    pool.set_tx_fee(compute_txid(a), 700);
    pool.set_tx_fee(compute_txid(b), 300);
    const auto sel = make_mempool_tx_source(pool, /*max_weight=*/4'000'000)();
    ASSERT_FALSE(sel.transactions.empty());

    auto sh = make_small_header();
    ::dgb::MerkleLink link;
    const uint256 won = won_hash();
    auto gentx_bytes = noseg_bytes(make_gentx());
    auto ug = unpack_gentx_coinbase(gentx_bytes);

    // Expected: [gentx] ++ decoded-template-txs straight through the SSOT.
    const auto other = deserialize_template_other_txs(sel.transactions);
    const auto expected =
        reconstruct_won_block_from_template(sh, link, ug.tx, ug.txid, other);

    // Actual: the run-loop shape -- closure pulls the per-share captured txs[]
    // through the bridge factory.
    auto txs_json = sel.transactions;
    auto closure = make_reconstruct_closure_from_template(
        [won, sh, link](const uint256& h) -> WonShareInputs {
            if (h != won) throw std::out_of_range("unknown share");
            return WonShareInputs{sh, link};
        },
        [gentx_bytes](const uint256&) { return gentx_bytes; },
        make_template_other_txs_fn(
            [txs_json](const uint256&) { return txs_json; }));

    auto got = closure(won);
    ASSERT_TRUE(got.has_value());
    EXPECT_FALSE(got->first.empty());
    EXPECT_EQ(got->first, expected.bytes);   // funded txs land in the block
    EXPECT_EQ(got->second, expected.hex);
}

// --- Test 5: a bad captured provider fails the whole won block CLOSED ----------
TEST(DgbTemplateOtherTxs, BadProviderFailsClosed)
{
    auto sh = make_small_header();
    ::dgb::MerkleLink link;
    const uint256 won = won_hash();
    auto gentx_bytes = noseg_bytes(make_gentx());

    nlohmann::json bad = nlohmann::json::array();
    bad.push_back({{"data", withwit_hex(tagged_tx(10, 0)) + "ff"}});   // trailing junk

    auto closure = make_reconstruct_closure_from_template(
        [won, sh, link](const uint256& h) -> WonShareInputs {
            if (h != won) throw std::out_of_range("unknown share");
            return WonShareInputs{sh, link};
        },
        [gentx_bytes](const uint256&) { return gentx_bytes; },
        make_template_other_txs_fn([bad](const uint256&) { return bad; }));

    EXPECT_FALSE(closure(won).has_value());   // decode throw -> nullopt, no broadcast
}
