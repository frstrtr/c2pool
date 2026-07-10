// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb_coinbase_value_parity_test -- END-TO-END GBT-parity KAT for the embedded
// coinbasevalue.
//
// The other dgb embedded tests pin each LINK of the chain in isolation:
//   * dgb_embedded_tx_select_test  -- make_mempool_tx_source shapes a Mempool
//                                     selection and sums total_fees.
//   * dgb_embedded_coin_node_test  -- a STUB tx source folds total_fees into
//                                     coinbasevalue via resolve_coinbase_value.
//   * dgb_work_source_test         -- the stratum path derives subsidy at era
//                                     boundaries and honours a present GBT
//                                     coinbasevalue verbatim.
//
// What was NOT pinned anywhere: the ASSEMBLED chain. This test drives a
// POPULATED embedded Mempool through the PRODUCTION make_mempool_tx_source ->
// EmbeddedCoinNode -> build_work_template path (the exact wiring main_dgb.cpp:233
// stands up) and asserts the emitted coinbasevalue is EXACTLY the figure
// digibyted's getblocktemplate reports for the same template:
//
//     coinbasevalue == subsidy(next_height) + sum(included-tx fees)
//
// This is the parity gate the integrator required (2026-06-20) before the
// embedded subsidy+fees derivation may stand in for the external-daemon GBT
// "coinbasevalue": the locally-built value must equal GBT bit-for-bit (so
// displacing the fallback is behaviour-preserving), and the GBT figure must
// stay authoritative when present (the HARD INVARIANT in embedded_coinbase_value.hpp).
//
// Oracle: dgb::CoinParams::subsidy (config_coin.hpp) is a bit-for-bit replica
// of the p2pool-dgb-scrypt get_subsidy() oracle, so the subsidy half of the GBT
// figure IS the spec. The era-boundary subsidy numbers are the captured oracle
// vectors (shared with dgb_work_source_test / test_dgb_subsidy.cpp).
//
// Links the FULL dgb_coin codec (Mempool -> transaction.hpp) like
// dgb_embedded_tx_select_test -- it exercises the real serialization shaper,
// NOT the stub. MUST also be in BOTH build.yml --target allowlists (#143
// NOT_BUILT trap).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include <impl/dgb/coin/embedded_coin_node.hpp>     // EmbeddedCoinNode, resolve_coinbase_value
#include <impl/dgb/coin/embedded_tx_select.hpp>     // make_mempool_tx_source (PRODUCTION source)
#include <impl/dgb/coin/mempool.hpp>                // Mempool, MutableTransaction
#include <impl/dgb/coin/transaction.hpp>            // compute_txid
#include <impl/dgb/coin/header_chain.hpp>           // HeaderChain, HeaderSample
#include <impl/dgb/coin/dgb_block_algo.hpp>         // DGB_BLOCK_VERSION_SCRYPT
#include <impl/dgb/config_coin.hpp>                 // dgb::CoinParams::subsidy (oracle SSOT)
#include <impl/dgb/config_pool.hpp>                 // dgb::PoolConfig::BLOCK_MAX_WEIGHT

#include <core/pow.hpp>                             // core::SubsidyFunc

using c2pool::dgb::HeaderChain;
using c2pool::dgb::HeaderSample;
using dgb::coin::EmbeddedCoinNode;
using dgb::coin::Mempool;
using dgb::coin::MutableTransaction;
using dgb::coin::TxIn;
using dgb::coin::TxOut;
using dgb::coin::compute_txid;
using dgb::coin::make_mempool_tx_source;
using dgb::coin::build_work_template;
using dgb::coin::resolve_coinbase_value;
using dgb::coin::DGB_BLOCK_VERSION_SCRYPT;

namespace {

// Header nVersion with the Scrypt algo nibble (PRIMARY default | Scrypt==0) --
// identical to dgb_embedded_coin_node_test.
constexpr int32_t SCRYPT = 2 | DGB_BLOCK_VERSION_SCRYPT;

// The LIVE CoinParams indirection -- byte-identical to params.hpp p.subsidy_func
// and dgb_work_source_test's fixture (dgb::CoinParams::subsidy = oracle SSOT).
core::SubsidyFunc oracle_subsidy() {
    return [](uint32_t height) -> uint64_t { return dgb::CoinParams::subsidy(height); };
}

// Captured p2pool-dgb-scrypt oracle subsidy on each side of every reward-era
// boundary -- the SAME vectors dgb_work_source_test pins. Reusing the captured
// numbers (not just the live function) double-locks the parity figure.
struct EraVec { uint32_t height; uint64_t subsidy; const char* era; };
constexpr EraVec kEraBoundaries[] = {
    {67199,   8000000000ULL, "phase1-fixed last"},
    {67200,   7960000000ULL, "phase2 -0.5%/wk first"},
    {399999,  6746441103ULL, "phase2 last"},
    {400000,  2434410000ULL, "phase3 -1%/wk first"},
    {1429999, 2157824200ULL, "phase3 last"},
    {1430000, 1078500000ULL, "phase4 monthly-decay first"},
};

// Minimal, distinct fee-known tx tagged by its output value (mirrors the
// builder in dgb_embedded_tx_select_test). `index` keeps the prevout (hence the
// txid) distinct so set_tx_fee targets each tx unambiguously.
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

// Seed a HeaderChain whose next_block_height() == `height`: set the base to
// height-1, then append a single Scrypt continuity header so size()==1 and
// next == (height-1)+1. (All era-boundary heights are > 0.) The appended
// sample carries no block_hash, so tip_hash() stays nullopt -- previousblockhash
// is held back, which is irrelevant to the coinbasevalue this KAT pins.
void seed_chain_at(HeaderChain& hc, uint32_t height)
{
    hc.set_base_height(height - 1);
    hc.validate_and_append(HeaderSample{SCRYPT, 1000, 100});
}

} // namespace

// 1. THE PARITY GATE. A populated embedded Mempool, driven through the real
//    make_mempool_tx_source -> EmbeddedCoinNode -> build_work_template path,
//    must emit coinbasevalue == subsidy(next_height) + sum(mempool fees) at
//    every reward era -- bit-for-bit the figure digibyted's GBT reports.
TEST(DgbCoinbaseValueParity, EmbeddedEqualsGbtFormulaWithMempoolFees)
{
    // Three fee-known txs; their fees sum to the value digibyted folds into the
    // GBT coinbasevalue for an identical tx set.
    const uint64_t f1 = 11000, f2 = 23000, f3 = 4000;
    const uint64_t total_fees = f1 + f2 + f3;

    for (const auto& v : kEraBoundaries) {
        HeaderChain hc;
        seed_chain_at(hc, v.height);
        ASSERT_EQ(hc.next_block_height(), v.height) << "seed height mismatch at " << v.era;

        Mempool pool;
        MutableTransaction a = tagged_tx(10, 0);
        MutableTransaction b = tagged_tx(20, 1);
        MutableTransaction c = tagged_tx(30, 2);
        ASSERT_TRUE(pool.add_tx(a));
        ASSERT_TRUE(pool.add_tx(b));
        ASSERT_TRUE(pool.add_tx(c));
        pool.set_tx_fee(compute_txid(a), f1);
        pool.set_tx_fee(compute_txid(b), f2);
        pool.set_tx_fee(compute_txid(c), f3);

        // PRODUCTION wiring: exactly main_dgb.cpp:233's construction.
        EmbeddedCoinNode node(
            hc, oracle_subsidy(),
            make_mempool_tx_source(pool, dgb::PoolConfig::BLOCK_MAX_WEIGHT));

        const nlohmann::json t = build_work_template(node.make_inputs(/*curtime=*/1718800000));

        // The GBT figure digibyted would report for this template.
        const uint64_t gbt_coinbasevalue = v.subsidy + total_fees;

        EXPECT_EQ(t["height"].get<uint32_t>(), v.height);
        EXPECT_EQ(t["coinbasevalue"].get<uint64_t>(), gbt_coinbasevalue)
            << "embedded coinbasevalue diverged from GBT subsidy+fees at " << v.era;
        // All three fee-known txs must be present in transactions[] (no silent drop).
        EXPECT_EQ(t["transactions"].size(), 3u) << "tx count wrong at " << v.era;
        // And the live oracle function agrees with the captured vector.
        EXPECT_EQ(dgb::CoinParams::subsidy(v.height), v.subsidy) << "oracle drift at " << v.era;
    }
}

// 2. BEHAVIOUR-PRESERVING DISPLACEMENT. The embedded derivation (no GBT) must
//    reproduce EXACTLY what resolve_coinbase_value returns when handed the GBT
//    figure for the same inputs -- i.e. swapping the external-daemon
//    coinbasevalue for the local one changes nothing when they agree.
TEST(DgbCoinbaseValueParity, EmbeddedIdenticalToGbtPresentPath)
{
    const auto subsidy = oracle_subsidy();
    for (const auto& v : kEraBoundaries) {
        for (uint64_t fees : {uint64_t{0}, uint64_t{1}, uint64_t{987654321}}) {
            const uint64_t embedded =
                resolve_coinbase_value(subsidy, v.height, fees, /*gbt=*/std::nullopt);
            const uint64_t gbt_present =
                resolve_coinbase_value(subsidy, v.height, fees,
                                       /*gbt=*/std::optional<uint64_t>(v.subsidy + fees));
            EXPECT_EQ(embedded, gbt_present)
                << "embedded != GBT-present at " << v.era << " fees=" << fees;
            EXPECT_EQ(embedded, v.subsidy + fees);
        }
    }
}

// 3. GBT FALLBACK STAYS AUTHORITATIVE. When a GBT coinbasevalue is present it is
//    returned VERBATIM even if it diverges from the local derivation -- the
//    embedded path NEVER overrides a live digibyted figure (HARD INVARIANT).
TEST(DgbCoinbaseValueParity, GbtPresentIsHonouredVerbatimEvenOnDivergence)
{
    const auto subsidy = oracle_subsidy();
    const uint32_t h = 400000;
    // A deliberately "wrong" GBT figure (digibyted is authoritative regardless).
    const uint64_t bogus_gbt = 424242ULL;
    EXPECT_EQ(resolve_coinbase_value(subsidy, h, /*fees=*/5000, std::optional<uint64_t>(bogus_gbt)),
              bogus_gbt);
}

// 4. EMPTY MEMPOOL -> PURE SUBSIDY (no fabricated fees). End-to-end through the
//    real source: an empty pool emits coinbasevalue == subsidy(next_height)
//    exactly and an empty transactions[] (truthful absence).
TEST(DgbCoinbaseValueParity, EmptyMempoolEmitsPureSubsidy)
{
    HeaderChain hc;
    seed_chain_at(hc, /*height=*/67200);

    Mempool empty_pool;
    EmbeddedCoinNode node(
        hc, oracle_subsidy(),
        make_mempool_tx_source(empty_pool, dgb::PoolConfig::BLOCK_MAX_WEIGHT));

    const nlohmann::json t = build_work_template(node.make_inputs(/*curtime=*/42));
    EXPECT_EQ(t["coinbasevalue"].get<uint64_t>(), dgb::CoinParams::subsidy(67200));
    EXPECT_TRUE(t["transactions"].is_array());
    EXPECT_TRUE(t["transactions"].empty());
}