// ---------------------------------------------------------------------------
// dgb_embedded_coin_node_test -- guards dgb::coin::EmbeddedCoinNode, the
// SECOND caller of the build_work_template SSOT (the stratum DGBWorkSource is
// the first). Proving build_work_template has a real embedded caller is what
// turns its "the two work paths cannot diverge" claim from theoretical into
// concrete (integrator directive, 2026-06-19).
//
// What it pins:
//   1. SSOT routing -- getwork()/make_inputs() emit EXACTLY what
//      build_work_template() emits for the same chain-derived inputs (the
//      embedded node fabricates nothing of its own).
//   2. Consensus pass-through -- coinbasevalue is resolved via the #207
//      resolve_coinbase_value -> subsidy_func SSOT (embedded path, no GBT).
//   3. Truthful absence -- previousblockhash is held back on a chain with no
//      real tip hash and emitted (byte-identical to the hash_format.hpp SSOT)
//      once the tip carries a block_hash; transactions[] stays empty and bits
//      is never present.
//
// Links the same proven SCC set as dgb_work_source_test (header_chain.hpp +
// embedded_coinbase_value.hpp + core/pow.hpp reach the core/dgb libs). MUST
// also be in BOTH build.yml --target allowlists (#143 NOT_BUILT trap).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <limits>
#include <optional>

#include <gtest/gtest.h>

#include <impl/dgb/coin/embedded_coin_node.hpp>
#include <impl/dgb/coin/hash_format.hpp>
#include <impl/dgb/coin/dgb_block_algo.hpp>

using c2pool::dgb::HeaderChain;
using c2pool::dgb::HeaderSample;
using dgb::coin::EmbeddedCoinNode;
using dgb::coin::WorkTemplateInputs;
using dgb::coin::build_work_template;
using dgb::coin::u256_be_display_hex;
using dgb::coin::DGB_BLOCK_VERSION_SCRYPT;

namespace {

// Header nVersion with the Scrypt algo nibble (PRIMARY default | Scrypt==0).
constexpr int32_t SCRYPT = 2 | DGB_BLOCK_VERSION_SCRYPT;

// Deterministic stand-in for CoinParams::subsidy_func; the real schedule is
// oracle-conformed in test_dgb_subsidy.cpp. Here we only need a known mapping
// to prove the value flows through resolve_coinbase_value verbatim.
core::SubsidyFunc make_subsidy() {
    return [](uint32_t height) -> uint64_t { return 1000ull + height; };
}

// Expected GBT template version (build_work_template's pin).
constexpr uint32_t EXPECTED_VERSION =
    0x20000000u | static_cast<uint32_t>(DGB_BLOCK_VERSION_SCRYPT);

} // namespace

// 1. make_inputs() + build_work_template() == the node's emitted template.
TEST(DgbEmbeddedCoinNode, RoutesThroughBuildWorkTemplateSSOT)
{
    HeaderChain hc;
    hc.validate_and_append(HeaderSample{SCRYPT, 1000, 100});   // one Scrypt tip

    EmbeddedCoinNode node(hc, make_subsidy());

    const int64_t curtime = 1718800000;
    const WorkTemplateInputs in = node.make_inputs(curtime);
    const nlohmann::json ssot = build_work_template(in);

    // The node, fed the same curtime, must reproduce the SSOT byte-for-byte.
    EXPECT_EQ(node.make_inputs(curtime).next_height, in.next_height);
    EXPECT_EQ(build_work_template(node.make_inputs(curtime)).dump(), ssot.dump());
}

// 2. Chain-derived fields + consensus pass-through.
TEST(DgbEmbeddedCoinNode, FieldsAndCoinbaseValueFromChainSSOT)
{
    HeaderChain hc;
    hc.validate_and_append(HeaderSample{SCRYPT, 1000, 100});

    EmbeddedCoinNode node(hc, make_subsidy());
    const WorkTemplateInputs in = node.make_inputs(/*curtime=*/42);
    const nlohmann::json t = build_work_template(in);

    const uint32_t h = hc.next_block_height();
    EXPECT_EQ(t["height"].get<uint32_t>(), h);
    EXPECT_EQ(t["coinbasevalue"].get<uint64_t>(), 1000ull + h);   // subsidy_func(h)+0 fees
    EXPECT_EQ(t["version"].get<uint32_t>(), EXPECTED_VERSION);
    EXPECT_EQ(t["mintime"].get<int64_t>(), hc.median_time_past() + 1);
    EXPECT_EQ(t["curtime"].get<int64_t>(), 42);
    EXPECT_TRUE(t["transactions"].is_array());
    EXPECT_TRUE(t["transactions"].empty());
    EXPECT_FALSE(t.contains("bits"));            // held back (MultiShield V4 == V37)
}

// 3a. No real tip hash -> previousblockhash held back (truthful absence).
TEST(DgbEmbeddedCoinNode, PrevhashHeldBackWithoutRealTipHash)
{
    HeaderChain hc;                              // empty: tip_hash() == nullopt
    EmbeddedCoinNode node(hc, make_subsidy());
    EXPECT_FALSE(build_work_template(node.make_inputs(0)).contains("previousblockhash"));

    // Appended tip with block_hash==0 sentinel is still "no real tip hash".
    hc.validate_and_append(HeaderSample{SCRYPT, 1000, 100});
    EXPECT_FALSE(build_work_template(node.make_inputs(0)).contains("previousblockhash"));
}

// 3b. Real tip hash -> previousblockhash emitted via the hash_format SSOT.
TEST(DgbEmbeddedCoinNode, PrevhashEmittedByteIdenticalToHashFormatSSOT)
{
    HeaderChain hc;
    HeaderSample s{SCRYPT, 1000, 100};
    s.block_hash = dgb::coin::u256(0xdeadbeefull);   // populate a real tip id
    hc.validate_and_append(s);

    EmbeddedCoinNode node(hc, make_subsidy());
    const nlohmann::json t = build_work_template(node.make_inputs(0));
    ASSERT_TRUE(t.contains("previousblockhash"));
    EXPECT_EQ(t["previousblockhash"].get<std::string>(),
              u256_be_display_hex(dgb::coin::u256(0xdeadbeefull)));
}

// 4. getwork() returns a non-fabricated WorkData (template body only).
TEST(DgbEmbeddedCoinNode, GetworkProducesTemplateWithNoFabrication)
{
    HeaderChain hc;
    hc.validate_and_append(HeaderSample{SCRYPT, 1000, 100});

    EmbeddedCoinNode node(hc, make_subsidy());
    const auto wd = node.getwork();
    EXPECT_EQ(wd.m_data["version"].get<uint32_t>(), EXPECTED_VERSION);
    EXPECT_TRUE(wd.m_data["transactions"].empty());
    EXPECT_TRUE(wd.m_hashes.empty());            // no tx hashes fabricated
    EXPECT_FALSE(node.is_synced());              // truthful: not synced yet
}

// 5. Injected tx source: the fee total folds into coinbasevalue via the #207
//    SSOT and transactions[] passes through build_work_template verbatim.
//    Codec-free: a stub source supplies an ALREADY-SHAPED selection, exactly
//    as make_mempool_tx_source would, so this guard never compiles the tx
//    serialization codec (the embedded_tx_select.cpp / dgb_embedded_tx_select_test
//    pins the real shaping over a Mempool).
TEST(DgbEmbeddedCoinNode, InjectedTxSourceFoldsFeesAndPassesTransactions)
{
    HeaderChain hc;
    hc.validate_and_append(HeaderSample{SCRYPT, 1000, 100});

    nlohmann::json txs = nlohmann::json::array();
    nlohmann::json e1; e1["data"]="00"; e1["txid"]="aa"; e1["hash"]="aa"; e1["fee"]=700;
    nlohmann::json e2; e2["data"]="01"; e2["txid"]="bb"; e2["hash"]="bb"; e2["fee"]=300;
    txs.push_back(e1); txs.push_back(e2);
    const uint64_t fees = 1000;

    EmbeddedCoinNode node(hc, make_subsidy(),
        [txs, fees]() -> dgb::coin::EmbeddedTxSelection { return {txs, fees}; });

    const uint32_t h = hc.next_block_height();
    const nlohmann::json t = build_work_template(node.make_inputs(7));
    EXPECT_EQ(t["coinbasevalue"].get<uint64_t>(), 1000ull + h + fees); // subsidy(h)+fees
    EXPECT_EQ(t["transactions"], txs);                                 // verbatim pass-through
    EXPECT_EQ(t["transactions"].size(), 2u);
}

// 6. Empty (default) tx source == byte-identical to the no-source template
//    (the #237 call-site invariant: a node with no tx source fabricates nothing).
TEST(DgbEmbeddedCoinNode, EmptyTxSourceByteIdenticalToNoSource)
{
    HeaderChain hc;
    hc.validate_and_append(HeaderSample{SCRYPT, 1000, 100});

    EmbeddedCoinNode no_src(hc, make_subsidy());
    EmbeddedCoinNode empty_src(hc, make_subsidy(), dgb::coin::EmbeddedTxSource{});

    EXPECT_EQ(build_work_template(empty_src.make_inputs(5)).dump(),
              build_work_template(no_src.make_inputs(5)).dump());
}
