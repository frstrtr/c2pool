// ---------------------------------------------------------------------------
// dgb_header_ingest_test -- guards c2pool::dgb::wire_header_ingest, the
// connector that feeds the embedded P2P header-download feed
// (dgb::interfaces::Node::new_headers, fired by coin/p2p_node.hpp's
// ADD_P2P_HANDLER(headers)) into HeaderChain::validate_and_append through the
// make_header_sample SSOT. This is what turns the HeaderChain from a unit-test
// fixture into a chain that advances on LIVE wire headers (lighting up
// tip_hash() -> previousblockhash for the embedded work template).
//
// What it pins:
//   1. Routing -- a header announced on new_headers lands in the chain via
//      make_header_sample (block_hash = sha256d(header)) + validate_and_append.
//   2. Batch fidelity -- a multi-header batch is ingested in arrival order; the
//      tip is the LAST header and the chain grew by the full batch length.
//   3. The connector is the driver -- an un-wired node ingests nothing
//      (no hidden side path appends headers).
//   4. Disposition is DELEGATED, not overridden -- a header validate_and_append
//      REJECTS (unknown algo bits) never reaches the chain; the connector adds
//      no policy of its own and never force-appends.
//
// LIVE PoW gate: make_header_sample now fills pow_hash = scrypt(header) for
// Scrypt-algo headers, so validate_and_append's satisfaction check (pow_hash <=
// target) fires on the ingest path. The Scrypt fixtures below therefore carry
// GENUINE PoW: an easy max-compact target plus a nonce searched until the real
// scrypt digest satisfies it (~2 scrypt evaluations). This keeps the WIRING
// assertions deterministic without hand-mining a hard block -- the sha256d
// block-id KAT (Bitcoin genesis) lives in dgb_header_sample_build_test.
//
// Pulls dgb::interfaces::Node (block.hpp codec) + header_chain.hpp + the
// make_header_sample SSOT, so it links the proven dgb OBJECT-lib SCC set like
// dgb_header_sample_build_test. MUST also appear in BOTH build.yml --target
// allowlists (#143 NOT_BUILT trap).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include <impl/dgb/coin/header_ingest.hpp>
#include <impl/dgb/coin/node_interface.hpp>
#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/header_sample_build.hpp>
#include <impl/dgb/coin/hash_format.hpp>
#include <impl/dgb/coin/dgb_block_algo.hpp>

using c2pool::dgb::HeaderChain;
using c2pool::dgb::make_header_sample;
using c2pool::dgb::wire_header_ingest;
using dgb::coin::BlockHeaderType;
using dgb::coin::u256_be_display_hex;
using dgb::coin::DGB_BLOCK_VERSION_ALGO;

namespace {

// An easy max-compact target: nBits 0x207fffff expands (compact_to_target,
// arith_uint256::SetCompact) to ~2^255, comfortably below the unconfigured
// chain's (absent) pow_limit ceiling. A uniformly-random scrypt digest lands at
// or under it with ~1/2 probability, so the nonce search below terminates in a
// couple of evaluations.
constexpr uint32_t EASY_BITS = 0x207fffffu;

// Build a Scrypt header (version 1 -> algo nibble 0 == SCRYPT) carrying real,
// satisfiable PoW: starting from seed_nonce, advance the nonce until the live
// make_header_sample scrypt(header) digest is <= the declared target. Returns a
// header validate_and_append's now-live satisfaction gate accepts.
BlockHeaderType satisfiable_scrypt_header(uint32_t seed_nonce, uint32_t timestamp)
{
    BlockHeaderType h;
    h.m_version = 1;
    h.m_previous_block.SetNull();
    h.m_merkle_root.SetHex(
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    h.m_timestamp = timestamp;
    h.m_bits      = EASY_BITS;

    for (uint32_t n = seed_nonce; n < seed_nonce + 1000000u; ++n) {
        h.m_nonce = n;
        auto s = make_header_sample(h);
        if (!(s.pow_hash > s.target))   // pow_hash <= target -> PoW satisfied
            return h;
    }
    ADD_FAILURE() << "no satisfiable nonce found for EASY_BITS (astronomically "
                     "unlikely -- check compact_to_target / scrypt wiring)";
    return h;
}

// An unknown-algo header: algo nibble 1 (0x0100) maps to no DigiByte algo, so
// dgb_header_disposition() -> REJECT. validate_and_append must drop it.
BlockHeaderType unknown_algo_header()
{
    BlockHeaderType h = satisfiable_scrypt_header(0, 1231006505u);
    h.m_version = 1 | 0x0100;  // nibble 1 == ALGO_UNKNOWN
    return h;
}

} // namespace

// A fresh HeaderChain is empty -- no tip height, no tip hash.
TEST(HeaderIngest, EmptyChainHasNoTip)
{
    HeaderChain chain;
    EXPECT_FALSE(chain.tip_height().has_value());
    EXPECT_FALSE(chain.tip_hash().has_value());
}

// 1. A Scrypt header announced on new_headers is ingested through
//    make_header_sample + validate_and_append: the chain grows and tip_hash()
//    is the header's sha256d block id. The live scrypt PoW gate accepts it
//    because the fixture carries genuine (easy-target) PoW.
TEST(HeaderIngest, AnnouncedScryptHeaderIsIngested)
{
    HeaderChain chain;
    dgb::interfaces::Node node;
    auto sub = wire_header_ingest(node, chain);

    BlockHeaderType h = satisfiable_scrypt_header(0, 1231006505u);
    node.new_headers.happened(std::vector<BlockHeaderType>{ h });

    ASSERT_TRUE(chain.tip_height().has_value());
    ASSERT_TRUE(chain.tip_hash().has_value());
    EXPECT_EQ(u256_be_display_hex(*chain.tip_hash()),
              u256_be_display_hex(make_header_sample(h).block_hash));
}

// 2. A multi-header batch is ingested in arrival order: the tip is the LAST
//    header, and the chain grew by the full batch length (height delta == 1
//    versus a single-header chain). The second header's nTime is strictly
//    greater (MTP monotonicity gate) and its nonce-search seed distinct, so it
//    is a different, independently-satisfiable Scrypt block.
TEST(HeaderIngest, BatchIngestedInArrivalOrder)
{
    BlockHeaderType h1 = satisfiable_scrypt_header(0, 1231006505u);
    BlockHeaderType h2 = satisfiable_scrypt_header(1000, 1231006506u);

    HeaderChain one;
    dgb::interfaces::Node node_one;
    auto sub_one = wire_header_ingest(node_one, one);
    node_one.new_headers.happened(std::vector<BlockHeaderType>{ h1 });

    HeaderChain two;
    dgb::interfaces::Node node_two;
    auto sub_two = wire_header_ingest(node_two, two);
    node_two.new_headers.happened(std::vector<BlockHeaderType>{ h1, h2 });

    ASSERT_TRUE(one.tip_height().has_value());
    ASSERT_TRUE(two.tip_height().has_value());
    // The two-header chain is exactly one block taller than the one-header chain.
    EXPECT_EQ(*two.tip_height(), *one.tip_height() + 1u);
    // Tip is the LAST header of the batch, not the first.
    ASSERT_TRUE(two.tip_hash().has_value());
    EXPECT_EQ(u256_be_display_hex(*two.tip_hash()),
              u256_be_display_hex(make_header_sample(h2).block_hash));
    EXPECT_NE(u256_be_display_hex(*two.tip_hash()),
              u256_be_display_hex(make_header_sample(h1).block_hash));
}

// 3. The connector is the driver: a node with NO ingest subscription appends
//    nothing when headers are announced.
TEST(HeaderIngest, UnwiredNodeIngestsNothing)
{
    HeaderChain chain;
    dgb::interfaces::Node node;  // deliberately NOT wired

    node.new_headers.happened(
        std::vector<BlockHeaderType>{ satisfiable_scrypt_header(0, 1231006505u) });

    EXPECT_FALSE(chain.tip_height().has_value());
    EXPECT_FALSE(chain.tip_hash().has_value());
}

// 4. Disposition is delegated to validate_and_append, not overridden by the
//    connector: an unknown-algo header (REJECT) never reaches the chain.
TEST(HeaderIngest, RejectedHeaderIsNotAppended)
{
    HeaderChain chain;
    dgb::interfaces::Node node;
    auto sub = wire_header_ingest(node, chain);

    // Sanity: this header really is on the unknown-algo (reject) path.
    ASSERT_EQ(unknown_algo_header().m_version & DGB_BLOCK_VERSION_ALGO, 0x0100);

    node.new_headers.happened(std::vector<BlockHeaderType>{ unknown_algo_header() });

    EXPECT_FALSE(chain.tip_height().has_value());
    EXPECT_FALSE(chain.tip_hash().has_value());
}
