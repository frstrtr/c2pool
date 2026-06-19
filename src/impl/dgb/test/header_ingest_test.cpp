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

// Canonical Bitcoin genesis header -- same 80-byte serialization DGB uses, and
// a Scrypt header (version 1 -> algo nibble 0 == SCRYPT), so it walks the
// VALIDATE_SCRYPT path. pow_hash is left 0 by make_header_sample (trivially
// satisfies any target), and a default-ctor HeaderChain leaves pow_limit /
// target_timespan 0 so the ceiling + DigiShield gates are no-ops -- exactly the
// bootstrap posture the embedded port starts from.
BlockHeaderType genesis_header()
{
    BlockHeaderType h;
    h.m_version = 1;
    h.m_previous_block.SetNull();
    h.m_merkle_root.SetHex(
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    h.m_timestamp = 1231006505u;
    h.m_bits      = 0x1d00ffffu;
    h.m_nonce     = 2083236893u;
    return h;
}

// A second Scrypt header whose nTime is strictly greater than genesis' (the MTP
// monotonicity gate requires nTime > median-of-ancestors), with a distinct
// nonce so its sha256d block id differs from genesis'.
BlockHeaderType second_scrypt_header()
{
    BlockHeaderType h = genesis_header();
    h.m_timestamp = 1231006506u;  // genesis + 1 -> passes MTP over [genesis]
    h.m_nonce     = 12345u;       // distinct id
    return h;
}

// An unknown-algo header: algo nibble 1 (0x0100) maps to no DigiByte algo, so
// dgb_header_disposition() -> REJECT. validate_and_append must drop it.
BlockHeaderType unknown_algo_header()
{
    BlockHeaderType h = genesis_header();
    h.m_version = 1 | 0x0100;  // nibble 1 == ALGO_UNKNOWN
    return h;
}

const std::string GENESIS_ID =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

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
//    is the header's sha256d block id (the well-known genesis hash).
TEST(HeaderIngest, AnnouncedScryptHeaderIsIngested)
{
    HeaderChain chain;
    dgb::interfaces::Node node;
    auto sub = wire_header_ingest(node, chain);

    node.new_headers.happened(std::vector<BlockHeaderType>{ genesis_header() });

    ASSERT_TRUE(chain.tip_height().has_value());
    ASSERT_TRUE(chain.tip_hash().has_value());
    EXPECT_EQ(u256_be_display_hex(*chain.tip_hash()), GENESIS_ID);
}

// 2. A multi-header batch is ingested in arrival order: the tip is the LAST
//    header, and the chain grew by the full batch length (height delta == 1
//    versus a single-header chain).
TEST(HeaderIngest, BatchIngestedInArrivalOrder)
{
    HeaderChain one;
    dgb::interfaces::Node node_one;
    auto sub_one = wire_header_ingest(node_one, one);
    node_one.new_headers.happened(std::vector<BlockHeaderType>{ genesis_header() });

    HeaderChain two;
    dgb::interfaces::Node node_two;
    auto sub_two = wire_header_ingest(node_two, two);
    node_two.new_headers.happened(
        std::vector<BlockHeaderType>{ genesis_header(), second_scrypt_header() });

    ASSERT_TRUE(one.tip_height().has_value());
    ASSERT_TRUE(two.tip_height().has_value());
    // The two-header chain is exactly one block taller than the one-header chain.
    EXPECT_EQ(*two.tip_height(), *one.tip_height() + 1u);
    // Tip is the LAST header of the batch, not the first.
    ASSERT_TRUE(two.tip_hash().has_value());
    EXPECT_EQ(u256_be_display_hex(*two.tip_hash()),
              u256_be_display_hex(make_header_sample(second_scrypt_header()).block_hash));
    EXPECT_NE(u256_be_display_hex(*two.tip_hash()), GENESIS_ID);
}

// 3. The connector is the driver: a node with NO ingest subscription appends
//    nothing when headers are announced.
TEST(HeaderIngest, UnwiredNodeIngestsNothing)
{
    HeaderChain chain;
    dgb::interfaces::Node node;  // deliberately NOT wired

    node.new_headers.happened(std::vector<BlockHeaderType>{ genesis_header() });

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
