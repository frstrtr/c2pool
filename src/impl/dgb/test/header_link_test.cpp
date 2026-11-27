// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The embedded DGB header ingest links on the parent (rides
// dgb_work_source_test). dgb.voidbind (2026-11-27) sat 161k blocks behind:
// every header was appended in arrival order whatever its parent, and the
// getheaders locator was the tip alone, so with a tip the peer did not have it
// answered from genesis, every header failed the MTP gate, and the walk-
// forward re-downloaded the chain in 20000-header batches. Pinned:
//   - a header is appended only onto the tip; a known one is skipped; one onto
//     an earlier retained header cuts the chain back there (the peer's
//     branch); an unconnected one is dropped;
//   - the locator is Core's shape (the tip, 10 below, doubling steps, the
//     oldest retained, genesis) and round-trips to the wire hashes.
// SHA256D-algo headers (continuity: no PoW, no MTP gate) keep it pure.
// ---------------------------------------------------------------------------

#include <impl/dgb/coin/block.hpp>
#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/header_ingest.hpp>
#include <impl/dgb/coin/header_sample_build.hpp>
#include <impl/dgb/coin/node_interface.hpp>

#include <core/hash.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifndef DGB_MAIN_SRC
#error "DGB_MAIN_SRC must name src/c2pool/main_dgb.cpp"
#endif

using c2pool::dgb::HeaderChain;
using c2pool::dgb::LinkResult;
using c2pool::dgb::ingest_linked;
using c2pool::dgb::make_header_sample;
using dgb::coin::BlockHeaderType;

namespace {

uint256 id_of(const BlockHeaderType& h)
{
    auto packed = pack(h);
    return Hash(packed.get_span());
}

BlockHeaderType header_on(const uint256& prev, uint32_t t, uint32_t nonce = 0)
{
    BlockHeaderType h;
    h.m_version = 0x20000200;   // SHA256D: continuity
    h.m_previous_block = prev;
    h.m_timestamp = t;
    h.m_bits = 0x1b0404cb;
    h.m_nonce = nonce;
    return h;
}

// `n` linked headers on `start`.
std::vector<BlockHeaderType> run_on(const uint256& start, int n, uint32_t t0, uint32_t salt = 0)
{
    std::vector<BlockHeaderType> v;
    uint256 prev = start;
    for (int i = 0; i < n; ++i) {
        v.push_back(header_on(prev, t0 + 15u * static_cast<uint32_t>(i), salt));
        prev = id_of(v.back());
    }
    return v;
}

} // namespace

TEST(DgbHeaderLink, AppendsOnlyOntoItsParent)
{
    uint256 genesis;
    genesis.SetHex("7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496");
    HeaderChain chain;
    chain.set_base_height(1);
    const auto a = run_on(genesis, 5, 1790000000);
    for (const auto& h : a)
        EXPECT_EQ(ingest_linked(chain, make_header_sample(h)), LinkResult::APPENDED);
    ASSERT_EQ(chain.tip_height(), std::optional<uint32_t>(5u));
    EXPECT_EQ(c2pool::dgb::wire_hash(*chain.tip_hash()), id_of(a[4]));

    // A known header: skipped, nothing moves.
    EXPECT_EQ(ingest_linked(chain, make_header_sample(a[2])), LinkResult::KNOWN);
    EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(5u));

    // The peer's branch from a[2]: the chain is cut back to it and follows.
    const auto b = run_on(id_of(a[2]), 3, 1790000100, /*salt=*/7);
    EXPECT_EQ(ingest_linked(chain, make_header_sample(b[0])), LinkResult::REORGED);
    EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(4u)) << "a[3], a[4] are not cut away";
    EXPECT_EQ(ingest_linked(chain, make_header_sample(b[1])), LinkResult::APPENDED);
    EXPECT_EQ(ingest_linked(chain, make_header_sample(b[2])), LinkResult::APPENDED);
    EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(6u));
    EXPECT_EQ(c2pool::dgb::wire_hash(*chain.tip_hash()), id_of(b[2]));

    // Unconnected (an answer from genesis, a random parent): dropped.
    uint256 stranger;
    stranger.SetHex("1234");
    EXPECT_EQ(ingest_linked(chain, make_header_sample(header_on(stranger, 1790000500))), LinkResult::UNCONNECTED);
    EXPECT_EQ(ingest_linked(chain, make_header_sample(header_on(genesis, 1790000600, 99))), LinkResult::UNCONNECTED);
    EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(6u));
}

TEST(DgbHeaderLink, TheLiveIngestLinksTheBatch)
{
    uint256 genesis;
    genesis.SetHex("7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496");
    HeaderChain chain;
    chain.set_base_height(1);
    dgb::interfaces::Node node;
    auto sub = c2pool::dgb::wire_header_ingest(node, chain);
    const auto a = run_on(genesis, 6, 1790000000);
    node.new_headers.happened(std::vector<BlockHeaderType>(a.begin(), a.begin() + 4));
    ASSERT_EQ(chain.tip_height(), std::optional<uint32_t>(4u));
    // The same batch again plus the next two (a resend from an older locator):
    // the known ones are skipped, the new ones appended once.
    node.new_headers.happened(a);
    ASSERT_EQ(chain.tip_height(), std::optional<uint32_t>(6u)) << "known headers appended again";
    // A batch from genesis (the wedge): nothing connects, nothing appended.
    node.new_headers.happened(run_on(genesis, 4, 1780000000, /*salt=*/3));
    EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(6u));
    EXPECT_EQ(c2pool::dgb::wire_hash(*chain.tip_hash()), id_of(a[5]));
}

TEST(DgbHeaderLink, TheLocatorHasCoresShape)
{
    uint256 genesis;
    genesis.SetHex("7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496");
    HeaderChain chain;
    chain.set_base_height(1);
    const auto a = run_on(genesis, 40, 1790000000);
    for (const auto& h : a)
        ASSERT_EQ(ingest_linked(chain, make_header_sample(h)), LinkResult::APPENDED);
    const auto loc = c2pool::dgb::getheaders_locator(chain, genesis);
    // Core's GetLocator over heights 39..0: 39..29 one by one, then 28, 26,
    // 22, 14 (steps 1, 2, 4, 8) and the oldest, 0.
    const std::vector<int> want = {39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 26, 22, 14, 0};
    ASSERT_EQ(loc.size(), want.size() + 1);
    for (size_t i = 0; i < want.size(); ++i)
        EXPECT_EQ(loc[i], id_of(a[want[i]])) << i;
    EXPECT_EQ(loc.back(), genesis);
    // An empty chain: genesis alone.
    HeaderChain empty;
    const auto g = c2pool::dgb::getheaders_locator(empty, genesis);
    ASSERT_EQ(g.size(), 1u);
    EXPECT_EQ(g[0], genesis);
}

TEST(DgbHeaderLink, MainDgbSendsTheFullLocatorAndUnknownCommandsAreQuiet)
{
    std::ifstream f(DGB_MAIN_SRC);
    ASSERT_TRUE(f.good());
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string main = ss.str();
    EXPECT_NE(main.find("const std::vector<uint256> locator = c2pool::dgb::getheaders_locator("), std::string::npos);
    EXPECT_EQ(main.find("(tip->limb[i] >> (8 * j))"), std::string::npos) << "a tip-only locator";

    const auto p2p = std::filesystem::path(DGB_MAIN_SRC).parent_path().parent_path() / "impl" / "dgb" / "coin"
                     / "p2p_node.hpp";
    std::ifstream g(p2p);
    std::stringstream sg;
    sg << g.rdbuf();
    const std::string node = sg.str();
    EXPECT_NE(node.find("note_unknown_command(rmsg->m_command, rmsg->m_data.size());"), std::string::npos);
    EXPECT_EQ(node.find("LOG_ERROR << \"NodeP2P: \" << ec.what();"), std::string::npos)
        << "an ERROR line per unknown message";
}
