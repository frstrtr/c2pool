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

namespace {
uint256 dgb_genesis()
{
    uint256 g;
    g.SetHex("7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496");
    return g;
}
c2pool::dgb::u256 u_of(const uint256& h)
{
    uint256 c = h;
    return c2pool::dgb::u256::from_le_bytes(reinterpret_cast<const unsigned char*>(c.begin()));
}
// A chain of `n` linked headers on genesis, through ingest_linked.
std::vector<BlockHeaderType> build(HeaderChain& chain, c2pool::dgb::ForkBuffer& fork, int n)
{
    const auto a = run_on(dgb_genesis(), n, 1790000000);
    for (const auto& h : a)
        EXPECT_EQ(ingest_linked(chain, fork, make_header_sample(h), u_of(dgb_genesis())), LinkResult::APPENDED);
    return a;
}
} // namespace

TEST(DgbHeaderLink, AppendsOnlyOntoItsParent)
{
    HeaderChain chain;   // production construction: no set_base_height
    c2pool::dgb::ForkBuffer fork;
    const auto a = build(chain, fork, 5);
    // Block 1 (the header on genesis) sits at height 1 (review 7a4373856 R2).
    ASSERT_EQ(chain.tip_height(), std::optional<uint32_t>(5u));
    EXPECT_EQ(chain.next_block_height(), 6u);
    EXPECT_EQ(c2pool::dgb::wire_hash(*chain.tip_hash()), id_of(a[4]));
    // A known header: skipped, nothing moves.
    EXPECT_EQ(ingest_linked(chain, fork, make_header_sample(a[2])), LinkResult::KNOWN);
    EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(5u));
    // Unconnected (an answer from genesis, a random parent): dropped.
    uint256 stranger;
    stranger.SetHex("1234");
    EXPECT_EQ(ingest_linked(chain, fork, make_header_sample(header_on(stranger, 1790000500))), LinkResult::UNCONNECTED);
    EXPECT_EQ(ingest_linked(chain, fork, make_header_sample(header_on(dgb_genesis(), 1790000600, 99))),
              LinkResult::UNCONNECTED);
    // A zero parent on a non-empty chain (review F2c): refused.
    EXPECT_EQ(ingest_linked(chain, fork, make_header_sample(header_on(uint256(), 1790000700))), LinkResult::UNCONNECTED);
    EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(5u));
}

// The tip switches only to a strictly longer branch above the fork point.
TEST(DgbHeaderLink, ALongerBranchSwitchesTheTip)
{
    HeaderChain chain;
    c2pool::dgb::ForkBuffer fork;
    const auto a = build(chain, fork, 5);   // heights 1..5
    const auto b = run_on(id_of(a[2]), 3, 1790000100, /*salt=*/7);   // on height 3
    EXPECT_EQ(ingest_linked(chain, fork, make_header_sample(b[0])), LinkResult::BUFFERED);
    EXPECT_EQ(ingest_linked(chain, fork, make_header_sample(b[1])), LinkResult::BUFFERED) << "as long, not longer";
    EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(5u)) << "first seen keeps the tip";
    std::size_t depth = 0;
    EXPECT_EQ(ingest_linked(chain, fork, make_header_sample(b[2]), 0, &depth), LinkResult::REORGED);
    EXPECT_EQ(depth, 2u);
    EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(6u));
    EXPECT_EQ(c2pool::dgb::wire_hash(*chain.tip_hash()), id_of(b[2]));
    EXPECT_FALSE(chain.find_index(u_of(id_of(a[3])))) << "the cut headers are still indexed";
    EXPECT_TRUE(chain.find_index(u_of(id_of(b[0]))));
}

// Review 7a4373856 F1: a rejected fork header never changes the chain, and
// the honest next header still lands on the tip.
TEST(DgbHeaderLink, ARejectedForkLeavesTheChainUnchanged)
{
    HeaderChain chain;
    c2pool::dgb::ForkBuffer fork;
    const auto a = build(chain, fork, 6);
    // A one-header fork on height 2 is never longer than the 4 above it.
    BlockHeaderType bad = header_on(id_of(a[1]), 1790000200, 3);
    bad.m_version = 0x20000100;   // unknown algo nibble: REJECT
    EXPECT_NE(ingest_linked(chain, fork, make_header_sample(bad)), LinkResult::REORGED);
    EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(6u));
    // A fork that does become longer, with its last header invalid: restored.
    std::vector<BlockHeaderType> f = run_on(id_of(a[4]), 2, 1790000300, /*salt=*/11);
    f[1].m_version = 0x20000100;
    EXPECT_EQ(ingest_linked(chain, fork, make_header_sample(f[0])), LinkResult::BUFFERED);
    EXPECT_EQ(ingest_linked(chain, fork, make_header_sample(f[1])), LinkResult::REJECTED);
    ASSERT_EQ(chain.tip_height(), std::optional<uint32_t>(6u)) << "a rejected switch cut the chain";
    EXPECT_EQ(c2pool::dgb::wire_hash(*chain.tip_hash()), id_of(a[5]));
    EXPECT_TRUE(chain.find_index(u_of(id_of(a[5])))) << "the restored tail is not indexed";
    // The honest child of the tip: appended.
    EXPECT_EQ(ingest_linked(chain, fork, make_header_sample(header_on(id_of(a[5]), 1790000400))), LinkResult::APPENDED);
    EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(7u));
}

// The review's cut demonstrations are no-ops now: one header far below the
// tip (beyond the depth bound), and a one-header fork that is not longer.
TEST(DgbHeaderLink, OneHeaderNoLongerCutsTheChain)
{
    {
        HeaderChain chain;
        c2pool::dgb::ForkBuffer fork;
        const auto a = build(chain, fork, 3000);
        EXPECT_EQ(ingest_linked(chain, fork, make_header_sample(header_on(id_of(a[0]), 1790100000))),
                  LinkResult::UNCONNECTED) << "a cut deeper than the bound";
        EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(3000u));
    }
    {
        HeaderChain chain;
        c2pool::dgb::ForkBuffer fork;
        const auto a = build(chain, fork, 30);
        BlockHeaderType easy = header_on(id_of(a[1]), 1790100000, 5);
        easy.m_version = 0x20000002;   // Scrypt, easy declared bits
        easy.m_bits = 0x207fffff;
        EXPECT_NE(ingest_linked(chain, fork, make_header_sample(easy)), LinkResult::REORGED);
        EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(30u));
        EXPECT_EQ(c2pool::dgb::wire_hash(*chain.tip_hash()), id_of(a[29]));
    }
}

TEST(DgbHeaderLink, TheLiveIngestLinksTheBatch)
{
    HeaderChain chain;
    dgb::interfaces::Node node;
    int requests = 0;
    uint32_t published = 0;
    c2pool::dgb::HeaderIngestOptions opts;
    opts.genesis = u_of(dgb_genesis());
    opts.request_headers = [&] { ++requests; };
    opts.on_tip = [&](uint32_t h) { published = h; };
    auto sub = c2pool::dgb::wire_header_ingest(node, chain, opts);
    const auto a = run_on(dgb_genesis(), 6, 1790000000);
    node.new_headers.happened(std::vector<BlockHeaderType>(a.begin(), a.begin() + 4));
    ASSERT_EQ(chain.tip_height(), std::optional<uint32_t>(4u)) << "block 1 is height 1 on the production chain";
    EXPECT_EQ(published, 4u);
    // The same batch again plus the next two (a resend from an older locator):
    // the known ones are skipped, the new ones appended once.
    node.new_headers.happened(a);
    ASSERT_EQ(chain.tip_height(), std::optional<uint32_t>(6u)) << "known headers appended again";
    EXPECT_EQ(requests, 0);
    // A batch from genesis that does not connect: nothing appended, and the
    // peer is asked again with the chain's locator.
    node.new_headers.happened(run_on(dgb_genesis(), 4, 1780000000, /*salt=*/3));
    EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(6u));
    EXPECT_EQ(c2pool::dgb::wire_hash(*chain.tip_hash()), id_of(a[5]));
    EXPECT_EQ(requests, 1);
    EXPECT_EQ(published, 6u);
}

TEST(DgbHeaderLink, TheLocatorHasCoresShape)
{
    uint256 genesis;
    genesis.SetHex("7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496");
    HeaderChain chain;
    c2pool::dgb::ForkBuffer fork;
    const auto a = run_on(genesis, 40, 1790000000);
    for (const auto& h : a)
        ASSERT_EQ(ingest_linked(chain, fork, make_header_sample(h), u_of(genesis)), LinkResult::APPENDED);
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
    // Review 7a4373856: the ingest knows genesis and asks for headers; the
    // walk-forward and inv use the chain's locator; --coin-daemon keeps a
    // driver; the HTTP thread reads the published tip; a deep switch resets
    // the tip latch.
    for (const char* line : {
             "auto header_ingest_sub  = c2pool::dgb::wire_header_ingest(coin_iface, header_chain, header_opts);",
             "coin_p2p->set_on_block_inv(header_opts.request_headers);",
             "stop_coin_header_driver = dgb::start_periodic(ioc, std::chrono::milliseconds(12000),",
             "const uint32_t hh = header_tip_pub->load();",
             "ws->reset_tip_latch();"})
        EXPECT_NE(main.find(line), std::string::npos) << line;
    size_t n = 0;
    for (size_t at = 0; (at = main.find("coin_p2p->set_locator_fn(", at)) != std::string::npos; ++at)
        ++n;
    EXPECT_EQ(n, 2u) << "both coin-peer modes walk forward from the chain's locator";

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
