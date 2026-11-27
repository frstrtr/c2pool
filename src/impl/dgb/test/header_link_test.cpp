// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The embedded DGB header ingest links on the parent (rides
// dgb_work_source_test). dgb.voidbind (2026-11-27) sat 161k blocks behind:
// every header was appended in arrival order whatever its parent, and the
// getheaders locator was the tip alone, so with a tip the peer did not have it
// answered from genesis, every header failed the MTP gate, and the walk-
// forward re-downloaded the chain in 20000-header batches. Pinned:
//   - a header is appended only onto the tip; a known one is skipped; an
//     unconnected one is dropped; an empty chain takes only the header on
//     genesis;
//   - the tip follows the branch with the most Scrypt work (2^256/(target+1)
//     per Scrypt header that meets its target within pow_limit, 0 for any
//     other header), from any retained depth; equal work keeps the first
//     seen; a rejected switch leaves the chain exactly as it was;
//   - the locator is Core's shape (the tip, 10 below, doubling steps, the
//     oldest retained, genesis) and round-trips to the wire hashes.
// ---------------------------------------------------------------------------

#include <impl/dgb/coin/block.hpp>
#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/header_ingest.hpp>
#include <impl/dgb/coin/header_sample_build.hpp>
#include <impl/dgb/coin/node_interface.hpp>

#include <core/hash.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

#ifndef DGB_MAIN_SRC
#error "DGB_MAIN_SRC must name src/c2pool/main_dgb.cpp"
#endif

using c2pool::dgb::HeaderChain;
using c2pool::dgb::HeaderSample;
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

// Synthetic samples (the ingest takes the sample): Scrypt ones with their
// PoW met (pow_hash 0; the live ingest computes scrypt), SHA256D ones.
constexpr uint32_t kBits = 0x1b0404cb;   // a mainnet-range Scrypt target
HeaderSample sample(uint64_t id, const c2pool::dgb::u256& prev, int64_t t, bool scrypt, uint32_t bits = kBits)
{
    HeaderSample s;
    s.n_version = scrypt ? 0x20000002 : 0x20000202;
    s.n_time = t;
    s.n_bits = bits;
    s.target = c2pool::dgb::compact_to_target(bits);
    s.block_hash.limb[0] = id;
    s.block_hash.limb[3] = 0x5a5a;   // never a wire id
    s.prev_hash = prev;
    return s;
}
c2pool::dgb::u256 work_of(uint32_t bits) { return c2pool::dgb::header_work(c2pool::dgb::compact_to_target(bits)); }

// The live chain (DigiByte's Scrypt pow_limit) with `n` headers on genesis,
// every even one Scrypt, 15 s apart.
struct Mixed {
    HeaderChain chain{c2pool::dgb::dgb_live_header_params(false), 0};
    c2pool::dgb::ForkBuffer fork;
    std::vector<HeaderSample> a;
};
void build_mixed(Mixed& m, int n, int64_t t0 = 1790000000)
{
    c2pool::dgb::u256 prev = u_of(dgb_genesis());
    for (int i = 0; i < n; ++i) {
        m.a.push_back(sample(static_cast<uint64_t>(i + 1), prev, t0 + 15 * i, i % 2 == 0));
        prev = m.a.back().block_hash;
        ASSERT_EQ(ingest_linked(m.chain, m.fork, m.a.back(), u_of(dgb_genesis())), LinkResult::APPENDED) << i;
    }
}
// `n` samples on `parent` (ids from `id0`), Scrypt where `scrypt(i)`.
std::vector<HeaderSample> branch(const c2pool::dgb::u256& parent, int n, int64_t t0, uint64_t id0,
                                 const std::function<bool(int)>& scrypt)
{
    std::vector<HeaderSample> v;
    c2pool::dgb::u256 prev = parent;
    for (int i = 0; i < n; ++i) {
        v.push_back(sample(id0 + static_cast<uint64_t>(i), prev, t0 + 15 * i, scrypt(i)));
        prev = v.back().block_hash;
    }
    return v;
}
// `n` SHA256D headers in wire form on `parent`, as make_header_sample builds them.
std::vector<HeaderSample> wire_run(const c2pool::dgb::u256& parent, int n, uint32_t t0, uint32_t salt)
{
    std::vector<HeaderSample> out;
    for (const auto& h : run_on(c2pool::dgb::wire_hash(parent), n, t0, salt))
        out.push_back(make_header_sample(h));
    return out;
}
} // namespace

TEST(DgbHeaderLink, AppendsOnlyOntoItsParent)
{
    HeaderChain chain;
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

// The work of a header: floor(2^256 / (target + 1)), as Core's GetBlockProof
// (and chain::target_to_average_attempts) computes it.
TEST(DgbHeaderLink, HeaderWorkIsTwoTo256OverTargetPlusOne)
{
    const auto trim = [](std::string h) {
        const auto p = h.find_first_not_of('0');
        return p == std::string::npos ? std::string("0") : h.substr(p);
    };
    for (uint32_t bits : {0x1b0404cbu, 0x1a47e953u, 0x1e0ffff0u, 0x1e0fffffu, 0x1d00ffffu, 0x207fffffu}) {
        const uint288 want = chain::target_to_average_attempts(chain::bits_to_target(bits));
        EXPECT_EQ(trim(c2pool::dgb::wire_hash(work_of(bits)).GetHex()), trim(want.GetHex())) << std::hex << bits;
    }
    c2pool::dgb::u256 max;
    for (auto& l : max.limb)
        l = ~uint64_t(0);
    EXPECT_TRUE(c2pool::dgb::header_work(c2pool::dgb::u256{}).is_zero());
    EXPECT_EQ(c2pool::dgb::header_work(max), c2pool::dgb::u256(1));
    c2pool::dgb::u256 half;
    half.limb[3] = uint64_t(1) << 63;
    EXPECT_EQ(c2pool::dgb::header_work(c2pool::dgb::u256(1)), half);
    EXPECT_EQ(c2pool::dgb::saturating_add(max, c2pool::dgb::u256(1)), max);
    // The live chain credits a Scrypt header within pow_limit that meets its
    // target; nothing else.
    Mixed m;
    const c2pool::dgb::u256 g = u_of(dgb_genesis());
    EXPECT_EQ(m.chain.header_credit(sample(1, g, 1790000000, true)), work_of(kBits));
    EXPECT_TRUE(m.chain.header_credit(sample(1, g, 1790000000, false)).is_zero()) << "a non-Scrypt header";
    EXPECT_TRUE(m.chain.header_credit(sample(1, g, 1790000000, true, 0x207fffff)).is_zero()) << "above pow_limit";
    auto unmet = sample(1, g, 1790000000, true);
    unmet.pow_hash = unmet.target;
    unmet.pow_hash += c2pool::dgb::u256(1);
    EXPECT_TRUE(m.chain.header_credit(unmet).is_zero()) << "a target its hash does not meet";
    EXPECT_FALSE(HeaderChain().header_credit(sample(1, g, 1790000000, true, 0x207fffff)).is_zero())
        << "no pow_limit: credited (at its own small work)";
}

// The tip switches only to a branch with strictly more Scrypt work above the
// fork point; equal work keeps the first seen; length does not count.
TEST(DgbHeaderLink, TheTipFollowsTheMostScryptWork)
{
    {
        Mixed m;
        build_mixed(m, 10);   // heights 1..10; Scrypt at a[0], a[2], ..., a[8]
        // Above a[5]: a[6] and a[8] are Scrypt (2 w).
        const auto b = branch(m.a[5].block_hash, 5, 1790000100, 1000, [](int i) { return i != 0 && i != 3; });
        EXPECT_EQ(ingest_linked(m.chain, m.fork, b[0]), LinkResult::BUFFERED) << "0 work";
        EXPECT_EQ(ingest_linked(m.chain, m.fork, b[1]), LinkResult::BUFFERED) << "w < 2 w";
        EXPECT_EQ(ingest_linked(m.chain, m.fork, b[2]), LinkResult::BUFFERED) << "equal work: the first seen keeps the tip";
        EXPECT_EQ(ingest_linked(m.chain, m.fork, b[3]), LinkResult::BUFFERED);
        EXPECT_EQ(m.chain.tip_height(), std::optional<uint32_t>(10u));
        std::size_t depth = 0;
        EXPECT_EQ(ingest_linked(m.chain, m.fork, b[4], 0, &depth), LinkResult::REORGED) << "3 w > 2 w";
        EXPECT_EQ(depth, 4u);
        EXPECT_EQ(m.chain.tip_height(), std::optional<uint32_t>(11u));
        EXPECT_EQ(*m.chain.tip_hash(), b[4].block_hash);
        EXPECT_FALSE(m.chain.find_index(m.a[6].block_hash)) << "the cut headers are still indexed";
        EXPECT_TRUE(m.chain.find_index(b[0].block_hash));
    }
    {
        Mixed m;
        build_mixed(m, 10);
        // A longer branch with no Scrypt work: kept aside, the tip stays.
        for (const auto& h : branch(m.a[5].block_hash, 40, 1790000100, 2000, [](int) { return false; }))
            EXPECT_EQ(ingest_linked(m.chain, m.fork, h), LinkResult::BUFFERED);
        EXPECT_EQ(*m.chain.tip_hash(), m.a[9].block_hash);
        // A shorter branch with more work (one header, a 256x harder target
        // than a[8]'s above a[7]): the tip switches.
        const auto hard = sample(3000, m.a[7].block_hash, 1790000200, true, 0x1a0404cb);
        EXPECT_EQ(ingest_linked(m.chain, m.fork, hard), LinkResult::REORGED);
        EXPECT_EQ(*m.chain.tip_hash(), hard.block_hash);
        EXPECT_EQ(m.chain.tip_height(), std::optional<uint32_t>(9u));
    }
}

// Review 7a4373856 F1: a rejected switch never changes the chain, and the
// honest next header still lands on the tip.
TEST(DgbHeaderLink, ARejectedForkLeavesTheChainUnchanged)
{
    const auto unchanged = [](const Mixed& m) {
        bool same = *m.chain.tip_hash() == m.a.back().block_hash
                    && m.chain.tip_height() == std::optional<uint32_t>(static_cast<uint32_t>(m.a.size()));
        for (std::size_t i = 0; i < m.a.size(); ++i)
            same = same && m.chain.find_index(m.a[i].block_hash) == std::optional<std::size_t>(i);
        return same;
    };
    {
        Mixed m;
        build_mixed(m, 10);   // above a[7]: a[8] (w)
        auto f = branch(m.a[7].block_hash, 3, 1790000200, 1000, [](int i) { return i != 0; });
        f[0].n_version = 0x20000100;   // unknown algo nibble: REJECT (no work)
        EXPECT_EQ(ingest_linked(m.chain, m.fork, f[0]), LinkResult::BUFFERED);
        EXPECT_EQ(ingest_linked(m.chain, m.fork, f[1]), LinkResult::BUFFERED);
        EXPECT_EQ(ingest_linked(m.chain, m.fork, f[2]), LinkResult::REJECTED) << "2 w > w: switched, then refused";
        EXPECT_TRUE(unchanged(m)) << "a rejected switch changed the chain or its index";
        const auto next = sample(5000, m.a[9].block_hash, 1790000300, true);
        EXPECT_EQ(ingest_linked(m.chain, m.fork, next), LinkResult::APPENDED);
        EXPECT_EQ(m.chain.tip_height(), std::optional<uint32_t>(11u));
    }
    {
        // A credited Scrypt header the median-time check refuses at the switch.
        Mixed m;
        build_mixed(m, 10);
        auto f = branch(m.a[7].block_hash, 2, 1790000200, 1000, [](int) { return true; });
        f[0].n_time = m.a[0].n_time;   // below the fork context's median time
        EXPECT_EQ(ingest_linked(m.chain, m.fork, f[0]), LinkResult::BUFFERED);
        EXPECT_EQ(ingest_linked(m.chain, m.fork, f[1]), LinkResult::REJECTED);
        EXPECT_TRUE(unchanged(m));
    }
}

// Review c6c1c0cff G1: on the live chain (DigiByte's Scrypt pow_limit),
// branches that carry no more Scrypt work never move the tip, at any depth
// or length; the chain keeps following its own branch.
TEST(DgbHeaderLink, BranchesWithoutMoreScryptWorkNeverMoveTheTip)
{
    {   // One SHA256D header 2999 below the tip.
        Mixed m;
        build_mixed(m, 3000);
        EXPECT_EQ(ingest_linked(m.chain, m.fork, wire_run(m.a[0].block_hash, 1, 1790100000, 1)[0]),
                  LinkResult::BUFFERED);
        EXPECT_EQ(m.chain.tip_height(), std::optional<uint32_t>(3000u));
    }
    {   // 29 Scrypt headers with easy declared bits (0x207fffff, met by scrypt).
        std::vector<BlockHeaderType> easy;
        Mixed m;
        build_mixed(m, 30);
        uint256 prev = c2pool::dgb::wire_hash(m.a[1].block_hash);
        for (int i = 0; i < 29; ++i) {
            BlockHeaderType h;
            for (uint32_t k = 0;; ++k) {
                h = header_on(prev, 1790009000 + 15u * static_cast<uint32_t>(i), 0xf000 + k);
                h.m_version = 0x20000002;
                h.m_bits = 0x207fffff;
                const auto smp = make_header_sample(h);
                if (!(smp.pow_hash > smp.target))
                    break;
            }
            easy.push_back(h);
            prev = id_of(h);
        }
        for (const auto& h : easy)
            EXPECT_NE(ingest_linked(m.chain, m.fork, make_header_sample(h)), LinkResult::REORGED);
        EXPECT_EQ(*m.chain.tip_hash(), m.a[29].block_hash) << "above pow_limit: no work";
        // Without a pow_limit their work is still far below the branch's.
        HeaderChain open;
        c2pool::dgb::ForkBuffer fork;
        for (const auto& h : m.a)
            ASSERT_EQ(ingest_linked(open, fork, h, u_of(dgb_genesis())), LinkResult::APPENDED);
        for (const auto& h : easy)
            EXPECT_NE(ingest_linked(open, fork, make_header_sample(h)), LinkResult::REORGED);
        EXPECT_EQ(*open.tip_hash(), m.a[29].block_hash);
    }
    {   // 32 SHA256D headers on a[68], 31 below the tip; then the tip's child.
        Mixed m;
        build_mixed(m, 100);
        for (const auto& h : wire_run(m.a[68].block_hash, 32, 1790001100, 2))
            EXPECT_EQ(ingest_linked(m.chain, m.fork, h), LinkResult::BUFFERED);
        EXPECT_EQ(*m.chain.tip_hash(), m.a[99].block_hash);
        EXPECT_EQ(ingest_linked(m.chain, m.fork, sample(9000, m.a[99].block_hash, 1790001500, true)),
                  LinkResult::APPENDED);
    }
    {   // 33 SHA256D headers on a[68]; then a[69..99] again and 200 more.
        Mixed m;
        build_mixed(m, 100);
        for (const auto& h : wire_run(m.a[68].block_hash, 33, 1790001100, 3))
            ingest_linked(m.chain, m.fork, h);
        int known = 0, appended = 0;
        for (std::size_t i = 69; i < 100; ++i)
            known += ingest_linked(m.chain, m.fork, m.a[i]) == LinkResult::KNOWN;
        for (const auto& h : branch(m.a[99].block_hash, 200, 1790001500, 10000, [](int i) { return i % 2 == 0; }))
            appended += ingest_linked(m.chain, m.fork, h) == LinkResult::APPENDED;
        EXPECT_EQ(known, 31);
        EXPECT_EQ(appended, 200);
        EXPECT_EQ(m.chain.tip_height(), std::optional<uint32_t>(300u));
    }
    {   // An empty chain takes only the header on genesis.
        HeaderChain chain(c2pool::dgb::dgb_live_header_params(false), 0);
        dgb::interfaces::Node node;
        c2pool::dgb::HeaderIngestOptions opts;
        opts.genesis = u_of(dgb_genesis());
        int requests = 0;
        opts.request_headers = [&] { ++requests; };
        auto sub = c2pool::dgb::wire_header_ingest(node, chain, opts);
        uint256 other;
        other.SetHex("c0ffe");
        node.new_headers.happened(std::vector<BlockHeaderType>{header_on(other, 1790000000, 1)});
        EXPECT_EQ(chain.size(), 0u) << "a first header off genesis";
        EXPECT_EQ(requests, 1) << "the peer is asked again from genesis";
        node.new_headers.happened(run_on(dgb_genesis(), 50, 1790000000));
        EXPECT_EQ(chain.tip_height(), std::optional<uint32_t>(50u));
        EXPECT_EQ(chain.base_height(), 1u);
    }
}

// Review c6c1c0cff G1(2)/R1: a branch with more Scrypt work is followed from
// any retained depth (an honest reorg deeper than the old bound of 32).
TEST(DgbHeaderLink, ADeepBranchWithMoreScryptWorkIsFollowed)
{
    Mixed m;
    build_mixed(m, 100);   // above a[50]: a[52], ..., a[98] Scrypt (24 w)
    const auto b = branch(m.a[50].block_hash, 60, 1790000800, 1000, [](int i) { return i % 2 == 0; });
    int reorged = 0, appended = 0, buffered = 0;
    std::size_t depth = 0, d = 0;
    for (const auto& h : b) {
        switch (ingest_linked(m.chain, m.fork, h, 0, &d)) {
        case LinkResult::REORGED: ++reorged; depth = d; break;
        case LinkResult::APPENDED: ++appended; break;
        case LinkResult::BUFFERED: ++buffered; break;
        default: break;
        }
    }
    EXPECT_EQ(reorged, 1);
    EXPECT_EQ(depth, 49u);
    EXPECT_EQ(buffered, 48) << "b[0..47]: at most 24 w";
    EXPECT_EQ(appended, 11);
    EXPECT_EQ(*m.chain.tip_hash(), b.back().block_hash);
    EXPECT_EQ(m.chain.tip_height(), std::optional<uint32_t>(111u));
}

// Review c6c1c0cff G1: non-Scrypt headers on the tip carry no work, so the
// next Scrypt header on the branch below them takes the tip back, at any
// depth (here 50, then 33).
TEST(DgbHeaderLink, TheTipReturnsToTheBranchWithScryptWork)
{
    Mixed m;
    build_mixed(m, 10);
    for (const auto& h : wire_run(m.a[9].block_hash, 50, 1790000150, 4))
        EXPECT_EQ(ingest_linked(m.chain, m.fork, h), LinkResult::APPENDED) << "followed until outweighed (known limit)";
    EXPECT_EQ(m.chain.tip_height(), std::optional<uint32_t>(60u));
    std::size_t depth = 0;
    const auto s1 = sample(7000, m.a[9].block_hash, 1790000150, true);
    EXPECT_EQ(ingest_linked(m.chain, m.fork, s1, 0, &depth), LinkResult::REORGED);
    EXPECT_EQ(depth, 50u);
    EXPECT_EQ(*m.chain.tip_hash(), s1.block_hash);
    EXPECT_EQ(m.chain.tip_height(), std::optional<uint32_t>(11u));
    for (const auto& h : wire_run(s1.block_hash, 33, 1790000165, 5))
        EXPECT_EQ(ingest_linked(m.chain, m.fork, h), LinkResult::APPENDED);
    const auto s2 = sample(7001, s1.block_hash, 1790000165, false);
    const auto s3 = sample(7002, s2.block_hash, 1790000180, true);
    EXPECT_EQ(ingest_linked(m.chain, m.fork, s2), LinkResult::BUFFERED);
    EXPECT_EQ(ingest_linked(m.chain, m.fork, s3, 0, &depth), LinkResult::REORGED);
    EXPECT_EQ(depth, 33u);
    EXPECT_EQ(*m.chain.tip_hash(), s3.block_hash);
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
    // driver; the HTTP thread reads the published tip. Review c6c1c0cff: the
    // live chain has DigiByte's Scrypt pow_limit; regtest without
    // --coin-genesis numbers the first header 1.
    for (const char* line : {
             "auto header_ingest_sub  = c2pool::dgb::wire_header_ingest(coin_iface, header_chain, header_opts);",
             "coin_p2p->set_on_block_inv(header_opts.request_headers);",
             "stop_coin_header_driver = dgb::start_periodic(ioc, std::chrono::milliseconds(12000),",
             "const uint32_t hh = header_tip_pub->load();",
             "c2pool::dgb::HeaderChain header_chain(c2pool::dgb::dgb_live_header_params(regtest), 0);",
             "if (regtest && coin_genesis.IsNull()) {\n        header_chain.set_base_height(1);"})
        EXPECT_NE(main.find(line), std::string::npos) << line;
    EXPECT_EQ(main.find("reset_tip_latch"), std::string::npos) << "the tip latch is gone (a stale tip stops serving)";
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
