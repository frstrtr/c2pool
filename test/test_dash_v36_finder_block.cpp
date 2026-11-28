// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH v36 network KATs: the finder assembles the full won block.
//
// A v36 share commits the template's transactions through its coinbase
// merkle_link; the tx bodies exist only on the node that served the template.
// The producer job freezes them (FrozenMintJob::tx_data_hex, parallel to
// desired_tx_hashes), and the tracker-arm reconstructor rebuilds a
// tx-committing v36 won block ONLY from those frozen bodies
// (reconstruct_won_block's FinderBodiesLookup), and only when they hash to the
// share's committed merkle root.
//
// What is pinned:
//   F1. build_producer_job freezes the template bodies on the DASH v36 network
//       (null on a coinbase-only job and on the public path) and declines a
//       template whose bodies do not match its hash list.
//   F2. The finder rebuilds header + [gentx] + the template txs in template
//       order; the header X11-hashes to the share hash, the body parses as a
//       DASH block and binds to the header merkle root (dashcore's check).
//   F3. Bodies that do not match the committed link -- a swapped body, a
//       missing body, a reordered hash list, a foreign template -- are refused
//       with a named cause (v36_finder_block_bodies) and nothing is framed.
//   F4. A won block rebuilds from the bodies the mint carried after the
//       frozen-job registry evicted its job (dash::mint::WonBlockBodies).
//   F5. v36_finder_block_bodies accepts the real bodies of testnet block 1599900,
//       whose v24 version 2 asset unlocks carry a stable txid that is not the
//       SHA256d of their bytes; a type-9 body with trailing bytes is refused.
//
// Folded into test_dash_node (the same harness and link set as
// test_dash_v36_flip.cpp).

#include <gtest/gtest.h>

#include "dash_v36_live_fixture.hpp"
#include "dash_v36_mint_fixture.hpp"

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/block_producer.hpp>
#include <impl/dash/coin/dash_txid.hpp>
#include <impl/dash/coin/reconstruct_won_block.hpp>
#include <impl/dash/coinbase_builder.hpp>   // merkle_branches_raw
#include <impl/dash/mint_runloop.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

using dash::coin::FinderBodiesLookup;
using dash::coin::FinderTemplateBodies;

// A tracker holding a v36 genesis + a child, both minted through the real
// producer job / mint path over `wd` (the finder's own chain).
struct FinderRig {
    core::CoinParams p;
    dash::coin::DashWorkData wd;
    SolvedJob j1, j2;
    std::optional<dash::stratum::MintedShare> m1, m2;
    dash::ShareTracker t;

    explicit FinderRig(const dash::coin::DashWorkData& work)
        : p(iso_prod_params()), wd(work)
    {
        dash::ShareChain scratch;
        j1 = solve_job(scratch, p, uint256(), h160(0xa5), wd, 7, wd.m_curtime);
        if (!j1.solved) return;
        m1 = mint_from_inputs_any(scratch, p, j1.in, j1.build.frozen);
        if (!m1) return;
        scratch.add(new dash::DashV36Share(v36_of(*m1).share));
        j2 = solve_job(scratch, p, v36_of(*m1).share.m_hash, h160(0xb6), wd, 8, wd.m_curtime + 20);
        if (!j2.solved) return;
        m2 = mint_from_inputs_any(scratch, p, j2.in, j2.build.frozen);
        if (!m2) return;
        t.m_coin_params = p;
        t.add(var_of(v36_of(*m1).share));
        t.add(var_of(v36_of(*m2).share));
    }
    bool ok() const { return m1 && m2; }
    const dash::DashV36Share& child() const { return v36_of(*m2).share; }

    // The finder's registry lookup, bound to the child's frozen job.
    FinderBodiesLookup finder(FinderTemplateBodies fb) const {
        const uint256 ref = j2.build.job.ref_hash;
        return [ref, fb](const uint256& r) -> std::optional<FinderTemplateBodies> {
            if (r != ref) return std::nullopt;
            return fb;
        };
    }
    FinderTemplateBodies frozen_bodies() const {
        return FinderTemplateBodies{j2.build.frozen.desired_tx_hashes, j2.build.frozen.tx_data_hex};
    }
};

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// F1. The producer job freezes the template bodies
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36FinderBlock, V36ProducerJobFreezesTemplateBodies)
{
    IdentityGuard guard;
    const auto script = dash::pubkey_hash_to_script2(h160(0x72));
    const auto wd = make_wd_with_txs(3);
    {
        const auto p = iso_prod_params();
        ASSERT_EQ(p.current_share_version, 36u);
        dash::ShareChain chain;
        const auto b = build_producer_job(chain, p, uint256(), script, wd, wd.m_curtime,
                                          7, 0, "c2pool");
        ASSERT_TRUE(b.has_value());
        EXPECT_EQ(b->frozen.desired_tx_hashes, wd.m_tx_hashes);
        ASSERT_TRUE(b->frozen.tx_data_hex) << "the template bodies are frozen with the job";
        EXPECT_EQ(*b->frozen.tx_data_hex, wd.m_tx_data_hex);

        const auto cb_only = make_wd();
        const auto c = build_producer_job(chain, p, uint256(), script, cb_only,
                                          cb_only.m_curtime, 7, 0, "c2pool");
        ASSERT_TRUE(c.has_value());
        EXPECT_EQ(c->frozen.tx_data_hex, nullptr) << "coinbase-only job: no bodies";

        auto short_bodies = wd;
        short_bodies.m_tx_data_hex.pop_back();
        EXPECT_FALSE(build_producer_job(chain, p, uint256(), script, short_bodies,
                                        short_bodies.m_curtime, 7, 0, "c2pool").has_value())
            << "a template whose bodies do not match its hash list is declined";
    }
    {
        const auto p = public_params();
        dash::ShareChain chain;
        const auto b = build_producer_job(chain, p, uint256(), script, wd, wd.m_curtime,
                                          7, 0, "c2pool");
        ASSERT_TRUE(b.has_value());
        EXPECT_EQ(b->frozen.tx_data_hex, nullptr) << "the public path freezes no bodies";
        auto short_bodies = wd;
        short_bodies.m_tx_data_hex.pop_back();
        const auto bs = build_producer_job(chain, p, uint256(), script, short_bodies,
                                           short_bodies.m_curtime, 7, 0, "c2pool");
        ASSERT_TRUE(bs.has_value()) << "the body check is v36-only";
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// F2. The finder assembles the full block from its frozen job
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36FinderBlock, FinderAssemblesFullBlockFromFrozenJob)
{
    IdentityGuard guard;
    FinderRig rig(make_wd_with_txs(3));
    ASSERT_TRUE(rig.ok());
    const auto& child = rig.child();
    ASSERT_EQ(child.m_merkle_link.m_branch.size(), 2u);
    ASSERT_TRUE(rig.j2.build.frozen.tx_data_hex);

    const auto r = dash::coin::reconstruct_won_block(
        child.m_hash, child, rig.t, rig.p, /*known_txs=*/{}, rig.finder(rig.frozen_bodies()));
    ASSERT_TRUE(r.has_value()) << "the finder rebuilds the tx-committing v36 won block";
    const Bytes& b = r->bytes;

    // Header: the one the miner solved (same X11 hash, same merkle root).
    ASSERT_GT(b.size(), 81u);
    EXPECT_EQ(Bytes(b.begin(), b.begin() + 80), rig.j2.in.header_bytes)
        << "the block header is byte-identical to the solved header";
    EXPECT_EQ(rig.p.pow_func(std::span<const unsigned char>(b.data(), 80)), child.m_hash);

    // Body: CompactSize(4) + gentx + the 3 template txs in template order.
    EXPECT_EQ(b[80], 4u) << "coinbase + 3 template txs";
    const Bytes& gentx = rig.j2.in.coinbase_bytes;
    ASSERT_GE(b.size(), 81u + gentx.size());
    EXPECT_TRUE(std::equal(gentx.begin(), gentx.end(), b.begin() + 81))
        << "the coinbase is the served coinbase";
    Bytes tail(b.begin() + 81 + gentx.size(), b.end());
    Bytes want;
    for (const auto& hex : rig.wd.m_tx_data_hex) {
        const auto body = ParseHex(hex);
        want.insert(want.end(), body.begin(), body.end());
    }
    EXPECT_EQ(tail, want) << "the template bodies follow in template order";
    EXPECT_EQ(r->hex, HexStr(b));

    // dashcore's check: the parsed body binds to the header merkle root.
    PackStream ps(b);
    dash::coin::BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 4u);
    EXPECT_TRUE(dash::coin::block_body_binds_to_header(blk))
        << "merkle root over [gentx] ++ template txs == the header's";
    std::vector<uint256> txids{sha256d_bytes(gentx)};
    txids.insert(txids.end(), rig.wd.m_tx_hashes.begin(), rig.wd.m_tx_hashes.end());
    EXPECT_EQ(dash::coin::compute_merkle_root(txids), blk.m_merkle_root);

    // A lookup miss (another ref) is the non-finder refusal.
    const auto miss = dash::coin::reconstruct_won_block(
        child.m_hash, child, rig.t, rig.p, {},
        [](const uint256&) -> std::optional<FinderTemplateBodies> { return std::nullopt; });
    EXPECT_FALSE(miss.has_value());
}

// A one-tx template (odd layer: the coinbase pairs with the single tx) and a
// five-tx template (odd layers duplicate their last node) assemble too.
TEST(DashV36FinderBlock, FinderAssemblesOddTemplates)
{
    for (size_t n : {size_t{1}, size_t{5}}) {
        SCOPED_TRACE("txs=" + std::to_string(n));
        IdentityGuard guard;
        FinderRig rig(make_wd_with_txs(n, static_cast<uint8_t>(0x20 + n)));
        ASSERT_TRUE(rig.ok());
        const auto r = dash::coin::reconstruct_won_block(
            rig.child().m_hash, rig.child(), rig.t, rig.p, {}, rig.finder(rig.frozen_bodies()));
        ASSERT_TRUE(r.has_value());
        PackStream ps(r->bytes);
        dash::coin::BlockType blk;
        ps >> blk;
        EXPECT_EQ(blk.m_txs.size(), 1u + n);
        EXPECT_TRUE(dash::coin::block_body_binds_to_header(blk));
        EXPECT_EQ(Bytes(r->bytes.begin(), r->bytes.begin() + 80), rig.j2.in.header_bytes);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// F3. Bodies that do not match the committed link are refused
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36FinderBlock, FinderRejectsBodiesThatDoNotMatchTheLink)
{
    IdentityGuard guard;
    FinderRig rig(make_wd_with_txs(3));
    ASSERT_TRUE(rig.ok());
    const auto& child = rig.child();
    const uint256 gentx_txid = sha256d_bytes(rig.j2.in.coinbase_bytes);
    const auto good = rig.frozen_bodies();

    std::string why;
    ASSERT_TRUE(dash::coin::v36_finder_block_bodies(child, gentx_txid, good, &why).has_value()) << why;

    auto refused = [&](const FinderTemplateBodies& fb, const std::string& cause_part) {
        std::string w;
        EXPECT_FALSE(dash::coin::v36_finder_block_bodies(child, gentx_txid, fb, &w).has_value());
        EXPECT_NE(w.find(cause_part), std::string::npos) << "cause: " << w;
        EXPECT_FALSE(dash::coin::reconstruct_won_block(child.m_hash, child, rig.t, rig.p, {},
                                                        rig.finder(fb)).has_value());
    };

    {   // a body swapped for another tx: it no longer hashes to its listed hash
        auto hex = *good.tx_data_hex;
        hex[1] = HexStr(pseudo_tx(9, 0x77));
        refused({good.tx_hashes, std::make_shared<const std::vector<std::string>>(hex)},
                "body hashes to");
    }
    {   // one body missing
        auto hex = *good.tx_data_hex;
        hex.pop_back();
        refused({good.tx_hashes, std::make_shared<const std::vector<std::string>>(hex)},
                "bodies");
    }
    {   // no bodies at all
        refused({good.tx_hashes, nullptr}, "no template tx bodies");
    }
    {   // the same txs in a foreign order: bodies match their hashes, but the
        // merkle root is not the committed one
        FinderTemplateBodies fb;
        fb.tx_hashes = {good.tx_hashes[1], good.tx_hashes[0], good.tx_hashes[2]};
        auto hex = *good.tx_data_hex;
        std::swap(hex[0], hex[1]);
        fb.tx_data_hex = std::make_shared<const std::vector<std::string>>(hex);
        refused(fb, "committed root");
    }
    {   // a foreign template (different txs, self-consistent)
        const auto other = make_wd_with_txs(3, 0x99);
        refused({other.m_tx_hashes,
                 std::make_shared<const std::vector<std::string>>(other.m_tx_data_hex)},
                "committed root");
    }
    {   // a truncated hex body
        auto hex = *good.tx_data_hex;
        hex[2].pop_back();
        refused({good.tx_hashes, std::make_shared<const std::vector<std::string>>(hex)},
                "tx 2");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// F4. P2': a won block rebuilds after the registry evicted its job
// ═════════════════════════════════════════════════════════════════════════════
//
// The mint seam copies the frozen job when the won solve arrives and records
// its bodies (WonBlockBodies); the rebuild runs later, after the win has moved
// the tip, and by then the bounded registry may have evicted the entry. The
// rebuild reads the carried copy first, so it still frames the full block.
TEST(DashV36FinderBlock, WonBlockRebuildsAfterItsEntryWasEvicted)
{
    IdentityGuard guard;
    FinderRig rig(make_wd_with_txs(3));
    ASSERT_TRUE(rig.ok());
    const auto& child = rig.child();
    const uint256 ref = rig.j2.build.job.ref_hash;

    auto t = std::chrono::steady_clock::time_point{} + std::chrono::hours(1);
    dash::mint::FrozenJobRegistry registry(dash::mint::FrozenRegistryConfig{}, [&t] { return t; });
    dash::mint::WonBlockBodies won;
    registry.put(ref, rig.j2.build.frozen, rig.wd.m_previous_block, uint256());

    // The won solve arrives: the seam reads the job and carries its bodies.
    auto job = dash::mint::frozen_job_for_mint(registry, ref, nullptr, &won);
    ASSERT_TRUE(job.has_value());
    EXPECT_EQ(won.size(), 1u);

    // The tip moves on and the registry ages the entry out.
    t += dash::mint::kFrozenJobAge + std::chrono::seconds(1);
    registry.put(uint256(std::vector<unsigned char>(32, 0x42)), dash::stratum::FrozenMintJob{},
                 uint256(std::vector<unsigned char>(32, 0x43)), uint256());
    ASSERT_FALSE(registry.contains(ref));

    auto lookup = [&](const dash::mint::WonBlockBodies& carried) -> FinderBodiesLookup {
        return [&registry, &carried](const uint256& r) -> std::optional<FinderTemplateBodies> {
            auto b = dash::mint::won_block_bodies_for(carried, registry, r);
            if (!b) return std::nullopt;
            return FinderTemplateBodies{std::move(b->tx_hashes), b->tx_data_hex};
        };
    };
    const auto rebuilt = dash::coin::reconstruct_won_block(
        child.m_hash, child, rig.t, rig.p, /*known_txs=*/{}, lookup(won));
    ASSERT_TRUE(rebuilt.has_value()) << "the won block was not rebuilt after its entry was evicted";
    const auto direct = dash::coin::reconstruct_won_block(
        child.m_hash, child, rig.t, rig.p, {}, rig.finder(rig.frozen_bodies()));
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(rebuilt->bytes, direct->bytes) << "the carried bodies frame the same block";

    // Without the carried copy the evicted registry cannot rebuild it.
    const dash::mint::WonBlockBodies none;
    EXPECT_FALSE(dash::coin::reconstruct_won_block(child.m_hash, child, rig.t, rig.p, {},
                                                   lookup(none)).has_value());
}

// ═════════════════════════════════════════════════════════════════════════════
// F5. Real v2 asset unlock bodies (testnet block 1599900)
// ═════════════════════════════════════════════════════════════════════════════

#include "data/dash_block_testnet_1599900.inc"
#include "data/dash_block_testnet_txids_1599900_1599924.inc"

namespace {

struct F5Block {
    dash::coin::BlockType     block;
    std::vector<std::string>  hex;        // every tx, coinbase first
    std::vector<uint256>      txids;      // dashd's
};

F5Block f5_load()
{
    F5Block b;
    std::string h;
    for (const char* p = kDashBlockTestnet1599900; *p; ++p)
        if (*p != '\n' && *p != '\r') h.push_back(*p);
    PackStream ps(ParseHex(h));
    ps >> b.block;
    for (const auto& tx : b.block.m_txs) {
        auto packed = ::pack(tx);
        auto sp = packed.get_span();
        b.hex.push_back(HexStr(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(sp.data()), sp.size())));
    }
    for (const char* t : kDashBlockTestnet1599900Txids) b.txids.push_back(uint256S(t));
    return b;
}

} // namespace

TEST(DashV36FinderBlock, FinderBodiesAcceptRealV2Unlocks)
{
    const F5Block b = f5_load();
    ASSERT_EQ(b.hex.size(), b.txids.size());
    size_t v2 = 0;
    for (const auto& tx : b.block.m_txs) v2 += dash::coin::is_asset_unlock_with_stable_txid(tx) ? 1 : 0;
    ASSERT_EQ(v2, 11u);

    // The share's merkle link: the stratum branch over [coinbase placeholder] ++
    // dashd's txids, ascended from the block's own coinbase txid.
    const uint256 gentx_txid = sha256d_bytes(ParseHex(b.hex[0]));
    std::vector<uint256> leaves{uint256::ZERO};
    leaves.insert(leaves.end(), b.txids.begin() + 1, b.txids.end());
    dash::DashV36Share share;
    share.m_merkle_link.m_branch = dash::coinbase::merkle_branches_raw(leaves);
    share.m_merkle_link.m_index  = 0;
    ASSERT_EQ(dash::check_merkle_link(gentx_txid, share.m_merkle_link), b.block.m_merkle_root);

    FinderTemplateBodies fb;
    fb.tx_hashes.assign(b.txids.begin() + 1, b.txids.end());
    fb.tx_data_hex = std::make_shared<const std::vector<std::string>>(b.hex.begin() + 1, b.hex.end());
    std::string why;
    const auto bodies = dash::coin::v36_finder_block_bodies(share, gentx_txid, fb, &why);
    ASSERT_TRUE(bodies.has_value()) << why;
    ASSERT_EQ(bodies->size(), fb.tx_hashes.size());
    for (size_t i = 0; i < bodies->size(); ++i)
        EXPECT_EQ(HexStr((*bodies)[i]), (*fb.tx_data_hex)[i]) << "tx " << i;

    // A type-9 body with trailing bytes is not the committed tx.
    auto hex = *fb.tx_data_hex;
    hex[4] += "00";
    FinderTemplateBodies trailing{fb.tx_hashes, std::make_shared<const std::vector<std::string>>(hex)};
    EXPECT_FALSE(dash::coin::v36_finder_block_bodies(share, gentx_txid, trailing, &why).has_value());
    EXPECT_NE(why.find("trailing bytes"), std::string::npos) << why;
}
