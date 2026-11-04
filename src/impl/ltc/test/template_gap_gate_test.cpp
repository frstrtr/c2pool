// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The embedded LTC template takes the pool's txs only when the pool was
// cleaned for the tip and the UTXO view's best block IS the tip; otherwise it
// is coinbase + HogEx only ON THE TIP, marked degraded and served (#2136,
// #2137 S0; rides share_test).
//
// The selection prices against the UTXO view. A view behind, beside or above
// the tip cannot show that an input is unspent at the tip: a tx one of the
// tip's ancestors confirmed (cleaned once, relayed again by a peer that had
// not seen the block) is priced against the older view, selected, and the
// block is one litecoind rejects (bad-txns-inputs-missingorspent). Holding
// the previous template instead keeps miners on the old prev, without bound
// when the view is stuck. Pinned here over a REAL HeaderChain, Mempool and
// UTXOViewCache/UTXOViewDB (and MWEBTracker for the MWEB-active cases):
//   - back to back (view at T0, tip T2): empty on T2, also once T1 was
//     cleaned; full once the view reaches T2;
//   - a reorg across a same-height sibling (view on S1): empty on T2, also
//     after the view rewound to the fork point; full at T2;
//   - a tx T1 confirmed, cleaned with T1 as a side block and admitted again
//     afterwards, never ships (the verifier's M1 case);
//   - liveness: with the tip's MWEB state, a heal that cannot rewind (view
//     on a sibling) or a body nobody serves (view behind) still yields work
//     ON THE TIP -- coinbase + HogEx, served, no refusal; without the tip's
//     MWEB state the template is refused as before (today's MWEB HOLD /
//     degraded start), never a HogEx-less block;
//   - core::coin::template_pool_gate itself;
//   - the cleaned_for window the tip check relies on (CLEANED_BLOCKS_KEPT
//     >= 32).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <random>
#include <string>

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/coin/mweb_shape.hpp>
#include <core/coin/template_gate.hpp>
#include <core/coin/template_txs_check.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>

#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/mweb_builder.hpp>
#include <impl/ltc/coin/template_builder.hpp>
#include <impl/ltc/test/mempool_test_view.hpp>

namespace {

using namespace ltc::coin;

BlockHeaderType testnet_genesis()
{
    BlockHeaderType g;
    g.m_version = 1;
    g.m_previous_block.SetNull();
    g.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    g.m_timestamp = 1486949366;
    g.m_bits = 0x1e0ffff0;
    g.m_nonce = 293345;
    return g;
}

uint256 hash_of(const BlockHeaderType& hdr)
{
    return Hash(pack(hdr).get_span());
}

BlockHeaderType child_of(const uint256& prev, uint32_t tag)
{
    BlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block = prev;
    h.m_merkle_root.SetHex(std::to_string(700 + tag));
    h.m_timestamp = 1486949366 + 150 * (tag + 1);
    h.m_bits = 0x1e0ffff0;
    h.m_nonce = tag;
    return h;
}

// genesis (h0) - T0 (h1) - T1 (h2) - T2 (h3), and S1 (h2), a sibling of T1
// seen after it (equal work: T1 stays on the best chain). Old enough below
// the peer's tip that the header chain checks them structurally.
struct Chain {
    HeaderChain chain{make_ltc_chain_params_testnet()};
    BlockHeaderType t0, t1, t2, s1;
    Chain()
    {
        EXPECT_TRUE(chain.init());
        EXPECT_TRUE(chain.add_header(testnet_genesis()));
        chain.set_peer_tip_height(10'000'000);
        t0 = child_of(hash_of(testnet_genesis()), 0);
        t1 = child_of(hash_of(t0), 1);
        s1 = child_of(hash_of(t0), 2);
        t2 = child_of(hash_of(t1), 3);
        EXPECT_TRUE(chain.add_header(t0));
        EXPECT_TRUE(chain.add_header(t1));
        EXPECT_TRUE(chain.add_header(s1));
        EXPECT_TRUE(chain.add_header(t2));
        EXPECT_EQ(chain.height(), 3u);
        EXPECT_EQ(chain.tip()->block_hash, hash_of(t2));
    }
};

// A UTXO view over a real DB in a temp dir; its best block is moved with
// flush().
struct View {
    std::filesystem::path dir;
    std::unique_ptr<core::coin::UTXOViewDB> db;
    std::unique_ptr<core::coin::UTXOViewCache> cache;
    View()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("ltc_gap_gate_" + std::to_string(rng()));
        std::filesystem::create_directories(dir);
        db = std::make_unique<core::coin::UTXOViewDB>(dir.string());
        EXPECT_TRUE(db->open());
        cache = std::make_unique<core::coin::UTXOViewCache>(db.get());
    }
    ~View()
    {
        cache.reset();
        db.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
    void add(const uint256& txid, uint32_t index, int64_t value)
    {
        core::coin::Coin coin;
        coin.value = value;
        coin.scriptPubKey.m_data = {0x51};  // OP_TRUE
        coin.height = 1;
        cache->add_coin(core::coin::Outpoint(txid, index), coin);
    }
    void best(const uint256& hash, uint32_t height)
    {
        ASSERT_TRUE(cache->flush(hash, height));
        ASSERT_EQ(cache->get_best_block(), hash);
    }
    void best(const BlockHeaderType& hdr, uint32_t height) { best(hash_of(hdr), height); }
};

uint256 hx(const char* hex)
{
    uint256 v;
    v.SetHex(hex);
    return v;
}

const uint256 FUND = hx("00000000000000000000000000000000000000000000000000000000000000f1");

MutableTransaction pay_from_fund()
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash = FUND;
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = 99'000;
    out.scriptPubKey.m_data = {0x51};
    tx.vout.push_back(out);
    return tx;
}

void clean_for(Mempool& pool, const BlockHeaderType& hdr)
{
    BlockType b;
    static_cast<BlockHeaderType&>(b) = hdr;
    pool.remove_for_block(b);
}

// A pool holding one priced tx whose input is in `view`.
void fill(Mempool& pool, View& view)
{
    const MutableTransaction tx = pay_from_fund();
    ASSERT_TRUE(pool.add_tx(tx));
    pool.set_tx_fee(compute_txid(tx), 1'000);
    view.add(FUND, 0, 100'000);
    pool.set_utxo(view.cache.get());
}

struct Built {
    std::optional<rpc::WorkData> wd;
    std::optional<rpc::WorkData> refused;
    std::optional<std::string> degraded() const
    {
        return wd ? core::coin::template_degraded_code(wd->m_data) : std::nullopt;
    }
    size_t n_txs() const { return wd ? wd->m_data["transactions"].size() : 0; }
};

Built build(const HeaderChain& chain, const Mempool& pool, const MWEBTracker* tracker = nullptr)
{
    Built b;
    b.wd = TemplateBuilder::build_template(chain, pool, /*is_testnet=*/true, tracker,
                                           TemplateBuilder::MAX_BLOCK_WEIGHT - TemplateBuilder::COINBASE_RESERVE,
                                           &b.refused);
    return b;
}

const std::string kNotAtTip = core::coin::kUtxoViewNotAtTip;

// An empty template on the tip that the ingress guard serves: no refusal, no
// pool tx, the tip as prev, coinbasevalue = subsidy.
void expect_empty_on_tip(const Built& b, const uint256& tip, const std::string& code, uint32_t next_h)
{
    ASSERT_TRUE(b.wd) << "work on the tip, not a HOLD";
    EXPECT_EQ(b.degraded(), std::optional<std::string>(code));
    EXPECT_FALSE(core::coin::template_refusal_code(b.wd->m_data));
    EXPECT_FALSE(core::coin::check_template_shape(b.wd->m_data)) << "served at ingress";
    EXPECT_EQ(b.wd->m_data["previousblockhash"].get<std::string>(), tip.GetHex());
    EXPECT_EQ(b.wd->m_data["coinbasevalue"].get<int64_t>(), static_cast<int64_t>(get_block_subsidy(next_h)));
}

} // namespace

// 2026-10-31 21:40Z (h 3205145): two blocks 10 s apart; the second's body
// was processed while the UTXO set was still before the first. View at T0,
// tip T2: nothing from the pool until the view reaches T2, cleaned T1 or not.
TEST(LtcTemplateGapGate, BackToBackBlocksMineEmptyOnTheTipUntilTheViewReachesIt)
{
    Chain c;
    View view;
    Mempool pool;
    fill(pool, view);
    view.best(c.t0, 1);
    clean_for(pool, c.t2);
    auto b = build(c.chain, pool);
    expect_empty_on_tip(b, hash_of(c.t2), kNotAtTip, 4);
    EXPECT_EQ(b.n_txs(), 0u);

    // The parent's body cleaned (a side delivery, or the fill under way):
    // still a view behind the tip.
    clean_for(pool, c.t1);
    b = build(c.chain, pool);
    expect_empty_on_tip(b, hash_of(c.t2), kNotAtTip, 4);

    // The fill connects T1 and T2: the view is the tip.
    view.best(c.t2, 3);
    b = build(c.chain, pool);
    ASSERT_TRUE(b.wd);
    EXPECT_FALSE(b.degraded());
    ASSERT_EQ(b.n_txs(), 1u) << "the priced tx ships";
    EXPECT_EQ(b.wd->m_data["coinbasevalue"].get<int64_t>(), static_cast<int64_t>(get_block_subsidy(4)) + 1'000);
}

// 2026-11-02 15:50Z (h 3206173): c2 sat on a sibling of litecoind's 3206172
// and reorged onto the child of the other one. The view on S1, then rewound
// to the fork point T0: both are not the tip.
TEST(LtcTemplateGapGate, SameHeightSiblingReorgMinesEmptyOnTheTipUntilTheViewReachesIt)
{
    Chain c;
    View view;
    Mempool pool;
    fill(pool, view);
    view.best(c.s1, 2);
    clean_for(pool, c.s1);
    clean_for(pool, c.t1);
    clean_for(pool, c.t2);
    expect_empty_on_tip(build(c.chain, pool), hash_of(c.t2), kNotAtTip, 4);
    view.best(c.t0, 1);  // the heal rewinds to the fork point
    expect_empty_on_tip(build(c.chain, pool), hash_of(c.t2), kNotAtTip, 4);
    view.best(c.t1, 2);  // the reorg fill connects T1
    expect_empty_on_tip(build(c.chain, pool), hash_of(c.t2), kNotAtTip, 4);
    view.best(c.t2, 3);  // ... and T2
    auto b = build(c.chain, pool);
    ASSERT_TRUE(b.wd);
    EXPECT_FALSE(b.degraded());
    EXPECT_EQ(b.n_txs(), 1u);
}

// The verifier's M1 case (VERIFY-S0-S1 VerifyS0.ReadmittedTxConfirmedBy-
// ACleanedSegmentBlockShips, now inverted): c2 on S1; litecoind's T1 arrives
// as a side block and is cleaned (its tx X leaves); a peer that has not seen
// T1 relays X again, priced against the view on S1; T2 (child of T1)
// arrives, the heal rewinds the set to T0, T2 is cleaned. Every block of
// (T0, T2] was cleaned and T0 is an ancestor -- the old segment gate built a
// template on T2 carrying X (bad-txns-inputs-missingorspent). X never ships.
TEST(LtcTemplateGapGate, ReadmittedTxConfirmedByTheParentNeverShips)
{
    Chain c;
    View view;
    Mempool pool;
    view.add(FUND, 0, 100'000);
    view.best(c.s1, 2);
    pool.set_utxo(view.cache.get());

    const MutableTransaction x = pay_from_fund();
    ASSERT_FALSE(pool.admit(x, view.cache.get()));
    ASSERT_EQ(pool.size(), 1u);
    BlockType t1_body;
    static_cast<BlockHeaderType&>(t1_body) = c.t1;
    t1_body.m_txs.push_back(x);
    pool.remove_for_block(t1_body);  // T1 seen as a side block: X leaves
    ASSERT_EQ(pool.size(), 0u);
    ASSERT_FALSE(pool.admit(x, view.cache.get())) << "re-admitted, priced against the view on S1";
    ASSERT_EQ(pool.size(), 1u);

    view.best(c.t0, 1);  // the heal rewinds to the fork point
    clean_for(pool, c.t2);
    auto b = build(c.chain, pool);
    expect_empty_on_tip(b, hash_of(c.t2), kNotAtTip, 4);
    ASSERT_TRUE(b.wd);
    for (const auto& e : b.wd->m_data["transactions"])
        EXPECT_NE(e["txid"].get<std::string>(), compute_txid(x).GetHex()) << "X, confirmed by T1, shipped";
    EXPECT_EQ(b.n_txs(), 0u);
}

// A view above the tip (a reorg onto a shorter branch, not yet rewound) and
// a pool not cleaned for the tip: empty on the tip, each under its code; an
// empty pool, and a view without a best block (it prices nothing), take the
// pool as is.
TEST(LtcTemplateGapGate, OtherStatesAndWhatIsNotGated)
{
    Chain c;
    {
        View view;
        Mempool pool;
        fill(pool, view);
        clean_for(pool, c.t2);
        view.best(child_of(hash_of(c.t2), 9), 4);
        expect_empty_on_tip(build(c.chain, pool), hash_of(c.t2), kNotAtTip, 4);
    }
    {
        View view;
        Mempool pool;
        fill(pool, view);
        view.best(c.t2, 3);  // the view is the tip, the tip's body not cleaned
        expect_empty_on_tip(build(c.chain, pool), hash_of(c.t2), core::coin::kNotCleanedForTip, 4);
    }
    {
        View view;
        Mempool empty;
        empty.set_utxo(view.cache.get());
        view.best(c.t0, 1);
        auto b = build(c.chain, empty);
        ASSERT_TRUE(b.wd);
        EXPECT_FALSE(b.degraded()) << "nothing to select, nothing to gate";
    }
    {
        Mempool pool;
        ASSERT_TRUE(pool.add_tx(pay_from_fund()));
        pool.set_tx_fee(compute_txid(pay_from_fund()), 1'000);
        ltc_test::CoveringView mem;  // no DB: no best block
        mem.cover(pool);
        clean_for(pool, c.t2);
        auto b = build(c.chain, pool);
        ASSERT_TRUE(b.wd);
        EXPECT_FALSE(b.degraded());
        EXPECT_EQ(b.n_txs(), 1u);
    }
}

// ── MWEB-active liveness ────────────────────────────────────────────────────

namespace {

constexpr uint32_t kMwebTip = 1000;

// A mainnet chain whose tip is a fast-start checkpoint at kMwebTip with the
// block hash of `tip_hdr` (no real headers below it).
std::unique_ptr<HeaderChain> mweb_chain(const BlockHeaderType& tip_hdr)
{
    auto p = make_ltc_chain_params_mainnet();
    LTCChainParams::Checkpoint cp;
    cp.height = kMwebTip;
    cp.hash = hash_of(tip_hdr);
    p.fast_start_checkpoint = cp;
    auto chain = std::make_unique<HeaderChain>(p);
    EXPECT_TRUE(chain->init());
    return chain;
}

// The tip's MWEB state: a block whose HogEx commits to its empty mw::Block
// (MWEBTracker::update checks the commitment).
void feed_tracker(MWEBTracker& tracker, uint32_t height, const BlockHeaderType& hdr)
{
    BlockType b;
    static_cast<BlockHeaderType&>(b) = hdr;
    MutableTransaction cb;
    cb.version = 1;
    cb.locktime = 0;
    TxIn cin;
    cin.prevout.hash.SetNull();
    cin.prevout.index = 0xffffffff;
    cin.sequence = 0xffffffff;
    cb.vin.push_back(cin);
    TxOut cb_out;
    cb_out.value = 5000000000LL;
    cb.vout.push_back(cb_out);

    MutableTransaction hog;
    hog.version = 2;
    hog.locktime = 0;
    hog.m_hogEx = true;
    TxIn hin;
    hin.prevout.hash = hx("4444444444444444444444444444444444444444444444444444444444444444");
    hin.prevout.index = 0;
    hin.sequence = 0xffffffff;
    hog.vin.push_back(hin);
    MWEBBlock mweb;
    mweb.header.height = height;
    const uint256 mweb_hash = blake3_hash_serialized(mweb.header);
    TxOut hout;
    hout.value = 123456789;
    hout.scriptPubKey.m_data.assign(34, 0x77);
    hout.scriptPubKey.m_data[0] = 0x58;  // OP_8
    hout.scriptPubKey.m_data[1] = 0x20;  // PUSH 32
    std::memcpy(hout.scriptPubKey.m_data.data() + 2, mweb_hash.data(), 32);
    hog.vout.push_back(hout);
    b.m_txs = {cb, hog};

    PackStream ps;
    ps << mweb;
    auto sp = ps.get_span();
    std::vector<unsigned char> raw(reinterpret_cast<const unsigned char*>(sp.data()),
                                   reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    ASSERT_TRUE(tracker.update(b, height, raw));
}

} // namespace

// The UTXO set cannot come back to the tip: a heal that cannot rewind (the
// view stuck on a sibling of the tip) or a gap body nobody serves (the view
// stuck behind). The tip's body arrived (its MWEB state was captured at
// once), so the work is coinbase + HogEx ON THE TIP, served -- for as long as
// the view is stuck -- instead of the previous template on the old prev.
TEST(LtcTemplateGapGate, StuckHealOrMissingBodyStillYieldsWorkOnTheTip)
{
    const BlockHeaderType tip_hdr = child_of(hx("00000000000000000000000000000000000000000000000000000000000000ee"), 1);
    auto chain = mweb_chain(tip_hdr);
    MWEBTracker tracker;
    feed_tracker(tracker, kMwebTip, tip_hdr);

    struct Case { const char* what; uint256 view_hash; uint32_t view_height; };
    const Case cases[] = {
        {"heal stuck on a sibling", hash_of(child_of(hx("00000000000000000000000000000000000000000000000000000000000000ee"), 2)), kMwebTip},
        {"gap body never served", hx("00000000000000000000000000000000000000000000000000000000000000dd"), kMwebTip - 1},
    };
    for (const auto& k : cases) {
        View view;
        Mempool pool;
        fill(pool, view);
        clean_for(pool, tip_hdr);
        view.best(k.view_hash, k.view_height);
        auto b = build(*chain, pool, &tracker);
        expect_empty_on_tip(b, hash_of(tip_hdr), kNotAtTip, kMwebTip + 1);
        ASSERT_TRUE(b.wd) << k.what;
        const auto& txs = b.wd->m_data["transactions"];
        ASSERT_EQ(txs.size(), 1u) << k.what << ": the HogEx only";
        EXPECT_TRUE(core::coin::tx_hex_is_hogex(txs[0]["data"].get<std::string>())) << k.what;
        EXPECT_FALSE(b.wd->m_data["mweb"].get<std::string>().empty()) << k.what;
        EXPECT_FALSE(core::coin::check_template_txs(b.wd->m_data)) << k.what << ": a block litecoind accepts";
    }
}

// Without the tip's MWEB state (its body has not arrived) no HogEx can be
// built: the template is refused exactly as before -- no pool tx, no HogEx,
// the shape check fails -- and the ingress guard keeps today's MWEB
// behaviour (HOLD the previous template; with none, serve it degraded:
// shares and merged work only, every LTC block refused at assembly).
TEST(LtcTemplateGapGate, NoMwebStateForTheTipKeepsTheMwebHold)
{
    const BlockHeaderType tip_hdr = child_of(hx("00000000000000000000000000000000000000000000000000000000000000ee"), 1);
    const BlockHeaderType parent = child_of(hx("00000000000000000000000000000000000000000000000000000000000000ee"), 5);
    auto chain = mweb_chain(tip_hdr);
    MWEBTracker tracker;
    feed_tracker(tracker, kMwebTip - 1, parent);  // the parent's state only
    View view;
    Mempool pool;
    fill(pool, view);
    view.best(parent, kMwebTip - 1);
    auto b = build(*chain, pool, &tracker);
    EXPECT_FALSE(b.wd);
    ASSERT_TRUE(b.refused);
    EXPECT_TRUE(core::coin::check_template_shape(b.refused->m_data)) << "the ingress guard HOLDs it";
    EXPECT_TRUE(b.refused->m_data["mweb"].get<std::string>().empty());
    EXPECT_EQ(b.refused->m_data["transactions"].size(), 0u) << "no pool tx, no HogEx";
    EXPECT_EQ(core::coin::template_degraded_code(b.refused->m_data),
              std::optional<std::string>(core::coin::kNotCleanedForTip));
}

// core::coin::template_pool_gate.
TEST(LtcTemplateGapGate, TemplatePoolGateHelper)
{
    using core::coin::BlockRef;
    using core::coin::template_pool_gate;
    const BlockRef tip{5, hx("05")};
    EXPECT_EQ(template_pool_gate(true, false, BlockRef{1, hx("01")}, tip), nullptr) << "empty pool";
    EXPECT_STREQ(template_pool_gate(false, false, tip, tip), core::coin::kNotCleanedForTip);
    EXPECT_EQ(template_pool_gate(false, true, tip, tip), nullptr);
    EXPECT_EQ(template_pool_gate(false, true, std::nullopt, tip), nullptr) << "no best block: prices nothing";
    EXPECT_STREQ(template_pool_gate(false, true, BlockRef{4, hx("04")}, tip), core::coin::kUtxoViewNotAtTip);
    EXPECT_STREQ(template_pool_gate(false, true, BlockRef{5, hx("55")}, tip), core::coin::kUtxoViewNotAtTip);
    EXPECT_STREQ(template_pool_gate(false, true, BlockRef{6, hx("06")}, tip), core::coin::kUtxoViewNotAtTip);
    EXPECT_STREQ(template_pool_gate(false, true, BlockRef{4, hx("05")}, tip), core::coin::kUtxoViewNotAtTip)
        << "hash and height must both match";
}

// L3 T7's cleaned_for semantics, with the window the tip check relies on:
// the tip stays cleaned while up to CLEANED_BLOCKS_KEPT - 1 later bodies (late
// copies, stale siblings) are cleaned after it; one more pushes it out.
TEST(LtcTemplateGapGate, CleanedForRemembersAtLeast32Blocks)
{
    static_assert(Mempool::CLEANED_BLOCKS_KEPT >= 32, "the tip must outlive a burst of side bodies");
    Mempool pool;
    const BlockHeaderType tip = child_of(hash_of(testnet_genesis()), 50);
    clean_for(pool, tip);
    for (uint32_t i = 0; i + 1 < Mempool::CLEANED_BLOCKS_KEPT; ++i)
        clean_for(pool, child_of(hash_of(tip), 100 + i));
    EXPECT_TRUE(pool.cleaned_for(hash_of(tip)));
    // The same block again does not take a second place.
    clean_for(pool, tip);
    EXPECT_TRUE(pool.cleaned_for(hash_of(tip)));
    clean_for(pool, child_of(hash_of(tip), 999));
    EXPECT_FALSE(pool.cleaned_for(hash_of(tip)));
}
