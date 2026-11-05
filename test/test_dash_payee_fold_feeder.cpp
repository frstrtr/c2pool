// SPDX-License-Identifier: AGPL-3.0-or-later
/// PayeeFoldFeeder (payee_fold_feeder.hpp) — ordered connect for the DASH
/// payee lane and the UTXO lane.
///
/// THE INCIDENT these pin (hotel reserve, 2026-10-26 22:00-22:06 MSK): a
/// coin-P2P blackout lost the invs for h=2561877/2561878; their headers came
/// via getheaders, nothing ever asked for their bodies, 2561879 then arrived
/// first and the maintainer answered `PAYEE APPLY GAP` with a wipe — 43 minutes
/// without work, and a second gap 4 h later forced a 12 571-block cold replay.
///
/// The rig is main_dash's wiring in miniature: Node::block_connected ->
/// PayeeFoldFeeder -> (UTXO lane, then) CoinStateMaintainer::on_block_connected,
/// with the feeder's header-chain lookups and getdata seam stubbed so every
/// request is observable. Each KAT names what it asserts and what the
/// arrival-order feed (no feeder) did instead.
///
/// Rides the allowlisted test_dash_coin_state_maintainer target (second TU; no
/// new target, no workflow edit).

#include <gtest/gtest.h>

#include <impl/dash/coin/payee_fold_feeder.hpp>
#include <impl/dash/coin/coin_state_maintainer.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/embedded_gbt.hpp>        // encode_cbtx
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/block_producer.hpp>      // compute_merkle_root
#include <impl/dash/coin/utxo_adapter.hpp>        // dash_txid
#include <impl/dash/coin/utxo_lane.hpp>           // UtxoLane (KAT 7)
#include <impl/dash/coin/subsidy.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>

#include <impl/dash/crypto/hash_x11.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

using dash::coin::BlockType;
using dash::coin::CoinStateMaintainer;
using dash::coin::DashWorkData;
using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::MutableTransaction;
using dash::coin::NodeCoinState;
using dash::coin::PayeeFeedAction;
using dash::coin::PayeeFoldFeeder;
using dash::coin::UtxoLane;
using dash::coin::WorkSelection;
using dash::coin::WorkSource;
using dash::coin::payee_feed_action;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

namespace {

constexpr uint8_t  kPubkeyVer = 76;
constexpr uint8_t  kP2shVer   = 16;
constexpr uint32_t kBits      = 0x1b104be3u;
constexpr uint32_t kMtp       = 1'700'000'000u;
constexpr uint32_t kCurtime   = 1'700'000'123u;
constexpr uint32_t kVersion   = 0x20000000u;
// The incident's own heights: the payee cursor stood at 2561876.
constexpr uint32_t H = 2'561'876;

uint256 raw256(uint8_t base)
{
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

std::vector<unsigned char> p2pkh(uint8_t seed)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(seed + i));
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

const std::vector<unsigned char> kPayout = p2pkh(0x30);

MutableTransaction make_spend(uint32_t salt)
{
    MutableTransaction tx;
    tx.version = 1; tx.type = 0; tx.locktime = salt;
    TxIn in; in.prevout.hash = raw256(0x91); in.prevout.index = salt;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    TxOut o; o.value = 1'000;
    tx.vout.push_back(o);
    return tx;
}

std::vector<std::pair<uint256, MNState>> single_mn()
{
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = kPayout;
    s.payoutSplitProvenance = MNState::SPLIT_KNOWN;
    return {{raw256(0x01), s}};
}

uint256 x11_of(const BlockType& b)
{
    auto packed = ::pack(static_cast<const dash::coin::BlockHeaderType&>(b));
    return ::dash::crypto::hash_x11(packed.get_span());
}

/// A bound block at `height`: a type-5 CbTx coinbase that pays the single
/// masternode (so every fold is a clean, non-desync fold) and commits
/// `credit_pool`. `salt` makes a same-height FORK twin with another hash.
BlockType make_block(uint32_t height, int64_t credit_pool, uint32_t salt = 0)
{
    dash::coin::vendor::CCbTx cb;
    cb.nVersion = dash::coin::vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
    cb.nHeight  = static_cast<int32_t>(height);
    cb.creditPoolBalance = credit_pool;
    MutableTransaction tx;
    tx.version = 3; tx.type = 5; tx.locktime = height + salt;
    TxIn in; in.prevout.hash = uint256::ZERO; in.prevout.index = 0xffffffffu;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    TxOut o; o.value = 500'000'000; o.scriptPubKey.m_data = kPayout;
    tx.vout.push_back(o);
    tx.extra_payload = dash::coin::encode_cbtx(cb);
    BlockType b;
    b.m_version   = 0x20000000u;
    b.m_timestamp = 1'700'000'000u + height;
    b.m_bits      = kBits;
    b.m_nonce     = height * 7 + salt;
    b.m_txs.push_back(tx);
    std::vector<uint256> ids;
    for (const auto& t : b.m_txs) ids.push_back(dash::coin::dash_txid(t));
    b.m_merkle_root = dash::coin::compute_merkle_root(ids);
    return b;
}

/// main_dash's leg-3 wiring in miniature.
struct FeedRig {
    NodeCoinState       st;
    CoinStateMaintainer m{st};
    PayeeFoldFeeder     f;
    std::map<uint32_t, BlockType> chain;       // the header chain's best block per height
    std::map<uint32_t, int64_t>   balance;
    uint32_t tip{0};
    int64_t  now_ms{1'000'000};
    std::vector<std::pair<uint256, uint32_t>> requests;
    std::vector<uint32_t> folded;               // heights the payee lane received, in order
    int  gaps{0};
    int  reseeds{0};
    std::vector<std::shared_ptr<EventDisposable>> subs;

    explicit FeedRig(uint32_t seed_at, uint32_t chain_top)
    {
        m.set_require_seeded_mn_set(true);   // the production posture
        m.set_on_mn_reseed([this] { ++reseeds; });
        balance[seed_at] = 111'000'000LL;
        for (uint32_t h = seed_at; h <= chain_top; ++h) {
            if (h > seed_at)
                balance[h] = balance[h - 1]
                    + dash::coin::compute_dash_platform_reward_post_v20_mn_rr(
                          h, st.mn_rr_height());
            chain[h] = make_block(h, balance[h]);
        }
        tip = seed_at;
        f.set_cursor_fn([this] { return m.payee_fold_cursor(); });
        f.set_tip_height_fn([this] { return tip; });
        f.set_hash_at_fn([this](uint32_t h) -> std::optional<uint256> {
            auto it = chain.find(h);
            if (it == chain.end()) return std::nullopt;
            return x11_of(it->second);
        });
        f.set_request_fn([this](const uint256& hash, uint32_t h) {
            requests.emplace_back(hash, h);
            return true;
        });
        f.set_clock_fn([this] { return now_ms; });
        subs.push_back(f.ordered.subscribe(
            [this](const dash::interfaces::BlockConnected& bc) {
                folded.push_back(bc.height);
                auto r = m.on_block_connected(bc.block, bc.height);
                if (r.gap_detected) ++gaps;
            }));
    }

    void seed(uint32_t as_of) { m.on_mn_list_update(single_mn(), as_of, "mn-ckpt"); }
    void deliver(uint32_t h) { f.on_block_connected({chain.at(h), h}); }
    void deliver_block(const BlockType& b, uint32_t h) { f.on_block_connected({b, h}); }
    uint32_t cursor() { return std::as_const(st).mnstates().last_applied_height(); }
    bool asked_for(uint32_t h) const
    {
        for (const auto& [hash, hh] : requests)
            if (hh == h && hash == x11_of(chain.at(h))) return true;
        return false;
    }
    size_t asks_for(uint32_t h) const
    {
        size_t n = 0;
        for (const auto& r : requests) if (r.second == h) ++n;
        return n;
    }
};

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// The rule itself (utxo_order.hpp's utxo_connect_action, DASH dialect).
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPayeeFoldFeeder, ActionRuleMatchesTheLtcOrderedConnect)
{
    EXPECT_EQ(payee_feed_action(0, 10, true), PayeeFeedAction::Pass)
        << "no ordered cursor = today's arrival-order feed";
    EXPECT_EQ(payee_feed_action(10, 10, true), PayeeFeedAction::Pass);
    EXPECT_EQ(payee_feed_action(10, 9, false), PayeeFeedAction::Pass)
        << "at/below the cursor the sinks guard themselves";
    EXPECT_EQ(payee_feed_action(10, 11, true), PayeeFeedAction::Deliver);
    EXPECT_EQ(payee_feed_action(10, 11, std::nullopt), PayeeFeedAction::Deliver);
    EXPECT_EQ(payee_feed_action(10, 13, true), PayeeFeedAction::Park);
    EXPECT_EQ(payee_feed_action(10, 11, false), PayeeFeedAction::DropFork);
    EXPECT_EQ(payee_feed_action(10, 13, false), PayeeFeedAction::DropFork);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 1 — PayeeLane_OutOfOrderBodyIsParkedNotWiped
// Seed as-of H; bodies arrive H+3, then H+1, H+2. The payee queue must end at
// H+3 with nothing wiped. Arrival order (master): H+3 hits APPLY GAP and the
// queue is wiped + re-seed asked.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPayeeFoldFeeder, PayeeLane_OutOfOrderBodyIsParkedNotWiped)
{
    FeedRig r(H, H + 3);
    r.seed(H);
    r.tip = H + 3;
    ASSERT_EQ(r.m.payee_fold_cursor(), H);

    r.deliver(H + 3);
    EXPECT_EQ(r.gaps, 0) << "H+3 on cursor H must be PARKED, not applied";
    EXPECT_EQ(r.reseeds, 0) << "no re-seed may be asked for a transport hole";
    EXPECT_FALSE(r.m.mn_needs_reseed_latched());
    EXPECT_EQ(r.st.mnstates().size(), 1u) << "the payee queue must not be wiped";
    EXPECT_TRUE(r.f.is_parked(H + 3));
    EXPECT_TRUE(r.asked_for(H + 1)) << "the missing heights are fetched at once";
    EXPECT_TRUE(r.asked_for(H + 2));

    r.deliver(H + 1);
    EXPECT_EQ(r.cursor(), H + 1);
    r.deliver(H + 2);
    EXPECT_EQ(r.cursor(), H + 3) << "H+2 drains the parked H+3 in order";
    EXPECT_EQ(r.f.parked(), 0u);
    EXPECT_EQ(r.gaps, 0);
    EXPECT_EQ(r.reseeds, 0);
    EXPECT_FALSE(r.m.mn_needs_reseed_latched());
    EXPECT_EQ(r.st.mnstates().size(), 1u);
    EXPECT_EQ(r.folded, (std::vector<uint32_t>{H + 1, H + 2, H + 3}))
        << "the payee lane must see strictly ascending heights";
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 2 — PayeeLane_HeaderAdvanceWithoutInvRequestsBodiesByHeight
// The header tip moves H -> H+2 and NO inv / new_block ever arrives (the
// reserve blackout). Within one tick past the inv grace the feeder must ask
// for both bodies BY HEADER-CHAIN HASH. Master: nothing ever asks.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPayeeFoldFeeder, PayeeLane_HeaderAdvanceWithoutInvRequestsBodiesByHeight)
{
    FeedRig r(H, H + 2);
    r.seed(H);
    r.tip = H + 2;
    r.f.on_tip_changed();
    EXPECT_TRUE(r.requests.empty())
        << "inside the inv grace the inv path gets first go (no duplicate getdata)";

    r.now_ms += PayeeFoldFeeder::kFirstAskGraceMs;
    r.f.tick();
    EXPECT_TRUE(r.asked_for(H + 1)) << "lost inv: H+1 must be fetched by position";
    EXPECT_TRUE(r.asked_for(H + 2)) << "lost inv: H+2 must be fetched by position";

    // ...and the bodies, whatever order the peers answer in, fold in order.
    r.deliver(H + 2);
    r.deliver(H + 1);
    EXPECT_EQ(r.cursor(), H + 2);
    EXPECT_EQ(r.gaps, 0);
    EXPECT_EQ(r.reseeds, 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 3 — PayeeLane_TipBodyOverdueTriggersFetchNotJustDemote
// Body-first serve tip at H, header tip H+1, the body never comes. Over 30 s
// the feeder asks and RE-ASKS (10 s) while the maintainer keeps the gate shut
// (tip-body-pending, then the overdue demote): never a template built on a
// payee queue behind the tip. Master: the overdue path demotes and asks for
// nothing (tip-body-overdue only re-requests the SML diff).
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPayeeFoldFeeder, PayeeLane_TipBodyOverdueTriggersFetchNotJustDemote)
{
    FeedRig r(H, H + 1);
    int64_t now_s = 1'000'000;
    r.m.set_body_first_serve_tip(true);
    r.m.set_now_fn([&] { return now_s; });
    r.m.set_tip_body_overdue_secs(30);
    r.seed(H);
    r.m.on_new_tip(H, x11_of(r.chain[H]), kBits, kMtp, kPubkeyVer, kP2shVer,
                   kCurtime, kVersion);
    r.m.on_block_connected(r.chain[H], H);   // credit pool at H: serve tip H
    ASSERT_TRUE(r.m.live());
    ASSERT_EQ(r.m.serve_tip_height(), H);

    // Header H+1 (its inv lost).
    r.tip = H + 1;
    r.m.on_new_tip(H + 1, x11_of(r.chain[H + 1]), kBits, kMtp, kPubkeyVer,
                   kP2shVer, kCurtime, kVersion);
    r.f.on_tip_changed();
    for (int t = 0; t <= 30; t += 3) {      // the 3 s pool tick for 30 s
        r.now_ms += 3000;
        now_s += 3;
        r.f.tick();
        r.m.on_mempool_tx(make_spend(static_cast<uint32_t>(t)));   // the maintainer's clock
    }
    EXPECT_TRUE(r.asked_for(H + 1)) << "an overdue tip body must be FETCHED";
    EXPECT_GE(r.asks_for(H + 1), 3u)
        << "and re-asked every 10 s while it stays missing";
    EXPECT_FALSE(r.m.live()) << "past the overdue bound the serve tip demotes";
    EXPECT_EQ(r.st.describe_decline().cause, "tip-body-pending");
    bool fb = false;
    WorkSelection sel = r.st.select_work([&] { fb = true; return DashWorkData{}; });
    EXPECT_NE(sel.source, WorkSource::Embedded)
        << "no template while the payee queue is behind the tip";

    // The fetched body lands: promotion re-arms the serve tip at H+1.
    r.deliver(H + 1);
    EXPECT_EQ(r.cursor(), H + 1);
    EXPECT_TRUE(r.m.live());
    EXPECT_EQ(r.m.serve_tip_height(), H + 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 4 — PayeeLane_ServeGateClosedWhileBehindTip (GUARD: holds before AND
// after the fix). H+2 parked, cursor H, header tip H+2. Whatever the arm does
// in that window it never builds a template on a block the payee queue has
// not folded: body-first keeps serving the H-based template (height H+1) or
// refuses; header-first refuses `payee-stale`.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPayeeFoldFeeder, PayeeLane_ServeGateClosedWhileBehindTip)
{
    for (const bool body_first : {true, false}) {
        SCOPED_TRACE(body_first ? "body-first" : "header-first");
        FeedRig r(H, H + 2);
        r.st.set_require_fresh_mn_payee(true);
        r.m.set_body_first_serve_tip(body_first);
        r.seed(H);
        r.m.on_new_tip(H, x11_of(r.chain[H]), kBits, kMtp, kPubkeyVer, kP2shVer,
                       kCurtime, kVersion);
        r.m.on_block_connected(r.chain[H], H);
        r.tip = H + 2;
        r.m.on_new_tip(H + 2, x11_of(r.chain[H + 2]), kBits, kMtp, kPubkeyVer,
                       kP2shVer, kCurtime, kVersion);
        r.deliver(H + 2);   // ahead of the cursor

        const uint32_t cursor = r.cursor();
        bool fb = false;
        WorkSelection sel = r.st.select_work([&] { fb = true; return DashWorkData{}; });
        if (sel.source == WorkSource::Embedded) {
            EXPECT_LE(sel.work.m_height, cursor + 1)
                << "a template may only build on a block the payee queue folded";
        } else {
            const auto d = r.st.describe_decline();
            EXPECT_FALSE(d.viable);
            EXPECT_TRUE(d.cause == "tip-body-pending" || d.cause == "payee-stale"
                        || d.cause == "mn-needs-reseed" || d.cause == "not-populated")
                << d.cause;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 5 — PayeeLane_ForkBodyAtParkedHeightDropped
// A body whose hash is not the header chain's block at its height never
// parks and never folds — ahead of the cursor or at cursor+1. Master: the
// fork body at H+1 folds onto the queue, the one at H+2 wipes it.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPayeeFoldFeeder, PayeeLane_ForkBodyAtParkedHeightDropped)
{
    FeedRig r(H, H + 2);
    r.seed(H);
    r.tip = H + 2;
    const BlockType fork2 = make_block(H + 2, r.balance[H + 2], /*salt=*/99);
    const BlockType fork1 = make_block(H + 1, r.balance[H + 1], /*salt=*/99);
    ASSERT_NE(x11_of(fork2), x11_of(r.chain[H + 2]));

    r.deliver_block(fork2, H + 2);
    EXPECT_FALSE(r.f.is_parked(H + 2)) << "a fork body must not park";
    EXPECT_EQ(r.gaps, 0);
    EXPECT_EQ(r.st.mnstates().size(), 1u);
    r.deliver_block(fork1, H + 1);
    EXPECT_EQ(r.cursor(), H) << "a fork body at cursor+1 must not fold";
    EXPECT_EQ(r.f.fork_drops(), 2u);
    EXPECT_TRUE(r.folded.empty());

    // The best-chain bodies still fold.
    r.deliver(H + 1);
    r.deliver(H + 2);
    EXPECT_EQ(r.cursor(), H + 2);
    EXPECT_EQ(r.reseeds, 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 5b — PayeeLane_ParkedBodyReorgedBeforeDrainIsDropped (verify M1)
// H+2 arrives first and is the chain's block there, so it PARKS. Before H+1
// fills the hole the header chain reorgs at H+2 (a tip race whose loser's
// body we held). When H+1 lands the parked loser must NOT fold — the
// maintainer binds a body only to its own header and apply_block has no
// prev-hash linkage, so it would fold the loser's coinbase mark and ProTx set
// and then ignore the winner as <= cursor. It is dropped, and the winner is
// asked for by its hash at once.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPayeeFoldFeeder, PayeeLane_ParkedBodyReorgedBeforeDrainIsDropped)
{
    FeedRig r(H, H + 2);
    r.seed(H);
    r.tip = H + 2;
    const BlockType loser = r.chain[H + 2];
    r.deliver(H + 2);
    ASSERT_TRUE(r.f.is_parked(H + 2)) << "on the chain at arrival: parked";

    // Reorg at H+2 while it waits.
    r.chain[H + 2] = make_block(H + 2, r.balance[H + 2], /*salt=*/77);
    ASSERT_NE(x11_of(r.chain[H + 2]), x11_of(loser));
    r.requests.clear();

    r.deliver(H + 1);
    EXPECT_EQ(r.cursor(), H + 1) << "the reorged-out parked body must not fold";
    EXPECT_EQ(r.folded, (std::vector<uint32_t>{H + 1}));
    EXPECT_EQ(r.f.fork_drops(), 1u);
    EXPECT_EQ(r.f.stale_parked_drops(), 1u);
    EXPECT_FALSE(r.f.is_parked(H + 2));
    EXPECT_TRUE(r.asked_for(H + 2))
        << "the block the chain holds at H+2 NOW is asked for, by its hash";
    EXPECT_EQ(r.reseeds, 0);

    // The winner lands and folds.
    r.deliver(H + 2);
    EXPECT_EQ(r.cursor(), H + 2);
    EXPECT_EQ(r.folded, (std::vector<uint32_t>{H + 1, H + 2}));
    EXPECT_EQ(r.gaps, 0);
}

// S5: the chain's block for a parked height arrives while the reorged-out
// loser is still held there — the winner replaces it, and folds the moment the
// hole fills, with no drop-and-refetch round trip.
TEST(DashPayeeFoldFeeder, PayeeLane_OnChainWinnerReplacesAParkedLoser)
{
    FeedRig r(H, H + 2);
    r.seed(H);
    r.tip = H + 2;
    r.deliver(H + 2);                       // the loser, on the chain at arrival
    ASSERT_TRUE(r.f.is_parked(H + 2));
    r.chain[H + 2] = make_block(H + 2, r.balance[H + 2], /*salt=*/77);
    r.deliver(H + 2);                       // the winner arrives, still ahead
    EXPECT_EQ(r.f.parked(), 1u);
    r.deliver(H + 1);
    EXPECT_EQ(r.cursor(), H + 2) << "the winner folds when the hole fills";
    EXPECT_EQ(r.folded, (std::vector<uint32_t>{H + 1, H + 2}));
    EXPECT_EQ(r.f.fork_drops(), 0u) << "nothing to drop: the loser was replaced";
    EXPECT_EQ(r.gaps, 0);
}

// S4: park overflow releases the lowest held body to the payee lane — unless
// that body lost its height to a reorg, which is dropped instead (still one
// out, one in) and never reaches the lane.
TEST(DashPayeeFoldFeeder, PayeeLane_OverflowDropsAReorgedLowestBody)
{
    const uint32_t cap = static_cast<uint32_t>(PayeeFoldFeeder::kParkCap);
    FeedRig r(H, H + cap + 2);
    r.seed(H);
    r.tip = H + cap + 2;
    for (uint32_t h = H + 2; h < H + 2 + cap; ++h) r.deliver(h);
    ASSERT_EQ(r.f.parked(), PayeeFoldFeeder::kParkCap);
    r.chain[H + 2] = make_block(H + 2, r.balance[H + 2], /*salt=*/77);   // reorg
    r.deliver(H + 2 + cap);
    EXPECT_EQ(r.f.overflows(), 1u);
    EXPECT_EQ(r.f.parked(), PayeeFoldFeeder::kParkCap) << "bounded";
    EXPECT_FALSE(r.f.is_parked(H + 2));
    EXPECT_TRUE(r.folded.empty()) << "the reorged-out body never reaches the lane";
    EXPECT_EQ(r.reseeds, 0);
    EXPECT_EQ(r.f.stale_parked_drops(), 1u);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 6 — PayeeLane_ParkOverflowFallsBackToWipe
// cursor+1 never arrives while kParkCap later bodies do: memory stays bounded
// and the lane takes today's fail-closed wipe + re-seed (the invariant is
// still reachable). Master: the wipe fires on the very first body.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPayeeFoldFeeder, PayeeLane_ParkOverflowFallsBackToWipe)
{
    const uint32_t cap = static_cast<uint32_t>(PayeeFoldFeeder::kParkCap);
    FeedRig r(H, H + cap + 2);
    r.seed(H);
    r.tip = H + cap + 2;
    for (uint32_t h = H + 2; h < H + 2 + cap; ++h) r.deliver(h);
    EXPECT_EQ(r.f.parked(), PayeeFoldFeeder::kParkCap);
    EXPECT_EQ(r.reseeds, 0) << "up to the cap, a hole is held, not wiped";
    EXPECT_EQ(r.st.mnstates().size(), 1u);

    r.deliver(H + 2 + cap);   // one past the cap
    EXPECT_EQ(r.f.overflows(), 1u);
    EXPECT_EQ(r.gaps, 1) << "overflow hands the lowest body to the payee lane";
    EXPECT_EQ(r.reseeds, 1) << "...which takes the fail-closed re-seed path";
    EXPECT_TRUE(r.m.mn_needs_reseed_latched());
    EXPECT_EQ(r.st.mnstates().size(), 0u);
    EXPECT_EQ(r.f.parked(), 0u) << "no cursor any more: everything held is released";
    EXPECT_EQ(r.m.payee_fold_cursor(), 0u);
    EXPECT_EQ(r.m.last_reseed_reason(), CoinStateMaintainer::ReseedReason::Gap);
    EXPECT_TRUE(r.m.has_gap_seed())
        << "the wiped queue is kept as the gap re-seed's resume point";
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 7 — UtxoLane_SameOrderedFeed
// The UTXO lane rides the same ordered stream (main_dash subscribes it first):
// its best height never advances over a hole. Master: utxo_lane.hpp's
// `height > best` connects H+2 over the missing H+1.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPayeeFoldFeeder, UtxoLane_SameOrderedFeed)
{
    const auto dir = std::filesystem::temp_directory_path()
        / ("c2pool-payee-feed-utxo-" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    {
        FeedRig r(H, H + 3);
        UtxoLane lane;
        ASSERT_TRUE(lane.open((dir / "utxo").string()));
        // A warm lane at H (no cold-start bootstrap): flush an empty batch at H.
        ASSERT_TRUE(lane.cache()->flush(x11_of(r.chain[H]), H));
        ASSERT_EQ(lane.cache()->get_best_height(), H);
        // UTXO first, maintainer second — main_dash's order.
        for (auto& sub : r.subs) sub->dispose();
        r.subs.clear();
        r.subs.push_back(r.f.ordered.subscribe(
            [&lane](const dash::interfaces::BlockConnected& bc) {
                lane.on_block_connected(bc.block, bc.height);
            }));
        r.subs.push_back(r.f.ordered.subscribe(
            [&r](const dash::interfaces::BlockConnected& bc) {
                r.folded.push_back(bc.height);
                if (r.m.on_block_connected(bc.block, bc.height).gap_detected)
                    ++r.gaps;
            }));
        r.seed(H);
        r.tip = H + 3;

        r.deliver(H + 1);   // the warm lane's first block: normal processing
        ASSERT_EQ(lane.cache()->get_best_height(), H + 1);

        r.deliver(H + 3);   // H+2's inv was lost
        EXPECT_EQ(lane.cache()->get_best_height(), H + 1)
            << "the UTXO view must not connect H+3 over the missing H+2";
        r.deliver(H + 2);
        EXPECT_EQ(lane.cache()->get_best_height(), H + 3)
            << "H+2 then the parked H+3, in order";
        EXPECT_EQ(lane.cache()->get_best_block(), x11_of(r.chain[H + 3]));
        EXPECT_EQ(r.cursor(), H + 3) << "payee and UTXO lanes stay in lockstep";
        EXPECT_EQ(r.gaps, 0);
    }
    std::filesystem::remove_all(dir);
}

// ═══════════════════════════════════════════════════════════════════════════
// Passthrough: with no ordered cursor (unseeded / wiped) the feeder is
// exactly today's feed — arrival order, every body, nothing fetched.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPayeeFoldFeeder, NoCursorIsArrivalOrderPassthrough)
{
    FeedRig r(H, H + 3);
    r.tip = H + 3;                    // never seeded: payee_fold_cursor() == 0
    ASSERT_EQ(r.m.payee_fold_cursor(), 0u);
    r.deliver(H + 3);
    r.deliver(H + 1);
    r.now_ms += 60'000;
    r.f.tick();
    EXPECT_EQ(r.folded, (std::vector<uint32_t>{H + 3, H + 1}));
    EXPECT_TRUE(r.requests.empty());
    EXPECT_EQ(r.f.parked(), 0u);
}
