// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ── THE SERVE SEAM: the replay fold FEEDS the payee queue ──────────────────
//
// src/impl/dash/coin/replay_payee_publish.hpp turns W1's root-checked
// deterministic masternode list into the authoritative PAYEE snapshot the
// serve gate needs (`have_mn`), through the exact same leg-4 event the dashd
// `protx list` seed and the compiled-in checkpoint bridge use.
//
// Measured on contabo (pure daemonless, no dashd at all): the fold rebuilt
// the DML to tip in 264 s with 4690/4690 byte-exact roots while the gate sat
// on `DECLINED cause=not-populated value=have_tip=1,have_mn=0` for 40-60 min
// waiting on a SECOND, independent reconstruction. Nothing consumed the fold.
//
// What must be true for that to be SAFE, and is pinned here:
//
//   1. a PROVEN-CURRENT fold publishes, names itself `replay-fold`, and
//      carries the payee axis faithfully (scripts, heights, eligibility,
//      operator split);
//   2. a fold that DIVERGED / is POISONED / is BEHIND THE TIP / was not
//      fully root-checked / whose list no longer re-hashes to the root it
//      matched publishes NOTHING, and says which condition blocked;
//   3. it is ONE-SHOT — the payee queue is a snapshot plus a forward apply
//      cursor, so only an explicit re-seed ask may republish;
//   4. a re-seed ask the fold cannot answer FALLS THROUGH, so the mn-ckpt /
//      dashd lanes keep their job.
//
// Real mainnet bytes throughout: the h=2516755 full-state prestate and the
// real bodies of h=2516756..2516760, the same fixtures test_dash_replay_fold
// checks the fold rules against.

#include <gtest/gtest.h>

#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/replay_fold_consumer.hpp>
#include <impl/dash/coin/replay_payee_publish.hpp>
#include <impl/dash/coin/block.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstring>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "data/dash_replay_prestate_2516755.inc"
#include "data/dash_replay_block_2516756.inc"
#include "data/dash_replay_block_2516757.inc"
#include "data/dash_replay_block_2516758.inc"
#include "data/dash_replay_block_2516759.inc"
#include "data/dash_replay_block_2516760.inc"

using dash::coin::BlockType;
using dash::coin::MNState;
using dash::coin::replay::DmlFoldEngine;
using dash::coin::replay::FoldConfig;
using dash::coin::replay::FoldConsumerStats;
using dash::coin::replay::FoldLiveTail;
using dash::coin::replay::FoldReplayConsumer;
using dash::coin::replay::ReplayMNState;
using dash::coin::replay::ReplayPayeePublisher;
using dash::coin::replay::evaluate_payee_guard;
using dash::coin::replay::to_payee_state;

namespace {

// ── minimal fixture parsing (kept local; the .inc symbols are `static`) ────

bool pp_hex_to_bytes(const std::string& s, std::vector<uint8_t>& out)
{
    if (s.size() % 2 != 0) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    for (size_t i = 0; i < s.size(); i += 2) {
        const int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

uint256 pp_u256_wire(const std::string& h)
{
    uint256 v;
    std::vector<uint8_t> b;
    if (pp_hex_to_bytes(h, b) && b.size() == 32) std::memcpy(v.data(), b.data(), 32);
    return v;
}

uint160 pp_u160_wire(const std::string& h)
{
    uint160 v;
    std::vector<uint8_t> b;
    if (pp_hex_to_bytes(h, b) && b.size() == 20) std::memcpy(v.data(), b.data(), 20);
    return v;
}

std::vector<std::string> pp_split(const std::string& line)
{
    std::vector<std::string> out;
    std::istringstream is(line);
    std::string tok;
    while (is >> tok) out.push_back(tok);
    return out;
}

struct PpPrestate {
    std::string network;
    uint32_t    height{0};
    std::string blockhash_display;
    std::string mnroot_display;
    std::vector<std::pair<uint256, ReplayMNState>> entries;
};

PpPrestate pp_parse_prestate(const char* text)
{
    PpPrestate fx;
    std::istringstream is(text);
    std::string line;
    std::getline(is, line);           // format tag
    while (std::getline(is, line)) {
        auto f = pp_split(line);
        if (f.empty()) continue;
        if (f[0] == "network")   { fx.network = f[1]; continue; }
        if (f[0] == "height")    { fx.height = static_cast<uint32_t>(std::stoul(f[1])); continue; }
        if (f[0] == "blockhash") { fx.blockhash_display = f[1]; continue; }
        if (f[0] == "mnroot")    { fx.mnroot_display = f[1]; continue; }
        if (f[0] == "count")     { continue; }
        if (f[0] != "mn" || f.size() != 26) continue;

        const uint256 protx = pp_u256_wire(f[1]);
        ReplayMNState st;
        if (f[2] != "-") st.UpdateConfirmedHash(protx, pp_u256_wire(f[2]));
        std::vector<uint8_t> ip;
        pp_hex_to_bytes(f[3], ip);
        if (ip.size() == 16) std::memcpy(st.netInfo.ip.data(), ip.data(), 16);
        st.netInfo.port_be = static_cast<uint16_t>(std::stoul(f[4]));
        if (f[5] != "-") {
            std::vector<uint8_t> pk;
            pp_hex_to_bytes(f[5], pk);
            if (pk.size() == 48) std::memcpy(st.pubKeyOperator.data(), pk.data(), 48);
        }
        st.keyIDVoting      = pp_u160_wire(f[6]);
        st.keyIDOwner       = pp_u160_wire(f[7]);
        st.nVersion         = static_cast<uint16_t>(std::stoul(f[8]));
        st.nType            = static_cast<uint16_t>(std::stoul(f[9]));
        st.platformNodeID   = (f[10] == "-") ? uint160{} : pp_u160_wire(f[10]);
        st.platformP2PPort  = static_cast<uint16_t>(std::stoul(f[11]));
        st.platformHTTPPort = static_cast<uint16_t>(std::stoul(f[12]));
        st.nOperatorReward  = static_cast<uint16_t>(std::stoul(f[13]));
        if (f[14] != "-") {
            std::vector<uint8_t> sp;
            pp_hex_to_bytes(f[14], sp);
            st.scriptPayout.m_data.assign(sp.begin(), sp.end());
        }
        if (f[15] != "-") {
            std::vector<uint8_t> sp;
            pp_hex_to_bytes(f[15], sp);
            st.scriptOperatorPayout.m_data.assign(sp.begin(), sp.end());
        }
        st.nRegisteredHeight    = static_cast<int32_t>(std::stol(f[16]));
        st.nLastPaidHeight      = static_cast<int32_t>(std::stol(f[17]));
        st.nConsecutivePayments = static_cast<int32_t>(std::stol(f[18]));
        st.nPoSePenalty         = static_cast<int32_t>(std::stol(f[19]));
        st.nPoSeBanHeight       = static_cast<int32_t>(std::stol(f[20]));
        st.nPoSeRevivedHeight   = static_cast<int32_t>(std::stol(f[21]));
        st.nRevocationReason    = static_cast<uint16_t>(std::stoul(f[22]));
        st.collateralOutpoint.hash  = pp_u256_wire(f[23]);
        st.collateralOutpoint.index = static_cast<uint32_t>(std::stoul(f[24]));
        st.internalId               = std::stoull(f[25]);
        fx.entries.emplace_back(protx, std::move(st));
    }
    return fx;
}

BlockType pp_parse_block(const char* hex_text)
{
    std::string hex;
    for (const char* p = hex_text; *p; ++p)
        if (*p != '\n' && *p != '\r') hex.push_back(*p);
    std::vector<uint8_t> bytes;
    pp_hex_to_bytes(hex, bytes);
    ::PackStream s(bytes);
    BlockType b;
    s >> b;
    return b;
}

const char* const kBodies[] = {
    kDashReplayBlock2516756, kDashReplayBlock2516757, kDashReplayBlock2516758,
    kDashReplayBlock2516759, kDashReplayBlock2516760,
};
constexpr uint32_t kFirstBody = 2516756;
constexpr uint32_t kLastBody  = 2516760;

// ── the rig: engine + consumer + a recording sink ─────────────────────────

struct Sink {
    struct Call {
        std::vector<std::pair<uint256, MNState>> set;
        uint32_t    as_of{0};
        std::string source;
    };
    std::vector<Call> calls;

    ReplayPayeePublisher::PublishFn fn()
    {
        return [this](std::vector<std::pair<uint256, MNState>> set,
                      uint32_t as_of, const char* source) {
            calls.push_back(Call{std::move(set), as_of, source ? source : ""});
        };
    }
};

struct Rig {
    DmlFoldEngine    engine;
    FoldReplayConsumer consumer;
    Sink             sink;
    uint32_t         tip{0};

    explicit Rig(std::vector<std::pair<uint256, ReplayMNState>> entries,
                 uint32_t anchor_h, const uint256& anchor_hash)
        : engine(make_cfg()), consumer(engine)
    {
        const size_t n = entries.size();
        engine.seed(std::move(entries), n, anchor_h, anchor_hash, "mainnet");
    }

    static FoldConfig make_cfg()
    {
        FoldConfig cfg;
        cfg.enabled = true;   // W1 feature flag — explicit opt-in
        return cfg;
    }

    ReplayPayeePublisher make_publisher()
    {
        return ReplayPayeePublisher(engine, consumer,
                                    [this]() { return tip; }, sink.fn());
    }

    // Fold the real bodies h=2516756..stop through the CONSUMER, so the proof
    // counters and last_matched_root are produced exactly as a live run
    // produces them.
    bool fold_through(uint32_t stop)
    {
        for (uint32_t h = kFirstBody; h <= stop; ++h) {
            auto blk = pp_parse_block(kBodies[h - kFirstBody]);
            if (!consumer.on_replay_block(h, uint256{}, blk)) return false;
        }
        return true;
    }
};

Rig make_clean_rig()
{
    auto fx = pp_parse_prestate(kDashReplayPrestate2516755);
    uint256 anchor;
    anchor.SetHex(fx.blockhash_display);
    Rig rig(fx.entries, fx.height, anchor);
    // The fixture is only trusted BECAUSE it reproduces the committed root.
    EXPECT_EQ(rig.engine.compute_sml_root().GetHex(), fx.mnroot_display);
    return rig;
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// KAT 1 — a PROVEN-CURRENT fold populates the payee queue, and names itself
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashReplayPayeePublish, ProvenCurrentFoldPublishesAndNamesItsSource)
{
    auto rig = make_clean_rig();
    ASSERT_TRUE(rig.fold_through(kLastBody));
    rig.tip = kLastBody;                       // fold cursor == header tip

    auto pub = rig.make_publisher();
    const auto g = pub.evaluate();
    ASSERT_TRUE(g.ok) << g.blocker;
    EXPECT_EQ(g.folded, 5u);
    EXPECT_EQ(g.roots_matched, 5u);            // THE proof counter
    EXPECT_EQ(g.fold_height, kLastBody);

    ASSERT_TRUE(pub.maybe_publish());
    ASSERT_EQ(rig.sink.calls.size(), 1u);
    const auto& c = rig.sink.calls.front();

    // "state says its own name": the queue can tell a daemonlessly derived
    // snapshot from an RPC-seeded one.
    EXPECT_EQ(c.source, "replay-fold");
    // as_of is the FOLDED height, which is what fences the maintainer's
    // forward apply cursor (blocks <= as_of are already reflected).
    EXPECT_EQ(c.as_of, kLastBody);
    EXPECT_EQ(c.set.size(), rig.engine.size());
    EXPECT_GT(c.set.size(), 2000u);            // real mainnet DML

    // The payee axis, entry for entry.
    size_t eligible = 0, banned = 0;
    for (const auto& [protx, mn] : c.set) {
        const ReplayMNState* src = rig.engine.find(protx);
        ASSERT_NE(src, nullptr) << protx.GetHex();
        EXPECT_FALSE(mn.scriptPayout.m_data.empty());
        EXPECT_EQ(mn.scriptPayout.m_data, src->scriptPayout.m_data);
        EXPECT_EQ(mn.scriptOperatorPayout.m_data, src->scriptOperatorPayout.m_data);
        EXPECT_EQ(mn.nOperatorReward, src->nOperatorReward);
        EXPECT_EQ(mn.isValid, !src->IsBanned());
        // Split provenance is EARNED here: every field came from a parsed
        // block body or from the root-verified prestate, so no height may be
        // refused with cause=mn-payout-split-unprovable.
        EXPECT_TRUE(mn.payout_split_provable());
        if (mn.isValid) ++eligible; else ++banned;
    }
    EXPECT_GT(eligible, 0u);
    EXPECT_EQ(eligible + banned, c.set.size());
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 2 — ONE-SHOT, and only an explicit re-seed ask republishes
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashReplayPayeePublish, OneShotThenOnlyReseedRepublishes)
{
    auto rig = make_clean_rig();
    ASSERT_TRUE(rig.fold_through(kLastBody));
    rig.tip = kLastBody;

    auto pub = rig.make_publisher();
    ASSERT_TRUE(pub.maybe_publish());
    // Re-loading a snapshot as-of h after the maintainer has applied live
    // blocks h+1.. would rewind its apply cursor and gap the next block.
    EXPECT_FALSE(pub.maybe_publish());
    EXPECT_FALSE(pub.maybe_publish());
    EXPECT_EQ(rig.sink.calls.size(), 1u);
    EXPECT_EQ(pub.publishes(), 1u);

    // The maintainer wiped a desynced queue and asked. The fold is still
    // proven current, so it answers — republishing the same height is
    // precisely the repair.
    ASSERT_TRUE(pub.republish_for_reseed());
    EXPECT_EQ(rig.sink.calls.size(), 2u);
    EXPECT_EQ(pub.reseeds(), 1u);
    EXPECT_EQ(rig.sink.calls.back().source, "replay-fold");
    EXPECT_EQ(rig.sink.calls.back().as_of, kLastBody);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 3 — THE FAIL-CLOSED GUARD: a fold BEHIND THE TIP must never publish
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashReplayPayeePublish, BehindTheTipMustNotPublish)
{
    auto rig = make_clean_rig();
    ASSERT_TRUE(rig.fold_through(kLastBody - 1));   // 4 of the 5 bodies
    rig.tip = kLastBody;                            // one block behind

    auto pub = rig.make_publisher();
    const auto g = pub.evaluate();
    EXPECT_FALSE(g.ok);
    EXPECT_EQ(g.blocker.substr(0, 2), "G7") << g.blocker;
    EXPECT_NE(g.blocker.find("BEHIND the tip"), std::string::npos) << g.blocker;

    EXPECT_FALSE(pub.maybe_publish());
    EXPECT_TRUE(rig.sink.calls.empty());

    // A re-seed ask it cannot answer FALLS THROUGH — the mn-ckpt / dashd
    // lanes keep their job rather than being silently replaced.
    EXPECT_FALSE(pub.republish_for_reseed());
    EXPECT_TRUE(rig.sink.calls.empty());

    // ... and the very next block closes it.
    ASSERT_TRUE(rig.fold_through(kLastBody));
    EXPECT_TRUE(pub.evaluate().ok);
    EXPECT_TRUE(pub.maybe_publish());
    EXPECT_EQ(rig.sink.calls.size(), 1u);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 4 — THE FAIL-CLOSED GUARD: a DIVERGED / POISONED fold must never publish
//
// Built the only honest way: tamper with the anchor (drop one masternode) so
// the very first real block's committed cbTx root disagrees with our fold.
// W1 poisons; the consumer records the divergence; the publisher refuses.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashReplayPayeePublish, DivergedFoldMustNotPublish)
{
    auto fx = pp_parse_prestate(kDashReplayPrestate2516755);
    ASSERT_GT(fx.entries.size(), 10u);
    fx.entries.erase(fx.entries.begin() + 7);      // ← the tamper
    uint256 anchor;
    anchor.SetHex(fx.blockhash_display);
    Rig rig(fx.entries, fx.height, anchor);
    ASSERT_NE(rig.engine.compute_sml_root().GetHex(), fx.mnroot_display)
        << "the tamper must actually change the list";

    // Fold h=2516756: real bytes, real committed root, wrong state.
    EXPECT_FALSE(rig.fold_through(kFirstBody));
    EXPECT_TRUE(rig.engine.poisoned());
    EXPECT_TRUE(rig.consumer.stats().diverged);
    rig.tip = rig.engine.height();                 // "at tip" — irrelevant now

    auto pub = rig.make_publisher();
    const auto g = pub.evaluate();
    EXPECT_FALSE(g.ok);
    EXPECT_EQ(g.blocker.substr(0, 2), "G1") << g.blocker;
    EXPECT_NE(g.blocker.find("POISONED"), std::string::npos) << g.blocker;

    EXPECT_FALSE(pub.maybe_publish());
    EXPECT_FALSE(pub.republish_for_reseed());
    EXPECT_TRUE(rig.sink.calls.empty());
    EXPECT_EQ(pub.publishes(), 0u);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 5 — the guard conditions a live rig cannot easily reproduce, pinned
//         directly against evaluate_payee_guard()
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashReplayPayeePublish, EveryGuardConditionNamesItself)
{
    auto rig = make_clean_rig();
    ASSERT_TRUE(rig.fold_through(kLastBody));
    const FoldConsumerStats good = rig.consumer.stats();
    ASSERT_TRUE(evaluate_payee_guard(rig.engine, good, kLastBody).ok);

    // G2 — a divergence recorded by the consumer, with a healthy engine.
    {
        FoldConsumerStats s = good;
        s.diverged          = true;
        s.divergence_height = 2516758;
        const auto g = evaluate_payee_guard(rig.engine, s, kLastBody);
        EXPECT_FALSE(g.ok);
        EXPECT_EQ(g.blocker.substr(0, 2), "G2") << g.blocker;
    }
    // G3 — nothing folded proves nothing.
    {
        FoldConsumerStats s;
        const auto g = evaluate_payee_guard(rig.engine, s, kLastBody);
        EXPECT_FALSE(g.ok);
        EXPECT_EQ(g.blocker.substr(0, 2), "G3") << g.blocker;
    }
    // G4 — a block folded but NOT root-checked. This is the one a counter
    // audit exists to catch: the list may be perfect or catastrophic and the
    // fold cannot tell which.
    {
        FoldConsumerStats s = good;
        s.roots_matched -= 1;
        const auto g = evaluate_payee_guard(rig.engine, s, kLastBody);
        EXPECT_FALSE(g.ok);
        EXPECT_EQ(g.blocker.substr(0, 2), "G4") << g.blocker;
    }
    // G5 — the engine cursor is not the height that passed.
    {
        FoldConsumerStats s = good;
        s.last_height -= 1;
        const auto g = evaluate_payee_guard(rig.engine, s, kLastBody);
        EXPECT_FALSE(g.ok);
        EXPECT_EQ(g.blocker.substr(0, 2), "G5") << g.blocker;
    }
    // G6 — THE guard no counter can fake: the list in hand must re-hash, NOW,
    // to the root that block committed.
    {
        FoldConsumerStats s = good;
        s.last_matched_root = uint256{};             // never matched
        const auto g = evaluate_payee_guard(rig.engine, s, kLastBody);
        EXPECT_FALSE(g.ok);
        EXPECT_EQ(g.blocker.substr(0, 2), "G6") << g.blocker;
    }
    {
        FoldConsumerStats s = good;
        s.last_matched_root.data()[0] ^= 0xff;       // one flipped byte
        const auto g = evaluate_payee_guard(rig.engine, s, kLastBody);
        EXPECT_FALSE(g.ok);
        EXPECT_EQ(g.blocker.substr(0, 2), "G6") << g.blocker;
    }
    // G7 — an unknown tip cannot prove currency.
    {
        const auto g = evaluate_payee_guard(rig.engine, good, 0);
        EXPECT_FALSE(g.ok);
        EXPECT_EQ(g.blocker.substr(0, 2), "G7") << g.blocker;
    }
    // G7 — and a fold behind a KNOWN tip stays refused however far behind.
    {
        const auto g = evaluate_payee_guard(rig.engine, good, kLastBody + 500);
        EXPECT_FALSE(g.ok);
        EXPECT_NE(g.blocker.find("500 blocks to go"), std::string::npos)
            << g.blocker;
    }
    // A fold AHEAD of the last header we have is fine — the header chain is
    // what lags, and the list is still the newest proven state.
    {
        const auto g = evaluate_payee_guard(rig.engine, good, kLastBody - 1);
        EXPECT_TRUE(g.ok) << g.blocker;
    }
    // An EMPTY list is a set-gap, never an authoritative snapshot. It is
    // refused EARLIER than G8, at G6: an empty SML's CalcMerkleRoot is the
    // null hash, and G6 rejects a null matched root outright. Pinned as
    // "refused, named" rather than as a specific letter — the defence is
    // layered on purpose and the outer layer is the stricter one.
    {
        DmlFoldEngine empty(Rig::make_cfg());
        empty.seed({}, 0, kLastBody, uint256{}, "mainnet");
        FoldConsumerStats s = good;
        s.last_matched_root = empty.compute_sml_root();
        EXPECT_TRUE(s.last_matched_root.IsNull());
        const auto g = evaluate_payee_guard(empty, s, kLastBody);
        EXPECT_FALSE(g.ok);
        EXPECT_EQ(g.blocker.substr(0, 2), "G6") << g.blocker;
    }
    // G8 — an entry with NO payout script occupies a DIP-3 queue slot it
    // cannot be paid at. Root-clean, current, and still refused.
    {
        ReplayMNState st;
        st.nRegisteredHeight = 2500000;
        st.nPoSeBanHeight    = ReplayMNState::NEVER;
        st.collateralOutpoint.hash.data()[0] = 0x11;
        // scriptPayout deliberately left EMPTY.
        std::vector<std::pair<uint256, ReplayMNState>> one;
        uint256 protx;
        protx.data()[0] = 0x22;
        one.emplace_back(protx, st);

        DmlFoldEngine scriptless(Rig::make_cfg());
        scriptless.seed(std::move(one), 1, kLastBody, uint256{}, "mainnet");
        FoldConsumerStats s = good;
        s.last_matched_root = scriptless.compute_sml_root();  // satisfies G6
        ASSERT_FALSE(s.last_matched_root.IsNull());
        const auto g = evaluate_payee_guard(scriptless, s, kLastBody);
        EXPECT_FALSE(g.ok);
        EXPECT_EQ(g.blocker.substr(0, 2), "G8") << g.blocker;
        EXPECT_NE(g.blocker.find("EMPTY scriptPayout"), std::string::npos)
            << g.blocker;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 6 — the ReplayMNState -> MNState dialect change, field by field
//
// -1 (the fold's NEVER) and 0 (MNState's "never") are the same fact in two
// encodings; getting it wrong pays a banned masternode or sorts the queue by
// a 4-billion height.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashReplayPayeePublish, NeverEncodingAndEligibilityConvertFaithfully)
{
    ReplayMNState st;
    st.nType                = dash::coin::vendor::MnType::EVO;
    st.nVersion             = 2;
    st.nOperatorReward      = 500;                  // 5.00%
    st.scriptPayout.m_data  = {0x76, 0xa9, 0x14, 0x01};
    st.scriptOperatorPayout.m_data = {0x76, 0xa9, 0x14, 0x02};
    st.nRegisteredHeight    = 2500000;
    st.nLastPaidHeight      = 2516700;
    st.nConsecutivePayments = 3;
    st.platformP2PPort      = 22821;
    st.platformHTTPPort     = 22822;
    // A never-banned, never-revived masternode.
    st.nPoSeBanHeight       = ReplayMNState::NEVER;
    st.nPoSeRevivedHeight   = ReplayMNState::NEVER;

    MNState a = to_payee_state(st);
    EXPECT_EQ(a.nPoSeBanHeight, 0u);        // NEVER -> 0, not 4294967295
    EXPECT_EQ(a.nPoSeRevivedHeight, 0u);
    EXPECT_TRUE(a.isValid);
    EXPECT_EQ(a.nRegisteredHeight, 2500000u);
    EXPECT_EQ(a.nLastPaidHeight, 2516700u);
    EXPECT_EQ(a.nConsecutivePayments, 3u);
    EXPECT_EQ(a.nType, dash::coin::vendor::MnType::EVO);
    EXPECT_EQ(a.nOperatorReward, 500);
    EXPECT_EQ(a.scriptOperatorPayout.m_data, st.scriptOperatorPayout.m_data);
    EXPECT_TRUE(a.payout_split_provable());
    // The operator split dashd's coinbase actually pays.
    EXPECT_EQ(a.operator_payment_of(1000000), 50000);

    // Now ban it: isValid is COMPUTED from the ban height, and the pair must
    // stay consistent (mn_state_machine refuses to pay isValid==true next to
    // a live ban height).
    st.BanIfNotBanned(2516759);
    MNState b = to_payee_state(st);
    EXPECT_EQ(b.nPoSeBanHeight, 2516759u);
    EXPECT_FALSE(b.isValid);

    // Revive it (the real h=2516756 transition shape).
    st.Revive(2516760);
    MNState c = to_payee_state(st);
    EXPECT_EQ(c.nPoSeBanHeight, 0u);
    EXPECT_EQ(c.nPoSeRevivedHeight, 2516760u);
    EXPECT_TRUE(c.isValid);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 7 — THE LAST MILE: live tip blocks arriving OUT OF ORDER still reach the
//         fold, and are what lets it reach the tip at all
//
// The first live seam run parked at
//     [BULK] delivered=2516911/2516911 inflight=0 hdr=joined
// with our own header chain at h=2516923: the bulk lane fetches what its peers
// announced when it planned and then idles. The node HAD the missing blocks —
// the tip lane connected each one — but they arrived while the fold was still
// thousands of blocks back, and a forward-contiguous fold cannot take a block
// out of order. Holding them and draining on contiguity is the whole fix.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashReplayPayeePublish, LiveTailHoldsOutOfOrderBlocksAndDrainsOnContiguity)
{
    auto rig = make_clean_rig();
    dash::coin::replay::FoldLiveTail tail(rig.consumer, rig.engine);

    // The tip lane hands us 2516758, 2516759, 2516760 while the fold is still
    // at the anchor h=2516755. None is foldable yet.
    for (uint32_t h = 2516758; h <= kLastBody; ++h)
        tail.offer(h, pp_parse_block(kBodies[h - kFirstBody]));
    EXPECT_EQ(tail.held(), 3u);
    EXPECT_EQ(tail.folded_live(), 0u);
    EXPECT_EQ(tail.lowest_held(), 2516758u);
    EXPECT_EQ(rig.engine.height(), 2516755u);       // nothing forced through

    // The bulk lane closes 2516756. Still a gap at 2516757 — hold.
    ASSERT_TRUE(rig.fold_through(kFirstBody));
    tail.drain();
    EXPECT_EQ(tail.held(), 3u);
    EXPECT_EQ(rig.engine.height(), 2516756u);

    // 2516757 arrives late, out of order. NOW the whole tail drains in one go
    // and the fold lands exactly on the tip.
    tail.offer(2516757, pp_parse_block(kBodies[2516757 - kFirstBody]));
    EXPECT_EQ(tail.held(), 0u);
    EXPECT_EQ(tail.folded_live(), 4u);
    EXPECT_EQ(rig.engine.height(), kLastBody);
    EXPECT_EQ(rig.consumer.stats().roots_matched, 5u);   // every one checked

    // A block the bulk lane already folded is a NO-OP, not an error.
    tail.offer(kFirstBody, pp_parse_block(kBodies[0]));
    EXPECT_EQ(tail.held(), 0u);
    EXPECT_EQ(tail.folded_live(), 4u);

    // ... and with the fold now AT the tip, the seam publishes.
    rig.tip = kLastBody;
    auto pub = rig.make_publisher();
    ASSERT_TRUE(pub.evaluate().ok) << pub.evaluate().blocker;
    EXPECT_TRUE(pub.maybe_publish());
    EXPECT_EQ(rig.sink.calls.size(), 1u);
    EXPECT_EQ(rig.sink.calls.front().as_of, kLastBody);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 8 — the live tail's overflow drops the HIGHEST held block, never the
//         lowest: the lowest is the one contiguity needs next.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashReplayPayeePublish, LiveTailOverflowKeepsTheContiguityFrontier)
{
    auto rig = make_clean_rig();
    dash::coin::replay::FoldLiveTail tail(rig.consumer, rig.engine, /*cap=*/2);

    tail.offer(2516758, pp_parse_block(kBodies[2516758 - kFirstBody]));
    tail.offer(2516759, pp_parse_block(kBodies[2516759 - kFirstBody]));
    tail.offer(kLastBody, pp_parse_block(kBodies[kLastBody - kFirstBody]));
    EXPECT_EQ(tail.held(), 2u);
    EXPECT_EQ(tail.dropped(), 1u);
    EXPECT_EQ(tail.lowest_held(), 2516758u);        // the frontier survived

    // The dropped height is a GAP, not a skip: the fold walks up to it and
    // stops there rather than folding past a block it never saw.
    ASSERT_TRUE(rig.fold_through(2516757));
    tail.drain();
    EXPECT_EQ(rig.engine.height(), 2516759u);
    EXPECT_EQ(tail.held(), 0u);
    EXPECT_EQ(rig.consumer.stats().roots_matched, 4u);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT 9 — the real h=2516756 revive survives the conversion INTO the queue
//
// Ties the seam back to the incident the fixtures were cut for: the
// masternode revived at h=2516756 must arrive in the payee queue eligible,
// with its revive height intact (queue position uses
// max(nLastPaidHeight, nPoSeRevivedHeight)).
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashReplayPayeePublish, RevivedMasternodeArrivesEligibleInThePayeeQueue)
{
    auto rig = make_clean_rig();
    ASSERT_TRUE(rig.fold_through(kLastBody));
    rig.tip = kLastBody;

    // Find whoever the fold revived in this window.
    const uint256* revived = nullptr;
    for (const auto& [protx, st] : rig.engine.entries()) {
        if (st.nPoSeRevivedHeight == static_cast<int32_t>(kFirstBody)) {
            revived = &protx;
            break;
        }
    }
    ASSERT_NE(revived, nullptr)
        << "fixture drift: h=2516756 is the revive block";
    const uint256 target = *revived;

    auto pub = rig.make_publisher();
    ASSERT_TRUE(pub.maybe_publish());
    ASSERT_EQ(rig.sink.calls.size(), 1u);

    bool seen = false;
    for (const auto& [protx, mn] : rig.sink.calls.front().set) {
        if (protx != target) continue;
        seen = true;
        EXPECT_TRUE(mn.isValid);
        EXPECT_EQ(mn.nPoSeBanHeight, 0u);
        EXPECT_EQ(mn.nPoSeRevivedHeight, kFirstBody);
        EXPECT_FALSE(mn.scriptPayout.m_data.empty());
    }
    EXPECT_TRUE(seen) << "the revived masternode never reached the queue";
}
