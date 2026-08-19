// SPDX-License-Identifier: AGPL-3.0-or-later
/// W1 (DASH full-history replay) — DML fold engine + snapshot-v3 KATs.
///
/// Two KAT families:
///
///  1. REAL MAINNET CHAIN BYTES. Full-state pre-lists captured at h=2516411
///     and h=2516755 (dashd protx list + protx diff, merged and verified
///     against the committed cbTx merkleRootMNList at generation time —
///     tools/dash/gen_replay_kat.py), then REAL block bodies folded over
///     them with the engine's per-block self-check as the assertion:
///       - h=2516412: the case-D PoSe event — qfcommit llmq_100_67
///         00000000…5552 marks members #2/#22 invalid; +CalcPenalty(66)
///         = +1961 punishes both, bans 1e5112a9…5614 (penalty 1937→2972 =
///         max), leaves 104b336e…ddef at 1961. The block's committed root
///         f9f27286…4edf only matches if punish+decay+ban fold EXACTLY —
///         omit any of them and this KAT reds (the fails-without-fold
///         property).
///       - h=2516756: THE REVIVE (incident 2026-08-05) — ProUpServTx
///         3b899207…9448 revives PoSe-banned df51257a…03e8 (banned at
///         2507061 with penalty 2958). The committed root flips
///         3687f8f3…360f → ed607b5c…0f79 exactly when Revive() folds.
///         Blocks 2516757..2516760 then fold with NO list mutation — the
///         no-spurious-mutation property over 4 more real bodies.
///       - operator split: MN 1dae04ea…b7a0 carries nOperatorReward=800bps
///         + a set scriptOperatorPayout through the whole sequence (the
///         h=2516595 bad-cb-payee field class, derived from history).
///
///  2. SYNTHETIC VECTORS with independently hand-built expected SML entry
///     sets (never the engine's own output): registration/internalId,
///     empty-netInfo ban, collateral replacement + spend, operator-key
///     change ban, revoke, punish/decay/ban/revive crossings, revive
///     requires-all-keys, confirmedHash at nMasternodeMinimumConfirmations,
///     the root-mismatch HARD STOP, the ExtAddr/v24 and feature-flag
///     refusals, forward-contiguous cursor, snapshot v3
///     save/load/resume/fail-loud.

#include <gtest/gtest.h>

#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/block.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "data/dash_replay_prestate_2516411.inc"
#include "data/dash_replay_prestate_2516755.inc"
#include "data/dash_replay_block_2516412.inc"
#include "data/dash_replay_block_2516756.inc"
#include "data/dash_replay_block_2516757.inc"
#include "data/dash_replay_block_2516758.inc"
#include "data/dash_replay_block_2516759.inc"
#include "data/dash_replay_block_2516760.inc"
#include "data/dash_replay_quorum_2516412.inc"

using dash::coin::BlockType;
using dash::coin::MutableTransaction;
using dash::coin::replay::DmlFoldEngine;
using dash::coin::replay::FoldConfig;
using dash::coin::replay::FoldGates;
using dash::coin::replay::FoldResult;
using dash::coin::replay::ReplayMNState;
using dash::coin::vendor::CCbTx;
using dash::coin::vendor::CFinalCommitment;
using dash::coin::vendor::CFinalCommitmentTxPayload;
using dash::coin::vendor::CProRegTx;
using dash::coin::vendor::CProUpRegTx;
using dash::coin::vendor::CProUpRevTx;
using dash::coin::vendor::CProUpServTx;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;
using dash::coin::vendor::LegacyNetService;
using bitcoin_family::coin::TxIn;
using bitcoin_family::coin::TxOut;
using bitcoin_family::coin::TxPrevOut;
namespace ProTxVersion = dash::coin::vendor::ProTxVersion;
namespace MnType = dash::coin::vendor::MnType;

// ─── generic helpers ────────────────────────────────────────────────────────

static bool hex_to_bytes(const std::string& hex, std::vector<uint8_t>& out)
{
    if (hex.size() % 2) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

// Fixture hex fields are RAW WIRE BYTES (see gen_replay_kat.py) — parse is a
// dumb memcpy, no byte-order decisions here.
static uint256 u256_wire(const std::string& hex)
{
    std::vector<uint8_t> b;
    EXPECT_TRUE(hex_to_bytes(hex, b) && b.size() == 32) << hex;
    uint256 h;
    if (b.size() == 32) std::memcpy(h.data(), b.data(), 32);
    return h;
}

static uint160 u160_wire(const std::string& hex)
{
    std::vector<uint8_t> b;
    EXPECT_TRUE(hex_to_bytes(hex, b) && b.size() == 20) << hex;
    uint160 h;
    if (b.size() == 20) std::memcpy(h.data(), b.data(), 20);
    return h;
}

static uint256 raw256(uint8_t base)
{
    uint256 h;
    for (size_t i = 0; i < 32; ++i) h.data()[i] = static_cast<uint8_t>(base + i);
    return h;
}

static uint160 raw160(uint8_t base)
{
    uint160 h;
    for (size_t i = 0; i < 20; ++i) h.data()[i] = static_cast<uint8_t>(base + i);
    return h;
}

template <size_t N>
static std::array<uint8_t, N> seq_array(uint8_t base)
{
    std::array<uint8_t, N> a{};
    for (size_t i = 0; i < N; ++i) a[i] = static_cast<uint8_t>(base + i);
    return a;
}

static std::vector<unsigned char> script_bytes(uint8_t tag, size_t n = 25)
{
    std::vector<unsigned char> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<unsigned char>(tag + i);
    return v;
}

// ─── fixture parsers ────────────────────────────────────────────────────────

struct PrestateFixture {
    std::string network;
    uint32_t    height{0};
    std::string blockhash_display;
    std::string mnroot_display;
    std::vector<std::pair<uint256, ReplayMNState>> entries;
};

static std::vector<std::string> split_ws(const std::string& line)
{
    std::vector<std::string> out;
    std::istringstream is(line);
    std::string tok;
    while (is >> tok) out.push_back(tok);
    return out;
}

static void parse_prestate_into(const char* text, PrestateFixture& fx)
{
    std::istringstream is(text);
    std::string line;
    size_t declared = 0;
    EXPECT_TRUE(std::getline(is, line));
    EXPECT_EQ(line, "c2pool-dash-replay-prestate/1");
    while (std::getline(is, line)) {
        if (line.empty()) continue;
        auto f = split_ws(line);
        if (f.empty()) continue;
        if (f[0] == "network")   { fx.network = f[1]; continue; }
        if (f[0] == "height")    { fx.height = static_cast<uint32_t>(std::stoul(f[1])); continue; }
        if (f[0] == "blockhash") { fx.blockhash_display = f[1]; continue; }
        if (f[0] == "mnroot")    { fx.mnroot_display = f[1]; continue; }
        if (f[0] == "count")     { declared = std::stoul(f[1]); continue; }
        ASSERT_EQ(f[0], "mn") << "unknown fixture line: " << line;
        ASSERT_EQ(f.size(), 26u) << line;
        uint256 protx = u256_wire(f[1]);
        ReplayMNState st;
        st.confirmedHash = (f[2] == "-") ? uint256{} : u256_wire(f[2]);
        if (!st.confirmedHash.IsNull()) {
            // Regenerate the pairing hash exactly as the fold would have.
            st.UpdateConfirmedHash(protx, st.confirmedHash);
        }
        std::vector<uint8_t> ip;
        ASSERT_TRUE(hex_to_bytes(f[3], ip) && ip.size() == 16) << line;
        std::memcpy(st.netInfo.ip.data(), ip.data(), 16);
        st.netInfo.port_be = static_cast<uint16_t>(std::stoul(f[4]));
        if (f[5] != "-") {
            std::vector<uint8_t> pk;
            ASSERT_TRUE(hex_to_bytes(f[5], pk) && pk.size() == 48) << line;
            std::memcpy(st.pubKeyOperator.data(), pk.data(), 48);
        }
        st.keyIDVoting        = u160_wire(f[6]);
        st.keyIDOwner         = u160_wire(f[7]);
        st.nVersion           = static_cast<uint16_t>(std::stoul(f[8]));
        st.nType              = static_cast<uint16_t>(std::stoul(f[9]));
        st.platformNodeID     = (f[10] == "-") ? uint160{} : u160_wire(f[10]);
        st.platformP2PPort    = static_cast<uint16_t>(std::stoul(f[11]));
        st.platformHTTPPort   = static_cast<uint16_t>(std::stoul(f[12]));
        st.nOperatorReward    = static_cast<uint16_t>(std::stoul(f[13]));
        if (f[14] != "-") {
            std::vector<uint8_t> sp;
            ASSERT_TRUE(hex_to_bytes(f[14], sp)) << line;
            st.scriptPayout.m_data.assign(sp.begin(), sp.end());
        }
        if (f[15] != "-") {
            std::vector<uint8_t> sp;
            ASSERT_TRUE(hex_to_bytes(f[15], sp)) << line;
            st.scriptOperatorPayout.m_data.assign(sp.begin(), sp.end());
        }
        st.nRegisteredHeight    = static_cast<int32_t>(std::stol(f[16]));
        st.nLastPaidHeight      = static_cast<int32_t>(std::stol(f[17]));
        st.nConsecutivePayments = static_cast<int32_t>(std::stol(f[18]));
        st.nPoSePenalty         = static_cast<int32_t>(std::stol(f[19]));
        st.nPoSeBanHeight       = static_cast<int32_t>(std::stol(f[20]));
        st.nPoSeRevivedHeight   = static_cast<int32_t>(std::stol(f[21]));
        st.nRevocationReason    = static_cast<uint16_t>(std::stoul(f[22]));
        st.collateralOutpoint.hash  = u256_wire(f[23]);
        st.collateralOutpoint.index = static_cast<uint32_t>(std::stoul(f[24]));
        st.internalId               = std::stoull(f[25]);
        fx.entries.emplace_back(protx, std::move(st));
    }
    EXPECT_EQ(fx.entries.size(), declared);
}

static PrestateFixture parse_prestate(const char* text)
{
    PrestateFixture fx;
    parse_prestate_into(text, fx);
    return fx;
}

static void parse_block_into(const char* hex_text, BlockType& b)
{
    std::string hex;
    for (const char* p = hex_text; *p; ++p)
        if (*p != '\n' && *p != '\r') hex.push_back(*p);
    std::vector<uint8_t> bytes;
    EXPECT_TRUE(hex_to_bytes(hex, bytes));
    ::PackStream s(bytes);
    s >> b;
    EXPECT_TRUE(s.empty()) << "trailing bytes after block";
}

static BlockType parse_block(const char* hex_text)
{
    BlockType b;
    parse_block_into(hex_text, b);
    return b;
}

struct QuorumFixture {
    uint8_t              llmq_type{0};
    std::string          quorum_hash_display;
    std::vector<uint256> members; // bitset order
};

static void parse_quorum_into(const char* text, QuorumFixture& fx)
{
    std::istringstream is(text);
    std::string line;
    EXPECT_TRUE(std::getline(is, line));
    EXPECT_EQ(line, "c2pool-dash-replay-quorum/1");
    while (std::getline(is, line)) {
        auto f = split_ws(line);
        if (f.empty()) continue;
        if (f[0] == "llmqType")   { fx.llmq_type = static_cast<uint8_t>(std::stoul(f[1])); continue; }
        if (f[0] == "quorumHash") { fx.quorum_hash_display = f[1]; continue; }
        if (f[0] == "count") continue;
        ASSERT_EQ(f[0], "member");
        fx.members.push_back(u256_wire(f[1]));
    }
}

static QuorumFixture parse_quorum(const char* text)
{
    QuorumFixture fx;
    parse_quorum_into(text, fx);
    return fx;
}

// Seed an enabled engine from a parsed prestate; assert pre-fold root parity
// against the committed cbTx root at the anchor height — the fixture is only
// trusted BECAUSE it reproduces chain bytes.
static DmlFoldEngine seed_from_fixture(const PrestateFixture& fx)
{
    FoldConfig cfg;
    cfg.enabled = true; // W1 feature flag — explicit opt-in, tests only
    DmlFoldEngine eng(cfg);
    auto entries = fx.entries;
    uint256 anchor_hash;
    anchor_hash.SetHex(fx.blockhash_display);
    eng.seed(std::move(entries), fx.entries.size(), fx.height, anchor_hash,
             fx.network);
    EXPECT_EQ(eng.compute_sml_root().GetHex(), fx.mnroot_display)
        << "prestate does not reproduce the committed root at h=" << fx.height;
    return eng;
}

// The coinbase's payout set must contain the projected payee's scriptPayout —
// the same per-block cross-check the checkpoint lane runs (behavioral
// falsification of the non-committed payee model, design doc §4.2).
static void expect_coinbase_pays(const BlockType& block,
                                 const DmlFoldEngine& eng,
                                 const FoldResult& r)
{
    ASSERT_TRUE(r.payee.has_value());
    ASSERT_TRUE(r.payee_marked);
    const ReplayMNState* st = eng.find(*r.payee);
    ASSERT_NE(st, nullptr);
    bool found = false;
    for (const auto& out : block.m_txs[0].vout)
        if (out.scriptPubKey.m_data == st->scriptPayout.m_data) found = true;
    EXPECT_TRUE(found) << "coinbase does not pay the projected payee "
                       << r.payee->GetHex();
}

// ════════════════════════════════════════════════════════════════════════
// REAL MAINNET KATs
// ════════════════════════════════════════════════════════════════════════

// Anchor constants, all RPC display hex (uint256::GetHex order), copied from
// the chain (dash-cli getblock / protx diff) — see file preamble.
static const char* kRoot2516411 =
    "486d22f406ac67038bbc9651f369b3c4acb0dcb7ae3664bbbf8501a5db8591a8";
static const char* kRoot2516412 =
    "f9f272868a54a56ac91eb4b3c788260fe28230d2d36d9583a164095590224edf";
static const char* kRoot2516755 =
    "3687f8f3545e7a4f2db926c46a8fe89015d97926d18164979976a947de75360f";
static const char* kRoot2516756 =
    "ed607b5c1b60ab76972e10be0bc1196112ba93b8fa3ccc250a7f62058a380f79";
// The revived MN (incident h=2516756) and the case-D pair (h=2516412),
// display hex.
static const char* kReviveMN =
    "df51257a58dd92cb5401fd852dece8ef1a0876dbd4aae15ea6e57e331a7503e8";
static const char* kBannedMN =
    "1e5112a9f38d7a0228b23a73fbeab0d7d097ccb5aa4aaf13b4065d1502be5614";
static const char* kPunishedMN =
    "104b336e605975a557182930f37e929eeca6e553e2e84dd7acb8c8503bfeddef";
// A real operator-split MN (nOperatorReward = 800 bps = 8%).
static const char* kSplitMN =
    "1dae04eaae642a2594fe3a0e7c0382cedbb8d6743f7c9bbbaa0449af59c3b7a0";

static uint256 from_display(const char* hex)
{
    uint256 h;
    h.SetHex(hex);
    return h;
}

TEST(DashReplayFoldReal, PrestateRootParity2516755)
{
    auto fx = parse_prestate(kDashReplayPrestate2516755);
    EXPECT_EQ(fx.height, 2516755u);
    EXPECT_EQ(fx.entries.size(), 2971u);
    EXPECT_EQ(fx.mnroot_display, kRoot2516755);
    auto eng = seed_from_fixture(fx); // asserts root parity inside
    EXPECT_EQ(eng.size(), 2971u);
}

TEST(DashReplayFoldReal, Revive2516756ThenQuietSequence)
{
    auto fx  = parse_prestate(kDashReplayPrestate2516755);
    auto eng = seed_from_fixture(fx);

    // Pre-fold: the incident MN is PoSe-banned exactly as the chain had it.
    const uint256 revive_mn = from_display(kReviveMN);
    const ReplayMNState* pre = eng.find(revive_mn);
    ASSERT_NE(pre, nullptr);
    EXPECT_TRUE(pre->IsBanned());
    EXPECT_EQ(pre->nPoSeBanHeight, 2507061);
    EXPECT_EQ(pre->nPoSePenalty, 2958);

    // Expected decay count = non-banned MNs carrying a penalty.
    size_t expect_decay = 0;
    for (const auto& [h, st] : eng.entries())
        if (!st.IsBanned() && st.nPoSePenalty > 0) ++expect_decay;

    // Fold the REAL block 2516756 (carries ProUpServTx 3b899207…9448).
    auto b2516756 = parse_block(kDashReplayBlock2516756);
    auto r = eng.fold_block(b2516756, 2516756);
    ASSERT_TRUE(r.ok) << r.error;

    // THE self-check ran against the block's own cbTx; pin the values too.
    EXPECT_EQ(r.committed_root.GetHex(), kRoot2516756);
    EXPECT_EQ(r.computed_root.GetHex(), kRoot2516756);
    EXPECT_EQ(eng.compute_sml_root().GetHex(), kRoot2516756);

    // The revive folded byte-exactly (specialtxman.cpp:368-377 → Revive).
    EXPECT_EQ(r.revived, 1u);
    EXPECT_EQ(r.updated, 1u);
    EXPECT_EQ(r.decayed, expect_decay);
    const ReplayMNState* post = eng.find(revive_mn);
    ASSERT_NE(post, nullptr);
    EXPECT_FALSE(post->IsBanned());
    EXPECT_EQ(post->nPoSePenalty, 0);
    EXPECT_EQ(post->nPoSeBanHeight, ReplayMNState::NEVER);
    EXPECT_EQ(post->nPoSeRevivedHeight, 2516756);
    expect_coinbase_pays(b2516756, eng, r);

    // 2516757..2516760: four more real bodies, no SML-visible mutation —
    // each block's committed root must equal the carried-forward state.
    const char* seq[] = {kDashReplayBlock2516757, kDashReplayBlock2516758,
                         kDashReplayBlock2516759, kDashReplayBlock2516760};
    uint32_t h = 2516757;
    for (const char* bh : seq) {
        auto blk = parse_block(bh);
        auto rr  = eng.fold_block(blk, h);
        ASSERT_TRUE(rr.ok) << "h=" << h << ": " << rr.error;
        EXPECT_EQ(rr.computed_root.GetHex(), kRoot2516756) << "h=" << h;
        EXPECT_EQ(rr.registered, 0u) << "h=" << h;
        EXPECT_EQ(rr.revived, 0u) << "h=" << h;
        EXPECT_EQ(rr.banned, 0u) << "h=" << h;
        expect_coinbase_pays(blk, eng, rr);
        ++h;
    }
    EXPECT_EQ(eng.height(), 2516760u);
}

TEST(DashReplayFoldReal, OperatorSplitCarriedThroughFold)
{
    auto fx  = parse_prestate(kDashReplayPrestate2516755);
    auto eng = seed_from_fixture(fx);

    const uint256 split_mn = from_display(kSplitMN);
    const ReplayMNState* st = eng.find(split_mn);
    ASSERT_NE(st, nullptr);
    // The h=2516595 incident class: split fields derived from history, not
    // from the (silent) SML wire.
    EXPECT_EQ(st->nOperatorReward, 800);
    EXPECT_FALSE(st->scriptOperatorPayout.m_data.empty());
    const auto op_script = st->scriptOperatorPayout.m_data;

    auto r = eng.fold_block(parse_block(kDashReplayBlock2516756), 2516756);
    ASSERT_TRUE(r.ok) << r.error;
    const ReplayMNState* post = eng.find(split_mn);
    ASSERT_NE(post, nullptr);
    EXPECT_EQ(post->nOperatorReward, 800);
    EXPECT_EQ(post->scriptOperatorPayout.m_data, op_script);
}

TEST(DashReplayFoldReal, PoSePunishAndCaseDBan2516412)
{
    auto fx  = parse_prestate(kDashReplayPrestate2516411);
    EXPECT_EQ(fx.entries.size(), 2972u);
    EXPECT_EQ(fx.mnroot_display, kRoot2516411);
    auto eng = seed_from_fixture(fx);

    // dashd CalcMaxPoSePenalty = max(100, registered count) = 2972;
    // CalcPenalty(66) = 2972*66/100 = 1961 (integer).
    EXPECT_EQ(eng.calc_max_pose_penalty(), 2972);
    EXPECT_EQ(eng.calc_penalty(66), 1961);

    const uint256 to_ban   = from_display(kBannedMN);
    const uint256 punished = from_display(kPunishedMN);
    ASSERT_NE(eng.find(to_ban), nullptr);
    EXPECT_EQ(eng.find(to_ban)->nPoSePenalty, 1937);
    EXPECT_FALSE(eng.find(to_ban)->IsBanned());
    EXPECT_EQ(eng.find(punished)->nPoSePenalty, 0);

    // The mined commitment's member set, in bitset order (captured via
    // `quorum info 4 <hash>`; indices 2 and 22 are the invalid members).
    auto qf = parse_quorum(kDashReplayQuorum2516412);
    ASSERT_EQ(qf.members.size(), 100u);
    EXPECT_EQ(qf.llmq_type, 4);
    const uint256 quorum_hash = from_display(qf.quorum_hash_display.c_str());
    eng.set_members_fn([&](uint8_t llmq_type, const uint256& qh)
                           -> std::optional<std::vector<uint256>> {
        if (llmq_type == qf.llmq_type && qh == quorum_hash) return qf.members;
        return std::nullopt;
    });

    auto blk = parse_block(kDashReplayBlock2516412);
    auto r   = eng.fold_block(blk, 2516412);
    ASSERT_TRUE(r.ok) << r.error;

    // The committed root only matches when decay(−1) + punish(+1961) +
    // ban-at-max fold EXACTLY (1937−1+1961 = 3897 → clamp 2972 = max ⇒ BAN,
    // the isValid flip under the root). This is the measured case-D class
    // (the 6.86% serve-loss "intractable" verdict, reversed by full history).
    EXPECT_EQ(r.committed_root.GetHex(), kRoot2516412);
    EXPECT_EQ(r.computed_root.GetHex(), kRoot2516412);
    EXPECT_EQ(r.punished, 2u);
    EXPECT_EQ(r.banned, 1u);

    const ReplayMNState* banned = eng.find(to_ban);
    ASSERT_NE(banned, nullptr);
    EXPECT_TRUE(banned->IsBanned());
    EXPECT_EQ(banned->nPoSeBanHeight, 2516412);
    EXPECT_EQ(banned->nPoSePenalty, 2972); // saturated at max

    const ReplayMNState* still_valid = eng.find(punished);
    ASSERT_NE(still_valid, nullptr);
    EXPECT_FALSE(still_valid->IsBanned());
    EXPECT_EQ(still_valid->nPoSePenalty, 1961);

    expect_coinbase_pays(blk, eng, r);
}

TEST(DashReplayFoldReal, QfcommitWithoutMemberResolverFailsClosed)
{
    auto fx  = parse_prestate(kDashReplayPrestate2516411);
    auto eng = seed_from_fixture(fx);
    // No members_fn installed: the non-null commitment must refuse the fold
    // (silently skipping punishes is exactly the projection's old blindness).
    auto r = eng.fold_block(parse_block(kDashReplayBlock2516412), 2516412);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.find("2516412"), std::string::npos);
    EXPECT_NE(r.error.find("resolver"), std::string::npos);
}

TEST(DashReplayFoldReal, SnapshotV3RoundTripAndResumeOnRealState)
{
    auto fx  = parse_prestate(kDashReplayPrestate2516755);
    auto eng = seed_from_fixture(fx);
    ASSERT_TRUE(eng.fold_block(parse_block(kDashReplayBlock2516756), 2516756).ok);

    auto bytes = eng.save_snapshot();

    FoldConfig cfg;
    cfg.enabled = true;
    DmlFoldEngine eng2(cfg);
    std::string err;
    ASSERT_TRUE(eng2.load_snapshot(bytes, err)) << err;
    EXPECT_EQ(eng2.height(), 2516756u);
    EXPECT_EQ(eng2.network(), "mainnet");
    EXPECT_EQ(eng2.size(), eng.size());
    EXPECT_EQ(eng2.total_registered_count(), eng.total_registered_count());
    EXPECT_EQ(eng2.compute_sml_root().GetHex(), kRoot2516756);
    // Field-exact, not just root-exact (the root omits penalties/scripts).
    EXPECT_TRUE(eng.entries() == eng2.entries());

    // RESUME: the restored engine folds the NEXT real block.
    auto r = eng2.fold_block(parse_block(kDashReplayBlock2516757), 2516757);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.computed_root.GetHex(), kRoot2516756);
}

// ════════════════════════════════════════════════════════════════════════
// SYNTHETIC VECTORS — hand-built expected entry sets, tiny gates
// ════════════════════════════════════════════════════════════════════════

// Gates for synthetic chains: everything active from h=1, mainnet
// min-confirmations kept at 15.
static FoldConfig synth_cfg()
{
    FoldConfig cfg;
    cfg.enabled = true;
    cfg.gates.dip0003_height = 1;
    // Synthetic vectors model the ENFORCED regime (their coinbases pay the
    // projected payee via make_block(&eng)); keep the payee cross-check ON so
    // the existing payee-axis assertions still bind. The DIP3-genesis window
    // (activation<h<enforcement) is exercised explicitly by the
    // PreEnforcementPayeeCheck suite, which lowers dip0003_enforcement_height.
    cfg.gates.dip0003_enforcement_height = 1;
    cfg.gates.v19_height     = 1;
    cfg.gates.mn_rr_height   = 1;
    return cfg;
}

static MutableTransaction make_coinbase(uint32_t height, const uint256& mnroot)
{
    CCbTx cb;
    cb.nVersion          = CCbTx::VERSION_MERKLE_ROOT_QUORUMS;
    cb.nHeight           = static_cast<int32_t>(height);
    cb.merkleRootMNList  = mnroot;
    MutableTransaction tx;
    tx.version = 3;
    tx.type    = 5;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.sequence      = 0xffffffff;
    tx.vin.push_back(in);
    auto ps = ::pack(cb);
    auto sp = ps.get_span();
    tx.extra_payload.assign(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tx;
}

template <typename Payload>
static MutableTransaction make_special_tx(uint16_t type, const Payload& p,
                                          uint8_t vin_tag = 0)
{
    MutableTransaction tx;
    tx.version = 3;
    tx.type    = type;
    TxIn in;
    in.prevout.hash  = raw256(static_cast<uint8_t>(0xA0 + vin_tag));
    in.prevout.index = vin_tag;
    in.sequence      = 0xffffffff;
    tx.vin.push_back(in);
    auto ps = ::pack(p);
    auto sp = ps.get_span();
    tx.extra_payload.assign(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tx;
}

/// The scriptPayout of the masternode `eng` will project for block H — i.e.
/// the script a REAL block at that height would have to pay. Empty when the
/// pre-block list is empty.
static std::vector<unsigned char> projected_payout_script(
    const DmlFoldEngine& eng, int32_t H)
{
    auto p = eng.project_payee(H);
    if (!p) return {};
    const ReplayMNState* st = eng.find(*p);
    return st ? st->scriptPayout.m_data : std::vector<unsigned char>{};
}

/// `pay_from`: build the coinbase so it PAYS the masternode the engine
/// projects for this height, the way every real DIP3 block does.
///
/// The fold now adjudicates that (replay_fold_engine.hpp, "THE SECOND
/// SELF-CHECK"): merkleRootMNList does not commit nLastPaidHeight, so a wrong
/// payment order folds to the right root, and the block's own coinbase is the
/// only answer key for that axis. A synthetic block that pays nobody is not a
/// block dashd could have produced, so these fixtures now model the one
/// property the engine checks. Pass nullptr only where a payee mismatch is
/// the thing under test.
static BlockType make_block(uint32_t height, const uint256& prev_hash,
                            const uint256& committed_root,
                            std::vector<MutableTransaction> special_txs = {},
                            const DmlFoldEngine* pay_from = nullptr)
{
    BlockType b;
    b.m_version        = 536870912;
    b.m_previous_block = prev_hash;
    b.m_timestamp      = 1700000000 + height;
    b.m_bits           = 0x1e0fffff;
    b.m_nonce          = height;
    auto cb = make_coinbase(height, committed_root);
    if (pay_from) {
        auto script = projected_payout_script(*pay_from,
                                              static_cast<int32_t>(height));
        if (!script.empty()) {
            TxOut out;
            out.value = 1;
            out.scriptPubKey.m_data = std::move(script);
            cb.vout.push_back(std::move(out));
        }
    }
    b.m_txs.push_back(std::move(cb));
    for (auto& tx : special_txs) b.m_txs.push_back(std::move(tx));
    return b;
}

static uint256 root_of(std::vector<CSimplifiedMNListEntry> entries)
{
    CSimplifiedMNList sml(std::move(entries));
    return sml.CalcMerkleRoot();
}

// A fresh v2 (BasicBLS) ProRegTx with everything set.
static CProRegTx make_proreg(uint8_t tag, uint16_t operator_reward_bps = 0)
{
    CProRegTx p;
    p.nVersion = ProTxVersion::BASIC_BLS;
    p.nType    = MnType::REGULAR;
    p.collateralOutpoint.hash  = raw256(static_cast<uint8_t>(0x40 + tag));
    p.collateralOutpoint.index = 1;
    p.netInfo.ip = seq_array<16>(static_cast<uint8_t>(0x10 + tag));
    p.netInfo.port_be = 9999;
    p.keyIDOwner  = raw160(static_cast<uint8_t>(0x20 + tag));
    p.pubKeyOperator = seq_array<48>(static_cast<uint8_t>(0x30 + tag));
    p.keyIDVoting = raw160(static_cast<uint8_t>(0x50 + tag));
    p.nOperatorReward = operator_reward_bps;
    p.scriptPayout.m_data = script_bytes(static_cast<uint8_t>(0x60 + tag));
    p.inputsHash = raw256(static_cast<uint8_t>(0x70 + tag));
    p.vchSig.assign(8, tag);
    return p;
}

// The expected SML entry for a ProRegTx folded at some height (independent
// hand-build — NEVER derived from the engine).
static CSimplifiedMNListEntry expected_entry_of(const CProRegTx& p,
                                                const uint256& protx,
                                                bool valid = true)
{
    CSimplifiedMNListEntry e;
    e.nVersion       = p.nVersion;
    e.proRegTxHash   = protx;
    e.confirmedHash  = uint256{};
    e.netAddress     = p.netInfo.ip;
    e.netPort        = p.netInfo.port_be;
    e.pubKeyOperator = p.pubKeyOperator;
    e.keyIDVoting    = p.keyIDVoting;
    e.isValid        = valid;
    e.nType          = p.nType;
    return e;
}

static uint256 tx_hash_of(const MutableTransaction& tx)
{
    ::PackStream s;
    s << tx;
    auto sp = s.get_span();
    uint256 h;
    CHash256()
        .Write(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
        .Finalize(std::span<unsigned char>(h.data(), 32));
    return h;
}

TEST(DashReplayFoldSynthetic, FeatureFlagOffRefusesEveryFold)
{
    DmlFoldEngine eng{FoldConfig{}}; // default: enabled == false
    auto r = eng.fold_block(make_block(1, raw256(1), uint256{}), 1);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.find("not enabled"), std::string::npos);
}

TEST(DashReplayFoldSynthetic, V24ActiveFailsClosed)
{
    auto cfg = synth_cfg();
    cfg.gates.v24_active = true;
    DmlFoldEngine eng(cfg);
    eng.seed({}, 0, 100, raw256(9));
    auto r = eng.fold_block(make_block(101, raw256(9), uint256{}), 101);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.find("V24"), std::string::npos);
}

TEST(DashReplayFoldSynthetic, ForwardContiguousCursorOnly)
{
    DmlFoldEngine eng(synth_cfg());
    eng.seed({}, 0, 100, raw256(9));
    // Gap (102 on a 100 cursor) refused, named.
    auto r = eng.fold_block(make_block(102, raw256(9), uint256{}), 102);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.find("forward-contiguous"), std::string::npos);
    // Duplicate/out-of-order (100) refused.
    r = eng.fold_block(make_block(100, raw256(9), uint256{}), 100);
    ASSERT_FALSE(r.ok);
    // Neither refusal poisoned the engine or moved the cursor.
    EXPECT_FALSE(eng.poisoned());
    EXPECT_EQ(eng.height(), 100u);
}

TEST(DashReplayFoldSynthetic, RegisterFoldsPayloadAndAssignsInternalIds)
{
    DmlFoldEngine eng(synth_cfg());
    eng.seed({}, /*total_registered=*/7, 100, raw256(9));

    auto p1  = make_proreg(1, /*operator_reward_bps=*/800);
    auto p2  = make_proreg(2);
    auto tx1 = make_special_tx(1, p1, 1);
    auto tx2 = make_special_tx(1, p2, 2);
    const uint256 mn1 = tx_hash_of(tx1), mn2 = tx_hash_of(tx2);

    const uint256 expected = root_of({expected_entry_of(p1, mn1),
                                      expected_entry_of(p2, mn2)});
    auto r = eng.fold_block(make_block(101, raw256(9), expected, {tx1, tx2}),
                            101);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.registered, 2u);

    // internalId continues the seeded GetTotalRegisteredCount, in tx order.
    ASSERT_NE(eng.find(mn1), nullptr);
    ASSERT_NE(eng.find(mn2), nullptr);
    EXPECT_EQ(eng.find(mn1)->internalId, 7u);
    EXPECT_EQ(eng.find(mn2)->internalId, 8u);
    EXPECT_EQ(eng.total_registered_count(), 9u);
    EXPECT_EQ(eng.find(mn1)->nRegisteredHeight, 101);
    // Operator split derived from registration history (h=2516595 class).
    EXPECT_EQ(eng.find(mn1)->nOperatorReward, 800);
    // External collateral: the payload outpoint is taken verbatim.
    EXPECT_EQ(eng.find(mn1)->collateralOutpoint.hash, p1.collateralOutpoint.hash);
}

TEST(DashReplayFoldSynthetic, EmptyNetInfoRegistersBannedThenProUpServRevives)
{
    DmlFoldEngine eng(synth_cfg());
    eng.seed({}, 0, 100, raw256(9));

    auto p = make_proreg(1);
    p.netInfo = LegacyNetService{}; // empty ⇒ registers banned
    auto tx = make_special_tx(1, p, 1);
    const uint256 mn = tx_hash_of(tx);

    // Expected entry: isValid FALSE, empty netInfo.
    auto e = expected_entry_of(p, mn, /*valid=*/false);
    e.netAddress = {};
    e.netPort    = 0;
    auto r = eng.fold_block(make_block(101, raw256(9), root_of({e}), {tx}), 101);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.banned, 1u);
    ASSERT_NE(eng.find(mn), nullptr);
    EXPECT_TRUE(eng.find(mn)->IsBanned());
    EXPECT_EQ(eng.find(mn)->nPoSeBanHeight, 101);

    // ProUpServTx with a real address revives (all keys are set).
    CProUpServTx up;
    up.nVersion  = ProTxVersion::BASIC_BLS;
    up.nType     = MnType::REGULAR;
    up.proTxHash = mn;
    up.netInfo.ip = seq_array<16>(0x77);
    up.netInfo.port_be = 9999;
    up.inputsHash = raw256(0x22);
    auto uptx = make_special_tx(2, up, 3);

    auto e2 = expected_entry_of(p, mn, /*valid=*/true);
    e2.netAddress = up.netInfo.ip;
    e2.netPort    = up.netInfo.port_be;
    auto r2 = eng.fold_block(
        make_block(102, raw256(10), root_of({e2}), {uptx}), 102);
    ASSERT_TRUE(r2.ok) << r2.error;
    EXPECT_EQ(r2.revived, 1u);
    EXPECT_FALSE(eng.find(mn)->IsBanned());
    EXPECT_EQ(eng.find(mn)->nPoSeRevivedHeight, 102);
    EXPECT_EQ(eng.find(mn)->nPoSePenalty, 0);
}

TEST(DashReplayFoldSynthetic, ReviveRequiresAllKeysSet)
{
    DmlFoldEngine eng(synth_cfg());
    // Seed a banned MN whose operator key is NULL (post-revoke shape).
    ReplayMNState st;
    st.nVersion = ProTxVersion::LEGACY_BLS;
    st.nType    = MnType::REGULAR;
    st.keyIDOwner  = raw160(0x21);
    st.keyIDVoting = raw160(0x51);
    st.collateralOutpoint.hash  = raw256(0x41);
    st.collateralOutpoint.index = 1;
    st.scriptPayout.m_data = script_bytes(0x61);
    st.nRegisteredHeight = 50;
    st.nPoSeBanHeight    = 90;
    const uint256 mn = raw256(0xE1);
    eng.seed({{mn, st}}, 1, 100, raw256(9));

    CProUpServTx up;
    up.nVersion  = ProTxVersion::LEGACY_BLS;
    up.nType     = MnType::REGULAR;
    up.proTxHash = mn;
    up.netInfo.ip = seq_array<16>(0x77);
    up.netInfo.port_be = 9999;
    auto uptx = make_special_tx(2, up, 1);

    // Expected: netInfo updates, but NO revive (operator key still null) —
    // the entry stays invalid. dashd specialtxman.cpp:368-372. The
    // confirmedHash pass ALSO fires this fold (registered at 50, so
    // (101−1)−50 ≥ 15 — banned MNs confirm too, specialtxman.cpp:205-218),
    // recording hash(H−1) = this block's prev hash.
    CSimplifiedMNListEntry e;
    e.nVersion      = st.nVersion;
    e.proRegTxHash  = mn;
    e.confirmedHash = raw256(9);
    e.netAddress    = up.netInfo.ip;
    e.netPort       = up.netInfo.port_be;
    e.keyIDVoting   = st.keyIDVoting;
    e.isValid       = false;
    auto r = eng.fold_block(make_block(101, raw256(9), root_of({e}), {uptx}),
                            101);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.revived, 0u);
    EXPECT_TRUE(eng.find(mn)->IsBanned());
}

TEST(DashReplayFoldSynthetic, OperatorKeyChangeResetsAndBans)
{
    DmlFoldEngine eng(synth_cfg());
    eng.seed({}, 0, 100, raw256(9));

    auto p  = make_proreg(1, 800);
    auto tx = make_special_tx(1, p, 1);
    const uint256 mn = tx_hash_of(tx);
    ASSERT_TRUE(eng.fold_block(
        make_block(101, raw256(9), root_of({expected_entry_of(p, mn)}), {tx}, &eng),
        101).ok);

    // Set an operator payout script first (so the reset is observable).
    {
        CProUpServTx up;
        up.nVersion  = ProTxVersion::BASIC_BLS;
        up.proTxHash = mn;
        up.netInfo   = p.netInfo;
        up.scriptOperatorPayout.m_data = script_bytes(0x99);
        auto uptx = make_special_tx(2, up, 2);
        auto r = eng.fold_block(
            make_block(102, raw256(10), root_of({expected_entry_of(p, mn)}),
                       {uptx}, &eng), 102);
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_FALSE(eng.find(mn)->scriptOperatorPayout.m_data.empty());
    }

    // ProUpRegTx with a DIFFERENT operator key: ResetOperatorFields + ban +
    // new key/voting/payout from the payload (specialtxman.cpp:395-407).
    CProUpRegTx upr;
    upr.nVersion       = ProTxVersion::BASIC_BLS;
    upr.proTxHash      = mn;
    upr.pubKeyOperator = seq_array<48>(0xB0);
    upr.keyIDVoting    = raw160(0xB4);
    upr.scriptPayout.m_data = script_bytes(0xB8);
    upr.vchSig.assign(8, 0xB);
    auto uprtx = make_special_tx(3, upr, 3);

    CSimplifiedMNListEntry e;
    e.nVersion       = ProTxVersion::BASIC_BLS; // never downgraded below basic
    e.proRegTxHash   = mn;
    e.netAddress     = {}; // reset empties netInfo
    e.netPort        = 0;
    e.pubKeyOperator = upr.pubKeyOperator;
    e.keyIDVoting    = upr.keyIDVoting;
    e.isValid        = false; // banned until a ProUpServTx revives
    e.nType          = MnType::REGULAR;
    auto r = eng.fold_block(make_block(103, raw256(11), root_of({e}), {uprtx}, &eng),
                            103);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.banned, 1u);
    const ReplayMNState* st = eng.find(mn);
    ASSERT_NE(st, nullptr);
    EXPECT_TRUE(st->IsBanned());
    EXPECT_EQ(st->nPoSeBanHeight, 103);
    EXPECT_TRUE(st->scriptOperatorPayout.m_data.empty());
    EXPECT_TRUE(st->netinfo_empty());
    EXPECT_EQ(st->pubKeyOperator, upr.pubKeyOperator);
    EXPECT_EQ(st->keyIDVoting, upr.keyIDVoting);
    EXPECT_EQ(st->scriptPayout.m_data, upr.scriptPayout.m_data);
    // The split BPS is DMN-level and survives the operator reset.
    EXPECT_EQ(st->nOperatorReward, 800);
}

TEST(DashReplayFoldSynthetic, ProUpRevRevokesAndRecordsReason)
{
    DmlFoldEngine eng(synth_cfg());
    eng.seed({}, 0, 100, raw256(9));

    auto p  = make_proreg(1);
    auto tx = make_special_tx(1, p, 1);
    const uint256 mn = tx_hash_of(tx);
    ASSERT_TRUE(eng.fold_block(
        make_block(101, raw256(9), root_of({expected_entry_of(p, mn)}), {tx}, &eng),
        101).ok);

    CProUpRevTx rev;
    rev.nVersion  = ProTxVersion::BASIC_BLS;
    rev.proTxHash = mn;
    rev.nReason   = CProUpRevTx::REASON_COMPROMISED_KEYS;
    auto revtx = make_special_tx(4, rev, 2);

    CSimplifiedMNListEntry e;
    e.nVersion     = ProTxVersion::LEGACY_BLS; // ResetOperatorFields floor
    e.proRegTxHash = mn;
    e.keyIDVoting  = p.keyIDVoting;
    e.isValid      = false;
    auto r = eng.fold_block(make_block(102, raw256(10), root_of({e}), {revtx}, &eng),
                            102);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.revoked, 1u);
    EXPECT_TRUE(eng.find(mn)->IsBanned());
    EXPECT_TRUE(eng.find(mn)->operator_pubkey_null());
    EXPECT_EQ(eng.find(mn)->nRevocationReason,
              CProUpRevTx::REASON_COMPROMISED_KEYS);
}

TEST(DashReplayFoldSynthetic, CollateralReplacementRemovesOldMN)
{
    DmlFoldEngine eng(synth_cfg());
    eng.seed({}, 0, 100, raw256(9));

    auto p1  = make_proreg(1); // external collateral raw256(0x41):1
    auto tx1 = make_special_tx(1, p1, 1);
    const uint256 mn1 = tx_hash_of(tx1);
    ASSERT_TRUE(eng.fold_block(
        make_block(101, raw256(9), root_of({expected_entry_of(p1, mn1)}),
                   {tx1}, &eng), 101).ok);

    // A second ProRegTx re-registering the SAME external collateral:
    // dashd removes the old MN and adds the new one fresh
    // (specialtxman.cpp:266-278).
    auto p2 = make_proreg(2);
    p2.collateralOutpoint = p1.collateralOutpoint;
    auto tx2 = make_special_tx(1, p2, 2);
    const uint256 mn2 = tx_hash_of(tx2);
    auto r = eng.fold_block(
        make_block(102, raw256(10), root_of({expected_entry_of(p2, mn2)}),
                   {tx2}, &eng), 102);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.collateral_replaced, 1u);
    EXPECT_EQ(eng.find(mn1), nullptr);
    ASSERT_NE(eng.find(mn2), nullptr);
    EXPECT_EQ(eng.size(), 1u);
    EXPECT_EQ(eng.find(mn2)->internalId, 1u); // fresh id, counter advanced
}

TEST(DashReplayFoldSynthetic, CollateralSpendRemovesMNSameBlockAware)
{
    DmlFoldEngine eng(synth_cfg());
    eng.seed({}, 0, 100, raw256(9));

    // Register in THIS block, spend the collateral in a LATER tx of the
    // SAME block — dashd's pass order (register pass fully before the vin
    // scan) removes it again.
    auto p  = make_proreg(1);
    auto tx = make_special_tx(1, p, 1);
    const uint256 mn = tx_hash_of(tx);

    MutableTransaction spend;
    spend.version = 1;
    TxIn in;
    in.prevout = p.collateralOutpoint;
    in.sequence = 0xffffffff;
    spend.vin.push_back(in);

    auto r = eng.fold_block(
        make_block(101, raw256(9), root_of({}), {tx, spend}), 101);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.registered, 1u);
    EXPECT_EQ(r.collateral_spent, 1u);
    EXPECT_EQ(eng.find(mn), nullptr);
    EXPECT_EQ(eng.size(), 0u);
    // The id was still consumed — dashd's counter never rolls back.
    EXPECT_EQ(eng.total_registered_count(), 1u);
}

TEST(DashReplayFoldSynthetic, PunishDecayBanReviveLifecycle)
{
    DmlFoldEngine eng(synth_cfg());
    eng.seed({}, 0, 100, raw256(9));

    // Three MNs → CalcMaxPoSePenalty = max(100,3) = 100, CalcPenalty(66)=66.
    auto pa = make_proreg(1); auto txa = make_special_tx(1, pa, 1);
    auto pb = make_proreg(2); auto txb = make_special_tx(1, pb, 2);
    auto pc = make_proreg(3); auto txc = make_special_tx(1, pc, 3);
    const uint256 a = tx_hash_of(txa), b = tx_hash_of(txb), c = tx_hash_of(txc);
    auto ea = expected_entry_of(pa, a), eb = expected_entry_of(pb, b),
         ec = expected_entry_of(pc, c);
    ASSERT_TRUE(eng.fold_block(
        make_block(101, raw256(9), root_of({ea, eb, ec}), {txa, txb, txc}, &eng),
        101).ok);
    EXPECT_EQ(eng.calc_max_pose_penalty(), 100);
    EXPECT_EQ(eng.calc_penalty(66), 66);

    // A commitment marking `a` invalid. Members in fixed order (a,b,c).
    const uint256 quorum_hash = raw256(0xC0);
    eng.set_members_fn([&](uint8_t, const uint256& qh)
                           -> std::optional<std::vector<uint256>> {
        if (qh == quorum_hash) return std::vector<uint256>{a, b, c};
        return std::nullopt;
    });
    auto make_qc = [&](uint8_t vin_tag) {
        CFinalCommitmentTxPayload qc;
        qc.nVersion = 1;
        qc.nHeight  = 0;
        qc.commitment.nVersion   = CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
        qc.commitment.llmqType   = CFinalCommitment::LLMQ_100_67;
        qc.commitment.quorumHash = quorum_hash;
        qc.commitment.signers      = {false, true, true};
        qc.commitment.validMembers = {false, true, true};
        qc.commitment.quorumPublicKey = seq_array<48>(0xD0);
        qc.commitment.quorumVvecHash  = raw256(0xD1);
        qc.commitment.quorumSig  = seq_array<96>(0xD2);
        qc.commitment.membersSig = seq_array<96>(0xD3);
        return make_special_tx(6, qc, vin_tag);
    };

    // Block 102: punish #1 → penalty 66, no ban (66 < 100), root unchanged.
    auto r = eng.fold_block(
        make_block(102, raw256(10), root_of({ea, eb, ec}), {make_qc(4)}, &eng), 102);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.punished, 1u);
    EXPECT_EQ(r.banned, 0u);
    EXPECT_EQ(eng.find(a)->nPoSePenalty, 66);

    // Block 103: decay first (66→65), then punish #2 → 131 → clamp 100 =
    // max ⇒ BAN. The committed root now carries isValid=false for `a` —
    // this vector FAILS if decay, punish, saturation or the ban-at-max rule
    // is dropped (each changes either the penalty arithmetic or the root).
    auto ea_banned = ea;
    ea_banned.isValid = false;
    r = eng.fold_block(
        make_block(103, raw256(11), root_of({ea_banned, eb, ec}),
                   {make_qc(5)}, &eng), 103);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.decayed, 1u);
    EXPECT_EQ(r.punished, 1u);
    EXPECT_EQ(r.banned, 1u);
    EXPECT_EQ(eng.find(a)->nPoSePenalty, 100);
    EXPECT_TRUE(eng.find(a)->IsBanned());
    EXPECT_EQ(eng.find(a)->nPoSeBanHeight, 103);

    // Block 104: banned MNs neither decay nor re-ban; a null commitment is
    // a no-op (no member resolution, no punish).
    CFinalCommitmentTxPayload null_qc;
    null_qc.nVersion = 1;
    null_qc.commitment.nVersion = CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
    null_qc.commitment.llmqType = CFinalCommitment::LLMQ_100_67;
    null_qc.commitment.quorumHash = raw256(0xC9); // resolver would refuse it
    null_qc.commitment.signers      = {false, false, false};
    null_qc.commitment.validMembers = {false, false, false};
    r = eng.fold_block(
        make_block(104, raw256(12), root_of({ea_banned, eb, ec}),
                   {make_special_tx(6, null_qc, 6)}, &eng), 104);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.punished, 0u);
    EXPECT_EQ(r.decayed, 0u);
    EXPECT_EQ(eng.find(a)->nPoSePenalty, 100); // frozen while banned

    // Block 105: ProUpServTx revives — penalty resets to 0, ban clears.
    CProUpServTx up;
    up.nVersion  = ProTxVersion::BASIC_BLS;
    up.proTxHash = a;
    up.netInfo   = pa.netInfo;
    r = eng.fold_block(
        make_block(105, raw256(13), root_of({ea, eb, ec}),
                   {make_special_tx(2, up, 7)}, &eng), 105);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.revived, 1u);
    EXPECT_EQ(eng.find(a)->nPoSePenalty, 0);
    EXPECT_FALSE(eng.find(a)->IsBanned());
    EXPECT_EQ(eng.find(a)->nPoSeRevivedHeight, 105);
}

TEST(DashReplayFoldSynthetic, ConfirmedHashSetAtMinimumConfirmations)
{
    DmlFoldEngine eng(synth_cfg()); // min confirmations = 15 (mainnet)
    eng.seed({}, 0, 100, raw256(9));

    auto p  = make_proreg(1);
    auto tx = make_special_tx(1, p, 1);
    const uint256 mn = tx_hash_of(tx);
    auto e = expected_entry_of(p, mn);
    ASSERT_TRUE(eng.fold_block(
        make_block(101, raw256(9), root_of({e}), {tx}, &eng), 101).ok);

    // Registered at 101. Confirmation at fold height H needs
    // (H−1) − 101 ≥ 15, i.e. FIRST at H = 117, with
    // confirmedHash = hash(116) = that block's own hashPrevBlock.
    for (uint32_t h = 102; h <= 116; ++h) {
        auto r = eng.fold_block(
            make_block(h, raw256(static_cast<uint8_t>(h)), root_of({e}), {}, &eng), h);
        ASSERT_TRUE(r.ok) << "h=" << h << ": " << r.error;
        EXPECT_EQ(r.confirmed, 0u) << "h=" << h;
        EXPECT_TRUE(eng.find(mn)->confirmedHash.IsNull()) << "h=" << h;
    }
    const uint256 hash116 = raw256(117); // prev-hash we hand block 117
    auto e_conf = e;
    e_conf.confirmedHash = hash116;
    auto r = eng.fold_block(make_block(117, hash116, root_of({e_conf}), {}, &eng), 117);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.confirmed, 1u);
    EXPECT_EQ(eng.find(mn)->confirmedHash, hash116);

    // The pairing hash is the SINGLE-SHA256 of proTxHash‖confirmedHash
    // (dmnstate.h:141-148 — NOT double-SHA).
    uint256 expect_pair;
    {
        CSHA256 hsh;
        hsh.Write(mn.data(), 32);
        hsh.Write(hash116.data(), 32);
        unsigned char out[CSHA256::OUTPUT_SIZE];
        hsh.Finalize(out);
        std::memcpy(expect_pair.data(), out, 32);
    }
    EXPECT_EQ(eng.find(mn)->confirmedHashWithProRegTxHash, expect_pair);
}

TEST(DashReplayFoldSynthetic, RootMismatchIsAHardStopWithNamedHeight)
{
    DmlFoldEngine eng(synth_cfg());
    eng.seed({}, 0, 100, raw256(9));

    auto p  = make_proreg(1);
    auto tx = make_special_tx(1, p, 1);
    // Commit a WRONG root: the fold must fail, name the height, poison.
    uint256 wrong = root_of({expected_entry_of(p, tx_hash_of(tx))});
    wrong.data()[0] ^= 0x01;
    auto r = eng.fold_block(make_block(101, raw256(9), wrong, {tx}), 101);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.find("ROOT MISMATCH at h=101"), std::string::npos);
    EXPECT_NE(r.error.find(r.computed_root.GetHex()), std::string::npos);
    EXPECT_TRUE(eng.poisoned());

    // Poisoned engines refuse EVERYTHING until re-seeded.
    auto r2 = eng.fold_block(
        make_block(102, raw256(10), uint256{}, {}), 102);
    ASSERT_FALSE(r2.ok);
    EXPECT_NE(r2.error.find("POISONED"), std::string::npos);

    // Re-seed clears the poison (the operator-visible recovery path).
    eng.seed({}, 0, 200, raw256(8));
    EXPECT_FALSE(eng.poisoned());
}

TEST(DashReplayFoldSynthetic, ExtAddrPayloadFailsClosed)
{
    DmlFoldEngine eng(synth_cfg());
    ReplayMNState st;
    st.nVersion = ProTxVersion::BASIC_BLS;
    st.keyIDOwner = raw160(0x21);
    st.keyIDVoting = raw160(0x51);
    st.pubKeyOperator = seq_array<48>(0x31);
    st.collateralOutpoint.hash = raw256(0x41);
    st.collateralOutpoint.index = 1;
    st.nRegisteredHeight = 50;
    const uint256 mn = raw256(0xE1);
    eng.seed({{mn, st}}, 1, 100, raw256(9));

    CProUpServTx up;
    up.nVersion  = ProTxVersion::EXT_ADDR; // v24-only wire — unimplemented
    up.nType     = MnType::REGULAR;
    up.proTxHash = mn;
    auto r = eng.fold_block(
        make_block(101, raw256(9), uint256{}, {make_special_tx(2, up, 1)}, &eng),
        101);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.find("ExtAddr"), std::string::npos);
    EXPECT_TRUE(eng.poisoned()); // a skipped mutation would be silent desync
}

TEST(DashReplayFoldSynthetic, UnknownProTxHashFailsClosed)
{
    DmlFoldEngine eng(synth_cfg());
    eng.seed({}, 0, 100, raw256(9));
    CProUpServTx up;
    up.nVersion  = ProTxVersion::BASIC_BLS;
    up.proTxHash = raw256(0xEE); // nobody home
    auto r = eng.fold_block(
        make_block(101, raw256(9), uint256{}, {make_special_tx(2, up, 1)}),
        101);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.find("does not hold"), std::string::npos);
}

TEST(DashReplayFoldSynthetic, SnapshotV3FailLoudPaths)
{
    DmlFoldEngine eng(synth_cfg());
    ReplayMNState st;
    st.nVersion = ProTxVersion::BASIC_BLS;
    st.keyIDOwner = raw160(0x21);
    st.keyIDVoting = raw160(0x51);
    st.pubKeyOperator = seq_array<48>(0x31);
    st.collateralOutpoint.hash = raw256(0x41);
    st.collateralOutpoint.index = 1;
    st.scriptPayout.m_data = script_bytes(0x61);
    st.nRegisteredHeight = 50;
    st.nPoSePenalty = 7;
    st.internalId = 3;
    st.confirmedHash = raw256(0x71);
    const uint256 mn = raw256(0xE1);
    eng.seed({{mn, st}}, 4, 100, raw256(9));

    auto good = eng.save_snapshot();
    std::string err;

    // Round trip preserves EVERYTHING (incl. the v3-only fields the v1
    // checkpoint format omits: confirmedHash/netInfo/nPoSePenalty/internalId).
    {
        DmlFoldEngine e2(synth_cfg());
        ASSERT_TRUE(e2.load_snapshot(good, err)) << err;
        ASSERT_NE(e2.find(mn), nullptr);
        EXPECT_TRUE(*e2.find(mn) == st);
        EXPECT_EQ(e2.height(), 100u);
        EXPECT_EQ(e2.total_registered_count(), 4u);
        EXPECT_EQ(e2.block_hash(), raw256(9));
        // Byte-stable: save(load(x)) == x.
        EXPECT_EQ(e2.save_snapshot(), good);
    }
    // Wrong magic.
    {
        auto bad = good;
        bad[0] ^= 0xFF;
        DmlFoldEngine e2(synth_cfg());
        EXPECT_FALSE(e2.load_snapshot(bad, err));
        EXPECT_NE(err.find("magic"), std::string::npos);
    }
    // Corrupted payload byte → digest mismatch.
    {
        auto bad = good;
        bad[DmlFoldEngine::kSnapshotMagicLen + 20] ^= 0x01;
        DmlFoldEngine e2(synth_cfg());
        EXPECT_FALSE(e2.load_snapshot(bad, err));
        EXPECT_NE(err.find("digest"), std::string::npos);
    }
    // Truncation → too short / digest.
    {
        auto bad = good;
        bad.resize(bad.size() - 5);
        DmlFoldEngine e2(synth_cfg());
        EXPECT_FALSE(e2.load_snapshot(bad, err));
    }
    // FUTURE/PAST format version → loud version error, never a silent
    // migration. (Version is the u32 right after the magic; patch it AND
    // recompute the digest so the version check itself is what trips.)
    {
        auto bad = good;
        bad[DmlFoldEngine::kSnapshotMagicLen] = 9;
        const size_t payload_len = bad.size() - 32;
        uint256 digest;
        CHash256()
            .Write(std::span<const unsigned char>(bad.data(), payload_len))
            .Finalize(std::span<unsigned char>(digest.data(), 32));
        std::memcpy(bad.data() + payload_len, digest.data(), 32);
        DmlFoldEngine e2(synth_cfg());
        EXPECT_FALSE(e2.load_snapshot(bad, err));
        EXPECT_NE(err.find("v9"), std::string::npos);
        EXPECT_NE(err.find("v3"), std::string::npos);
    }
    // A failed load never clobbers existing state.
    EXPECT_EQ(eng.size(), 1u);
    EXPECT_EQ(eng.height(), 100u);
}

// ─────────────────────────────────────────────────────────────────────────────
// DIP3-GENESIS payee cross-check gate (dashd DeploymentDIP0003Enforced parity).
//
// The deterministic MN list is BUILT from DIP3 ACTIVATION (h=1028160) but the
// coinbase paying GetMNPayee(list) is only ENFORCED from DIP0003EnforcementHeight
// (mainnet 1047200). In the [activation, enforcement) window dashd's own
// consensus rule CMNPaymentsProcessor::IsTransactionValid (masternode/
// payments.cpp:114) returns valid WITHOUT checking the det payee — the coinbase
// pays the LEGACY masternode winner, not the det projection. So the fold's payee
// cross-check must not run there, or it false-poisons a byte-correct fold — the
// observed h=1028163 divergence: merkleRootMNList MATCHED, projection sound, the
// coinbase simply pays the legacy winner (which drifts from the det order once
// more than a couple of MNs are registered).
//
// This is the ONE property the payee gate changes: the SAME state + SAME
// payment-block (coinbase pays nobody) POISONS when the height is at/above
// enforcement (RED — the check is still strict where dashd enforces it) and
// FOLDS THROUGH when the height is below enforcement (GREEN — the DIP3-genesis
// window no longer false-poisons). The merkleRootMNList SET self-check runs in
// BOTH arms regardless.
namespace {
// Two MNs registered at h=101; both configs are identical except the enforcement
// height, so the only variable is the gate under test.
struct PayeeGateFixture {
    DmlFoldEngine eng;
    uint256       payment_root;   // SML root after the reg block (unchanged by pay)
    uint256       reg_hash;       // block hash the payment block builds on
    explicit PayeeGateFixture(int32_t enforcement_height)
        : eng(make_cfg(enforcement_height))
    {
        eng.seed({}, /*total_registered=*/0, /*height=*/100, raw256(9));
        auto p1  = make_proreg(1);
        auto p2  = make_proreg(2);
        auto tx1 = make_special_tx(1, p1, 1);
        auto tx2 = make_special_tx(1, p2, 2);
        const uint256 mn1 = tx_hash_of(tx1), mn2 = tx_hash_of(tx2);
        payment_root = root_of({expected_entry_of(p1, mn1),
                                expected_entry_of(p2, mn2)});
        auto reg_blk = make_block(101, raw256(9), payment_root, {tx1, tx2});
        auto rr = eng.fold_block(reg_blk, 101);
        EXPECT_TRUE(rr.ok) << "register fold must succeed: " << rr.error;
        EXPECT_EQ(rr.registered, 2u);
    }
    static FoldConfig make_cfg(int32_t enforcement_height)
    {
        FoldConfig cfg;
        cfg.enabled = true;
        cfg.gates.dip0003_height             = 1;
        cfg.gates.dip0003_enforcement_height = enforcement_height;
        // v19/mn_rr far out (classic payee path); confirmations far out so no
        // confirmedHash mutation at h=102 keeps the SML root stable across the
        // payment fold.
        cfg.gates.v19_height                 = 100000000;
        cfg.gates.mn_rr_height               = 100000000;
        cfg.gates.masternode_min_confirmations = 100000000;
        return cfg;
    }
};
} // namespace

// GREEN: h=102 is BELOW enforcement (103). A payment block whose coinbase pays
// NOBODY folds THROUGH — dashd does not commit the det payee to the coinbase
// there. The SET self-check still ran (root matched); the payee axis is derived
// and self-consistent (nLastPaidHeight bumped on the projection).
TEST(DashReplayFoldPreEnforcement, BelowEnforcementPayeeMismatchFoldsThrough)
{
    PayeeGateFixture fx(/*enforcement_height=*/103);  // 102 < 103 ⇒ pre-enforcement
    ASSERT_TRUE(fx.eng.project_payee(101).has_value())
        << "a payee must be projected (else the test proves nothing)";
    auto pay_blk = make_block(102, raw256(9), fx.payment_root,
                              /*special_txs=*/{}, /*pay_from=*/nullptr);
    auto r = fx.eng.fold_block(pay_blk, 102);
    ASSERT_TRUE(r.ok) << "pre-enforcement payee mismatch must NOT poison (dashd "
                         "IsTransactionValid skips the check below enforcement): "
                      << r.error;
    EXPECT_TRUE(r.payee.has_value());
    EXPECT_TRUE(r.payee_check_preenforcement_skipped)
        << "the skip must be recorded, not silently absent";
    EXPECT_FALSE(r.payee_paid_verified);
    EXPECT_EQ(r.computed_root, r.committed_root);   // SET self-check still bound
    EXPECT_TRUE(r.payee_marked);                    // nLastPaidHeight still bumped
}

// RED: the SAME state + SAME payment block, but h=102 is AT enforcement (102).
// The coinbase pays nobody, so the strict payee cross-check fires and POISONS —
// exactly as it must at tip, where dashd enforces the det payee. This proves the
// gate is scoped to the genesis window, not a blanket disable of the check.
TEST(DashReplayFoldPreEnforcement, AtEnforcementPayeeMismatchStillPoisons)
{
    PayeeGateFixture fx(/*enforcement_height=*/102);  // 102 >= 102 ⇒ enforced
    ASSERT_TRUE(fx.eng.project_payee(101).has_value());
    auto pay_blk = make_block(102, raw256(9), fx.payment_root,
                              /*special_txs=*/{}, /*pay_from=*/nullptr);
    auto r = fx.eng.fold_block(pay_blk, 102);
    ASSERT_FALSE(r.ok) << "at/after enforcement a payee mismatch MUST poison";
    EXPECT_NE(r.error.find("PAYEE MISMATCH"), std::string::npos) << r.error;
    EXPECT_FALSE(r.payee_check_preenforcement_skipped);
}

// Control: when the pre-enforcement block DOES pay the projected payee (the
// common case, since legacy and det winners coincide while the set is tiny),
// the fold succeeds and the skip flag is NOT set — the check simply passed.
TEST(DashReplayFoldPreEnforcement, BelowEnforcementPayeePaidIsNotFlaggedSkipped)
{
    PayeeGateFixture fx(/*enforcement_height=*/103);
    auto pay_blk = make_block(102, raw256(9), fx.payment_root,
                              /*special_txs=*/{}, /*pay_from=*/&fx.eng);
    auto r = fx.eng.fold_block(pay_blk, 102);
    ASSERT_TRUE(r.ok) << r.error;
    // Below enforcement the check is skipped regardless of whether the coinbase
    // happens to pay the projection; the flag reflects the GATE, not the match.
    EXPECT_TRUE(r.payee_check_preenforcement_skipped);
}

// ════════════════════════════════════════════════════════════════════════
// OPERATOR-REWARD SPLIT payee cross-check — h=1439234 sub-class
// ════════════════════════════════════════════════════════════════════════
//
// dashd masternode/payments.cpp GetBlockTxOuts:64-77 does NOT unconditionally
// emit scriptPayout. When nOperatorReward==10000 and scriptOperatorPayout is
// set, the operator reward eats the WHOLE MN share, masternodeReward folds to
// exactly 0, and the ONLY MN output dashd emits (and its IsTransactionValid
// :109-139 requires) is scriptOperatorPayout. A payee cross-check that always
// demands scriptPayout is STRICTER THAN DASHD there and false-poisons a
// byte-correct fold — the live self-derive incident at h=1439234 (proTxHash
// 71ed3bf5…, bps=10000, owner==operator self-host, coinbase paid the operator
// script for the full 1.51818084 share, no owner remainder; roots matched
// 411073/411073). These KATs pin the faithful branch.
//
// Build the fixture by SEEDING the pre-block state directly (scriptOperatorPayout
// is set by a ProUpServTx in history; seeding it is the same pre-block tuple
// dashd built the coinbase from). Confirmations are pushed out so pass 1 never
// mutates confirmedHash and the SML root stays byte-stable across the payment
// fold — the SET self-check binds in every arm.
namespace {
static FoldConfig op_split_cfg()
{
    FoldConfig cfg;
    cfg.enabled = true;
    cfg.gates.dip0003_height               = 1;
    cfg.gates.dip0003_enforcement_height   = 1;   // ENFORCED: payee check ON
    cfg.gates.v19_height                   = 1;
    cfg.gates.mn_rr_height                 = 1;
    cfg.gates.masternode_min_confirmations = 100000000;  // no confirmedHash churn
    return cfg;
}

// Seed one non-banned MN carrying (scriptPayout=owner, scriptOperatorPayout=op,
// nOperatorReward=bps). Returns the engine + the committed SML root of that
// single-entry list (unchanged by a payment fold).
struct OpSplitFixture {
    DmlFoldEngine eng;
    uint256       committed_root;
    uint256       mn;
    std::vector<unsigned char> owner_script;
    std::vector<unsigned char> op_script;
    OpSplitFixture(uint16_t bps,
                   const std::vector<unsigned char>& owner,
                   const std::vector<unsigned char>& op)
        : eng(op_split_cfg())
        , mn(raw256(0xE7))
        , owner_script(owner)
        , op_script(op)
    {
        ReplayMNState st;
        st.nVersion   = ProTxVersion::BASIC_BLS;
        st.nType      = MnType::REGULAR;
        st.keyIDOwner  = raw160(0x27);
        st.keyIDVoting = raw160(0x57);
        st.pubKeyOperator = seq_array<48>(0x37);
        st.collateralOutpoint.hash  = raw256(0x47);
        st.collateralOutpoint.index = 1;
        st.netInfo.ip      = seq_array<16>(0x17);
        st.netInfo.port_be = 9999;
        st.nOperatorReward = bps;
        st.scriptPayout.m_data         = owner;
        st.scriptOperatorPayout.m_data = op;
        st.nRegisteredHeight = 50;
        st.nLastPaidHeight   = 0;            // never paid — first payment here
        st.confirmedHash     = raw256(0x99); // pre-set: pass 1 leaves it alone
        eng.seed({{mn, st}}, /*total_registered=*/1, /*height=*/100, raw256(9));
        committed_root = eng.compute_sml_root();
    }
    // A payment block at h whose coinbase pays EXACTLY `scripts` (one vout each).
    BlockType payment_block(uint32_t h,
                            std::vector<std::vector<unsigned char>> scripts) const
    {
        auto blk = make_block(h, raw256(9), committed_root);  // coinbase, no payee vout
        for (auto& s : scripts) {
            TxOut out;
            out.value = 100000000;
            out.scriptPubKey.m_data = std::move(s);
            blk.m_txs[0].vout.push_back(std::move(out));
        }
        return blk;
    }
};
} // namespace

// GREEN (RED on master): bps==10000 with a set operator script. dashd zeroes
// masternodeReward and pays ONLY the operator script — so a coinbase paying the
// operator script (and NOT scriptPayout) is exactly what dashd produced. The
// fold must accept it. On master this REDS: the check demands scriptPayout,
// which is legitimately absent, and false-poisons.
TEST(DashReplayFoldOperatorSplit, FullOperatorRewardPaysOperatorScriptFoldsThrough)
{
    OpSplitFixture fx(/*bps=*/10000, script_bytes(0x6A), script_bytes(0x6B));
    ASSERT_TRUE(fx.eng.project_payee(101).has_value());
    // Coinbase pays ONLY the operator script (the h=1439234 shape).
    auto blk = fx.payment_block(101, {fx.op_script});
    auto r = fx.eng.fold_block(blk, 101);
    ASSERT_TRUE(r.ok) << "a full-operator-reward payment (dashd emits ONLY the "
                         "operator output) must fold through, not poison: "
                      << r.error;
    EXPECT_EQ(r.computed_root, r.committed_root);      // SET self-check bound
    EXPECT_TRUE(r.payee_paid_verified);                // payee AXIS verified
    EXPECT_TRUE(r.payee_operator_full_reward);         // via the operator branch
    EXPECT_TRUE(r.payee_marked);                       // nLastPaidHeight bumped
}

// STRICTNESS / reward-safety: same 100%-operator MN, but the coinbase pays the
// OWNER scriptPayout instead of the operator script. dashd would REJECT that
// coinbase (it requires the operator output, masternodeReward==0 so no owner
// output is valid) — our check must also POISON. The fix makes the requirement
// EQUAL to dashd's, never weaker: it does not accept "pays either script".
TEST(DashReplayFoldOperatorSplit, FullOperatorRewardPayingOwnerScriptStillPoisons)
{
    OpSplitFixture fx(/*bps=*/10000, script_bytes(0x6A), script_bytes(0x6B));
    auto blk = fx.payment_block(101, {fx.owner_script});  // pays owner, NOT operator
    auto r = fx.eng.fold_block(blk, 101);
    ASSERT_FALSE(r.ok) << "at bps=10000 dashd emits only the operator output; a "
                          "coinbase paying scriptPayout instead is invalid and "
                          "MUST poison";
    EXPECT_NE(r.error.find("PAYEE MISMATCH"), std::string::npos) << r.error;
    EXPECT_NE(r.error.find("scriptOperatorPayout"), std::string::npos)
        << "the poison message must name the required operator script: " << r.error;
    EXPECT_TRUE(fx.eng.poisoned());                    // fail-closed, engine poisoned
}

// UNCHANGED for partial splits: 0<bps<10000 keeps masternodeReward>0, so dashd
// still emits scriptPayout and the check still requires it. A coinbase paying
// the owner script folds through (the operator output is fee-priced, which the
// fold cannot compute, so it is NEVER poisoned on for absence).
TEST(DashReplayFoldOperatorSplit, PartialOperatorRewardRequiresOwnerScript)
{
    OpSplitFixture fx(/*bps=*/800, script_bytes(0x6A), script_bytes(0x6B));
    // Pays owner only (operator output amount is fee-unknown; not required).
    auto blk = fx.payment_block(101, {fx.owner_script});
    auto r = fx.eng.fold_block(blk, 101);
    ASSERT_TRUE(r.ok) << "a partial-split payment paying scriptPayout must fold "
                         "through: " << r.error;
    EXPECT_TRUE(r.payee_paid_verified);
    EXPECT_FALSE(r.payee_operator_full_reward);         // partial ⇒ owner-required branch
}

// STRICTNESS for partial splits: masternodeReward>0 so scriptPayout is required;
// a coinbase paying ONLY the operator script (no owner output) is invalid and
// MUST poison — the owner axis is always priceable and always enforced.
TEST(DashReplayFoldOperatorSplit, PartialOperatorRewardMissingOwnerScriptPoisons)
{
    OpSplitFixture fx(/*bps=*/800, script_bytes(0x6A), script_bytes(0x6B));
    auto blk = fx.payment_block(101, {fx.op_script});  // operator only, no owner
    auto r = fx.eng.fold_block(blk, 101);
    ASSERT_FALSE(r.ok) << "partial split with no owner output MUST poison";
    EXPECT_NE(r.error.find("PAYEE MISMATCH"), std::string::npos) << r.error;
}

// ════════════════════════════════════════════════════════════════════════
// INCREMENTAL SML MERKLE-ROOT KATs
//
// The incremental root (per-proTxHash CalcHash cache + cached merkle tree,
// hybrid path/rebuild — replay_fold_engine.hpp compute_sml_root) MUST equal
// the cache-independent full recompute (compute_sml_root_full) at EVERY
// block, and the fold self-check MUST still poison when the incremental path
// is wrong. The whole existing synthetic + real suite above already folds
// through the incremental path (every self-check passes only if incremental
// == committed); these add the EXPLICIT incremental == full equality and the
// missed-invalidation poison property.
// ════════════════════════════════════════════════════════════════════════

// Root-axis-isolating config: folds enabled from h=1, payee cross-check OFF
// (enforcement height pushed above every test height) so the UNCONDITIONAL
// merkleRootMNList self-check is the only thing under test — no coinbase
// payout scaffolding needed. v19/mn_rr on from h=1 like synth_cfg.
static FoldConfig inc_cfg()
{
    FoldConfig cfg;
    cfg.enabled = true;
    cfg.gates.dip0003_height             = 1;
    cfg.gates.dip0003_enforcement_height = 100000000; // payee axis dormant
    cfg.gates.v19_height                 = 1;
    cfg.gates.mn_rr_height               = 1;
    return cfg;
}

static MutableTransaction spend_collateral_tx(const TxPrevOut& outpoint)
{
    MutableTransaction spend;
    spend.version = 1;
    TxIn in;
    in.prevout  = outpoint;
    in.sequence = 0xffffffff;
    spend.vin.push_back(in);
    return spend;
}

// A multi-block window that exercises, with the incremental root proven equal
// to the full recompute AND to an independently hand-built root at each step:
//   • ProRegTx add (h=101, h=102) — new leaves shift sorted positions
//   • ProUpRevTx revoke (h=103)   — ResetOperatorFields + ban → isValid false
//   • ProUpRegTx operator-key change (h=104) — reset + ban + new keys
//   • collateral spend remove (h=105, h=106) — leaves shift again
TEST(DashReplayFoldIncremental, WindowIncrementalEqualsFullEqualsHandBuilt)
{
    DmlFoldEngine eng(inc_cfg());
    eng.seed({}, 0, 100, raw256(9));
    EXPECT_EQ(eng.compute_sml_root(), eng.compute_sml_root_full());
    EXPECT_EQ(eng.compute_sml_root(), uint256::ZERO); // empty list

    // ── h=101: register a, b, c ─────────────────────────────────────────
    auto pa = make_proreg(1), pb = make_proreg(2), pc = make_proreg(3);
    auto txa = make_special_tx(1, pa, 1);
    auto txb = make_special_tx(1, pb, 2);
    auto txc = make_special_tx(1, pc, 3);
    const uint256 ha = tx_hash_of(txa), hb = tx_hash_of(txb), hc = tx_hash_of(txc);
    CSimplifiedMNListEntry ea = expected_entry_of(pa, ha);
    CSimplifiedMNListEntry eb = expected_entry_of(pb, hb);
    CSimplifiedMNListEntry ec = expected_entry_of(pc, hc);
    uint256 root1 = root_of({ea, eb, ec});
    {
        auto r = eng.fold_block(make_block(101, raw256(9), root1, {txa, txb, txc}),
                                101);
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.computed_root, root1);
        EXPECT_EQ(eng.compute_sml_root(), eng.compute_sml_root_full());
        EXPECT_EQ(eng.compute_sml_root(), root1);
    }

    // ── h=102: register d, e (positions shift) ──────────────────────────
    auto pd = make_proreg(4), pe = make_proreg(5);
    auto txd = make_special_tx(1, pd, 4);
    auto txe = make_special_tx(1, pe, 5);
    const uint256 hd = tx_hash_of(txd), he = tx_hash_of(txe);
    CSimplifiedMNListEntry ed = expected_entry_of(pd, hd);
    CSimplifiedMNListEntry ee = expected_entry_of(pe, he);
    uint256 root2 = root_of({ea, eb, ec, ed, ee});
    {
        auto r = eng.fold_block(make_block(102, raw256(10), root2, {txd, txe}), 102);
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.computed_root, root2);
        EXPECT_EQ(eng.compute_sml_root(), eng.compute_sml_root_full());
        EXPECT_EQ(eng.compute_sml_root(), root2);
    }

    // ── h=103: ProUpRevTx revoke c → reset + ban (isValid flips false) ──
    CProUpRevTx rev;
    rev.nVersion  = ProTxVersion::BASIC_BLS;
    rev.proTxHash = hc;
    rev.nReason   = CProUpRevTx::REASON_COMPROMISED_KEYS;
    auto revtx = make_special_tx(4, rev, 6);
    CSimplifiedMNListEntry ec2;                 // hand-built revoked entry
    ec2.nVersion     = ProTxVersion::LEGACY_BLS; // ResetOperatorFields floor
    ec2.proRegTxHash = hc;
    ec2.keyIDVoting  = pc.keyIDVoting;
    ec2.isValid      = false;
    uint256 root3 = root_of({ea, eb, ec2, ed, ee});
    {
        auto r = eng.fold_block(make_block(103, raw256(11), root3, {revtx}), 103);
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.revoked, 1u);
        EXPECT_EQ(r.computed_root, root3);
        EXPECT_EQ(eng.compute_sml_root(), eng.compute_sml_root_full());
        EXPECT_EQ(eng.compute_sml_root(), root3);
    }

    // ── h=104: ProUpRegTx operator-key change on a → reset + ban + keys ─
    CProUpRegTx upr;
    upr.nVersion       = ProTxVersion::BASIC_BLS;
    upr.proTxHash      = ha;
    upr.pubKeyOperator = seq_array<48>(0xB0);
    upr.keyIDVoting    = raw160(0xB4);
    upr.scriptPayout.m_data = script_bytes(0xB8);
    upr.vchSig.assign(8, 0xB);
    auto uprtx = make_special_tx(3, upr, 7);
    CSimplifiedMNListEntry ea2;                  // hand-built key-changed entry
    ea2.nVersion       = ProTxVersion::BASIC_BLS; // never downgraded below basic
    ea2.proRegTxHash   = ha;
    ea2.netAddress     = {};                      // reset empties netInfo
    ea2.netPort        = 0;
    ea2.pubKeyOperator = upr.pubKeyOperator;
    ea2.keyIDVoting    = upr.keyIDVoting;
    ea2.isValid        = false;                   // banned until a ProUpServTx
    ea2.nType          = MnType::REGULAR;
    uint256 root4 = root_of({ea2, eb, ec2, ed, ee});
    {
        auto r = eng.fold_block(make_block(104, raw256(12), root4, {uprtx}), 104);
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.banned, 1u);
        EXPECT_EQ(r.computed_root, root4);
        EXPECT_EQ(eng.compute_sml_root(), eng.compute_sml_root_full());
        EXPECT_EQ(eng.compute_sml_root(), root4);
    }

    // ── h=105: collateral-spend e (remove; positions shift) ─────────────
    {
        auto spend = spend_collateral_tx(pe.collateralOutpoint);
        uint256 root5 = root_of({ea2, eb, ec2, ed});
        auto r = eng.fold_block(make_block(105, raw256(13), root5, {spend}), 105);
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.collateral_spent, 1u);
        EXPECT_EQ(eng.find(he), nullptr);
        EXPECT_EQ(r.computed_root, root5);
        EXPECT_EQ(eng.compute_sml_root(), eng.compute_sml_root_full());
        EXPECT_EQ(eng.compute_sml_root(), root5);
    }

    // ── h=106: collateral-spend a (remove the banned, key-changed leaf) ─
    {
        auto spend = spend_collateral_tx(pa.collateralOutpoint);
        uint256 root6 = root_of({eb, ec2, ed});
        auto r = eng.fold_block(make_block(106, raw256(14), root6, {spend}), 106);
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.collateral_spent, 1u);
        EXPECT_EQ(eng.find(ha), nullptr);
        EXPECT_EQ(r.computed_root, root6);
        EXPECT_EQ(eng.compute_sml_root(), eng.compute_sml_root_full());
        EXPECT_EQ(eng.compute_sml_root(), root6);
    }
}

// Real mainnet, large N (~2972 / ~4900): the incremental root equals the full
// recompute across the case-D PoSe BAN (isValid flip false) at h=2516412 and
// the REVIVE (isValid flip true) + confirmedHash + quiet sequence at
// h=2516756..2516760 — the demanding window the port targets.
TEST(DashReplayFoldIncremental, RealCaseDBanIncrementalEqualsFull)
{
    auto fx  = parse_prestate(kDashReplayPrestate2516411);
    auto eng = seed_from_fixture(fx);
    EXPECT_EQ(eng.compute_sml_root(), eng.compute_sml_root_full());

    auto qf = parse_quorum(kDashReplayQuorum2516412);
    const uint256 quorum_hash = from_display(qf.quorum_hash_display.c_str());
    eng.set_members_fn([&](uint8_t llmq_type, const uint256& qh)
                           -> std::optional<std::vector<uint256>> {
        if (llmq_type == qf.llmq_type && qh == quorum_hash) return qf.members;
        return std::nullopt;
    });

    auto blk = parse_block(kDashReplayBlock2516412);
    auto r   = eng.fold_block(blk, 2516412);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.banned, 1u);
    EXPECT_EQ(r.computed_root.GetHex(), kRoot2516412);
    EXPECT_EQ(eng.compute_sml_root(), eng.compute_sml_root_full());
    EXPECT_EQ(eng.compute_sml_root().GetHex(), kRoot2516412);
}

TEST(DashReplayFoldIncremental, RealReviveAndQuietSequenceIncrementalEqualsFull)
{
    auto fx  = parse_prestate(kDashReplayPrestate2516755);
    auto eng = seed_from_fixture(fx);
    EXPECT_EQ(eng.compute_sml_root(), eng.compute_sml_root_full());

    auto r = eng.fold_block(parse_block(kDashReplayBlock2516756), 2516756);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.revived, 1u);
    EXPECT_EQ(r.computed_root.GetHex(), kRoot2516756);
    EXPECT_EQ(eng.compute_sml_root(), eng.compute_sml_root_full());

    const char* seq[] = {kDashReplayBlock2516757, kDashReplayBlock2516758,
                         kDashReplayBlock2516759, kDashReplayBlock2516760};
    uint32_t h = 2516757;
    for (const char* bh : seq) {
        auto rr = eng.fold_block(parse_block(bh), h);
        ASSERT_TRUE(rr.ok) << "h=" << h << ": " << rr.error;
        EXPECT_EQ(eng.compute_sml_root(), eng.compute_sml_root_full()) << "h=" << h;
        EXPECT_EQ(rr.computed_root.GetHex(), kRoot2516756) << "h=" << h;
        ++h;
    }
}

// POISON: a deliberately-wrong incremental invalidation (a mutation that
// changed an entry's SML fields but failed to mark its proTxHash dirty) makes
// compute_sml_root() return a STALE root; the self-check then MISMATCHES the
// committed cbTx root and HARD-STOPS. Proves the incremental path can never
// silently serve a wrong list — a missed invalidation is fail-CLOSED.
TEST(DashReplayFoldIncremental, MissedInvalidationPoisonsAtSelfCheck)
{
    auto fx  = parse_prestate(kDashReplayPrestate2516755);
    auto eng = seed_from_fixture(fx);
    ASSERT_TRUE(eng.fold_block(parse_block(kDashReplayBlock2516756), 2516756).ok);
    EXPECT_EQ(eng.compute_sml_root().GetHex(), kRoot2516756);

    // Pick a long-confirmed MN (confirmedHash already set ⇒ pass 1 will not
    // re-mark it, and the quiet block 2516757 does not otherwise touch it).
    uint256 victim;
    for (const auto& [protx, st] : eng.entries()) {
        if (!st.confirmedHash.IsNull()) { victim = protx; break; }
    }
    ASSERT_FALSE(victim.IsNull());

    // Simulate the missed invalidation.
    eng.test_only_corrupt_incremental_cache(victim);

    // The incremental root now diverges from the truth (full recompute).
    EXPECT_NE(eng.compute_sml_root(), eng.compute_sml_root_full());

    // Folding the next (correct) block: the stale incremental root != the
    // block's committed cbTx root ⇒ HARD STOP, engine poisoned.
    auto r = eng.fold_block(parse_block(kDashReplayBlock2516757), 2516757);
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(eng.poisoned());
    EXPECT_NE(r.error.find("ROOT MISMATCH"), std::string::npos) << r.error;

    // Sticky: no further fold is accepted after poison.
    auto r2 = eng.fold_block(parse_block(kDashReplayBlock2516758), 2516758);
    EXPECT_FALSE(r2.ok);
    EXPECT_NE(r2.error.find("POISONED"), std::string::npos) << r2.error;
}
