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
#include <impl/dash/coin/vendor/incremental_sml_merkle.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/block.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <set>
#include <span>
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

static void parse_prestate_into(const char* text, PrestateFixture& fx,
                                bool canonicalize_opkeys = true)
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
        // The fixture opkey field is RAW WIRE bytes (per-nVersion scheme). The DML
        // engine's STORE CONTRACT is canonical BASIC (to_sml_entry re-encodes each
        // leaf per nVersion via opkey_for_leaf), so canonicalize on ingest — exactly
        // what the production wire-ingest boundaries do (main_dash.cpp anchor-SML
        // seed, replay_prestate.hpp, fold_proupreg store sites). Seeding raw wire
        // bytes makes a legacy-era (nVersion=1) leaf hash the wrong point and the
        // seed self-check fails against the committed merkleRootMNList. The
        // canonicalize_opkeys=false path exists ONLY to reproduce that failure in a
        // regression-lock test.
        if (canonicalize_opkeys)
            st.pubKeyOperator = dash::coin::vendor::opkey_to_basic(
                st.pubKeyOperator, st.nVersion < ProTxVersion::BASIC_BLS);
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
    // The fixtures are dashd `protx list` captures: their poSePenalty IS
    // dashd's value, so the certainty bounds start exact.
    eng.seed(std::move(entries), fx.entries.size(), fx.height, anchor_hash,
             fx.network, dash::coin::replay::SeedPenalties::Exact);
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

#ifdef C2POOL_DASH_BLS
// Regression lock for the #154 seed-side opkey scheme bug (this PR): the DML
// engine's store contract is CANONICAL BASIC operator keys — to_sml_entry
// re-encodes each SML leaf per its own nVersion (opkey_for_leaf: legacy iff
// nVersion < BASIC_BLS). Seeding the RAW WIRE bytes (legacy-encoded for the
// pre-v19 nVersion=1 entries, 1784 of 2971 at this height) makes those leaves
// hash the wrong point, so compute_sml_root() DIVERGES from the committed
// merkleRootMNList. The production wire-ingest boundaries (main_dash.cpp
// anchor-SML seed, replay_prestate.hpp) canonicalize on ingest — when they do,
// the root reproduces BY CONSTRUCTION and the anchor seed self-check passes
// (fail-CLOSED preserved: a seed that cannot reproduce the root unseeds).
// Guarded on C2POOL_DASH_BLS because opkey_to_basic is an identity no-op
// without a BLS backend, so raw == canonical and both reproduce the root
// (this is exactly why the defect was invisible to the BLS-OFF CI jobs).
TEST(DashReplayFoldReal, SeedRawWireOpkeyDivergesCanonicalReproducesRoot2516755)
{
    uint256 anchor;
    // RAW WIRE seed (canonicalize_opkeys=false) MUST NOT reproduce the root.
    PrestateFixture raw;
    parse_prestate_into(kDashReplayPrestate2516755, raw,
                        /*canonicalize_opkeys=*/false);
    anchor.SetHex(raw.blockhash_display);
    FoldConfig cfg;
    cfg.enabled = true;
    DmlFoldEngine eng_raw(cfg);
    eng_raw.seed(raw.entries, raw.entries.size(), raw.height, anchor,
                 raw.network);
    EXPECT_NE(eng_raw.compute_sml_root().GetHex(), raw.mnroot_display)
        << "raw-wire opkey seed unexpectedly reproduced the committed root — "
           "the store contract or the fixture's legacy-scheme mix changed";

    // CANONICAL seed (the production wire-ingest path) MUST reproduce the root.
    auto fx = parse_prestate(kDashReplayPrestate2516755);
    DmlFoldEngine eng_can(cfg);
    eng_can.seed(fx.entries, fx.entries.size(), fx.height, anchor, fx.network);
    EXPECT_EQ(eng_can.compute_sml_root().GetHex(), fx.mnroot_display);
}
#endif // C2POOL_DASH_BLS

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

// task #154 delta path at the ENGINE level, on real mainnet bodies. The
// self-check's incremental root recompute must NOT re-materialise + re-sort the
// whole ~2971-entry SML on every block (the #1297 wall-clock regression). After
// the one unavoidable warm-up rebuild, four real quiet bodies together examine
// FEWER SML entries than a SINGLE full re-materialise — where the shipped code
// examined 4*n. The folded roots stay byte-exact against the chain throughout,
// so the speed-up costs nothing in correctness.
TEST(DashReplayFoldReal, IncrementalSelfCheckAvoidsPerBlockFullRematerialize)
{
    auto fx  = parse_prestate(kDashReplayPrestate2516755);
    auto eng = seed_from_fixture(fx);
    const uint64_t n = eng.size();   // 2971

    // Warm the cache: the first fold after a seed rebuilds from the full set
    // (seed() dropped the diff base). This is the one unavoidable O(n).
    ASSERT_TRUE(eng.fold_block(parse_block(kDashReplayBlock2516756), 2516756).ok);

    // Four more real bodies. None registers or removes an MN (the leaf set is
    // stable — the roots below prove it), so each takes the delta / cached-root
    // path and examines only the leaves it actually mutated.
    const char* seq[] = {kDashReplayBlock2516757, kDashReplayBlock2516758,
                         kDashReplayBlock2516759, kDashReplayBlock2516760};
    uint32_t h = 2516757;
    const uint64_t ex0 = dash::coin::vendor::sml_leaves_examined_count();
    for (const char* bh : seq) {
        auto rr = eng.fold_block(parse_block(bh), h);
        ASSERT_TRUE(rr.ok) << "h=" << h << ": " << rr.error;
        // Byte-exact against the chain — the delta path never trades away
        // correctness for speed.
        EXPECT_EQ(rr.computed_root.GetHex(), kRoot2516756) << "h=" << h;
        EXPECT_EQ(rr.registered, 0u) << "h=" << h;   // leaf set stable ⇒ non-structural
        ++h;
    }
    const uint64_t examined =
        dash::coin::vendor::sml_leaves_examined_count() - ex0;
    EXPECT_LT(examined, n)
        << "four blocks' delta self-check examined " << examined
        << " SML entries — must be < one full re-materialise (n=" << n
        << "); the shipped full path examined 4*n = " << (4 * n);
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
    // Exact seed => exact bounds through decay + punish + ban.
    EXPECT_EQ(still_valid->nPoSePenaltyHi, 1961);
    EXPECT_EQ(banned->nPoSePenaltyHi, 2972);
    EXPECT_EQ(r.root_resolved_bans, 0u);

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
        make_block(102, eng.block_hash(), root_of({e2}), {uptx}), 102);
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
            make_block(102, eng.block_hash(), root_of({expected_entry_of(p, mn)}),
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
    auto r = eng.fold_block(make_block(103, eng.block_hash(), root_of({e}), {uprtx}, &eng),
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

// nOperatorReward == 10000 (the 2026-10-28 mn-payout-split-unprovable
// incident class). dashd masternode/payments.cpp:65-79: with the operator
// script set, operatorReward == masternodeReward, the owner remainder is 0 and
// `if (masternodeReward > 0)` emits NO owner output — the coinbase pays the
// projected masternode at its OPERATOR script only. The fold's pass-6 payee
// cross-check must therefore look for that script; checking scriptPayout here
// false-poisons a byte-correct fold (and this engine also runs on the cold
// MN-CKPT path that feeds the diff store).
TEST(DashReplayFoldSynthetic, ReplayFoldPayeeCheckAcceptsFullOperatorSplit)
{
    // Build the same two-block history twice: one engine sees the operator-
    // only payment dashd makes, the other an owner-only payment dashd could
    // not have made for this state.
    auto history = [](DmlFoldEngine& eng, uint256& mn, CProRegTx& p) {
        eng.seed({}, 0, 100, raw256(9));
        p  = make_proreg(1, /*operator_reward_bps=*/10000);
        auto tx = make_special_tx(1, p, 1);
        mn = tx_hash_of(tx);
        auto r1 = eng.fold_block(
            make_block(101, raw256(9), root_of({expected_entry_of(p, mn)}),
                       {tx}, &eng), 101);
        ASSERT_TRUE(r1.ok) << r1.error;
        // The operator sets its payout script (ProUpServTx). Block 102 is
        // still built from the PRE-block list, where no operator script is
        // set yet, so dashd pays the owner the whole share there.
        CProUpServTx up;
        up.nVersion  = ProTxVersion::BASIC_BLS;
        up.proTxHash = mn;
        up.netInfo   = p.netInfo;
        up.scriptOperatorPayout.m_data = script_bytes(0x99);
        auto uptx = make_special_tx(2, up, 2);
        auto r2 = eng.fold_block(
            make_block(102, eng.block_hash(), root_of({expected_entry_of(p, mn)}),
                       {uptx}, &eng), 102);
        ASSERT_TRUE(r2.ok) << r2.error;
        ASSERT_EQ(eng.find(mn)->nOperatorReward, 10000);
        ASSERT_EQ(eng.find(mn)->scriptOperatorPayout.m_data, script_bytes(0x99));
    };
    auto paying = [](const DmlFoldEngine& eng, const CProRegTx& p, const uint256& mn,
                     const std::vector<unsigned char>& script) {
        auto b = make_block(103, eng.block_hash(), root_of({expected_entry_of(p, mn)}));
        TxOut out;
        out.value = 77'055'682;
        out.scriptPubKey.m_data = script;
        b.m_txs[0].vout.push_back(std::move(out));
        return b;
    };

    {
        DmlFoldEngine eng(synth_cfg());
        uint256 mn; CProRegTx p;
        history(eng, mn, p);
        if (HasFatalFailure()) return;
        ASSERT_TRUE(eng.project_payee(103).has_value());
        ASSERT_EQ(*eng.project_payee(103), mn);
        auto r = eng.fold_block(paying(eng, p, mn, script_bytes(0x99)), 103);
        ASSERT_TRUE(r.ok)
            << "a coinbase paying ONLY the operator script is dashd's exact"
               " output set for a bps=10000 masternode: " << r.error;
        EXPECT_TRUE(r.payee_paid_verified);
        EXPECT_FALSE(eng.poisoned());
        EXPECT_EQ(eng.find(mn)->nLastPaidHeight, 103);
    }
    {
        DmlFoldEngine eng(synth_cfg());
        uint256 mn; CProRegTx p;
        history(eng, mn, p);
        if (HasFatalFailure()) return;
        auto r = eng.fold_block(paying(eng, p, mn, p.scriptPayout.m_data), 103);
        ASSERT_FALSE(r.ok)
            << "an owner-only coinbase cannot have been built by dashd from a"
               " bps=10000 state with an operator script — exact script"
               " equality, never 'any script of this masternode'";
        EXPECT_NE(r.error.find("PAYEE MISMATCH"), std::string::npos) << r.error;
    }
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
    auto r = eng.fold_block(make_block(102, eng.block_hash(), root_of({e}), {revtx}, &eng),
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
        make_block(102, eng.block_hash(), root_of({expected_entry_of(p2, mn2)}),
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
        make_block(102, eng.block_hash(), root_of({ea, eb, ec}), {make_qc(4)}, &eng), 102);
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
        make_block(103, eng.block_hash(), root_of({ea_banned, eb, ec}),
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
        make_block(104, eng.block_hash(), root_of({ea_banned, eb, ec}),
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
        make_block(105, eng.block_hash(), root_of({ea, eb, ec}),
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
            make_block(h, eng.block_hash(), root_of({e}), {}, &eng), h);
        ASSERT_TRUE(r.ok) << "h=" << h << ": " << r.error;
        EXPECT_EQ(r.confirmed, 0u) << "h=" << h;
        EXPECT_TRUE(eng.find(mn)->confirmedHash.IsNull()) << "h=" << h;
    }
    // The prev-link block 117 must carry = the cursor block (116) — and
    // that hash is what becomes the confirmedHash.
    const uint256 hash116 = eng.block_hash();
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

// The engine's state is the post-state of (m_height, m_block_hash) and the
// penalty oracle answers for exactly that pair (PR-B verify, must-fix
// 2): a block whose prev-link names a different block is REFUSED — no
// mutation, no poison (the held state is still right for its own block) —
// and the correct child still folds afterwards.
TEST(DashReplayFoldSynthetic, FoldRefusesABlockThatDoesNotExtendTheCursor)
{
    DmlFoldEngine eng(synth_cfg());
    eng.seed({}, 0, 100, raw256(9));
    auto p  = make_proreg(1);
    auto tx = make_special_tx(1, p, 1);
    const uint256 mn = tx_hash_of(tx);
    const auto e = expected_entry_of(p, mn);
    ASSERT_TRUE(eng.fold_block(
        make_block(101, raw256(9), root_of({e}), {tx}, &eng), 101).ok);
    const uint256 cursor = eng.block_hash();
    const ReplayMNState before = *eng.find(mn);

    auto r = eng.fold_block(make_block(102, raw256(0x55), root_of({e}), {}, &eng), 102);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.find("prev-link"), std::string::npos) << r.error;
    EXPECT_FALSE(eng.poisoned()) << "a foreign block is a refusal, not a poison";
    EXPECT_EQ(eng.height(), 101u);
    EXPECT_EQ(eng.block_hash(), cursor);
    EXPECT_TRUE(*eng.find(mn) == before) << "a refused fold must not mutate";
    EXPECT_EQ(eng.find(mn)->nLastPaidHeight, before.nLastPaidHeight);

    auto ok = eng.fold_block(make_block(102, cursor, root_of({e}), {}, &eng), 102);
    ASSERT_TRUE(ok.ok) << ok.error;
    EXPECT_EQ(eng.height(), 102u);
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

// ════════════════════════════════════════════════════════════════════════
// Dash Core v23.1.9 port — chain-side rules (items A and B)
// ════════════════════════════════════════════════════════════════════════

// A seeded, already-confirmed masternode (pass 1 leaves it alone).
static ReplayMNState v2319_mn(uint8_t tag, uint8_t type = MnType::REGULAR)
{
    ReplayMNState st;
    st.nVersion = ProTxVersion::BASIC_BLS;
    st.nType = type;
    st.keyIDOwner = raw160(static_cast<uint8_t>(0x20 + tag));
    st.keyIDVoting = raw160(static_cast<uint8_t>(0x50 + tag));
    st.pubKeyOperator = seq_array<48>(static_cast<uint8_t>(0x30 + tag));
    st.collateralOutpoint.hash = raw256(static_cast<uint8_t>(0x40 + tag));
    st.collateralOutpoint.index = 1;
    st.netInfo.ip = seq_array<16>(static_cast<uint8_t>(0x10 + tag));
    st.netInfo.port_be = 9999;
    st.scriptPayout.m_data = script_bytes(static_cast<uint8_t>(0x60 + tag));
    st.nRegisteredHeight = 50;
    st.confirmedHash = raw256(0x77);
    if (type == MnType::EVO) {
        st.platformNodeID = raw160(static_cast<uint8_t>(0x90 + tag));
        st.platformP2PPort = 26656;
        st.platformHTTPPort = 443;
    }
    return st;
}

static MutableTransaction v2319_plain_tx(int32_t version, uint16_t type = 0)
{
    MutableTransaction tx;
    tx.version = version;
    tx.type = type;
    TxIn in;
    in.prevout.hash = raw256(0xA9);
    in.prevout.index = 3;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = 5;
    out.scriptPubKey.m_data = script_bytes(0xAA);
    tx.vout.push_back(out);
    if (type != 0) tx.extra_payload = {0x01, 0x02};
    return tx;
}

// A5 (07494dd62): after DIP3 a negative-nVersion tx makes the block invalid
// (bad-txns-version). The fold refuses it BEFORE any pass mutates the list —
// no poison, cursor unmoved — and the valid block at that height still folds.
TEST(DashReplayFoldSynthetic, NegativeVersionTxRefusesTheBlock)
{
    auto cfg = synth_cfg();
    cfg.gates.dip0003_height = 100;   // DIP3 active for blocks at h > 100
    DmlFoldEngine eng(cfg);
    const uint256 mn = raw256(0xE1);
    const auto st = v2319_mn(11);
    eng.seed({{mn, st}}, 1, 100, raw256(9));
    const uint256 root = root_of({st.to_sml_entry(mn)});
    ASSERT_NE(eng.find(mn), nullptr);
    const ReplayMNState before = *eng.find(mn);

    auto r = eng.fold_block(
        make_block(101, raw256(9), root, {v2319_plain_tx(0xFFFF)}, &eng), 101);
    ASSERT_FALSE(r.ok) << "dashd: bad-txns-version";
    EXPECT_NE(r.error.find("bad-txns-version"), std::string::npos) << r.error;
    EXPECT_FALSE(eng.poisoned()) << "a block dashd rejects is another chain, not a desync";
    EXPECT_EQ(eng.height(), 100u);
    ASSERT_NE(eng.find(mn), nullptr);
    EXPECT_TRUE(*eng.find(mn) == before) << "the held list is unchanged";

    auto ok = eng.fold_block(make_block(101, raw256(9), root, {}, &eng), 101);
    EXPECT_TRUE(ok.ok) << ok.error;
}

// Control for A5: the rule is post-DIP3 only (DeploymentActiveAfter).
TEST(DashReplayFoldSynthetic, NegativeVersionTxIsOutsideTheRuleAtTheDip3Block)
{
    auto cfg = synth_cfg();
    cfg.gates.dip0003_height = 101;
    DmlFoldEngine eng(cfg);
    const uint256 mn = raw256(0xE1);
    const auto st = v2319_mn(11);
    eng.seed({{mn, st}}, 1, 100, raw256(9));
    auto r = eng.fold_block(
        make_block(101, raw256(9), root_of({st.to_sml_entry(mn)}),
                   {v2319_plain_tx(0xFFFF)}, &eng), 101);
    EXPECT_TRUE(r.ok) << r.error;
}

// A6: an unknown special type post-DIP3 is bad-txns-type.
TEST(DashReplayFoldSynthetic, UnknownSpecialTypePostDip3RefusesTheBlock)
{
    auto cfg = synth_cfg();
    cfg.gates.dip0003_height = 100;
    DmlFoldEngine eng(cfg);
    const uint256 mn = raw256(0xE1);
    const auto st = v2319_mn(11);
    eng.seed({{mn, st}}, 1, 100, raw256(9));
    auto r = eng.fold_block(
        make_block(101, raw256(9), root_of({st.to_sml_entry(mn)}),
                   {v2319_plain_tx(3, /*type=*/42)}, &eng), 101);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.find("bad-txns-type"), std::string::npos) << r.error;
    EXPECT_FALSE(eng.poisoned());
    EXPECT_EQ(eng.height(), 100u);
}

// B9 (#7488): IsValidMnType is checked by name, ahead of the lookup.
TEST(DashReplayFoldSynthetic, ProUpServInvalidNTypeRefusesFold)
{
    DmlFoldEngine eng(synth_cfg());
    const uint256 mn = raw256(0xE1);
    eng.seed({{mn, v2319_mn(11)}}, 1, 100, raw256(9));
    CProUpServTx up;
    up.nVersion  = ProTxVersion::BASIC_BLS;
    up.nType     = 2;
    up.proTxHash = mn;
    up.netInfo.ip = seq_array<16>(0x19);
    up.netInfo.port_be = 9999;
    auto r = eng.fold_block(
        make_block(101, raw256(9), uint256{}, {make_special_tx(2, up, 1)}, &eng), 101);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.find("(bad-protx-type)"), std::string::npos) << r.error;
}

// B9: a ProRegTx whose keyIDOwner an existing MN holds (bad-protx-dup-key).
// The block commits the root a fold WITHOUT the check would compute, so the
// only thing refusing it is the uniqueness rule.
TEST(DashReplayFoldSynthetic, DupOwnerKeyRefusesFold)
{
    DmlFoldEngine eng(synth_cfg());
    const uint256 mn = raw256(0xE1);
    const auto st = v2319_mn(11);
    eng.seed({{mn, st}}, 1, 100, raw256(9));
    auto p = make_proreg(1);
    p.keyIDOwner = st.keyIDOwner;
    auto tx = make_special_tx(1, p, 1);
    auto r = eng.fold_block(
        make_block(101, raw256(9),
                   root_of({st.to_sml_entry(mn), expected_entry_of(p, tx_hash_of(tx))}),
                   {tx}, &eng), 101);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.find("bad-protx-dup-key"), std::string::npos) << r.error;
}

// B9 (#7846): keyIDOwner and platformNodeID are ONE namespace — both ways.
TEST(DashReplayFoldSynthetic, OwnerPlatformNamespaceRefusesFold)
{
    {   // a ProRegTx owner key equal to an Evo MN's platformNodeID
        DmlFoldEngine eng(synth_cfg());
        const uint256 evo = raw256(0xE2);
        const auto se = v2319_mn(12, MnType::EVO);
        eng.seed({{evo, se}}, 1, 100, raw256(9));
        auto p = make_proreg(1);
        p.keyIDOwner = se.platformNodeID;
        auto tx = make_special_tx(1, p, 1);
        auto r = eng.fold_block(
            make_block(101, raw256(9),
                       root_of({se.to_sml_entry(evo), expected_entry_of(p, tx_hash_of(tx))}),
                       {tx}, &eng), 101);
        ASSERT_FALSE(r.ok);
        EXPECT_NE(r.error.find("bad-protx-dup-key"), std::string::npos) << r.error;
    }
    {   // an Evo ProUpServTx platformNodeID equal to another MN's owner key
        DmlFoldEngine eng(synth_cfg());
        const uint256 x = raw256(0xE1), evo = raw256(0xE3);
        const auto sx = v2319_mn(11);
        const auto se = v2319_mn(13, MnType::EVO);
        eng.seed({{x, sx}, {evo, se}}, 2, 100, raw256(9));
        CProUpServTx up;
        up.nVersion = ProTxVersion::BASIC_BLS;
        up.nType = MnType::EVO;
        up.proTxHash = evo;
        up.netInfo = se.netInfo;
        up.platformNodeID = sx.keyIDOwner;
        up.platformP2PPort = se.platformP2PPort;
        up.platformHTTPPort = se.platformHTTPPort;
        auto upd = se;
        upd.platformNodeID = up.platformNodeID;
        auto r = eng.fold_block(
            make_block(101, raw256(9),
                       root_of({sx.to_sml_entry(x), upd.to_sml_entry(evo)}),
                       {make_special_tx(2, up, 1)}, &eng), 101);
        ASSERT_FALSE(r.ok);
        EXPECT_NE(r.error.find("bad-protx-dup-platformnodeid"), std::string::npos) << r.error;
    }
}

// B9: a ProUpRegTx moving to an operator key another MN holds
// (UpdateUniqueProperty throws => bad-protx-dup-key).
TEST(DashReplayFoldSynthetic, DupOperatorKeyRefusesFold)
{
    DmlFoldEngine eng(synth_cfg());
    const uint256 x = raw256(0xE1), y = raw256(0xE4);
    const auto sx = v2319_mn(11);
    const auto sy = v2319_mn(14);
    eng.seed({{x, sx}, {y, sy}}, 2, 100, raw256(9));
    CProUpRegTx up;
    up.nVersion = ProTxVersion::BASIC_BLS;
    up.proTxHash = y;
    up.pubKeyOperator = sx.pubKeyOperator;
    up.keyIDVoting = sy.keyIDVoting;
    up.scriptPayout = sy.scriptPayout;
    // What a fold without the rule produces: Y reset + banned on the new key.
    auto ey = sy;
    ey.ResetOperatorFields();
    ey.BanIfNotBanned(101);
    ey.nVersion = ProTxVersion::BASIC_BLS;
    ey.pubKeyOperator = sx.pubKeyOperator;
    auto r = eng.fold_block(
        make_block(101, raw256(9), root_of({sx.to_sml_entry(x), ey.to_sml_entry(y)}),
                   {make_special_tx(3, up, 1)}, &eng), 101);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.find("bad-protx-dup-key"), std::string::npos) << r.error;
}


// ═══════════════════════════════════════════════════════════════════════════
// task #154 — INCREMENTAL merkleRootMNList cache KATs.
//
// The DASH replay fold recomputes merkleRootMNList every block as a reward-safe
// self-check. The naive path (CSimplifiedMNList::CalcMerkleRoot) rebuilds the
// whole ~4900-leaf tree each block; IncrementalSmlMerkle reuses the leaf hashes
// and internal nodes the block did not disturb. These KATs prove the two
// deliverables:
//   (a) THE HARD INVARIANT — for EVERY mutation the incremental root byte-
//       matches the naive full recompute (a fast-but-wrong root would serve a
//       forked list). Proven step-by-step over a synthetic mutation sequence.
//   (b) THE REDUCED HASH COUNT — measured via the shared sml_leaf_hash_count()
//       / sml_node_hash_count() seams that BOTH paths bump, so the numbers are
//       directly comparable. A payment-rotation-only block hashes NOTHING; a
//       block touching k SML entries re-hashes only those k leaves + O(k·log n)
//       internal nodes, versus the naive ~n leaves + ~n nodes every block.
// ═══════════════════════════════════════════════════════════════════════════

using dash::coin::vendor::IncrementalSmlMerkle;
using dash::coin::vendor::sml_leaf_hash_count;
using dash::coin::vendor::sml_node_hash_count;
using dash::coin::vendor::sml_leaves_examined_count;

namespace {

// Deterministic, well-spread, unique proRegTxHash for a given seed. Spread
// across all 32 bytes so the memcmp merkle sort interleaves the MNs (a
// realistic tree, not a degenerate one).
uint256 incmerkle_protx_of(uint32_t seed)
{
    uint256 h;
    unsigned char* p = h.data();
    uint64_t x = 0x9E3779B97F4A7C15ull ^ (static_cast<uint64_t>(seed) * 0xD1B54A32D192ED03ull);
    for (int b = 0; b < 32; ++b) {
        x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ull;
        x ^= x >> 27; x *= 0x94D049BB133111EBull;
        x ^= x >> 31;
        p[b] = static_cast<unsigned char>(x & 0xFF);
    }
    return h;
}

CSimplifiedMNListEntry incmerkle_mk_entry(uint32_t seed, bool valid = true)
{
    CSimplifiedMNListEntry e;
    e.nVersion      = CSimplifiedMNListEntry::VER_BASIC_BLS;
    e.proRegTxHash  = incmerkle_protx_of(seed);
    e.confirmedHash = uint256::ZERO;
    e.netPort       = static_cast<uint16_t>(9999u);
    e.isValid       = valid;
    e.nType         = CSimplifiedMNListEntry::TYPE_REGULAR;
    // give the operator key deterministic non-zero content so CalcHash is
    // hashing a realistic ~200-byte leaf.
    for (size_t i = 0; i < e.pubKeyOperator.size(); ++i)
        e.pubKeyOperator[i] = static_cast<uint8_t>((seed * 31u + i) & 0xFF);
    return e;
}

} // namespace

// The whole point of the fold self-check is to catch divergence from
// consensus, so the incremental root MUST equal the naive full recompute at
// EVERY step. Drives a synthetic sequence of MN-list mutations — the exact
// shapes the fold produces per block — and asserts byte-identical roots while
// measuring the hash-count reduction.
TEST(DashReplayFoldIncrementalMerkle, ByteIdenticalRootsAndReducedHashCount)
{
    const uint32_t N = 300;
    std::map<uint32_t, CSimplifiedMNListEntry> state;   // seed -> current SML entry
    for (uint32_t i = 0; i < N; ++i) state[i] = incmerkle_mk_entry(i, true);

    IncrementalSmlMerkle cache;

    struct StepCost { uint64_t nl, nn, il, in; std::string root; };
    uint64_t tot_nl = 0, tot_nn = 0, tot_il = 0, tot_in = 0;

    auto entries_of = [&]() {
        std::vector<CSimplifiedMNListEntry> v;
        v.reserve(state.size());
        for (const auto& [k, e] : state) { (void)k; v.push_back(e); }
        return v;
    };

    auto step = [&](const char* label) -> StepCost {
        const std::vector<CSimplifiedMNListEntry> v = entries_of();

        // NAIVE full recompute (the correctness oracle). Its CalcHash /
        // merkle_pair_hash bump the shared counters.
        const uint64_t nl0 = sml_leaf_hash_count(), nn0 = sml_node_hash_count();
        const uint256 rn =
            CSimplifiedMNList(std::vector<CSimplifiedMNListEntry>(v)).CalcMerkleRoot();
        const uint64_t nl = sml_leaf_hash_count() - nl0;
        const uint64_t nn = sml_node_hash_count() - nn0;

        // INCREMENTAL cache — same shared counters.
        const uint64_t il0 = sml_leaf_hash_count(), in0 = sml_node_hash_count();
        const uint256 ri = cache.update(v);
        const uint64_t il = sml_leaf_hash_count() - il0;
        const uint64_t in = sml_node_hash_count() - in0;

        // THE HARD INVARIANT.
        EXPECT_EQ(rn.GetHex(), ri.GetHex())
            << "incremental root diverged from naive recompute at step: " << label;

        tot_nl += nl; tot_nn += nn; tot_il += il; tot_in += in;
        std::cout << "  [#154 KAT] " << label
                  << " | naive leaf=" << nl << " node=" << nn
                  << " | incr leaf=" << il << " node=" << in
                  << " | root=" << ri.GetHex().substr(0, 16) << "\n";
        return { nl, nn, il, in, ri.GetHex() };
    };

    // ── Step 1: cold build (first fold) — every leaf hashed once. ──────────
    const StepCost s1 = step("cold-build N=300 (structural)");
    EXPECT_EQ(s1.il, static_cast<uint64_t>(N)) << "cold build must hash all leaves once";
    EXPECT_EQ(s1.nl, static_cast<uint64_t>(N));

    // ── Step 2: pure payment rotation — nLastPaidHeight/PoSePenalty are NOT
    // in the SML entry, so the SML is byte-unchanged. ZERO incremental hashes;
    // naive re-hashes the whole list regardless. This is the dashd invariant. ─
    const StepCost s2 = step("payment-rotation (SML unchanged)");
    EXPECT_EQ(s2.il, 0u) << "no SML entry changed -> no leaf may be re-hashed";
    EXPECT_EQ(s2.in, 0u) << "no SML entry changed -> no internal node may be re-hashed";
    EXPECT_EQ(s2.nl, static_cast<uint64_t>(N)) << "naive re-hashes everything anyway";

    // ── Step 3: PoSe ban one MN (isValid flip) — 1 leaf changed, same set. ──
    state[7].isValid = false;
    const StepCost s3 = step("pose-ban 1 MN (isValid flip, same set)");
    EXPECT_EQ(s3.il, 1u) << "exactly one leaf changed";
    EXPECT_GE(s3.in, 1u);
    EXPECT_LE(s3.in, 12u) << "single-leaf update must be O(log n), not O(n)";
    EXPECT_LT(s3.in, s3.nn) << "incremental node work must beat the full rebuild";

    // ── Step 4: confirmedHash crosses on three MNs — 3 leaves, same set. ───
    state[10].confirmedHash = incmerkle_protx_of(900010);
    state[20].confirmedHash = incmerkle_protx_of(900020);
    state[30].confirmedHash = incmerkle_protx_of(900030);
    const StepCost s4 = step("confirmedHash on 3 MNs (same set)");
    EXPECT_EQ(s4.il, 3u) << "exactly three leaves changed";
    EXPECT_LE(s4.in, 3u * 12u) << "three O(log n) paths";
    EXPECT_LT(s4.in, s4.nn);

    // ── Step 5: ProReg adds a new MN (structural, shifts sorted positions). ─
    state[N] = incmerkle_mk_entry(N, true);
    const StepCost s5 = step("proreg add 1 MN (structural)");
    EXPECT_EQ(s5.il, 1u) << "only the new leaf is hashed; all others reused";
    EXPECT_LT(s5.il, s5.nl) << "naive re-hashes the whole grown list";

    // ── Step 6: collateral spend removes one MN (structural). ──────────────
    state.erase(50);
    const StepCost s6 = step("collateral-spend remove 1 MN (structural)");
    EXPECT_EQ(s6.il, 0u) << "a removal hashes no leaf; survivors reuse cached hashes";

    // ── Step 7: another quiet block — back to zero work. ───────────────────
    const StepCost s7 = step("quiet block (SML unchanged)");
    EXPECT_EQ(s7.il, 0u);
    EXPECT_EQ(s7.in, 0u);

    // ── Aggregate proof of the reduced hash-count. ─────────────────────────
    std::cout << "  [#154 KAT] TOTAL  naive leaf=" << tot_nl << " node=" << tot_nn
              << "  |  incr leaf=" << tot_il << " node=" << tot_in << "\n";

    // Steady-state (everything after the unavoidable cold build): incremental
    // hashed exactly the 5 leaves that actually changed (1+3+1 over steps
    // 2..7), while naive re-hashed the full list on all six blocks.
    const uint64_t steady_incr_leaf  = tot_il - s1.il;
    const uint64_t steady_naive_leaf = tot_nl - s1.nl;
    EXPECT_EQ(steady_incr_leaf, 5u) << "0+1+3+1+0+0 across steps 2..7";
    EXPECT_GT(steady_naive_leaf, 1500u) << "naive re-hashes ~N leaves every block";
    EXPECT_LT(tot_il, tot_nl);
    EXPECT_LT(tot_in, tot_nn);
    // Order-of-magnitude reduction overall (dominated by the cold build here;
    // on a real 1.5M-block fold the cold build is a one-time cost and the
    // steady-state ratio — 5 vs ~1800 above — is what matters).
    EXPECT_LT(tot_il * 3, tot_nl) << "incremental leaf hashing is a small fraction of naive";

    // The cache's root reflects the last mutation, and its size tracks the set.
    EXPECT_EQ(cache.root().GetHex(), s7.root);
    EXPECT_EQ(cache.size(), state.size());
}

// reset() drops the diff base so the next update() rebuilds in full — the
// contract the fold relies on across seed()/load_snapshot() (wholesale state
// replacement). After a reset the root must still equal the naive recompute of
// the NEW list, and the rebuild must re-hash every leaf (nothing carried over).
TEST(DashReplayFoldIncrementalMerkle, ResetForcesFullRebuildAndStaysCorrect)
{
    IncrementalSmlMerkle cache;

    std::vector<CSimplifiedMNListEntry> listA;
    for (uint32_t i = 0; i < 64; ++i) listA.push_back(incmerkle_mk_entry(i));
    const uint256 rootA_incr = cache.update(listA);
    const uint256 rootA_naive =
        CSimplifiedMNList(std::vector<CSimplifiedMNListEntry>(listA)).CalcMerkleRoot();
    EXPECT_EQ(rootA_incr.GetHex(), rootA_naive.GetHex());

    // A completely different list (as a snapshot resume would install).
    std::vector<CSimplifiedMNListEntry> listB;
    for (uint32_t i = 1000; i < 1090; ++i) listB.push_back(incmerkle_mk_entry(i));

    cache.reset();
    EXPECT_FALSE(cache.valid());

    const uint64_t l0 = sml_leaf_hash_count();
    const uint256 rootB_incr = cache.update(listB);
    const uint64_t hashed = sml_leaf_hash_count() - l0;
    const uint256 rootB_naive =
        CSimplifiedMNList(std::vector<CSimplifiedMNListEntry>(listB)).CalcMerkleRoot();

    EXPECT_EQ(rootB_incr.GetHex(), rootB_naive.GetHex());
    EXPECT_EQ(hashed, listB.size()) << "post-reset rebuild re-hashes every leaf";
    EXPECT_NE(rootB_incr.GetHex(), rootA_incr.GetHex());
}

// Fuzz-ish invariant sweep: a long pseudo-random walk of adds / removes /
// value-changes / no-ops, asserting the incremental root byte-matches the
// naive recompute at every one of many steps. This is the reward-safety net —
// if any mutation shape produced a divergent root, one of these steps reds.
TEST(DashReplayFoldIncrementalMerkle, RandomWalkAlwaysMatchesNaive)
{
    IncrementalSmlMerkle cache;
    std::map<uint32_t, CSimplifiedMNListEntry> state;
    uint32_t next_seed = 0;
    for (; next_seed < 128; ++next_seed) state[next_seed] = incmerkle_mk_entry(next_seed);

    // Deterministic LCG — reproducible, no external RNG dependency.
    uint64_t rng = 0xC0FFEEULL;
    auto nextu = [&]() { rng = rng * 6364136223846793005ULL + 1442695040888963407ULL; return rng >> 33; };

    for (int stepno = 0; stepno < 400; ++stepno) {
        const uint32_t op = nextu() % 5;
        if (op == 0) {
            // add
            state[next_seed] = incmerkle_mk_entry(next_seed);
            ++next_seed;
        } else if (op == 1 && state.size() > 8) {
            // remove a pseudo-random existing key
            auto it = state.begin();
            std::advance(it, static_cast<long>(nextu() % state.size()));
            state.erase(it);
        } else if (op == 2 && !state.empty()) {
            // value-change: flip isValid
            auto it = state.begin();
            std::advance(it, static_cast<long>(nextu() % state.size()));
            it->second.isValid = !it->second.isValid;
        } else if (op == 3 && !state.empty()) {
            // value-change: bump confirmedHash
            auto it = state.begin();
            std::advance(it, static_cast<long>(nextu() % state.size()));
            it->second.confirmedHash = incmerkle_protx_of(500000u + stepno);
        }
        // op == 4 (and the guarded fall-throughs): no-op quiet block.

        std::vector<CSimplifiedMNListEntry> v;
        v.reserve(state.size());
        for (const auto& [k, e] : state) { (void)k; v.push_back(e); }

        const uint256 ri = cache.update(v);
        const uint256 rn =
            CSimplifiedMNList(std::vector<CSimplifiedMNListEntry>(v)).CalcMerkleRoot();
        ASSERT_EQ(ri.GetHex(), rn.GetHex())
            << "random-walk divergence at step " << stepno
            << " (op=" << op << ", size=" << state.size() << ")";
    }
}

// task #154 DELTA PATH — the fix for the #1297 wall-clock regression.
//
// The #1297 consolidation kept the LEAF-HASH reduction but paid a FULL per-block
// re-materialise + std::sort + full-set diff + full-cache realloc on EVERY
// block, including the pure-payment-rotation majority that change NOTHING in the
// SML. apply_value_changes() drives the resident sorted cache from the O(k)
// leaves a block actually mutated instead. This KAT proves the two things that
// matter:
//   (a) the delta root is BYTE-IDENTICAL to the naive full recompute (reward-
//       safety — a fast-but-wrong root would serve a forked list); and
//   (b) the delta path EXAMINES only the k changed leaves, where the full path
//       (what shipped) examines all n — the O(n)→O(k) win, measured on the
//       shared sml_leaves_examined_count() seam.
TEST(DashReplayFoldIncrementalMerkle, DeltaPathByteIdenticalAndExaminesOnlyK)
{
    const uint32_t N = 300;
    std::map<uint32_t, CSimplifiedMNListEntry> state;
    for (uint32_t i = 0; i < N; ++i) state[i] = incmerkle_mk_entry(i, true);

    auto entries_of = [&]() {
        std::vector<CSimplifiedMNListEntry> v;
        v.reserve(state.size());
        for (const auto& [k, e] : state) { (void)k; v.push_back(e); }
        return v;
    };

    IncrementalSmlMerkle cache;

    // Cold build via the full path — examines all N once (unavoidable seed cost).
    const uint64_t ex0 = sml_leaves_examined_count();
    cache.update(entries_of());
    EXPECT_EQ(sml_leaves_examined_count() - ex0, static_cast<uint64_t>(N))
        << "cold build examines the whole set once";

    // Mutate three leaves in place — value-only (confirmedHash / isValid), the
    // set unchanged. This is the shape of a real change block.
    state[10].confirmedHash = incmerkle_protx_of(900010);
    state[20].isValid       = false;
    state[30].confirmedHash = incmerkle_protx_of(900030);
    const std::vector<CSimplifiedMNListEntry> changed =
        { state[10], state[20], state[30] };

    // (b) THE FULL PATH — what #1297 shipped — examines the WHOLE set again.
    IncrementalSmlMerkle full_cache;
    full_cache.update(entries_of());                 // its own cold build
    const uint64_t exf0 = sml_leaves_examined_count();
    const uint256 r_full = full_cache.update(entries_of());
    const uint64_t full_examined = sml_leaves_examined_count() - exf0;
    EXPECT_EQ(full_examined, static_cast<uint64_t>(N))
        << "the shipped full path re-examines every leaf every block";

    // (b) THE DELTA PATH examines ONLY the three changed leaves.
    const uint64_t exd0 = sml_leaves_examined_count();
    const std::optional<uint256> r_delta = cache.apply_value_changes(changed);
    const uint64_t delta_examined = sml_leaves_examined_count() - exd0;
    ASSERT_TRUE(r_delta.has_value()) << "a same-set value change must apply";
    EXPECT_EQ(delta_examined, 3u) << "delta examines exactly the k changed leaves";
    EXPECT_LT(delta_examined * 50, full_examined) << "O(k), not O(n)";

    // (a) THE HARD INVARIANT — delta root == naive full recompute == full path.
    const uint256 r_naive = CSimplifiedMNList(entries_of()).CalcMerkleRoot();
    EXPECT_EQ(r_delta->GetHex(), r_naive.GetHex())
        << "delta root diverged from the naive recompute — reward-path hazard";
    EXPECT_EQ(r_full.GetHex(), r_naive.GetHex());

    // FAIL-SAFE: a key not present ⇒ nullopt, so the fold falls back to the full
    // rebuild and the self-check root is never approximate when the SET changed.
    const std::vector<CSimplifiedMNListEntry> absent = { incmerkle_mk_entry(99999) };
    EXPECT_FALSE(cache.apply_value_changes(absent).has_value())
        << "an absent key must bail to the full-rebuild fallback";
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
    ASSERT_TRUE(fx.eng.project_payee(102).has_value())
        << "a payee must be projected (else the test proves nothing)";
    auto pay_blk = make_block(102, fx.eng.block_hash(), fx.payment_root,
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
    ASSERT_TRUE(fx.eng.project_payee(102).has_value());
    auto pay_blk = make_block(102, fx.eng.block_hash(), fx.payment_root,
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
    auto pay_blk = make_block(102, fx.eng.block_hash(), fx.payment_root,
                              /*special_txs=*/{}, /*pay_from=*/&fx.eng);
    auto r = fx.eng.fold_block(pay_blk, 102);
    ASSERT_TRUE(r.ok) << r.error;
    // Below enforcement the check is skipped regardless of whether the coinbase
    // happens to pay the projection; the flag reflects the GATE, not the match.
    EXPECT_TRUE(r.payee_check_preenforcement_skipped);
}

// ════════════════════════════════════════════════════════════════════════
// PoSe PENALTY CERTAINTY BOUNDS (design PR-B §4.2, KAT 13) — the penalty
// oracle. nPoSePenalty is the LOWER bound (the model the ban is decided on),
// nPoSePenaltyHi the UPPER bound; dashd's value sits between them.
// ════════════════════════════════════════════════════════════════════════
namespace pose_bounds_kat {

using dash::coin::replay::PoSeBounds;
using dash::coin::replay::PoSeExactness;
using dash::coin::replay::SeedPenalties;

// A confirmed, valid, regular MN as an anchor seed would carry it.
static ReplayMNState synth_state(uint8_t tag, int32_t lo = 0)
{
    ReplayMNState st;
    st.nVersion       = ProTxVersion::BASIC_BLS;
    st.nType          = MnType::REGULAR;
    st.internalId     = tag;
    st.collateralOutpoint.hash  = raw256(static_cast<uint8_t>(0x40 + tag));
    st.collateralOutpoint.index = 1;
    st.netInfo.ip      = seq_array<16>(static_cast<uint8_t>(0x10 + tag));
    st.netInfo.port_be = 9999;
    st.keyIDOwner      = raw160(static_cast<uint8_t>(0x20 + tag));
    st.pubKeyOperator  = seq_array<48>(static_cast<uint8_t>(0x30 + tag));
    st.keyIDVoting     = raw160(static_cast<uint8_t>(0x50 + tag));
    st.scriptPayout.m_data = script_bytes(static_cast<uint8_t>(0x60 + tag));
    st.nRegisteredHeight = 1;
    st.confirmedHash   = raw256(static_cast<uint8_t>(0x70 + tag));
    st.nPoSePenalty    = lo;
    return st;
}

// Independent hand-build of the DIP-4 entry (never the engine's own output).
static CSimplifiedMNListEntry synth_entry(const uint256& protx,
                                          const ReplayMNState& st, bool valid)
{
    CSimplifiedMNListEntry e;
    e.nVersion       = st.nVersion;
    e.proRegTxHash   = protx;
    e.confirmedHash  = st.confirmedHash;
    e.netAddress     = st.netInfo.ip;
    e.netPort        = st.netInfo.port_be;
    e.pubKeyOperator = st.pubKeyOperator;
    e.keyIDVoting    = st.keyIDVoting;
    e.isValid        = valid;
    e.nType          = st.nType;
    return e;
}

static MutableTransaction punish_qc(const uint256& quorum_hash,
                                    std::vector<bool> valid, uint8_t vin_tag)
{
    CFinalCommitmentTxPayload qc;
    qc.nVersion = 1;
    qc.nHeight  = 0;
    qc.commitment.nVersion   = CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
    qc.commitment.llmqType   = CFinalCommitment::LLMQ_100_67;
    qc.commitment.quorumHash = quorum_hash;
    qc.commitment.signers      = valid;
    qc.commitment.validMembers = valid;
    qc.commitment.quorumPublicKey = seq_array<48>(0xD0);
    qc.commitment.quorumVvecHash  = raw256(0xD1);
    qc.commitment.quorumSig  = seq_array<96>(0xD2);
    qc.commitment.membersSig = seq_array<96>(0xD3);
    return make_special_tx(6, qc, vin_tag);
}

// Three seeded MNs a, b, c (count 3 => CalcMaxPoSePenalty 100, P = 66, seed
// ceiling 200) with a quorum whose members are (a, b, c) in bitset order.
struct BoundsChain
{
    DmlFoldEngine eng{synth_cfg()};
    uint256 a{raw256(0xE1)}, b{raw256(0xE2)}, c{raw256(0xE3)};
    std::map<uint256, ReplayMNState> st;
    uint256  quorum{raw256(0xC0)};
    uint32_t h{100};
    uint256  prev{raw256(9)};
    uint8_t  tag{10};

    explicit BoundsChain(SeedPenalties mode, int32_t lo_a = 0)
    {
        st[a] = synth_state(1, lo_a);
        st[b] = synth_state(2);
        st[c] = synth_state(3);
        eng.seed({{a, st[a]}, {b, st[b]}, {c, st[c]}}, 3, h, prev, "mainnet",
                 mode);
        eng.set_members_fn([this](uint8_t, const uint256& qh)
                               -> std::optional<std::vector<uint256>> {
            if (qh == quorum) return std::vector<uint256>{a, b, c};
            return std::nullopt;
        });
    }

    uint256 root(const std::set<uint256>& banned) const
    {
        std::vector<CSimplifiedMNListEntry> v;
        for (const auto& [p, s] : st) v.push_back(synth_entry(p, s, !banned.count(p)));
        return root_of(std::move(v));
    }

    MutableTransaction qc_marking(const uint256& who)
    {
        return punish_qc(quorum, {who != a, who != b, who != c}, ++tag);
    }

    MutableTransaction proupserv(const uint256& who)
    {
        CProUpServTx up;
        up.nVersion  = ProTxVersion::BASIC_BLS;
        up.proTxHash = who;
        up.netInfo   = st.at(who).netInfo;   // root-neutral service update
        return make_special_tx(2, up, ++tag);
    }

    // Fold the next block; `banned_after` is the set dashd's committed root
    // carries (the answer key the test chooses).
    FoldResult next(std::vector<MutableTransaction> txs,
                    const std::set<uint256>& banned_after = {})
    {
        ++h;
        auto blk = make_block(h, prev, root(banned_after), std::move(txs), &eng);
        auto r = eng.fold_block(blk, h);
        if (r.ok) prev = DmlFoldEngine::block_header_hash(blk);
        return r;
    }

    PoSeBounds bounds(const uint256& p) const { return *eng.pose_bounds(p); }
};

} // namespace pose_bounds_kat

using namespace pose_bounds_kat;

// Seed without penalties: lo = 0 (the placeholder), hi = the ceiling
// 2 x CalcMaxPoSePenalty. Seed WITH dashd's penalties: hi = lo. The caller's
// own nPoSePenaltyHi is ignored either way. Mutation "seed hi=0" reds here.
TEST(DashPoSeBounds, UnknownSeedWidensHiExactSeedKeepsItTight)
{
    {
        BoundsChain ch(SeedPenalties::Unknown, /*lo_a=*/7);
        EXPECT_EQ(ch.eng.calc_max_pose_penalty(), 100);
        EXPECT_EQ(ch.eng.seed_penalty_ceiling(), 200);
        EXPECT_EQ(ch.bounds(ch.a).lo, 7);
        EXPECT_EQ(ch.bounds(ch.a).hi, 200);
        EXPECT_EQ(ch.bounds(ch.b).lo, 0);
        EXPECT_EQ(ch.bounds(ch.b).hi, 200);
        const PoSeExactness x = ch.eng.pose_exactness();
        EXPECT_EQ(x.valid_exact, 0u);
        EXPECT_EQ(x.valid_inexact, 3u);
        EXPECT_EQ(x.max_gap, 200);
    }
    {
        BoundsChain ch(SeedPenalties::Exact, /*lo_a=*/7);
        EXPECT_EQ(ch.bounds(ch.a).lo, 7);
        EXPECT_EQ(ch.bounds(ch.a).hi, 7);
        EXPECT_EQ(ch.bounds(ch.b).hi, 0);
        EXPECT_EQ(ch.eng.pose_exactness().valid_exact, 3u);
    }
    {
        // Default is Unknown, and a stray caller-side hi never survives.
        DmlFoldEngine eng(synth_cfg());
        auto s = synth_state(1, 0);
        s.nPoSePenaltyHi = 3;
        eng.seed({{raw256(0xE1), s}}, 1, 100, raw256(9));
        EXPECT_EQ(eng.find(raw256(0xE1))->nPoSePenaltyHi, 200);
    }
}

// Convergence: with no punish after the seed, hi decays one per block and the
// bound is exact (0) after exactly `ceiling` blocks.
TEST(DashPoSeBounds, BoundsConvergeOverACleanRun)
{
    BoundsChain ch(SeedPenalties::Unknown);
    for (int k = 1; k <= 200; ++k) {
        auto r = ch.next({});
        ASSERT_TRUE(r.ok) << "k=" << k << " " << r.error;
        EXPECT_EQ(ch.bounds(ch.a).hi, 200 - k);
        EXPECT_EQ(ch.bounds(ch.a).lo, 0);
        if (k == 199) EXPECT_EQ(ch.eng.pose_exactness().valid_inexact, 3u);
    }
    const PoSeExactness x = ch.eng.pose_exactness();
    EXPECT_EQ(x.valid_exact, 3u);
    EXPECT_EQ(x.valid_inexact, 0u);
    EXPECT_EQ(x.max_gap, 0);
}

// A punish moves BOTH bounds (decay first, then +P, clamp at max); the ban is
// decided on lo only. dashd's hidden value 0 => no ban at the first punish,
// the root is unchanged and nothing needs resolving; the second punish takes
// lo to max and the model bans.
TEST(DashPoSeBounds, PunishMovesBothBoundsAndTheBanStaysOnLo)
{
    BoundsChain ch(SeedPenalties::Unknown);
    auto r = ch.next({ch.qc_marking(ch.a)});
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.punished, 1u);
    EXPECT_EQ(r.banned, 0u);
    EXPECT_EQ(r.root_resolved_bans + r.root_resolved_nobans, 0u);
    EXPECT_EQ(ch.bounds(ch.a).lo, 66);          // 0 -> decay 0 -> +66
    EXPECT_EQ(ch.bounds(ch.a).hi, 100);         // 200 -> 199 -> +66 -> clamp 100
    EXPECT_FALSE(ch.bounds(ch.a).banned);
    EXPECT_EQ(ch.bounds(ch.b).hi, 199);         // decay only

    r = ch.next({ch.qc_marking(ch.a)}, {ch.a});
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.banned, 1u);
    EXPECT_EQ(ch.bounds(ch.a).lo, 100);         // 65 + 66 -> clamp 100 = max
    EXPECT_EQ(ch.bounds(ch.a).hi, 100);         // 99 + 66 -> clamp 100
    EXPECT_TRUE(ch.bounds(ch.a).banned);
    EXPECT_EQ(ch.eng.find(ch.a)->nPoSeBanHeight, 102);
}

// The ambiguous band (lo < max <= hi): dashd MAY have banned. The committed
// root decides — exactly one candidate subset reproduces it, and it is
// adopted (banned, penalty = max exactly). With the resolver removed this
// block poisons (the pre-bounds behaviour on an unknown-penalty seed).
TEST(DashPoSeBounds, AmbiguousPunishIsResolvedFromTheCommittedRoot)
{
    {
        BoundsChain ch(SeedPenalties::Unknown);
        auto r = ch.next({ch.qc_marking(ch.a)}, /*dashd banned=*/{ch.a});
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.root_resolved_bans, 1u);
        EXPECT_EQ(r.banned, 1u);
        EXPECT_EQ(r.computed_root, r.committed_root);
        EXPECT_TRUE(ch.bounds(ch.a).banned);
        EXPECT_EQ(ch.bounds(ch.a).lo, 100);
        EXPECT_EQ(ch.bounds(ch.a).hi, 100);
        EXPECT_EQ(ch.eng.find(ch.a)->nPoSeBanHeight, 101);
        // and the fold keeps going on the adopted state
        auto r2 = ch.next({}, {ch.a});
        ASSERT_TRUE(r2.ok) << r2.error;
    }
    {
        // A divergence the PoSe ambiguity cannot explain (b banned, b was
        // never punished) still poisons, exactly as before.
        BoundsChain ch(SeedPenalties::Unknown);
        auto r = ch.next({ch.qc_marking(ch.a)}, {ch.b});
        ASSERT_FALSE(r.ok);
        EXPECT_NE(r.error.find("ROOT MISMATCH"), std::string::npos) << r.error;
        EXPECT_TRUE(ch.eng.poisoned());
    }
    {
        // An EXACT seed never enters the band: lo = hi = 66 < 100, so a root
        // showing `a` banned is a genuine divergence and poisons.
        BoundsChain ch(SeedPenalties::Exact);
        auto r = ch.next({ch.qc_marking(ch.a)}, {ch.a});
        ASSERT_FALSE(r.ok);
        EXPECT_TRUE(ch.eng.poisoned());
    }
}

// Same block: ambiguous punish of `a`, then a ProUpServTx for `a`. dashd may
// have banned and then revived it (penalty 0) — indistinguishable by the root
// — so the lower bound must drop to 0. Before the punish, or after an exact
// (non-ambiguous) punish, the ProUpServTx leaves the bounds alone.
TEST(DashPoSeBounds, ProUpServAfterAmbiguousPunishWidensTheLowerBound)
{
    {
        BoundsChain ch(SeedPenalties::Unknown);
        auto r = ch.next({ch.qc_marking(ch.a), ch.proupserv(ch.a)});
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(ch.bounds(ch.a).lo, 0);
        EXPECT_EQ(ch.bounds(ch.a).hi, 100);
        EXPECT_FALSE(ch.bounds(ch.a).banned);
    }
    {
        BoundsChain ch(SeedPenalties::Unknown);
        auto r = ch.next({ch.proupserv(ch.a), ch.qc_marking(ch.a)});
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(ch.bounds(ch.a).lo, 66);
        EXPECT_EQ(ch.bounds(ch.a).hi, 100);
    }
    {
        BoundsChain ch(SeedPenalties::Exact);
        auto r = ch.next({ch.qc_marking(ch.a), ch.proupserv(ch.a)});
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(ch.bounds(ch.a).lo, 66);
        EXPECT_EQ(ch.bounds(ch.a).hi, 66);
    }
}

// The oracle accessor answers ONLY for the post-state of the exact block the
// engine stands on, never when poisoned, never for an MN it does not hold.
TEST(DashPoSeBounds, OracleAccessorAnswersOnlyAtItsOwnTip)
{
    BoundsChain ch(SeedPenalties::Unknown);
    ASSERT_TRUE(ch.eng.pose_bounds_at(100, raw256(9), ch.a).has_value());
    EXPECT_FALSE(ch.eng.pose_bounds_at(101, raw256(9), ch.a).has_value());
    EXPECT_FALSE(ch.eng.pose_bounds_at(100, raw256(8), ch.a).has_value());
    EXPECT_FALSE(ch.eng.pose_bounds_at(100, raw256(9), raw256(0xEE)).has_value());

    ASSERT_TRUE(ch.next({ch.qc_marking(ch.a)}).ok);
    auto v = ch.eng.pose_bounds_at(101, ch.prev, ch.a);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->lo, 66);
    EXPECT_EQ(v->hi, 100);
    EXPECT_FALSE(ch.eng.pose_bounds_at(100, raw256(9), ch.a).has_value());

    const uint256 tip = ch.prev;
    ASSERT_FALSE(ch.next({}, {ch.c}).ok);        // poisons at 102
    EXPECT_FALSE(ch.eng.pose_bounds_at(101, tip, ch.a).has_value());
}

// v4 round trip carries both bounds and is byte-stable.
TEST(DashPoSeBounds, SnapshotV4RoundTripCarriesTheBounds)
{
    BoundsChain ch(SeedPenalties::Unknown);
    ASSERT_TRUE(ch.next({ch.qc_marking(ch.a)}).ok);
    const auto bytes = ch.eng.save_snapshot();
    ASSERT_EQ(std::memcmp(bytes.data(), "C2POOL-DASH-DML-SNAP/v04", 24), 0);

    DmlFoldEngine e2(synth_cfg());
    std::string err;
    ASSERT_TRUE(e2.load_snapshot(bytes, err)) << err;
    EXPECT_EQ(e2.loaded_snapshot_version(), 4u);
    for (const auto& p : {ch.a, ch.b, ch.c}) {
        EXPECT_EQ(e2.find(p)->nPoSePenalty, ch.eng.find(p)->nPoSePenalty);
        EXPECT_EQ(e2.find(p)->nPoSePenaltyHi, ch.eng.find(p)->nPoSePenaltyHi);
    }
    EXPECT_EQ(e2.find(ch.a)->nPoSePenaltyHi, 100);
    EXPECT_EQ(e2.find(ch.b)->nPoSePenaltyHi, 199);
    EXPECT_EQ(e2.save_snapshot(), bytes);
    EXPECT_TRUE(e2.at_block(101, ch.prev));
}

// A v3 file (no bound on disk) still loads, with hi widened to the ceiling —
// the same reading as an Unknown-penalty seed. Magic/version must agree.
TEST(DashPoSeBounds, SnapshotV3LoadsWithTheUpperBoundAtTheCeiling)
{
    auto v3_bytes = [](const char* magic, uint32_t version,
                       const std::vector<std::pair<uint256, ReplayMNState>>& es) {
        ::PackStream s;
        s.write(std::as_bytes(std::span<const char>(magic, 24)));
        s << version;
        s << std::string("mainnet");
        s << uint32_t{100};
        s << raw256(9);
        s << uint64_t{es.size()};
        s << uint64_t{es.size()};
        for (const auto& [p, st] : es) { s << p; s << st; }
        auto sp = s.get_span();
        uint256 d;
        CHash256()
            .Write(std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
            .Finalize(std::span<unsigned char>(d.data(), 32));
        s << d;
        auto full = s.get_span();
        return std::vector<uint8_t>(
            reinterpret_cast<const uint8_t*>(full.data()),
            reinterpret_cast<const uint8_t*>(full.data()) + full.size());
    };
    const std::vector<std::pair<uint256, ReplayMNState>> es = {
        {raw256(0xE1), synth_state(1, 0)},
        {raw256(0xE2), synth_state(2, 150)},
        {raw256(0xE3), synth_state(3, 0)}};

    DmlFoldEngine e(synth_cfg());
    std::string err;
    ASSERT_TRUE(e.load_snapshot(v3_bytes("C2POOL-DASH-DML-SNAP/v03", 3, es), err))
        << err;
    EXPECT_EQ(e.loaded_snapshot_version(), 3u);
    EXPECT_EQ(e.find(raw256(0xE1))->nPoSePenalty, 0);
    EXPECT_EQ(e.find(raw256(0xE1))->nPoSePenaltyHi, 200);
    EXPECT_EQ(e.find(raw256(0xE2))->nPoSePenalty, 150);
    EXPECT_EQ(e.find(raw256(0xE2))->nPoSePenaltyHi, 200);
    // Re-saved as v4.
    EXPECT_EQ(std::memcmp(e.save_snapshot().data(), "C2POOL-DASH-DML-SNAP/v04", 24), 0);

    DmlFoldEngine e2(synth_cfg());
    EXPECT_FALSE(e2.load_snapshot(v3_bytes("C2POOL-DASH-DML-SNAP/v03", 4, es), err));
    EXPECT_FALSE(e2.load_snapshot(v3_bytes("C2POOL-DASH-DML-SNAP/v04", 3, es), err));
    EXPECT_EQ(e2.size(), 0u);
}

// REAL CHAIN BYTES, h=2516412 (the case-D event): what an anchor seeded from
// an SML (no penalties) sees. Every MN starts at [0, 2 x 2972]; dashd's own
// pre-state value is inside the interval for all 2972. The block punishes
// two MNs into the ambiguous band; the committed root proves one ban
// (1e5112a9…, dashd 1937 -> clamp 2972) and one non-ban (104b336e…, dashd
// 0 -> 1961), and after the fold every MN's dashd value (the exact-seeded
// engine) is still bracketed. The exact seed stays exact throughout.
TEST(DashPoSeBoundsReal, UnknownSeedBracketsDashdAndTheRootResolvesCaseD2516412)
{
    auto fx = parse_prestate(kDashReplayPrestate2516411);
    auto qf = parse_quorum(kDashReplayQuorum2516412);
    const uint256 quorum_hash = from_display(qf.quorum_hash_display.c_str());
    auto members = [&](uint8_t t, const uint256& qh)
        -> std::optional<std::vector<uint256>> {
        if (t == qf.llmq_type && qh == quorum_hash) return qf.members;
        return std::nullopt;
    };
    uint256 anchor_hash;
    anchor_hash.SetHex(fx.blockhash_display);

    FoldConfig cfg;
    cfg.enabled = true;
    DmlFoldEngine truth(cfg);   // dashd's penalties (protx list): EXACT
    {
        auto es = fx.entries;
        truth.seed(std::move(es), fx.entries.size(), fx.height, anchor_hash,
                   fx.network, SeedPenalties::Exact);
    }
    DmlFoldEngine blind(cfg);   // an SML anchor: penalties unknown
    {
        auto es = fx.entries;
        for (auto& [p, st] : es) st.nPoSePenalty = 0;
        blind.seed(std::move(es), fx.entries.size(), fx.height, anchor_hash,
                   fx.network, SeedPenalties::Unknown);
    }
    EXPECT_EQ(blind.compute_sml_root().GetHex(), kRoot2516411);
    EXPECT_EQ(blind.seed_penalty_ceiling(), 2 * 2972);
    for (const auto& [p, st] : truth.entries()) {
        const auto* bs = blind.find(p);
        ASSERT_NE(bs, nullptr);
        EXPECT_LE(bs->nPoSePenalty, st.nPoSePenalty);
        EXPECT_GE(bs->nPoSePenaltyHi, st.nPoSePenalty);
    }
    EXPECT_EQ(truth.pose_exactness().valid_inexact, 0u);

    truth.set_members_fn(members);
    blind.set_members_fn(members);
    const auto blk = parse_block(kDashReplayBlock2516412);
    auto rt = truth.fold_block(blk, 2516412);
    ASSERT_TRUE(rt.ok) << rt.error;
    EXPECT_EQ(rt.root_resolved_bans, 0u);         // exact: the model banned it
    auto rb = blind.fold_block(blk, 2516412);
    ASSERT_TRUE(rb.ok) << rb.error;
    EXPECT_EQ(rb.computed_root.GetHex(), kRoot2516412);
    EXPECT_EQ(rb.root_resolved_bans, 1u);
    EXPECT_EQ(rb.root_resolved_nobans, 1u);

    const uint256 to_ban   = from_display(kBannedMN);
    const uint256 punished = from_display(kPunishedMN);
    EXPECT_TRUE(blind.find(to_ban)->IsBanned());
    EXPECT_EQ(blind.find(to_ban)->nPoSeBanHeight, 2516412);
    EXPECT_EQ(blind.find(to_ban)->nPoSePenalty, 2972);
    EXPECT_EQ(blind.find(to_ban)->nPoSePenaltyHi, 2972);
    EXPECT_EQ(blind.find(punished)->nPoSePenalty, 1961);
    EXPECT_EQ(blind.find(punished)->nPoSePenaltyHi, 2971);   // proven < max

    for (const auto& [p, st] : truth.entries()) {
        const auto* bs = blind.find(p);
        ASSERT_NE(bs, nullptr);
        EXPECT_EQ(bs->IsBanned(), st.IsBanned());
        EXPECT_LE(bs->nPoSePenalty, st.nPoSePenalty) << p.GetHex();
        EXPECT_GE(bs->nPoSePenaltyHi, st.nPoSePenalty) << p.GetHex();
        EXPECT_EQ(st.nPoSePenalty, st.nPoSePenaltyHi) << "exact seed drifted";
    }
}
