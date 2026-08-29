// SPDX-License-Identifier: AGPL-3.0-or-later
/// OPTIONAL, DEFAULT-OFF V20 getmnlistdiff SEED for the replay fold
/// (mnlist_seed.hpp) — the path-ii escape hatch for #154's pre-V20
/// rotated-quorum derivation.
///
/// WHAT THIS KAT PROVES (and, honestly, what it does not)
/// ------------------------------------------------------
/// PROVEN HERE, STRUCTURALLY (no dashd, no network, self-contained):
///   (a) FLAGS-ABSENT == from-DIP3 path unchanged. A default-constructed
///       arming request is inert — mnlist_seed_armed() is false — so the seed
///       arm is never entered and the from-DIP3 default is untouched. (The
///       whole-binary proof of "byte-identical to master" is the guarded,
///       purely-additive diff; this asserts the arm's gate at unit level.)
///   (b) FLAGS-PRESENT: a valid getmnlistdiff seed LOADS, VERIFIES against the
///       committed merkleRootMNList at the seed height, and leaves the engine
///       fold-ready at H (so the next block it accepts is H+1). The committed
///       root is the engine's OWN computed root over an independently built SML
///       set, round-tripped through the shared prestate parser.
///   (c) A seed whose committed root != the state's computed root FAILS CLOSED
///       at seed_engine_from_prestate() — the reward-safety gate. Plus the
///       escape-hatch policy gates: source must be "getmnlistdiff", height is
///       required and must be >= the V20 floor, a file is required, and the
///       declared height and network must match the snapshot.
///
/// NOT PROVEN HERE (sequenced later on the operator's call, #154):
///   * That a LIVE dashd getmnlistdiff at mainnet h=1'987'776 reproduces
///     mainnet's real committed root, and that folding V20->2522504 stays
///     byte-exact. That is the live validation leg; this KAT proves the GATE
///     MECHANICS (compute-vs-committed, fail-closed, V20-floor, height/network
///     match), which is what makes the live leg safe to run.
///
/// The committed root here is SELF-CONSISTENT (the engine's own compute over
/// hand-built entries), never a memorized mainnet constant — so a bug in
/// CalcMerkleRoot could not make this KAT falsely green on the happy path; the
/// mismatch case flips exactly one nibble of the committed root and REQUIRES
/// the gate to red the seed.

#include <gtest/gtest.h>

#include <impl/dash/coin/mnlist_seed.hpp>
#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/replay_prestate.hpp>
#include <impl/dash/coin/vendor/quorum_members.hpp>

#include <core/uint256.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace rp = dash::coin::replay;

namespace {

// ── wire-hex of raw internal bytes (the convention the prestate parser reads
//    for every per-mn hash field: memcpy'd, NOT display-reversed). ──────────
template <class Blob>
std::string wire_hex(const Blob& b)
{
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (size_t i = 0; i < b.size(); ++i) {
        const uint8_t v = static_cast<uint8_t>(b.data()[i]);
        s.push_back(k[v >> 4]);
        s.push_back(k[v & 0xF]);
    }
    return s;
}

std::string bytes_hex(const std::vector<uint8_t>& v)
{
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (uint8_t b : v) { s.push_back(k[b >> 4]); s.push_back(k[b & 0xF]); }
    return s;
}

// A deterministic 32-byte blob from a seed byte (fills all 32 bytes so the
// value is non-trivial and unique per mn).
uint256 mk_u256(uint8_t seed)
{
    uint256 u;
    for (int i = 0; i < 32; ++i) u.data()[i] = static_cast<uint8_t>(seed + i);
    return u;
}
uint160 mk_u160(uint8_t seed)
{
    uint160 u;
    for (int i = 0; i < 20; ++i) u.data()[i] = static_cast<uint8_t>(seed + i * 3);
    return u;
}

// Build a small, independently-specified masternode set. The SML-bearing
// fields (proTxHash, confirmedHash, service, keyIDVoting, isValid via
// NEVER-ban, nType, nVersion, platform*) are what merkleRootMNList commits;
// scriptPayout is set only because the prestate parser requires it (it is NOT
// in the SML leaf).
std::vector<std::pair<uint256, rp::ReplayMNState>> build_set()
{
    std::vector<std::pair<uint256, rp::ReplayMNState>> out;
    for (uint8_t i = 1; i <= 5; ++i) {
        uint256 protx = mk_u256(static_cast<uint8_t>(0x10 * i));
        rp::ReplayMNState st;
        st.UpdateConfirmedHash(protx, mk_u256(static_cast<uint8_t>(0x20 + i)));
        for (int b = 0; b < 16; ++b)
            st.netInfo.ip.data()[b] = static_cast<uint8_t>(i * 7 + b);
        st.netInfo.port_be = static_cast<uint16_t>(9999 + i);
        st.keyIDVoting = mk_u160(static_cast<uint8_t>(0x30 + i));
        st.keyIDOwner  = mk_u160(static_cast<uint8_t>(0x40 + i));
        // A minimal well-formed P2PKH payout (25 bytes) — required by the
        // parser, irrelevant to merkleRootMNList.
        std::vector<uint8_t> spk = {0x76, 0xa9, 0x14};
        for (int b = 0; b < 20; ++b) spk.push_back(static_cast<uint8_t>(i + b));
        spk.push_back(0x88); spk.push_back(0xac);
        st.scriptPayout.m_data.assign(spk.begin(), spk.end());
        st.nRegisteredHeight   = 1'900'000 + i;
        st.nLastPaidHeight     = 2'000'000 + i;
        st.nPoSeBanHeight      = rp::ReplayMNState::NEVER;   // isValid == true
        st.nPoSeRevivedHeight  = rp::ReplayMNState::NEVER;
        st.collateralOutpoint.hash  = mk_u256(static_cast<uint8_t>(0x50 + i));
        st.collateralOutpoint.index = i;
        st.internalId               = 500 + i;
        out.emplace_back(protx, std::move(st));
    }
    return out;
}

// Serialize a set into the SHARED prestate text format
// (c2pool-dash-replay-prestate/1) that mnlist_seed reuses — the SAME 26 fields
// in the SAME order the fail-closed parser reads. `mnroot_display` is written
// as-given so a test can inject a WRONG root and prove the gate reds.
std::string serialize_seed(const std::vector<std::pair<uint256, rp::ReplayMNState>>& set,
                           const std::string& network,
                           uint32_t height,
                           const std::string& blockhash_display,
                           const std::string& mnroot_display)
{
    std::ostringstream os;
    os << rp::kPrestateMagic << "\n";
    os << "network " << network << "\n";
    os << "height " << height << "\n";
    os << "blockhash " << blockhash_display << "\n";
    os << "mnroot " << mnroot_display << "\n";
    os << "count " << set.size() << "\n";
    for (const auto& [protx, st] : set) {
        os << "mn "
           << wire_hex(protx) << " "
           << wire_hex(st.confirmedHash) << " "
           << wire_hex(st.netInfo.ip) << " "
           << st.netInfo.port_be << " "
           << "- "                                   // pubKeyOperator (null)
           << wire_hex(st.keyIDVoting) << " "
           << wire_hex(st.keyIDOwner) << " "
           << st.nVersion << " "
           << st.nType << " "
           << "- "                                   // platformNodeID
           << st.platformP2PPort << " "
           << st.platformHTTPPort << " "
           << st.nOperatorReward << " "
           << bytes_hex(std::vector<uint8_t>(st.scriptPayout.m_data.begin(),
                                             st.scriptPayout.m_data.end())) << " "
           << "- "                                   // scriptOperatorPayout
           << st.nRegisteredHeight << " "
           << st.nLastPaidHeight << " "
           << st.nConsecutivePayments << " "
           << st.nPoSePenalty << " "
           << st.nPoSeBanHeight << " "
           << st.nPoSeRevivedHeight << " "
           << st.nRevocationReason << " "
           << wire_hex(st.collateralOutpoint.hash) << " "
           << st.collateralOutpoint.index << " "
           << st.internalId << "\n";
    }
    return os.str();
}

// The committed root of a set == the engine's own compute over it, seeded at
// `height`. This is what a real getmnlistdiff at `height` would have to
// reproduce; we mint it locally so the KAT is self-contained.
uint256 root_of(const std::vector<std::pair<uint256, rp::ReplayMNState>>& set,
                uint32_t height)
{
    rp::FoldConfig cfg; cfg.enabled = true;
    rp::DmlFoldEngine eng(cfg);
    auto copy = set;
    eng.seed(std::move(copy), set.size(), height, mk_u256(0xAA), "mainnet");
    return eng.compute_sml_root();
}

std::string write_temp(const std::string& body, const std::string& tag)
{
    const auto p = std::filesystem::temp_directory_path()
                 / ("c2pool_mnseed_kat_" + tag + "_"
                    + std::to_string(::getpid()) + ".txt");
    std::ofstream(p, std::ios::binary) << body;
    return p.string();
}

constexpr uint32_t kV20 = dash::coin::vendor::kV20FloorMainnet; // 1'987'776

} // namespace

// ── (a) FLAGS-ABSENT — the arm is inert, from-DIP3 default is unchanged ─────
TEST(DashMnListSeed, DisarmedByDefault_FromDip3Unchanged)
{
    rp::MnListSeedRequest req;                       // all defaults
    EXPECT_FALSE(rp::mnlist_seed_armed(req));
    // Touching ANY single flag arms it (and only then is the seed arm entered).
    rp::MnListSeedRequest h; h.seed_height = kV20;
    EXPECT_TRUE(rp::mnlist_seed_armed(h));
    rp::MnListSeedRequest s; s.source = rp::kMnListSeedSourceGetMnListDiff;
    EXPECT_TRUE(rp::mnlist_seed_armed(s));
    rp::MnListSeedRequest f; f.file = "/x";
    EXPECT_TRUE(rp::mnlist_seed_armed(f));
}

// ── (c) POLICY GATE: unknown/blank source is never guessed ──────────────────
TEST(DashMnListSeed, SourceGateRejectsUnknown)
{
    rp::MnListSeedRequest req;
    req.seed_height = kV20; req.source = "rpc"; req.file = "/whatever";
    const auto ps = rp::load_and_validate_mnlist_seed(req);
    EXPECT_FALSE(ps.ok);
    EXPECT_NE(ps.error.find("getmnlistdiff"), std::string::npos);
}

// ── (c) POLICY GATE: height is required ─────────────────────────────────────
TEST(DashMnListSeed, HeightRequired)
{
    rp::MnListSeedRequest req;
    req.source = rp::kMnListSeedSourceGetMnListDiff; req.file = "/whatever";
    const auto ps = rp::load_and_validate_mnlist_seed(req);
    EXPECT_FALSE(ps.ok);
    EXPECT_NE(ps.error.find("height"), std::string::npos);
}

// ── (c) THE ESCAPE-HATCH GATE: below the V20 floor is rejected ──────────────
TEST(DashMnListSeed, V20FloorRejectsPreV20SeedHeight)
{
    rp::MnListSeedRequest req;
    req.source = rp::kMnListSeedSourceGetMnListDiff;
    req.seed_height = 1'028'160;                            // DIP3 height, < V20
    req.file = "/whatever";
    const auto ps = rp::load_and_validate_mnlist_seed(req);
    EXPECT_FALSE(ps.ok);
    EXPECT_NE(ps.error.find("V20"), std::string::npos);
}

// ── (c) POLICY GATE: a file (offline snapshot) is required for now ──────────
TEST(DashMnListSeed, FileRequired)
{
    rp::MnListSeedRequest req;
    req.source = rp::kMnListSeedSourceGetMnListDiff; req.seed_height = kV20;
    const auto ps = rp::load_and_validate_mnlist_seed(req);
    EXPECT_FALSE(ps.ok);
    EXPECT_NE(ps.error.find("file"), std::string::npos);
}

// ── (b) HAPPY PATH: seed loads, verifies against the committed root, and is
//        left fold-ready at H (next accepted block is H+1). ──────────────────
TEST(DashMnListSeed, SeedLoadsVerifiesAndIsFoldReady)
{
    const uint32_t H = kV20 + 10;                    // >= V20 floor
    auto set = build_set();
    const uint256 root = root_of(set, H);
    const std::string body = serialize_seed(set, "mainnet", H,
                                            mk_u256(0xAA).GetHex(), root.GetHex());
    const std::string path = write_temp(body, "ok");

    rp::MnListSeedRequest req;
    req.source = rp::kMnListSeedSourceGetMnListDiff;
    req.seed_height = H; req.file = path; req.testnet = false;

    const auto ps = rp::load_and_validate_mnlist_seed(req);
    ASSERT_TRUE(ps.ok) << ps.error;
    EXPECT_EQ(ps.height, H);
    EXPECT_EQ(ps.entries.size(), set.size());

    // THE REWARD-SAFETY GATE (reused verbatim from the prestate arm): seed +
    // re-verify the committed merkleRootMNList before any forward fold.
    rp::FoldConfig cfg; cfg.enabled = true;
    rp::DmlFoldEngine eng(cfg);
    const std::string serr = rp::seed_engine_from_prestate(eng, ps);
    EXPECT_TRUE(serr.empty()) << serr;
    EXPECT_EQ(eng.compute_sml_root().GetHex(), root.GetHex());
    EXPECT_EQ(eng.height(), H);                       // fold-forward-ready: next is H+1
    EXPECT_EQ(eng.size(), set.size());

    std::filesystem::remove(path);
}

// ── (c) REWARD-SAFETY: a seed whose committed root != computed FAILS CLOSED ──
TEST(DashMnListSeed, MismatchedCommittedRootFailsClosed)
{
    const uint32_t H = kV20 + 10;
    auto set = build_set();
    const uint256 root = root_of(set, H);

    // Flip one nibble of the committed root — the state is byte-identical, only
    // the CLAIMED root diverges. The gate must red.
    std::string wrong = root.GetHex();
    wrong[0] = (wrong[0] == '0') ? '1' : '0';
    ASSERT_NE(wrong, root.GetHex());

    const std::string body = serialize_seed(set, "mainnet", H,
                                            mk_u256(0xAA).GetHex(), wrong);
    const std::string path = write_temp(body, "bad");

    rp::MnListSeedRequest req;
    req.source = rp::kMnListSeedSourceGetMnListDiff;
    req.seed_height = H; req.file = path;

    // Parsing + policy still pass (the text is well-formed) ...
    const auto ps = rp::load_and_validate_mnlist_seed(req);
    ASSERT_TRUE(ps.ok) << ps.error;

    // ... but the root gate REJECTS the seed — it is a guess, not an anchor.
    rp::FoldConfig cfg; cfg.enabled = true;
    rp::DmlFoldEngine eng(cfg);
    const std::string serr = rp::seed_engine_from_prestate(eng, ps);
    EXPECT_FALSE(serr.empty());
    EXPECT_NE(serr.find("ANCHOR SEED REJECTED"), std::string::npos);

    std::filesystem::remove(path);
}

// ── (c) POLICY GATE: declared height must match the snapshot's height ───────
TEST(DashMnListSeed, HeightMismatchFailsClosed)
{
    const uint32_t Hfile = kV20 + 10;
    auto set = build_set();
    const uint256 root = root_of(set, Hfile);
    const std::string body = serialize_seed(set, "mainnet", Hfile,
                                            mk_u256(0xAA).GetHex(), root.GetHex());
    const std::string path = write_temp(body, "hmm");

    rp::MnListSeedRequest req;
    req.source = rp::kMnListSeedSourceGetMnListDiff;
    req.seed_height = Hfile + 1;                      // operator asked a DIFFERENT height
    req.file = path;

    const auto ps = rp::load_and_validate_mnlist_seed(req);
    EXPECT_FALSE(ps.ok);
    EXPECT_NE(ps.error.find("does not match"), std::string::npos);

    std::filesystem::remove(path);
}

// ── (c) POLICY GATE: network of the snapshot must match the run ─────────────
TEST(DashMnListSeed, NetworkMismatchFailsClosed)
{
    const uint32_t H = kV20 + 10;
    auto set = build_set();
    const uint256 root = root_of(set, H);
    const std::string body = serialize_seed(set, "testnet", H,
                                            mk_u256(0xAA).GetHex(), root.GetHex());
    const std::string path = write_temp(body, "net");

    rp::MnListSeedRequest req;                        // testnet=false (mainnet run)
    req.source = rp::kMnListSeedSourceGetMnListDiff;
    req.seed_height = H; req.file = path;

    const auto ps = rp::load_and_validate_mnlist_seed(req);
    EXPECT_FALSE(ps.ok);
    EXPECT_NE(ps.error.find("network"), std::string::npos);

    std::filesystem::remove(path);
}
