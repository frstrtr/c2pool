// SPDX-License-Identifier: MIT
//
// DASH S8 stratum job-notify round-trip contract KAT.
//
// Pins the second half of the get_work() -> stratum wire contract: the
// mining.notify merkle_branch. #630 (test_dash_stratum_binding) proved the
// extranonce2 (nonce64) coinbase-slot geometry; this leaf proves that the
// merkle_branch our server ships in mining.notify, when a miner folds its
// extranonce2-substituted coinbase through it (leaf index 0), reproduces the
// EXACT header merkle_root -- closing the loop:
//
//     get_work() --> [coinb1][extranonce2 slot][coinb2] + merkle_branch
//                 --> miner substitutes extranonce2, hashes coinbase
//                 --> folds branch (index 0) --> header merkle_root
//
// Oracle (frstrtr/p2pool-dash @9a0a609):
//   p2pool/work.py:474   header['merkle_root'] == check_merkle_link(
//                            hash256(new_packed_gentx), merkle_link)
//   p2pool/work.py:493   merkle_link = calculate_merkle_link(hashes, index)
//   p2pool/dash/data.py:189 calculate_merkle_link  (branch producer, index 0)
//   p2pool/dash/data.py:216 check_merkle_link       (miner-side fold)
//   p2pool/dash/data.py:180 merkle_hash             (full-tree root)
//
// merkle_record_type.pack(left,right) == left||right (32B internal LE each);
// hash256 == sha256d. For coinbase leaf index 0, every fold step places the
// running hash on the LEFT: cur = sha256d(cur || sibling).
//
// This binds the REAL landed producer dash::coinbase::merkle_branches_raw()
// (src/impl/dash/coinbase_builder.hpp) -- the exact code mining.notify uses.
// The miner-side fold + full-tree root are mirrored locally (the miner is
// cpuminer, not our code) and cross-checked THREE ways: (a) real branch folds
// to the locally-recomputed full root, (b) both equal externally-computed
// golden sha256d anchors (independent Python hashlib, NOT the oracle code),
// (c) round-trip is exercised across distinct extranonce2 values so the #630
// slot demonstrably propagates into the block-header merkle_root.
//
// Fenced: test/ + build.yml allowlist only. Non-consensus, socket-free,
// node-free -- pure synthetic CoinbaseLayout, no live node / RPC / P2P.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstring>
#include <map>
#include <span>
#include <string>
#include <vector>

#include <impl/dash/coinbase_builder.hpp>  // merkle_branches_raw, sha256d, EXTRANONCE2_SIZE
#include <impl/dash/stratum/tip_refresh.hpp>   // fire_share_tip_refresh (tip-change fan-out)
#include <impl/dash/local_mint_ledger.hpp>     // LocalMintLedger / classify_local_mint
#include <btclibs/util/strencodings.h>     // HexStr
#include <core/uint256.hpp>

using dash::coinbase::merkle_branches_raw;
using dash::coinbase::sha256d;
using dash::coinbase::EXTRANONCE2_SIZE;

namespace {

// ── Synthetic fixtures ───────────────────────────────────────────────────────
// Same 40-byte coinbase as #630: bytes[i] = i, with the 8-byte nonce64 slot at
// [28,36) zeroed (nonce64_offset = 40 - locktime(4) - nonce64(8) = 28).
constexpr size_t kNonceOffset = 28;

// Build the coinbase bytes with `e2` (8 bytes) substituted into the nonce64 slot.
std::vector<unsigned char> build_coinbase(std::span<const unsigned char> e2) {
    std::vector<unsigned char> cb(40);
    for (size_t i = 0; i < 40; ++i) cb[i] = static_cast<unsigned char>(i);
    for (size_t i = kNonceOffset; i < kNonceOffset + EXTRANONCE2_SIZE; ++i) cb[i] = 0;
    std::memcpy(cb.data() + kNonceOffset, e2.data(), EXTRANONCE2_SIZE);
    return cb;
}

uint256 coinbase_hash(std::span<const unsigned char> e2) {
    auto cb = build_coinbase(e2);
    return sha256d(std::span<const unsigned char>(cb.data(), cb.size()));
}

// A 32-byte internal-order hash filled with a single byte (order-independent).
uint256 fill_hash(unsigned char b) {
    return uint256(std::vector<unsigned char>(32, b));
}

// sha256d(left || right), 32B internal LE each -- mirrors merkle_record_type.pack.
uint256 node(const uint256& l, const uint256& r) {
    std::vector<unsigned char> buf(64);
    auto lc = l.GetChars();
    auto rc = r.GetChars();
    std::memcpy(buf.data(),      lc.data(), 32);
    std::memcpy(buf.data() + 32, rc.data(), 32);
    return sha256d(std::span<const unsigned char>(buf.data(), buf.size()));
}

// Full merkle root (mirror of oracle dash_data.merkle_hash: duplicate-last on odd).
uint256 merkle_root_full(std::vector<uint256> leaves) {
    if (leaves.empty()) return uint256();
    while (leaves.size() > 1) {
        if (leaves.size() % 2 == 1) leaves.push_back(leaves.back());
        std::vector<uint256> next;
        next.reserve(leaves.size() / 2);
        for (size_t i = 0; i + 1 < leaves.size(); i += 2)
            next.push_back(node(leaves[i], leaves[i + 1]));
        leaves.swap(next);
    }
    return leaves[0];
}

// Miner-side fold for coinbase leaf index 0: running hash always on the LEFT
// (mirror of oracle check_merkle_link with index == 0).
uint256 fold_index0(const uint256& tip, const std::vector<uint256>& branch) {
    uint256 cur = tip;
    for (const auto& sib : branch) cur = node(cur, sib);
    return cur;
}

// Deliberately-wrong orientation (running hash on the RIGHT) -- for the guard
// that the LE-orientation the server encodes actually matters.
uint256 fold_wrongside(const uint256& tip, const std::vector<uint256>& branch) {
    uint256 cur = tip;
    for (const auto& sib : branch) cur = node(sib, cur);
    return cur;
}

const std::vector<unsigned char> E2_ZERO(8, 0x00);
const std::vector<unsigned char> E2_A{0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8};
const std::vector<unsigned char> E2_B{0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8};

// Independently-computed golden anchors (Python hashlib sha256d, NOT oracle
// code). Display (GetHex) form. Four-leaf tree: [coinbase, 0x11.., 0x22.., 0x33..].
const char* GOLD_BRANCH1  = "a3b916608afe957e34063e2253d49027536edf473f62d82891974f94fca5c569";
const char* GOLD_CBHASH_Z = "b0d22de8e7f6765f9d8c289ecd77ad8e0ab6a88c2a4ccf594c509d7775bb54ab";
const char* GOLD_ROOT_Z   = "26f79b540fe6f2ac6fc52f37e5af5b33a61f33216bc4ec394635b24235850ea0";
const char* GOLD_CBHASH_A = "22a146527ac0731341d026480042a55cee0bdb804043b570af24feb9e76f2c8b";
const char* GOLD_ROOT_A   = "4b2d0948edb39954294fd28ca3926a78f0e56990c69d4fd7530a80a40491198e";
const char* GOLD_CBHASH_B = "04c8f4793537be307eaa2166642accc8265add0a59ccf4d01525f0ec54c6237a";
const char* GOLD_ROOT_B   = "72f7c45d5d6c65fd77053fec86d20d918681b92aba88c87f5aaa5bf7ab3a8230";

// Four-leaf tx set: coinbase placeholder at [0] + three sibling tx hashes.
std::vector<uint256> leaves_with(const uint256& cb) {
    return { cb, fill_hash(0x11), fill_hash(0x22), fill_hash(0x33) };
}

} // namespace

// (1) Producer geometry: a 4-leaf tree yields a 2-element merkle_branch, and
//     the placeholder value at [0] does not affect the branch (only siblings).
TEST(DashStratumNotifyRoundtrip, BranchDepthAndPlaceholderIndependence) {
    auto a = merkle_branches_raw(leaves_with(coinbase_hash(E2_ZERO)));
    auto b = merkle_branches_raw(leaves_with(coinbase_hash(E2_A)));
    ASSERT_EQ(a.size(), 2u);              // ceil(log2(4)) siblings
    EXPECT_EQ(a, b);                      // branch is coinbase-value-independent
    EXPECT_EQ(a[0].GetHex(), std::string(64, '1'));  // first sibling == 0x11..
    EXPECT_EQ(a[1].GetHex(), GOLD_BRANCH1);
}

// (2) Round-trip core (oracle work.py:474): folding the real notify branch over
//     the coinbase hash (index 0) reproduces the full-tree merkle_root exactly.
TEST(DashStratumNotifyRoundtrip, BranchFoldsToFullRoot) {
    uint256 cb = coinbase_hash(E2_ZERO);
    auto branch = merkle_branches_raw(leaves_with(cb));
    uint256 folded = fold_index0(cb, branch);
    uint256 full   = merkle_root_full(leaves_with(cb));
    EXPECT_EQ(folded, full);
    EXPECT_EQ(folded.GetHex(), GOLD_ROOT_Z);
}

// (3) Extranonce2 binds into the header root: distinct extranonce2 -> distinct
//     coinbase hash -> distinct folded merkle_root under the SAME branch. This
//     propagates #630's slot binding all the way into the block-header field.
TEST(DashStratumNotifyRoundtrip, Extranonce2BindsIntoMerkleRoot) {
    uint256 cbZ = coinbase_hash(E2_ZERO);
    uint256 cbA = coinbase_hash(E2_A);
    uint256 cbB = coinbase_hash(E2_B);
    // Branch is the same regardless of coinbase value (asserted in test 1); use it.
    auto branch = merkle_branches_raw(leaves_with(cbZ));

    uint256 rZ = fold_index0(cbZ, branch);
    uint256 rA = fold_index0(cbA, branch);
    uint256 rB = fold_index0(cbB, branch);

    // injective: three distinct extranonce2 -> three distinct roots
    EXPECT_NE(rZ, rA);
    EXPECT_NE(rZ, rB);
    EXPECT_NE(rA, rB);

    // each folded root equals both its full-tree recomputation and its golden.
    EXPECT_EQ(rA, merkle_root_full(leaves_with(cbA)));
    EXPECT_EQ(rB, merkle_root_full(leaves_with(cbB)));
    EXPECT_EQ(rA.GetHex(), GOLD_ROOT_A);
    EXPECT_EQ(rB.GetHex(), GOLD_ROOT_B);
}

// (4) Zero nonce is the identity element into the root as well: the E2_ZERO
//     coinbase reproduces the baseline root (complements #630 ZeroNonceIsIdentity).
TEST(DashStratumNotifyRoundtrip, ZeroNonceRootIsBaseline) {
    uint256 cb = coinbase_hash(E2_ZERO);
    EXPECT_EQ(cb.GetHex(), GOLD_CBHASH_Z);
    auto branch = merkle_branches_raw(leaves_with(cb));
    EXPECT_EQ(fold_index0(cb, branch).GetHex(), GOLD_ROOT_Z);
}

// (5) Solo-coinbase (single-tx block, oracle work.py:124/357 empty branch):
//     merkle_branches_raw returns an empty branch and the root IS the coinbase
//     hash -- the fold degenerates to the identity.
TEST(DashStratumNotifyRoundtrip, SoloCoinbaseEmptyBranch) {
    uint256 cb = coinbase_hash(E2_ZERO);
    auto branch = merkle_branches_raw({cb});          // one leaf -> empty branch
    EXPECT_TRUE(branch.empty());
    EXPECT_EQ(fold_index0(cb, branch), cb);
    EXPECT_EQ(merkle_root_full({cb}), cb);
}

// (6) Orientation guard: index-0 binding puts the running hash on the LEFT. The
//     opposite orientation yields a different root -- pinning the exact byte
//     order (the merkle_branches_hex LE-vs-display trap documented in-source).
TEST(DashStratumNotifyRoundtrip, FoldOrientationIndex0IsLeft) {
    uint256 cb = coinbase_hash(E2_A);
    auto branch = merkle_branches_raw(leaves_with(cb));
    EXPECT_EQ(fold_index0(cb, branch).GetHex(), GOLD_ROOT_A);
    EXPECT_NE(fold_index0(cb, branch), fold_wrongside(cb, branch));
}

// (7) Golden byte-parity anchors (independent Python sha256d). Non-circular:
//     these hex values were computed outside both the oracle and this code.
TEST(DashStratumNotifyRoundtrip, GoldenAnchors) {
    EXPECT_EQ(coinbase_hash(E2_ZERO).GetHex(), GOLD_CBHASH_Z);
    EXPECT_EQ(coinbase_hash(E2_A).GetHex(),    GOLD_CBHASH_A);
    EXPECT_EQ(coinbase_hash(E2_B).GetHex(),    GOLD_CBHASH_B);
    EXPECT_EQ(merkle_branches_raw(leaves_with(coinbase_hash(E2_ZERO)))[1].GetHex(), GOLD_BRANCH1);
}

// ═════════════════════════════════════════════════════════════════════════════
// Sharechain tip-change -> stratum PUSH fan-out, and the local-mint gauge.
//
// Same file/target as the notify wire-contract KATs above (allowlisted), one
// step upstream: WHEN does a notify get pushed at all. The production defect
// these pin: the sharechain best-share-changed callback only invalidated the
// served payload (bump_work_generation) and never called notify_all(), so rigs
// kept hashing the previous prev_share_hash until the 25 s keepalive timer
// fired. The producer job_cache is keyed (prev_share_hash, payout_script), so
// every solve inside that window rebuilt the SAME frozen job -> siblings at one
// sharechain height (measured 4.13 shares/height, ~76% orphan) instead of a
// linear chain.
//
// (a) fire_share_tip_refresh (src/impl/dash/stratum/tip_refresh.hpp) is the
//     REAL fan-out the run loop binds -- these run the landed code, not a copy.
// (b) LocalMintLedger/classify_local_mint (src/impl/dash/local_mint_ledger.hpp)
//     is the display-only gauge that makes the failure visible: of the shares
//     WE minted, how many are still on the best chain. Consensus-invisible.
// ═════════════════════════════════════════════════════════════════════════════

namespace {

// ── Fan-out spies ────────────────────────────────────────────────────────────
struct SpyLog { std::vector<std::string> calls; };

struct SpyWorkSource {
    SpyLog* log; int bumps = 0;
    void bump_work_generation() { ++bumps; log->calls.push_back("bump"); }
};
struct SpyStratumServer {
    SpyLog* log; int notifies = 0;
    void notify_all() { ++notifies; log->calls.push_back("notify"); }
};
struct SpyWebServer {
    SpyLog* log; int refreshes = 0;
    void trigger_work_refresh_debounced() { ++refreshes; log->calls.push_back("web"); }
};

// ── Fake sharechain: the three primitives classify_local_mint uses ───────────
class FakeChain {
public:
    void add(const uint256& hash, const uint256& parent, int32_t height) {
        m_parent[hash] = parent;
        m_height[hash] = height;
    }
    bool contains(const uint256& h) const { return m_height.count(h) != 0; }
    int32_t get_acc_height(const uint256& h) {
        auto it = m_height.find(h);
        return it == m_height.end() ? 0 : it->second;
    }
    uint256 get_nth_parent_via_skip(const uint256& h, int32_t n) const {
        uint256 cur = h;
        for (int32_t i = 0; i < n; ++i) {
            auto it = m_parent.find(cur);
            if (it == m_parent.end()) return uint256();
            cur = it->second;
        }
        return cur;
    }
private:
    std::map<uint256, uint256> m_parent;
    std::map<uint256, int32_t> m_height;
};

// A linear chain h1..h6 (heights 1..6) plus one SIBLING of h4 (same parent h3).
// h1 is the root; sibling shares h4's parent and height but not the best chain.
struct SiblingFixture {
    FakeChain chain;
    uint256 h[7];
    uint256 sibling;
    SiblingFixture() {
        for (int i = 1; i <= 6; ++i) h[i] = fill_hash(static_cast<unsigned char>(0x10 + i));
        chain.add(h[1], uint256(), 1);
        for (int i = 2; i <= 6; ++i) chain.add(h[i], h[i - 1], i);
        sibling = fill_hash(0xAB);
        chain.add(sibling, h[3], 4);            // same height as h4, off the best chain
    }
};

} // namespace

// (8) THE REGRESSION PIN: a sharechain tip change must PUSH work to the miners,
//     not merely invalidate the cached payload. bump-only is the defect.
TEST(DashSharechainTipRefresh, TipChangePushesNotifyToMiners) {
    SpyLog log;
    SpyWorkSource ws{&log};
    SpyStratumServer ss{&log};
    SpyWebServer web{&log};

    dash::stratum::fire_share_tip_refresh(&ws, &ss, &web);

    EXPECT_EQ(ws.bumps, 1);
    EXPECT_EQ(ss.notifies, 1) << "sharechain tip change did not push mining.notify "
                                 "-- rigs keep the stale prev_share_hash job";
    EXPECT_EQ(web.refreshes, 1);
    // Order matters: invalidate the payload BEFORE pushing, so the notify a
    // session builds is sourced from the new tip, and notify the miners BEFORE
    // the dashboard (miners first).
    ASSERT_EQ(log.calls.size(), 3u);
    EXPECT_EQ(log.calls[0], "bump");
    EXPECT_EQ(log.calls[1], "notify");
    EXPECT_EQ(log.calls[2], "web");
}

// (9) Every leg is independently optional: --stratum-port 0 (no acceptor) and
//     the dashboard-off build must not fault, and must not lose the bump.
TEST(DashSharechainTipRefresh, LegsAreNullTolerant) {
    SpyLog log;
    SpyWorkSource ws{&log};
    SpyStratumServer ss{&log};

    dash::stratum::fire_share_tip_refresh(&ws, static_cast<SpyStratumServer*>(nullptr),
                                          static_cast<SpyWebServer*>(nullptr));
    EXPECT_EQ(ws.bumps, 1);
    EXPECT_EQ(ss.notifies, 0);

    dash::stratum::fire_share_tip_refresh(static_cast<SpyWorkSource*>(nullptr), &ss,
                                          static_cast<SpyWebServer*>(nullptr));
    EXPECT_EQ(ws.bumps, 1);
    EXPECT_EQ(ss.notifies, 1);
}

// (10) One notify per tip change -- N tip changes push N times (the keepalive
//      timer is a SAFETY net, never the work-delivery mechanism).
TEST(DashSharechainTipRefresh, OneNotifyPerTipChange) {
    SpyLog log;
    SpyWorkSource ws{&log};
    SpyStratumServer ss{&log};
    SpyWebServer web{&log};
    for (int i = 0; i < 7; ++i)
        dash::stratum::fire_share_tip_refresh(&ws, &ss, &web);
    EXPECT_EQ(ss.notifies, 7);
    EXPECT_EQ(ws.bumps, 7);
}

// (11) Gauge: a mint that is still an ancestor of the best share is on-chain;
//      a sibling at the same height is not. This is the number that was 0.
TEST(DashLocalMintLedger, ClassifiesOnChainVsSibling) {
    SiblingFixture f;
    const int32_t depth = dash::mint::LocalMintLedger::kSettleDepth;   // 3

    // best = h6 -> h3 is buried 3 deep: settled, on-chain.
    EXPECT_EQ(dash::mint::classify_local_mint(f.chain, f.h[6], f.h[3], depth),
              dash::mint::MintVerdict::on_chain);
    // The sibling of h4 is buried 2 deep at best=h6 -> still pending...
    EXPECT_EQ(dash::mint::classify_local_mint(f.chain, f.h[6], f.sibling, depth),
              dash::mint::MintVerdict::pending);
    // ...and h4 itself is likewise pending at that depth (symmetry check).
    EXPECT_EQ(dash::mint::classify_local_mint(f.chain, f.h[6], f.h[4], depth),
              dash::mint::MintVerdict::pending);

    // Grow the chain to h7/h8 so the height-4 pair settles: h4 on-chain,
    // its sibling off-chain (an orphan that earns nothing).
    uint256 h7 = fill_hash(0x21), h8 = fill_hash(0x22);
    f.chain.add(h7, f.h[6], 7);
    f.chain.add(h8, h7, 8);
    EXPECT_EQ(dash::mint::classify_local_mint(f.chain, h8, f.h[4], depth),
              dash::mint::MintVerdict::on_chain);
    EXPECT_EQ(dash::mint::classify_local_mint(f.chain, h8, f.sibling, depth),
              dash::mint::MintVerdict::off_chain);
}

// (12) Unknowables never inflate the rate: a hash the tracker no longer holds
//      settles as `gone`, and a null best share stays pending.
TEST(DashLocalMintLedger, PrunedAndUnknownAreNotCountedAsOrphans) {
    SiblingFixture f;
    const int32_t depth = dash::mint::LocalMintLedger::kSettleDepth;
    EXPECT_EQ(dash::mint::classify_local_mint(f.chain, f.h[6], fill_hash(0x77), depth),
              dash::mint::MintVerdict::gone);
    EXPECT_EQ(dash::mint::classify_local_mint(f.chain, uint256(), f.h[1], depth),
              dash::mint::MintVerdict::pending);
}

// (13) End-to-end gauge: mint 2 winners + 2 siblings, settle against the best
//      chain, read the rate. 50% here; the live node measured ~76%.
TEST(DashLocalMintLedger, SettlesAndReportsOrphanRate) {
    SiblingFixture f;
    uint256 sib2 = fill_hash(0xCD);
    f.chain.add(sib2, f.h[1], 2);          // sibling of h2

    dash::mint::LocalMintLedger ledger;
    ledger.record_mint(f.h[2]);
    ledger.record_mint(sib2);
    ledger.record_mint(f.h[3]);
    ledger.record_mint(f.sibling);         // sibling of h4

    EXPECT_EQ(ledger.stats().minted, 4u);
    EXPECT_EQ(ledger.stats().pending, 4u);

    auto settle_against = [&](const uint256& best) {
        ledger.settle([&](const uint256& h) {
            return dash::mint::classify_local_mint(
                f.chain, best, h, dash::mint::LocalMintLedger::kSettleDepth);
        });
    };

    // best = h6: heights 2 and 3 are deep enough; height 4 is not.
    settle_against(f.h[6]);
    auto s = ledger.stats();
    EXPECT_EQ(s.on_chain, 2u);             // h2, h3
    EXPECT_EQ(s.orphaned, 1u);             // sib2
    EXPECT_EQ(s.pending,  1u);             // f.sibling — still too shallow
    EXPECT_DOUBLE_EQ(s.orphan_rate, 1.0 / 3.0);

    // Chain grows two more: the height-4 sibling now settles as an orphan.
    uint256 h7 = fill_hash(0x21), h8 = fill_hash(0x22);
    f.chain.add(h7, f.h[6], 7);
    f.chain.add(h8, h7, 8);
    settle_against(h8);
    s = ledger.stats();
    EXPECT_EQ(s.minted,   4u);
    EXPECT_EQ(s.on_chain, 2u);
    EXPECT_EQ(s.orphaned, 2u);
    EXPECT_EQ(s.pending,  0u);
    EXPECT_DOUBLE_EQ(s.orphan_rate, 0.5);
}

// (14) The gauge is bounded and cheap: the un-settled set can never grow past
//      kMaxPending, and evictions are accounted (never silently lost).
TEST(DashLocalMintLedger, PendingSetIsBounded) {
    dash::mint::LocalMintLedger ledger;
    const std::size_t over = dash::mint::LocalMintLedger::kMaxPending + 10;
    for (std::size_t i = 0; i < over; ++i) {
        std::vector<unsigned char> raw(32, 0);
        raw[0] = static_cast<unsigned char>(i & 0xff);
        raw[1] = static_cast<unsigned char>((i >> 8) & 0xff);
        raw[2] = 0x01;             // never the null hash (record_mint ignores null)
        ledger.record_mint(uint256(raw));
    }
    auto s = ledger.stats();
    EXPECT_EQ(s.minted,  static_cast<uint64_t>(over));
    EXPECT_EQ(s.pending, static_cast<uint64_t>(dash::mint::LocalMintLedger::kMaxPending));
    EXPECT_EQ(s.dropped, 10u);
    EXPECT_DOUBLE_EQ(s.orphan_rate, 0.0);   // nothing settled -> no rate invented
}
