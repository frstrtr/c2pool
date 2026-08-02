// SPDX-License-Identifier: AGPL-3.0-or-later
/// MN DIFF-LADDER recovery KAT (DASH_MN_DIFF_LADDER_RECOVERY.md).
///
/// The defect being closed: a masternode PAYEE DESYNC latches
/// CoinStateMaintainer::m_mn_needs_reseed, and the ONLY key that opens that
/// latch is an authoritative re-seed obtained via the `protx` coin RPC. A
/// daemonless node has no coin RPC, so the latch is permanent and the node is
/// demoted to an arm that does not exist (contabo smoke rig, 639 consecutive
/// empty-set-gap templates over 76 minutes).
///
/// EVERY POSITIVE TEST HERE HAS A NEGATIVE TWIN. This project has repeatedly
/// shipped tests that could only return one answer; a test that cannot fail is
/// not evidence. The twins are named ...Aborts / ...Refused / ...StaysLatched
/// and each one deletes or corrupts exactly one thing and asserts the ladder
/// REFUSES — landing on today's behaviour rather than on a rebuilt state.

#include <gtest/gtest.h>

#include <impl/dash/coin/sml_quorum_db.hpp>
#include <impl/dash/coin/coin_state_maintainer.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/block_producer.hpp>   // compute_merkle_root (body<->header bind)
#include <impl/dash/coin/vendor/smldiff.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/leveldb_store.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <random>
#include <string>
#include <vector>

using dash::coin::SMLDb;
using dash::coin::LadderOutcome;
using dash::coin::LadderReplay;
using dash::coin::MN_LADDER_ANCHOR_INTERVAL;
using dash::coin::MN_LADDER_RETENTION_HEIGHTS;
using dash::coin::CoinStateMaintainer;
using dash::coin::NodeCoinState;
using dash::coin::MNState;
using dash::coin::BlockType;
using dash::coin::MutableTransaction;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;
using dash::coin::vendor::CSimplifiedMNListDiff;
using dash::coin::vendor::apply_diff;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

namespace {

// ── scratch dir (same shape as test_dash_sml_quorum_db.cpp) ───────────────
std::string ladder_scratch_dir(const char* tag) {
    static std::atomic<int> seq{0};
    std::random_device rd;
    auto p = std::filesystem::temp_directory_path()
           / ("c2pool_mn_ladder_" + std::string(tag) + "_"
              + std::to_string(rd()) + "_" + std::to_string(seq++));
    std::filesystem::remove_all(p);
    std::filesystem::create_directories(p);
    return p.string();
}

struct ScratchDb {
    std::string path;
    explicit ScratchDb(const char* tag) : path(ladder_scratch_dir(tag)) {}
    ~ScratchDb() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

uint256 hash_from(uint32_t seed) {
    uint256 h;
    for (int i = 0; i < 32; ++i)
        h.data()[i] = static_cast<uint8_t>((seed * 31u + i * 7u + 11u) & 0xFF);
    return h;
}

CSimplifiedMNListEntry make_entry(uint32_t seed, bool is_valid = true) {
    CSimplifiedMNListEntry e;
    e.nVersion      = CSimplifiedMNListEntry::VER_BASIC_BLS;
    e.nType         = CSimplifiedMNListEntry::TYPE_REGULAR;
    e.proRegTxHash  = hash_from(seed);
    e.confirmedHash = hash_from(seed + 1000);
    for (int i = 0; i < 16; ++i)
        e.netAddress[i] = static_cast<uint8_t>(seed + i);
    e.netPort = static_cast<uint16_t>(9999 + (seed % 100));
    for (int i = 0; i < 48; ++i)
        e.pubKeyOperator[i] = static_cast<uint8_t>(seed * 3 + i);
    e.isValid = is_valid;
    return e;
}

// A ZERO-base diff = a full snapshot at `block_hash`.
CSimplifiedMNListDiff make_snapshot_diff(const std::vector<CSimplifiedMNListEntry>& set,
                                         const uint256& block_hash) {
    CSimplifiedMNListDiff d;
    d.baseBlockHash = uint256::ZERO;
    d.blockHash     = block_hash;
    d.mnList        = set;
    return d;
}

// An INCREMENTAL diff: chains onto `base`, adds/updates one entry.
CSimplifiedMNListDiff make_incr_diff(const uint256& base, const uint256& block_hash,
                                     const CSimplifiedMNListEntry& upsert) {
    CSimplifiedMNListDiff d;
    d.baseBlockHash = base;
    d.blockHash     = block_hash;
    d.mnList.push_back(upsert);
    return d;
}

// Drive the store the way main_dash's persist hook does: apply the diff to the
// live SML, then write the resulting state + the accepted diff in ONE batch.
struct LadderFixture {
    CSimplifiedMNList live;
    uint32_t          anchor_h{0};
    uint32_t          top_h{0};

    void seed(SMLDb& db, uint32_t anchor_height, uint32_t n_incremental,
              size_t base_entries = 6) {
        anchor_h = anchor_height;
        std::vector<CSimplifiedMNListEntry> set;
        for (size_t i = 0; i < base_entries; ++i)
            set.push_back(make_entry(static_cast<uint32_t>(i + 1)));

        auto snap = make_snapshot_diff(set, hash_from(anchor_height));
        live.mnList.clear();
        apply_diff(live, snap);
        ASSERT_TRUE(db.write_sml(live, snap.blockHash, anchor_height, &snap));

        for (uint32_t k = 1; k <= n_incremental; ++k) {
            const uint32_t h = anchor_height + k;
            auto d = make_incr_diff(hash_from(h - 1), hash_from(h),
                                    make_entry(1000 + k));
            apply_diff(live, d);
            ASSERT_TRUE(db.write_sml(live, d.blockHash, h, &d));
        }
        top_h = anchor_height + n_incremental;
    }
};

// Raw mutation of the CLOSED store — the only way to express "one record went
// missing" / "one stored root is wrong" without a fake seam in production code.
void with_raw_store(const std::string& path,
                    const std::function<void(::core::LevelDBStore&)>& fn) {
    ::core::LevelDBStore raw(path, {});
    ASSERT_TRUE(raw.open());
    fn(raw);
    raw.close();
}

std::string ladder_key(char tag, uint32_t h) {
    std::string k;
    k.push_back(tag);
    k.push_back(static_cast<char>((h >> 24) & 0xFF));
    k.push_back(static_cast<char>((h >> 16) & 0xFF));
    k.push_back(static_cast<char>((h >>  8) & 0xFF));
    k.push_back(static_cast<char>( h        & 0xFF));
    return k;
}

// Anchor height must be a multiple of the interval or no 'A' is ever written.
constexpr uint32_t kAnchorH = 32u * 100u;   // 3200

}  // namespace

// ════════════════════════════════════════════════════════════════════════
// STORAGE LAYER
// ════════════════════════════════════════════════════════════════════════

// Guard on the codec the whole ladder rests on: CSimplifiedMNListDiff's
// unserializer DRAINS the rest of the stream as its opaque quorum tail, so a
// value laid out as pack(diff)++root(32B) is only readable if the reader stops
// 32 bytes short. If this ever silently changes, every replay would swallow the
// root into quorum_tail and the root-compare would be meaningless.
TEST(DashMnDiffLadderStore, DiffRecordRoundTripsWithRootSuffix) {
    auto d = make_incr_diff(hash_from(7), hash_from(8), make_entry(42));
    d.quorum_tail = {0xde, 0xad, 0xbe, 0xef};
    const uint256 root = hash_from(999);

    auto stream = ::pack(d);
    auto sp = stream.get_span();
    std::vector<uint8_t> value(
        reinterpret_cast<const uint8_t*>(sp.data()),
        reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
    value.insert(value.end(), root.data(), root.data() + 32);

    uint256 read_root;
    std::memcpy(read_root.data(), value.data() + value.size() - 32, 32);
    EXPECT_EQ(read_root, root);

    std::vector<uint8_t> body(value.begin(), value.end() - 32);
    ::PackStream ps(body);
    CSimplifiedMNListDiff back;
    ASSERT_NO_THROW(ps >> back);
    EXPECT_EQ(back.baseBlockHash, d.baseBlockHash);
    EXPECT_EQ(back.blockHash, d.blockHash);
    ASSERT_EQ(back.mnList.size(), 1u);
    EXPECT_EQ(back.mnList[0].proRegTxHash, d.mnList[0].proRegTxHash);
    EXPECT_EQ(back.quorum_tail, d.quorum_tail);
}

TEST(DashMnDiffLadderStore, WriteAppendsDiffsAndAnchorsAndReportsDepth) {
    ScratchDb dir("depth");
    SMLDb db(dir.path);
    ASSERT_TRUE(db.open());

    LadderFixture fx;
    fx.seed(db, kAnchorH, /*n_incremental=*/5);

    const auto st = db.ladder_stats();
    EXPECT_EQ(st.diffs, 6u) << "one 'D' per accepted diff (anchor height + 5)";
    EXPECT_EQ(st.anchors, 1u) << "one 'A' at the anchor-interval boundary";
    EXPECT_EQ(st.lowest_diff, kAnchorH);
    EXPECT_EQ(st.highest_diff, kAnchorH + 5);
    EXPECT_EQ(st.highest_anchor, kAnchorH);
    EXPECT_NE(st.banner().find("interval=32"), std::string::npos)
        << "the banner must state the sizing constants it is running with";
    db.close();
}

// The whole point of the "additive keyspace" claim: the ladder append must not
// perturb the 'S'/'B' warm-restart bytes AT ALL. Two stores, same diffs, one
// written the master way (no ladder) and one the new way; the reloaded state
// must be identical in every observable respect.
TEST(DashMnDiffLadderStore, WarmRestartIsByteIdenticalWithAndWithoutLadder) {
    ScratchDb dir_old("warm_master");
    ScratchDb dir_new("warm_ladder");
    SMLDb db_old(dir_old.path), db_new(dir_new.path);
    ASSERT_TRUE(db_old.open());
    ASSERT_TRUE(db_new.open());

    std::vector<CSimplifiedMNListEntry> set;
    for (uint32_t i = 1; i <= 6; ++i) set.push_back(make_entry(i));
    auto snap = make_snapshot_diff(set, hash_from(kAnchorH));
    CSimplifiedMNList live_old, live_new;
    apply_diff(live_old, snap);
    apply_diff(live_new, snap);
    ASSERT_TRUE(db_old.write_sml(live_old, snap.blockHash, kAnchorH));       // master path
    ASSERT_TRUE(db_new.write_sml(live_new, snap.blockHash, kAnchorH, &snap)); // ladder path

    for (uint32_t k = 1; k <= 4; ++k) {
        const uint32_t h = kAnchorH + k;
        auto d = make_incr_diff(hash_from(h - 1), hash_from(h), make_entry(2000 + k));
        apply_diff(live_old, d);
        apply_diff(live_new, d);
        ASSERT_TRUE(db_old.write_sml(live_old, d.blockHash, h));
        ASSERT_TRUE(db_new.write_sml(live_new, d.blockHash, h, &d));
    }
    db_old.close();
    db_new.close();

    SMLDb re_old(dir_old.path), re_new(dir_new.path);
    ASSERT_TRUE(re_old.open());
    ASSERT_TRUE(re_new.open());
    CSimplifiedMNList out_old, out_new;
    ASSERT_TRUE(re_old.load_verified(out_old));
    ASSERT_TRUE(re_new.load_verified(out_new));

    EXPECT_EQ(re_old.get_best_hash(), re_new.get_best_hash());
    EXPECT_EQ(re_old.get_best_height(), re_new.get_best_height());
    EXPECT_EQ(re_old.get_expected_root(), re_new.get_expected_root());
    ASSERT_EQ(out_old.size(), out_new.size());
    EXPECT_EQ(out_old.CalcMerkleRoot(), out_new.CalcMerkleRoot());
    for (size_t i = 0; i < out_old.size(); ++i)
        EXPECT_TRUE(out_old.mnList[i] == out_new.mnList[i]) << "entry " << i;
    // ...and the ladder is present in exactly one of them.
    EXPECT_EQ(re_old.ladder_stats().diffs, 0u);
    EXPECT_EQ(re_new.ladder_stats().diffs, 5u);
    re_old.close();
    re_new.close();
}

TEST(DashMnDiffLadderStore, PruneKeepsTheWindowBounded) {
    ScratchDb dir("prune");
    SMLDb db(dir.path);
    ASSERT_TRUE(db.open());

    // The window must be OVERFILLED for this test to mean anything: writing
    // fewer than MN_LADDER_RETENTION_HEIGHTS records would satisfy the bound
    // whether or not a prune exists, i.e. a test that could only pass. Start
    // well below the floor and end well above it so ~200 records MUST have
    // been dropped. Small SML so the per-write 'S' rewrite stays cheap.
    const uint32_t start = 100;
    const uint32_t end   = MN_LADDER_RETENTION_HEIGHTS + 304;  // 4400
    std::vector<CSimplifiedMNListEntry> set{make_entry(1), make_entry(2)};
    CSimplifiedMNList live;
    auto snap = make_snapshot_diff(set, hash_from(start));
    apply_diff(live, snap);
    ASSERT_TRUE(db.write_sml(live, snap.blockHash, start, &snap));
    for (uint32_t h = start + 1; h <= end; ++h) {
        auto d = make_incr_diff(hash_from(h - 1), hash_from(h),
                                make_entry(1 + (h % 2)));
        apply_diff(live, d);
        ASSERT_TRUE(db.write_sml(live, d.blockHash, h, &d));
    }

    // Sanity: without a prune this store would hold end-start+1 == 4301
    // records, so the bound below is only satisfiable BY the prune.
    ASSERT_GT(end - start + 1, MN_LADDER_RETENTION_HEIGHTS + 1);

    const auto st = db.ladder_stats();
    EXPECT_EQ(st.diffs, MN_LADDER_RETENTION_HEIGHTS + 1)
        << "retention window must bound the ladder exactly";
    EXPECT_EQ(st.lowest_diff, end - MN_LADDER_RETENTION_HEIGHTS)
        << "records below the window floor must be gone";
    EXPECT_EQ(st.highest_diff, end);
    // Anchors ride the same window.
    EXPECT_GE(st.highest_anchor, end - MN_LADDER_ANCHOR_INTERVAL);
    db.close();
}

// ════════════════════════════════════════════════════════════════════════
// RECOVERY — positive, then one negative twin per failure mode
// ════════════════════════════════════════════════════════════════════════

TEST(DashMnDiffLadderReplay, RebuildsStateFromAnchorPlusDiffs) {
    ScratchDb dir("replay_ok");
    SMLDb db(dir.path);
    ASSERT_TRUE(db.open());
    LadderFixture fx;
    fx.seed(db, kAnchorH, /*n_incremental=*/5);

    auto r = db.replay_from_ladder(fx.top_h);
    ASSERT_TRUE(r.ok()) << "reason=" << r.reason();
    EXPECT_EQ(r.reason(), "ok-replayed-5-diffs");
    EXPECT_EQ(r.anchor_height, kAnchorH);
    EXPECT_EQ(r.replayed, 5u);
    EXPECT_EQ(r.block_hash, hash_from(fx.top_h));
    // The rebuilt state must be the SAME state the live path holds, proven by
    // the independently-recomputed root, not by a stored value.
    EXPECT_EQ(r.root, fx.live.CalcMerkleRoot());
    ASSERT_EQ(r.sml.size(), fx.live.size());
    for (size_t i = 0; i < r.sml.size(); ++i)
        EXPECT_TRUE(r.sml.mnList[i] == fx.live.mnList[i]) << "entry " << i;
    db.close();
}

TEST(DashMnDiffLadderReplay, ReplayToTheAnchorItselfAppliesNoDiffs) {
    ScratchDb dir("replay_anchor_only");
    SMLDb db(dir.path);
    ASSERT_TRUE(db.open());
    LadderFixture fx;
    fx.seed(db, kAnchorH, /*n_incremental=*/5);

    auto r = db.replay_from_ladder(kAnchorH);
    ASSERT_TRUE(r.ok()) << "reason=" << r.reason();
    EXPECT_EQ(r.replayed, 0u);
    EXPECT_EQ(r.anchor_height, kAnchorH);
    db.close();
}

// NEGATIVE TWIN 1 — no anchor at or below the target.
TEST(DashMnDiffLadderReplay, MissingAnchorRefuses) {
    ScratchDb dir("no_anchor");
    SMLDb db(dir.path);
    ASSERT_TRUE(db.open());
    // Seed starting one height PAST the anchor boundary so no 'A' is written.
    LadderFixture fx;
    fx.seed(db, kAnchorH + 1, /*n_incremental=*/4);
    ASSERT_EQ(db.ladder_stats().anchors, 0u);

    auto r = db.replay_from_ladder(fx.top_h);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.outcome, LadderOutcome::AnchorMissing);
    EXPECT_EQ(r.reason(), "anchor-missing");
    EXPECT_EQ(r.sml.size(), 0u) << "a refused replay must return NO state";
    db.close();
}

// NEGATIVE TWIN 2 — the ladder is dense except for ONE height. This is the
// missed-diff case: replaying around it would rebuild a queue that skipped a
// block's worth of changes. It must ABORT, never skip.
TEST(DashMnDiffLadderReplay, DeletedDiffHeightAborts) {
    ScratchDb dir("gap");
    uint32_t top = 0;
    {
        SMLDb db(dir.path);
        ASSERT_TRUE(db.open());
        LadderFixture fx;
        fx.seed(db, kAnchorH, /*n_incremental=*/5);
        top = fx.top_h;
        ASSERT_TRUE(db.replay_from_ladder(top).ok()) << "pre-condition: clean replay";
        db.close();
    }
    const uint32_t victim = kAnchorH + 3;
    with_raw_store(dir.path, [&](::core::LevelDBStore& raw) {
        ASSERT_TRUE(raw.exists(ladder_key('D', victim)));
        ASSERT_TRUE(raw.remove(ladder_key('D', victim)));
    });
    {
        SMLDb db(dir.path);
        ASSERT_TRUE(db.open());
        auto r = db.replay_from_ladder(top);
        EXPECT_FALSE(r.ok());
        EXPECT_EQ(r.outcome, LadderOutcome::DiffGap);
        EXPECT_EQ(r.failed_height, victim);
        EXPECT_EQ(r.reason(), "diff-gap-at-h=" + std::to_string(victim));
        EXPECT_EQ(r.sml.size(), 0u);
        db.close();
    }
}

// NEGATIVE TWIN 3 — the anchor's stored root does not reproduce.
TEST(DashMnDiffLadderReplay, CorruptedAnchorRootRefuses) {
    ScratchDb dir("anchor_root");
    uint32_t top = 0;
    {
        SMLDb db(dir.path);
        ASSERT_TRUE(db.open());
        LadderFixture fx;
        fx.seed(db, kAnchorH, /*n_incremental=*/5);
        top = fx.top_h;
        ASSERT_TRUE(db.replay_from_ladder(top).ok()) << "pre-condition: clean replay";
        db.close();
    }
    with_raw_store(dir.path, [&](::core::LevelDBStore& raw) {
        std::vector<uint8_t> v;
        ASSERT_TRUE(raw.get(ladder_key('A', kAnchorH), v));
        ASSERT_GE(v.size(), 64u);
        v[v.size() - 64] ^= 0xFF;      // flip a byte of the stored root
        ASSERT_TRUE(raw.put(ladder_key('A', kAnchorH), v));
    });
    {
        SMLDb db(dir.path);
        ASSERT_TRUE(db.open());
        auto r = db.replay_from_ladder(top);
        EXPECT_FALSE(r.ok());
        EXPECT_EQ(r.outcome, LadderOutcome::AnchorRootMismatch);
        EXPECT_EQ(r.reason(),
                  "anchor-root-mismatch-at-h=" + std::to_string(kAnchorH));
        EXPECT_EQ(r.sml.size(), 0u);
        db.close();
    }
}

// NEGATIVE TWIN 4 — a mid-ladder record's resulting root does not reproduce.
TEST(DashMnDiffLadderReplay, CorruptedDiffResultRootRefusesAtThatHeight) {
    ScratchDb dir("diff_root");
    uint32_t top = 0;
    {
        SMLDb db(dir.path);
        ASSERT_TRUE(db.open());
        LadderFixture fx;
        fx.seed(db, kAnchorH, /*n_incremental=*/5);
        top = fx.top_h;
        ASSERT_TRUE(db.replay_from_ladder(top).ok()) << "pre-condition: clean replay";
        db.close();
    }
    const uint32_t victim = kAnchorH + 2;
    with_raw_store(dir.path, [&](::core::LevelDBStore& raw) {
        std::vector<uint8_t> v;
        ASSERT_TRUE(raw.get(ladder_key('D', victim), v));
        ASSERT_GE(v.size(), 32u);
        v[v.size() - 1] ^= 0x01;
        ASSERT_TRUE(raw.put(ladder_key('D', victim), v));
    });
    {
        SMLDb db(dir.path);
        ASSERT_TRUE(db.open());
        auto r = db.replay_from_ladder(top);
        EXPECT_FALSE(r.ok());
        EXPECT_EQ(r.outcome, LadderOutcome::DiffRootMismatch);
        EXPECT_EQ(r.failed_height, victim);
        EXPECT_EQ(r.sml.size(), 0u);
        db.close();
    }
}

// NEGATIVE TWIN 5 — a record that does not CHAIN onto the previous block, even
// though it exists at the right height and carries a self-consistent root.
TEST(DashMnDiffLadderReplay, BrokenBaseContinuityRefuses) {
    ScratchDb dir("base_chain");
    SMLDb db(dir.path);
    ASSERT_TRUE(db.open());

    std::vector<CSimplifiedMNListEntry> set;
    for (uint32_t i = 1; i <= 4; ++i) set.push_back(make_entry(i));
    CSimplifiedMNList live;
    auto snap = make_snapshot_diff(set, hash_from(kAnchorH));
    apply_diff(live, snap);
    ASSERT_TRUE(db.write_sml(live, snap.blockHash, kAnchorH, &snap));
    // h+1 chains correctly.
    auto d1 = make_incr_diff(hash_from(kAnchorH), hash_from(kAnchorH + 1),
                             make_entry(500));
    apply_diff(live, d1);
    ASSERT_TRUE(db.write_sml(live, d1.blockHash, kAnchorH + 1, &d1));
    // h+2 claims a base we were never at (an off-branch record).
    auto d2 = make_incr_diff(hash_from(777777), hash_from(kAnchorH + 2),
                             make_entry(501));
    apply_diff(live, d2);
    ASSERT_TRUE(db.write_sml(live, d2.blockHash, kAnchorH + 2, &d2));

    auto r = db.replay_from_ladder(kAnchorH + 2);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.outcome, LadderOutcome::DiffBaseMismatch);
    EXPECT_EQ(r.failed_height, kAnchorH + 2);
    db.close();
}

// G3: the reorg / fail-closed wipe MUST take the ladder with it. An
// orphaned-branch ladder is self-consistent and would replay perfectly clean
// into a wrong-branch state — the exact hazard clear() exists to prevent.
TEST(DashMnDiffLadderReplay, StoreClearWipesTheLadderToo) {
    ScratchDb dir("clear");
    SMLDb db(dir.path);
    ASSERT_TRUE(db.open());
    LadderFixture fx;
    fx.seed(db, kAnchorH, /*n_incremental=*/3);
    ASSERT_TRUE(db.replay_from_ladder(fx.top_h).ok());

    ASSERT_TRUE(db.clear());
    EXPECT_EQ(db.ladder_stats().diffs, 0u);
    EXPECT_EQ(db.ladder_stats().anchors, 0u);
    auto r = db.replay_from_ladder(fx.top_h);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.outcome, LadderOutcome::AnchorMissing);
    db.close();
}

// ════════════════════════════════════════════════════════════════════════
// THE LATCH — end-to-end through CoinStateMaintainer
// ════════════════════════════════════════════════════════════════════════
namespace {

constexpr uint8_t  kAddrVer  = 76;
constexpr uint8_t  kP2shVer  = 16;
constexpr uint32_t kTipH     = 2'400'000;

uint256 seq256(uint8_t base) {
    uint256 h;
    for (int i = 0; i < 32; ++i) h.data()[i] = static_cast<uint8_t>(base + i);
    return h;
}

std::vector<unsigned char> pkh_script(uint8_t seed) {
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(seed + i));
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

void bind(BlockType& b) {
    std::vector<uint256> ids;
    for (const auto& tx : b.m_txs) ids.push_back(dash::coin::dash_txid(tx));
    b.m_merkle_root = dash::coin::compute_merkle_root(ids);
}

MutableTransaction coinbase_paying(const std::vector<unsigned char>& script) {
    MutableTransaction tx;
    tx.version = 1; tx.type = 0; tx.locktime = 1;
    TxIn in; in.prevout.hash = seq256(0x90); in.prevout.index = 0;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    TxOut o; o.value = 500000000; o.scriptPubKey.m_data = script;
    tx.vout.push_back(o);
    return tx;
}

std::vector<std::pair<uint256, MNState>> one_mn(const std::vector<unsigned char>& payout) {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = payout;
    return {{seq256(0x01), s}};
}

// Arm a maintainer into the live embedded posture, then feed it a block whose
// coinbase pays somebody OTHER than the projected masternode = payee desync.
struct DesyncRig {
    NodeCoinState st;
    CoinStateMaintainer m{st};

    void arm() {
        m.set_require_seeded_mn_set(true);   // the embedded-arm posture
        m.on_mn_list_update(one_mn(pkh_script(0x30)), kTipH - 1);
        m.on_new_tip(kTipH - 1, seq256(0x50), 0x1d00ffff, 1'700'000'000,
                     kAddrVer, kP2shVer, 1'700'000'100, 4);
    }
    dash::coin::MnStateMachine::ApplyResult desync() {
        BlockType blk;
        blk.m_txs.push_back(coinbase_paying(pkh_script(0x77)));  // NOT the MN
        bind(blk);
        return m.on_block_connected(blk, kTipH);
    }
};

}  // namespace

// Flag OFF (the shipped default) — a desync must latch EXACTLY as on master,
// even with a perfectly replayable ladder wired up.
TEST(DashMnDiffLadderLatch, FlagOffKeepsTodaysLatchBehaviour) {
    DesyncRig rig;
    int ladder_calls = 0;
    rig.m.set_mn_ladder_reseed_fn([&](uint32_t) { ++ladder_calls; return true; });
    // deliberately NOT calling set_mn_ladder_reseed_enabled(true)
    ASSERT_FALSE(rig.m.mn_ladder_reseed_enabled());
    rig.arm();
    ASSERT_TRUE(rig.m.live());

    auto r = rig.desync();
    ASSERT_TRUE(r.payee_desync);
    EXPECT_EQ(ladder_calls, 0)
        << "with the flag off the ladder must not even be consulted";
    EXPECT_FALSE(rig.m.live());
    EXPECT_TRUE(rig.st.mn_needs_reseed()) << "latch must STAY SET";
    EXPECT_EQ(rig.st.classify_decline(), "mn-needs-reseed");
}

// Flag ON + a replay that succeeds — the latch opens.
TEST(DashMnDiffLadderLatch, FlagOnAndReplayOkClearsTheLatch) {
    DesyncRig rig;
    uint32_t seen_target = 0;
    rig.m.set_mn_ladder_reseed_fn([&](uint32_t h) { seen_target = h; return true; });
    rig.m.set_mn_ladder_reseed_enabled(true);
    rig.arm();
    ASSERT_TRUE(rig.m.live());

    auto r = rig.desync();
    ASSERT_TRUE(r.payee_desync);
    EXPECT_EQ(seen_target, kTipH) << "the replay target is the desync height";
    EXPECT_FALSE(rig.st.mn_needs_reseed()) << "verified replay must clear the latch";

    // ...and clearing the latch is NOT sufficient to serve. The Simplified MN
    // List carries no scriptPayout / nLastPaidHeight, so the payee queue is
    // still empty and MN-readiness stays down. There is no new way to serve.
    EXPECT_FALSE(rig.m.live());
    EXPECT_EQ(rig.st.mnstates().size(), 0u);
    bool fell_back = false;
    auto sel = rig.st.select_work([&]() {
        fell_back = true;
        return dash::coin::DashWorkData{};
    });
    EXPECT_EQ(sel.source, dash::coin::WorkSource::DashdFallback);
    EXPECT_TRUE(fell_back);
}

// NEGATIVE TWIN — flag ON but the replay REFUSES. Failure must land on today's
// behaviour: latch set, arm demoted, decline named.
TEST(DashMnDiffLadderLatch, FlagOnButReplayRefusedStaysLatched) {
    DesyncRig rig;
    int calls = 0;
    rig.m.set_mn_ladder_reseed_fn([&](uint32_t) { ++calls; return false; });
    rig.m.set_mn_ladder_reseed_enabled(true);
    rig.arm();
    ASSERT_TRUE(rig.m.live());

    auto r = rig.desync();
    ASSERT_TRUE(r.payee_desync);
    EXPECT_EQ(calls, 1);
    EXPECT_TRUE(rig.st.mn_needs_reseed()) << "a refused replay must NOT open the latch";
    EXPECT_FALSE(rig.m.live());
    EXPECT_EQ(rig.st.classify_decline(), "mn-needs-reseed");
}

// NEGATIVE TWIN — flag ON, replay would succeed, but the anti-mint seeded-MN
// requirement is OFF. Clearing the latch there would reopen the E2d hole
// (block-connect alone arming MN-readiness off an incidental ProRegTx), so the
// ladder must refuse to clear.
TEST(DashMnDiffLadderLatch, AntiMintInterlockRefusesWhenSeededMnNotRequired) {
    NodeCoinState st;
    CoinStateMaintainer m(st);
    int calls = 0;
    m.set_mn_ladder_reseed_fn([&](uint32_t) { ++calls; return true; });
    m.set_mn_ladder_reseed_enabled(true);
    // NOTE: set_require_seeded_mn_set() deliberately NOT called (KAT default).
    m.on_mn_list_update(one_mn(pkh_script(0x30)), kTipH - 1);
    m.on_new_tip(kTipH - 1, seq256(0x50), 0x1d00ffff, 1'700'000'000,
                 kAddrVer, kP2shVer, 1'700'000'100, 4);
    ASSERT_TRUE(m.live());

    BlockType blk;
    blk.m_txs.push_back(coinbase_paying(pkh_script(0x77)));
    bind(blk);
    auto r = m.on_block_connected(blk, kTipH);

    ASSERT_TRUE(r.payee_desync);
    EXPECT_EQ(calls, 0) << "the interlock must short-circuit BEFORE the replay";
    EXPECT_TRUE(st.mn_needs_reseed());
    EXPECT_FALSE(m.live());
}

// Observability: before this slice the latch was invisible to the decline
// classifier — the smoke rig reported "not-populated" 639 times while the real
// cause was a payee desync. classify_decline must now NAME it.
TEST(DashMnDiffLadderLatch, ClassifyDeclineNamesTheLatch) {
    NodeCoinState st;
    EXPECT_NE(st.classify_decline(), "mn-needs-reseed");
    st.set_mn_needs_reseed(true);
    EXPECT_EQ(st.classify_decline(), "mn-needs-reseed");
    st.set_mn_needs_reseed(false);
    EXPECT_NE(st.classify_decline(), "mn-needs-reseed");
}

// End-to-end: a REAL ladder store behind the maintainer seam. Proves the two
// halves compose — the store replays, the maintainer opens the latch — and,
// in the twin, that deleting one 'D' height keeps the arm latched.
TEST(DashMnDiffLadderLatch, EndToEndRealLadderRearms) {
    ScratchDb dir("e2e");
    SMLDb db(dir.path);
    ASSERT_TRUE(db.open());
    LadderFixture fx;
    fx.seed(db, kAnchorH, /*n_incremental=*/6);

    DesyncRig rig;
    std::string outcome;
    rig.m.set_mn_ladder_reseed_fn([&](uint32_t) {
        auto rep = db.replay_from_ladder(fx.top_h);
        outcome = rep.reason();
        return rep.ok();
    });
    rig.m.set_mn_ladder_reseed_enabled(true);
    rig.arm();
    ASSERT_TRUE(rig.desync().payee_desync);
    EXPECT_EQ(outcome, "ok-replayed-6-diffs");
    EXPECT_FALSE(rig.st.mn_needs_reseed());
    db.close();
}

TEST(DashMnDiffLadderLatch, EndToEndMissingDiffKeepsArmLatched) {
    ScratchDb dir("e2e_gap");
    uint32_t top = 0;
    {
        SMLDb seedb(dir.path);
        ASSERT_TRUE(seedb.open());
        LadderFixture fx;
        fx.seed(seedb, kAnchorH, /*n_incremental=*/6);
        top = fx.top_h;
        seedb.close();
    }
    with_raw_store(dir.path, [&](::core::LevelDBStore& raw) {
        ASSERT_TRUE(raw.remove(ladder_key('D', kAnchorH + 4)));
    });

    SMLDb db(dir.path);
    ASSERT_TRUE(db.open());
    DesyncRig rig;
    std::string outcome;
    rig.m.set_mn_ladder_reseed_fn([&](uint32_t) {
        auto rep = db.replay_from_ladder(top);
        outcome = rep.reason();
        return rep.ok();
    });
    rig.m.set_mn_ladder_reseed_enabled(true);
    rig.arm();
    ASSERT_TRUE(rig.desync().payee_desync);
    EXPECT_EQ(outcome, "diff-gap-at-h=" + std::to_string(kAnchorH + 4));
    EXPECT_TRUE(rig.st.mn_needs_reseed()) << "a gap must leave the arm LATCHED";
    EXPECT_FALSE(rig.m.live());
    EXPECT_EQ(rig.st.classify_decline(), "mn-needs-reseed");
    db.close();
}
