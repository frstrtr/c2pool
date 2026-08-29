// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KATs for the MN diff/snapshot store (mn_diff_store.hpp) — the dashd evodb
// dmn_D4/dmn_S3 mechanism (evo/deterministicmns.cpp:689-870) ported over
// ReplayMNState. Coverage:
//   * MnStateDiff bitmask semantics (dmnstate.h:155-260): masking, the
//     nVersion-first rule, round-trip
//   * MnListDiff build/apply (deterministicmns.cpp:361-418): added sorted by
//     internalId, removal arithmetic, every ApplyDiff throw as a REFUSAL
//   * MnDiffRecord codec: sha256d trailer, digest-corrupt refuse, empty diff
//     is a real record (proof-of-processing)
//   * MnDiffStore reconstruct (GetListForBlockInternal analogue): the
//     snapshot+diff walk, the fail-closed inversion (missing row REFUSES,
//     never an empty list), flag holes, orphaned-sibling disambiguation,
//     depth bound, internalId reproduction via total_registered_count
//   * 'F' wipe-on-mismatch (the dmn_D3->D4 idiom) and the startup verify
//     ('B' sentinel cross-check + newest snapshot pair)

#include <gtest/gtest.h>

#include <impl/dash/coin/mn_diff_store.hpp>
#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>

#include <cstring>
#include <filesystem>
#include <iterator>
#include <map>
#include <unistd.h>
#include <optional>
#include <string>
#include <vector>

using namespace dash::coin::replay;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;

namespace {

uint256 h256(uint64_t v)
{
    uint256 h;
    std::memset(h.data(), 0, 32);
    std::memcpy(h.data(), &v, sizeof(v));
    return h;
}

ReplayMNState make_state(uint64_t i)
{
    ReplayMNState st;
    st.internalId              = i;
    st.collateralOutpoint.hash = h256(0x10000 + i);
    st.collateralOutpoint.index = 1;
    st.nRegisteredHeight       = static_cast<int32_t>(1000 + i);
    st.nLastPaidHeight         = static_cast<int32_t>(2000 + i);
    st.keyIDOwner              = uint160{};
    st.pubKeyOperator[0]       = static_cast<uint8_t>(0x40 + i);
    st.netInfo.ip[15]          = static_cast<uint8_t>(i + 1);
    st.netInfo.port_be         = 9999;
    st.scriptPayout.m_data     = {0x76, 0xa9, 0x14, static_cast<uint8_t>(i),
                                  0x88, 0xac};
    return st;
}

DmlFoldEngine::Entries make_list(size_t n)
{
    DmlFoldEngine::Entries e;
    for (size_t i = 0; i < n; ++i) e.emplace(h256(i + 1), make_state(i));
    return e;
}

uint256 sml_root_of(const DmlFoldEngine::Entries& list)
{
    std::vector<CSimplifiedMNListEntry> ents;
    ents.reserve(list.size());
    for (const auto& [protx, st] : list) ents.push_back(st.to_sml_entry(protx));
    CSimplifiedMNList sml(std::move(ents));
    return sml.CalcMerkleRoot();
}

std::string fresh_db_dir(const char* name)
{
    const auto dir = std::filesystem::temp_directory_path()
                   / ("c2pool_mn_diff_store_kat_" + std::string(name) + "_"
                      + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return (dir / "db").string();
}

std::vector<uint8_t> record_bytes(const MnListDiff& d, const uint256& prev,
                                  const uint256& root, uint8_t flags,
                                  uint64_t trc)
{
    MnDiffRecord rec;
    rec.prev_hash              = prev;
    rec.merkle_root_mn_list    = root;
    rec.flags                  = flags;
    rec.total_registered_count = trc;
    rec.diff                   = d;
    return rec.encode();
}

/// Synthetic hash-linked chain: hash(h) = h256(0xA00000 + h).
uint256 chain_hash(uint32_t h) { return h256(0xA00000ull + h); }

MnDiffStore::HeaderLookupFn synth_headers(uint32_t max_h)
{
    return [max_h](const uint256& hash)
        -> std::optional<std::pair<uint32_t, uint256>> {
        for (uint32_t h = 0; h <= max_h; ++h) {
            if (chain_hash(h) == hash) {
                return std::make_pair(
                    h, h == 0 ? uint256{} : chain_hash(h - 1));
            }
        }
        return std::nullopt;
    };
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// MnStateDiff — the dashd bitmask semantics
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMnDiffStore, StateDiffMasksExactlyTheChangedField)
{
    ReplayMNState a = make_state(1);
    ReplayMNState b = a;
    b.nLastPaidHeight = 777;
    MnStateDiff d(a, b);
    EXPECT_EQ(d.fields, MnStateDiff::Field_nLastPaidHeight);

    // apply reproduces b from a
    ReplayMNState t = a;
    d.apply_to(t);
    EXPECT_TRUE(t == b);

    // codec round-trip
    ::PackStream s;
    d.write_to(s);
    auto sp = s.get_span();
    std::vector<uint8_t> bytes(
        reinterpret_cast<const uint8_t*>(sp.data()),
        reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
    ::PackStream in(bytes);
    MnStateDiff d2;
    d2.read_from(in);
    EXPECT_EQ(d2.fields, d.fields);
    ReplayMNState t2 = a;
    d2.apply_to(t2);
    EXPECT_TRUE(t2 == b);
}

TEST(DashMnDiffStore, StateDiffNetInfoAndOperatorKeyForceVersionBit)
{
    // dashd dmnstate.h:237-241: pubKeyOperator/netInfo need nVersion.
    {
        ReplayMNState a = make_state(1), b = a;
        b.netInfo.port_be = 12345;
        MnStateDiff d(a, b);
        EXPECT_TRUE(d.fields & MnStateDiff::Field_netInfo);
        EXPECT_TRUE(d.fields & MnStateDiff::Field_nVersion);
    }
    {
        ReplayMNState a = make_state(1), b = a;
        b.pubKeyOperator[5] = 0xEE;
        MnStateDiff d(a, b);
        EXPECT_TRUE(d.fields & MnStateDiff::Field_pubKeyOperator);
        EXPECT_TRUE(d.fields & MnStateDiff::Field_nVersion);
    }
    // The deser guard refuses the invalid combination (dashd throws the same).
    {
        ::PackStream s;
        WriteCompactSize(s, MnStateDiff::Field_netInfo);   // no nVersion bit
        auto sp = s.get_span();
        std::vector<uint8_t> bytes(
            reinterpret_cast<const uint8_t*>(sp.data()),
            reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
        ::PackStream in(bytes);
        MnStateDiff d;
        EXPECT_THROW(d.read_from(in), std::ios_base::failure);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MnListDiff — BuildDiff/ApplyDiff (deterministicmns.cpp:361-418)
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMnDiffStore, ListDiffBuildApplyRoundTrip)
{
    auto from = make_list(3);                       // internalIds 0,1,2
    auto to   = from;
    to.erase(h256(3));                              // remove internalId 2
    to.at(h256(2)).nLastPaidHeight = 555;           // update internalId 1
    ReplayMNState add_b = make_state(9);            // internalId 9
    ReplayMNState add_a = make_state(8);            // internalId 8
    to.emplace(h256(20), add_b);
    to.emplace(h256(21), add_a);

    auto d = MnListDiff::build(from, to);
    ASSERT_EQ(d.added.size(), 2u);
    // sorted ASCENDING by internalId (deterministicmns.cpp:383-386)
    EXPECT_EQ(d.added[0].second.internalId, 8u);
    EXPECT_EQ(d.added[1].second.internalId, 9u);
    ASSERT_EQ(d.updated.size(), 1u);
    EXPECT_EQ(d.updated.begin()->first, 1u);
    ASSERT_EQ(d.removed.size(), 1u);
    EXPECT_EQ(*d.removed.begin(), 2u);

    // encode through the record codec and back
    auto bytes = record_bytes(d, chain_hash(0), sml_root_of(to),
                              MnDiffRecord::kFlagRootMatched
                                  | MnDiffRecord::kFlagPayeeVerified,
                              10);
    MnDiffRecord rec;
    std::string err;
    ASSERT_TRUE(MnDiffRecord::decode(bytes, rec, err)) << err;

    auto applied = from;
    ASSERT_TRUE(rec.diff.apply(applied, err)) << err;
    EXPECT_TRUE(applied == to);
}

TEST(DashMnDiffStore, EmptyDiffIsARealRecord)
{
    // The empty record is proof-of-processing: skipping empties turns "no
    // change at h" into an indistinguishable gap (the dashd gotcha).
    auto list = make_list(2);
    auto d = MnListDiff::build(list, list);
    EXPECT_TRUE(d.empty());
    auto bytes = record_bytes(d, chain_hash(0), sml_root_of(list),
                              MnDiffRecord::kFlagRootMatched
                                  | MnDiffRecord::kFlagPayeeVerified,
                              2);
    MnDiffRecord rec;
    std::string err;
    ASSERT_TRUE(MnDiffRecord::decode(bytes, rec, err)) << err;
    EXPECT_TRUE(rec.diff.empty());
    auto applied = list;
    ASSERT_TRUE(rec.diff.apply(applied, err)) << err;
    EXPECT_TRUE(applied == list);
}

TEST(DashMnDiffStore, RecordDigestCorruptionRefuses)
{
    auto list = make_list(2);
    auto d = MnListDiff::build(make_list(1), list);
    auto bytes = record_bytes(d, chain_hash(0), sml_root_of(list), 3, 2);
    bytes[bytes.size() / 2] ^= 0xFF;
    MnDiffRecord rec;
    std::string err;
    EXPECT_FALSE(MnDiffRecord::decode(bytes, rec, err));
    EXPECT_NE(err.find("digest"), std::string::npos) << err;
}

TEST(DashMnDiffStore, ApplyRefusesEveryBaseStateMismatch)
{
    // dashd ApplyDiff THROWS on each of these (deterministicmns.cpp:396-447);
    // ours refuses — a throw is never a skip.
    auto base = make_list(2);   // internalIds 0,1
    std::string err;

    { // removed id not present
        MnListDiff d;
        d.removed.insert(77);
        auto l = base;
        EXPECT_FALSE(d.apply(l, err));
        EXPECT_NE(err.find("removed"), std::string::npos) << err;
    }
    { // updated id not present
        MnListDiff d;
        d.updated.emplace(77, MnStateDiff{});
        auto l = base;
        EXPECT_FALSE(d.apply(l, err));
        EXPECT_NE(err.find("updated"), std::string::npos) << err;
    }
    { // duplicate proTxHash
        MnListDiff d;
        d.added.emplace_back(h256(1), make_state(9));
        auto l = base;
        EXPECT_FALSE(d.apply(l, err));
        EXPECT_NE(err.find("proTxHash"), std::string::npos) << err;
    }
    { // duplicate internalId
        MnListDiff d;
        d.added.emplace_back(h256(50), make_state(1));   // internalId 1 taken
        auto l = base;
        EXPECT_FALSE(d.apply(l, err));
        EXPECT_NE(err.find("internalId"), std::string::npos) << err;
    }
    { // duplicate collateralOutpoint (unique-property violation)
        MnListDiff d;
        ReplayMNState st  = make_state(9);
        st.collateralOutpoint = base.at(h256(1)).collateralOutpoint;
        d.added.emplace_back(h256(50), st);
        auto l = base;
        EXPECT_FALSE(d.apply(l, err));
        EXPECT_NE(err.find("collateralOutpoint"), std::string::npos) << err;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// The store: format wipe, walk, refusals
// ═══════════════════════════════════════════════════════════════════════════

/// Writes a snapshot at h0 and diff records for h1..hN over a synthetic
/// hash-linked chain, mutating the list once per block. Returns the final
/// list per height.
struct SynthChain
{
    std::vector<DmlFoldEngine::Entries> lists;   // index = height
    uint64_t trc{0};

    static SynthChain build(MnDiffStore& store, uint32_t n_blocks,
                            uint8_t flags = MnDiffRecord::kFlagRootMatched
                                          | MnDiffRecord::kFlagPayeeVerified,
                            uint32_t skip_height = 0)
    {
        SynthChain c;
        c.lists.push_back(make_list(3));
        c.trc = 3;

        // grounding snapshot at h0 (the seed/anchor row)
        DmlFoldEngine eng{FoldConfig{}};
        std::vector<std::pair<uint256, ReplayMNState>> seed;
        for (const auto& [k, v] : c.lists[0]) seed.emplace_back(k, v);
        eng.seed(std::move(seed), c.trc, 0, chain_hash(0));
        EXPECT_TRUE(store.put_snapshot(chain_hash(0), eng.save_snapshot()));

        for (uint32_t h = 1; h <= n_blocks; ++h) {
            auto next = c.lists.back();
            // one mutation per block, cycling add/update/remove
            if (h % 3 == 1) {
                ReplayMNState st = make_state(c.trc);
                next.emplace(h256(0x900 + h), st);
                ++c.trc;
            } else if (h % 3 == 2) {
                next.begin()->second.nLastPaidHeight =
                    static_cast<int32_t>(3000 + h);
            } else if (next.size() > 1) {
                next.erase(std::prev(next.end()));
            }
            auto d = MnListDiff::build(c.lists.back(), next);
            MnDiffRecord rec;
            rec.prev_hash              = chain_hash(h - 1);
            rec.merkle_root_mn_list    = sml_root_of(next);
            rec.flags                  = flags;
            rec.total_registered_count = c.trc;
            rec.diff                   = d;
            if (h != skip_height)
                EXPECT_TRUE(store.put_block(chain_hash(h), h, rec, nullptr));
            c.lists.push_back(std::move(next));
        }
        return c;
    }
};

TEST(DashMnDiffStore, ReconstructWalksSnapshotPlusDiffs)
{
    MnDiffStore store(fresh_db_dir("walk"));
    ASSERT_TRUE(store.open());
    auto c = SynthChain::build(store, 5);

    DmlFoldEngine::Entries out;
    uint64_t trc = 0;
    std::string err;
    ASSERT_TRUE(store.reconstruct(chain_hash(5), synth_headers(5), out, trc,
                                  err)) << err;
    EXPECT_TRUE(out == c.lists[5]);
    // internalId assignment restart-reproducible via the stored counter
    EXPECT_EQ(trc, c.trc);

    // ... and an interior height reconstructs to ITS list, not the tip's.
    ASSERT_TRUE(store.reconstruct(chain_hash(3), synth_headers(5), out, trc,
                                  err)) << err;
    EXPECT_TRUE(out == c.lists[3]);
}

TEST(DashMnDiffStore, MissingMiddleRowRefusesNeverEmptyList)
{
    // THE fail-closed inversion: dashd's "no snapshot AND no diff => initial
    // empty list" (deterministicmns.cpp:813-819) would silently ground the
    // walk here; ours refuses.
    MnDiffStore store(fresh_db_dir("hole"));
    ASSERT_TRUE(store.open());
    SynthChain::build(store, 5, MnDiffRecord::kFlagRootMatched
                                    | MnDiffRecord::kFlagPayeeVerified,
                      /*skip_height=*/3);

    DmlFoldEngine::Entries out;
    uint64_t trc = 0;
    std::string err;
    EXPECT_FALSE(store.reconstruct(chain_hash(5), synth_headers(5), out, trc,
                                   err));
    EXPECT_NE(err.find("REPAIR-REFUSED"), std::string::npos) << err;
    EXPECT_TRUE(out.empty());
}

TEST(DashMnDiffStore, ProofFlagHoleRefusesWholeRange)
{
    // A single payee-unverified record poisons the range: merkleRootMNList
    // does not commit nLastPaidHeight (G9 semantics).
    MnDiffStore store(fresh_db_dir("flags"));
    ASSERT_TRUE(store.open());
    SynthChain::build(store, 4, MnDiffRecord::kFlagRootMatched); // no payee bit

    DmlFoldEngine::Entries out;
    uint64_t trc = 0;
    std::string err;
    EXPECT_FALSE(store.reconstruct(chain_hash(4), synth_headers(4), out, trc,
                                   err));
    EXPECT_NE(err.find("payee_verified"), std::string::npos) << err;
}

TEST(DashMnDiffStore, OrphanedSiblingRowDoesNotConfuseTheWalk)
{
    // Hash keying disambiguates same-height siblings (a reorged branch's
    // rows are harmless residue — dashd UndoBlock keeps disk rows too).
    MnDiffStore store(fresh_db_dir("sibling"));
    ASSERT_TRUE(store.open());
    auto c = SynthChain::build(store, 4);

    // A sibling record at height 3 on a dead branch, keyed by a different
    // hash, with garbage prev linkage.
    MnDiffRecord orphan;
    orphan.prev_hash           = h256(0xDEAD);
    orphan.merkle_root_mn_list = h256(0xBEEF);
    orphan.flags = MnDiffRecord::kFlagRootMatched
                 | MnDiffRecord::kFlagPayeeVerified;
    ASSERT_TRUE(store.put_block(h256(0xFACE), 3, orphan, nullptr));

    DmlFoldEngine::Entries out;
    uint64_t trc = 0;
    std::string err;
    ASSERT_TRUE(store.reconstruct(chain_hash(4), synth_headers(4), out, trc,
                                  err)) << err;
    EXPECT_TRUE(out == c.lists[4]);
}

TEST(DashMnDiffStore, RecordPrevHashMustMatchHeaderChain)
{
    // The record is self-spanning but never trusted alone: a record whose
    // prev_hash disagrees with the PoW-validated header chain refuses.
    MnDiffStore store(fresh_db_dir("prevmismatch"));
    ASSERT_TRUE(store.open());
    auto c = SynthChain::build(store, 2);

    MnDiffRecord bad;
    bad.prev_hash           = h256(0x666);      // NOT chain_hash(2)
    bad.merkle_root_mn_list = sml_root_of(c.lists[2]);
    bad.flags = MnDiffRecord::kFlagRootMatched
              | MnDiffRecord::kFlagPayeeVerified;
    bad.total_registered_count = c.trc;
    ASSERT_TRUE(store.put_block(chain_hash(3), 3, bad, nullptr));

    DmlFoldEngine::Entries out;
    uint64_t trc = 0;
    std::string err;
    EXPECT_FALSE(store.reconstruct(chain_hash(3), synth_headers(3), out, trc,
                                   err));
    EXPECT_NE(err.find("header-chain prev"), std::string::npos) << err;
}

TEST(DashMnDiffStore, FinalRootMismatchRefuses)
{
    // verify-then-trust: the reconstructed list must re-hash to the root the
    // target block committed.
    MnDiffStore store(fresh_db_dir("rootbad"));
    ASSERT_TRUE(store.open());
    auto c = SynthChain::build(store, 2);

    // h3's record claims a WRONG committed root.
    auto next = c.lists[2];
    next.begin()->second.nLastPaidHeight = 4444;
    auto d = MnListDiff::build(c.lists[2], next);
    MnDiffRecord rec;
    rec.prev_hash              = chain_hash(2);
    rec.merkle_root_mn_list    = h256(0x777);   // not sml_root_of(next)
    rec.flags = MnDiffRecord::kFlagRootMatched
              | MnDiffRecord::kFlagPayeeVerified;
    rec.total_registered_count = c.trc;
    rec.diff                   = d;
    ASSERT_TRUE(store.put_block(chain_hash(3), 3, rec, nullptr));

    DmlFoldEngine::Entries out;
    uint64_t trc = 0;
    std::string err;
    EXPECT_FALSE(store.reconstruct(chain_hash(3), synth_headers(3), out, trc,
                                   err));
    EXPECT_NE(err.find("re-hashes"), std::string::npos) << err;
}

TEST(DashMnDiffStore, FormatMismatchWipesWholeStore)
{
    // The dmn_D3->D4 idiom: wipe-on-mismatch, never per-entry migration
    // (the MnStateDb v1->v2 silently-skipped-rows counterexample).
    const std::string dir = fresh_db_dir("format");
    {
        MnDiffStore store(dir);
        ASSERT_TRUE(store.open());
        SynthChain::build(store, 2);
        ASSERT_TRUE(store.has_diff(chain_hash(1)));
    }
    {   // corrupt the 'F' key out-of-band
        ::core::LevelDBStore raw(dir, {});
        ASSERT_TRUE(raw.open());
        raw.put("F", {0x63, 0x00, 0x00, 0x00});   // v99
        raw.close();
    }
    {
        MnDiffStore store(dir);
        ASSERT_TRUE(store.open());
        EXPECT_FALSE(store.has_diff(chain_hash(1)))
            << "format mismatch must clear the WHOLE store";
        EXPECT_FALSE(store.has_snapshot(chain_hash(0)));
    }
}

TEST(DashMnDiffStore, StartupVerifySentinelCrossCheckWipes)
{
    // dashd EVODB_BEST_BLOCK posture (validation.cpp:2322/:2707): a sentinel
    // naming a row that does not decode wipes the store (ALONE).
    const std::string dir = fresh_db_dir("sentinel");
    {
        MnDiffStore store(dir);
        ASSERT_TRUE(store.open());
        SynthChain::build(store, 2);
    }
    {   // corrupt the newest 'D' row out-of-band
        ::core::LevelDBStore raw(dir, {});
        ASSERT_TRUE(raw.open());
        std::string key(1, 'D');
        key.append(reinterpret_cast<const char*>(chain_hash(2).data()), 32);
        raw.put(key, {0x01, 0x02, 0x03});
        raw.close();
    }
    {
        MnDiffStore store(dir);
        ASSERT_TRUE(store.open());
        std::string note;
        ASSERT_TRUE(store.startup_verify(synth_headers(2), note));
        EXPECT_NE(note.find("wiping store"), std::string::npos) << note;
        EXPECT_FALSE(store.has_diff(chain_hash(1)));
    }
}

TEST(DashMnDiffStore, StartupVerifyNewestPairPassesAndFailsClosed)
{
    // VerifySnapshotPair analogue, scope-reduced to the newest pair:
    // re-derive the newest snapshot from the previous one via stored diffs.
    const std::string dir = fresh_db_dir("pair");
    {
        MnDiffStore store(dir);
        ASSERT_TRUE(store.open());
        auto c = SynthChain::build(store, 4);
        // write a second snapshot at h4 (the test's "cadence" row)
        DmlFoldEngine eng{FoldConfig{}};
        std::vector<std::pair<uint256, ReplayMNState>> seed;
        for (const auto& [k, v] : c.lists[4]) seed.emplace_back(k, v);
        eng.seed(std::move(seed), c.trc, 4, chain_hash(4));
        ASSERT_TRUE(store.put_snapshot(chain_hash(4), eng.save_snapshot()));

        std::string note;
        ASSERT_TRUE(store.startup_verify(synth_headers(4), note));
        EXPECT_NE(note.find("verified"), std::string::npos) << note;
        EXPECT_TRUE(store.has_diff(chain_hash(1)))
            << "a passing verify must not wipe anything";
    }
    // Now a pair whose connecting diffs have a hole: wipe.
    const std::string dir2 = fresh_db_dir("pairhole");
    {
        MnDiffStore store(dir2);
        ASSERT_TRUE(store.open());
        auto c = SynthChain::build(store, 4,
                                   MnDiffRecord::kFlagRootMatched
                                       | MnDiffRecord::kFlagPayeeVerified,
                                   /*skip_height=*/2);
        DmlFoldEngine eng{FoldConfig{}};
        std::vector<std::pair<uint256, ReplayMNState>> seed;
        for (const auto& [k, v] : c.lists[4]) seed.emplace_back(k, v);
        eng.seed(std::move(seed), c.trc, 4, chain_hash(4));
        ASSERT_TRUE(store.put_snapshot(chain_hash(4), eng.save_snapshot()));

        std::string note;
        ASSERT_TRUE(store.startup_verify(synth_headers(4), note));
        EXPECT_NE(note.find("wiping store"), std::string::npos) << note;
        EXPECT_FALSE(store.has_snapshot(chain_hash(4)));
    }
}

TEST(DashMnDiffStore, WalkDepthBoundRefuses)
{
    // >576 diffs without a snapshot refuses (the cadence guarantees a
    // grounding row within 576 on a healthy store).
    MnDiffStore store(fresh_db_dir("depth"));
    ASSERT_TRUE(store.open());
    const uint32_t n = MnDiffStore::kSnapshotPeriod + 2;   // 578 blocks
    auto list = make_list(2);
    const auto root = sml_root_of(list);
    // NO grounding snapshot at h0 — every row is an (empty) diff.
    for (uint32_t h = 1; h <= n; ++h) {
        MnDiffRecord rec;
        rec.prev_hash              = chain_hash(h - 1);
        rec.merkle_root_mn_list    = root;
        rec.flags = MnDiffRecord::kFlagRootMatched
                  | MnDiffRecord::kFlagPayeeVerified;
        rec.total_registered_count = 2;
        ASSERT_TRUE(store.put_block(chain_hash(h), h, rec, nullptr));
    }
    DmlFoldEngine::Entries out;
    uint64_t trc = 0;
    std::string err;
    EXPECT_FALSE(store.reconstruct(chain_hash(n), synth_headers(n), out, trc,
                                   err));
    EXPECT_NE(err.find("exceeded"), std::string::npos) << err;
}

TEST(DashMnDiffStore, TargetOffOurHeaderChainRefuses)
{
    MnDiffStore store(fresh_db_dir("offchain"));
    ASSERT_TRUE(store.open());
    SynthChain::build(store, 2);
    DmlFoldEngine::Entries out;
    uint64_t trc = 0;
    std::string err;
    EXPECT_FALSE(store.reconstruct(h256(0x123456), synth_headers(2), out, trc,
                                   err));
    EXPECT_NE(err.find("header chain"), std::string::npos) << err;
}
