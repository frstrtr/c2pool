// SPDX-License-Identifier: AGPL-3.0-or-later
//
// #946 found-block store KATs — the explorer keeps found LTC/DOGE blocks
// visible after their share ages out of the chain, so the fblk/mblk records on
// disk are the only source once that happens. These pin:
//
//   * every record a pre-#946 node wrote still loads: fblk v1 + v2 (DASH lands
//     here too, via main_dash) and mblk v1, byte-built exactly as the old
//     serializers laid them out;
//   * the fblk v3 + v4 / mblk v2 tails are pure appends, and an unknown value stays
//     unknown (empty / nullopt), never "" or 0 — a known tx_count of 0 and an
//     unknown one stay distinct, even across a truncated tail;
//   * a short read consumes the rest of the record, so a cut field never leaks
//     into the next one; a cut inside the v1 body drops the row;
//   * a DOGE row's parent_hash / parent_height (fblk v4) survive a restart,
//     and a v3 record (no parent tail) restores with the parent unknown;
//   * update_coinbase reaches the newest DOGE record past 1000 stored ones
//     (it used to scan list_keys("mblk:", 1000) oldest first);
//   * find_by_hash answers only for the FULL hash, although the key holds the
//     first 16 hex chars.
//
// Display-path storage only; no consensus surface is reachable from here.

#include <gtest/gtest.h>

#include <c2pool/storage/found_block_store.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>   // MiningInterface: the found-block rows this store persists

#include "found_block_records_2e6db7b5f.hpp"   // the earlier build's own record serializers

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <limits>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

using c2pool::storage::FoundBlockRecord;
using c2pool::storage::FoundBlockStore;
using c2pool::storage::MergedBlockRecord;
using c2pool::storage::MergedBlockStore;

namespace {

// Little-endian byte writer matching the old serializers' layout.
struct Bytes {
    std::vector<uint8_t> v;
    Bytes& u8(uint8_t x) { v.push_back(x); return *this; }
    Bytes& u32(uint32_t x) { for (int i = 0; i < 4; ++i) v.push_back(uint8_t(x >> (8 * i))); return *this; }
    Bytes& u64(uint64_t x) { for (int i = 0; i < 8; ++i) v.push_back(uint8_t(x >> (8 * i))); return *this; }
    Bytes& str(const std::string& s) { u8(uint8_t(s.size())); v.insert(v.end(), s.begin(), s.end()); return *this; }
    Bytes& dbl(double d) { uint64_t b; std::memcpy(&b, &d, 8); return u64(b); }
};

// The bytes each serializer writes after its last versioned tail: the fblk
// extension byte (aux_difficulty_known) and the mblk aux difficulty (a u64).
constexpr size_t kFblkExt = 1;
constexpr size_t kMblkExt = 8;

// Two 64-char hashes sharing their first 16 chars (the part the key keeps).
const std::string kHashA = std::string(16, '5') + std::string(48, 'a');
const std::string kHashB = std::string(16, '5') + std::string(48, 'b');

// fblk v1 body (everything after the version byte), as pre-#159 nodes wrote it.
Bytes fblk_v1_body()
{
    Bytes b;
    b.str("DASH").u64(2531045).str(kHashA).u64(1788182946)
     .u8(1).u8(3).u64(1788183000).u32(300).str("Xminer").u64(225000000);
    return b;
}

// fblk v2 = v1 body + #159 enrichment tail.
Bytes fblk_v2_record()
{
    Bytes b; b.u8(2);
    auto body = fblk_v1_body();
    b.v.insert(b.v.end(), body.v.begin(), body.v.end());
    b.dbl(1.5).dbl(240228.0).dbl(4294967296.0).str(kHashA).u8(2);
    return b;
}

// mblk v1, the only version the pre-#946 reader accepted.
Bytes mblk_v1_record(uint32_t chain_id, uint32_t height, const std::string& hash)
{
    Bytes b; b.u8(1);
    b.u32(chain_id).str("DOGE").u32(height).str(hash).str("parenthash")
     .u64(1788182946).u8(1 | 2).u64(1000000000000ULL).u32(2900000).str("Dminer");
    return b;
}

std::string fblk_key(const std::string& chain, uint64_t height, const std::string& hash)
{
    char h[13]; std::snprintf(h, sizeof(h), "%012llu", static_cast<unsigned long long>(height));
    return "fblk:" + chain + ":" + h + ":" + hash.substr(0, 16);
}

std::string mblk_key(uint32_t chain_id, int height, const std::string& hash)
{
    char h[13]; std::snprintf(h, sizeof(h), "%012d", height);
    return "mblk:" + std::to_string(chain_id) + ":" + h + ":" + hash.substr(0, 16);
}

std::string hash_n(uint32_t n)
{
    char buf[65]; std::snprintf(buf, sizeof(buf), "%064x", n);
    return buf;
}

// Unique per process + call so parallel ctest workers never share a LOCK.
std::string fresh_db_dir(const std::string& name)
{
    static std::atomic<uint64_t> seq{0};
    std::filesystem::path p = std::filesystem::path(testing::TempDir()) /
        (name + "_pid" + std::to_string(static_cast<long long>(::getpid())) +
         "_n" + std::to_string(seq.fetch_add(1)));
    std::error_code ec;
    std::filesystem::remove_all(p, ec);
    return p.string();
}

struct TempDb {
    std::string path;
    core::LevelDBStore db;
    explicit TempDb(const std::string& name)
        : path(fresh_db_dir(name)), db(path, core::LevelDBOptions{}) {}
    ~TempDb() { db.close(); std::error_code ec; std::filesystem::remove_all(path, ec); }
};

} // namespace

// ── fblk ─────────────────────────────────────────────────────────────────────

TEST(FoundBlockStoreKat, FblkV1RecordRestores)
{
    Bytes b; b.u8(1);
    auto body = fblk_v1_body();
    b.v.insert(b.v.end(), body.v.begin(), body.v.end());

    auto rec = FoundBlockRecord::deserialize(b.v);
    EXPECT_EQ(rec.chain, "DASH");
    EXPECT_EQ(rec.height, 2531045u);
    EXPECT_EQ(rec.block_hash, kHashA);
    EXPECT_EQ(rec.timestamp, 1788182946u);
    EXPECT_EQ(rec.status, 1);
    EXPECT_EQ(rec.check_count, 3);
    EXPECT_EQ(rec.last_checked, 1788183000u);
    EXPECT_EQ(rec.confirmations, 300u);
    EXPECT_EQ(rec.finder_address, "Xminer");
    EXPECT_EQ(rec.reward_satoshis, 225000000u);
    EXPECT_TRUE(rec.share_hash.empty());
    EXPECT_TRUE(rec.coinbase_txid.empty());
    EXPECT_FALSE(rec.tx_count.has_value());
}

TEST(FoundBlockStoreKat, FblkV2DashRecordRestores)
{
    auto rec = FoundBlockRecord::deserialize(fblk_v2_record().v);
    EXPECT_EQ(rec.block_hash, kHashA);
    EXPECT_EQ(rec.reward_satoshis, 225000000u);
    EXPECT_DOUBLE_EQ(rec.network_difficulty, 1.5);
    EXPECT_DOUBLE_EQ(rec.share_difficulty, 240228.0);
    EXPECT_DOUBLE_EQ(rec.pool_hashrate, 4294967296.0);
    EXPECT_EQ(rec.share_hash, kHashA);
    EXPECT_EQ(rec.authorship, 2);
    EXPECT_TRUE(rec.coinbase_txid.empty());
    EXPECT_FALSE(rec.tx_count.has_value());
}

TEST(FoundBlockStoreKat, FblkV3IsAPureAppendAndRoundTrips)
{
    auto rec = FoundBlockRecord::deserialize(fblk_v2_record().v);
    auto v2 = fblk_v2_record().v;

    // Unknown body fields: the v3 bytes after the version byte start with the
    // exact v2 body.
    auto out = rec.serialize();
    ASSERT_EQ(out[0], 4);
    ASSERT_GT(out.size(), v2.size());
    EXPECT_TRUE(std::equal(v2.begin() + 1, v2.end(), out.begin() + 1));
    auto back = FoundBlockRecord::deserialize(out);
    EXPECT_EQ(back.share_hash, kHashA);
    EXPECT_TRUE(back.coinbase_txid.empty());
    EXPECT_FALSE(back.tx_count.has_value());

    // A known tx_count of 0 must stay 0, not collapse to unknown.
    rec.coinbase_txid = hash_n(0xc0ffee);
    rec.tx_count = 0;
    back = FoundBlockRecord::deserialize(rec.serialize());
    EXPECT_EQ(back.coinbase_txid, hash_n(0xc0ffee));
    ASSERT_TRUE(back.tx_count.has_value());
    EXPECT_EQ(*back.tx_count, 0u);

    rec.tx_count = 1234;
    back = FoundBlockRecord::deserialize(rec.serialize());
    ASSERT_TRUE(back.tx_count.has_value());
    EXPECT_EQ(*back.tx_count, 1234u);
    EXPECT_DOUBLE_EQ(back.share_difficulty, 240228.0);
}

TEST(FoundBlockStoreKat, TruncatedTailLeavesTxCountUnknown)
{
    FoundBlockRecord f = FoundBlockRecord::deserialize(fblk_v2_record().v);
    f.tx_count = 7;
    auto fb = f.serialize();
    // Cuts the v3 tail: drops the extension byte, the empty v4 parent tail
    // (len + flag + u64) and the last 2 bytes of the tx_count u32.
    fb.resize(fb.size() - kFblkExt - (1 + 1 + 8) - 2);
    auto back = FoundBlockRecord::deserialize(fb);
    EXPECT_EQ(back.block_hash, kHashA);
    EXPECT_FALSE(back.tx_count.has_value());
    EXPECT_TRUE(back.parent_hash.empty());
    EXPECT_FALSE(back.parent_height.has_value());

    MergedBlockRecord m = MergedBlockRecord::deserialize(mblk_v1_record(98, 1, kHashA).v);
    m.tx_count = 7;
    auto mb = m.serialize();
    mb.resize(mb.size() - kMblkExt - 2);   // the difficulty, then 2 of tx_count
    EXPECT_FALSE(MergedBlockRecord::deserialize(mb).tx_count.has_value());
}

TEST(FoundBlockStoreKat, CutTxCountDoesNotLeakIntoTheParentTail)
{
    // A short read used to leave pos in place, so the kept tx_count bytes were
    // read again as the v4 parent_hash length + body. tx_count=1 is common on
    // DASH: keeping 2 of its 4 bytes gave parent_hash = "\x00".
    FoundBlockRecord f = FoundBlockRecord::deserialize(fblk_v2_record().v);
    for (auto [tx_count, kept] : {std::pair<uint32_t, size_t>{1, 2}, {1, 3}, {258, 3}}) {
        f.tx_count = tx_count;
        auto fb = f.serialize();
        fb.resize(fb.size() - kFblkExt - (1 + 1 + 8) - (4 - kept));
        auto back = FoundBlockRecord::deserialize(fb);
        EXPECT_EQ(back.block_hash, kHashA) << tx_count << "/" << kept;
        EXPECT_FALSE(back.tx_count.has_value()) << tx_count << "/" << kept;
        EXPECT_TRUE(back.parent_hash.empty()) << tx_count << "/" << kept;
        EXPECT_FALSE(back.parent_height.has_value()) << tx_count << "/" << kept;
    }
}

TEST(FoundBlockStoreKat, CutV1BodyDropsTheRow)
{
    // fblk cut inside the v1 timestamp (4 of 8 bytes kept): it used to restore
    // with ts=0 and the leftover bytes as status/check_count.
    Bytes v1; v1.u8(1);
    auto body = fblk_v1_body();
    v1.v.insert(v1.v.end(), body.v.begin(), body.v.end());
    auto fcut = v1.v;
    fcut.resize(1 + (1 + 4) + 8 + (1 + 64) + 4);
    EXPECT_TRUE(FoundBlockRecord::deserialize(fcut).block_hash.empty());

    // mblk cut inside the v1 parent_height (2 of 4 bytes kept, miner gone).
    auto mcut = mblk_v1_record(98, 5400000, kHashB).v;
    mcut.resize(mcut.size() - (1 + 6) - 2);
    EXPECT_TRUE(MergedBlockRecord::deserialize(mcut).block_hash.empty());

    // load_all skips the damaged rows and keeps the whole ones; update_status
    // leaves a damaged row's bytes alone.
    TempDb t("fblk_cut_v1");
    ASSERT_TRUE(t.db.open());
    FoundBlockStore fstore(t.db);
    MergedBlockStore mstore(t.db);
    ASSERT_TRUE(t.db.put(fblk_key("DASH", 2531045, kHashA), v1.v));
    ASSERT_TRUE(t.db.put(fblk_key("DASH", 2531046, kHashB), fcut));
    ASSERT_TRUE(t.db.put(mblk_key(98, 5400000, kHashA), mblk_v1_record(98, 5400000, kHashA).v));
    ASSERT_TRUE(t.db.put(mblk_key(98, 5400001, kHashB), mcut));

    auto fall = fstore.load_all();
    ASSERT_EQ(fall.size(), 1u);
    EXPECT_EQ(fall[0].block_hash, kHashA);
    auto mall = mstore.load_all();
    ASSERT_EQ(mall.size(), 1u);
    EXPECT_EQ(mall[0].block_hash, kHashA);

    EXPECT_FALSE(fstore.update_status("DASH", 2531046, kHashB, 2, 1, 1));
    std::vector<uint8_t> still;
    ASSERT_TRUE(t.db.get(fblk_key("DASH", 2531046, kHashB), still));
    EXPECT_EQ(still, fcut);
}

TEST(FoundBlockStoreKat, FblkV3RecordRestoresWithParentUnknown)
{
    // fblk v3 = v2 body + #946 explorer tail, as the pre-v4 writer left it.
    auto v2 = fblk_v2_record();
    Bytes b; b.u8(3);
    b.v.insert(b.v.end(), v2.v.begin() + 1, v2.v.end());
    b.str(hash_n(0xcb)).u8(1).u32(42);
    auto rec = FoundBlockRecord::deserialize(b.v);
    EXPECT_EQ(rec.block_hash, kHashA);
    EXPECT_EQ(rec.coinbase_txid, hash_n(0xcb));
    ASSERT_TRUE(rec.tx_count.has_value());
    EXPECT_EQ(*rec.tx_count, 42u);
    EXPECT_TRUE(rec.parent_hash.empty());
    EXPECT_FALSE(rec.parent_height.has_value());

    // v4 rewrite keeps the v3 bytes as its prefix.
    auto out = rec.serialize();
    ASSERT_EQ(out[0], 4);
    EXPECT_TRUE(std::equal(b.v.begin() + 1, b.v.end(), out.begin() + 1));
}

TEST(FoundBlockStoreKat, FblkV4CarriesTheMergedParent)
{
    FoundBlockRecord rec = FoundBlockRecord::deserialize(fblk_v2_record().v);
    rec.chain = "DOGE";
    rec.parent_hash = hash_n(0x17c);
    rec.parent_height = 2900001;
    auto back = FoundBlockRecord::deserialize(rec.serialize());
    EXPECT_EQ(back.chain, "DOGE");
    EXPECT_EQ(back.parent_hash, hash_n(0x17c));
    ASSERT_TRUE(back.parent_height.has_value());
    EXPECT_EQ(*back.parent_height, 2900001u);
    EXPECT_EQ(back.share_hash, kHashA);

    // Hash known, height unknown (peer prev not in the header chain).
    rec.parent_height.reset();
    back = FoundBlockRecord::deserialize(rec.serialize());
    EXPECT_EQ(back.parent_hash, hash_n(0x17c));
    EXPECT_FALSE(back.parent_height.has_value());

    // A cut parent_height stays unknown, never 0.
    rec.parent_height = 2900001;
    auto cut = rec.serialize();
    cut.resize(cut.size() - kFblkExt - 3);
    EXPECT_FALSE(FoundBlockRecord::deserialize(cut).parent_height.has_value());
}

// The byte after the v4 tail says a merged row's network_difficulty is the
// AUX chain's own (a row written before it holds the parent's). It is an
// extension WITHOUT a version bump: a build that predates it refuses any
// version above 4 and would lose the row, but stops reading after the v4 tail
// and so never sees the byte.
TEST(FoundBlockStoreKat, FblkExtensionByteCarriesTheAuxDifficultyFlag)
{
    FoundBlockRecord rec = FoundBlockRecord::deserialize(fblk_v2_record().v);
    rec.chain = "DOGE";
    rec.parent_hash = hash_n(0x17c);
    rec.network_difficulty = 33000000.0;

    // Written before the flag existed: no byte, not known.
    auto old_row = rec.serialize();
    ASSERT_EQ(old_row[0], 4) << "no version bump";
    old_row.resize(old_row.size() - kFblkExt);
    auto back = FoundBlockRecord::deserialize(old_row);
    EXPECT_EQ(back.block_hash, kHashA);
    EXPECT_EQ(back.parent_hash, hash_n(0x17c));
    EXPECT_FALSE(back.aux_difficulty_known);

    // Default false round-trips false; set, it round-trips true.
    EXPECT_FALSE(FoundBlockRecord::deserialize(rec.serialize()).aux_difficulty_known);
    rec.aux_difficulty_known = true;
    const auto with_flag = rec.serialize();
    back = FoundBlockRecord::deserialize(with_flag);
    EXPECT_TRUE(back.aux_difficulty_known);
    EXPECT_DOUBLE_EQ(back.network_difficulty, 33000000.0);
    EXPECT_EQ(back.parent_hash, hash_n(0x17c));

    // The row is the pre-extension row plus one byte: an earlier build reads
    // the same bytes up to the v4 tail and gets every field it knows.
    ASSERT_EQ(with_flag.size(), old_row.size() + kFblkExt);
    EXPECT_TRUE(std::equal(old_row.begin(), old_row.end(), with_flag.begin()));

    // A cut v4 tail never turns leftover bytes into the flag.
    auto cut = with_flag;
    cut.resize(cut.size() - kFblkExt - 3);
    EXPECT_FALSE(FoundBlockRecord::deserialize(cut).aux_difficulty_known);
}

// The source node's measured effort of an imported row's round rides a tail
// AFTER the extension byte, behind its bit 0x04 -- no version bump. A row
// without one is byte for byte what the earlier writer wrote; with one it is
// that row plus the tail. Every earlier build stops reading at (or before)
// the extension byte, so it loads such a row with every field it knows; when
// it writes the row back it drops the tail and the bit, which reads here as
// "no imported effort".
TEST(FoundBlockStoreKat, ImportedEffortRidesATailBehindItsExtensionBit)
{
    FoundBlockRecord rec = FoundBlockRecord::deserialize(fblk_v2_record().v);
    rec.chain = "DOGE";
    rec.parent_hash = hash_n(0x17c);
    rec.parent_height = 3211872;
    rec.aux_difficulty_known = true;
    rec.imported = true;
    const auto without = rec.serialize();
    ASSERT_EQ(without[0], 4) << "no version bump";
    EXPECT_EQ(without.back(),
              FoundBlockRecord::kExtAuxDifficultyKnown | FoundBlockRecord::kExtImported);
    auto back = FoundBlockRecord::deserialize(without);
    EXPECT_FALSE(back.has_imported_effort());
    EXPECT_DOUBLE_EQ(back.imported_effort, 0.0);

    // DOGE 6454700 as ltc.voidbind.com measured it.
    rec.imported_effort = 1.3911304960028799;
    rec.imported_coverage = 1.0;
    rec.imported_prev_hash = hash_n(0xb9ed3c3d);
    const auto with = rec.serialize();
    ASSERT_EQ(with[0], 4);
    ASSERT_EQ(with.size(), without.size() + 8 + 8 + 1 + 64);
    EXPECT_TRUE(std::equal(without.begin(), without.end() - 1, with.begin()))
        << "the earlier row up to its extension byte";
    EXPECT_EQ(with[without.size() - 1],
              FoundBlockRecord::kExtAuxDifficultyKnown | FoundBlockRecord::kExtImported
                  | FoundBlockRecord::kExtImportedEffort);
    back = FoundBlockRecord::deserialize(with);
    EXPECT_DOUBLE_EQ(back.imported_effort, 1.3911304960028799);
    EXPECT_DOUBLE_EQ(back.imported_coverage, 1.0);
    EXPECT_EQ(back.imported_prev_hash, hash_n(0xb9ed3c3d));
    EXPECT_TRUE(back.aux_difficulty_known);
    EXPECT_TRUE(back.imported);
    EXPECT_EQ(back.parent_hash, hash_n(0x17c));
    ASSERT_TRUE(back.parent_height.has_value());
    EXPECT_EQ(*back.parent_height, 3211872u);
    EXPECT_EQ(back.serialize(), with) << "round-trips byte for byte";

    // What an earlier build writes back: its fields, its bits, no tail.
    auto rewritten = std::vector<uint8_t>(with.begin(), with.begin() + without.size());
    rewritten.back() &= static_cast<uint8_t>(~FoundBlockRecord::kExtImportedEffort);
    EXPECT_EQ(rewritten, without);
    EXPECT_FALSE(FoundBlockRecord::deserialize(rewritten).has_imported_effort());

    // A cut tail is no imported effort -- never leftover bytes -- and the
    // rest of the row stands.
    for (size_t cut : {size_t(1), size_t(30), size_t(64), size_t(66), size_t(80)}) {
        auto c = with;
        c.resize(with.size() - cut);
        const auto r = FoundBlockRecord::deserialize(c);
        EXPECT_EQ(r.block_hash, kHashA) << cut;
        EXPECT_FALSE(r.has_imported_effort()) << cut;
        EXPECT_DOUBLE_EQ(r.imported_effort, 0.0) << cut;
        EXPECT_TRUE(r.imported) << cut;
        EXPECT_TRUE(r.aux_difficulty_known) << cut;
    }
    // A figure out of range is neither written nor read.
    for (double coverage : {0.0, 1.5, std::nan("")}) {
        FoundBlockRecord bad = rec;
        bad.imported_coverage = coverage;
        EXPECT_EQ(bad.serialize(), without) << coverage;
    }
    {
        auto forged = with;
        double big = 7.0;   // coverage 7 in the tail
        std::memcpy(&forged[without.size() + 8], &big, sizeof(big));
        EXPECT_FALSE(FoundBlockRecord::deserialize(forged).has_imported_effort());
    }
    // Rows from before the extension byte, and from before the tail, load
    // with no imported effort.
    auto pre_ext = without;
    pre_ext.pop_back();
    EXPECT_FALSE(FoundBlockRecord::deserialize(pre_ext).has_imported_effort());
    EXPECT_FALSE(FoundBlockRecord::deserialize(fblk_v2_record().v).has_imported_effort());
}

TEST(FoundBlockStoreKat, UnknownVersionsAreRejected)
{
    auto f = fblk_v2_record().v; f[0] = 5;
    EXPECT_TRUE(FoundBlockRecord::deserialize(f).block_hash.empty());
    f[0] = 0;
    EXPECT_TRUE(FoundBlockRecord::deserialize(f).block_hash.empty());

    auto m = mblk_v1_record(98, 1, kHashA).v; m[0] = 3;
    EXPECT_TRUE(MergedBlockRecord::deserialize(m).block_hash.empty());
    m[0] = 0;
    EXPECT_TRUE(MergedBlockRecord::deserialize(m).block_hash.empty());
}

TEST(FoundBlockStoreKat, StoreRestoresPreChangeRowsAndFillsTheBody)
{
    TempDb t("fblk_restore");
    ASSERT_TRUE(t.db.open());
    FoundBlockStore store(t.db);

    // A DASH v2 row and an LTC v1 row, exactly as older nodes left them.
    ASSERT_TRUE(t.db.put(fblk_key("DASH", 2531045, kHashA), fblk_v2_record().v));
    Bytes v1; v1.u8(1);
    v1.str("LTC").u64(2900000).str(kHashB).u64(1788182000)
      .u8(1).u8(0).u64(0).u32(0).str("").u64(625000000);
    ASSERT_TRUE(t.db.put(fblk_key("LTC", 2900000, kHashB), v1.v));

    auto all = store.load_all();
    ASSERT_EQ(all.size(), 2u);
    EXPECT_EQ(all[0].block_hash, kHashA);   // newest timestamp first
    EXPECT_EQ(all[1].block_hash, kHashB);

    // kHashA and kHashB share their first 16 chars: only the full hash matches.
    auto a = store.find_by_hash(kHashA);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->chain, "DASH");
    auto b = store.find_by_hash(kHashB);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->chain, "LTC");
    EXPECT_FALSE(store.find_by_hash(hash_n(1)).has_value());
    EXPECT_FALSE(store.find_by_hash(kHashA.substr(0, 16)).has_value());
    EXPECT_FALSE(store.find_by_hash("").has_value());

    // Full block arrives: the body fields land, the v2 enrichment survives.
    ASSERT_TRUE(store.update_body("DASH", 2531045, kHashA, hash_n(0xcb), 42));
    a = store.find_by_hash(kHashA);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->coinbase_txid, hash_n(0xcb));
    ASSERT_TRUE(a->tx_count.has_value());
    EXPECT_EQ(*a->tx_count, 42u);
    EXPECT_DOUBLE_EQ(a->share_difficulty, 240228.0);
    EXPECT_EQ(a->authorship, 2);
    EXPECT_FALSE(store.update_body("DASH", 2531045, kHashB, hash_n(0xcb), 1));
}

// ── mblk ─────────────────────────────────────────────────────────────────────

TEST(MergedBlockStoreKat, MblkV1RecordRestores)
{
    auto rec = MergedBlockRecord::deserialize(mblk_v1_record(98, 5400000, kHashA).v);
    EXPECT_EQ(rec.chain_id, 98u);
    EXPECT_EQ(rec.symbol, "DOGE");
    EXPECT_EQ(rec.height, 5400000);
    EXPECT_EQ(rec.block_hash, kHashA);
    EXPECT_EQ(rec.parent_hash, "parenthash");
    EXPECT_EQ(rec.timestamp, 1788182946);
    EXPECT_TRUE(rec.accepted);
    EXPECT_TRUE(rec.is_local);
    EXPECT_EQ(rec.coinbase_value, 1000000000000ULL);
    EXPECT_EQ(rec.parent_height, 2900000u);
    EXPECT_EQ(rec.miner, "Dminer");
    EXPECT_TRUE(rec.share_hash.empty());
    EXPECT_TRUE(rec.coinbase_txid.empty());
    EXPECT_FALSE(rec.tx_count.has_value());
}

TEST(MergedBlockStoreKat, MblkV2IsAPureAppendAndRoundTrips)
{
    auto v1 = mblk_v1_record(98, 5400000, kHashA).v;
    auto rec = MergedBlockRecord::deserialize(v1);
    auto out = rec.serialize();
    ASSERT_EQ(out[0], 2);
    ASSERT_GT(out.size(), v1.size());
    EXPECT_TRUE(std::equal(v1.begin() + 1, v1.end(), out.begin() + 1));

    rec.share_hash = hash_n(0x5a);
    rec.coinbase_txid = hash_n(0xcb);
    rec.tx_count = 0;
    auto back = MergedBlockRecord::deserialize(rec.serialize());
    EXPECT_EQ(back.share_hash, hash_n(0x5a));
    EXPECT_EQ(back.coinbase_txid, hash_n(0xcb));
    ASSERT_TRUE(back.tx_count.has_value());
    EXPECT_EQ(*back.tx_count, 0u);
    EXPECT_EQ(back.miner, "Dminer");
    EXPECT_EQ(back.parent_height, 2900000u);
}

// The aux chain's own difficulty rides after the v2 tail, again without a
// version bump (an earlier build stops after its tail and keeps the record).
TEST(MergedBlockStoreKat, MblkExtensionCarriesTheAuxDifficulty)
{
    auto rec = MergedBlockRecord::deserialize(mblk_v1_record(98, 5400000, kHashA).v);
    EXPECT_DOUBLE_EQ(rec.difficulty, 0.0) << "a v1 record has none";
    rec.share_hash = hash_n(0x5a);
    rec.tx_count = 7;

    // Written before the difficulty existed: nothing after the v2 tail.
    auto old_row = rec.serialize();
    ASSERT_EQ(old_row[0], 2) << "no version bump";
    old_row.resize(old_row.size() - kMblkExt);
    auto back = MergedBlockRecord::deserialize(old_row);
    EXPECT_EQ(back.block_hash, kHashA);
    EXPECT_DOUBLE_EQ(back.difficulty, 0.0);
    ASSERT_TRUE(back.tx_count.has_value());
    EXPECT_EQ(*back.tx_count, 7u);

    rec.difficulty = 33412345.678;
    const auto with_difficulty = rec.serialize();
    back = MergedBlockRecord::deserialize(with_difficulty);
    EXPECT_DOUBLE_EQ(back.difficulty, 33412345.678);
    EXPECT_EQ(back.share_hash, hash_n(0x5a));
    ASSERT_EQ(with_difficulty.size(), old_row.size() + kMblkExt);
    EXPECT_TRUE(std::equal(old_row.begin(), old_row.end(), with_difficulty.begin()));

    // A cut difficulty is not known, never a number made of leftover bytes.
    auto cut = with_difficulty;
    cut.resize(cut.size() - 3);
    EXPECT_DOUBLE_EQ(MergedBlockRecord::deserialize(cut).difficulty, 0.0);
}

// The pool rate at find follows the difficulty, written only when known: a
// record without it is byte for byte the earlier one, and an earlier build
// (which stops after the difficulty) keeps a record with it.
TEST(MergedBlockStoreKat, RateAtFindFollowsTheDifficultyWhenKnown)
{
    auto rec = MergedBlockRecord::deserialize(mblk_v1_record(98, 6463962, kHashA).v);
    EXPECT_DOUBLE_EQ(rec.pool_hashrate, 0.0) << "a v1 record has none";
    rec.difficulty = 42136316.98663563;
    const auto without = rec.serialize();
    EXPECT_DOUBLE_EQ(MergedBlockRecord::deserialize(without).pool_hashrate, 0.0);

    rec.pool_hashrate = 1.48e11;
    const auto with = rec.serialize();
    ASSERT_EQ(with[0], 2) << "no version bump";
    ASSERT_EQ(with.size(), without.size() + 8);
    EXPECT_TRUE(std::equal(without.begin(), without.end(), with.begin()));
    auto back = MergedBlockRecord::deserialize(with);
    EXPECT_DOUBLE_EQ(back.pool_hashrate, 1.48e11);
    EXPECT_DOUBLE_EQ(back.difficulty, 42136316.98663563);
    EXPECT_EQ(back.miner, "Dminer");
    EXPECT_EQ(back.serialize(), with);

    // A cut rate is not known; the difficulty before it stands.
    auto cut = with;
    cut.resize(cut.size() - 3);
    back = MergedBlockRecord::deserialize(cut);
    EXPECT_DOUBLE_EQ(back.pool_hashrate, 0.0);
    EXPECT_DOUBLE_EQ(back.difficulty, 42136316.98663563);
    // A record from before the difficulty has neither.
    auto pre = without;
    pre.resize(pre.size() - kMblkExt);
    back = MergedBlockRecord::deserialize(pre);
    EXPECT_EQ(back.block_hash, kHashA);
    EXPECT_DOUBLE_EQ(back.difficulty, 0.0);
    EXPECT_DOUBLE_EQ(back.pool_hashrate, 0.0);
}

// The same block stored again without a rate -- learned again long after its
// find, by the startup scan of the share chain -- keeps the rate read when it
// was found; everything else the new record says is taken.
TEST(MergedBlockStoreKat, StoreKeepsAHeldRateAtFind)
{
    TempDb t("mblk_rate_keep");
    ASSERT_TRUE(t.db.open());
    MergedBlockStore store(t.db);
    MergedBlockRecord r;
    r.chain_id = 98; r.symbol = "DOGE"; r.height = 6463962; r.block_hash = kHashA;
    r.timestamp = 1795083273; r.difficulty = 42136316.98663563; r.pool_hashrate = 1.48e11;
    ASSERT_TRUE(store.store(r));

    MergedBlockRecord again = r;
    again.pool_hashrate = 0.0;
    again.coinbase_value = 1000000000000ULL;
    ASSERT_TRUE(store.store(again));
    auto all = store.load_all();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_DOUBLE_EQ(all[0].pool_hashrate, 1.48e11);
    EXPECT_EQ(all[0].coinbase_value, 1000000000000ULL);

    // A known rate is stored as given; the updaters keep it.
    again.pool_hashrate = 1.5e11;
    ASSERT_TRUE(store.store(again));
    ASSERT_TRUE(store.update_coinbase(kHashA, 98, 777));
    ASSERT_TRUE(store.update_body(kHashA, 98, hash_n(0xcb), 3));
    all = store.load_all();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_DOUBLE_EQ(all[0].pool_hashrate, 1.5e11);
    EXPECT_EQ(all[0].coinbase_value, 777u);

    // Another block under the same 16-char key prefix is not "held".
    MergedBlockRecord other = r;
    other.block_hash = kHashB;
    other.pool_hashrate = 0.0;
    ASSERT_TRUE(store.store(other));
    std::vector<uint8_t> raw;
    ASSERT_TRUE(t.db.get(mblk_key(98, 6463962, kHashB), raw));
    const auto o = MergedBlockRecord::deserialize(raw);
    EXPECT_EQ(o.block_hash, kHashB);
    EXPECT_DOUBLE_EQ(o.pool_hashrate, 0.0);
}

TEST(MergedBlockStoreKat, UpdateCoinbaseReachesTheNewestPast1000)
{
    TempDb t("mblk_update");
    ASSERT_TRUE(t.db.open());
    MergedBlockStore store(t.db);

    // 1200 DOGE records written by the new code...
    for (uint32_t h = 1; h <= 1200; ++h) {
        MergedBlockRecord r;
        r.chain_id = 98; r.symbol = "DOGE"; r.height = static_cast<int>(h);
        r.block_hash = hash_n(h); r.timestamp = 1788000000 + h;
        ASSERT_TRUE(store.store(r));
    }
    // ...and the newest one a pre-change v1 record already on disk.
    const std::string newest = hash_n(0xfffff);
    ASSERT_TRUE(t.db.put(mblk_key(98, 1201, newest), mblk_v1_record(98, 1201, newest).v));
    // Same hash on another merged chain must stay untouched.
    ASSERT_TRUE(t.db.put(mblk_key(7, 1201, newest), mblk_v1_record(7, 1201, newest).v));

    ASSERT_TRUE(store.update_coinbase(newest, 98, 777));
    std::vector<uint8_t> raw;
    ASSERT_TRUE(t.db.get(mblk_key(98, 1201, newest), raw));
    auto rec = MergedBlockRecord::deserialize(raw);
    EXPECT_EQ(raw[0], 2);                       // rewritten as v2...
    EXPECT_EQ(rec.coinbase_value, 777u);
    EXPECT_EQ(rec.miner, "Dminer");             // ...without losing v1 fields
    EXPECT_EQ(rec.parent_height, 2900000u);
    ASSERT_TRUE(t.db.get(mblk_key(7, 1201, newest), raw));
    EXPECT_EQ(MergedBlockRecord::deserialize(raw).coinbase_value, 1000000000000ULL);

    // The oldest one is still reachable too.
    ASSERT_TRUE(store.update_coinbase(hash_n(1), 98, 5));
    ASSERT_TRUE(store.update_body(hash_n(1200), 98, hash_n(0xcb), 3));
    ASSERT_TRUE(t.db.get(mblk_key(98, 1200, hash_n(1200)), raw));
    rec = MergedBlockRecord::deserialize(raw);
    EXPECT_EQ(rec.coinbase_txid, hash_n(0xcb));
    ASSERT_TRUE(rec.tx_count.has_value());
    EXPECT_EQ(*rec.tx_count, 3u);

    EXPECT_FALSE(store.update_coinbase(hash_n(0xdead), 98, 1));
    EXPECT_FALSE(store.update_coinbase(hash_n(5), 99, 1));   // wrong chain
    EXPECT_EQ(store.load_all().size(), 1202u);
}

TEST(MergedBlockStoreKat, UpdatersLeaveADamagedRowAlone)
{
    // A damaged mblk row deserializes to an empty record (block_hash "",
    // chain_id 0). find_key matches it for an empty hash on chain 0, so
    // without the guard update_coinbase/update_body rewrote the damaged bytes
    // as an empty v2 record. fblk update_status already refuses this.
    auto cut = mblk_v1_record(98, 5400001, kHashB).v;
    cut.resize(cut.size() - (1 + 6) - 2);
    ASSERT_TRUE(MergedBlockRecord::deserialize(cut).block_hash.empty());

    TempDb t("mblk_damaged_update");
    ASSERT_TRUE(t.db.open());
    MergedBlockStore store(t.db);
    const std::string empty_key = mblk_key(0, 5400001, "");
    const std::string doge_key = mblk_key(98, 5400001, kHashB);
    ASSERT_TRUE(t.db.put(empty_key, cut));
    ASSERT_TRUE(t.db.put(doge_key, cut));

    EXPECT_FALSE(store.update_coinbase("", 0, 777));
    EXPECT_FALSE(store.update_body("", 0, hash_n(0xcb), 3));
    EXPECT_FALSE(store.update_coinbase(kHashB, 98, 777));
    EXPECT_FALSE(store.update_body(kHashB, 98, hash_n(0xcb), 3));

    std::vector<uint8_t> still;
    ASSERT_TRUE(t.db.get(empty_key, still));
    EXPECT_EQ(still, cut);
    ASSERT_TRUE(t.db.get(doge_key, still));
    EXPECT_EQ(still, cut);
    EXPECT_TRUE(store.load_all().empty());
}

TEST(MergedBlockStoreKat, FindByHashNeedsTheFullHash)
{
    TempDb t("mblk_find");
    ASSERT_TRUE(t.db.open());
    MergedBlockStore store(t.db);

    ASSERT_TRUE(t.db.put(mblk_key(98, 10, kHashA), mblk_v1_record(98, 10, kHashA).v));
    MergedBlockRecord r;
    r.chain_id = 98; r.symbol = "DOGE"; r.height = 11; r.block_hash = kHashB;
    r.share_hash = hash_n(0x5a);
    ASSERT_TRUE(store.store(r));

    auto a = store.find_by_hash(kHashA);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->height, 10);
    EXPECT_TRUE(a->share_hash.empty());
    auto b = store.find_by_hash(kHashB);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->height, 11);
    EXPECT_EQ(b->share_hash, hash_n(0x5a));
    EXPECT_FALSE(store.find_by_hash(hash_n(2)).has_value());
    EXPECT_FALSE(store.find_by_hash(kHashA.substr(0, 16)).has_value());
}

// ── A row stored at height 0 learns its height and keeps it ─────────────────
// The stale-job block 2561316 of 2026-10-25 was stored at height 0 and
// pending. The key carries the height (fblk:<chain>:<height12>:<hash16>), so
// a later record that knows the real height must (a) give the in-memory row
// that height, (b) leave no height-0 key behind -- it lists first and would
// win the (hash, chain) dedup on the next load -- and (c) let the
// confirm/orphan verdict resolve at the real height. Wired the way
// main_dash.cpp wires the store.

namespace {

using MI = core::MiningInterface;

void wire_store(MI& mi, FoundBlockStore& store)
{
    mi.set_found_block_persistence(
        [&store](const MI::FoundBlock& b) -> bool {
            FoundBlockRecord rec;
            rec.chain = b.chain; rec.height = b.height; rec.block_hash = b.hash;
            rec.timestamp = b.ts; rec.status = static_cast<uint8_t>(b.status);
            rec.check_count = b.check_count; rec.confirmations = b.confirmations;
            rec.finder_address = b.miner; rec.reward_satoshis = b.subsidy;
            rec.network_difficulty = b.network_difficulty;
            rec.share_difficulty = b.share_difficulty;
            rec.pool_hashrate = b.pool_hashrate; rec.share_hash = b.share_hash;
            rec.authorship = static_cast<uint8_t>(b.authorship);
            return store.store(rec, b.replaced_height);
        },
        [&store]() {
            std::vector<MI::FoundBlock> out;
            for (const auto& rec : store.load_all()) {
                MI::FoundBlock b{};
                b.height = rec.height; b.hash = rec.block_hash; b.ts = rec.timestamp;
                b.status = static_cast<MI::BlockStatus>(rec.status);
                b.check_count = rec.check_count; b.chain = rec.chain;
                b.confirmations = rec.confirmations; b.miner = rec.finder_address;
                b.subsidy = rec.reward_satoshis;
                b.network_difficulty = rec.network_difficulty;
                b.share_difficulty = rec.share_difficulty;
                b.pool_hashrate = rec.pool_hashrate; b.share_hash = rec.share_hash;
                b.authorship = static_cast<MI::BlockAuthorship>(rec.authorship);
                out.push_back(std::move(b));
            }
            return out;
        });
}

const std::string kStaleHash =
    "000000000000001c9e20a446e73e4a734fd79adba4b7c4d736e34551bc37f10f";
const std::string kPrevHash =
    "000000000000001b1181483e7c1ff9d25880ce5688c84696bf5f3913f58a1197";
constexpr uint64_t kStaleHeight = 2561316;

FoundBlockRecord dash_row(uint64_t height, const std::string& hash, uint64_t ts,
                          uint8_t status)
{
    FoundBlockRecord rec;
    rec.chain = "DASH"; rec.height = height; rec.block_hash = hash;
    rec.timestamp = ts; rec.status = status;
    rec.finder_address = "XoZcEFbqwnty5secW7HYjdQEZYfubMkURu";
    rec.share_hash = hash; rec.reward_satoshis = 164425700;
    rec.network_difficulty = 93611841.8; rec.pool_hashrate = 4.6e13;
    rec.authorship = 2;
    return rec;
}

// The DASH confirm lane's answer: nothing is known at height 0 (pending), and
// a competitor holds 2561316 (orphaned).
void arm_competitor_verdict(MI& mi)
{
    mi.set_block_verify_fn([&mi](const std::string& hash) -> int {
        for (const auto& b : mi.get_found_blocks())
            if (b.hash == hash) return b.height == kStaleHeight ? -1 : 0;
        return 0;
    });
}

const MI::FoundBlock* row_of(const std::vector<MI::FoundBlock>& rows,
                             const std::string& hash)
{
    for (const auto& b : rows)
        if (b.hash == hash) return &b;
    return nullptr;
}

bool has_key(core::LevelDBStore& db, const std::string& key)
{
    std::vector<uint8_t> v;
    return db.get(key, v);
}

} // namespace

TEST(FoundBlockStoreKat, HeightZeroRowLearnsItsHeightAndKeepsItAcrossReloads)
{
    TempDb t("fblk_height_learn");
    ASSERT_TRUE(t.db.open());
    FoundBlockStore store(t.db);
    // What the primary has on disk: the stale-job block at height 0, pending.
    ASSERT_TRUE(store.store(dash_row(2561265, kPrevHash, 1792945704, /*confirmed*/1)));
    ASSERT_TRUE(store.store(dash_row(0, kStaleHash, 1792954341, /*pending*/0)));

    {
        MI mi(/*testnet=*/false, nullptr, c2pool::address::Blockchain::DASH);
        wire_store(mi, store);
        mi.load_persisted_found_blocks();
        arm_competitor_verdict(mi);
        const auto loaded = mi.get_found_blocks();
        ASSERT_NE(row_of(loaded, kStaleHash), nullptr);
        EXPECT_EQ(row_of(loaded, kStaleHash)->height, 0u);
        // At height 0 the lane cannot answer: the row stays pending.
        EXPECT_EQ(mi.run_block_verification_now(kStaleHash), 0);

        // The sharechain hook re-records the block from its share (BIP34).
        uint256 h; h.SetHex(kStaleHash);
        mi.record_found_block(kStaleHeight, h, 1792954024, "DASH",
                              "XoZcEFbqwnty5secW7HYjdQEZYfubMkURu", kStaleHash,
                              93611841.8, 240584.8, 0.0, 164425700,
                              MI::BlockAuthorship::sharechain_peer);
        const auto rows = mi.get_found_blocks();
        ASSERT_NE(row_of(rows, kStaleHash), nullptr);
        EXPECT_EQ(row_of(rows, kStaleHash)->height, kStaleHeight)
            << "a later record that knows the height must lift the row out of 0";
        EXPECT_EQ(rows.front().hash, kStaleHash) << "newest first by height";
        EXPECT_FALSE(has_key(t.db, fblk_key("DASH", 0, kStaleHash)))
            << "the height-0 key must not survive the update";
        EXPECT_TRUE(has_key(t.db, fblk_key("DASH", kStaleHeight, kStaleHash)));

        EXPECT_EQ(mi.run_block_verification_now(kStaleHash), -1)
            << "at its real height the verdict resolves orphaned";
    }

    // Two restarts: the row comes back at its height, orphaned, and stays so.
    for (int restart = 0; restart < 2; ++restart) {
        MI mi(/*testnet=*/false, nullptr, c2pool::address::Blockchain::DASH);
        wire_store(mi, store);
        mi.load_persisted_found_blocks();
        const auto rows = mi.get_found_blocks();
        ASSERT_EQ(rows.size(), 2u) << "restart " << restart;
        const auto* r = row_of(rows, kStaleHash);
        ASSERT_NE(r, nullptr);
        EXPECT_EQ(r->height, kStaleHeight) << "restart " << restart << " re-zeroed the row";
        EXPECT_EQ(r->status, MI::BlockStatus::orphaned) << "restart " << restart;
        EXPECT_FALSE(has_key(t.db, fblk_key("DASH", 0, kStaleHash)));
    }
}

// Both keys on disk (a crash between the write and the removal, or an older
// binary): the record at the real height is the newer one and must win the
// load whatever order the store lists them in -- the height-0 key lists first.
TEST(FoundBlockStoreKat, LoadPrefersTheRealHeightOverAHeightZeroKey)
{
    TempDb t("fblk_height_prefer");
    ASSERT_TRUE(t.db.open());
    FoundBlockStore store(t.db);
    ASSERT_TRUE(t.db.put(fblk_key("DASH", 0, kStaleHash),
                         dash_row(0, kStaleHash, 1792954341, /*pending*/0).serialize()));
    ASSERT_TRUE(t.db.put(fblk_key("DASH", kStaleHeight, kStaleHash),
                         dash_row(kStaleHeight, kStaleHash, 1792954341, /*orphaned*/2).serialize()));

    MI mi(/*testnet=*/false, nullptr, c2pool::address::Blockchain::DASH);
    wire_store(mi, store);
    mi.load_persisted_found_blocks();
    const auto rows = mi.get_found_blocks();
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].height, kStaleHeight);
    EXPECT_EQ(rows[0].status, MI::BlockStatus::orphaned);
}

// The startup repair: a row restored at height 0 takes the height a lookup
// (main_dash: the header chain) knows for its hash, through the same path, and
// the lookup is asked about unknown heights only.
TEST(FoundBlockStoreKat, StartupBackfillGivesAHeightZeroRowItsHeight)
{
    TempDb t("fblk_height_backfill");
    ASSERT_TRUE(t.db.open());
    FoundBlockStore store(t.db);
    ASSERT_TRUE(store.store(dash_row(2561265, kPrevHash, 1792945704, /*confirmed*/1)));
    ASSERT_TRUE(store.store(dash_row(0, kStaleHash, 1792954341, /*pending*/0)));

    MI mi(/*testnet=*/false, nullptr, c2pool::address::Blockchain::DASH);
    wire_store(mi, store);
    mi.load_persisted_found_blocks();
    std::vector<std::string> asked;
    mi.backfill_found_block_heights([&asked](const std::string& hash) -> uint64_t {
        asked.push_back(hash);
        return hash == kStaleHash ? kStaleHeight : 0;
    });
    ASSERT_EQ(asked.size(), 1u);
    EXPECT_EQ(asked[0], kStaleHash);

    const auto rows = mi.get_found_blocks();
    const auto* r = row_of(rows, kStaleHash);
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->height, kStaleHeight);
    EXPECT_FALSE(has_key(t.db, fblk_key("DASH", 0, kStaleHash)));
    EXPECT_TRUE(has_key(t.db, fblk_key("DASH", kStaleHeight, kStaleHash)));

    arm_competitor_verdict(mi);
    EXPECT_EQ(mi.run_block_verification_now(kStaleHash), -1);
}

// A height the header chain CORRECTS (the LTC peer path stored the share
// absheight, 27707625 for block 3211872, 2026-11-12) moves the row to its
// real key: the absheight key must not survive to be loaded again. Wired as
// main_ltc.cpp wires the store (FoundBlock::replaced_height names the old
// key; store() stays O(1), no key scan).
TEST(FoundBlockStoreKat, CorrectedHeightLeavesOneKey)
{
    const std::string kLtc = "84024db9063696eabf560504fa15737d6ab15a560441e5bab7fd51bd03571223";
    const std::string kOther = "84024db9063696ea" + std::string(48, '0');   // same key suffix
    constexpr uint64_t kAbs = 27707625, kReal = 3211872;
    TempDb t("fblk_height_correct");
    ASSERT_TRUE(t.db.open());
    FoundBlockStore store(t.db);
    auto ltc_row = [](uint64_t height, const std::string& hash) {
        FoundBlockRecord rec;
        rec.chain = "LTC"; rec.height = height; rec.block_hash = hash;
        rec.timestamp = 1794498365; rec.status = 0;
        rec.finder_address = "085cdff070d752d9e137e82396e387ec1641fd75";
        rec.share_hash = hash; rec.authorship = 1;
        return rec;
    };
    ASSERT_TRUE(store.store(ltc_row(kAbs, kLtc)));
    // A different block whose key shares the 16-hex suffix is not touched.
    ASSERT_TRUE(store.store(ltc_row(3000000, kOther)));

    {
        MI mi(/*testnet=*/false, nullptr, c2pool::address::Blockchain::LITECOIN);
        wire_store(mi, store);
        mi.load_persisted_found_blocks();
        mi.correct_found_block_heights([&](const std::string& h) -> uint64_t {
            return h == kLtc ? kReal : 0;
        }, /*tip_height=*/kReal + 100);
        EXPECT_FALSE(has_key(t.db, fblk_key("LTC", kAbs, kLtc)))
            << "the absheight key would be loaded again on the next start";
        EXPECT_TRUE(has_key(t.db, fblk_key("LTC", kReal, kLtc)));
        EXPECT_TRUE(has_key(t.db, fblk_key("LTC", 3000000, kOther)));
    }
    MI mi(/*testnet=*/false, nullptr, c2pool::address::Blockchain::LITECOIN);
    wire_store(mi, store);
    mi.load_persisted_found_blocks();
    const auto rows = mi.get_found_blocks();
    ASSERT_EQ(rows.size(), 2u);
    ASSERT_NE(row_of(rows, kLtc), nullptr);
    EXPECT_EQ(row_of(rows, kLtc)->height, kReal);
    // The row now renders the miner it can: a bare pubkey hash is not an address.
    for (const auto& b : mi.rest_recent_blocks())
        if (b["hash"].get<std::string>() == kLtc)
            EXPECT_EQ(b["miner"].get<std::string>(), "");
}

// The record path's correction (the block's own BIP34 height arriving for a
// row stored at the share absheight) re-keys the stored row the same way.
TEST(FoundBlockStoreKat, RecordPathCorrectionLeavesOneKey)
{
    const std::string kLtc = "84024db9063696eabf560504fa15737d6ab15a560441e5bab7fd51bd03571223";
    constexpr uint64_t kAbs = 27707625, kReal = 3211872;
    TempDb t("fblk_height_record_correct");
    ASSERT_TRUE(t.db.open());
    FoundBlockStore store(t.db);
    MI mi(/*testnet=*/false, nullptr, c2pool::address::Blockchain::LITECOIN);
    wire_store(mi, store);
    uint256 h; h.SetHex(kLtc);
    mi.record_found_block(kAbs, h, 1794498365, "LTC", "085cdff070d752d9e137e82396e387ec1641fd75",
                          kLtc, 0.0, 0.0, 0.0, 0, MI::BlockAuthorship::sharechain_peer);
    ASSERT_TRUE(has_key(t.db, fblk_key("LTC", kAbs, kLtc)));
    mi.record_found_block(kReal, h, 1794498365, "LTC", "LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F",
                          kLtc, 0.0, 0.0, 0.0, 0, MI::BlockAuthorship::sharechain_peer,
                          /*height_from_block=*/true);
    EXPECT_FALSE(has_key(t.db, fblk_key("LTC", kAbs, kLtc)));
    EXPECT_TRUE(has_key(t.db, fblk_key("LTC", kReal, kLtc)));
    const auto loaded = store.load_all();
    ASSERT_EQ(loaded.size(), 1u);
    EXPECT_EQ(loaded[0].height, kReal);
    EXPECT_EQ(loaded[0].finder_address, "LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F");
}

// ── Against the earlier build's OWN serializers ──────────────────────────────
// found_block_records_2e6db7b5f.hpp is origin/master 2e6db7b5f's record code,
// byte for byte (identical to v0.2.12.10's), in its own namespace. Both ways:
//   * the earlier build reads a new row with every field it knows, and what
//     it writes back is byte for byte the new writer's row without the tail
//     (fblk) / the rate (mblk) -- which the new reader takes as "none";
//   * the new reader reads the earlier build's rows and writes them back
//     unchanged;
//   * no cut of a new row, no value of the tail's hash-length byte and no
//     trailing bytes make either reader read past the end or take a figure
//     from anything but a whole tail.
namespace {

FoundBlockRecord full_fblk_with_effort()
{
    FoundBlockRecord r;
    r.chain = "DOGE"; r.height = 6454700; r.block_hash = hash_n(0x700); r.timestamp = 1794498365;
    r.status = 1; r.check_count = 3; r.last_checked = 1794500000; r.confirmations = 120;
    r.finder_address = "LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F"; r.reward_satoshis = 1000000000000ULL;
    r.network_difficulty = 37146875.79962987; r.share_difficulty = 514.33; r.pool_hashrate = 1.45e11;
    r.share_hash = hash_n(0x701); r.authorship = 1; r.coinbase_txid = hash_n(0x702); r.tx_count = 17;
    r.parent_hash = hash_n(0x703); r.parent_height = 3211872; r.aux_difficulty_known = true;
    r.imported = true;
    r.imported_effort = 1.3911304960028799; r.imported_coverage = 1.0;
    r.imported_prev_hash = hash_n(0x704);
    return r;
}

template <class A, class B>
void expect_same_fblk_fields(const A& a, const B& b, const char* what)
{
    EXPECT_EQ(a.chain, b.chain) << what;
    EXPECT_EQ(a.height, b.height) << what;
    EXPECT_EQ(a.block_hash, b.block_hash) << what;
    EXPECT_EQ(a.timestamp, b.timestamp) << what;
    EXPECT_EQ(a.status, b.status) << what;
    EXPECT_EQ(a.check_count, b.check_count) << what;
    EXPECT_EQ(a.last_checked, b.last_checked) << what;
    EXPECT_EQ(a.confirmations, b.confirmations) << what;
    EXPECT_EQ(a.finder_address, b.finder_address) << what;
    EXPECT_EQ(a.reward_satoshis, b.reward_satoshis) << what;
    EXPECT_DOUBLE_EQ(a.network_difficulty, b.network_difficulty) << what;
    EXPECT_DOUBLE_EQ(a.share_difficulty, b.share_difficulty) << what;
    EXPECT_DOUBLE_EQ(a.pool_hashrate, b.pool_hashrate) << what;
    EXPECT_EQ(a.share_hash, b.share_hash) << what;
    EXPECT_EQ(a.authorship, b.authorship) << what;
    EXPECT_EQ(a.coinbase_txid, b.coinbase_txid) << what;
    EXPECT_EQ(a.tx_count.has_value(), b.tx_count.has_value()) << what;
    EXPECT_EQ(a.tx_count.value_or(0), b.tx_count.value_or(0)) << what;
    EXPECT_EQ(a.parent_hash, b.parent_hash) << what;
    EXPECT_EQ(a.parent_height.has_value(), b.parent_height.has_value()) << what;
    EXPECT_EQ(a.parent_height.value_or(0), b.parent_height.value_or(0)) << what;
    EXPECT_EQ(a.aux_difficulty_known, b.aux_difficulty_known) << what;
    EXPECT_EQ(a.imported, b.imported) << what;
}

} // namespace

TEST(FoundBlockStoreKat, FblkRowsInteroperateWithThe2e6db7b5fSerializer)
{
    namespace O = c2pool::storage_2e6db7b5f;
    const FoundBlockRecord rec = full_fblk_with_effort();
    const auto with = rec.serialize();
    FoundBlockRecord rec0 = rec;
    rec0.imported_effort = 0.0; rec0.imported_coverage = 0.0; rec0.imported_prev_hash.clear();
    const auto without = rec0.serialize();
    ASSERT_EQ(with.size(), without.size() + 8 + 8 + 1 + 64);

    // The earlier build reads the new row: every field it knows.
    const O::FoundBlockRecord o = O::FoundBlockRecord::deserialize(with);
    expect_same_fblk_fields(o, rec, "earlier reader on new bytes");
    // What it writes back is the row without the tail ...
    EXPECT_EQ(o.serialize(), without);
    // ... which the new reader takes as "no imported effort", every other
    // field intact, and writes back unchanged.
    const FoundBlockRecord n = FoundBlockRecord::deserialize(o.serialize());
    expect_same_fblk_fields(n, rec, "new reader on the earlier build's bytes");
    EXPECT_FALSE(n.has_imported_effort());
    EXPECT_EQ(n.serialize(), without);

    // Every cut of the new row: neither reader reads past the end; the new
    // one takes a figure only from the whole tail.
    for (size_t len = 0; len <= with.size(); ++len) {
        const std::vector<uint8_t> cut(with.begin(), with.begin() + static_cast<std::ptrdiff_t>(len));
        const auto nr = FoundBlockRecord::deserialize(cut);
        (void)O::FoundBlockRecord::deserialize(cut);
        EXPECT_EQ(nr.has_imported_effort(), len == with.size()) << len;
    }
    // Every value of the tail's hash-length byte: only the whole 64-char
    // hash is a round's start (a short one would match no round, and only
    // keep a valid figure out).
    const size_t ip_len_at = without.size() + 16;
    for (int v = 0; v < 256; ++v) {
        auto c = with;
        c[ip_len_at] = static_cast<uint8_t>(v);
        const auto nr = FoundBlockRecord::deserialize(c);
        EXPECT_EQ(nr.has_imported_effort(), v == 64) << v;
        EXPECT_EQ(nr.block_hash, rec.block_hash) << v;
        const FoundBlockRecord kept = FoundBlockRecord::deserialize(nr.serialize());
        EXPECT_EQ(kept.has_imported_effort(), v == 64) << v;
    }
    // Trailing bytes after a whole tail are ignored by both.
    auto longer = with;
    longer.insert(longer.end(), {1, 2, 3, 4, 5});
    EXPECT_TRUE(FoundBlockRecord::deserialize(longer).has_imported_effort());
    expect_same_fblk_fields(O::FoundBlockRecord::deserialize(longer), rec,
                            "earlier reader, trailing bytes");
}

TEST(MergedBlockStoreKat, MblkRecordsInteroperateWithThe2e6db7b5fSerializer)
{
    namespace O = c2pool::storage_2e6db7b5f;
    MergedBlockRecord m;
    m.chain_id = 98; m.symbol = "DOGE"; m.height = 6463962; m.block_hash = hash_n(0x800);
    m.parent_hash = hash_n(0x801); m.timestamp = 1795083273; m.accepted = true;
    m.coinbase_value = 1000000000000ULL; m.is_local = false; m.parent_height = 3215000;
    m.miner = "LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F"; m.share_hash = hash_n(0x802);
    m.coinbase_txid = hash_n(0x803); m.tx_count = 9; m.difficulty = 42136316.98663563;
    m.pool_hashrate = 1.48e11;
    const auto with = m.serialize();
    MergedBlockRecord m0 = m;
    m0.pool_hashrate = 0.0;
    const auto without = m0.serialize();
    ASSERT_EQ(with.size(), without.size() + 8);

    const O::MergedBlockRecord o = O::MergedBlockRecord::deserialize(with);
    EXPECT_EQ(o.block_hash, m.block_hash);
    EXPECT_EQ(o.miner, m.miner);
    EXPECT_EQ(o.share_hash, m.share_hash);
    EXPECT_EQ(o.coinbase_value, m.coinbase_value);
    EXPECT_EQ(o.tx_count.value_or(0), m.tx_count.value_or(0));
    EXPECT_DOUBLE_EQ(o.difficulty, m.difficulty);
    EXPECT_EQ(o.serialize(), without) << "the earlier writer drops only the rate";
    const auto n = MergedBlockRecord::deserialize(o.serialize());
    EXPECT_DOUBLE_EQ(n.pool_hashrate, 0.0);
    EXPECT_DOUBLE_EQ(n.difficulty, m.difficulty);
    EXPECT_EQ(n.serialize(), without);

    for (size_t len = 0; len <= with.size(); ++len) {
        const std::vector<uint8_t> cut(with.begin(), with.begin() + static_cast<std::ptrdiff_t>(len));
        const auto nr = MergedBlockRecord::deserialize(cut);
        (void)O::MergedBlockRecord::deserialize(cut);
        EXPECT_EQ(nr.pool_hashrate > 0.0, len == with.size()) << len;
    }
    // A rate with no known difficulty: it follows a zero difficulty, which
    // the earlier reader reads as "not known", as before.
    MergedBlockRecord nd = m;
    nd.difficulty = 0.0;
    const auto nd_bytes = nd.serialize();
    const auto nd_back = MergedBlockRecord::deserialize(nd_bytes);
    EXPECT_DOUBLE_EQ(nd_back.difficulty, 0.0);
    EXPECT_DOUBLE_EQ(nd_back.pool_hashrate, 1.48e11);
    EXPECT_DOUBLE_EQ(O::MergedBlockRecord::deserialize(nd_bytes).difficulty, 0.0);
}
