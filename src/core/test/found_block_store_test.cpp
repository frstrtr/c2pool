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

#include <algorithm>
#include <atomic>
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
    // Cuts the v3 tail: drops the empty v4 parent tail (len + flag + u64) and
    // the last 2 bytes of the tx_count u32.
    fb.resize(fb.size() - (1 + 1 + 8) - 2);
    auto back = FoundBlockRecord::deserialize(fb);
    EXPECT_EQ(back.block_hash, kHashA);
    EXPECT_FALSE(back.tx_count.has_value());
    EXPECT_TRUE(back.parent_hash.empty());
    EXPECT_FALSE(back.parent_height.has_value());

    MergedBlockRecord m = MergedBlockRecord::deserialize(mblk_v1_record(98, 1, kHashA).v);
    m.tx_count = 7;
    auto mb = m.serialize();
    mb.resize(mb.size() - 2);
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
        fb.resize(fb.size() - (1 + 1 + 8) - (4 - kept));
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
    cut.resize(cut.size() - 3);
    EXPECT_FALSE(FoundBlockRecord::deserialize(cut).parent_height.has_value());
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
