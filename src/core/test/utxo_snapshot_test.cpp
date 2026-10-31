// KATs for the Dash Core v23 `dumptxoutset` reader / writer, the pin, the
// import into a UTXOViewDB and the dump back out
// (src/core/coin/utxo_snapshot.{hpp,cpp}).

#include "utxo_kat_fixture.hpp"

#include <core/coin/coin_compressor.hpp>
#include <core/coin/utxo_set_hash.hpp>
#include <core/coin/utxo_snapshot.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/leveldb_store.hpp>

#include <btclibs/crypto/common.h>

#include <gtest/gtest.h>

#include <cstdlib>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace core::coin;
using namespace utxo_kat;
namespace R = core::coin::snapshot_refusal;

namespace {

SnapshotPin real3_pin(const std::vector<unsigned char>& bytes)
{
    SnapshotPin pin;
    pin.coin = "dash";
    pin.network = "mainnet";
    pin.height = 2564044;
    pin.blockhash = display_hash(kRealBaseHex);
    pin.coins = 3;
    pin.muhash = display_hash(kReal3Muhash);
    pin.hash_serialized_2 = display_hash(kReal3HashSer2);
    pin.parts.push_back({bytes.size(), sha256_hex(bytes)});
    return pin;
}

SnapshotImportOptions opts_at(uint32_t height, const uint256& hash)
{
    SnapshotImportOptions o;
    o.hash_at_height = [height, hash](uint32_t h) -> std::optional<uint256> {
        if (h == height) return hash;
        return std::nullopt;
    };
    o.batch_records = 2;  // several batches even for tiny sets
    return o;
}

/// The DB at `dir` holds no key at all (opened only after the importer closed it).
bool db_empty(const std::string& dir)
{
    core::LevelDBStore store(dir, core::LevelDBOptions{});
    if (!store.open()) return false;
    const bool empty = leveldb_store_empty(store);
    store.close();
    return empty;
}

std::vector<unsigned char> coin_bytes(const Outpoint& op, const Coin& c)
{
    std::vector<unsigned char> b(op.txid.data(), op.txid.data() + 32);
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<unsigned char>(op.index >> (8 * i)));
    SerializeCoreCoin(b, c);
    return b;
}

void write_snapshot(const std::string& path, const uint256& base, const std::vector<KatCoin>& coins)
{
    SnapshotWriter w(path);
    ASSERT_TRUE(w.begin(SnapshotMetadata{base, coins.size()}));
    for (const auto& k : coins) ASSERT_TRUE(w.append(k.op, k.coin)) << w.refusal() << " " << w.detail();
    ASSERT_TRUE(w.finish()) << w.refusal() << " " << w.detail();
}

} // namespace

TEST(UtxoSnapshot, ReadsDashV23Layout)
{
    // Metadata of the real 2564044 dump, then its first three coins verbatim.
    utxo_kat::TempDir tmp("read");
    const auto bytes = real3_file_bytes();
    ASSERT_EQ(bytes.size(), 40u + 64 + 64 + 62);
    const std::string file = tmp.sub("real3.dat");
    write_file(file, bytes);

    SnapshotReader rd({file});
    ASSERT_TRUE(rd.open()) << rd.refusal();
    EXPECT_EQ(rd.metadata().base_blockhash.GetHex(), kRealBaseHex);
    EXPECT_EQ(rd.metadata().coins_count, 3u);

    struct Want { const char* txid; uint32_t n; uint32_t h; int64_t v; const char* spk; };
    const Want want[3] = {
        {"27de47f603388191b858584847c1216772d839197e3c42854ceba19a87080000", 1, 2542518, 100001000,
         "76a9143a3b7b6c89a099c64fbc24b2c1d9ceddcbffec5488ac"},
        {"6e2439332b1a3d4c160f4237177b17fa38cfe24642acf402e05a98fda70d0000", 1, 732902, 28035698,
         "76a914349678549f2d4c15196e72ddff587d0da93e8b6188ac"},
        {"af28456d16075c3f14eb103c789657f52a1d2b81349c81d9e2c183c692100000", 0, 881512, 31600,
         "76a91465bc8282cf566e7c17caf069ecbfb414eba3042988ac"},
    };
    Outpoint op;
    Coin c;
    for (const auto& w : want) {
        ASSERT_TRUE(rd.next(op, c)) << rd.refusal() << " " << rd.detail();
        EXPECT_EQ(op.txid.GetHex(), w.txid);
        EXPECT_EQ(op.index, w.n);
        EXPECT_EQ(c.height, w.h);
        EXPECT_FALSE(c.coinbase);
        EXPECT_EQ(c.value, w.v);
        EXPECT_EQ(to_hex(c.scriptPubKey.m_data), w.spk);
    }
    EXPECT_FALSE(rd.next(op, c));
    EXPECT_FALSE(rd.refused());
    ASSERT_TRUE(rd.finish()) << rd.refusal();
    ASSERT_EQ(rd.parts().size(), 1u);
    EXPECT_EQ(rd.parts()[0].bytes, bytes.size());
    EXPECT_EQ(rd.parts()[0].sha256, sha256_hex(bytes));

    // The scan gives the reference hashes; the writer reproduces the bytes.
    const auto scan = scan_utxo_snapshot({file});
    ASSERT_TRUE(scan.ok) << scan.refusal << " " << scan.detail;
    EXPECT_EQ(scan.hashes.muhash.GetHex(), kReal3Muhash);
    EXPECT_EQ(scan.hashes.hash_serialized_2.GetHex(), kReal3HashSer2);
    EXPECT_EQ(scan.special_scripts[0], 3u);

    SnapshotReader rd2({file});
    ASSERT_TRUE(rd2.open());
    std::vector<KatCoin> coins;
    while (rd2.next(op, c)) coins.push_back({op, c});
    const std::string again = tmp.sub("again.dat");
    write_snapshot(again, rd2.metadata().base_blockhash, coins);
    EXPECT_EQ(read_file(again), bytes);
    EXPECT_FALSE(std::filesystem::exists(again + ".incomplete"));
}

TEST(UtxoSnapshot, SyntheticSetFileMatchesIndependentReference)
{
    utxo_kat::TempDir tmp("syn");
    const std::string file = tmp.sub("syn.dat");
    write_snapshot(file, syn_best(), synthetic_set());
    const auto scan = scan_utxo_snapshot({file});
    ASSERT_TRUE(scan.ok) << scan.refusal << " " << scan.detail;
    EXPECT_EQ(scan.meta.coins_count, 307u);
    EXPECT_EQ(scan.hashes.muhash.GetHex(), kSynMuhash);
    EXPECT_EQ(scan.hashes.hash_serialized_2.GetHex(), kSynHashSer2);
    EXPECT_EQ(scan.hashes.zero_value_coins, 1u);
    EXPECT_EQ(scan.hashes.empty_script_coins, 1u);
}

TEST(UtxoSnapshot, RefusesSha256CountBaseTruncationOverrunUnorderedUnspendable)
{
    utxo_kat::TempDir tmp("refuse");
    const auto bytes = real3_file_bytes();
    const auto base = display_hash(kRealBaseHex);
    const std::string good = tmp.sub("good.dat");
    write_file(good, bytes);
    int n = 0;
    auto run = [&](const std::vector<std::string>& files, const SnapshotPin& pin, SnapshotImportOptions o,
                   const char* want) {
        const std::string db = tmp.sub("db" + std::to_string(n++));
        const auto r = import_utxo_snapshot(files, db, pin, o);
        EXPECT_FALSE(r.ok) << want;
        EXPECT_EQ(r.refusal, want) << r.detail;
        EXPECT_TRUE(db_empty(db)) << want << ": the DB must stay empty";
        return r;
    };
    const auto o = opts_at(2564044, base);

    {   // sha256 of the part
        auto pin = real3_pin(bytes);
        pin.parts[0].sha256[0] = pin.parts[0].sha256[0] == '0' ? '1' : '0';
        const auto r = run({good}, pin, o, R::kSha256Mismatch);
        EXPECT_NE(r.detail.find("part 0"), std::string::npos) << r.detail;
    }
    {   // part size
        auto pin = real3_pin(bytes);
        pin.parts[0].size += 1;
        run({good}, pin, o, R::kSha256Mismatch);
    }
    {   // coins_count vs the pin
        auto pin = real3_pin(bytes);
        pin.coins = 4;
        run({good}, pin, o, R::kCountMismatch);
    }
    {   // base vs the pin
        auto pin = real3_pin(bytes);
        pin.blockhash = syn_best();
        run({good}, pin, o, R::kBaseMismatch);
    }
    {   // base not our header at the pinned height
        run({good}, real3_pin(bytes), opts_at(2564044, syn_best()), R::kNotInHeaderChain);
        run({good}, real3_pin(bytes), opts_at(2564043, base), R::kNotInHeaderChain);
    }
    {   // no header chain and not declared offline
        SnapshotImportOptions none;
        run({good}, real3_pin(bytes), none, R::kNoHeaderChain);
    }
    {   // no pin
        SnapshotPin empty;
        run({good}, empty, o, R::kNoPin);
    }
    {   // truncated: the file ends inside the last coin, and inside the metadata
        auto cut = bytes;
        cut.resize(cut.size() - 5);
        const std::string f = tmp.sub("cut.dat");
        write_file(f, cut);
        auto pin = real3_pin(bytes);
        pin.parts.clear();
        run({f}, pin, o, R::kTruncated);
        cut.resize(30);
        write_file(f, cut);
        run({f}, pin, o, R::kTruncated);
    }
    {   // overrun: a byte after the last coin
        auto longer = bytes;
        longer.push_back(0x00);
        const std::string f = tmp.sub("long.dat");
        write_file(f, longer);
        auto pin = real3_pin(bytes);
        pin.parts.clear();
        run({f}, pin, o, R::kOverrun);
    }
    {   // unordered: coins 1 and 2 swapped
        std::vector<std::vector<unsigned char>> coins = {hex(kRealCoinBytes[0]), hex(kRealCoinBytes[2]),
                                                         hex(kRealCoinBytes[1])};
        const std::string f = tmp.sub("unordered.dat");
        write_file(f, snapshot_bytes(base, 3, coins));
        auto pin = real3_pin(bytes);
        pin.parts.clear();
        run({f}, pin, o, R::kUnordered);
    }
    {   // a repeated outpoint is unordered too
        std::vector<std::vector<unsigned char>> coins = {hex(kRealCoinBytes[0]), hex(kRealCoinBytes[0]),
                                                         hex(kRealCoinBytes[1])};
        const std::string f = tmp.sub("dup.dat");
        write_file(f, snapshot_bytes(base, 3, coins));
        auto pin = real3_pin(bytes);
        pin.parts.clear();
        run({f}, pin, o, R::kUnordered);
    }
    {   // unspendable: an OP_RETURN script, and a script over MAX_SCRIPT_SIZE
        Outpoint op = Outpoint(display_hash("00000000000000000000000000000000000000000000000000000000000000ff"), 0);
        std::vector<unsigned char> opret(op.txid.data(), op.txid.data() + 32);
        for (unsigned char b : hex("00000000" "02" "00" "0c" "6a0401020304")) opret.push_back(b);
        std::vector<std::vector<unsigned char>> coins = {hex(kRealCoinBytes[0]), hex(kRealCoinBytes[1]),
                                                         hex(kRealCoinBytes[2]), opret};
        const std::string f = tmp.sub("opret.dat");
        write_file(f, snapshot_bytes(base, 4, coins));
        auto pin = real3_pin(bytes);
        pin.parts.clear();
        pin.coins = 4;
        run({f}, pin, o, R::kUnspendable);

        std::vector<unsigned char> big(op.txid.data(), op.txid.data() + 32);
        for (unsigned char b : hex("00000000" "02" "00")) big.push_back(b);
        WriteVarInt(big, static_cast<unsigned int>(MAX_SCRIPT_SIZE + 1 + nSpecialScripts));
        big.insert(big.end(), MAX_SCRIPT_SIZE + 1, 0x51);
        coins.back() = big;
        write_file(f, snapshot_bytes(base, 4, coins));
        run({f}, pin, o, R::kUnspendable);
    }
    {   // a 0x04 point that does not decompress
        Outpoint op = Outpoint(display_hash("00000000000000000000000000000000000000000000000000000000000000ff"), 0);
        std::vector<unsigned char> bad(op.txid.data(), op.txid.data() + 32);
        for (unsigned char b : hex("00000000" "02" "00" "04")) bad.push_back(b);
        for (unsigned char b : hex("0000000000000000000000000000000000000000000000000000000000000005")) bad.push_back(b);
        std::vector<std::vector<unsigned char>> coins = {hex(kRealCoinBytes[0]), hex(kRealCoinBytes[1]),
                                                         hex(kRealCoinBytes[2]), bad};
        const std::string f = tmp.sub("badpk.dat");
        write_file(f, snapshot_bytes(base, 4, coins));
        auto pin = real3_pin(bytes);
        pin.parts.clear();
        pin.coins = 4;
        const auto r = run({f}, pin, o, R::kBadCoin);
        EXPECT_NE(r.detail.find("bad-pubkey"), std::string::npos) << r.detail;
    }
}

TEST(UtxoSnapshot, MuhashMismatchWipes)
{
    utxo_kat::TempDir tmp("wipe");
    const std::string file = tmp.sub("syn.dat");
    write_snapshot(file, syn_best(), synthetic_set());
    const auto bytes = read_file(file);
    SnapshotPin pin;
    pin.coin = "test";
    pin.network = "regtest";
    pin.height = 4242;
    pin.blockhash = syn_best();
    pin.coins = 307;
    pin.muhash = display_hash(kSynMuhash);
    pin.hash_serialized_2 = display_hash(kSynHashSer2);
    pin.parts.push_back({bytes.size(), sha256_hex(bytes)});
    const auto o = opts_at(4242, syn_best());

    {   // a wrong muhash: refused before anything is written
        auto p = pin;
        p.muhash = display_hash(kSynMuhashHeightsPlus1);
        const std::string db = tmp.sub("db-mu");
        const auto r = import_utxo_snapshot({file}, db, p, o);
        EXPECT_EQ(r.refusal, R::kMuhashMismatch) << r.detail;
        EXPECT_NE(r.detail.find(kSynMuhash), std::string::npos) << r.detail;
        EXPECT_TRUE(db_empty(db));
    }
    {   // a wrong hash_serialized_2
        auto p = pin;
        p.hash_serialized_2 = display_hash(kEmptyHashSer2);
        const std::string db = tmp.sub("db-hs");
        const auto r = import_utxo_snapshot({file}, db, p, o);
        EXPECT_EQ(r.refusal, R::kHashSer2Mismatch) << r.detail;
        EXPECT_TRUE(db_empty(db));
    }
    {   // the write pass fails half way: every committed batch is wiped
        auto oo = o;
        oo.batch_records = 16;
        oo.test_fail_write_after = 100;
        const std::string db = tmp.sub("db-fault");
        const auto r = import_utxo_snapshot({file}, db, pin, oo);
        EXPECT_EQ(r.refusal, R::kDbWriteFailed) << r.detail;
        EXPECT_NE(r.detail.find("wiped back to empty"), std::string::npos) << r.detail;
        EXPECT_TRUE(db_empty(db));
    }
    {   // the same pin and file import cleanly
        const std::string db = tmp.sub("db-ok");
        const auto r = import_utxo_snapshot({file}, db, pin, o);
        ASSERT_TRUE(r.ok) << r.refusal << " " << r.detail;
        EXPECT_EQ(r.coins, 307u);
        EXPECT_FALSE(db_empty(db));
    }
}

TEST(UtxoSnapshot, ImportIsReadableByUtxoViewDB)
{
    utxo_kat::TempDir tmp("import");
    const std::string file = tmp.sub("syn.dat");
    const auto coins = synthetic_set();
    write_snapshot(file, syn_best(), coins);
    SnapshotPin pin;
    pin.height = 4242;
    pin.blockhash = syn_best();
    pin.coins = coins.size();
    pin.muhash = display_hash(kSynMuhash);
    pin.hash_serialized_2 = display_hash(kSynHashSer2);
    const std::string db = tmp.sub("db");
    std::vector<std::string> log;
    auto o = opts_at(4242, syn_best());
    o.log = [&](const std::string& l) { log.push_back(l); };
    const auto r = import_utxo_snapshot({file}, db, pin, o);
    ASSERT_TRUE(r.ok) << r.refusal << " " << r.detail;
    EXPECT_EQ(r.best_height, 4242u);
    ASSERT_FALSE(log.empty());
    EXPECT_NE(log.back().find("[UTXO-SNAPSHOT] imported coins=307 height=4242 muhash=" + std::string(kSynMuhash)),
              std::string::npos)
        << log.back();

    {   // The node's own class reads the set: best block, height, every coin.
        UTXOViewDB view(db);
        ASSERT_TRUE(view.open());
        EXPECT_EQ(view.get_best_block(), syn_best());
        EXPECT_EQ(view.get_best_height(), 4242u);
        for (const auto& k : coins) {
            Coin c;
            ASSERT_TRUE(view.get_coin(k.op, c)) << k.op.txid.GetHex() << ":" << k.op.index;
            EXPECT_EQ(c.value, k.coin.value);
            EXPECT_EQ(c.height, k.coin.height);
            EXPECT_EQ(c.coinbase, k.coin.coinbase);
            EXPECT_FALSE(c.pegout);
            EXPECT_EQ(c.scriptPubKey.m_data, k.coin.scriptPubKey.m_data);
        }
        view.close();
    }
    {   // The set hashes over the DB equal the file's.
        core::LevelDBStore store(db, core::LevelDBOptions{});
        ASSERT_TRUE(store.open());
        std::string refusal;
        auto h = hash_utxo_view_db(store, UtxoSetHasher::Options{}, refusal);
        ASSERT_TRUE(h) << refusal;
        EXPECT_EQ(h->best_height, 4242u);
        EXPECT_EQ(h->hashes.muhash.GetHex(), kSynMuhash);
        EXPECT_EQ(h->hashes.hash_serialized_2.GetHex(), kSynHashSer2);
        store.close();
    }
    {   // The importer never merges: a second import into it refuses.
        const auto again = import_utxo_snapshot({file}, db, pin, o);
        EXPECT_EQ(again.refusal, R::kDbNotEmpty);
    }
}

TEST(UtxoSnapshot, MultiPartFileConcatenates)
{
    utxo_kat::TempDir tmp("parts");
    const auto bytes = real3_file_bytes();
    // Cut inside the metadata and inside coin 1.
    const size_t cut1 = 17, cut2 = 140;
    const std::vector<std::vector<unsigned char>> pieces = {
        {bytes.begin(), bytes.begin() + cut1},
        {bytes.begin() + cut1, bytes.begin() + cut2},
        {bytes.begin() + cut2, bytes.end()},
    };
    std::vector<std::string> files;
    SnapshotPin pin = real3_pin(bytes);
    pin.parts.clear();
    for (size_t i = 0; i < pieces.size(); ++i) {
        files.push_back(tmp.sub("real3.part0" + std::to_string(i)));
        write_file(files.back(), pieces[i]);
        pin.parts.push_back({pieces[i].size(), sha256_hex(pieces[i])});
    }
    const auto scan = scan_utxo_snapshot(files);
    ASSERT_TRUE(scan.ok) << scan.refusal << " " << scan.detail;
    EXPECT_EQ(scan.hashes.muhash.GetHex(), kReal3Muhash);
    ASSERT_EQ(scan.parts.size(), 3u);
    for (size_t i = 0; i < 3; ++i) {
        EXPECT_EQ(scan.parts[i].bytes, pieces[i].size());
        EXPECT_EQ(scan.parts[i].sha256, sha256_hex(pieces[i]));
    }
    const auto o = opts_at(2564044, display_hash(kRealBaseHex));
    const auto r = import_utxo_snapshot(files, tmp.sub("db"), pin, o);
    EXPECT_TRUE(r.ok) << r.refusal << " " << r.detail;

    // Parts out of order: refused, and the DB stays empty.
    std::vector<std::string> swapped = {files[0], files[2], files[1]};
    const auto bad = import_utxo_snapshot(swapped, tmp.sub("db2"), pin, o);
    EXPECT_FALSE(bad.ok);
    EXPECT_TRUE(db_empty(tmp.sub("db2")));
    // A missing part.
    const auto missing = import_utxo_snapshot({files[0], files[1]}, tmp.sub("db3"), pin, o);
    EXPECT_EQ(missing.refusal, R::kSha256Mismatch);
}

TEST(UtxoSnapshotPin, DigestGatedRoundTrip)
{
    SnapshotPin pin;
    pin.coin = "dash";
    pin.network = "mainnet";
    pin.height = 2564044;
    pin.blockhash = display_hash(kRealBaseHex);
    pin.coins = 4531254;
    pin.muhash = display_hash("c00ab2e7ba53e9981a8c560002bb2229cc855820db6c4434ad2081bd267e32b5");
    pin.hash_serialized_2 = display_hash("eedc6501ea8cbc171199a1c26eaaa812d12f6d34ba7cec91b40d74b72ac4a355");
    pin.parts.push_back({288605502, "50f2579cb842a64bcf04a0934d2367264ddf38e99a2b815c5161a1035cc78160"});
    pin.url = "https://github.com/frstrtr/c2pool/releases/download/utxo-dash-2564044/dash-utxo-2564044.dat";
    pin.sources = "vm210:coinstatsindex tertiary:tip";
    pin.generated = "2026-10-30T18:06:00Z";

    const std::string text = render_snapshot_pin(pin);
    EXPECT_EQ(text.rfind(kSnapshotPinMagic, 0), 0u);
    EXPECT_NE(text.find("\nheight 2564044\n"), std::string::npos);
    EXPECT_NE(text.find("\npart 0 288605502 50f2579cb842a64bcf04a0934d2367264ddf38e99a2b815c5161a1035cc78160\n"),
              std::string::npos);
    std::string err;
    auto back = parse_snapshot_pin(text, err);
    ASSERT_TRUE(back) << err;
    EXPECT_EQ(back->height, pin.height);
    EXPECT_EQ(back->blockhash, pin.blockhash);
    EXPECT_EQ(back->coins, pin.coins);
    EXPECT_EQ(back->muhash, pin.muhash);
    ASSERT_TRUE(back->hash_serialized_2);
    EXPECT_EQ(*back->hash_serialized_2, *pin.hash_serialized_2);
    ASSERT_EQ(back->parts.size(), 1u);
    EXPECT_EQ(back->parts[0].size, 288605502u);
    EXPECT_EQ(back->url, pin.url);

    // The `.inc` literal form parses to the same pin.
    const std::string inc = render_snapshot_pin_inc(pin);
    EXPECT_NE(inc.find("\"c2pool-utxo-snapshot/1\\n\"\n"), std::string::npos) << inc;
    auto from_inc = parse_snapshot_pin(inc, err);
    ASSERT_TRUE(from_inc) << err;
    EXPECT_EQ(from_inc->muhash, pin.muhash);

    // Comments and blank lines are outside the digest domain.
    auto commented = parse_snapshot_pin("# a comment\n\n" + text, err);
    EXPECT_TRUE(commented) << err;

    // A hand edit of any committed line is refused.
    std::string tampered = text;
    tampered.replace(tampered.find("coins 4531254"), 13, "coins 4531255");
    EXPECT_FALSE(parse_snapshot_pin(tampered, err));
    EXPECT_NE(err.find("digest mismatch"), std::string::npos) << err;

    // Missing, unknown, duplicate, wrong magic, wrong format.
    auto strip_line = [&](const std::string& prefix) {
        std::string t = text;
        const size_t p = t.find("\n" + prefix);
        t.erase(p + 1, t.find('\n', p + 1) - p);
        return t;
    };
    EXPECT_FALSE(parse_snapshot_pin(strip_line("muhash "), err));
    EXPECT_FALSE(parse_snapshot_pin(strip_line("digest "), err));
    EXPECT_FALSE(parse_snapshot_pin(text + "extra 1\n", err));
    EXPECT_NE(err.find("unknown key"), std::string::npos) << err;
    EXPECT_FALSE(parse_snapshot_pin(text + "coin dash\n", err));
    EXPECT_NE(err.find("duplicate"), std::string::npos) << err;
    EXPECT_FALSE(parse_snapshot_pin("c2pool-utxo-snapshot/2\n" + text.substr(text.find('\n') + 1), err));
    std::string fmt = text;
    fmt.replace(fmt.find("format dashcore-v23-utxo-v1"), 27, "format bitcoincore-v28-utx");
    EXPECT_FALSE(parse_snapshot_pin(fmt, err));
    EXPECT_NE(err.find("unsupported format"), std::string::npos) << err;
}

TEST(UtxoDump, RoundTripSameDigest)
{
    // A UTXOViewDB written by the node's own class -> dump -> import into a
    // fresh DB: the same set, coin for coin, and the same hashes.
    utxo_kat::TempDir tmp("dump");
    const auto coins = synthetic_set();
    const std::string src = tmp.sub("src");
    {
        UTXOViewDB db(src);
        ASSERT_TRUE(db.open());
        UTXOViewDB::ChangeMap changes;
        for (const auto& k : coins) changes[k.op] = k.coin;
        ASSERT_TRUE(db.write_batch(changes, syn_best(), 4242));
        db.close();
    }
    const std::string file = tmp.sub("dump.dat");
    SnapshotDumpResult d;
    {
        core::LevelDBStore store(src, core::LevelDBOptions{});
        ASSERT_TRUE(store.open());
        d = dump_utxo_snapshot(store, file);
        store.close();
    }
    ASSERT_TRUE(d.ok) << d.refusal << " " << d.detail;
    EXPECT_EQ(d.coins, 307u);
    EXPECT_EQ(d.base_blockhash, syn_best());
    EXPECT_EQ(d.base_height, 4242u);
    EXPECT_EQ(d.hashes.muhash.GetHex(), kSynMuhash);
    EXPECT_EQ(d.hashes.hash_serialized_2.GetHex(), kSynHashSer2);
    EXPECT_EQ(d.sha256, sha256_hex(read_file(file)));

    // The dump is byte-identical to the writer fed the set in key order.
    const std::string direct = tmp.sub("direct.dat");
    write_snapshot(direct, syn_best(), coins);
    EXPECT_EQ(read_file(file), read_file(direct));

    SnapshotPin pin;
    pin.height = 4242;
    pin.blockhash = syn_best();
    pin.coins = 307;
    pin.muhash = d.hashes.muhash;
    pin.hash_serialized_2 = d.hashes.hash_serialized_2;
    pin.parts.push_back({d.bytes, d.sha256});
    const std::string dst = tmp.sub("dst");
    const auto r = import_utxo_snapshot({file}, dst, pin, opts_at(4242, syn_best()));
    ASSERT_TRUE(r.ok) << r.refusal << " " << r.detail;

    core::LevelDBStore a(src, core::LevelDBOptions{});
    core::LevelDBStore b(dst, core::LevelDBOptions{});
    ASSERT_TRUE(a.open());
    ASSERT_TRUE(b.open());
    std::string ra, rb;
    auto ha = hash_utxo_view_db(a, UtxoSetHasher::Options{}, ra);
    auto hb = hash_utxo_view_db(b, UtxoSetHasher::Options{}, rb);
    ASSERT_TRUE(ha && hb) << ra << " " << rb;
    EXPECT_EQ(ha->hashes.muhash, hb->hashes.muhash);
    EXPECT_EQ(ha->hashes.hash_serialized_2, hb->hashes.hash_serialized_2);
    EXPECT_EQ(ha->best_height, hb->best_height);
    // Coin for coin: every 'C' record is byte-identical.
    std::map<std::string, std::vector<uint8_t>> ca, cb;
    a.for_each_prefix("C", [&](const std::string& k, const std::vector<uint8_t>& v) { ca[k] = v; return true; });
    b.for_each_prefix("C", [&](const std::string& k, const std::vector<uint8_t>& v) { cb[k] = v; return true; });
    EXPECT_EQ(ca.size(), 307u);
    EXPECT_EQ(ca, cb);
    a.close();
    b.close();

    // A DB without a best block is not dumped.
    utxo_kat::TempDir empty("dump-empty");
    core::LevelDBStore e(empty.path(), core::LevelDBOptions{});
    ASSERT_TRUE(e.open());
    const auto none = dump_utxo_snapshot(e, empty.sub("x.dat"));
    EXPECT_EQ(none.refusal, R::kDbNoBest);
    EXPECT_FALSE(std::filesystem::exists(empty.sub("x.dat")));
}

#if !defined(_WIN32)
TEST(UtxoSnapshot, HeldDbRefusedAndLeftIntact)
{
    // Another process holds the DB's LevelDB lock (as a running node does):
    // the importer refuses by name and touches nothing, LOCK included.
    utxo_kat::TempDir tmp("held");
    const std::string db = tmp.sub("db");
    {
        core::LevelDBStore s(db, core::LevelDBOptions{});
        ASSERT_TRUE(s.open());
        s.close();
    }
    const std::string lock = db + "/LOCK";
    ASSERT_TRUE(std::filesystem::exists(lock));
    EXPECT_FALSE(leveldb_dir_lock_held(db));

    int ready[2], release[2];
    ASSERT_EQ(::pipe(ready), 0);
    ASSERT_EQ(::pipe(release), 0);
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        const int fd = ::open(lock.c_str(), O_RDWR);
        struct flock fl;
        std::memset(&fl, 0, sizeof(fl));
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        char c = (fd >= 0 && ::fcntl(fd, F_SETLK, &fl) == 0) ? 'y' : 'n';
        (void)!::write(ready[1], &c, 1);
        (void)!::read(release[0], &c, 1);
        ::_exit(0);
    }
    char c = 0;
    ASSERT_EQ(::read(ready[0], &c, 1), 1);
    ASSERT_EQ(c, 'y');

    long holder = 0;
    EXPECT_TRUE(leveldb_dir_lock_held(db, &holder));
    EXPECT_EQ(holder, static_cast<long>(child));

    const auto bytes = real3_file_bytes();
    const std::string file = tmp.sub("real3.dat");
    write_file(file, bytes);
    const auto r = import_utxo_snapshot({file}, db, real3_pin(bytes), opts_at(2564044, display_hash(kRealBaseHex)));
    EXPECT_EQ(r.refusal, R::kDbHeld) << r.detail;
    EXPECT_NE(r.detail.find(std::to_string(child)), std::string::npos) << r.detail;
    EXPECT_TRUE(std::filesystem::exists(lock));

    c = 'x';
    ASSERT_EQ(::write(release[1], &c, 1), 1);
    int status = 0;
    ::waitpid(child, &status, 0);
    for (int fd : {ready[0], ready[1], release[0], release[1]}) ::close(fd);
    EXPECT_FALSE(leveldb_dir_lock_held(db));
}
#endif

TEST(UtxoSnapshotLive, DashMainnet2564044)
{
    // Live KAT, not for CI: set C2POOL_UTXO_LIVE_SNAPSHOT to the real
    // dash-utxo-2564044.dat (dashd 23.1.7 dumptxoutset, VM210). Expected
    // values: the dump's RPC result and `gettxoutsetinfo muhash 2564044`
    // on two independent dashd.
    const char* path = std::getenv("C2POOL_UTXO_LIVE_SNAPSHOT");
    if (!path || !*path) GTEST_SKIP() << "C2POOL_UTXO_LIVE_SNAPSHOT not set";
    SnapshotScanOptions so;
    const auto r = scan_utxo_snapshot({path}, so);
    ASSERT_TRUE(r.ok) << r.refusal << " " << r.detail;
    EXPECT_EQ(r.meta.coins_count, 4531254u);
    EXPECT_EQ(r.hashes.coins, 4531254u);
    EXPECT_EQ(r.meta.base_blockhash.GetHex(), kRealBaseHex);
    EXPECT_EQ(r.bytes, 288605502u);
    ASSERT_EQ(r.parts.size(), 1u);
    EXPECT_EQ(r.parts[0].sha256, "50f2579cb842a64bcf04a0934d2367264ddf38e99a2b815c5161a1035cc78160");
    EXPECT_EQ(r.hashes.muhash.GetHex(), "c00ab2e7ba53e9981a8c560002bb2229cc855820db6c4434ad2081bd267e32b5");
    EXPECT_EQ(r.hashes.hash_serialized_2.GetHex(), "eedc6501ea8cbc171199a1c26eaaa812d12f6d34ba7cec91b40d74b72ac4a355");
}
