// KATs for c2pool-utxo (src/core/utxo_tools.{hpp,cpp}) through its library
// entry point, so CI runs the CLI paths without the binary.

#include "utxo_kat_fixture.hpp"

#include <core/coin/utxo_snapshot.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/leveldb_store.hpp>
#include <core/utxo_tools.hpp>

#include <gtest/gtest.h>

#include <sstream>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace core::coin;
using namespace utxo_kat;

namespace {

struct Run {
    int code{0};
    std::string out;
    std::string err;
};

Run tool(const std::vector<std::string>& args)
{
    std::ostringstream out, err;
    Run r;
    r.code = core::run_utxo_tool(args, out, err);
    r.out = out.str();
    r.err = err.str();
    return r;
}

bool has_line(const std::string& text, const std::string& line)
{
    return ("\n" + text).find("\n" + line + "\n") != std::string::npos;
}

std::string write_syn_file(const utxo_kat::TempDir& tmp)
{
    const std::string file = tmp.sub("syn.dat");
    SnapshotWriter w(file);
    const auto coins = synthetic_set();
    EXPECT_TRUE(w.begin(SnapshotMetadata{syn_best(), coins.size()}));
    for (const auto& k : coins) EXPECT_TRUE(w.append(k.op, k.coin));
    EXPECT_TRUE(w.finish());
    return file;
}

} // namespace

TEST(UtxoTool, InspectImportHashDumpPinEndToEnd)
{
    utxo_kat::TempDir tmp("tool");
    const std::string file = write_syn_file(tmp);
    const std::string sha = sha256_hex(read_file(file));

    // inspect, every expectation met
    auto r = tool({"--utxo-inspect", file, "--expect-coins", "307", "--expect-base", kSynBestHex, "--expect-muhash",
                   kSynMuhash, "--expect-hash-serialized-2", kSynHashSer2, "--expect-sha256", sha});
    EXPECT_EQ(r.code, 0) << r.out << r.err;
    EXPECT_TRUE(has_line(r.out, std::string("muhash ") + kSynMuhash)) << r.out;
    EXPECT_TRUE(has_line(r.out, std::string("hash_serialized_2 ") + kSynHashSer2)) << r.out;
    EXPECT_TRUE(has_line(r.out, "coins 307")) << r.out;
    EXPECT_TRUE(has_line(r.out, "RESULT OK")) << r.out;

    // inspect, one expectation missed
    r = tool({"--utxo-inspect", file, "--expect-muhash", kSynMuhashHeightsPlus1});
    EXPECT_EQ(r.code, 1);
    EXPECT_NE(r.out.find("check muhash MISMATCH"), std::string::npos) << r.out;
    EXPECT_TRUE(has_line(r.out, "RESULT MISMATCH")) << r.out;

    // import without an expected muhash: refused
    const std::string db = tmp.sub("db");
    r = tool({"--utxo-import", file, "--utxo-db", db});
    EXPECT_EQ(r.code, 1);
    EXPECT_NE(r.out.find(snapshot_refusal::kNoPin), std::string::npos) << r.out;

    // import with expectations
    r = tool({"--utxo-import", file, "--utxo-db", db, "--expect-height", "4242", "--expect-base", kSynBestHex,
              "--expect-coins", "307", "--expect-muhash", kSynMuhash, "--expect-hash-serialized-2", kSynHashSer2,
              "--expect-sha256", sha});
    EXPECT_EQ(r.code, 0) << r.out << r.err;
    EXPECT_TRUE(has_line(r.out, "best_height 4242")) << r.out;
    EXPECT_TRUE(has_line(r.out, "header_chain_check skipped (offline tool)")) << r.out;
    EXPECT_NE(r.err.find("base-in-header-chain: NOT checked"), std::string::npos) << r.err;

    // hash the imported DB: both hashes at its best block
    r = tool({"--utxo-hash", db});
    EXPECT_EQ(r.code, 0) << r.out;
    EXPECT_TRUE(has_line(r.out, std::string("muhash ") + kSynMuhash)) << r.out;
    EXPECT_TRUE(has_line(r.out, std::string("hash_serialized_2 ") + kSynHashSer2)) << r.out;
    EXPECT_TRUE(has_line(r.out, std::string("best_block ") + kSynBestHex)) << r.out;
    r = tool({"--utxo-hash", db, "--muhash"});
    EXPECT_TRUE(has_line(r.out, std::string("muhash ") + kSynMuhash)) << r.out;
    EXPECT_EQ(r.out.find("hash_serialized_2"), std::string::npos) << r.out;

    // dump it back out: byte-identical to the original file
    const std::string dumped = tmp.sub("dumped.dat");
    r = tool({"--utxo-dump", db, dumped});
    EXPECT_EQ(r.code, 2) << "an offline dump must say --utxo-dump-at-best";
    r = tool({"--utxo-dump", db, dumped, "--utxo-dump-at-best"});
    EXPECT_EQ(r.code, 0) << r.out;
    EXPECT_TRUE(has_line(r.out, "sha256 " + sha)) << r.out;
    EXPECT_EQ(read_file(dumped), read_file(file));

    // pin: generated, parsed back, and accepted by --utxo-import
    r = tool({"--dump-utxo-snapshot-pin", file, "--coin", "test", "--network", "regtest", "--height", "4242",
              "--sources", "kat", "--generated", "2026-10-30T00:00:00Z"});
    ASSERT_EQ(r.code, 0) << r.out << r.err;
    std::string perr;
    auto pin = parse_snapshot_pin(r.out, perr);
    ASSERT_TRUE(pin) << perr << "\n" << r.out;
    EXPECT_EQ(pin->muhash.GetHex(), kSynMuhash);
    EXPECT_EQ(pin->parts.at(0).sha256, sha);
    const std::string pin_file = tmp.sub("pin.inc");
    r = tool({"--dump-utxo-snapshot-pin", file, "--coin", "test", "--network", "regtest", "--height", "4242",
              "--generated", "2026-10-30T00:00:00Z", "--inc"});
    ASSERT_EQ(r.code, 0);
    {
        std::ofstream f(pin_file);
        f << r.out;
    }
    r = tool({"--utxo-import", file, "--utxo-db", tmp.sub("db2"), "--utxo-snapshot-pin", pin_file});
    EXPECT_EQ(r.code, 0) << r.out << r.err;

    // a tampered pin file is refused
    {
        std::ifstream f(pin_file);
        std::stringstream ss;
        ss << f.rdbuf();
        std::string text = ss.str();
        text.replace(text.find("height 4242"), 11, "height 4243");
        std::ofstream o(pin_file, std::ios::trunc);
        o << text;
    }
    r = tool({"--utxo-import", file, "--utxo-db", tmp.sub("db3"), "--utxo-snapshot-pin", pin_file});
    EXPECT_EQ(r.code, 1);
    EXPECT_NE(r.out.find("utxo-snapshot-pin-invalid"), std::string::npos) << r.out;
}

TEST(UtxoTool, RefusesAbsentDbWithoutCreatingIt)
{
    utxo_kat::TempDir tmp("absent");
    const std::string db = tmp.sub("nope");
    auto r = tool({"--utxo-hash", db});
    EXPECT_EQ(r.code, 1);
    EXPECT_NE(r.out.find("utxo-db-absent"), std::string::npos) << r.out;
    EXPECT_FALSE(std::filesystem::exists(db));
    r = tool({"--utxo-dump", db, tmp.sub("x.dat"), "--utxo-dump-at-best"});
    EXPECT_EQ(r.code, 1);
    EXPECT_FALSE(std::filesystem::exists(db));
}

TEST(UtxoTool, UsageErrors)
{
    EXPECT_EQ(tool({}).code, 2);
    EXPECT_EQ(tool({"--bogus"}).code, 2);
    EXPECT_EQ(tool({"--utxo-hash"}).code, 2);
    EXPECT_EQ(tool({"--utxo-hash", "a", "--utxo-inspect", "b"}).code, 2);
    EXPECT_EQ(tool({"--utxo-import", "f"}).code, 2);
    EXPECT_EQ(tool({"--dump-utxo-snapshot-pin", "f", "--coin", "dash"}).code, 2);
}

#if !defined(_WIN32)
TEST(UtxoTool, RefusesHeldDb)
{
    // The 10-30 incident: a read-only tool opened the DB a live node held and
    // "recovered" its LOCK. The tool must refuse instead, by name.
    utxo_kat::TempDir tmp("toolheld");
    const std::string file = write_syn_file(tmp);
    const std::string db = tmp.sub("db");
    auto r = tool({"--utxo-import", file, "--utxo-db", db, "--expect-height", "4242", "--expect-base", kSynBestHex,
                   "--expect-coins", "307", "--expect-muhash", kSynMuhash});
    ASSERT_EQ(r.code, 0) << r.out << r.err;
    const std::string lock = db + "/LOCK";

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

    r = tool({"--utxo-hash", db});
    EXPECT_EQ(r.code, 1);
    EXPECT_NE(r.out.find(snapshot_refusal::kDbHeld), std::string::npos) << r.out;
    r = tool({"--utxo-dump", db, tmp.sub("d.dat"), "--utxo-dump-at-best"});
    EXPECT_EQ(r.code, 1);
    EXPECT_NE(r.out.find(snapshot_refusal::kDbHeld), std::string::npos) << r.out;
    EXPECT_TRUE(std::filesystem::exists(lock));

    c = 'x';
    ASSERT_EQ(::write(release[1], &c, 1), 1);
    int status = 0;
    ::waitpid(child, &status, 0);
    for (int fd : {ready[0], ready[1], release[0], release[1]}) ::close(fd);

    // Released: the same DB hashes to the imported set.
    r = tool({"--utxo-hash", db});
    EXPECT_EQ(r.code, 0) << r.out;
    EXPECT_TRUE(has_line(r.out, std::string("muhash ") + kSynMuhash)) << r.out;
}
#endif
