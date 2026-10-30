// SPDX-License-Identifier: AGPL-3.0-or-later
//
// core::LevelDBStore::open and the DB's LOCK. LevelDB locks <dir>/LOCK with
// fcntl: the kernel releases a dead holder's lock, so a lock that cannot be
// taken is held by an open DB, never stale. open() used to unlink LOCK and
// open again (then RepairDB): a second process (--utxo-digest) opened a live
// IBD's full UTXO set beside it, 68 table files went missing and a
// 4.75 M-height set was lost. Pinned here:
//   * a DB held by another process: open() fails, LOCK stays (the same
//     inode), the holder's data is intact;
//   * a DB held by another handle in this process: the same;
//   * a LOCK file nobody holds (a crash leaves one): open() opens.

#include <gtest/gtest.h>

#include <core/leveldb_store.hpp>

#include <leveldb/db.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <random>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

struct TempDir {
    std::filesystem::path dir;
    TempDir()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("leveldb_lock_" + std::to_string(rng()));
    }
    ~TempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

/// The file's inode (0 where there is none to read): LOCK unlinked and made
/// again is another inode.
uint64_t inode_of(const std::filesystem::path& p)
{
#if !defined(_WIN32)
    struct stat st {};
    return ::stat(p.c_str(), &st) == 0 ? uint64_t(st.st_ino) : 0;
#else
    return std::filesystem::exists(p) ? 1 : 0;
#endif
}

std::vector<uint8_t> bytes(const std::string& s) { return std::vector<uint8_t>(s.begin(), s.end()); }

/// A DB with one record, closed.
void make_db(const std::filesystem::path& dir)
{
    core::LevelDBStore db(dir.string(), core::LevelDBOptions{});
    ASSERT_TRUE(db.open());
    ASSERT_TRUE(db.put("k", bytes("held")));
}

} // namespace

#if !defined(_WIN32)
// Another process holds the DB open (the IBD); this one opens it too (a
// --utxo-digest run): the open fails and nothing of the holder's is touched.
TEST(LevelDBStoreLock, ADbHeldByAnotherProcessDoesNotOpen)
{
    TempDir t;
    make_db(t.dir);
    const auto lock = t.dir / "LOCK";
    ASSERT_TRUE(std::filesystem::exists(lock));
    const uint64_t before = inode_of(lock);

    int ready[2], done[2];
    ASSERT_EQ(::pipe(ready), 0);
    ASSERT_EQ(::pipe(done), 0);
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        // The holder: LevelDB itself (no logging after fork), writes while
        // the parent tries, then closes.
        leveldb::DB* db = nullptr;
        leveldb::Options o;
        if (!leveldb::DB::Open(o, t.dir.string(), &db).ok())
            ::_exit(2);
        char c = 1;
        if (::write(ready[1], &c, 1) != 1)
            ::_exit(3);
        if (::read(done[0], &c, 1) != 1)
            ::_exit(4);
        const bool ok = db->Put(leveldb::WriteOptions(), "k2", "after").ok();
        delete db;
        ::_exit(ok ? 0 : 5);
    }
    char c = 0;
    ASSERT_EQ(::read(ready[0], &c, 1), 1) << "the holder did not open the DB";

    bool opened = false;
    {
        core::LevelDBStore second(t.dir.string(), core::LevelDBOptions{});
        opened = second.open();
    }
    const bool lock_there = std::filesystem::exists(lock);
    const uint64_t during = inode_of(lock);
    c = 1;
    ASSERT_EQ(::write(done[1], &c, 1), 1);
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);

    EXPECT_FALSE(opened) << "a DB another process holds was opened beside it";
    EXPECT_TRUE(lock_there) << "LOCK was unlinked under its holder";
    EXPECT_EQ(during, before) << "LOCK was replaced under its holder";
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0) << "the holder's DB failed after the second open";

    // The holder's data, after it closed: both records, nothing repaired.
    core::LevelDBStore db(t.dir.string(), core::LevelDBOptions{});
    ASSERT_TRUE(db.open());
    std::vector<uint8_t> v;
    EXPECT_TRUE(db.get("k", v) && v == bytes("held"));
    EXPECT_TRUE(db.get("k2", v) && v == bytes("after"));
    EXPECT_FALSE(std::filesystem::exists(t.dir / "lost")) << "RepairDB ran on a live DB";
}
#endif

// Two handles in one process: the second open fails, the first keeps working.
TEST(LevelDBStoreLock, ASecondOpenInThisProcessDoesNotOpen)
{
    TempDir t;
    core::LevelDBStore first(t.dir.string(), core::LevelDBOptions{});
    ASSERT_TRUE(first.open());
    ASSERT_TRUE(first.put("k", bytes("one")));
    const auto lock = t.dir / "LOCK";
    const uint64_t before = inode_of(lock);
    {
        core::LevelDBStore second(t.dir.string(), core::LevelDBOptions{});
        EXPECT_FALSE(second.open());
    }
    EXPECT_EQ(inode_of(lock), before) << "LOCK was unlinked or replaced under its holder";
    EXPECT_FALSE(std::filesystem::exists(t.dir / "lost")) << "RepairDB ran on a live DB";
    ASSERT_TRUE(first.put("k2", bytes("two")));
    std::vector<uint8_t> v;
    EXPECT_TRUE(first.get("k", v) && v == bytes("one"));
    EXPECT_TRUE(first.get("k2", v) && v == bytes("two"));
}

// A LOCK file nobody holds (a crashed process leaves one): the DB opens.
TEST(LevelDBStoreLock, AnUnheldLockFileOpens)
{
    TempDir t;
    make_db(t.dir);
    ASSERT_TRUE(std::filesystem::exists(t.dir / "LOCK"));
    core::LevelDBStore db(t.dir.string(), core::LevelDBOptions{});
    ASSERT_TRUE(db.open());
    std::vector<uint8_t> v;
    EXPECT_TRUE(db.get("k", v) && v == bytes("held"));
}
