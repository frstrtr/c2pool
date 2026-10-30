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
//   * a DB held by another handle in this process: the same, refused before
//     LevelDB (whose refusal closes a descriptor of LOCK and so drops this
//     process's fcntl lock: another process could then open it);
//   * the held status is read on every platform (env_windows has no "lock "
//     prefix: a sharing violation on <dir>/LOCK);
//   * open_waiting takes the DB once its holder closes;
//   * a sharechain store another c2pool holds exits the node with what to do;
//   * a LOCK file nobody holds (a crash leaves one): open() opens.

#include <gtest/gtest.h>

#include <c2pool/storage/sharechain_storage.hpp>
#include <core/filesystem.hpp>
#include <core/leveldb_store.hpp>

#include <leveldb/db.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <random>
#include <string>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#include <fcntl.h>
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

    bool opened = false, held = false;
    {
        core::LevelDBStore second(t.dir.string(), core::LevelDBOptions{});
        opened = second.open();
        held = second.lock_held();
    }
    const bool lock_there = std::filesystem::exists(lock);
    const uint64_t during = inode_of(lock);
    c = 1;
    ASSERT_EQ(::write(done[1], &c, 1), 1);
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);

    EXPECT_FALSE(opened) << "a DB another process holds was opened beside it";
    EXPECT_TRUE(held) << "the refusal does not say the DB is held";
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
        EXPECT_TRUE(second.lock_held());
    }
    {
        // Another spelling of the same directory.
        core::LevelDBStore third((t.dir / "." ).string(), core::LevelDBOptions{});
        EXPECT_FALSE(third.open()) << "the same DB under another spelling of its path";
    }
    EXPECT_EQ(inode_of(lock), before) << "LOCK was unlinked or replaced under its holder";
    EXPECT_FALSE(std::filesystem::exists(t.dir / "lost")) << "RepairDB ran on a live DB";
#if !defined(_WIN32)
    // The refused opens left the first handle's fcntl lock in place: another
    // process cannot take LOCK (a forked child: it does not inherit fcntl
    // locks, so it asks the kernel as a separate process would).
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        const int fd = ::open(lock.c_str(), O_RDWR);
        if (fd < 0)
            ::_exit(3);
        struct flock f {};
        f.l_type = F_WRLCK;
        f.l_whence = SEEK_SET;
        ::_exit(::fcntl(fd, F_SETLK, &f) == 0 ? 0 : 1);  // 0: the lock was free
    }
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 1) << "after a refused second open another process can take LOCK";
#endif
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

// The status a held LOCK gives on each platform (LevelDB 1.23): env_posix
// "lock <dir>/LOCK: ...", env_windows "<dir>/LOCK: <sharing violation>" (no
// "lock " prefix). Anything else is not a held lock.
TEST(LevelDBStoreLock, AHeldLockIsReadOnEveryPlatform)
{
    const std::string dir = "/data/dogecoin/utxo_full_leveldb";
    EXPECT_TRUE(core::leveldb_status_lock_held(
        leveldb::Status::IOError("lock " + dir + "/LOCK", "Resource temporarily unavailable"), dir));
    EXPECT_TRUE(core::leveldb_status_lock_held(
        leveldb::Status::IOError("lock " + dir + "/LOCK", "already held by process"), dir));
    EXPECT_TRUE(core::leveldb_status_lock_held(
        leveldb::Status::IOError(dir + "/LOCK",
                                 "The process cannot access the file because it is being used by another process."),
        dir))
        << "env_windows";
    EXPECT_FALSE(core::leveldb_status_lock_held(leveldb::Status::Corruption(dir + "/LOCK", "x"), dir));
    EXPECT_FALSE(core::leveldb_status_lock_held(leveldb::Status::IOError(dir + "/000005.ldb", "x"), dir));
    EXPECT_FALSE(core::leveldb_status_lock_held(
        leveldb::Status::IOError("lock /other/LOCK", "Resource temporarily unavailable"), dir));
}

// A restart that overlaps the process it replaces: open_waiting takes the DB
// once the holder closes; a holder that stays makes it give up, held.
TEST(LevelDBStoreLock, OpenWaitingTakesTheDbOnceItsHolderCloses)
{
    TempDir t;
    auto holder = std::make_unique<core::LevelDBStore>(t.dir.string(), core::LevelDBOptions{});
    ASSERT_TRUE(holder->open());
    {
        core::LevelDBStore waiter(t.dir.string(), core::LevelDBOptions{});
        EXPECT_FALSE(waiter.open_waiting(3, std::chrono::milliseconds(10)));
        EXPECT_TRUE(waiter.lock_held());
    }
    std::thread closer([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        holder.reset();
    });
    core::LevelDBStore waiter(t.dir.string(), core::LevelDBOptions{});
    const bool opened = waiter.open_waiting(50, std::chrono::milliseconds(20));
    closer.join();
    EXPECT_TRUE(opened);
    EXPECT_FALSE(waiter.lock_held());
}

#if !defined(_WIN32)
namespace {

[[noreturn]] void open_held_sharechain(const std::string& data_dir)
{
    core::filesystem::set_data_dir(data_dir);
    c2pool::storage::SharechainStorage storage("kat", 2, std::chrono::milliseconds(10));
    std::exit(0);  // opened beside its holder
}

} // namespace

// A node whose sharechain store another c2pool holds (the same --data-dir):
// it waits, then exits saying what to do, instead of running without
// persistence and losing every share of the run.
TEST(LevelDBStoreLock, AHeldSharechainStoreExitsTheNode)
{
    TempDir t;
    std::filesystem::create_directories(t.dir);
    core::SharechainLevelDBStore holder(t.dir.string(), "kat");
    ASSERT_TRUE(holder.open());
    // The death test's child finds the DB held: by the kernel's lock (another
    // process), or by the registry when it is a fork of this one.
    EXPECT_EXIT(open_held_sharechain(t.dir.string()), ::testing::ExitedWithCode(EXIT_FAILURE),
                "stop the other c2pool using this --data-dir");
}
#endif
