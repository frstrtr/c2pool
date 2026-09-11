// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/p2pool_persist.hpp
//
// PUTTING THE STATE ON A DISK, AND THE FOUR WAYS THAT GOES WRONG.
//
// p2pool_state.hpp decides what a saved monitor looks like. This file is the
// part that touches the filesystem, and it is short because almost all of it is
// the answer to one question: what does a reader see if we die in the middle?
//
// ---------------------------------------------------------------------------
// 1. A TORN FILE IS WORSE THAN NO FILE
// ---------------------------------------------------------------------------
// Writing 3 KB of JSON over the previous 3 KB of JSON is not one operation. A
// process killed between the truncate and the last write leaves a file that is
// half new state and half old state, parses as garbage or -- far worse -- as
// PLAUSIBLE garbage, and the next run starts from it. A monitor whose whole
// purpose is to not lie must not have a failure mode that invents numbers.
//
// So a save is: write a temporary file in the SAME directory, fdatasync it,
// rename() it over the real name. rename() within a directory is atomic on
// POSIX -- every reader sees either the whole previous state or the whole new
// one, at every instant, including during the write. The directory itself is
// then fsynced so the rename survives a power cut and not merely a kill.
//
// The temporary file carries our pid in its name, so two monitors that somehow
// reached the same directory cannot collide on it even in the moment before the
// lock below rules the second one out.
//
// ---------------------------------------------------------------------------
// 2. TWO MONITORS, ONE DIRECTORY
// ---------------------------------------------------------------------------
// The second monitor started against the same state directory must not write to
// it. Not because the file would tear -- rename() protects it -- but because
// the two would overwrite each other's snapshots with different views of the
// world, and the surviving file would be an alternating sequence of two
// sessions with no way to tell them apart.
//
// A `.lock` file held with flock(LOCK_EX | LOCK_NB) decides it. The loser does
// not fail and does not exit: it runs with PERSISTENCE OFF, says so on the
// header row with the winner's pid, and never touches the directory. A monitor
// is a thing you start twice by accident at 4am; refusing to run would be the
// wrong answer, and silently clobbering would be a much worse one. flock is
// released by the kernel when the process dies however it dies, so a killed
// monitor leaves no stale lock to clean up.
//
// ---------------------------------------------------------------------------
// 3. THERE MAY BE NO HOME
// ---------------------------------------------------------------------------
// The default directory is $HOME/p2pmon-state, resolved from the environment
// and then from the password database, because a process started from a service
// manager or a cron job frequently has neither HOME nor a sane cwd.
//
// When neither resolves, persistence is OFF and the header says so. It does NOT
// fall back to /tmp. A state file in /tmp is deleted by the next reboot or by a
// tmpfiles rule in the middle of the night, which produces the one outcome this
// component exists to prevent: numbers that the operator believes are durable
// and are not. An honest "PERSIST OFF (no HOME)" is worth more than a directory
// that works until it does not.
//
// ---------------------------------------------------------------------------
// 4. THE DISK CAN SAY NO
// ---------------------------------------------------------------------------
// Full filesystems, read-only mounts and quota failures are ordinary. Every
// failure here is counted, the last message is kept, and both are rendered on
// the header row AND written into the next state file that does succeed. A
// write error is never fatal to the poll loop: the monitor's job is to watch
// three chains, and it keeps doing that with persistence degraded rather than
// exiting because a disk filled up.
//
// POSIX + STL. No ncurses, no boost, no asio, no threads.
// ---------------------------------------------------------------------------
#pragma once

#include <fcntl.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "impl/xmr/p2pool/p2pool_state.hpp"

namespace c2pool::xmr::p2pool {

// One rotated generation of the journal, and the size that triggers it. 32 MiB
// of one-line digests is several weeks of a 2-second cadence; keeping exactly
// one old generation bounds the directory at 64 MiB without a cron job.
inline constexpr off_t kJournalRotateBytes = 32ull * 1024 * 1024;

class StateStore {
public:
    StateStore() = default;
    ~StateStore() { close_all(); }

    StateStore(const StateStore&) = delete;
    StateStore& operator=(const StateStore&) = delete;

    // $HOME/p2pmon-state, or "" when there is no home to resolve. See note 3.
    static std::string default_dir() {
        const char* env = std::getenv("HOME");
        if (env && *env == '/') return std::string(env) + "/p2pmon-state";
        if (const passwd* pw = ::getpwuid(::getuid()))
            if (pw->pw_dir && pw->pw_dir[0] == '/') return std::string(pw->pw_dir) + "/p2pmon-state";
        return std::string();
    }

    static std::string hostname() {
        char b[256];
        if (::gethostname(b, sizeof(b)) != 0) return std::string("unknown");
        b[sizeof(b) - 1] = '\0';
        return std::string(b);
    }

    // Create the directory (one level; the parent must already exist) and take
    // the lock. Returns false with off_reason() set on every refusal, and the
    // caller keeps running with persistence disabled.
    bool open(const std::string& dir) {
        close_all();
        enabled_ = false;
        off_reason_.clear();
        dir_ = dir;

        if (dir_.empty()) { off_reason_ = "(no HOME)"; return false; }

        if (::mkdir(dir_.c_str(), 0700) != 0 && errno != EEXIST) {
            off_reason_ = "(cannot create " + dir_ + ": " + std::strerror(errno) + ")";
            return false;
        }
        struct stat st{};
        if (::stat(dir_.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
            off_reason_ = "(" + dir_ + " is not a directory)";
            return false;
        }

        const std::string lock_path = path(state::kLockFile);
        lock_fd_ = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (lock_fd_ < 0) {
            off_reason_ = "(cannot open lock: " + std::string(std::strerror(errno)) + ")";
            return false;
        }
        if (::flock(lock_fd_, LOCK_EX | LOCK_NB) != 0) {
            const long other = read_lock_pid();
            off_reason_ = other > 0 ? "(locked by pid " + std::to_string(other) + ")"
                                    : "(locked by another monitor)";
            ::close(lock_fd_);
            lock_fd_ = -1;
            return false;
        }
        // Our pid, for whoever loses the next race.
        if (::ftruncate(lock_fd_, 0) == 0) {
            const std::string me = std::to_string(static_cast<long>(::getpid())) + "\n";
            (void)write_all(lock_fd_, me);
        }

        enabled_ = true;
        return true;
    }

    // Read-only attach: no directory creation, no lock, no writing. This is what
    // `--read` uses, and not taking the lock is the point -- a reader must be
    // able to look at the file WHILE the live monitor is writing it, which is
    // safe precisely because every write lands through rename().
    bool open_read_only(const std::string& dir) {
        close_all();
        dir_       = dir;
        enabled_   = false;
        read_only_ = true;
        if (dir_.empty()) { off_reason_ = "(no HOME)"; return false; }
        return true;
    }

    bool               enabled()    const noexcept { return enabled_; }
    bool               read_only()  const noexcept { return read_only_; }

    // The rotation cap, settable so the KAT can exercise the rotation path with
    // a few hundred bytes instead of 32 MiB. Nothing else changes it.
    void set_journal_rotate_bytes(off_t n) { rotate_bytes_ = n > 0 ? n : kJournalRotateBytes; }
    const std::string& dir()        const noexcept { return dir_; }
    const std::string& off_reason() const noexcept { return off_reason_; }
    std::uint64_t      seq()        const noexcept { return seq_; }
    std::size_t        errors()     const noexcept { return errors_; }
    const std::string& last_error() const noexcept { return last_error_; }
    std::uint64_t      journal_lines() const noexcept { return journal_lines_; }

    std::string state_path()   const { return path(state::kStateFile); }
    std::string journal_path() const { return path(state::kJournalFile); }

    // Read the last complete state. A missing file is not an error worth
    // counting -- it is what the first run of the first session sees.
    bool load(state::MonitorState& out, std::string& why) const {
        const std::string p = state_path();
        const int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            why = errno == ENOENT ? "no previous state file"
                                  : std::string("cannot read state: ") + std::strerror(errno);
            return false;
        }
        std::string text;
        char buf[8192];
        for (;;) {
            const ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n > 0)       { text.append(buf, static_cast<std::size_t>(n)); continue; }
            if (n == 0)      break;
            if (errno == EINTR) continue;
            ::close(fd);
            why = std::string("read failed: ") + std::strerror(errno);
            return false;
        }
        ::close(fd);
        if (text.empty()) { why = "state file is empty"; return false; }
        return state::from_json(text, out, why);
    }

    // Temp + fdatasync + rename + directory fsync. See note 1.
    bool save_atomic(const state::MonitorState& s) {
        if (!enabled_) return false;
        const std::string text = state::to_json(s);
        const std::string tmp  = path(std::string(".") + state::kStateFile + ".tmp."
                                      + std::to_string(static_cast<long>(::getpid())));
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) return fail("open temp: " + std::string(std::strerror(errno)));
        if (!write_all(fd, text)) {
            const std::string e = std::strerror(errno);
            ::close(fd);
            ::unlink(tmp.c_str());
            return fail("write temp: " + e);
        }
        if (::fdatasync(fd) != 0) {
            const std::string e = std::strerror(errno);
            ::close(fd);
            ::unlink(tmp.c_str());
            return fail("fdatasync: " + e);
        }
        ::close(fd);
        if (::rename(tmp.c_str(), state_path().c_str()) != 0) {
            const std::string e = std::strerror(errno);
            ::unlink(tmp.c_str());
            return fail("rename: " + e);
        }
        sync_dir();
        ++seq_;
        return true;
    }

    // Append one line to the journal, rotating one generation when it grows
    // past the cap. Best effort by design: the durable record is the state
    // file, and a journal that could stall the poll loop on an fsync would be
    // paying a latency cost for a convenience log.
    void journal(const std::string& line) {
        if (!enabled_ || line.empty()) return;
        if (journal_fd_ < 0 && !open_journal()) return;

        struct stat st{};
        if (::fstat(journal_fd_, &st) == 0 && st.st_size > rotate_bytes_) {
            ::close(journal_fd_);
            journal_fd_ = -1;
            const std::string one = journal_path() + ".1";
            if (::rename(journal_path().c_str(), one.c_str()) != 0)
                (void)fail("journal rotate: " + std::string(std::strerror(errno)));
            if (!open_journal()) return;
        }
        if (!write_all(journal_fd_, line + "\n"))
            (void)fail("journal write: " + std::string(std::strerror(errno)));
        else
            ++journal_lines_;
    }

    void close_all() {
        if (journal_fd_ >= 0) { ::close(journal_fd_); journal_fd_ = -1; }
        if (lock_fd_ >= 0)    { ::close(lock_fd_);    lock_fd_ = -1; }  // flock released with it
        enabled_ = false;
    }

private:
    std::string path(const std::string& leaf) const {
        if (dir_.empty()) return leaf;
        return dir_.back() == '/' ? dir_ + leaf : dir_ + "/" + leaf;
    }

    bool fail(const std::string& msg) {
        ++errors_;
        last_error_ = msg;
        return false;
    }

    static bool write_all(int fd, const std::string& s) {
        std::size_t off = 0;
        while (off < s.size()) {
            const ssize_t n = ::write(fd, s.data() + off, s.size() - off);
            if (n > 0) { off += static_cast<std::size_t>(n); continue; }
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        return true;
    }

    bool open_journal() {
        journal_fd_ = ::open(journal_path().c_str(),
                             O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (journal_fd_ < 0)
            return fail("open journal: " + std::string(std::strerror(errno)));
        return true;
    }

    // A rename is only durable once the DIRECTORY entry is on the platter.
    // Failing to fsync the directory is not counted as an error: the state file
    // itself is already safe against every failure short of a power cut.
    void sync_dir() const {
        const int dfd = ::open(dir_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd < 0) return;
        (void)::fsync(dfd);
        ::close(dfd);
    }

    long read_lock_pid() const {
        char b[32] = {0};
        const int fd = ::open(path(state::kLockFile).c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        const ssize_t n = ::read(fd, b, sizeof(b) - 1);
        ::close(fd);
        if (n <= 0) return -1;
        b[n] = '\0';
        return std::strtol(b, nullptr, 10);
    }

    std::string   dir_;
    std::string   off_reason_;
    std::string   last_error_;
    int           lock_fd_    = -1;
    int           journal_fd_ = -1;
    bool          enabled_    = false;
    bool          read_only_  = false;
    std::uint64_t seq_        = 0;
    std::size_t   errors_     = 0;
    std::uint64_t journal_lines_ = 0;
    off_t         rotate_bytes_   = kJournalRotateBytes;
};

} // namespace c2pool::xmr::p2pool
