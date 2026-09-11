// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/test/p2pool_persist_kat.cpp
//
// THE DURABILITY KAT. The half of persistence that needs a filesystem.
//
// xmr_p2pool_monitor_kat pins the FORMAT -- frame to state to JSON and back,
// number by number -- and is deliberately POSIX-free so a layout can be checked
// without a socket layer or a disk. This binary is the other half: open(2),
// rename(2), flock(2), fork(2), SIGKILL. It exists because the claim that makes
// the state file worth having is an operational one, not a syntactic one:
//
//     IF THE MONITOR IS KILLED, THE NUMBERS ARE STILL THERE, AND THEY ARE NOT
//     HALF-WRITTEN.
//
// That cannot be demonstrated by a round trip through a string. So the central
// test here forks a child, has it save a state, and kills it with SIGKILL --
// the signal a process cannot catch, clean up after, or flush on -- and then
// has the parent read the file back and check every number. What a real
// `kill -9` does to a real monitor is what this does to that child.
//
// The rest is the failure modes, each of which must degrade rather than break:
//
//   * a SECOND monitor on the same directory takes no lock and writes nothing,
//     leaving the live writer's file untouched;
//   * a reader can read WHILE the writer holds the lock, because a reader takes
//     no lock at all -- which is only safe because every write lands by rename;
//   * no HOME means persistence OFF with a reason, and NEVER a fallback to /tmp;
//   * a directory that cannot be created, and a journal that has grown past its
//     cap, are both handled without the caller noticing anything but a flag.
//
// Everything is done under a fresh mkdtemp() directory which is removed at the
// end. This test writes nowhere else and needs no network.
//
// Registered with add_test AND in BOTH `--target` lists in build.yml: a target
// registered but not built reports "***Not Run" and fails the leg (#1539).
// ---------------------------------------------------------------------------

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/p2pool/p2pool_persist.hpp"
#include "impl/xmr/p2pool/p2pool_read_model.hpp"
#include "impl/xmr/p2pool/p2pool_state.hpp"
#include "impl/xmr/p2pool/p2pool_tui.hpp"

namespace p2p = c2pool::xmr::p2pool;
namespace tui = c2pool::xmr::p2pool::tui;
namespace st  = c2pool::xmr::p2pool::state;

namespace {

int g_checks = 0;
int g_fail   = 0;

void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) { std::printf("FAIL: %s\n", what); ++g_fail; }
}

template <typename A, typename B>
void check_eq(const A& got, const B& want, const char* what) {
    ++g_checks;
    if (!(got == static_cast<A>(want))) { std::printf("FAIL: %s\n", what); ++g_fail; }
}

void check_str(const std::string& got, const std::string& want, const char* what) {
    ++g_checks;
    if (got != want) {
        std::printf("FAIL: %s\n  got  |%s|\n  want |%s|\n", what, got.c_str(), want.c_str());
        ++g_fail;
    }
}

// ---------------------------------------------------------------------------
// A small fixture: one chain with numbers a reader can recognise on sight, so a
// partial read shows up as a wrong number rather than as a plausible one.
// ---------------------------------------------------------------------------
constexpr std::uint64_t kNow = 1757620000123ull;

p2p::Hash mk_hash(std::uint8_t n) {
    p2p::Hash h{};
    for (std::size_t i = 0; i < h.size(); ++i)
        h[i] = static_cast<std::uint8_t>((n * 37u + i * 11u) & 0xFFu);
    return h;
}

p2p::ReadModel build_model(p2p::Sidechain chain, std::uint64_t base_height) {
    p2p::ReadModel m(chain);
    for (std::uint8_t i = 0; i < 5; ++i) {
        p2p::ObservedBlock b;
        b.sidechain_id             = mk_hash(i);
        b.sidechain_height         = base_height + i;
        b.difficulty.lo            = 4360000000ull;
        b.cumulative_difficulty.hi = 3;                 // exercise the 128-bit path
        b.cumulative_difficulty.lo = 7788990011223344ull;
        b.monero_height            = 3512000 + i;
        b.share_outputs            = 100 + i;
        b.id_verified              = true;
        b.first_seen_ms            = kNow - 40000 + i * 9500;
        m.observe(b);
    }
    for (int i = 0; i < 4; ++i) m.note_connected("198.51.100." + std::to_string(i) + ":37889");
    for (int i = 0; i < 57; ++i) m.note_peer("198.51.100." + std::to_string(i) + ":37889");
    m.note_peer_gossip(48);
    m.note_broadcast_seen();
    return m;
}

p2p::FreshnessView mk_fresh() {
    p2p::FreshnessView f;
    f.known          = true;
    f.have_data      = true;
    f.ever_connected = true;
    f.started_at_ms  = kNow - 600000;
    f.tip_at_ms      = kNow - 2000;
    f.rx_at_ms       = kNow - 2000;
    f.up_since_ms    = kNow - 590000;
    return f;
}

tui::MonitorFrame build_frame() {
    static const p2p::ReadModel main_m = build_model(p2p::Sidechain::Main, 15200100);
    static const p2p::ReadModel mini_m = build_model(p2p::Sidechain::Mini, 14757140);
    tui::MonitorFrame f;
    f.elapsed_ms = 600000;
    tui::EmitCounts e;
    e.messages[0] = 6;   e.bytes[0] = 102;
    e.messages[1] = 6;   e.bytes[1] = 246;
    e.messages[2] = 141; e.bytes[2] = 4653;
    e.messages[3] = 6;   e.bytes[3] = 6;
    f.chains.push_back(tui::view_of(main_m, e, 4, 12, kNow, mk_fresh()));
    f.chains.push_back(tui::view_of(mini_m, e, 3, 7, kNow, mk_fresh()));
    return f;
}

st::MonitorState build_state(std::uint64_t seq, const char* shutdown) {
    st::SessionMeta meta;
    meta.written_at_ms = kNow;
    meta.seq  = seq;
    meta.pid  = static_cast<std::uint64_t>(::getpid());
    meta.host = p2p::StateStore::hostname();
    meta.session_id            = "1757619000000-4711";
    meta.session_started_at_ms = kNow - 600000;
    meta.shutdown              = shutdown ? shutdown : "";
    meta.lifetime.sessions            = 3;
    meta.lifetime.first_started_at_ms = kNow - 9000000;
    meta.lifetime.runtime_ms_total    = 8400000;
    return st::state_of(build_frame(), meta);
}

// ---------------------------------------------------------------------------
// Filesystem helpers.
// ---------------------------------------------------------------------------
std::string make_tmpdir() {
    const char* base = std::getenv("TMPDIR");
    std::string tpl = std::string(base && *base ? base : "/tmp") + "/p2pmon-kat-XXXXXX";
    std::vector<char> buf(tpl.begin(), tpl.end());
    buf.push_back('\0');
    if (!::mkdtemp(buf.data())) return std::string();
    return std::string(buf.data());
}

std::vector<std::string> list_dir(const std::string& dir) {
    std::vector<std::string> names;
    DIR* d = ::opendir(dir.c_str());
    if (!d) return names;
    while (const dirent* e = ::readdir(d)) {
        const std::string n = e->d_name;
        if (n != "." && n != "..") names.push_back(n);
    }
    ::closedir(d);
    return names;
}

void remove_tree(const std::string& dir) {
    for (const std::string& n : list_dir(dir)) ::unlink((dir + "/" + n).c_str());
    ::rmdir(dir.c_str());
}

off_t file_size(const std::string& p) {
    struct stat s{};
    return ::stat(p.c_str(), &s) == 0 ? s.st_size : -1;
}

// ---------------------------------------------------------------------------
// 1) THE ROUND TRIP THROUGH A REAL FILE.
// ---------------------------------------------------------------------------
void check_file_round_trip(const std::string& root) {
    const std::string dir = root + "/rt";
    p2p::StateStore store;
    check(store.open(dir), "a state directory is created and locked");
    check(store.enabled(), "the store is enabled after a successful open");
    check_str(store.dir(), dir, "the store reports the directory it opened");

    struct stat ds{};
    check(::stat(dir.c_str(), &ds) == 0, "the directory exists");
    check_eq(static_cast<int>(ds.st_mode & 0777), 0700, "the directory is private (0700)");

    const st::MonitorState a = build_state(1, nullptr);
    check(store.save_atomic(a), "a state is written");
    check_eq(store.seq(), std::uint64_t(1), "the store counts its saves");
    check(file_size(store.state_path()) > 800, "the state file has content");

    // NO DEBRIS. A temp file left behind would mean a save path that can fail
    // half way and leave the directory in a state the next run has to reason
    // about.
    for (const std::string& n : list_dir(dir)) {
        ++g_checks;
        if (n.find(".tmp.") != std::string::npos) {
            std::printf("FAIL: a temporary file survived the save: %s\n", n.c_str());
            ++g_fail;
        }
    }

    st::MonitorState b;
    std::string why;
    check(store.load(b, why), "the state reads back");
    check_eq(b.chains.size(), a.chains.size(), "every chain came back");
    check_eq(b.written_at_ms, a.written_at_ms, "the write instant came back exactly");
    check_eq(b.lifetime.sessions, a.lifetime.sessions, "the session count came back");

    for (std::size_t i = 0; i < b.chains.size() && i < a.chains.size(); ++i) {
        check_str(b.chains[i].name, a.chains[i].name, "the chain name came back");
        check_eq(b.chains[i].tip_height, a.chains[i].tip_height, "the tip height came back exactly");
        check_str(b.chains[i].tip_id, a.chains[i].tip_id, "the 64-hex tip id came back");
        check_str(b.chains[i].cumulative_difficulty, a.chains[i].cumulative_difficulty,
                  "a 128-bit cumulative difficulty came back to the digit");
        check_eq(b.chains[i].distinct, a.chains[i].distinct, "the block count came back");
        check_eq(b.chains[i].peers_up, a.chains[i].peers_up, "the peer count came back");
        check_eq(b.chains[i].tip_advanced_at_ms, a.chains[i].tip_advanced_at_ms,
                 "the staleness clock came back");
    }

    // The read-only claim, auditable off-line from the file itself.
    check_eq(b.emitted_ids.size(), std::size_t(4), "the file records four emitted ids");
    const int want[4] = {0, 1, 3, 6};
    for (std::size_t i = 0; i < b.emitted_ids.size() && i < 4; ++i)
        check_eq(b.emitted_ids[i], want[i], "the file records the emit set {0,1,3,6}");

    // Overwriting is atomic too: the second save replaces the first, and the
    // file that comes back is entirely the second one.
    const st::MonitorState c = build_state(2, "clean");
    check(store.save_atomic(c), "a second state overwrites the first");
    st::MonitorState d;
    check(store.load(d, why), "the overwritten state reads back");
    check_str(d.shutdown, "clean", "the second state is the one on disk, whole");
    check_eq(store.errors(), std::size_t(0), "no write errors occurred");
}

// ---------------------------------------------------------------------------
// 2) SURVIVING SIGKILL -- the claim the whole file exists for.
// ---------------------------------------------------------------------------
void check_survives_kill(const std::string& root) {
    const std::string dir = root + "/kill";

    const pid_t child = ::fork();
    if (child < 0) {
        std::printf("SKIP: fork failed (%s); the kill test needs a child process\n",
                    std::strerror(errno));
        return;
    }
    if (child == 0) {
        // THE CHILD IS THE MONITOR. It opens the store, writes a state with NO
        // shutdown marker -- exactly what a running monitor's periodic save
        // looks like -- and then dies the way `kill -9` kills: no unwinding, no
        // destructors, no atexit, no flush.
        p2p::StateStore s;
        if (!s.open(dir)) ::_exit(3);
        if (!s.save_atomic(build_state(17, nullptr))) ::_exit(4);
        s.journal(st::journal_line(build_state(17, nullptr)));
        ::raise(SIGKILL);
        ::_exit(5);                      // unreachable
    }

    int status = 0;
    check(::waitpid(child, &status, 0) == child, "the child was reaped");
    check(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
          "the child died of SIGKILL, not of a clean exit");

    // THE PARENT IS THE RESTART. Nothing was handed over in memory; everything
    // it knows comes off the disk the dead process left behind.
    p2p::StateStore reopened;
    check(reopened.open(dir), "the directory reopens after the writer was killed");
    check(reopened.enabled(), "flock was released by the kernel when the process died");

    st::MonitorState s;
    std::string why;
    check(reopened.load(s, why), "the state a killed process wrote is readable");
    check_eq(s.seq, std::uint64_t(17), "the killed process's sequence number survived");
    check_eq(s.chains.size(), std::size_t(2), "both chains survived the kill");
    check(s.shutdown.empty(),
          "a file with no shutdown marker is how a killed session is recognised");

    const st::ChainState* main_c = s.find("main");
    check(main_c != nullptr, "the main chain survived by name");
    if (main_c) {
        check_eq(main_c->tip_height, std::uint64_t(15200104), "the tip height survived exactly");
        check_eq(main_c->distinct, std::uint64_t(5), "the block count survived");
        check_eq(main_c->peers_up, std::uint64_t(4), "the peer count survived");
        check_str(main_c->cumulative_difficulty,
                  st::MonitorState(build_state(17, nullptr)).chains[0].cumulative_difficulty,
                  "the 128-bit cumulative difficulty survived to the digit");
        check(main_c->have_data, "the survived chain is marked as holding data");
    }

    // CONTINUITY: the restarted process renders that state through the live
    // renderer, and the numbers on the screen are the numbers from before the
    // kill -- with an age, because they are not current.
    const tui::MonitorFrame f = st::frame_of(s, kNow + 5000);
    check_eq(f.chains.size(), std::size_t(2), "the restored frame has both chains");
    check_eq(f.chains[0].tip_height, std::uint64_t(15200104),
             "the restored frame shows the pre-kill tip");
    check(f.from_file, "the restored frame is marked as coming from a file");
    const std::string text = tui::snapshot_text(f, 100);
    check(text.find("15200104") != std::string::npos,
          "the pre-kill tip height is on the restored screen");
    check(text.find("RESTORED FRAME") != std::string::npos,
          "the restored screen says it is restored");

    // The journal the child appended is there too, and is one JSON line.
    const off_t jsize = file_size(reopened.journal_path());
    check(jsize > 100, "the journal the killed process appended survived");
}

// ---------------------------------------------------------------------------
// 3) TWO MONITORS, ONE DIRECTORY.
// ---------------------------------------------------------------------------
void check_lock(const std::string& root) {
    const std::string dir = root + "/lock";

    p2p::StateStore first;
    check(first.open(dir), "the first monitor takes the directory");
    check(first.save_atomic(build_state(5, nullptr)), "the first monitor writes");

    p2p::StateStore second;
    check(!second.open(dir), "the second monitor is refused the directory");
    check(!second.enabled(), "the second monitor runs with persistence off");
    const std::string reason = second.off_reason();
    check(reason.find("locked by pid") != std::string::npos,
          "the second monitor names the pid holding the lock");
    check(reason.find(std::to_string(static_cast<long>(::getpid()))) != std::string::npos,
          "the pid named is the one that actually holds it");

    // AND IT MUST NOT WRITE. save_atomic on a disabled store is a no-op, so the
    // live writer's file is exactly what the live writer left.
    check(!second.save_atomic(build_state(999, "clean")),
          "a store with no lock refuses to save");
    st::MonitorState s;
    std::string why;
    check(first.load(s, why), "the first monitor's file is still readable");
    check_eq(s.seq, std::uint64_t(5), "the locked-out monitor did not clobber the file");
    check(s.shutdown.empty(), "the locked-out monitor did not even change the marker");

    // A READER takes no lock, so it can read the live file while it is being
    // written -- safe only because every write lands by rename().
    p2p::StateStore reader;
    reader.open_read_only(dir);
    check(!reader.enabled(), "a read-only attach is never write-enabled");
    check(reader.read_only(), "a read-only attach says so");
    st::MonitorState r;
    check(reader.load(r, why), "a reader reads the live file without taking the lock");
    check_eq(r.seq, std::uint64_t(5), "the reader saw the writer's state");

    // The lock goes when the process does -- here, when the store closes.
    first.close_all();
    p2p::StateStore third;
    check(third.open(dir), "the directory is free again once the holder closes it");
}

// ---------------------------------------------------------------------------
// 4) DEGRADING RATHER THAN BREAKING.
// ---------------------------------------------------------------------------
void check_degradation(const std::string& root) {
    // No HOME: off, with a reason, and NEVER /tmp.
    p2p::StateStore nohome;
    check(!nohome.open(""), "an empty directory is refused");
    check(!nohome.enabled(), "no directory means persistence off");
    check_str(nohome.off_reason(), "(no HOME)", "the reason is stated, not implied");
    check(!nohome.save_atomic(build_state(1, nullptr)), "a disabled store writes nothing");

    const std::string dflt = p2p::StateStore::default_dir();
    check(dflt.empty() || dflt.rfind("/tmp", 0) != 0,
          "the default state directory is never under /tmp");
    check(dflt.empty() || dflt.find("/p2pmon-state") != std::string::npos,
          "the default state directory is named p2pmon-state under the home directory");

    // A parent that does not exist: refused with the errno, no crash, and the
    // caller is expected to carry on.
    p2p::StateStore deep;
    check(!deep.open(root + "/no/such/parent/dir"), "a missing parent is refused");
    check(!deep.off_reason().empty(), "the refusal carries a reason");
    check(deep.off_reason().find("cannot create") != std::string::npos,
          "the reason says what failed");

    // A path that is a FILE, not a directory.
    const std::string as_file = root + "/not-a-dir";
    { FILE* f = std::fopen(as_file.c_str(), "we"); if (f) std::fclose(f); }
    p2p::StateStore notdir;
    check(!notdir.open(as_file), "a file where a directory should be is refused");
    check(!notdir.enabled(), "and persistence stays off");

    // Loading a directory that has no state file is a plain "nothing yet".
    const std::string empty_dir = root + "/empty";
    p2p::StateStore fresh;
    check(fresh.open(empty_dir), "a brand new directory opens");
    st::MonitorState s;
    std::string why;
    check(!fresh.load(s, why), "a first run finds no previous state");
    check(why.find("no previous state") != std::string::npos,
          "and says so rather than reporting an error");
    check_eq(fresh.errors(), std::size_t(0), "a missing file is not counted as an error");

    // A CORRUPT file is refused, and refusing is what keeps a plausible-looking
    // state out of the next session.
    const std::string corrupt_dir = root + "/corrupt";
    p2p::StateStore corrupt;
    check(corrupt.open(corrupt_dir), "the corrupt-file directory opens");
    check(corrupt.save_atomic(build_state(3, nullptr)), "a good state is written first");
    {
        FILE* f = std::fopen(corrupt.state_path().c_str(), "we");
        check(f != nullptr, "the state file can be rewritten by the test");
        if (f) { std::fputs("{\"schema\":\"p2pmon-state/1\",\"written_at_ms\"", f); std::fclose(f); }
    }
    st::MonitorState bad;
    check(!corrupt.load(bad, why), "a truncated state file is refused");
    check(!why.empty(), "the refusal says why");
}

// ---------------------------------------------------------------------------
// 5) THE JOURNAL: appended, rotated, never read back.
// ---------------------------------------------------------------------------
void check_journal(const std::string& root) {
    const std::string dir = root + "/journal";
    p2p::StateStore store;
    check(store.open(dir), "the journal directory opens");
    store.set_journal_rotate_bytes(2048);           // a cap a test can reach

    const std::string line = st::journal_line(build_state(1, nullptr));
    check(line.size() > 60 && line.size() < 1024, "a journal line is a compact digest");
    check(line.find('\n') == std::string::npos, "a journal line is one line");
    check(line.find("\"chains\"") != std::string::npos, "a journal line carries the chains");
    check(line.find("15200104") != std::string::npos, "a journal line carries the tip height");

    for (int i = 0; i < 40; ++i) store.journal(line);
    check_eq(store.journal_lines(), std::uint64_t(40), "every line was written");
    check(file_size(store.journal_path()) > 0, "the journal exists");
    check(file_size(store.journal_path() + ".1") > 0,
          "the journal rotated one generation past the cap");
    check(file_size(store.journal_path()) <= 2048 + static_cast<off_t>(line.size()) + 1,
          "the live journal is bounded by the cap");
    check_eq(store.errors(), std::size_t(0), "journalling produced no errors");

    // The journal is never consulted on load: deleting it changes nothing.
    check(store.save_atomic(build_state(9, nullptr)), "a state is saved beside the journal");
    ::unlink(store.journal_path().c_str());
    st::MonitorState s;
    std::string why;
    check(store.load(s, why), "the state loads with no journal present");
    check_eq(s.seq, std::uint64_t(9), "the state is unaffected by the journal");
}

}  // namespace

int main(int argc, char** argv) {
    const std::string root = make_tmpdir();
    if (root.empty()) {
        std::printf("FAIL: cannot create a temporary directory: %s\n", std::strerror(errno));
        return 1;
    }
    if (argc > 1 && std::strcmp(argv[1], "--show-dir") == 0) {
        std::printf("%s\n", root.c_str());
        return 0;
    }

    check_file_round_trip(root);
    check_survives_kill(root);
    check_lock(root);
    check_degradation(root);
    check_journal(root);

    // Leave nothing behind. Each sub-test made its own directory under root.
    for (const char* sub : {"rt", "kill", "lock", "empty", "corrupt", "journal"})
        remove_tree(root + "/" + sub);
    remove_tree(root);

    std::printf("checks=%d failures=%d\n", g_checks, g_fail);
    if (g_fail) { std::printf("KAT FAILED\n"); return 1; }
    std::printf("KAT OK\n");
    return 0;
}
