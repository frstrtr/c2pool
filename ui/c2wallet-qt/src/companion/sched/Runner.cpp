// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Runner.hpp"

#include <cerrno>
#include <cstring>
#include <vector>

#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace c2w::companion::sched {

namespace {

bool file_exists(const std::string& path)
{
#if defined(_WIN32)
    (void)path;
    return false;
#else
    struct stat st {};
    return ::stat(path.c_str(), &st) == 0;
#endif
}

// mkdir -p for the queue's directory (each created level 0700).
bool make_parent_dirs(const std::string& path, std::string& why)
{
#if defined(_WIN32)
    (void)path;
    why = "queue directories unsupported on this platform";
    return false;
#else
    const size_t slash = path.rfind('/');
    if (slash == std::string::npos || slash == 0) return true;
    const std::string dir = path.substr(0, slash);
    std::string cur;
    size_t pos = 0;
    while (pos <= dir.size()) {
        const size_t next = dir.find('/', pos);
        cur = dir.substr(0, next == std::string::npos ? dir.size() : next);
        pos = next == std::string::npos ? dir.size() + 1 : next + 1;
        if (cur.empty()) continue;
        if (::mkdir(cur.c_str(), 0700) != 0 && errno != EEXIST) {
            why = "cannot create directory " + cur + " (" + std::strerror(errno) + ")";
            return false;
        }
    }
    return true;
#endif
}

} // namespace

std::string runner_lock_base(const std::string& queue_path)
{
    return queue_path + ".runner";
}

bool runner_lock_held(const std::string& queue_path)
{
#if defined(_WIN32)
    (void)queue_path;
    return false;
#else
    const std::string lp = runner_lock_base(queue_path) + ".lock";
    const int fd = ::open(lp.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    bool held = false;
    if (::flock(fd, LOCK_SH | LOCK_NB) != 0) held = errno == EWOULDBLOCK;
    else ::flock(fd, LOCK_UN);
    ::close(fd);
    return held;
#endif
}

int sweep_stale_temp_files(const std::string& queue_path)
{
#if defined(_WIN32)
    (void)queue_path;
    return 0;
#else
    const size_t slash = queue_path.rfind('/');
    const std::string dir = slash == std::string::npos ? "." : (slash == 0 ? "/" : queue_path.substr(0, slash));
    const std::string prefix = (slash == std::string::npos ? queue_path : queue_path.substr(slash + 1)) + ".tmp.";
    DIR* d = ::opendir(dir.c_str());
    if (!d) return 0;
    std::vector<std::string> stale;
    while (const struct dirent* e = ::readdir(d)) {
        const std::string n = e->d_name;
        if (n.size() <= prefix.size() || n.compare(0, prefix.size(), prefix) != 0) continue;
        bool digits = true;
        for (size_t i = prefix.size(); i < n.size(); ++i)
            if (n[i] < '0' || n[i] > '9') digits = false;
        if (digits) stale.push_back(dir + "/" + n);
    }
    ::closedir(d);
    int removed = 0;
    for (const std::string& f : stale)
        if (::unlink(f.c_str()) == 0) ++removed;
    return removed;
#endif
}

Queue merge_runner_view(const Queue& mem, const Queue& disk)
{
    Queue out = mem;
    // Operator-owned configuration.
    out.schema = disk.schema;
    out.coin = disk.coin;
    out.network = disk.network;
    out.node = disk.node;
    out.defaults = disk.defaults;
    out.alerts_acked_at = disk.alerts_acked_at;

    // Consent: an operator change (record_consent: record, revoke, or clear a
    // suspension) bumps arm_policy.rev -> the file wins for the policy; the
    // runner keeps its own record of having armed the node. Otherwise the
    // runner's copy stands (it may have just set a suspension the file has
    // not seen yet).
    if (disk.arm_policy.rev > mem.arm_policy.rev) {
        const std::optional<std::string> armed = mem.arm_policy.armed_by_scheduler_at;
        out.arm_policy = disk.arm_policy;
        out.arm_policy.armed_by_scheduler_at = armed;
    }

    out.items.clear();
    out.items.reserve(disk.items.size());
    for (const Item& di : disk.items) {
        const Item* mi = find_item(mem, di.id);
        out.items.push_back(!mi || di.rev > mi->rev ? di : *mi);
    }

    // Tracked foreign parents: the runner's records, plus any an enqueue added.
    for (const Tracked& t : disk.tracked)
        if (!find_tracked(out, t.txid)) out.tracked.push_back(t);
    return out;
}

bool load_or_create_queue(const std::string& path, Queue& out, bool& created, std::string& why,
                          const std::function<void(Queue&)>& init)
{
    created = false;
    if (!make_parent_dirs(path, why)) return false;
    QueueLock edit;
    if (!edit.acquire(path, /*blocking=*/true, why)) return false;
    sweep_stale_temp_files(path);
    if (file_exists(path)) return load_queue_file(path, out, why);
    Queue q;
    if (init) init(q);
    if (!save_queue_file(path, q, why)) return false;
    out = std::move(q);
    created = true;
    return true;
}

bool edit_queue_file(const std::string& path, const std::function<bool(Queue&, std::string&)>& edit,
                     std::string& why, bool create_if_missing)
{
    if (create_if_missing && !make_parent_dirs(path, why)) return false;
    QueueLock lock;
    if (!lock.acquire(path, /*blocking=*/true, why)) return false;
    sweep_stale_temp_files(path);
    Queue q;
    if (file_exists(path)) {
        if (!load_queue_file(path, q, why)) return false;
    } else if (!create_if_missing) {
        why = "no queue at " + path;
        return false;
    }
    if (!edit(q, why)) return false;
    return save_queue_file(path, q, why);
}

bool owned_by_other_user(const std::string& path, std::string& why)
{
#if defined(_WIN32)
    (void)path;
    (void)why;
    return false;
#else
    // The file itself, or (not created yet) its directory.
    std::string probe = path;
    struct stat st {};
    if (::stat(probe.c_str(), &st) != 0) {
        const size_t slash = path.rfind('/');
        if (slash == std::string::npos) return false;
        probe = slash == 0 ? "/" : path.substr(0, slash);
        if (::stat(probe.c_str(), &st) != 0) return false;
    }
    if (st.st_uid == ::geteuid()) return false;
    why = probe + " belongs to uid " + std::to_string(st.st_uid) + ", this process runs as uid " +
          std::to_string(::geteuid()) + "; run the command as the queue's owner (e.g. sudo -u <owner> ...)";
    return true;
#endif
}

// ── Runner ───────────────────────────────────────────────────────────────────

Runner::Runner(std::string queue_path, Queue initial, NodeApi& api, const Clock& clock, JournalSink& sink,
               SchedulerOptions opt)
    : path_(std::move(queue_path)), q_(std::move(initial))
{
    sched_ = std::make_unique<Scheduler>(q_, api, clock, sink, std::move(opt));
    sched_->set_persist([this](const Queue& mem, std::string& why) { return persist_merged(mem, why); });
}

Runner::~Runner() = default;

bool Runner::sync_from_disk(std::string& why)
{
    QueueLock lock;
    if (!lock.acquire(path_, /*blocking=*/true, why)) return false;
    if (!file_exists(path_)) {
        // Deleted under us: the runner's memory is the best record left.
        return save_queue_file(path_, q_, why);
    }
    Queue disk;
    if (!load_queue_file(path_, disk, why)) return false;
    q_ = merge_runner_view(q_, disk);
    return true;
}

bool Runner::persist_merged(const Queue& mem, std::string& why)
{
    QueueLock lock;
    if (!lock.acquire(path_, /*blocking=*/true, why)) return false;
    if (!file_exists(path_)) return save_queue_file(path_, mem, why);
    Queue disk;
    if (!load_queue_file(path_, disk, why)) {
        why = "queue file unreadable, not overwritten: " + why;
        return false;
    }
    return save_queue_file(path_, merge_runner_view(mem, disk), why);
}

Runner::Step Runner::step()
{
    Step s;
    if (!sync_from_disk(s.sync_error)) return s;
    s.ticked = true;
    s.report = sched_->tick();
    return s;
}

} // namespace c2w::companion::sched
