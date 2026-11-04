// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — the runner side of the queue file (slice S2), Qt-free.
//
// One process runs the loop for a queue (the headless c2wallet-qt-schedd, or
// later the GUI); operators edit the same file from other processes (the
// daemon's add/pause/resume/rm/... subcommands over SSH). Two flocks keep that
// safe (see QueueLock):
//   * the RUNNER lock (queue.json.runner.lock), held for the loop's lifetime:
//     a second runner exits "lock held";
//   * the EDIT lock (queue.json.lock), held for every short read-modify-write:
//     each operator edit, and each runner persist.
//
// Ownership, so neither side overwrites the other:
//   * operator-owned: adding and removing items, every edit of an item (each
//     bumps the item's rev), the arm policy when the operator changed it (its
//     own rev), node/defaults, and alerts_acked_at;
//   * runner-owned: the state machine of items whose rev it already holds,
//     tracked parents, alerts and the runner record.
// The runner re-reads the file at the start of every step and merges it into
// its memory (merge_runner_view); every persist during a tick re-reads the
// file under the edit lock and writes the merge, never a stale whole-file
// copy. An operator edit therefore takes effect at the runner's next step at
// the latest, and an item edited by the operator during a tick keeps the
// operator's version (the runner's in-flight transition on it is dropped; the
// node's idempotent answers make the next submit safe).

#include "Clock.hpp"
#include "InjectQueue.hpp"
#include "NodeApi.hpp"
#include "Scheduler.hpp"

#include <functional>
#include <memory>
#include <string>

namespace c2w::companion::sched {

// The merge rule above: `mem` is the runner's copy, `disk` the file as it is
// now. Items follow the file's order; an item only on disk is new (added),
// an item only in memory was removed, an item with a higher rev on disk was
// edited by the operator.
Queue merge_runner_view(const Queue& mem, const Queue& disk);

// The runner lock path base: QueueLock::acquire(runner_lock_base(q), false).
std::string runner_lock_base(const std::string& queue_path);

// Is a runner holding the queue right now? Probes the runner lock with a
// non-blocking SHARED flock on an existing lock file (never creates one, so a
// read-only `list`/`status` run by another user leaves nothing behind).
bool runner_lock_held(const std::string& queue_path);

// Load the queue, or create an empty one (mode 0600, parent directories 0700)
// when the file does not exist. `init` fills the node config of a new queue.
// Holds the edit lock. false + why on a read/parse/validation error.
bool load_or_create_queue(const std::string& path, Queue& out, bool& created, std::string& why,
                          const std::function<void(Queue&)>& init = {});

// Read-modify-write under the edit lock: load (or create), apply `edit`, save
// when it returns true. The edit's own refusal text comes back in `why`.
bool edit_queue_file(const std::string& path, const std::function<bool(Queue&, std::string&)>& edit,
                     std::string& why, bool create_if_missing = true);

// Remove queue.json.tmp.<pid> files left by a writer that died between its
// write and its rename. Call only with the edit lock held (every writer holds
// it for the whole write, so any temp file seen then is stale). Returns the
// number removed. load_or_create_queue and edit_queue_file do it themselves.
int sweep_stale_temp_files(const std::string& queue_path);

// Is the file at `path` owned by another user? Editing it would leave a file
// the runner (its owner) cannot read back after the atomic rename.
bool owned_by_other_user(const std::string& path, std::string& why);

class Runner {
public:
    Runner(std::string queue_path, Queue initial, NodeApi& api, const Clock& clock, JournalSink& sink,
           SchedulerOptions opt = {});
    ~Runner();
    // The scheduler holds a reference to q_ and the persist hook captures
    // this: a Runner never moves.
    Runner(const Runner&) = delete;
    Runner& operator=(const Runner&) = delete;

    struct Step {
        bool ticked = false;     // false: the file could not be read; nothing was sent to the node
        std::string sync_error;  // why the step skipped the tick
        TickReport report;
    };

    // Re-read the file (merge operator edits), run one scheduler tick, persist.
    // A missing file is re-created from memory; an unreadable or invalid one
    // skips the tick without touching the node or the file.
    Step step();

    const Queue& queue() const { return q_; }
    const std::string& path() const { return path_; }

private:
    bool sync_from_disk(std::string& why);
    bool persist_merged(const Queue& mem, std::string& why);

    std::string path_;
    Queue q_;
    std::unique_ptr<Scheduler> sched_;
};

} // namespace c2w::companion::sched
