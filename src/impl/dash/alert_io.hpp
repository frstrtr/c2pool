// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Durable file writes for the alert relay (D-MINER.7), kept OFF the node IO
// thread. The node IO thread also runs the StratumServer and the sharechain
// p2p, so write()+fsync()+rename() must never run there on the event path.
//
// A job is an ordered list of ops (Replace = write tmp, fsync, rename; Append
// = O_APPEND, fsync). The ops of one job run in order and stop at the first
// failure, so "append the outbox row, THEN persist the state that claims it"
// is expressed as one job. Jobs run strictly FIFO on one worker thread.
//
// Results are NOT delivered by callback into another thread: the worker
// queues them and the owner collects them with take_results() on its own
// thread (the service drains them at the top of every handler and tick).
// Nothing here posts into the io_context, so the writer has no lifetime
// coupling with it; the destructor finishes the queued jobs and joins.
//
// Coalescing: a job that is a single Replace of path P is folded into the
// LAST queued (not yet started) job when that job's TRAILING op is a Replace
// of P (at most one of the two carrying a completion tag): the newer snapshot
// takes the trailing op's place. That covers a lone state save as well as the
// state save that ends an "append the outbox row, then the state" job. The
// later snapshot supersedes the earlier one, it is written no earlier than it
// would have been, and FIFO order against every other job is preserved, so a
// burst of state saves costs one fsync. (A folded snapshot is skipped with the
// job when an earlier op of that job fails; the owner re-dirties its state on
// such a failure, so the snapshot is rewritten on the next save.)
//
// Bounded queue: a job submitted as `deferrable` is refused (submit() returns
// false, deferred() counts it) while max_jobs jobs are already queued. The
// service submits the jobs that inbound traffic can create at will (accepting
// an alert) as deferrable and answers "not now" (no ack; the origin
// retransmits); its own bounded work (state saves -- which coalesce -- and
// ledger rows, at most one per event) is never refused.
//
// inline mode (KATs): submit() executes the job immediately on the caller's
// thread; results are still collected with take_results().

#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace dash::alert {

struct FileOp {
    enum class Type : uint8_t { Replace, Append };
    Type type{Type::Replace};
    std::string path;
    std::string data;   // Append: one line, "\n" added by the writer
};

struct FileJobResult {
    uint64_t tag{0};
    bool ok{true};
    std::string failed_path;   // first op that failed (empty when ok)
};

class FileWriter {
public:
    static constexpr std::size_t kDefaultMaxJobs = 256;

    explicit FileWriter(bool inline_mode, std::size_t max_jobs = kDefaultMaxJobs)
        : m_inline(inline_mode), m_max_jobs(max_jobs ? max_jobs : 1)
    {
        if (!m_inline) m_thread = std::thread([this] { run(); });
    }

    FileWriter(const FileWriter&) = delete;
    FileWriter& operator=(const FileWriter&) = delete;

    ~FileWriter()
    {
        {
            std::lock_guard<std::mutex> lk(m_mu);
            m_stop = true;
        }
        m_cv.notify_all();
        if (m_thread.joinable()) m_thread.join();
    }

    bool inline_mode() const { return m_inline; }

    // tag 0 = fire and forget (a failure is still reported, tag 0).
    // Returns false only for a `deferrable` job refused by the queue cap (the
    // job is dropped, nothing ran); every other job is accepted.
    bool submit(uint64_t tag, std::vector<FileOp> ops, bool deferrable = false)
    {
        if (ops.empty()) return true;
        if (m_inline) {
            ++m_submitted;
            FileJobResult r = execute(tag, ops);
            std::lock_guard<std::mutex> lk(m_mu);
            ++m_done;
            if (tag || !r.ok) m_results.push_back(std::move(r));
            return true;
        }
        std::lock_guard<std::mutex> lk(m_mu);
        if (ops.size() == 1 && ops[0].type == FileOp::Type::Replace && !m_queue.empty()) {
            Job& last = m_queue.back();
            FileOp& trailing = last.ops.back();
            if (trailing.type == FileOp::Type::Replace && trailing.path == ops[0].path &&
                (last.tag == 0 || tag == 0)) {
                trailing.data = std::move(ops[0].data);
                if (tag) last.tag = tag;
                ++m_submitted;
                ++m_coalesced;
                return true;
            }
        }
        if (deferrable && m_queue.size() >= m_max_jobs) {
            ++m_deferred;
            return false;
        }
        ++m_submitted;
        m_queue.push_back(Job{tag, std::move(ops)});
        m_cv.notify_one();
        return true;
    }

    std::vector<FileJobResult> take_results()
    {
        std::lock_guard<std::mutex> lk(m_mu);
        std::vector<FileJobResult> out;
        out.swap(m_results);
        return out;
    }

    // Block until every submitted job has run. Used at startup (init) and by
    // KATs; never on the event path.
    void flush()
    {
        if (m_inline) return;
        std::unique_lock<std::mutex> lk(m_mu);
        m_idle_cv.wait(lk, [&] { return m_queue.empty() && !m_busy; });
    }

    // KAT hook: runs on the worker thread before every job (e.g. to stall the
    // disk and prove the caller never waits for it).
    void set_before_job_hook(std::function<void()> h)
    {
        std::lock_guard<std::mutex> lk(m_mu);
        m_before_job = std::move(h);
    }

    uint64_t submitted() const { std::lock_guard<std::mutex> lk(m_mu); return m_submitted; }
    uint64_t done() const { std::lock_guard<std::mutex> lk(m_mu); return m_done; }
    uint64_t coalesced() const { std::lock_guard<std::mutex> lk(m_mu); return m_coalesced; }
    uint64_t deferred() const { std::lock_guard<std::mutex> lk(m_mu); return m_deferred; }
    std::size_t queued() const { std::lock_guard<std::mutex> lk(m_mu); return m_queue.size(); }
    std::size_t max_jobs() const { return m_max_jobs; }
    std::size_t backlog() const { std::lock_guard<std::mutex> lk(m_mu); return m_queue.size() + (m_busy ? 1 : 0); }

    static bool atomic_write(const std::string& path, const std::string& data)
    {
        const std::string tmp = path + ".tmp";
        int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) return false;
        bool ok = ::write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
        ok = (::fsync(fd) == 0) && ok;
        ::close(fd);
        return ok && std::rename(tmp.c_str(), path.c_str()) == 0;
    }

    static bool append_line(const std::string& path, const std::string& line)
    {
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd < 0) return false;
        const std::string l = line + "\n";
        bool ok = ::write(fd, l.data(), l.size()) == static_cast<ssize_t>(l.size());
        ok = (::fsync(fd) == 0) && ok;
        ::close(fd);
        return ok;
    }

private:
    struct Job {
        uint64_t tag{0};
        std::vector<FileOp> ops;
    };

    static FileJobResult execute(uint64_t tag, const std::vector<FileOp>& ops)
    {
        FileJobResult r;
        r.tag = tag;
        for (const auto& op : ops) {
            const bool ok = op.type == FileOp::Type::Replace ? atomic_write(op.path, op.data)
                                                             : append_line(op.path, op.data);
            if (!ok) {
                r.ok = false;
                r.failed_path = op.path;
                break;
            }
        }
        return r;
    }

    void run()
    {
        std::unique_lock<std::mutex> lk(m_mu);
        for (;;) {
            m_cv.wait(lk, [&] { return m_stop || !m_queue.empty(); });
            if (m_queue.empty()) return;   // stop requested and nothing left to write
            Job job = std::move(m_queue.front());
            m_queue.pop_front();
            m_busy = true;
            auto hook = m_before_job;
            lk.unlock();
            if (hook) hook();
            FileJobResult r = execute(job.tag, job.ops);
            lk.lock();
            m_busy = false;
            ++m_done;
            if (job.tag || !r.ok) m_results.push_back(std::move(r));
            m_idle_cv.notify_all();
        }
    }

    const bool m_inline;
    const std::size_t m_max_jobs;
    mutable std::mutex m_mu;
    std::condition_variable m_cv, m_idle_cv;
    std::deque<Job> m_queue;
    std::vector<FileJobResult> m_results;
    std::function<void()> m_before_job;
    bool m_busy{false};
    bool m_stop{false};
    uint64_t m_submitted{0}, m_done{0}, m_coalesced{0}, m_deferred{0};
    std::thread m_thread;   // last: started after every member above exists
};

} // namespace dash::alert
