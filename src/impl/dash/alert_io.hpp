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
// Coalescing: a job that is a single Replace of path P replaces the data of
// the LAST queued (not yet started) job when that one is also a single
// Replace of P (at most one of the two carrying a completion tag). The later
// snapshot supersedes the earlier one and FIFO order against every other job
// is preserved, so a burst of state saves costs one fsync.
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
    explicit FileWriter(bool inline_mode) : m_inline(inline_mode)
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
    void submit(uint64_t tag, std::vector<FileOp> ops)
    {
        if (ops.empty()) return;
        if (m_inline) {
            ++m_submitted;
            FileJobResult r = execute(tag, ops);
            std::lock_guard<std::mutex> lk(m_mu);
            ++m_done;
            if (tag || !r.ok) m_results.push_back(std::move(r));
            return;
        }
        std::lock_guard<std::mutex> lk(m_mu);
        ++m_submitted;
        if (ops.size() == 1 && ops[0].type == FileOp::Type::Replace && !m_queue.empty()) {
            Job& last = m_queue.back();
            if (last.ops.size() == 1 && last.ops[0].type == FileOp::Type::Replace &&
                last.ops[0].path == ops[0].path && (last.tag == 0 || tag == 0)) {
                last.ops[0].data = std::move(ops[0].data);
                if (tag) last.tag = tag;
                ++m_coalesced;
                return;
            }
        }
        m_queue.push_back(Job{tag, std::move(ops)});
        m_cv.notify_one();
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
    mutable std::mutex m_mu;
    std::condition_variable m_cv, m_idle_cv;
    std::deque<Job> m_queue;
    std::vector<FileJobResult> m_results;
    std::function<void()> m_before_job;
    bool m_busy{false};
    bool m_stop{false};
    uint64_t m_submitted{0}, m_done{0}, m_coalesced{0};
    std::thread m_thread;   // last: started after every member above exists
};

} // namespace dash::alert
