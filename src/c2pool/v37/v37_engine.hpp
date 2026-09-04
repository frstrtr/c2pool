#pragma once
// V37Engine — the node-lifetime host shell the v37 executor plugs into.
// Track A2 bring-up step W0 (node-scaffold slice). CONSUMER-tree code: it
// lives here, NOT in src/sharechain/v37/, which stays the pure header-only
// consensus module with zero consumers.
//
// V37Engine is the SOLE owner of one v37::LaneExecutor (which privately owns
// the whole Roundabout). It is the only seam every other subsystem talks to:
//
//   producers (W2 share admission, W3 carrier, W5 coinbase — any thread)
//       -> submit(record) / submit_tracked(record) -> a strict MPSC FIFO
//       -> ONE executor thread drains it in arrival order -> LaneExecutor
//
//   readers (W4 settlement, dashboard, /sharechain HTTP — any thread)
//       -> snapshot(chain) -> atomic load() of a per-lane publication mailbox
//
// The ONE hard rule (v37_lane_executor.hpp / Lanes.tla §8.3): the consensus
// fold is single-threaded and deterministic, and the ORDER records reach the
// executor IS the consensus input. The shell MUST NOT reorder, batch, defer,
// or parallelize records. The MPSC FIFO's pop order is the committed order,
// and it is this process's only source of record sequencing.
//
// O1 mapping (obligation -> the construct that discharges it here):
//   O1.1  snapshot publication is atomic and immutable — the executor thread
//         store()s a shared_ptr<const LaneSnapshot> into a per-lane atomic
//         mailbox slot; readers load() it and hold it validly across later
//         mutations (versions retained, never mutated).
//   O1.2  no Lane&/Roundabout&/LaneExecutor& ever escapes V37Engine; the
//         public surface returns values or shared-const only (static-asserted
//         at the bottom of this header).
//   O1.4  producers enqueue by value and never take a lock the executor holds
//         and never get a callback out; submit_tracked's future is fulfilled
//         from inside the executor thread by value copy.
//   O1.5  exactly one writer: one executor thread, one LaneExecutor; the
//         engine is non-copyable and non-movable.
//
// F1 (W1 finding) — LaneExecutor::receive() mutates the executor's per-lane
// cache, so it is executor-thread-only. This shell interposes the publication
// mailbox: the executor thread is the SOLE caller of receive() and the SOLE
// writer of every slot; readers only load(). No reader ever calls receive().
//
// F2 (W1 finding) — the node-monotone lane incarnation id is minted by the
// executor (the sole minter, X-4), stamped onto LaneSnapshot, and merely
// CARRIED out through this mailbox. V37Engine runs NO counter of its own.
//
// stdlib-only: this header pulls in nothing but <sharechain/v37/...> and the
// C++20 standard library, so the seam is unit-testable without Boost/gtest.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>

#include <sharechain/v37/v37_lane_executor.hpp>

namespace c2pool::v37n {

class V37Engine {
public:
    V37Engine() = default;
    ~V37Engine() { stop(); }

    // O1.5 / wraps a non-movable LaneExecutor: exactly one writer, and the
    // shell that holds it cannot be duplicated or moved out from under it.
    V37Engine(const V37Engine&) = delete;
    V37Engine& operator=(const V37Engine&) = delete;
    V37Engine(V37Engine&&) = delete;
    V37Engine& operator=(V37Engine&&) = delete;

    // Spawn the single executor thread; begin draining the FIFO. Idempotent.
    void start() {
        if (m_running.exchange(true)) return;
        m_stopping = false;
        m_thread = std::thread([this] { run(); });
    }

    // Drain-and-join: stop accepting new records, finish the queued prefix,
    // then join the executor thread. Called AFTER ioc.run() returns (donor
    // teardown order), so no wire handler can submit() into a torn-down
    // engine. Idempotent.
    void stop() {
        if (!m_running.exchange(false)) return;
        {
            std::lock_guard<std::mutex> lk(m_qmtx);
            m_stopping = true;
        }
        m_qcv.notify_all();
        if (m_thread.joinable()) m_thread.join();
    }

    // ── producer seam (any thread) ────────────────────────────────────────
    // Fire-and-forget: enqueue in arrival order and return immediately (O1.4;
    // no callback out). Records offered after stop() begins are dropped
    // before enqueue (never half-applied).
    void submit(::v37::LaneRecord r) {
        std::lock_guard<std::mutex> lk(m_qmtx);
        if (m_stopping) return;                 // dropped-before-enqueue
        m_q.push_back(Command{std::move(r), {}, false});
        m_qcv.notify_one();
    }

    // Tracked: the producer needs the disposition back (W2 needs the interned
    // MinerId + accept/reject). The promise is fulfilled ON the executor
    // thread by value copy, no lock held across the boundary (O1.4).
    std::future<::v37::SubmitResult> submit_tracked(::v37::LaneRecord r) {
        std::promise<::v37::SubmitResult> prom;
        std::future<::v37::SubmitResult> fut = prom.get_future();
        std::lock_guard<std::mutex> lk(m_qmtx);
        if (m_stopping) {
            // Engine is winding down: the record will not be applied. Report
            // it to the waiter rather than leaving a broken promise.
            prom.set_exception(std::make_exception_ptr(
                std::runtime_error("V37Engine stopped; record not enqueued")));
            return fut;
        }
        m_q.push_back(Command{std::move(r), std::move(prom), true});
        m_qcv.notify_one();
        return fut;
    }

    // ── reader seam (any thread) ──────────────────────────────────────────
    // Atomic load() of the lane's publication mailbox. nullptr if the lane
    // has no published version yet (or was removed). NEVER calls receive():
    // this is the F1-safe reader path.
    std::shared_ptr<const ::v37::LaneSnapshot> snapshot(::v37::ChainId c) const {
        std::lock_guard<std::mutex> lk(m_slots_mtx);   // guards map STRUCTURE
        auto it = m_slots.find(c);
        if (it == m_slots.end()) return nullptr;
        return it->second->load();                     // atomic pointer load
    }

    // Mirror of LaneExecutor::ops_committed(), readable from any thread
    // (the executor's own counter is single-thread state; this atomic is
    // published by the executor thread after each committed record).
    std::uint64_t ops_committed() const { return m_ops_mirror.load(); }

private:
    struct Command {
        ::v37::LaneRecord rec;
        std::promise<::v37::SubmitResult> prom;   // valid iff tracked
        bool tracked = false;
    };

    // The executor-thread body: pop one record, apply it, publish the fresh
    // snapshot (F1: sole receive() caller), fulfill any tracked promise.
    void run() {
        for (;;) {
            Command c;
            {
                std::unique_lock<std::mutex> lk(m_qmtx);
                m_qcv.wait(lk, [this] { return !m_q.empty() || m_stopping; });
                if (m_q.empty()) {           // woken only to stop, fully drained
                    if (m_stopping) break;
                    continue;
                }
                c = std::move(m_q.front());
                m_q.pop_front();
            }
            ::v37::SubmitResult res = m_exec.submit(c.rec);
            publish(c.rec, res);
            m_ops_mirror.store(m_exec.ops_committed());
            if (c.tracked) c.prom.set_value(res);
        }
    }

    // Executor thread only. Re-publish the affected lane's mailbox slot.
    void publish(const ::v37::LaneRecord& rec, const ::v37::SubmitResult& res) {
        using K = ::v37::LaneRecord::Kind;
        if (!res.applied()) return;                    // rejected: no change
        ::v37::ChainId c = rec.chain;
        if (rec.kind == K::RemoveLane) {
            // Lane is gone; clear its slot so readers see nullptr until it is
            // re-added (a fresh incarnation, F2).
            slot(c).store(nullptr);
            return;
        }
        // AddLane / Push / Rewind applied: the lane exists. receive() is safe
        // here — this is the one thread that owns m_exec.
        slot(c).store(m_exec.receive(c));
    }

    // Executor thread only: get-or-create the atomic slot for a lane. Slots
    // are never erased (RemoveLane store()s nullptr), so a slot's address is
    // stable for the engine's life. The slot's POINTER VALUE is published via an
    // atomic store()/load() (acquire/release), so a reader always observes a
    // fully-constructed snapshot and never a torn pointer. This is NOT a
    // lock-free read in the strict sense, though: the reader path (snapshot())
    // first takes m_slots_mtx briefly for the map structural lookup and only then
    // does the atomic load() — only the publication of the pointer value itself
    // is lock-free, not the lane lookup.
    std::atomic<std::shared_ptr<const ::v37::LaneSnapshot>>& slot(
        ::v37::ChainId c) {
        std::lock_guard<std::mutex> lk(m_slots_mtx);
        auto it = m_slots.find(c);
        if (it == m_slots.end()) {
            it = m_slots.emplace(
                     c, std::make_unique<
                            std::atomic<std::shared_ptr<
                                const ::v37::LaneSnapshot>>>())
                     .first;
        }
        return *it->second;
    }

    // Owned; never escapes. Touched ONLY by the executor thread.
    ::v37::LaneExecutor m_exec;

    // MPSC command FIFO (many producers, one consumer). Pop order == the
    // committed consensus order.
    std::mutex m_qmtx;
    std::condition_variable m_qcv;
    std::deque<Command> m_q;
    bool m_stopping = false;

    // Per-lane publication mailbox. unique_ptr keeps each atomic's address
    // stable across map growth; the map STRUCTURE is guarded by m_slots_mtx,
    // the pointer value by the atomic itself (F1 fix).
    mutable std::mutex m_slots_mtx;
    std::map<::v37::ChainId,
             std::unique_ptr<std::atomic<
                 std::shared_ptr<const ::v37::LaneSnapshot>>>>
        m_slots;

    std::atomic<std::uint64_t> m_ops_mirror{0};
    std::thread m_thread;
    std::atomic<bool> m_running{false};
};

// ── O1.2 surface audit: no reference into lane state escapes the engine ────
// Expressible at compile time: every public read returns a value or a shared
// pointer to const, and the writer cannot be duplicated or moved. There is no
// public member that hands out a Lane&/Roundabout&/LaneExecutor& — that is
// enforced by their absence from the surface, which these traits pin down.
static_assert(
    std::is_same_v<decltype(std::declval<V37Engine&>().submit(
                       std::declval<::v37::LaneRecord>())),
                   void>,
    "submit is fire-and-forget (no reference, no disposition leaked)");
static_assert(
    std::is_same_v<decltype(std::declval<V37Engine&>().submit_tracked(
                       std::declval<::v37::LaneRecord>())),
                   std::future<::v37::SubmitResult>>,
    "submit_tracked returns a future of a value disposition");
static_assert(
    std::is_same_v<decltype(std::declval<const V37Engine&>().snapshot(
                       ::v37::ChainId{})),
                   std::shared_ptr<const ::v37::LaneSnapshot>>,
    "snapshot returns a shared pointer to an immutable snapshot value");
static_assert(!std::is_reference_v<decltype(std::declval<const V37Engine&>()
                                                .ops_committed())>,
              "ops_committed is a value");
static_assert(!std::is_copy_constructible_v<V37Engine> &&
                  !std::is_copy_assignable_v<V37Engine> &&
                  !std::is_move_constructible_v<V37Engine> &&
                  !std::is_move_assignable_v<V37Engine>,
              "O1.5: exactly one writer — the engine cannot be duplicated");

} // namespace c2pool::v37n
