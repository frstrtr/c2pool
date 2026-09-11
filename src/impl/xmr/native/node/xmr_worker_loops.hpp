// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/node/xmr_worker_loops.hpp
//
// M0, the ASSEMBLY: the threads the components were written to be driven from,
// and the fence that keeps the expensive ones off the io thread.
//
// Every wave-1 component states its threading contract in its own banner and
// none of them provides the thread:
//
//   * C1c (xmr_peer_pool.hpp) calls IChainIndexInbound and IRelayedTxSink from
//     the io thread, and the header says "enqueue-and-return".
//   * C2c (xmr_chain_index.hpp) says "one owner (the verify thread) mutates",
//     and offer_block() is where PowGate::check() runs a ~10-15 ms RandomX
//     evaluation. Calling it from the io thread would stall every other peer on
//     the same io_context and let one crafted push wedge the node -- the exact
//     failure C1b's "RandomX never runs on the io thread" fence exists to
//     prevent, which C1b can only enforce for ITSELF (it hashes nothing).
//   * C3 (xmr_relayed_txpool.hpp) says "decoding and proof verification happen
//     INSIDE on_relayed, so the caller must not be the io thread once the heavy
//     leg is on" -- a Bulletproof+ verification per relayed transaction.
//
// So the wire-up owes three things, and they are all here:
//
//   1. WorkerLoop  -- one thread, one bounded queue, a blocking call() for the
//      control path. The thread IS the component's contract made real.
//   2. VerifyInbound / TxSinkLoop -- the enqueue-and-return adapters that sit
//      between the io thread and the component, so no component had to be
//      changed to acquire a thread.
//   3. ThreadWitnessPowSource -- the proof, not the promise. It records the
//      thread every RandomX evaluation actually ran on and counts the ones that
//      ran on a thread declared forbidden (the io threads). "RandomX is off the
//      io thread" then stops being an argument about call graphs and becomes a
//      number the node prints, and the node KAT asserts.
//
// WHY A BOUNDED QUEUE, AND WHY `control` JUMPS IT. The queue is the one place a
// peer can make us allocate without bound: blocks arrive at whatever rate the
// network offers and the verify thread drains at the speed of RandomX. So the
// data queue is capped and an overflow is REFUSED and COUNTED rather than
// grown -- a refused block is re-offered by the next peer announcement or
// re-fetched by the sync driver, an unbounded queue is an out-of-memory kill.
// Control tasks (the driver tick, a status read, the parity drain) are posted
// by us, are O(1) in number, and must never be dropped by a peer's flood, so
// they are admitted past the cap.
//
// TXPOOL VERDICTS SURVIVE THE DEFERRAL. IRelayedTxSink::on_relayed returns the
// per-transaction verdicts C1c scores the peer on, and a deferred call cannot
// return them. Answering with an invented "accepted" would silently disarm the
// relay-offence path, so TxSinkLoop answers with NO verdicts (C1c raises no
// fault on an empty vector) and reports every drop-offence afterwards through a
// FaultSink bound to IChainFetcher::penalize, which is thread-safe by contract
// and posts back to the io thread. The DoS signal is delayed, never lost.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record;
// nothing here activates v37 consensus and src/sharechain/v37 is not touched.
//
// NAMESPACE. `c2pool::xmr::native::rt` (runtime), NOT `...::native::node`:
// contracts/types.hpp opens `namespace node = ::c2pool::xmr::node` inside
// `c2pool::xmr::native`, so a nested namespace called `node` would shadow the
// alias every component in this tree spells its value types through.
//
// Header-only. STL only.
// ---------------------------------------------------------------------------
#pragma once

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "impl/xmr/native/chain/xmr_pow_gate.hpp"
#include "impl/xmr/native/contracts/chain_index.hpp"
#include "impl/xmr/native/contracts/txpool.hpp"
#include "impl/xmr/native/contracts/types.hpp"

namespace c2pool::xmr::native::rt {

// ---------------------------------------------------------------------------
// WorkerLoop: one thread, one bounded queue.
// ---------------------------------------------------------------------------
class WorkerLoop {
public:
    using Task = std::function<void()>;

    struct Stats {
        std::uint64_t posted    = 0;
        std::uint64_t executed  = 0;
        std::uint64_t refused   = 0;   // queue full and the task was not control
        std::size_t   depth     = 0;
        std::size_t   max_depth = 0;
    };

    explicit WorkerLoop(std::string name, std::size_t capacity = 4096)
        : name_(std::move(name)), capacity_(capacity ? capacity : 1) {}

    WorkerLoop(const WorkerLoop&)            = delete;
    WorkerLoop& operator=(const WorkerLoop&) = delete;
    ~WorkerLoop() { stop(); }

    const std::string& name() const noexcept { return name_; }

    void start() {
        std::lock_guard<std::mutex> lk(mu_);
        if (running_) return;
        running_ = true;
        thread_  = std::thread([this] { run_(); });
        tid_     = thread_.get_id();
    }

    // Idempotent, and safe to call from any thread except this loop's own.
    void stop() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!running_) return;
            running_ = false;
        }
        cv_.notify_all();
        if (thread_.joinable() && std::this_thread::get_id() != thread_.get_id())
            thread_.join();
    }

    bool running() const {
        std::lock_guard<std::mutex> lk(mu_);
        return running_;
    }

    std::thread::id thread_id() const {
        std::lock_guard<std::mutex> lk(mu_);
        return tid_;
    }

    bool on_this_thread() const {
        std::lock_guard<std::mutex> lk(mu_);
        return running_ && std::this_thread::get_id() == tid_;
    }

    // false == refused because the data queue is full (never for control tasks,
    // and never silently: `refused` counts it).
    bool post(Task t, bool control = false) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!running_) return false;
            if (!control && queue_.size() >= capacity_) {
                ++stats_.refused;
                return false;
            }
            queue_.push_back(std::move(t));
            ++stats_.posted;
            if (queue_.size() > stats_.max_depth) stats_.max_depth = queue_.size();
        }
        cv_.notify_one();
        return true;
    }

    // Blocking round trip, for the control path only (a status read, a parity
    // drain). Runs inline when the caller already IS this loop, so a task that
    // calls back into its own loop cannot deadlock itself.
    bool call(const Task& t) {
        if (on_this_thread()) { t(); return true; }
        std::mutex m;
        std::condition_variable cv;
        bool done = false;
        if (!post([&] {
                t();
                { std::lock_guard<std::mutex> lk(m); done = true; }
                cv.notify_one();
            },
            /*control=*/true))
            return false;
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [&] { return done; });
        return true;
    }

    Stats stats() const {
        std::lock_guard<std::mutex> lk(mu_);
        Stats s = stats_;
        s.depth = queue_.size();
        return s;
    }

private:
    void run_() {
        for (;;) {
            Task t;
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait(lk, [this] { return !running_ || !queue_.empty(); });
                if (!running_ && queue_.empty()) return;
                t = std::move(queue_.front());
                queue_.pop_front();
                ++stats_.executed;
            }
            t();
        }
    }

    mutable std::mutex      mu_;
    std::condition_variable cv_;
    std::string             name_;
    std::size_t             capacity_;
    std::deque<Task>        queue_;
    std::thread             thread_;
    std::thread::id         tid_{};
    bool                    running_ = false;
    Stats                   stats_{};
};

// ---------------------------------------------------------------------------
// VerifyInbound: IChainIndexInbound on the io thread -> the verify loop.
//
// Every method copies what it was handed onto the queue and returns. The index
// behind it is then touched by exactly one thread, which is what its own
// "one owner mutates" contract asks for -- and RandomX runs there.
// ---------------------------------------------------------------------------
class VerifyInbound final : public IChainIndexInbound {
public:
    struct Stats {
        std::uint64_t sync_data   = 0;
        std::uint64_t chain_entry = 0;
        std::uint64_t objects     = 0;
        std::uint64_t new_block   = 0;
        std::uint64_t peer_gone   = 0;
        std::uint64_t refused     = 0;   // queue full: the message was dropped
    };

    VerifyInbound(WorkerLoop& loop, IChainIndexInbound& target)
        : loop_(loop), target_(target) {}

    void on_peer_sync_data(const PeerRef& p, const PeerSyncData& d) override {
        bump_(stats_.sync_data);
        defer_([this, p, d] { target_.on_peer_sync_data(p, d); });
    }

    void on_chain_entry(const PeerRef& p, ChainEntry&& e) override {
        bump_(stats_.chain_entry);
        defer_([this, p, e = std::move(e)]() mutable {
            target_.on_chain_entry(p, std::move(e));
        });
    }

    void on_objects(const PeerRef& p, std::vector<BlockEntry>&& blocks,
                    std::vector<Hash>&& missed, std::uint64_t peer_height) override {
        bump_(stats_.objects);
        defer_([this, p, blocks = std::move(blocks), missed = std::move(missed),
                peer_height]() mutable {
            target_.on_objects(p, std::move(blocks), std::move(missed), peer_height);
        });
    }

    void on_new_block(const PeerRef& p, BlockEntry&& block, std::uint64_t peer_height,
                      bool fluffy) override {
        bump_(stats_.new_block);
        defer_([this, p, block = std::move(block), peer_height, fluffy]() mutable {
            target_.on_new_block(p, std::move(block), peer_height, fluffy);
        });
    }

    void on_peer_gone(const PeerRef& p) override {
        bump_(stats_.peer_gone);
        // A peer going away must always be delivered: the index's peer cohort
        // (and with it the synced flag) is derived from it, and a dropped
        // departure leaves a ghost peer holding the cohort height up forever.
        defer_([this, p] { target_.on_peer_gone(p); }, /*control=*/true);
    }

    Stats stats() const {
        std::lock_guard<std::mutex> lk(mu_);
        return stats_;
    }

private:
    void bump_(std::uint64_t& counter) {
        std::lock_guard<std::mutex> lk(mu_);
        ++counter;
    }

    void defer_(WorkerLoop::Task t, bool control = false) {
        if (loop_.post(std::move(t), control)) return;
        std::lock_guard<std::mutex> lk(mu_);
        ++stats_.refused;
    }

    WorkerLoop&         loop_;
    IChainIndexInbound& target_;
    mutable std::mutex  mu_;
    Stats               stats_{};
};

// ---------------------------------------------------------------------------
// TxSinkLoop: IRelayedTxSink on the io thread -> the pool loop.
//
// See the banner: the verdicts cannot come back synchronously, so none are
// invented. Drop-offences are reported afterwards through `faults`.
// ---------------------------------------------------------------------------
class TxSinkLoop final : public IRelayedTxSink {
public:
    using FaultSink = std::function<void(const PeerRef&, PeerFault, const std::string&)>;

    struct Stats {
        std::uint64_t batches       = 0;
        std::uint64_t blobs         = 0;
        std::uint64_t refused       = 0;
        std::uint64_t drop_offences = 0;
    };

    TxSinkLoop(WorkerLoop& loop, IRelayedTxSink& target, FaultSink faults = {})
        : loop_(loop), target_(target), faults_(std::move(faults)) {}

    // The fault route is bound after construction because the peer pool it
    // penalizes through does not exist until the sinks it is built from do.
    void set_faults(FaultSink f) {
        std::lock_guard<std::mutex> lk(mu_);
        faults_ = std::move(f);
    }

    std::vector<TxRelayVerdict> on_relayed(const PeerRef&                         from,
                                           std::vector<std::vector<std::uint8_t>> blobs,
                                           bool dandelionpp_fluff) override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            ++stats_.batches;
            stats_.blobs += blobs.size();
        }
        const bool queued = loop_.post(
            [this, from, blobs = std::move(blobs), dandelionpp_fluff]() mutable {
                const std::vector<TxRelayVerdict> v =
                    target_.on_relayed(from, std::move(blobs), dandelionpp_fluff);
                for (const TxRelayVerdict& r : v) {
                    if (!r.drop_offense) continue;
                    FaultSink fs;
                    {
                        std::lock_guard<std::mutex> lk(mu_);
                        ++stats_.drop_offences;
                        fs = faults_;
                    }
                    if (fs) fs(from, PeerFault::BadData, "relayed transaction offence");
                    break;
                }
            });
        if (!queued) {
            std::lock_guard<std::mutex> lk(mu_);
            ++stats_.refused;
        }
        return {};   // no verdict is invented; see the banner
    }

    // A cheap read under the pool's own mutex; it allocates a vector of ids and
    // touches no proof, so it answers in place rather than costing a round trip
    // on the path that is about to write a frame.
    std::vector<Hash> complement_request_ids() const override {
        return target_.complement_request_ids();
    }

    Stats stats() const {
        std::lock_guard<std::mutex> lk(mu_);
        return stats_;
    }

private:
    WorkerLoop&        loop_;
    IRelayedTxSink&    target_;
    FaultSink          faults_;
    mutable std::mutex mu_;
    Stats              stats_{};
};

// ---------------------------------------------------------------------------
// ThreadWitnessPowSource: the io-thread fence, measured.
//
// It wraps any IPowSource and records the thread ids RandomX actually ran on.
// `forbid()` names a thread that must never appear (the io threads); every call
// that arrives on one is counted in `foreign_calls`, which the status line
// prints and the node KAT asserts is zero. A structural argument about who
// calls whom is worth less than a counter that would be non-zero if the wiring
// ever regressed.
// ---------------------------------------------------------------------------
class ThreadWitnessPowSource final : public IPowSource {
public:
    struct Witness {
        std::uint64_t               hashes        = 0;
        std::uint64_t               prefetches    = 0;
        std::uint64_t               foreign_calls = 0;   // MUST be 0
        std::vector<std::string>    threads;             // where it really ran
    };

    explicit ThreadWitnessPowSource(IPowSource& inner) : inner_p_(&inner) {}

    // Re-point at the real verifier once it exists. The WITNESS OBJECT must
    // outlive this change and keep its address: ChainIndex caches the
    // IPowSource* it was constructed with (its sync_state() reads mode()
    // through it), so swapping the witness itself for a new one leaves that
    // cached pointer dangling -- which is a segfault on the first status read,
    // found exactly that way on the first live run.
    void set_inner(IPowSource& inner) {
        std::lock_guard<std::mutex> lk(mu_);
        inner_p_ = &inner;
    }

    // Name a thread RandomX must never run on. Called once per io thread.
    void forbid(std::thread::id id) {
        std::lock_guard<std::mutex> lk(mu_);
        forbidden_.insert(id);
    }

    bool prefetch(const Hash& current_seed, const std::optional<Hash>& next_seed) override {
        note_(/*hash=*/false);
        return inner_()->prefetch(current_seed, next_seed);
    }

    bool seed_resident(const Hash& seed) const override {
        return inner_()->seed_resident(seed);
    }

    PowVerdict verify(const std::uint8_t* blob, std::size_t blob_len, const Hash& seed,
                      const U128& difficulty, Hash& pow_hash_out) override {
        note_(/*hash=*/true);
        return inner_()->verify(blob, blob_len, seed, difficulty, pow_hash_out);
    }

    RandomXMode mode() const override { return inner_()->mode(); }

    Witness witness() const {
        std::lock_guard<std::mutex> lk(mu_);
        Witness w;
        w.hashes        = hashes_;
        w.prefetches    = prefetches_;
        w.foreign_calls = foreign_;
        for (const std::thread::id& id : seen_) {
            std::ostringstream os;
            os << id;
            w.threads.push_back(os.str());
        }
        return w;
    }

private:
    void note_(bool hash) {
        const std::thread::id me = std::this_thread::get_id();
        std::lock_guard<std::mutex> lk(mu_);
        if (hash) ++hashes_; else ++prefetches_;
        seen_.insert(me);
        if (forbidden_.count(me)) ++foreign_;
    }

    IPowSource* inner_() const {
        std::lock_guard<std::mutex> lk(mu_);
        return inner_p_;
    }

    IPowSource*                    inner_p_ = nullptr;
    mutable std::mutex             mu_;
    std::set<std::thread::id>      seen_;
    std::set<std::thread::id>      forbidden_;
    std::uint64_t                  hashes_     = 0;
    std::uint64_t                  prefetches_ = 0;
    std::uint64_t                  foreign_    = 0;
};

} // namespace c2pool::xmr::native::rt
