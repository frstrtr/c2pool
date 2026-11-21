// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_node_rx.hpp
// The node's RandomX wiring, shared by main_v37_xmr.cpp and the KATs:
//   seed_walk        the seed of P_r's branch (S1.3 #11, S2.3 #15): from P_r by parent links over the rows the index
//                    holds (main or alternative) and the follower's kept rows, down to the seed height, at most
//                    kept_rows_cap() links, under one hold of the rows. At the seed height: the row's own id. On a
//                    main-chain row above it: the held main row at the seed height, else the index's seed table.
//                    Any other end: no seed (DEFER Seed), with the stopping id.
//   SeedMemo         a seed per P_r the index holds, kept while it holds it; per P_r without a seed, the walk's
//                    stopping id: one lookup per call until that id is held or kept, then the walk resumes from it.
//                    Called inside the rows hold (main: the index mutex); the row event drops the entries no longer
//                    held or no longer asked. A P_r neither held nor kept gets no entry.
//   INodeRxEngine    the node's RandomX engine (main: NodeRxVerifier, xmr_node_rx_verify.hpp)
//   RxKeyer          the keying worker: one thread, one request in flight per seed, the adoption and the failure
//                    callbacks; manual mode: the caller pumps it
//   node_hash        RandomX on the engine; a seed not keyed posts its keying request and leaves as RandomxNotKeyed
//   main_seed_pins   the main-chain seeds the open heights name: seed(t + 1), and seed(t + 1 - (F + Fresh)) when it
//                    differs, else the next epoch's once t + 1 is within the lag; at most two
//   make_node_rx_io  ONE factory: seed_of, verify, the context hash, the pins, the row event, the keyer, the memo
//   index_seed_rows  the rows of a ChainIndex (with_held_rows) and the follower's kept rows (kept_row)
// ---------------------------------------------------------------------------
#pragma once

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "impl/xmr/coin/xmr_check_hash.hpp"
#include "impl/xmr/coin/xmr_seedheight.hpp"
#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "c2pool/v37/xmr/pathb/pathb_follower_rows.hpp"
#include "c2pool/v37/xmr/pathb/pathb_node.hpp"

namespace c2pool::xmr::pathb {

struct SeedRow {
    Hash32 id{};
    Hash32 prev_id{};
    std::uint64_t height = 0;
    bool main = false;
};

// The rows the walk reads, inside one hold.
class ISeedRows {
public:
    virtual ~ISeedRows() = default;
    virtual std::optional<SeedRow> held(const Hash32& id) const = 0;                          // main or alternative
    virtual std::optional<SeedRow> kept(const Hash32& id, std::uint64_t tip_h) const = 0;     // a kept row
    virtual std::optional<Hash32> main_id_at(std::uint64_t h) const = 0;                       // a held main row
    virtual std::optional<Hash32> seed_id_for(std::uint64_t h_child) const = 0;                // the seed table
    virtual std::uint64_t tip_height() const = 0;
};
// Runs fn(rows) under one hold.
using SeedRowsHold = std::function<void(const std::function<void(const ISeedRows&)>&)>;

struct SeedWalk {
    std::optional<Hash32> seed;
    Hash32 stop{};               // no seed: the first parent nobody holds, or the row the walk ended on
    std::uint64_t steps = 0;     // parent links followed
    std::uint64_t h_child = 0;   // height(P_r) + 1 (0: P_r not read)
    bool start_held = false;     // the walk's first row is a held row
};

inline std::optional<Hash32> main_seed_at(const ISeedRows& r, std::uint64_t seed_h, std::uint64_t h_child) {
    if (const std::optional<Hash32> id = r.main_id_at(seed_h)) return id;
    return r.seed_id_for(h_child);
}

// h_child: height(P_r) + 1 when known (a resumed walk), else 0 (read from the first row).
inline SeedWalk seed_walk(const ISeedRows& r, const Hash32& from, std::uint64_t h_child, std::uint64_t steps,
                          std::uint64_t bound) {
    SeedWalk w;
    w.steps = steps;
    w.h_child = h_child;
    const std::uint64_t tip_h = r.tip_height();
    Hash32 cur = from;
    for (bool first = true;; first = false) {
        std::optional<SeedRow> row = r.held(cur);
        if (first) w.start_held = row.has_value();
        if (!row) row = r.kept(cur, tip_h);
        if (!row) {
            w.stop = cur;
            return w;
        }
        if (w.h_child == 0) w.h_child = row->height + 1;
        const std::uint64_t seed_h = ::xmr::coin::rx_seedheight(w.h_child);
        if (row->height == seed_h) {
            w.seed = row->id;
            return w;
        }
        if (row->main && row->height > seed_h) {
            w.seed = main_seed_at(r, seed_h, w.h_child);
            if (!w.seed) w.stop = cur;
            return w;
        }
        if (row->height < seed_h || w.steps >= bound) {
            w.stop = cur;
            return w;
        }
        ++w.steps;
        cur = row->prev_id;
    }
}

class SeedMemo {
public:
    struct Stats {
        std::uint64_t walks = 0;    // walks from P_r
        std::uint64_t resumes = 0;  // walks resumed from a stopping id
        std::uint64_t hits = 0;     // seeds answered from the memo
        std::uint64_t waits = 0;    // calls answered by the stopping id's one lookup
    };
    explicit SeedMemo(std::uint64_t bound = kept_rows_cap()) : bound_(bound) {}

    std::optional<Hash32> seed_of(const ISeedRows& r, const Hash32& p_r) {
        if (const auto s = seeds_.find(p_r); s != seeds_.end()) {
            if (r.held(p_r)) {
                ++st_.hits;
                return s->second;
            }
            seeds_.erase(s);
        }
        SeedWalk w;
        const auto d = defers_.find(p_r);
        if (d != defers_.end()) {
            d->second.touched = epoch_;
            const Hash32 stop = d->second.stop;
            if (!r.held(stop) && !r.kept(stop, r.tip_height())) {
                ++st_.waits;
                return std::nullopt;
            }
            ++st_.resumes;
            w = seed_walk(r, stop, d->second.h_child, d->second.steps, bound_);
            w.start_held = r.held(p_r).has_value();
        } else {
            ++st_.walks;
            w = seed_walk(r, p_r, 0, 0, bound_);
        }
        if (w.seed) {
            defers_.erase(p_r);
            if (w.start_held) seeds_[p_r] = *w.seed;
            return w.seed;
        }
        if (w.h_child == 0) {  // P_r neither held nor kept
            defers_.erase(p_r);
            return std::nullopt;
        }
        defers_[p_r] = Defer{w.stop, w.steps, w.h_child, epoch_};
        return std::nullopt;
    }

    // A row event of the index: the seeds of rows no longer held go; a DEFER not asked since the previous event goes.
    void on_rows_event(const ISeedRows& r) {
        ++epoch_;
        for (auto it = seeds_.begin(); it != seeds_.end();) it = r.held(it->first) ? std::next(it) : seeds_.erase(it);
        for (auto it = defers_.begin(); it != defers_.end();)
            it = it->second.touched + 1 < epoch_ ? defers_.erase(it) : std::next(it);
    }

    std::size_t seeds() const noexcept { return seeds_.size(); }
    std::size_t defers() const noexcept { return defers_.size(); }
    std::optional<Hash32> stop_of(const Hash32& p_r) const {
        const auto it = defers_.find(p_r);
        if (it == defers_.end()) return std::nullopt;
        return it->second.stop;
    }
    const Stats& stats() const noexcept { return st_; }

private:
    struct Defer {
        Hash32 stop{};
        std::uint64_t steps = 0;
        std::uint64_t h_child = 0;
        std::uint64_t touched = 0;
    };
    std::uint64_t bound_;
    std::uint64_t epoch_ = 0;
    std::map<Hash32, Hash32> seeds_;
    std::map<Hash32, Defer> defers_;
    Stats st_;
};

// The node's RandomX engine.
enum class RxHash : std::uint8_t { Hashed, NotKeyed, NotReady, Fault };
class INodeRxEngine {
public:
    virtual ~INodeRxEngine() = default;
    virtual bool ready() const = 0;
    virtual std::string mode_name() const = 0;
    virtual bool resident(const Hash32& seed) const = 0;
    virtual RxHash hash(const std::vector<std::uint8_t>& bytes, const Hash32& seed, Hash32& pow) = 0;
    // Builds the seed's cache off the caller's locks and installs it (the keying thread); false: not built.
    virtual bool key(const Hash32& seed) = 0;
    // The pinned main-chain seeds, (seed height, id), at most two.
    virtual void set_pins(const std::vector<std::pair<std::uint64_t, Hash32>>& pins) = 0;
};

// The engine over a verifier with ready(), mode_name(), resident(seed), hash(bytes, seed, pow) -> V::Hashed
// {Ok, NotKeyed, NotReady, Fault}, key(seed) and set_pins(pins) (main: NodeRxVerifier).
template <class V>
class VerifierEngine final : public INodeRxEngine {
public:
    explicit VerifierEngine(V& v) : v_(v) {}
    bool ready() const override { return v_.ready(); }
    std::string mode_name() const override { return v_.mode_name(); }
    bool resident(const Hash32& seed) const override { return v_.resident(seed); }
    RxHash hash(const std::vector<std::uint8_t>& bytes, const Hash32& seed, Hash32& pow) override {
        switch (v_.hash(bytes, seed, pow)) {
            case V::Hashed::Ok: return RxHash::Hashed;
            case V::Hashed::NotKeyed: return RxHash::NotKeyed;
            case V::Hashed::NotReady: return RxHash::NotReady;
            case V::Hashed::Fault: break;
        }
        return RxHash::Fault;
    }
    bool key(const Hash32& seed) override { return v_.key(seed); }
    void set_pins(const std::vector<std::pair<std::uint64_t, Hash32>>& pins) override { v_.set_pins(pins); }

private:
    V& v_;
};

class RxKeyer {
public:
    using Adopted = std::function<void(const Hash32& seed)>;
    using Failed = std::function<void(const Hash32& seed)>;
    struct Stats {
        std::uint64_t requests = 0;
        std::uint64_t built = 0;
        std::uint64_t failed = 0;
    };
    RxKeyer(INodeRxEngine& e, bool manual) : e_(e), manual_(manual) {}
    ~RxKeyer() { stop(); }
    RxKeyer(const RxKeyer&) = delete;
    RxKeyer& operator=(const RxKeyer&) = delete;

    void set_on_adopted(Adopted cb) {
        std::lock_guard<std::mutex> lk(mu_);
        cb_ = std::move(cb);
    }
    void set_on_failed(Failed cb) {
        std::lock_guard<std::mutex> lk(mu_);
        fail_cb_ = std::move(cb);
    }
    void start() {
        if (manual_) return;
        std::lock_guard<std::mutex> lk(mu_);
        if (th_.joinable() || stop_) return;
        th_ = std::thread([this] { run_(); });
    }
    void stop() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        idle_cv_.notify_all();
        if (th_.joinable()) th_.join();
    }
    // One request in flight per seed; true: queued now.
    bool request(const Hash32& seed) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (stop_ || !pending_.insert(seed).second) return false;
            q_.push_back(seed);
            ++st_.requests;
        }
        cv_.notify_one();
        return true;
    }
    // Manual mode: the queued seeds built now, on the caller's thread; the number built.
    std::size_t pump() {
        std::size_t n = 0;
        for (;;) {
            Hash32 s;
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (q_.empty()) return n;
                s = q_.front();
                q_.pop_front();
                busy_ = true;
            }
            if (build_(s)) ++n;
        }
    }
    // Until the queue is empty and no build runs (manual mode: pump()); the builds that failed meanwhile.
    std::uint64_t wait_idle() {
        std::uint64_t f0 = 0;
        {
            std::lock_guard<std::mutex> lk(mu_);
            f0 = st_.failed;
        }
        if (manual_) {
            (void)pump();
        } else {
            std::unique_lock<std::mutex> lk(mu_);
            idle_cv_.wait(lk, [this] { return (q_.empty() && !busy_) || stop_; });
        }
        std::lock_guard<std::mutex> lk(mu_);
        return st_.failed - f0;
    }
    bool pending(const Hash32& seed) const {
        std::lock_guard<std::mutex> lk(mu_);
        return pending_.count(seed) != 0;
    }
    std::size_t queued() const {
        std::lock_guard<std::mutex> lk(mu_);
        return q_.size();
    }
    Stats stats() const {
        std::lock_guard<std::mutex> lk(mu_);
        return st_;
    }

private:
    void run_() {
        std::unique_lock<std::mutex> lk(mu_);
        for (;;) {
            cv_.wait(lk, [this] { return stop_ || !q_.empty(); });
            if (stop_) return;
            const Hash32 s = q_.front();
            q_.pop_front();
            busy_ = true;
            lk.unlock();
            (void)build_(s);
            lk.lock();
        }
    }
    bool build_(const Hash32& s) {
        const bool ok = e_.key(s);
        Adopted cb;
        Failed fcb;
        {
            std::lock_guard<std::mutex> lk(mu_);
            pending_.erase(s);
            if (ok) ++st_.built;
            else ++st_.failed;
            cb = cb_;
            fcb = fail_cb_;
        }
        if (ok && cb) cb(s);
        if (!ok && fcb) fcb(s);
        {
            std::lock_guard<std::mutex> lk(mu_);
            busy_ = false;  // after the callbacks: idle means their work is posted
        }
        idle_cv_.notify_all();
        return ok;
    }

    INodeRxEngine& e_;
    const bool manual_;
    mutable std::mutex mu_;
    std::condition_variable cv_, idle_cv_;
    std::deque<Hash32> q_;
    std::set<Hash32> pending_;
    bool busy_ = false;
    bool stop_ = false;
    Adopted cb_;
    Failed fail_cb_;
    Stats st_;
    std::thread th_;
};

inline std::string rx_hex16(const Hash32& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < 8; ++i) {
        s.push_back(d[h[i] >> 4]);
        s.push_back(d[h[i] & 15]);
    }
    return s;
}

// RandomX on the node's engine: true with the hash, or false with the reason it computed none. A seed not keyed
// posts its keying request and leaves as RandomxNotKeyed (node-internal).
inline bool node_hash(INodeRxEngine& e, RxKeyer* k, const std::vector<std::uint8_t>& bytes, const Hash32& seed,
                      Hash32& pow, std::string& why) {
    switch (e.hash(bytes, seed, pow)) {
        case RxHash::Hashed: return true;
        case RxHash::NotReady: why = "the node verifier is not ready (" + e.mode_name() + ")"; return false;
        case RxHash::NotKeyed:
            if (k != nullptr) (void)k->request(seed);
            throw RandomxNotKeyed("RandomX computed no hash: the seed " + rx_hex16(seed) + " is not keyed", seed);
        case RxHash::Fault: break;
    }
    why = "the VM gave no hash with the seed " + rx_hex16(seed);
    return false;
}

inline std::vector<std::pair<std::uint64_t, Hash32>> main_seed_pins(const ISeedRows& r, std::uint64_t open_heights) {
    std::vector<std::pair<std::uint64_t, Hash32>> out;
    const std::uint64_t t = r.tip_height();
    if (!r.main_id_at(t)) return out;
    const std::uint64_t h1 = t + 1;
    const auto add = [&](std::uint64_t h) {
        const std::uint64_t s = ::xmr::coin::rx_seedheight(h);
        for (const auto& p : out)
            if (p.first == s) return;
        if (const std::optional<Hash32> id = main_seed_at(r, s, h)) out.emplace_back(s, *id);
    };
    add(h1);
    const std::uint64_t oldest = h1 > open_heights ? h1 - open_heights : 0;
    if (::xmr::coin::rx_seedheight(oldest) != ::xmr::coin::rx_seedheight(h1)) add(oldest);
    else if (::xmr::coin::rx_seedheight(h1 + ::xmr::coin::SEEDHASH_EPOCH_LAG) != ::xmr::coin::rx_seedheight(h1))
        add(h1 + ::xmr::coin::SEEDHASH_EPOCH_LAG);
    return out;
}

struct NodeRxWiring {
    INodeRxEngine* engine = nullptr;
    SeedRowsHold rows;
    std::uint64_t open_heights = kRuledLaneParams.open_bins + kRuledLaneParams.fresh_max;
    std::uint64_t walk_bound = kept_rows_cap();
    bool manual = false;  // the keyer pumped by the caller
    // the word on a hash computed (empty: check_hash at d)
    std::function<bool(const Hash32& pow, std::uint64_t d, const HashingBlob& b, const Hash32& seed)> judge;
};

struct NodeRxIo {
    std::function<std::optional<Hash32>(const Hash32& p_r)> seed_of;
    std::function<bool(const HashingBlob&, std::uint64_t d, const Hash32& seed)> verify;
    std::function<bool(const std::vector<std::uint8_t>& blob, const Hash32& seed, Hash32& pow)> ctx_hash;
    // the pins for the index tip (off the node lock): set on the engine, the ones not keyed requested
    std::function<std::vector<std::pair<std::uint64_t, Hash32>>()> repin;
    // a row event of the index (under the node lock)
    std::function<void()> on_rows_event;
    std::shared_ptr<RxKeyer> keyer;
    std::shared_ptr<SeedMemo> memo;
    INodeRxEngine* engine = nullptr;
};

inline NodeRxIo make_node_rx_io(NodeRxWiring w) {
    NodeRxIo o;
    INodeRxEngine* const e = w.engine;
    o.keyer = std::make_shared<RxKeyer>(*e, w.manual);
    o.memo = std::make_shared<SeedMemo>(w.walk_bound);
    RxKeyer* const k = o.keyer.get();
    SeedMemo* const m = o.memo.get();
    o.engine = e;
    const SeedRowsHold rows = w.rows;
    o.seed_of = [rows, m](const Hash32& p_r) {
        std::optional<Hash32> out;
        rows([&](const ISeedRows& r) { out = m->seed_of(r, p_r); });
        return out;
    };
    const auto hash = [e, k](const std::vector<std::uint8_t>& bytes, const Hash32& seed, Hash32& pow, std::string& why) {
        return node_hash(*e, k, bytes, seed, pow, why);
    };
    if (w.judge) {
        o.verify = [hash, judge = w.judge](const HashingBlob& b, std::uint64_t d, const Hash32& seed) {
            std::vector<std::uint8_t> bytes;
            encode_hashing_blob(b, bytes);
            Hash32 pow{};
            rx_hash_or_fail(hash, bytes, seed, pow);
            return judge(pow, d, b, seed);
        };
    } else {
        o.verify = [hash](const HashingBlob& b, std::uint64_t d, const Hash32& seed) {
            return verify_rx_at_d(hash, b, d, seed);
        };
    }
    o.ctx_hash = [hash](const std::vector<std::uint8_t>& blob, const Hash32& seed, Hash32& pow) {
        rx_hash_or_fail(hash, blob, seed, pow);
        return true;
    };
    o.repin = [rows, e, k, open = w.open_heights]() {
        std::vector<std::pair<std::uint64_t, Hash32>> pins;
        rows([&](const ISeedRows& r) { pins = main_seed_pins(r, open); });
        e->set_pins(pins);
        for (const auto& p : pins)
            if (!e->resident(p.second)) (void)k->request(p.second);
        return pins;
    };
    o.on_rows_event = [rows, m]() { rows([&](const ISeedRows& r) { m->on_rows_event(r); }); };
    return o;
}

// The rows of a ChainIndex and the follower's kept rows.
class IndexSeedRows final : public ISeedRows {
public:
    IndexSeedRows(const ::c2pool::xmr::native::ChainIndex::HeldRowsReader& r, const PathbFollowerRows& fr)
        : r_(r), fr_(fr) {}
    std::optional<SeedRow> held(const Hash32& id) const override {
        const auto h = r_.held_row(id);
        if (!h) return std::nullopt;
        return SeedRow{h->id, h->prev_id, h->height, h->main};
    }
    std::optional<SeedRow> kept(const Hash32& id, std::uint64_t tip_h) const override {
        const std::optional<BranchBlock> b = fr_.kept_row(id, tip_h);
        if (!b) return std::nullopt;
        return SeedRow{b->id, b->prev_id, b->height, false};
    }
    std::optional<Hash32> main_id_at(std::uint64_t h) const override { return r_.main_row_at(h); }
    std::optional<Hash32> seed_id_for(std::uint64_t h_child) const override { return r_.seed_hash_for_height(h_child); }
    std::uint64_t tip_height() const override { return r_.tip_height(); }

private:
    const ::c2pool::xmr::native::ChainIndex::HeldRowsReader& r_;
    const PathbFollowerRows& fr_;
};

inline SeedRowsHold index_seed_rows(const ::c2pool::xmr::native::ChainIndex& ix, const PathbFollowerRows& fr) {
    return [&ix, &fr](const std::function<void(const ISeedRows&)>& fn) {
        ix.with_held_rows([&](const ::c2pool::xmr::native::ChainIndex::HeldRowsReader& r) {
            const IndexSeedRows a(r, fr);
            fn(a);
        });
    };
}

}  // namespace c2pool::xmr::pathb
