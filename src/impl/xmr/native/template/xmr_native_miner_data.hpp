// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/template/xmr_native_miner_data.hpp
//
// C4, the native half: NativeMinerDataSource -- an IMinerDataSource built from
// the C2c chain index (IChainView) and the C3 relayed txpool (ITxpoolSnapshot,
// ITxBlobSource). It answers the exact question the option-B assembler asks
// monerod today, with NO monerod call anywhere on the path.
//
// WHAT THIS IS NOT. It computes nothing about the chain. Every one of the seven
// get_miner_data fields is read straight out of TemplateInputs, which C2a/C2c
// already derive and which the C2a KAT already pins against monerod over 600
// real heights. Re-deriving any of them here would be a second implementation
// of a consensus rule -- exactly the split-risk the W0 contracts exist to
// prevent. What C4 adds is the SEAM, the READINESS gate, the epoch/rebuild
// rule, and three policy guards that only make sense at the template layer:
//
//   * the difficulty sanity band. The retarget function cannot legitimately
//     move the next difficulty outside [tip/4, tip*4]; a value that does means
//     our own window is corrupt, and a template built on it would ask miners
//     to grind against the wrong target. Refuse, do not serve.
//   * the stale-tip flag. No new tip for stale_tip_s (default 30 min; under a
//     2-minute target that is an e^-15 event) is NOT a refusal -- the tip we
//     have is still the best chain we know -- but it is the signal the arm
//     resolver uses to fall back to an armed daemon.
//   * the peer floor. Fewer than min_peers handshaked peers means our view of
//     the network is thin. Also a flag, never a refusal: on regtest the floor
//     is legitimately zero, and a source that refused there would be untestable.
//
// FAIL-CLOSED. snapshot() returns nullopt whenever readiness() is not ok(). The
// PROVIDER keeps serving its last good template while its prev_id is still the
// tip -- that rule lives there, because the retained-template ring lives there;
// this class never hands out a stale MinerData.
//
// EPOCH AND REBUILD (the byte-stability rule). The assembler stamps a fresh
// header timestamp on every build, so rebuilding under an unchanged tip changes
// the bytes a miner is already grinding and its shares start missing on re-hash
// ("Low diff"). epoch() therefore moves on a tip change always, and on a
// backlog change only when the refresh policy allows it:
//
//   backlog_refresh_s == 0  (default)  tip-only. backlog_seq is FROZEN at the
//                                      value it had when the last snapshot was
//                                      taken, so txs arriving under a stable
//                                      tip cannot move the epoch. Jobs are
//                                      byte-stable for the whole block.
//   backlog_refresh_s  > 0             the pool's backlog_version() is admitted
//                                      at most once per interval, and only when
//                                      it actually changed. The rebuild gets a
//                                      new template id, which is a NEW JOB --
//                                      acceptable precisely because it is not
//                                      the same job with different bytes.
//
// BODIES. C5 needs the body of every transaction a template that can still win
// selected. snapshot() therefore pins the selected ids in the pool under a key
// derived from the epoch and keeps the last RETAINED_EPOCHS pin generations
// alive, unpinning the oldest as it falls out. tx_body() answers from the
// bodies fetched at snapshot time; the pointer stays valid until that epoch's
// generation is evicted, which is the contract's "until the next snapshot()"
// promise widened to match the provider's retained ring rather than narrowed
// below it.
//
// Two rules the body path lives or dies by, both of them regression-pinned:
//
//   * tx_body(id) returns the body OF THAT ID or nothing. ITxBlobSource
//     compacts its `out` vector and reports absent ids in `missing`, so the
//     fill walks the ids and consumes `out` in order, skipping exactly what
//     was missing. Index-zipping out[i] with ids[i] would silently file every
//     later body under the wrong id the moment one transaction was mined or
//     expired between selectable_backlog() and get_blobs() -- and C5 would
//     then relay a block carrying bytes that do not hash to the id beside
//     them.
//   * a re-snapshot under an UNCHANGED tip keeps its pin. The generation it
//     replaces is retired BEFORE the new pin is taken, because pinning a key
//     and then unpinning the same key leaves the live template unpinned and
//     the pool free to evict what it selected.
//
// THREADING. snapshot() is the template/serve path (the provider's refresh
// thread). epoch(), readiness() and tx_body() are any-thread reads guarded by
// one mutex; nothing here blocks on the C2 verify thread beyond the IChainView
// call itself.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/native/consensus/xmr_epoch.hpp"
#include "impl/xmr/native/contracts/chain_index.hpp"
#include "impl/xmr/native/contracts/miner_data.hpp"
#include "impl/xmr/native/contracts/txpool.hpp"

namespace c2pool::xmr::native::tmpl {

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------
struct NativeTemplatePolicy {
    // Backlog refresh, in seconds. 0 = tip-only (byte-stable jobs); see the
    // header banner for what a non-zero value costs and buys.
    std::uint64_t backlog_refresh_s = 0;

    // Handshaked-peer floor. 0 disables the check (regtest / a pinned single
    // peer). Never a refusal: it raises thin_peers(), which the arm resolver
    // and the status line read.
    std::uint32_t min_peers = 0;

    // Seconds without a new tip before stale_tip() goes true. Never a refusal.
    std::uint64_t stale_tip_s = 1800;

    // The difficulty sanity band, as a divisor/multiplier pair around the tip's
    // own difficulty. Set band_div == 0 to disable (the KAT does, to prove the
    // guard is what refuses and not something else).
    std::uint64_t band_div = 4;
    std::uint64_t band_mul = 4;

    // Select the backlog under an EXPLICIT policy instead of the pool's
    // configured one. This is what lets a shadow arm select under the SERVED
    // arm's rule, which is the only way a template diff means anything.
    bool               use_explicit_select = false;
    TxpoolSelectPolicy select{};
};

// Why a snapshot was refused, in the order the checks run.
enum class NativeRefusal : std::uint8_t {
    None = 0,
    NoTemplateInputs,   // index not synced, or the hard-fork fence is closed
    NoTip,
    NoSeed,
    NoDifficulty,
    DifficultyBand,
    NoWeightWindow,
    NoCoins,
    NoHardFork,
};

inline const char* to_string(NativeRefusal r) noexcept {
    switch (r) {
        case NativeRefusal::None:             return "ok";
        case NativeRefusal::NoTemplateInputs: return "NoTemplateInputs";
        case NativeRefusal::NoTip:            return "NoTip";
        case NativeRefusal::NoSeed:           return "NoSeed";
        case NativeRefusal::NoDifficulty:     return "NoDifficulty";
        case NativeRefusal::DifficultyBand:   return "DifficultyBand";
        case NativeRefusal::NoWeightWindow:   return "NoWeightWindow";
        case NativeRefusal::NoCoins:          return "NoCoins";
        case NativeRefusal::NoHardFork:       return "NoHardFork";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// NativeMinerDataSource
// ---------------------------------------------------------------------------
class NativeMinerDataSource final : public IMinerDataSource {
public:
    // How many pin generations stay alive. Matches the provider's retained
    // template ring (RING = 6) so a body is resolvable for as long as the
    // template that selected it can still be named by an in-flight share.
    static constexpr std::size_t RETAINED_EPOCHS = 6;

    NativeMinerDataSource(const IChainView&       view,
                          const ITxpoolSnapshot&  pool,
                          NativeTemplatePolicy    policy = {},
                          ITxBlobSource*          bodies = nullptr)
        : view_(view), pool_(pool), policy_(policy), bodies_(bodies) {}

    NativeMinerDataSource(const NativeMinerDataSource&)            = delete;
    NativeMinerDataSource& operator=(const NativeMinerDataSource&) = delete;

    ~NativeMinerDataSource() override {
        if (!bodies_) return;
        for (const auto& g : generations_) bodies_->unpin(g.key);
    }

    const char* name() const override { return "native"; }

    // --- readiness -----------------------------------------------------------
    MinerDataReadiness readiness() const override {
        MinerDataReadiness r;
        NativeRefusal      refusal = NativeRefusal::None;
        (void)evaluate_(r, refusal, nullptr);
        return r;
    }

    // --- epoch ---------------------------------------------------------------
    // Cheap: one tip read plus a counter. Never assembles anything.
    MinerDataEpoch epoch() const override {
        MinerDataEpoch e;
        const auto t = view_.tip();
        if (t) {
            e.height  = t->height + 1;
            e.prev_id = t->id;
        }
        std::lock_guard<std::mutex> lk(mtx_);
        e.backlog_seq = admitted_backlog_seq_locked_(e.height, e.prev_id);
        return e;
    }

    // --- snapshot ------------------------------------------------------------
    std::optional<node::MinerData> snapshot(std::string* why) const override {
        MinerDataReadiness r;
        NativeRefusal      refusal = NativeRefusal::None;
        std::optional<TemplateInputs> ti = evaluate_(r, refusal, why);
        if (!ti || !r.ok()) {
            std::lock_guard<std::mutex> lk(mtx_);
            ++refusals_;
            last_refusal_ = refusal;
            return std::nullopt;
        }

        node::MinerData md = ti->to_miner_data();
        // to_miner_data() deliberately leaves tx_backlog empty: the chain state
        // and the transaction set come from two different components, and the
        // conversion above stays a pure function of chain state (D-7/D-11).
        md.tx_backlog = policy_.use_explicit_select
                            ? pool_.selectable_backlog(policy_.select)
                            : pool_.selectable_backlog();

        const std::uint64_t pool_seq = pool_.backlog_version();

        std::lock_guard<std::mutex> lk(mtx_);
        // Admit the pool's sequence under the refresh policy, then FREEZE it:
        // everything the provider compares against must be the number that was
        // actually served, not a number that moved after the bytes were built.
        served_epoch_.height      = md.height;
        served_epoch_.prev_id     = md.prev_id;
        served_epoch_.backlog_seq = admit_backlog_locked_(pool_seq, md.height, md.prev_id);
        served_pool_seq_          = pool_seq;
        pin_bodies_locked_(md);
        ++snapshots_;
        last_refusal_ = NativeRefusal::None;
        if (why) why->clear();
        return md;
    }

    // --- bodies --------------------------------------------------------------
    const std::vector<std::uint8_t>* tx_body(const Hash& id) const override {
        std::lock_guard<std::mutex> lk(mtx_);
        // Newest generation first: the same id in two templates resolves to the
        // most recently fetched body, and both are the same bytes anyway.
        for (auto g = generations_.rbegin(); g != generations_.rend(); ++g) {
            const auto it = g->bodies.find(key_(id));
            if (it != g->bodies.end()) return &it->second;
        }
        return nullptr;
    }

    // --- flags the arm resolver and the status line read ---------------------
    // Feed the handshaked peer count in from C1; 0 with min_peers == 0 is a
    // legitimate regtest configuration, not a fault.
    void set_peer_count(std::uint32_t n) {
        std::lock_guard<std::mutex> lk(mtx_);
        peers_ = n;
    }
    // Inject the clock the stale-tip rule is judged against (unix seconds). 0,
    // the default, disables the rule: a replay of recorded history has no
    // meaningful "now" and must not be judged stale.
    void set_now(std::uint64_t unix_seconds) {
        std::lock_guard<std::mutex> lk(mtx_);
        now_ = unix_seconds;
    }

    bool thin_peers() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return policy_.min_peers != 0 && peers_ < policy_.min_peers;
    }
    bool stale_tip() const {
        std::lock_guard<std::mutex> lk(mtx_);
        if (now_ == 0 || policy_.stale_tip_s == 0) return false;
        const auto t = view_.tip();
        if (!t) return true;
        return now_ > t->timestamp && (now_ - t->timestamp) > policy_.stale_tip_s;
    }

    // Bodies the pool could not hand over at snapshot time (an id evicted
    // between selectable_backlog() and get_blobs()), and the count of
    // ITxBlobSource replies that did not satisfy out.size() + missing.size() ==
    // ids.size(). Both are zero on a healthy path; the second is never zero on
    // a source that broke the contract, and a template built then carries NO
    // bodies rather than misfiled ones.
    std::uint64_t missing_bodies()         const { std::lock_guard<std::mutex> lk(mtx_); return missing_bodies_; }
    std::uint64_t body_source_violations() const { std::lock_guard<std::mutex> lk(mtx_); return body_source_violations_; }

    NativeRefusal        last_refusal() const { std::lock_guard<std::mutex> lk(mtx_); return last_refusal_; }
    std::uint64_t        snapshots()    const { std::lock_guard<std::mutex> lk(mtx_); return snapshots_; }
    std::uint64_t        refusals()     const { std::lock_guard<std::mutex> lk(mtx_); return refusals_; }
    NativeTemplatePolicy policy()       const { std::lock_guard<std::mutex> lk(mtx_); return policy_; }

private:
    using Key = std::string;   // 32 raw bytes; std::array has no std::hash

    static Key key_(const Hash& h) {
        return Key(reinterpret_cast<const char*>(h.data()), h.size());
    }

    // One pinned template generation: the ids it selected and their bodies.
    struct Generation {
        Hash                             key{};        // pin key = the epoch's prev_id
        std::vector<Hash>                ids;
        std::map<Key, std::vector<std::uint8_t>> bodies;
    };

    // The single place readiness and snapshot agree on what is missing.
    std::optional<TemplateInputs> evaluate_(MinerDataReadiness& r,
                                            NativeRefusal&      refusal,
                                            std::string*        why) const {
        auto no = [&](NativeRefusal f, const char* msg) -> std::optional<TemplateInputs> {
            refusal = f;
            r.why   = msg;
            if (why) *why = std::string("native: ") + msg;
            return std::nullopt;
        };

        const auto tip = view_.tip();
        r.tip_known = tip.has_value();
        if (!r.tip_known) return no(NativeRefusal::NoTip, "no tip: the chain index has no best block");

        const std::optional<TemplateInputs> ti = view_.template_inputs();
        if (!ti)
            return no(NativeRefusal::NoTemplateInputs,
                      "chain index is not synced, or the hard-fork fence refuses a template here");

        r.hf_known = ti->major_version != 0 && ti->synced;
        if (!r.hf_known) return no(NativeRefusal::NoHardFork, "hard-fork version unresolved");

        r.seed_reach = !node::is_zero(ti->seed_hash);
        if (!r.seed_reach)
            return no(NativeRefusal::NoSeed, "RandomX seed block for this height is not reachable");

        r.difficulty_window = !ti->difficulty.empty();
        if (!r.difficulty_window)
            return no(NativeRefusal::NoDifficulty, "next difficulty is zero: the 735-row window is short");

        // The band. Compared against the TIP's own difficulty, which is the one
        // number in the window that a corrupt window cannot also have faked
        // without failing the chain index's own connect checks.
        if (policy_.band_div != 0 && policy_.band_mul != 0 && !tip->difficulty.empty()) {
            if (!within_band_(ti->difficulty, tip->difficulty, policy_.band_div, policy_.band_mul)) {
                r.difficulty_window = false;
                return no(NativeRefusal::DifficultyBand,
                          "next difficulty is outside the sanity band around the tip's difficulty");
            }
        }

        r.weight_window = ti->median_weight != 0 && ti->block_weight_limit != 0;
        if (!r.weight_window)
            return no(NativeRefusal::NoWeightWindow, "weight windows are not populated");

        r.coins_known = ti->already_generated_coins != 0;
        if (!r.coins_known)
            return no(NativeRefusal::NoCoins, "already_generated_coins is not carried forward");

        refusal = NativeRefusal::None;
        r.why.clear();
        if (why) why->clear();
        return ti;
    }

    // d in [tip/div, tip*mul], all in 128 bits, no division of the 128-bit
    // value by anything but a small constant.
    static bool within_band_(const U128& d, const U128& tip,
                             std::uint64_t div, std::uint64_t mul) {
        const U128 lo = u128_div_small_(tip, div);
        const U128 hi = u128_mul_small_(tip, mul);
        if (u128_less(d, lo)) return false;
        // A multiplication that overflowed 128 bits cannot be exceeded by any
        // representable difficulty, so treat the saturated ceiling as open.
        if (hi.hi == UINT64_MAX && hi.lo == UINT64_MAX) return true;
        return !u128_greater(d, hi);
    }
    static U128 u128_div_small_(const U128& a, std::uint64_t d) {
        if (d <= 1) return a;
        U128 r{};
        // long division, most significant limb first
        const std::uint64_t hi_q = a.hi / d;
        const std::uint64_t hi_r = a.hi % d;
        r.hi = hi_q;
        // (hi_r << 64 | lo) / d, done as two 32-bit halves to stay in 64 bits
        const std::uint64_t top = (hi_r << 32) | (a.lo >> 32);
        const std::uint64_t q1  = top / d;
        const std::uint64_t r1  = top % d;
        const std::uint64_t bot = (r1 << 32) | (a.lo & 0xFFFFFFFFull);
        const std::uint64_t q2  = bot / d;
        r.lo = (q1 << 32) | q2;
        return r;
    }
    static U128 u128_mul_small_(const U128& a, std::uint64_t m) {
        U128 r = a;
        for (std::uint64_t i = 1; i < m; ++i) {
            const U128 next = u128_add(r, a);
            if (u128_less(next, r)) { r.hi = UINT64_MAX; r.lo = UINT64_MAX; return r; }  // saturate
            r = next;
        }
        return r;
    }

    // What epoch() reports without taking a snapshot.
    std::uint64_t admitted_backlog_seq_locked_(std::uint64_t height, const Hash& prev) const {
        // A tip move always re-opens the backlog: the next snapshot is a new
        // template anyway, so there is nothing to keep byte-stable.
        if (height != served_epoch_.height || !(prev == served_epoch_.prev_id))
            return pool_.backlog_version();
        if (policy_.backlog_refresh_s == 0) return served_epoch_.backlog_seq;
        const std::uint64_t seq = pool_.backlog_version();
        if (seq == served_pool_seq_) return served_epoch_.backlog_seq;
        if (now_ != 0 && last_backlog_admit_ != 0 &&
            now_ - last_backlog_admit_ < policy_.backlog_refresh_s)
            return served_epoch_.backlog_seq;
        return seq;
    }

    std::uint64_t admit_backlog_locked_(std::uint64_t pool_seq,
                                        std::uint64_t height, const Hash& prev) const {
        if (height != served_epoch_.height || !(prev == served_epoch_.prev_id)) {
            last_backlog_admit_ = now_;
            return pool_seq;
        }
        if (policy_.backlog_refresh_s == 0) return served_epoch_.backlog_seq;
        if (pool_seq == served_pool_seq_) return served_epoch_.backlog_seq;
        if (now_ != 0 && last_backlog_admit_ != 0 &&
            now_ - last_backlog_admit_ < policy_.backlog_refresh_s)
            return served_epoch_.backlog_seq;
        last_backlog_admit_ = now_;
        return pool_seq;
    }

    // Is `key` still named by a retained generation? Two generations can carry
    // the same pin key -- a reorg that comes back to a tip we already built on
    // -- and unpinning on eviction must not drop a pin a LIVE generation still
    // depends on.
    bool key_still_retained_locked_(const Hash& key) const {
        for (const auto& g : generations_)
            if (g.key == key) return true;
        return false;
    }

    void pin_bodies_locked_(const node::MinerData& md) const {
        Generation g;
        g.key = md.prev_id;
        g.ids.reserve(md.tx_backlog.size());
        for (const auto& t : md.tx_backlog) g.ids.push_back(t.id);

        const bool fetching = (bodies_ != nullptr && !g.ids.empty());

        // ONE generation per epoch: a re-snapshot under an unchanged tip
        // REPLACES the generation rather than growing the ring. Retire the
        // superseded generation FIRST, and never unpin the key we are about to
        // re-pin -- pin(key) followed by unpin(key) leaves the live template
        // with NO pin at all, and the pool is then free to evict bodies a
        // still-winnable template selected. Only when this snapshot will not
        // re-pin (no body source, or an empty selection) does the superseded
        // generation's pin have to be released here.
        if (!generations_.empty() && generations_.back().key == g.key) {
            if (bodies_ && !fetching) bodies_->unpin(generations_.back().key);
            generations_.pop_back();
        }

        if (fetching) {
            std::vector<std::vector<std::uint8_t>> out;
            std::vector<Hash>                      missing;
            bodies_->get_blobs(g.ids, out, missing);

            // ITxBlobSource COMPACTS `out`: a body that is not there is named in
            // `missing` and simply does not appear in `out` (RelayedTxPool and
            // the contract fake both do this). Zipping out[i] with ids[i] would
            // therefore file every later body under a DIFFERENT transaction's
            // id as soon as one id went missing -- and an id CAN go missing,
            // because selectable_backlog() and get_blobs() are two separate lock
            // acquisitions and a transaction can be mined, conflicted or expired
            // in between. tx_body(id) would then hand C5 bytes that do not hash
            // to the id it asked for, i.e. an invalid block. Walk the IDS and
            // consume `out` in order, skipping exactly the ids the source
            // reported missing, so a body is only ever filed under its own id.
            if (out.size() + missing.size() != g.ids.size()) {
                // The source broke the contract. File NOTHING rather than guess
                // an alignment: a wrong body is worse than a missing one.
                ++body_source_violations_;
                missing_bodies_ += g.ids.size();
            } else {
                std::map<Key, std::size_t> missing_left;
                for (const Hash& h : missing) ++missing_left[key_(h)];

                std::size_t next = 0;
                for (const Hash& id : g.ids) {
                    const Key  k = key_(id);
                    const auto m = missing_left.find(k);
                    if (m != missing_left.end() && m->second != 0) { --m->second; continue; }
                    if (next >= out.size()) break;   // cannot happen under the guard above
                    g.bodies.emplace(k, std::move(out[next]));
                    ++next;
                }
                missing_bodies_ += missing.size();
            }

            bodies_->pin(g.key, g.ids);
        }

        generations_.push_back(std::move(g));
        while (generations_.size() > RETAINED_EPOCHS) {
            const Hash evicted = generations_.front().key;
            generations_.pop_front();
            if (bodies_ && !key_still_retained_locked_(evicted)) bodies_->unpin(evicted);
        }
    }

    const IChainView&      view_;
    const ITxpoolSnapshot& pool_;
    NativeTemplatePolicy   policy_;
    ITxBlobSource*         bodies_ = nullptr;

    mutable std::mutex             mtx_;
    mutable MinerDataEpoch         served_epoch_{};
    mutable std::uint64_t          served_pool_seq_     = 0;
    mutable std::uint64_t          last_backlog_admit_  = 0;
    mutable std::deque<Generation> generations_;
    mutable std::uint32_t          peers_ = 0;
    mutable std::uint64_t          now_   = 0;
    mutable std::uint64_t          snapshots_ = 0, refusals_ = 0, missing_bodies_ = 0;
    mutable std::uint64_t          body_source_violations_ = 0;
    mutable NativeRefusal          last_refusal_ = NativeRefusal::None;
};

} // namespace c2pool::xmr::native::tmpl
