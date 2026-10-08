// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/template/xmr_monerod_miner_data.hpp
//
// C4, the daemon half: MonerodMinerDataSource -- the EXISTING option-B path,
// wrapped in the IMinerDataSource seam and not otherwise changed.
//
// This arm is never removed. It is the M0..M4 default, it is what the parity
// oracle judges the native arm against, and it is what the resolver falls back
// to when the native arm loses readiness. Its body is the same three lines the
// provider's refresh() ran before this component existed:
//
//     rpc_post(body_get_miner_data)  ->  parse_miner_data  ->  node::MinerData
//
// including the hex-string difficulty the daemon actually returns
// ("difficulty":"0x39d402"), which is decoded by the production parser rather
// than by a second copy of it here. That is deliberate: the whole value of the
// K-C4-1 KAT is that this arm IS the old path, so a template built through the
// seam is byte-identical to one built before it.
//
// WHY poll() IS NOT ON THE INTERFACE. IMinerDataSource::epoch() is pinned as a
// lock-free read the provider may call on every refresh; a network round trip
// cannot live behind it. So the RPC lives in poll(), a non-virtual method the
// provider drives through a pump function it is given at construction. The
// native arm needs no pump, which is exactly the difference the seam exists to
// hide from the assembler.
//
// THE REBUILD RULE (good-citizen, 2026-09-22). epoch() reports (height,
// prev_id, backlog_seq). The tip term is the pre-seam rule, character for
// character: a tip move is always a rebuild. The backlog term is the SAME
// rate-limited policy the native arm runs (xmr_native_miner_data.hpp): when the
// set of transactions monerod OFFERS in get_miner_data.tx_backlog differs from
// the set the served template was built from, and at least
// `backlog_refresh_s` have elapsed since the last admission, the sequence
// advances and the provider rebuilds. The admitted set is FROZEN in between,
// so miners grind byte-stable bytes for the whole window and a rebuild is a
// NEW JOB (new template id), never the same job restamped.
//
// WHY this arm no longer freezes backlog_seq at 0. It used to (R-C4-3), on the
// argument that a size-derived sequence would restamp headers at the poll
// cadence. The frozen rule had a consequence the argument did not weigh: the
// template is built at the instant the parent tip moves, which is the instant
// the pool is emptiest (the block that just landed swept it), and it is then
// served UNCHANGED for the whole block interval while transactions arrive. On
// the 3-node regtest soak of 2026-09-21 that produced five coinbase-only blocks
// (h=122,132,137,139,145) mined off a template with n_tx=0 while the winner's
// own daemon offered 3-5 transactions for the preceding 20-75 s -- a breach of
// the operator hard rule that a c2pool block ALWAYS carries the available
// transactions (coinbase-only ONLY when the pool is truly empty). The cure is
// the native arm's bargain, not the size rule: change-triggered, rate-limited,
// frozen between admissions. `backlog_refresh_s = 0` keeps the legacy tip-only
// behaviour exactly (a CONTROL setting; the K-C4-1 identity KAT pins it).
//
// WHAT the sequence keys on. An order-independent fingerprint of the offered
// tx ids (monerod hands the backlog fee-sorted; the same set in another order
// is not a new job). Not the size: a set that changed at constant size (one tx
// mined, one arrived) IS a new job. A fingerprint collision costs at most one
// missed admission until the set moves again; it can never cause a restamp.
//
// READINESS. The daemon is the authority on its own readiness: a get_miner_data
// that parsed and validated sets every flag, and a transport error or a refusal
// clears them all with the daemon's own words in `why`. There is deliberately
// no attempt to attribute a daemon failure to one of the six windows -- we do
// not know which one it was, and inventing an attribution would put a wrong
// reason in a log line that an operator will act on.
//
// ...AND READINESS EXPIRES. The paragraph above was, on its own, not enough. It
// describes how `have_` is SET; nothing described how it stops being true. A
// successful poll at 09:00 left have_ == true for the life of the process, and
// poll() deliberately does not clear the cache on failure (so a transport blip
// does not cost a template) -- so a daemon that died at 09:01 left this arm
// reporting all six readiness flags, at 17:00, off a miner_data eight hours
// stale. The resolver gates fallback on readiness().ok(), so "the daemon arm is
// available" would have been true of a daemon that no longer existed, and the
// pool would have fallen back onto a dead tip.
//
// So the cache carries the time it was filled, and readiness() and snapshot()
// both refuse past `max_age_ms`. The default is one Monero target block
// interval (120 s): a miner_data older than the block it was meant to build on
// is not stale-but-usable, it is wrong. Zero disables the bound, which is for a
// test that wants the old behaviour and not for production. `epoch()` is left
// alone on purpose -- it is the provider's rebuild trigger, not a readiness
// claim, and making it lurch when the clock crosses the bound would restamp
// headers under miners for a reason that has nothing to do with the tip.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// ---------------------------------------------------------------------------
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/native/contracts/miner_data.hpp"
#include "impl/xmr/node/monero_rpc.hpp"          // body_get_miner_data / parse_miner_data
#include "impl/xmr/node/monerod_transport.hpp"   // IMonerodTransport / RpcResponse
#include "impl/xmr/coin/xmr_seedheight.hpp"      // rx_seedheights (next_seed_hash)

namespace c2pool::xmr::native::tmpl {

// How long a filled cache stays a readiness claim, and how often the offered
// backlog may move the epoch under an unchanged tip. See the header comment.
struct MonerodArmConfig {
    std::uint64_t max_age_ms = 120000;   // one Monero target block interval; 0 = no bound
    // Good-citizen backlog admission: rebuild when the OFFERED tx set moved, at
    // most once per this many seconds. Same default and semantics as the native
    // arm's NativeTemplatePolicy::backlog_refresh_s. 0 = legacy tip-only rebuild
    // (CONTROL / the K-C4-1 byte-identity pin).
    std::uint64_t backlog_refresh_s = 3;
};

class MonerodMinerDataSource final : public IMinerDataSource {
public:
    // Monotonic milliseconds. Injectable so a test can age the cache without
    // sleeping; the default is steady_clock, which no NTP step can rewind.
    using ClockFn = std::function<std::uint64_t()>;

    explicit MonerodMinerDataSource(node::IMonerodTransport& transport,
                                    MonerodArmConfig cfg = {},
                                    ClockFn clock = {})
        : tx_(transport), cfg_(cfg), clock_(std::move(clock)) {}

    MonerodMinerDataSource(const MonerodMinerDataSource&)            = delete;
    MonerodMinerDataSource& operator=(const MonerodMinerDataSource&) = delete;

    const char* name() const override { return "monerod"; }

    // MAIN THREAD. One get_miner_data round trip; updates the cache on success
    // and leaves the previous cache untouched on failure (the provider decides
    // whether a stale-but-valid template may still be served, and it can only
    // decide that if the last good snapshot survives a transport blip).
    bool poll(std::string* why = nullptr) {
        node::MinerData md;
        std::string     err;
        bool            got = false;

        tx_.rpc_post(node::MoneroDaemonRpc::body_get_miner_data(),
                     [&](const node::RpcResponse& r) {
                         if (!r.ok()) { err = "transport: " + r.error; return; }
                         if (auto p = node::MoneroDaemonRpc::parse_miner_data(r.body)) {
                             md = *p; got = true;
                         } else {
                             err = "get_miner_data: parse/validate failed";
                         }
                     });

        if (!got) {
            set_error_(err.empty() ? "get_miner_data: no response" : err, why);
            return false;
        }
        if (!md.valid()) {
            set_error_("get_miner_data: invalid miner_data", why);
            return false;
        }

        announce_next_seed_(md);

        const std::uint64_t fp  = backlog_fingerprint_(md);
        const std::uint64_t now = now_ms_();

        std::lock_guard<std::mutex> lk(mtx_);
        // GOOD-CITIZEN backlog admission (see the header). A tip move re-opens
        // the backlog unconditionally -- the next template is a new job anyway,
        // so the set it is built from is simply the set on offer now. Under an
        // unchanged tip the offered set is admitted only when it differs from
        // the set the served template was built from AND the refresh window has
        // elapsed; between admissions the sequence (and so the epoch) is frozen.
        const bool tip_moved = !have_ || md.height != cached_.height
                            || !(md.prev_id == cached_.prev_id);
        if (tip_moved) {
            admitted_fp_    = fp;
            last_admit_ms_  = now;
        } else if (cfg_.backlog_refresh_s != 0 && fp != admitted_fp_
                   && (last_admit_ms_ == 0 || now - last_admit_ms_ >= cfg_.backlog_refresh_s * 1000)) {
            admitted_fp_    = fp;
            last_admit_ms_  = now;
            ++backlog_seq_;
            ++backlog_admits_;
        }
        last_backlog_n_ = md.tx_backlog.size();

        cached_    = std::move(md);
        have_      = true;
        filled_ms_ = now;
        last_error_.clear();
        ++polls_;
        if (why) why->clear();
        return true;
    }

    // get_block_header_by_height round trips made for next_seed_hash (status/KATs).
    std::uint64_t next_seed_fetches() const noexcept { return next_fetches_; }

    MinerDataReadiness readiness() const override {
        MinerDataReadiness r;
        std::lock_guard<std::mutex> lk(mtx_);
        if (!have_) {
            r.why = last_error_.empty() ? "monerod: no miner data yet" : last_error_;
            return r;
        }
        if (stale_locked_()) {
            r.why = stale_why_locked_();
            return r;
        }
        // The daemon answered and the parser validated: every window it owns is
        // by construction the one it used. All six flags together, or none.
        r.tip_known = r.seed_reach = r.difficulty_window =
        r.weight_window = r.coins_known = r.hf_known = true;
        return r;
    }

    MinerDataEpoch epoch() const override {
        MinerDataEpoch e;
        std::lock_guard<std::mutex> lk(mtx_);
        if (!have_) return e;
        e.height  = cached_.height;
        e.prev_id = cached_.prev_id;
        // The ADMITTED backlog sequence: advanced in poll() only when the
        // offered tx set moved under an unchanged tip and the refresh window
        // allowed it (see the header). Frozen at 0 for the life of the process
        // when backlog_refresh_s == 0 (legacy tip-only rebuild). It is never
        // the backlog SIZE: a size-derived sequence would reassemble at the poll
        // cadence and restamp the header under miners mid-grind ("Low diff").
        e.backlog_seq = backlog_seq_;
        return e;
    }

    std::optional<node::MinerData> snapshot(std::string* why) const override {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!have_) {
            if (why) *why = last_error_.empty() ? "monerod: no miner data yet" : last_error_;
            return std::nullopt;
        }
        // Belt to readiness()'s braces. The resolver checks readiness before it
        // picks an arm, but a consumer that reaches snapshot() by another road
        // must not be handed an expired cache just because it did not ask.
        if (stale_locked_()) {
            if (why) *why = stale_why_locked_();
            return std::nullopt;
        }
        if (why) why->clear();
        return cached_;
    }

    // Age of the cache in milliseconds, or 0 if it was never filled. For the
    // status line: an operator watching the daemon arm should be able to see it
    // ageing BEFORE it expires, not only after.
    std::uint64_t age_ms() const {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!have_) return 0;
        const std::uint64_t t = now_ms_();
        return t > filled_ms_ ? (t - filled_ms_) : 0;
    }
    bool stale() const { std::lock_guard<std::mutex> lk(mtx_); return stale_locked_(); }
    const MonerodArmConfig& config() const noexcept { return cfg_; }

    // The daemon relays a found block from its OWN pool, so this arm holds no
    // bodies. C5's ARM A (levin fluffy push) is only reachable with a body
    // source; with this arm alone it is ARM B that delivers, by design.
    const std::vector<std::uint8_t>* tx_body(const Hash&) const override { return nullptr; }

    std::string   last_error() const { std::lock_guard<std::mutex> lk(mtx_); return last_error_; }
    std::uint64_t polls()      const { std::lock_guard<std::mutex> lk(mtx_); return polls_; }
    std::uint64_t failures()   const { std::lock_guard<std::mutex> lk(mtx_); return failures_; }

    // Good-citizen observability for the status line: how many times the
    // offered backlog moved the epoch under an unchanged tip, and how many
    // transactions the daemon offered on the last poll.
    std::uint64_t backlog_admits() const { std::lock_guard<std::mutex> lk(mtx_); return backlog_admits_; }
    std::size_t   last_backlog_n() const { std::lock_guard<std::mutex> lk(mtx_); return last_backlog_n_; }

private:
    // Order-independent fingerprint of the offered tx-id set (FNV-1a per id,
    // summed). See "WHAT the sequence keys on" in the header.
    static std::uint64_t backlog_fingerprint_(const node::MinerData& md) {
        std::uint64_t fp = 0x9e3779b97f4a7c15ull ^ static_cast<std::uint64_t>(md.tx_backlog.size());
        for (const auto& e : md.tx_backlog) {
            std::uint64_t h = 0xcbf29ce484222325ull;
            for (const auto c : e.id) {
                h ^= static_cast<unsigned char>(c);
                h *= 0x100000001b3ull;
            }
            fp += h;
        }
        return fp;
    }

    std::uint64_t now_ms_() const {
        if (clock_) return clock_();
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    bool stale_locked_() const {
        if (!have_ || cfg_.max_age_ms == 0) return false;
        const std::uint64_t t = now_ms_();
        return t > filled_ms_ && (t - filled_ms_) > cfg_.max_age_ms;
    }

    std::string stale_why_locked_() const {
        const std::uint64_t t = now_ms_();
        const std::uint64_t age = t > filled_ms_ ? (t - filled_ms_) : 0;
        std::string w = "monerod: miner data is " + std::to_string(age / 1000)
                      + "s old (limit " + std::to_string(cfg_.max_age_ms / 1000)
                      + "s): the daemon has not answered since it was cached";
        if (!last_error_.empty()) w += "; last error: " + last_error_;
        return w;
    }

    // NEXT-SEED ANNOUNCE (operator ruling 09-26). get_miner_data carries no
    // next_seed_hash; monerod's get_block_template publishes it as
    //   rx_seedheights(height, &seed, &next); next != seed -> id(next).
    // Inside that 64-block lag window the next seed block is already in the
    // chain, so ONE get_block_header_by_height resolves it, re-asked only when
    // the tip moves (a reorg across the seed block is followed; 0 extra RPCs
    // outside the window). A failed lookup announces nothing; poll() succeeds.
    void announce_next_seed_(node::MinerData& md) {
        std::uint64_t seed_h = 0, next_h = 0;
        ::xmr::coin::rx_seedheights(md.height, seed_h, next_h);
        if (next_h == seed_h) return;
        if (!(next_ok_ && next_h_ == next_h && next_tip_ == md.prev_id)) {
            next_ok_ = false;
            ++next_fetches_;
            tx_.rpc_post(node::MoneroDaemonRpc::body_get_block_header_by_height(next_h),
                         [&](const node::RpcResponse& r) {
                             if (!r.ok()) return;
                             const auto b = node::MoneroDaemonRpc::parse_block_header(r.body);
                             if (b && b->height == next_h && !node::is_zero(b->id)) {
                                 next_id_ = b->id; next_ok_ = true;
                             }
                         });
            next_h_ = next_h; next_tip_ = md.prev_id;
        }
        if (next_ok_ && !(next_id_ == md.seed_hash)) md.next_seed_hash = next_id_;
    }

    void set_error_(std::string e, std::string* why) {
        std::lock_guard<std::mutex> lk(mtx_);
        last_error_ = std::move(e);
        ++failures_;
        if (why) *why = last_error_;
    }

    node::IMonerodTransport& tx_;
    // next_seed_hash lookup cache (poll() / main thread only)
    node::Hash    next_id_{};
    node::Hash    next_tip_{};
    std::uint64_t next_h_ = 0;
    bool          next_ok_ = false;
    std::uint64_t next_fetches_ = 0;
    MonerodArmConfig         cfg_{};
    ClockFn                  clock_;

    mutable std::mutex mtx_;
    node::MinerData    cached_{};
    bool               have_ = false;
    std::uint64_t      filled_ms_ = 0;
    std::string        last_error_;
    std::uint64_t      polls_ = 0, failures_ = 0;

    // Good-citizen backlog admission state (guarded by mtx_).
    std::uint64_t      backlog_seq_     = 0;   // what epoch() reports
    std::uint64_t      admitted_fp_     = 0;   // fingerprint of the set the served template was built from
    std::uint64_t      last_admit_ms_   = 0;   // clock at the last admission / tip re-open
    std::uint64_t      backlog_admits_  = 0;   // admissions under an unchanged tip (observability)
    std::size_t        last_backlog_n_  = 0;   // offered backlog size on the last poll
};

} // namespace c2pool::xmr::native::tmpl
