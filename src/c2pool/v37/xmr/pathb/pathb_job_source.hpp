// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_job_source.hpp
// The stratum template source of a Path B node (strat::ITemplateSource):
//   set_template  the shared template of the best tip (one template id per
//                 template), with the Monero network difficulty and the RandomX
//                 seeds of its height; clear(): no template
//   bind          the session of one job's extra_nonce (payee and stated vote;
//                 the listener's session binder): taken by the next get_job of
//                 that extra_nonce on every return path
//   bind_own      the CPU miner's own slot: kept for every template
//   get_job       PathbNode::make_job for the extra_nonce's session (through
//                 the caller's make_job function, under the node lock); the
//                 job's hashing blob (nonce 0) and its block blob; an
//                 extra_nonce with no session gets the template's values and
//                 no blob (a peek)
//   rebuild_blob  the issued job's hashing blob
//   network_job   an issued job for a Monero block (the exact gate, the
//                 publish arms' candidate, the found line)
//   issued        an issued job for the node's own share: none once its
//                 template was withdrawn (clear())
//   clear()       the template withdrawn; the issued jobs stay for a Monero
//                 block found on them, withdrawn for own shares
// Issued jobs are kept for the last kKeptTemplates templates (a found block's
// job lives as long): a stratum session's job ring (JOBS_RING) names jobs of at
// most that many templates. The sessions held are the binds whose get_job has
// not run yet (a bind and its get_job run in one make_job) and the own slot.
// MinerSlot: the CPU miner's job per template; a template the miner got no job
// for is counted once and named.
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "c2pool/v37/xmr/pathb/pathb_node.hpp"
#include "c2pool/v37/xmr/xmr_live_submit.hpp"   // BlockCandidate
#include "impl/xmr/stratum/xmr_stratum.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"   // pathb_block_blob

namespace c2pool::xmr::pathb {

// The Monero values of a template's height (from the native source when its
// parent is the template's P_r).
struct JobNetwork {
    bool known = false;                  // false: no network block is attempted
    std::uint64_t difficulty_lo = 0;
    std::uint64_t difficulty_hi = 0;
    Hash32 seed{};
    std::optional<Hash32> next_seed;
};

struct IssuedJob {
    std::uint32_t template_id = 0;
    std::uint32_t extra_nonce = 0;
    PathbJob job;
    std::vector<std::uint8_t> hashing_blob;  // nonce 0
    std::vector<std::uint8_t> block_blob;    // nonce 0
    std::size_t nonce_offset = 0;
    Hash32 tip{};
    Hash32 p_r{};
    Hash32 window_root{};
    std::uint64_t h = 0;
    std::uint64_t d = 0;
    std::uint64_t reward = 0;                // R
    std::size_t n_outputs = 0;
    std::uint8_t hf = 0;
    JobNetwork net;
};

// The lane target of difficulty d (the u64 target of the stratum dialect).
inline std::uint64_t stratum_target_of(std::uint64_t d) noexcept {
    return d ? UINT64_MAX / d : UINT64_MAX;
}

// The hashing blob's nonce offset: varint major, minor, timestamp, prev_id.
inline std::size_t hashing_nonce_offset(const HashingBlob& b) noexcept {
    return varint_len(b.major) + varint_len(b.minor) + varint_len(b.timestamp) + kHashBytes;
}

// The block blob of a job: the Path B miner tx and the template's transactions through the block assembly
// (impl/xmr/template/xmr_block_assembly.hpp).
inline std::vector<std::uint8_t> job_block_blob(const PathbJob& j, const std::vector<std::uint8_t>& hashing_blob,
                                                std::size_t nonce_offset, const std::vector<TemplateTx>& txs) {
    std::vector<Hash32> ids;
    ids.reserve(txs.size());
    for (const TemplateTx& t : txs) ids.push_back(t.hash);
    return ::c2pool::xmr::assembly::pathb_block_blob(hashing_blob, nonce_offset, j.miner_tx.prefix, ids);
}

class PathbJobSource final : public ::v37::xmr::stratum::ITemplateSource {
public:
    static constexpr std::size_t kKeptTemplates = ::v37::xmr::stratum::XmrStratumSession::JOBS_RING;
    using MakeJob = std::function<std::optional<PathbJob>(const PathbTemplate&, const PathbSession&)>;

    explicit PathbJobSource(MakeJob make) : make_(std::move(make)) {}

    // A new template (a new template id); returns the id.
    std::uint32_t set_template(const PathbTemplate& t, const JobNetwork& net) {
        std::lock_guard<std::mutex> lk(mu_);
        ++next_tid_;
        if (next_tid_ == 0) ++next_tid_;
        tpl_ = t;
        net_ = net;
        tid_ = next_tid_;
        kept_.push_back(tid_);
        while (kept_.size() > kKeptTemplates) {
            const std::uint32_t old = kept_.front();
            kept_.pop_front();
            withdrawn_.erase(old);
            jobs_.erase(jobs_.lower_bound({old, 0}), jobs_.upper_bound({old, UINT32_MAX}));
        }
        return tid_;
    }
    // The template withdrawn: no new job; the issued jobs of the kept templates stay for a Monero block found on
    // them (network_job, rebuild_blob, candidate) and are withdrawn for own shares (issued: a share on one is stale).
    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        tpl_.reset();
        withdrawn_.insert(kept_.begin(), kept_.end());
    }
    bool has_template() const {
        std::lock_guard<std::mutex> lk(mu_);
        return tpl_.has_value();
    }
    std::uint32_t template_id() const {
        std::lock_guard<std::mutex> lk(mu_);
        return tpl_ ? tid_ : 0;
    }
    std::optional<PathbTemplate> current() const {
        std::lock_guard<std::mutex> lk(mu_);
        return tpl_;
    }

    // The session of one job's extra_nonce: the next get_job of that extra_nonce takes it.
    void bind(std::uint32_t extra_nonce, const PathbSession& s) {
        std::lock_guard<std::mutex> lk(mu_);
        if (own_ && own_->first == extra_nonce) return;
        sessions_[extra_nonce] = s;
    }
    // The CPU miner's own slot: its session stays for every template.
    void bind_own(std::uint32_t extra_nonce, const PathbSession& s) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(extra_nonce);
        own_ = std::make_pair(extra_nonce, s);
    }
    // The sessions held now (the binds not yet taken by a get_job, and the own slot).
    std::size_t sessions_held() const {
        std::lock_guard<std::mutex> lk(mu_);
        return sessions_.size() + (own_ ? 1 : 0);
    }

    bool get_job(std::uint32_t extra_nonce, ::v37::xmr::stratum::TemplateJob& out) override {
        PathbTemplate t;
        JobNetwork net;
        std::uint32_t tid = 0;
        std::optional<PathbSession> s;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (own_ && own_->first == extra_nonce) {
                s = own_->second;
            } else if (auto node = sessions_.extract(extra_nonce)) {
                s = std::move(node.mapped());
            }
            if (!tpl_) return false;
            t = *tpl_;
            net = net_;
            tid = tid_;
            const auto j = jobs_.find({tid, extra_nonce});
            if (j != jobs_.end()) {
                fill(j->second, out);
                return true;
            }
        }
        if (!s) {
            fill_peek(t, net, tid, out);
            return true;
        }
        PathbSession session = *s;
        for (std::size_t i = 0; i < kExtraNonceBytes; ++i)
            session.extra_nonce[i] = static_cast<std::uint8_t>(extra_nonce >> (8 * i));
        const std::optional<PathbJob> job = make_ ? make_(t, session) : std::nullopt;
        if (!job) {
            std::lock_guard<std::mutex> lk(mu_);
            ++make_failed_;
            return false;
        }
        IssuedJob ij;
        ij.template_id = tid;
        ij.extra_nonce = extra_nonce;
        ij.job = *job;
        encode_hashing_blob(job->body.blob, ij.hashing_blob);
        ij.nonce_offset = hashing_nonce_offset(job->body.blob);
        ij.block_blob = job_block_blob(*job, ij.hashing_blob, ij.nonce_offset, t.txs);
        ij.tip = t.tip;
        ij.p_r = t.p_r;
        ij.window_root = t.window.window_root;
        ij.h = t.h;
        ij.d = t.d;
        ij.reward = t.reward;
        ij.n_outputs = job->miner_tx.outs.size();
        ij.hf = t.hf;
        ij.net = net;
        std::lock_guard<std::mutex> lk(mu_);
        fill(ij, out);
        if (std::find(kept_.begin(), kept_.end(), tid) != kept_.end()) jobs_[{tid, extra_nonce}] = std::move(ij);
        ++issued_;
        return true;
    }

    bool rebuild_blob(std::uint32_t template_id, std::uint32_t extra_nonce,
                      ::v37::xmr::stratum::TemplateJob& out) override {
        std::lock_guard<std::mutex> lk(mu_);
        const auto it = jobs_.find({template_id, extra_nonce});
        if (it == jobs_.end()) return false;
        fill(it->second, out);
        out.withdrawn = withdrawn_.count(template_id) != 0;  // a found block only; an own share on it is stale
        return true;
    }

    std::uint32_t max_extra_nonces() const override { return UINT32_MAX; }

    // An issued job for the node's own share: none once its template was withdrawn.
    std::optional<IssuedJob> issued(std::uint32_t template_id, std::uint32_t extra_nonce) const {
        std::lock_guard<std::mutex> lk(mu_);
        if (withdrawn_.count(template_id) != 0) return std::nullopt;
        const auto it = jobs_.find({template_id, extra_nonce});
        if (it == jobs_.end()) return std::nullopt;
        return it->second;
    }
    // An issued job for a Monero block found on it: while its template is kept, withdrawn or not.
    std::optional<IssuedJob> network_job(std::uint32_t template_id, std::uint32_t extra_nonce) const {
        std::lock_guard<std::mutex> lk(mu_);
        const auto it = jobs_.find({template_id, extra_nonce});
        if (it == jobs_.end()) return std::nullopt;
        return it->second;
    }

    // The publish arms' candidate of an issued job.
    bool candidate(std::uint32_t template_id, std::uint32_t extra_nonce,
                   ::c2pool::v37n::xmr::submit::BlockCandidate& c) const {
        const std::optional<IssuedJob> j = network_job(template_id, extra_nonce);
        if (!j) return false;
        c.template_id = template_id;
        c.height = j->h;
        c.full_blob = j->block_blob;
        c.hashing_blob = j->hashing_blob;
        c.nonce_offset = j->nonce_offset;
        c.reserved_offset = 0;
        c.reserved_size = 0;
        c.prev_id = j->p_r;
        c.expected_reward = j->reward;
        c.major_version = j->hf;
        return true;
    }

    std::uint64_t issued_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return issued_;
    }
    std::uint64_t make_failed() const {
        std::lock_guard<std::mutex> lk(mu_);
        return make_failed_;
    }

private:
    static void fill(const IssuedJob& j, ::v37::xmr::stratum::TemplateJob& out) {
        out.blob = j.hashing_blob;
        out.nonce_offset = j.nonce_offset;
        out.template_id = j.template_id;
        out.height = j.h;
        out.lane_target = stratum_target_of(j.d);
        out.mainchain_target = network_target(j.net);
        out.seed_hash = j.net.seed;
        out.next_seed_hash = j.net.next_seed;
        out.monero_major_version = j.hf;
    }
    static void fill_peek(const PathbTemplate& t, const JobNetwork& net, std::uint32_t tid,
                          ::v37::xmr::stratum::TemplateJob& out) {
        out.blob.clear();
        out.template_id = tid;
        out.height = t.h;
        out.lane_target = stratum_target_of(t.d);
        out.mainchain_target = network_target(net);
        out.seed_hash = net.seed;
        out.next_seed_hash = net.next_seed;
        out.monero_major_version = t.hf;
    }
    // The stratum dialect's u64 network target (0: no network block).
    static std::uint64_t network_target(const JobNetwork& n) noexcept {
        if (!n.known || n.difficulty_hi != 0 || n.difficulty_lo == 0) return 0;
        return UINT64_MAX / n.difficulty_lo;
    }

    MakeJob make_;
    mutable std::mutex mu_;
    std::optional<PathbTemplate> tpl_;
    JobNetwork net_;
    std::uint32_t tid_ = 0;
    std::uint32_t next_tid_ = 0;
    std::deque<std::uint32_t> kept_;
    std::set<std::uint32_t> withdrawn_;  // kept templates withdrawn by clear() (own shares stale)
    std::map<std::pair<std::uint32_t, std::uint32_t>, IssuedJob> jobs_;
    std::map<std::uint32_t, PathbSession> sessions_;
    std::optional<std::pair<std::uint32_t, PathbSession>> own_;  // the CPU miner's slot
    std::uint64_t issued_ = 0;
    std::uint64_t make_failed_ = 0;
};

// The CPU miner's job per template (W-E5b): next() gives the own slot's job of the current template while the miner
// holds no job of it; the caller reports pushed() or refused(); settle() counts a template the miner holds no job
// for once and returns its line (no template: nothing counted).
class MinerSlot {
public:
    explicit MinerSlot(std::uint32_t extra_nonce) : en_(extra_nonce) {}

    std::optional<::v37::xmr::stratum::TemplateJob> next(PathbJobSource& jobs) {
        cur_ = jobs.template_id();
        if (cur_ == 0 || cur_ == job_tid_) return std::nullopt;
        ::v37::xmr::stratum::TemplateJob tj;
        if (!jobs.get_job(en_, tj)) {
            why_ = "no job (make_job failed)";
            return std::nullopt;
        }
        if (tj.blob.empty()) {
            why_ = "no blob (the slot has no session)";
            return std::nullopt;
        }
        return tj;
    }
    void pushed(std::uint32_t template_id) { job_tid_ = template_id; }
    void refused(const std::string& why) { why_ = "refused: " + why; }
    std::optional<std::string> settle() {
        if (cur_ == 0 || cur_ == job_tid_ || cur_ == skipped_tid_) return std::nullopt;
        skipped_tid_ = cur_;
        ++skipped_;
        return "template " + std::to_string(cur_) + " skipped (miner job of template " + std::to_string(job_tid_) +
               "): " + why_;
    }
    std::uint32_t job_template() const noexcept { return job_tid_; }
    std::uint64_t skipped() const noexcept { return skipped_; }
    std::uint32_t extra_nonce() const noexcept { return en_; }

private:
    std::uint32_t en_ = 0;
    std::uint32_t cur_ = 0;
    std::uint32_t job_tid_ = 0;
    std::uint32_t skipped_tid_ = 0;
    std::uint64_t skipped_ = 0;
    std::string why_;
};

}  // namespace c2pool::xmr::pathb
