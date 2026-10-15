// ---------------------------------------------------------------------------
// pathb_own_share.hpp -- the own share path of the pool node (W-E5, W-E5b)
// ---------------------------------------------------------------------------
// A share this node's stratum or its in-process miner found goes to
// PathbNode::on_own_share (the caller runs it under the node lock). A
// RandomX failure there (RandomxFailure: node-internal) keeps the share, its
// job, nonce and pow hash, and runs it again until it is placed or its job is
// stale (no longer issued): a local alarm, no process end, nothing re-hashed
// by the share's own PoW.
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "pathb_node.hpp"

namespace c2pool::xmr::pathb {

struct OwnShare {
    std::uint32_t template_id = 0;
    std::uint32_t extra_nonce = 0;
    PathbJob job;
    std::uint32_t nonce = 0;
    Hash32 pow_hash{};
};

class OwnShareRunner {
public:
    using Run = std::function<NodeEventResult(const OwnShare&)>;  // on_own_share, under the node lock
    using Live = std::function<bool(const OwnShare&)>;            // the share's job still issued
    using Log = std::function<void(const std::string&)>;

    struct Stats {
        std::uint64_t rx_failures = 0;  // RandomX failures of an own share (the first try or a re-run)
        std::uint64_t reruns = 0;       // re-runs of a kept share
        std::uint64_t rerun_done = 0;   // kept shares run to their end (placed, pending or another action)
        std::uint64_t stale = 0;        // kept shares whose job was no longer issued
    };

    OwnShareRunner(Run run, Live live, Log log = {}) : run_(std::move(run)), live_(std::move(live)), log_(std::move(log)) {}

    // Runs one share. nullopt: a RandomX failure, the share kept for run_kept().
    std::optional<NodeEventResult> submit(OwnShare s) {
        try {
            NodeEventResult r = run_(s);
            return r;
        } catch (const RandomxFailure& e) {
            std::lock_guard<std::mutex> lk(m_);
            failed_locked(e.what());
            kept_.push_back(std::move(s));
            return std::nullopt;
        }
    }

    // Runs the kept shares again, oldest first: every share whose job is stale leaves first (the kept list is bounded
    // by the issued jobs' lifetime); a share run to its end leaves; a RandomX failure keeps it (and the ones after it,
    // untried, for the next call).
    std::vector<NodeEventResult> run_kept() {
        std::deque<OwnShare> q;
        {
            std::lock_guard<std::mutex> lk(m_);
            q.swap(kept_);
        }
        for (auto it = q.begin(); it != q.end();) {
            if (live_(*it)) {
                ++it;
                continue;
            }
            it = q.erase(it);
            std::lock_guard<std::mutex> lk(m_);
            ++st_.stale;
        }
        std::vector<NodeEventResult> out;
        while (!q.empty()) {
            OwnShare& s = q.front();
            try {
                {
                    std::lock_guard<std::mutex> lk(m_);
                    ++st_.reruns;
                }
                out.push_back(run_(s));
                q.pop_front();
                std::lock_guard<std::mutex> lk(m_);
                ++st_.rerun_done;
                if (failing_ && kept_.empty() && q.empty()) {
                    failing_ = false;
                    say("own share: RandomX hashes again; the kept shares ran");
                }
            } catch (const RandomxFailure& e) {
                std::lock_guard<std::mutex> lk(m_);
                failed_locked(e.what());
                while (!q.empty()) {  // kept in their order, before any share kept meanwhile
                    kept_.push_front(std::move(q.back()));
                    q.pop_back();
                }
                break;
            }
        }
        return out;
    }

    std::size_t kept() const {
        std::lock_guard<std::mutex> lk(m_);
        return kept_.size();
    }
    Stats stats() const {
        std::lock_guard<std::mutex> lk(m_);
        return st_;
    }

private:
    void failed_locked(const std::string& what) {
        ++st_.rx_failures;
        if (!failing_) {
            failing_ = true;
            say("own share: RandomX failing (" + what + "): the share kept and run again");
        }
    }
    void say(const std::string& l) {
        if (log_) log_(l);
    }

    Run run_;
    Live live_;
    Log log_;
    mutable std::mutex m_;
    std::deque<OwnShare> kept_;
    Stats st_;
    bool failing_ = false;
};

}  // namespace c2pool::xmr::pathb
