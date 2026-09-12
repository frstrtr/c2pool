// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_cut_projector.hpp   (R-A — project the settlement
//                                             view at a PEER'S named prefix)
//
// THE RACE THIS CLOSES. A block winner names its fold on the S-1c wire as
// (P, spine_digest): P is the lane RECORD PREFIX its E_b was folded at and the
// digest is the lane's commitment there. The receiver answers that name out of
// V37Engine's OI-W4-3 ring (settlement_view_by_cut). But the engine's executor
// COALESCES a burst of queued records into ONE publication per lane
// (v37_engine.hpp kCoalesceBurst = 64), so the ring holds a view only at each
// BURST-TERMINAL prefix. A winner whose own burst boundaries fell elsewhere
// names a prefix this node never published, and the receive seam reads that as
// a cut_miss and REFUSES the block — permanently, because no amount of waiting
// conjures a publication that was coalesced away. On the 2-node XMR regtest
// this fired on 92 of 102 status samples (the peer's lane version jumped by
// more than 1) and it is the first of the two races that kept cross-node
// convergence from being SUSTAINED.
//
// WHY THE FIX IS NOT "PUBLISH MORE OFTEN". Publishing per record would put the
// O(N) Merkle recompute of build_snapshot back on the per-record path, which is
// exactly the cost kCoalesceBurst exists to amortise, and it would change the
// engine's publication semantics for every consumer — a foundational change
// that is the operator's call, not a receive-side patch's. Nothing about the
// CONSENSUS fold changes either way: v37_lane_executor.hpp states that snapshot
// CONTENT is a pure function of the committed record prefix, so the view at P
// is well-defined whether or not this node happened to publish it.
//
// SO THE RECEIVER PROJECTS IT. This class keeps, beside the engine and fed from
// the SAME single producer seam (CarrierIngest's RecordSink, under the same
// lock that enqueues into the engine's MPSC FIFO, so the order is identical by
// construction), a SHADOW ::v37::LaneExecutor and the ordered push log. Asked
// for (P, digest) it replays the log into the shadow until the lane's prefix is
// exactly P, publishes THAT prefix, and hands back the SettlementView.
//
// ★ WHY THIS CANNOT CREDIT A WRONG NUMBER — the fail-closed argument, which is
// the whole safety case. A projected view is returned ONLY when the shadow's
// lane digest at P equals the digest the WINNER committed to. The digest is the
// lane's canonical commitment over the record prefix, so:
//   • if the shadow is a faithful replica, its digest at P matches and the fold
//     reads the same payout map the winner folded — the correct credit;
//   • if the shadow has drifted for ANY reason (a missed tee, a reordered
//     record, a different geometry), its digest at P does NOT match and the
//     projection is refused — which lands the caller on exactly the behaviour
//     it has today, a loud refusal, never a silent mis-credit.
// There is no third outcome. That is why this is additive receive-side
// robustness and not a new trust assumption: the projector can only ever turn a
// refusal into a correct credit, never a refusal into a wrong one.
//
// WHAT IT IS NOT. It is not a second consensus fold: the shadow IS
// ::v37::LaneExecutor, the canon executor, applying canon LaneRecords; no
// arithmetic from src/sharechain/v37 is restated here, no digest is defined
// here, and the engine's own publication path is untouched. It is not a cache
// of engine views either — it never consults the ring; the two answers are
// independent and the digest is what reconciles them.
//
// BOUNDS, STATED HONESTLY.
//   • The push log is retained from AddLane and CAPPED (Options::max_log). Past
//     the cap the projector SATURATES: it stops retaining, says so once, and
//     every later projection above the retained prefix refuses — i.e. the node
//     falls back to today's behaviour rather than guessing. Sizing the cap is a
//     memory-vs-window trade the operator can set (--cut-projector-log).
//   • Replaying to a prefix BELOW the shadow's cursor needs a rebuild from the
//     log head (the canon Lane is not copyable and its rewind journal is
//     shallow), so backward asks cost O(prefix). Peer wins name monotonically
//     increasing prefixes in practice, so the common path is a short forward
//     replay; the rebuild counter makes any surprise visible.
//   • A Rewind or RemoveLane on the observed lane DISABLES the projector (it
//     would need the journal to stay faithful). The daemon issues neither on
//     the Monero parent lane; if one ever appears the projector says so and
//     stops serving rather than serving a stale replica.
//
// SCOPE FENCE: consumer tree, header-only, STL only. src/sharechain/v37 is
// read-only here; v37_engine.hpp is included for the SettlementView shape only
// and its publication path is not touched.
// ===========================================================================
#pragma once

#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>

#include <c2pool/v37/v37_engine.hpp>          // SettlementView (the shape we hand back)
#include <sharechain/v37/v37_lane_executor.hpp>  // ::v37::LaneExecutor, LaneRecord

namespace c2pool::v37n::xmr::o2 {

// ── counters (diagnostics only — never consensus) ───────────────────────────
struct XmrCutProjectorStats {
    std::uint64_t teed          = 0;   // push records observed on the tee
    std::uint64_t asked         = 0;   // project() calls
    std::uint64_t served        = 0;   // returned a view whose digest MATCHED
    std::uint64_t cache_hits    = 0;   // same (P,digest) asked again (the retry path)
    std::uint64_t forward       = 0;   // served by replaying FORWARD from the cursor
    std::uint64_t rebuilds      = 0;   // shadow rebuilt from the log head (backward ask)
    std::uint64_t replayed      = 0;   // records pushed into the shadow, total
    std::uint64_t beyond_tip    = 0;   // P is ahead of every record we have seen yet
    std::uint64_t below_floor   = 0;   // P is older than the retained log (saturated)
    std::uint64_t digest_miss   = 0;   // reached P, commitment DIFFERED -> refused
    std::uint64_t not_ready     = 0;   // no AddLane seen / projector disabled
    std::uint64_t over_budget   = 0;   // the replay would exceed max_replay
    std::uint64_t log_size      = 0;   // retained push records
    std::uint64_t cursor        = 0;   // the shadow's current lane prefix
    bool          saturated     = false;
    bool          disabled      = false;
};

class XmrCutProjector {
public:
    struct Options {
        // Retained push records. A LaneRecord carries a whole LaneParams, so the
        // log holds a SLIM per-push row instead (descriptor + weight + flags):
        // ~100 B/row, i.e. ~13 MiB at the default. Sized so a regtest or a
        // bring-up testnet never saturates, and bounded so a long-running node
        // degrades to today's refusal instead of to an unbounded map.
        std::size_t max_log = 131072;
        // Hard ceiling on records replayed in ONE project() call (a rebuild is
        // bounded by the log anyway; this catches a pathological ask).
        std::size_t max_replay = 1u << 21;
    };

    XmrCutProjector(::v37::ChainId chain, Options o) : m_chain(chain), m_o(o) {}
    // Defaults. A SEPARATE overload rather than `Options o = Options()`: GCC
    // rejects a default argument naming a nested struct whose members carry
    // default initializers, from inside the enclosing class body (the same
    // workaround carrier_send.hpp already uses).
    explicit XmrCutProjector(::v37::ChainId chain) : m_chain(chain), m_o() {}

    XmrCutProjector(const XmrCutProjector&) = delete;
    XmrCutProjector& operator=(const XmrCutProjector&) = delete;

    // ── the AddLane seam ────────────────────────────────────────────────────
    // Called once, from the carrier stack's start(), with the params the daemon
    // seeded the lane with (read back off the engine's v1 snapshot, so it is the
    // geometry the engine actually committed and not a second copy of the
    // config). `incarnation` is carried only so a projected view's diagnostic
    // fields name the engine's incarnation rather than the shadow's own.
    void seed(const ::v37::LaneParams& p, std::uint64_t incarnation) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_params = p;
        m_incarnation = incarnation;
        m_ready = true;
        m_disabled = false;
        m_saturated = false;
        m_log.clear();
        m_exec.reset();
        m_cursor = 0;
        m_applied = 0;
        m_cache.reset();
    }

    // ── the record tee (ANY thread; called under CarrierIngest's admit lock) ──
    // The ONE ordering requirement of this whole class: this must be called in
    // the SAME order the records reach V37Engine::submit. CarrierIngest holds
    // its m_mtx across admit()->sink()->submit(), so binding the tee inside that
    // sink makes the two streams identical by construction rather than by luck.
    void note(const ::v37::LaneRecord& r) {
        if (r.chain != m_chain) return;
        std::lock_guard<std::mutex> lk(m_mtx);
        switch (r.kind) {
        case ::v37::LaneRecord::Kind::Push:
            ++m_teed;
            if (!m_ready || m_disabled || m_saturated) return;
            if (m_log.size() >= m_o.max_log) {
                // Saturation: stop retaining rather than drop the HEAD, because
                // dropping the head would leave the shadow unable to reach any
                // prefix at all (the canon Lane cannot be copied or cheaply
                // checkpointed). Every later ask above the retained prefix then
                // refuses, which is precisely today's behaviour, said out loud.
                m_saturated = true;
                m_note = "cut projector SATURATED at " + std::to_string(m_log.size()) +
                         " retained push records — prefixes beyond it can no longer be "
                         "projected and a winner naming one is refused exactly as before "
                         "(raise --cut-projector-log to widen the window)";
                return;
            }
            m_log.push_back(Push{r.desc, r.w_raw, r.flags});
            return;
        case ::v37::LaneRecord::Kind::AddLane:
            // A second AddLane for this chain means a fresh incarnation; the
            // replica must restart with it or it would answer for a dead lane.
            m_params = r.params;
            m_ready = true;
            m_disabled = false;
            m_saturated = false;
            m_log.clear();
            m_exec.reset();
            m_cursor = 0;
            m_applied = 0;
            m_cache.reset();
            return;
        case ::v37::LaneRecord::Kind::Rewind:
        case ::v37::LaneRecord::Kind::RemoveLane:
            // Neither is issued on the Monero parent lane. If one ever is, the
            // replica can no longer be proven faithful by replaying pushes
            // alone, so it DISABLES itself: the receive seam falls back to the
            // engine ring and refuses what it cannot answer, which is correct.
            m_disabled = true;
            m_cache.reset();
            m_note = "cut projector DISABLED: a " +
                     std::string(r.kind == ::v37::LaneRecord::Kind::Rewind ? "Rewind"
                                                                           : "RemoveLane") +
                     " reached the observed lane and a push-log replica cannot stay "
                     "faithful across it";
            return;
        }
    }

    // Convenience for the ingest sink (avoids building a LaneRecord twice).
    void note_push(const ::v37::PayoutDescriptor& d, ::v37::u64 w_raw,
                   std::uint32_t flags) {
        std::lock_guard<std::mutex> lk(m_mtx);
        ++m_teed;
        if (!m_ready || m_disabled || m_saturated) return;
        if (m_log.size() >= m_o.max_log) {
            m_saturated = true;
            m_note = "cut projector SATURATED at " + std::to_string(m_log.size()) +
                     " retained push records";
            return;
        }
        m_log.push_back(Push{d, w_raw, flags});
    }

    // ── the projection (main thread) ────────────────────────────────────────
    // Returns the settlement projection at EXACTLY prefix `next_pos`, and only
    // when the shadow's commitment there equals `spine_digest`. nullptr with
    // *digest_mismatch == true means we reached P and the commitments DIFFER —
    // which is a real sharechain divergence, not a coalescing miss, and the
    // caller must keep treating it as one.
    std::shared_ptr<const SettlementView> project(std::uint64_t next_pos,
                                                  const ::v37::bytes32& spine_digest,
                                                  bool* digest_mismatch = nullptr,
                                                  std::string* why = nullptr) {
        if (digest_mismatch) *digest_mismatch = false;
        std::lock_guard<std::mutex> lk(m_mtx);
        ++m_asked;

        if (!m_ready || m_disabled) {
            ++m_not_ready;
            if (why) *why = m_disabled ? m_note
                                       : std::string("the cut projector has no AddLane yet");
            return nullptr;
        }
        if (m_cache && m_cache->next_pos == next_pos && m_cache->digest == spine_digest) {
            ++m_cache_hits;
            return m_cache;     // the 20-tick retry path costs nothing
        }
        // A prefix BELOW the shadow's cursor needs the replica rebuilt from the
        // log head: ::v37::Lane is not copyable and its rewind journal is far
        // shallower than the distance a peer's cut can sit behind our tip.
        if (!m_exec || m_cursor > next_pos) {
            if (m_saturated && m_cursor > next_pos) {
                // The log no longer starts at the lane's genesis prefix, so a
                // rebuild could not reproduce this prefix. Refuse, loudly.
                ++m_below_floor;
                if (why) *why = m_note;
                return nullptr;
            }
            if (!rebuild_locked()) {
                ++m_not_ready;
                if (why) *why = "the shadow lane refused its AddLane (geometry?)";
                return nullptr;
            }
        }
        if (next_pos > m_cursor) {
            const std::uint64_t need = next_pos - m_cursor;
            if (need > static_cast<std::uint64_t>(m_o.max_replay)) {
                ++m_over_budget;
                if (why)
                    *why = "the winner's prefix P=" + std::to_string(next_pos) +
                           " is " + std::to_string(need) +
                           " records ahead of the projector cursor, past its replay budget";
                return nullptr;
            }
            bool forward = false;
            while (m_cursor < next_pos) {
                if (m_applied >= m_log.size()) {
                    ++m_beyond_tip;
                    if (why)
                        *why = "the winner's prefix P=" + std::to_string(next_pos) +
                               " is AHEAD of every record this node has admitted (cursor=" +
                               std::to_string(m_cursor) + ", log=" +
                               std::to_string(m_log.size()) +
                               ") — the carrier that produces it has not arrived yet";
                    return nullptr;
                }
                const Push& p = m_log[m_applied];
                const ::v37::SubmitResult res = m_exec->submit(
                    ::v37::LaneRecord::push(m_chain, p.desc, p.w_raw, p.flags));
                ++m_applied;
                ++m_replayed;
                if (res.applied()) ++m_cursor;
                forward = true;
            }
            if (forward) ++m_forward;
        }

        std::shared_ptr<const ::v37::LaneSnapshot> snap = m_exec->receive(m_chain);
        if (!snap) {
            ++m_not_ready;
            if (why) *why = "the shadow lane published nothing at P";
            return nullptr;
        }
        if (snap->next_pos != next_pos) {
            // Only reachable if Lane::push stopped advancing next_pos by one per
            // applied record. Refuse rather than fold at a neighbour (O2.3).
            ++m_not_ready;
            if (why)
                *why = "the projector reached lane prefix " +
                       std::to_string(static_cast<unsigned long long>(snap->next_pos)) +
                       " asking for " + std::to_string(next_pos);
            return nullptr;
        }
        if (!(snap->digest == spine_digest)) {
            ++m_digest_miss;
            if (digest_mismatch) *digest_mismatch = true;
            if (why)
                *why = "the projector reached the winner's prefix P=" +
                       std::to_string(next_pos) +
                       " but this node's replay commits to a DIFFERENT lane digest there — "
                       "the two nodes folded different records into the same prefix";
            return nullptr;
        }

        auto sv = std::make_shared<SettlementView>();
        sv->version       = snap->version;      // the SHADOW's version (node-local either way)
        sv->incarnation   = m_incarnation;      // the engine's, so diagnostics do not lie
        sv->chain         = snap->chain;
        sv->params        = snap->params;
        sv->next_pos      = snap->next_pos;
        sv->acc_total     = snap->acc_total;
        sv->decayed_total = snap->decayed_total;
        sv->raw_total     = snap->raw_total;
        sv->payout        = snap->payout;
        sv->digest        = snap->digest;
        sv->identities    = snap->identities;
        m_cache = sv;
        ++m_served;
        return sv;
    }

    // One-shot note the daemon prints once (saturation / disable). Cleared when
    // read, so a status loop does not repeat it every line.
    std::string take_note() {
        std::lock_guard<std::mutex> lk(m_mtx);
        std::string n;
        n.swap(m_note);
        return n;
    }

    XmrCutProjectorStats stats() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        XmrCutProjectorStats s;
        s.teed        = m_teed;
        s.asked       = m_asked;
        s.served      = m_served;
        s.cache_hits  = m_cache_hits;
        s.forward     = m_forward;
        s.rebuilds    = m_rebuilds;
        s.replayed    = m_replayed;
        s.beyond_tip  = m_beyond_tip;
        s.below_floor = m_below_floor;
        s.digest_miss = m_digest_miss;
        s.not_ready   = m_not_ready;
        s.over_budget = m_over_budget;
        s.log_size    = static_cast<std::uint64_t>(m_log.size());
        s.cursor      = m_cursor;
        s.saturated   = m_saturated;
        s.disabled    = m_disabled;
        return s;
    }

    bool ready() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_ready && !m_disabled;
    }

private:
    struct Push {
        ::v37::PayoutDescriptor desc;
        ::v37::u64              w_raw = 0;
        std::uint32_t           flags = 0;
    };

    // Caller holds m_mtx. Fresh replica at the lane's genesis prefix.
    bool rebuild_locked() {
        m_exec = std::make_unique<::v37::LaneExecutor>();
        const ::v37::SubmitResult r =
            m_exec->submit(::v37::LaneRecord::add_lane(m_chain, m_params));
        if (!r.applied()) { m_exec.reset(); return false; }
        m_cursor = 0;
        m_applied = 0;
        m_cache.reset();
        ++m_rebuilds;
        return true;
    }

    ::v37::ChainId m_chain;
    Options        m_o;

    mutable std::mutex m_mtx;
    ::v37::LaneParams  m_params;
    std::uint64_t      m_incarnation = 0;
    bool               m_ready = false;
    bool               m_disabled = false;
    bool               m_saturated = false;
    std::string        m_note;

    std::deque<Push>                          m_log;
    std::unique_ptr<::v37::LaneExecutor>      m_exec;     // the shadow replica
    std::size_t                               m_applied = 0;  // log index next to replay
    std::uint64_t                             m_cursor = 0;   // shadow lane prefix
    std::shared_ptr<const SettlementView>     m_cache;

    std::uint64_t m_teed = 0, m_asked = 0, m_served = 0, m_cache_hits = 0,
                  m_forward = 0, m_rebuilds = 0, m_replayed = 0, m_beyond_tip = 0,
                  m_below_floor = 0, m_digest_miss = 0, m_not_ready = 0,
                  m_over_budget = 0;
};

} // namespace c2pool::v37n::xmr::o2
