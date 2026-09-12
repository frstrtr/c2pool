// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_carrier_defer.hpp   (R-B — never DROP a block-winner
//                                             carrier for a momentary miss)
//
// THE RACE THIS CLOSES. A block-winner carrier is keyed to the block's PARENT.
// The receiving node admits it against its own mainchain index, so if the
// parent has not been polled yet the index cannot place it, W2 answers
// CarrierStatus::REJECT_POW (the enum lumps "PoW / target / chain /
// UNRESOLVABLE BIN" into one value), and the S-1c receive seam — which returns
// early on any non-admitted frame — threw the whole frame away, cut descriptor
// and all. It was never re-offered and never re-requested, so the peer simply
// never learned of that block: on the 2-node XMR regtest node A emitted 45
// block-winner carriers and node B offered 44, and the single lost one (h=86,
// win:9291a269, parent@85) was a PERMANENT fork — B never registered h=86 and
// the two owed ledgers could not rejoin.
//
// It is a MOMENTARY condition by construction: the parent is a block that is
// already on the chain the winner mined on, so the receiver resolves it one
// poll later. Refusing it forever because we asked one poll too early is the
// I-2 survey gap (carrier_index.hpp: "the seam is binary (optional), so a
// transient Unknown is indistinguishable from a bogus carrier") applied to the
// one frame the pool can least afford to lose.
//
// WHAT THIS ADDS — two bounded registers, both RECEIVE-SIDE and both additive.
// The carrier wire is untouched: no frame changes shape, no field is added, and
// the v0x03 K_fair WIRE-CARRY rides exactly as before.
//
//   (1) XmrDeferredCarriers — PARK AND RE-OFFER, keyed by (h_b, bid).
//       A frame that carries a cut and was rejected for a possibly-momentary
//       cause is parked with the carrier's own parent hash. Each tick the
//       parent is re-asked through the SAME index the admission uses — the I-2
//       tri-state gate, read honestly: resolved => re-drive the frame through
//       the relay (W2 never recorded it in its dedup window, because it never
//       admitted it, so the re-drive admits cleanly and the cut is offered by
//       the ordinary path); still unresolvable => wait. Bounded by a parked-set
//       cap, a per-entry attempt budget and a TTL, so a genuinely bogus frame
//       costs a fixed, small number of index lookups and is then dropped
//       LOUDLY, which is what the old path did immediately and silently.
//
//   (2) XmrWinnerReflood — a BOUNDED re-announce of our OWN winner frames.
//       Parking only recovers a frame that ARRIVED. A frame lost on the wire
//       (a peer that was not connected yet, a dropped socket) leaves the same
//       permanent hole, and the receiver cannot ask for it: the frozen W3-B5
//       wire has no request opcode and adding one would be a wire change, which
//       this patch must not make. So the WINNER re-floods each block-winner
//       frame a small, fixed number of extra times at a fixed spacing. A peer
//       that already took it answers REJECT_DEDUP (counted as the ordinary
//       flood ECHO, no lane weight, no second credit — W2's window is the
//       authority); a peer that missed it admits it and offers the cut. One
//       miss is therefore recoverable end-to-end.
//
// HONEST BOUNDARY: (2) is a bounded re-ANNOUNCE by the winner, not a receiver-
// initiated re-REQUEST by (h_b, bid). The register in (1) IS keyed by (h_b,
// bid) and is what makes a re-offer idempotent per block; a true receiver->peer
// "send me the descriptor for (h_b, bid)" needs a new message on the frozen
// wire, and that is a wire change held for the operator, not taken here.
//
// SCOPE FENCE: consumer tree, header-only, STL only. Nothing here admits,
// credits, folds or digests anything: it only decides WHEN a frame the relay
// already owns is handed to the relay again.
// ===========================================================================
#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <c2pool/v37/w2_admission.hpp>   // IMainchainIndex
#include <c2pool/v37/w2_receipt.hpp>     // bytes32

namespace c2pool::v37n::xmr::o2 {

// ── (1) park-and-re-offer ───────────────────────────────────────────────────

struct XmrDeferStats {
    std::uint64_t parked        = 0;   // frames taken in (first time per key)
    std::uint64_t re_offered    = 0;   // re-driven through the relay
    std::uint64_t readmitted    = 0;   // re-drive that ADMITTED (the recovery)
    std::uint64_t dropped_spent = 0;   // attempt budget / TTL exhausted
    std::uint64_t dropped_full  = 0;   // the parked set was at its cap
    std::uint64_t duplicates    = 0;   // same (h_b,bid) offered again while parked
    std::uint64_t waiting       = 0;   // parked right now (sampled at stats())
};

class XmrDeferredCarriers {
public:
    struct Options {
        // A parked entry is one block-winner frame; a handful is already far
        // more than a healthy network produces. The cap is what keeps a peer
        // that floods junk from turning this into a memory sink.
        std::size_t max_parked = 64;
        // Re-asks before the entry is dropped LOUDLY. At the daemon's default
        // --poll-ms this is a couple of minutes, which is orders of magnitude
        // longer than a parent poll and still ends.
        unsigned max_attempts = 40;
        // Belt-and-braces wall clock bound, independent of the tick rate.
        std::chrono::seconds ttl{600};
    };

    explicit XmrDeferredCarriers(Options o) : m_o(o) {}
    // Defaults as a SEPARATE overload: GCC rejects a default argument naming a
    // nested struct with default member initializers from inside the enclosing
    // class body (the workaround carrier_send.hpp already carries).
    XmrDeferredCarriers() : m_o() {}

    // Key a parked frame by the BLOCK it names, not by the frame bytes: a peer
    // may re-flood the same win (see XmrWinnerReflood) and both copies describe
    // the same block, so one parked entry per block is the right cardinality.
    static std::string key_of(std::uint64_t h_b, const std::string& bid) {
        return bid + "@" + std::to_string(h_b);
    }

    // Take a rejected block-winner frame in. `prev` is the carrier's OWN
    // prev_block_hash in lane-prev form — the exact value the admission asked
    // the index about — so the retry gate re-asks the identical question.
    // Returns true if the frame is now parked.
    bool park(std::uint64_t h_b, const std::string& bid, const bytes32& prev,
              std::vector<std::uint8_t> frame) {
        std::lock_guard<std::mutex> lk(m_mtx);
        const std::string k = key_of(h_b, bid);
        auto it = m_parked.find(k);
        if (it != m_parked.end()) { ++m_st.duplicates; return true; }
        if (m_parked.size() >= m_o.max_parked) { ++m_st.dropped_full; return false; }
        Entry e;
        e.h_b = h_b;
        e.bid = bid;
        e.prev = prev;
        e.frame = std::move(frame);
        e.first = std::chrono::steady_clock::now();
        m_parked.emplace(k, std::move(e));
        ++m_st.parked;
        return true;
    }

    bool holds(std::uint64_t h_b, const std::string& bid) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_parked.count(key_of(h_b, bid)) != 0;
    }

    // The block has been learned of some other way (its descriptor arrived on a
    // later flood, or the node registered it itself): stop re-offering.
    void retire(std::uint64_t h_b, const std::string& bid) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_parked.erase(key_of(h_b, bid));
    }

    // ── the tick (MAIN thread) ──────────────────────────────────────────────
    // `resolves` is the I-2 tri-state gate: true iff the index can place the
    // parent NOW. `redrive` hands the frame back to the relay and answers
    // whether it ADMITTED this time. Neither is called with the lock held — the
    // relay takes its own mutex and the index may touch the node, and taking
    // this lock across either would invert the documented lock order.
    template <class ResolvesFn, class RedriveFn>
    std::size_t pump(ResolvesFn&& resolves, RedriveFn&& redrive,
                     std::vector<std::string>* narrate = nullptr) {
        struct Shot { std::string key; bytes32 prev; std::vector<std::uint8_t> frame;
                      std::uint64_t h_b; std::string bid; };
        std::vector<Shot> shots;
        const auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            for (auto it = m_parked.begin(); it != m_parked.end();) {
                Entry& e = it->second;
                if (e.attempts >= m_o.max_attempts || (now - e.first) > m_o.ttl) {
                    ++m_st.dropped_spent;
                    if (narrate)
                        narrate->push_back(
                            "[v37-xmr-carrier] S-1c DEFERRED CARRIER DROPPED for block " +
                            short_of(e.bid) + " h=" + std::to_string(e.h_b) +
                            " after " + std::to_string(e.attempts) +
                            " re-asks: its parent never resolved in this index, so the "
                            "block-winner descriptor cannot be admitted here and this node "
                            "will NOT credit that block");
                    it = m_parked.erase(it);
                    continue;
                }
                shots.push_back(Shot{it->first, e.prev, e.frame, e.h_b, e.bid});
                ++it;
            }
        }
        std::size_t recovered = 0;
        for (Shot& s : shots) {
            if (!resolves(s.prev)) {
                std::lock_guard<std::mutex> lk(m_mtx);
                auto it = m_parked.find(s.key);
                if (it != m_parked.end()) ++it->second.attempts;
                continue;   // still Missing/Unknown — wait, do not burn the frame
            }
            ++m_st.re_offered;
            const bool admitted = redrive(s.frame);
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_parked.find(s.key);
            if (admitted) {
                ++m_st.readmitted;
                ++recovered;
                if (narrate)
                    narrate->push_back(
                        "[v37-xmr-carrier] S-1c DEFERRED CARRIER RECOVERED for block " +
                        short_of(s.bid) + " h=" + std::to_string(s.h_b) +
                        ": its parent resolved and the block-winner descriptor was "
                        "re-offered to the settlement seam (it would have been dropped "
                        "silently before R-B)");
                if (it != m_parked.end()) m_parked.erase(it);
            } else if (it != m_parked.end()) {
                ++it->second.attempts;
            }
        }
        return recovered;
    }

    XmrDeferStats stats() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        XmrDeferStats s = m_st;
        s.waiting = static_cast<std::uint64_t>(m_parked.size());
        return s;
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_parked.size();
    }

private:
    static std::string short_of(const std::string& bid) {
        return bid.size() > 12 ? bid.substr(0, 12) + "\xe2\x80\xa6" : bid;
    }

    struct Entry {
        std::uint64_t h_b = 0;
        std::string   bid;
        bytes32       prev{};
        std::vector<std::uint8_t> frame;
        unsigned      attempts = 0;
        std::chrono::steady_clock::time_point first{};
    };

    Options                      m_o;
    mutable std::mutex           m_mtx;
    std::map<std::string, Entry> m_parked;
    XmrDeferStats                m_st;
};

// ── (2) bounded winner re-flood ─────────────────────────────────────────────

struct XmrRefloodStats {
    std::uint64_t held    = 0;   // winner frames taken in
    std::uint64_t sent    = 0;   // extra floods put on the wire
    std::uint64_t retired = 0;   // frames that spent their budget
    std::uint64_t dropped = 0;   // frames refused: the hold set was at its cap
};

class XmrWinnerReflood {
public:
    struct Options {
        // EXTRA floods after the original. Two is enough to survive a peer that
        // reconnects within a few seconds and cheap enough to be invisible: a
        // winner frame is a few hundred bytes and blocks are minutes apart.
        unsigned repeats = 2;
        std::chrono::milliseconds interval{2000};
        std::size_t max_held = 8;
    };

    explicit XmrWinnerReflood(Options o) : m_o(o) {}
    XmrWinnerReflood() : m_o() {}   // see XmrDeferredCarriers on the GCC default-arg rule

    // Called from the send worker thread with the EXACT bytes that went out.
    void hold(std::vector<std::uint8_t> frame) {
        if (m_o.repeats == 0 || frame.empty()) return;
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_held.size() >= m_o.max_held) { ++m_st.dropped; return; }
        Entry e;
        e.frame = std::move(frame);
        e.due = std::chrono::steady_clock::now() + m_o.interval;
        m_held.push_back(std::move(e));
        ++m_st.held;
    }

    // MAIN thread. `bcast` puts the frame on the wire and answers how many peers
    // took it (the value is only narrated, never gated on: a re-flood that
    // reaches nobody is still bounded and still retires).
    template <class BroadcastFn>
    std::size_t pump(BroadcastFn&& bcast) {
        std::vector<std::vector<std::uint8_t>> due;
        const auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            for (auto it = m_held.begin(); it != m_held.end();) {
                if (it->due > now) { ++it; continue; }
                due.push_back(it->frame);
                ++it->sent;
                it->due = now + m_o.interval;
                if (it->sent >= m_o.repeats) { ++m_st.retired; it = m_held.erase(it); }
                else ++it;
            }
        }
        for (const auto& f : due) { (void)bcast(f); }
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            m_st.sent += due.size();
        }
        return due.size();
    }

    XmrRefloodStats stats() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_st;
    }

private:
    struct Entry {
        std::vector<std::uint8_t> frame;
        unsigned sent = 0;
        std::chrono::steady_clock::time_point due{};
    };
    Options            m_o;
    mutable std::mutex m_mtx;
    std::vector<Entry> m_held;
    XmrRefloodStats    m_st;
};

} // namespace c2pool::v37n::xmr::o2
