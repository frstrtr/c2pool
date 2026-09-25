// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/node/xmr_sync_driver.hpp
//
// M0: THE HALF OF CHAIN SYNC NO COMPONENT OWNS -- deciding WHEN to ask, and WHO
// to ask.
//
// C2c is explicit about the split. `on_chain_entry` ends with
//
//     "the SCHEDULE is the sync driver's business; the index only says what is
//      missing and in what order"
//
// and it proves it: the index turns a RESPONSE_CHAIN_ENTRY straight into a
// `request_objects` for the ids it lacks. What nothing in the tree does is send
// the FIRST `NOTIFY_REQUEST_CHAIN`, and without it a freshly booted node sits
// handshaked, liveness-green and empty forever -- which is exactly the silent
// starvation shape the X9 stagenet bring-up spent a day on. This file is that
// missing edge, and it is deliberately small: three decisions, all of them on
// the verify thread, all of them stateless enough to be re-derived every tick.
//
//   1. WHO. The peer with the greatest advertised CUMULATIVE DIFFICULTY, not the
//      greatest height. Height is a number a peer can pick; cumulative
//      difficulty is the same claim priced in work, and the index re-derives it
//      anyway before believing anything -- so choosing on it costs nothing and
//      refuses to be steered by a cheap lie about length.
//   2. WHEN. Only while the best peer claims to be ahead of us, and never with
//      two chain requests in flight on the same link (C1b matches
//      notify-answered requests through ONE expect latch, so a second overlapping
//      question is a dropped connection). An unanswered request times out and is
//      re-asked -- of a DIFFERENT peer where one exists, because "the peer that
//      answers nothing" and "the peer that answers slowly" look identical from
//      here and only the retry distinguishes them.
//   3. WHAT ELSE. `refetch_wanted()` -- the parents of blocks the index parked
//      as orphans. A fluffy push that arrives while we are still behind lands
//      with an unknown parent; asking for that parent is what turns a park into
//      a connect without waiting for the next chain entry.
//
// THE BOOT ASK. Before the index has a trust root the driver asks for exactly
// one object: the network's pinned genesis id (see xmr_chain_boot.hpp). It is
// the only request in this file that is not driven by a height comparison,
// because before the seed there is no height to compare.
//
// TIP-FOLLOW USES NONE OF THIS. Once we are level with the cohort, new blocks
// arrive as NOTIFY_NEW_FLUFFY_BLOCK pushes from peers that hold us in
// state_normal, and the driver goes quiet -- `chain_requests` stops rising while
// the height keeps moving, which is the observable difference between
// "following the tip" and "still catching up".
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/.
//
// Header-only. STL only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/contracts/chain_index.hpp"
#include "impl/xmr/native/contracts/fetcher.hpp"
#include "impl/xmr/native/contracts/serving.hpp"
#include "impl/xmr/native/contracts/types.hpp"

namespace c2pool::xmr::native::rt {

struct SyncDriverConfig {
    // How long an unanswered NOTIFY_REQUEST_CHAIN may stay outstanding before it
    // is re-asked. monerod answers in milliseconds on a LAN and in a second or
    // two across the internet; 20 s is "this peer is not going to answer".
    std::uint64_t chain_request_timeout_ms = 20'000;
    // The same, for the one-object genesis fetch at boot.
    std::uint64_t boot_request_timeout_ms  = 10'000;
    // Ids per refetch request. C1c chunks a span into <=100-id wire requests on
    // its own (D-3); this is the span size, not the wire size.
    std::size_t   refetch_batch            = 64;
    // How long before the same missing id is asked for again. The index's
    // refetch list is a STANDING WANT LIST -- it is not cleared when a block
    // arrives -- so a driver that asked for all of it every tick would re-ask
    // twice a second forever. Observed exactly that way: 361 RESPONSE_GET_OBJECTS
    // frames for a 12-block backfill, all of them answers to questions already
    // answered. Whether the index should prune the list is a C2c question; that
    // the SCHEDULE must not be a busy loop is this file's.
    std::uint64_t refetch_reask_ms          = 15'000;
    // Batches of refetch_batch ids the driver may put on the wire per tick.
    // Each batch goes to the first peer that has a span slot free (the best
    // peer first); a batch no peer can take is not booked as asked, so it is
    // offered again on the next tick instead of sitting out refetch_reask_ms.
    std::size_t   refetch_batches_per_tick  = 4;

    // #1680: how long a bodiless fluffy park (ChainIndex::bodies_wanted) may sit
    // before the driver re-asks for the whole block via GET_OBJECTS. A park is
    // created the instant we send its announcer a REQUEST_FLUFFY_MISSING_TX
    // (2009); this grace lets that reply arrive normally before we fall back.
    // 5 s is ten driver ticks at driver_tick_ms=500 -- generous for a LAN reply,
    // short enough that a reply lost to the DoS bucket or a disconnect self-heals
    // long before the next found share submits at a taken height. Re-asked every
    // timeout until the block connects (which erases the park).
    std::uint64_t fluffy_reply_timeout_ms   = 5'000;

    // READ-ONLY PROBE. Ask one NOTIFY_REQUEST_CHAIN from a genesis-terminated
    // locator, record the answer, and never ask for a block. This is what a
    // live probe against somebody else's synced daemon is allowed to do: a
    // chain entry costs the daemon a walk of its own id index, while a
    // GET_OBJECTS span costs it disk and bandwidth it is using to sync.
    bool          probe_only               = false;
};

class SyncDriver {
public:
    struct Stats {
        std::uint64_t ticks            = 0;
        std::uint64_t boot_requests    = 0;
        std::uint64_t chain_requests   = 0;
        std::uint64_t chain_timeouts   = 0;
        std::uint64_t refetch_requests = 0;
        std::uint64_t refetch_refused  = 0;   // a batch no peer had a span slot for (not booked)
        std::uint64_t bodies_refetch_requests = 0;   // #1680: whole-block fallback for a stranded fluffy park
        std::uint64_t no_peer_ticks    = 0;
        std::uint64_t our_height       = 0;
        std::uint64_t best_peer_height = 0;
        std::string   target;            // the peer key we are asking, "" = none
    };

    // `booted` is a predicate rather than a flag so the driver never caches the
    // one piece of state it does not own. `refetch` is a function for the same
    // reason and one more: refetch_wanted() is ChainIndex's own surface rather
    // than part of IChainView, and reaching for the concrete class here would
    // make this file untestable against the W0 fakes.
    using BootedFn  = std::function<bool()>;
    using RefetchFn = std::function<std::vector<Hash>()>;

    SyncDriver(IChainFetcher& fetcher, IChainServing& serving, IChainView& view,
               Hash genesis_id, BootedFn booted, RefetchFn refetch,
               RefetchFn bodies = {},
               SyncDriverConfig cfg = {})
        : fetcher_(fetcher),
          serving_(serving),
          view_(view),
          genesis_id_(genesis_id),
          booted_(std::move(booted)),
          refetch_(std::move(refetch)),
          bodies_(std::move(bodies)),
          cfg_(cfg) {}

    // One pass. MUST be called on the verify thread: it reads the index and
    // hands the index's own locator to the fetcher.
    void tick(std::uint64_t now_ms) {
        ++stats_.ticks;

        const std::vector<std::pair<PeerRef, PeerSyncData>> peers = fetcher_.peers();
        if (peers.empty()) {
            ++stats_.no_peer_ticks;
            stats_.target.clear();
            in_flight_ = false;
            return;
        }

        // --- who -------------------------------------------------------------
        std::size_t best = 0;
        for (std::size_t i = 1; i < peers.size(); ++i) {
            if (u128_less(peers[best].second.cumulative_difficulty,
                          peers[i].second.cumulative_difficulty))
                best = i;
        }
        const PeerRef&      peer = peers[best].first;
        const PeerSyncData& sync = peers[best].second;
        stats_.target            = peer.addr;
        stats_.best_peer_height  = sync.current_height;

        // --- the read-only probe ---------------------------------------------
        if (cfg_.probe_only) {
            if (probe_sent_) return;
            probe_sent_ = fetcher_.request_chain(peer, {genesis_id_}, /*prune=*/true);
            if (probe_sent_) ++stats_.chain_requests;
            return;
        }

        // The boot fetch and the first chain request are two different
        // questions, and the second must not wait out the first one's timeout.
        // Without this the node sat handshaked and empty for a full
        // chain_request_timeout_ms after its trust root had landed -- 20 s of
        // "connected, synced=0, nothing happening" on every cold start, which
        // is the exact shape of failure this whole layer exists to make
        // impossible to misread.
        const bool booted_now = booted_();
        if (booted_now && !was_booted_) {
            was_booted_ = true;
            in_flight_  = false;
        }

        // --- the boot ask ----------------------------------------------------
        if (!booted_now) {
            if (in_flight_ && now_ms - sent_at_ms_ < cfg_.boot_request_timeout_ms) return;
            in_flight_  = fetcher_.request_objects(peer, {genesis_id_}, /*prune=*/false);
            sent_at_ms_ = now_ms;
            if (in_flight_) ++stats_.boot_requests;
            return;
        }

        const SyncState st = view_.sync_state();
        stats_.our_height  = st.header_frontier;

        // Progress is the height moving, or a chain entry being accepted (the
        // index now holds a want list to work through).
        const bool answered = st.chain_entries != entries_at_request_;
        if (st.header_frontier != last_frontier_ || st.chain_entries != last_entries_) {
            last_frontier_    = st.header_frontier;
            last_entries_     = st.chain_entries;
            last_progress_ms_ = now_ms;
        }

        // Our height moved since the request went out, or its answer was
        // accepted: it was answered, and the want list says what to fetch.
        if (in_flight_ && (st.header_frontier != height_at_request_ || answered))
            in_flight_ = false;

        // --- the want list: the chain entry's window, and parked parents ----
        // Done before the height comparison: an orphan's parent is missing
        // whether or not the cohort is ahead of us. An id is booked as asked
        // only when a peer ACCEPTED the batch carrying it: booking it first
        // and then losing the batch to a full span slot was half of the
        // catch-up livelock (the whole want list frozen for refetch_reask_ms
        // while nothing was fetching it).
        const std::vector<Hash> want = refetch_ ? refetch_() : std::vector<Hash>{};
        if (!want.empty()) {
            std::size_t       sent = 0;
            bool              refused = false;
            std::vector<Hash> ask;
            auto flush = [&]() {
                if (ask.empty()) return;
                if (!ask_objects_(peers, best, st.header_frontier, ask)) {
                    refused = true;
                    ++stats_.refetch_refused;
                } else {
                    for (const Hash& id : ask)
                        asked_[std::string(reinterpret_cast<const char*>(id.data()), id.size())] = now_ms;
                    ++stats_.refetch_requests;
                    ++sent;
                }
                ask.clear();
            };
            for (const Hash& id : want) {
                if (refused || sent >= cfg_.refetch_batches_per_tick) break;
                if (view_.by_id(id)) continue;          // it arrived; stop asking
                const std::string key(reinterpret_cast<const char*>(id.data()), id.size());
                const auto it = asked_.find(key);
                if (it != asked_.end() && now_ms - it->second < cfg_.refetch_reask_ms) continue;
                ask.push_back(id);
                if (ask.size() >= cfg_.refetch_batch) flush();
            }
            if (!refused && sent < cfg_.refetch_batches_per_tick) flush();
            // The ask-book is a rate limiter, not a record: a bounded forget is
            // better than an unbounded memory of every id we ever wanted.
            if (asked_.size() > 4096) asked_.clear();
        }

        // --- the stranded fluffy parks (#1680) -------------------------------
        // A block announced fluffy and parked WITH a body blob but WITHOUT its
        // transactions is invisible to refetch_wanted() (have_body_locked_ sees
        // the blob) and to on_chain_entry (skips ids in alt_). If the missing-tx
        // reply we asked for is lost -- dropped by the block DoS bucket, or by a
        // disconnect -- nothing re-asks and the node freezes one block behind.
        // We give each park a grace window (its own in-flight 2009 gets to
        // answer) and then re-ask for the WHOLE block via GET_OBJECTS, which
        // works from any peer and rides the existing span machinery. Kept as a
        // list separate from refetch above so a healthy fluffy reply is never
        // raced by a duplicate whole-block fetch.
        const std::vector<Hash> parks = bodies_ ? bodies_() : std::vector<Hash>{};
        if (!parks.empty()) {
            std::vector<Hash> ask;
            for (const Hash& id : parks) {
                if (ask.size() >= cfg_.refetch_batch) break;
                const std::string key(reinterpret_cast<const char*>(id.data()), id.size());
                const auto it = bodies_seen_.find(key);
                if (it == bodies_seen_.end()) {   // first sighting: let the 2009 reply land
                    bodies_seen_[key] = now_ms;
                    continue;
                }
                if (now_ms - it->second < cfg_.fluffy_reply_timeout_ms) continue;
                it->second = now_ms;              // re-ask every timeout until it connects
                ask.push_back(id);
            }
            if (!ask.empty() && fetcher_.request_objects(peer, std::move(ask), /*prune=*/true))
                ++stats_.bodies_refetch_requests;
            // Forget parks that have connected (no longer in the wanted list), so
            // the book does not grow without bound.
            if (bodies_seen_.size() > parks.size() + 256) {
                std::map<std::string, std::uint64_t> live;
                for (const Hash& id : parks)
                    live[std::string(reinterpret_cast<const char*>(id.data()), id.size())] =
                        bodies_seen_[std::string(reinterpret_cast<const char*>(id.data()), id.size())];
                bodies_seen_.swap(live);
            }
        } else if (!bodies_seen_.empty()) {
            bodies_seen_.clear();
        }

        // --- the chain ask ---------------------------------------------------
        // `current_height` is monerod's own spelling: one PAST the peer's tip.
        // So "the peer is ahead of us" is current_height > our_tip + 1.
        if (sync.current_height <= st.header_frontier + 1) {
            in_flight_ = false;
            return;
        }
        if (in_flight_) {
            if (now_ms - sent_at_ms_ < cfg_.chain_request_timeout_ms) return;
            ++stats_.chain_timeouts;
            // Re-ask somebody else where there is somebody else: a peer that
            // answered nothing twice is not going to answer the third time.
            avoid_ = peer.addr;
        } else if (chain_asked_ && !want.empty()
                   && now_ms - last_progress_ms_ < cfg_.chain_request_timeout_ms) {
            // The last entry's want list is still being worked through and it
            // is moving: another chain request now would only re-state it (and
            // queue behind the span chunks on the same wire). Ask again once
            // it runs out, or once it has stopped moving for a timeout.
            return;
        }

        const PeerRef* ask = &peer;
        if (!avoid_.empty() && peer.addr == avoid_) {
            for (const auto& [ref, sd] : peers) {
                if (ref.addr == avoid_) continue;
                if (sd.current_height <= st.header_frontier + 1) continue;
                ask = &ref;
                break;
            }
        }

        std::vector<Hash> locator = serving_.locator();
        if (locator.empty()) return;
        in_flight_          = fetcher_.request_chain(*ask, std::move(locator), /*prune=*/true);
        sent_at_ms_         = now_ms;
        height_at_request_  = st.header_frontier;
        entries_at_request_ = st.chain_entries;
        chain_asked_        = chain_asked_ || in_flight_;
        if (in_flight_) {
            ++stats_.chain_requests;
            stats_.target = ask->addr;
        }
    }

    const Stats& stats() const noexcept { return stats_; }

private:
    // One batch, to the first peer with a span slot for it: the chosen best
    // peer, then every other peer at least level with us. False when none
    // accepted (the fetcher refuses a span over its D-3 caps).
    bool ask_objects_(const std::vector<std::pair<PeerRef, PeerSyncData>>& peers,
                      std::size_t best, std::uint64_t our_height,
                      const std::vector<Hash>& ids) {
        if (fetcher_.request_objects(peers[best].first, ids, /*prune=*/true)) return true;
        for (std::size_t i = 0; i < peers.size(); ++i) {
            if (i == best || peers[i].second.current_height < our_height + 1) continue;
            if (fetcher_.request_objects(peers[i].first, ids, /*prune=*/true)) return true;
        }
        return false;
    }

    IChainFetcher& fetcher_;
    IChainServing& serving_;
    IChainView&    view_;
    Hash           genesis_id_;
    BootedFn       booted_;
    RefetchFn      refetch_;
    RefetchFn      bodies_;      // #1680: bodiless fluffy parks; {} disables the fallback
    SyncDriverConfig cfg_;

    std::map<std::string, std::uint64_t> asked_;   // refetch id -> when we last asked
    std::map<std::string, std::uint64_t> bodies_seen_;  // #1680: park id -> when first noticed / last re-asked
    bool          was_booted_        = false;
    bool          probe_sent_        = false;
    bool          in_flight_         = false;
    std::uint64_t sent_at_ms_        = 0;
    std::uint64_t height_at_request_ = 0;
    std::uint64_t entries_at_request_ = 0;
    std::uint64_t last_frontier_     = 0;
    std::uint64_t last_entries_      = 0;
    std::uint64_t last_progress_ms_  = 0;
    bool          chain_asked_       = false;
    std::string   avoid_;
    Stats         stats_{};
};

} // namespace c2pool::xmr::native::rt
