// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/node/xmr_anchor_confirm.hpp
//
// GATE 4: the anchor, confirmed against the live network before this node
// serves anything.
//
// anchor/xmr_anchor_load.hpp states the duty in the file that owes it and
// spells out why it cannot discharge it itself:
//
//     "load_anchor() proves the bundle is well-formed and self-consistent; the
//      caller MUST still fetch the block at bundle.height from peers and refuse
//      to start unless it hashes to bundle.id (anchor_confirmed_by_network)."
//
// Gates 1..3 (source, form, meaning) all judge the bundle AGAINST ITSELF. They
// catch a damaged file, a bundle for the wrong network, a window of the wrong
// length, seeds off an epoch boundary. What no self-check can catch is a bundle
// that is internally PERFECT and names a block that is not on this network at
// all: a fabricated chain, correctly encoded, is indistinguishable from the
// real one until somebody asks the network. That question is this file.
//
// WHAT IT ASKS, AND WHY THAT IS THE ONLY HONEST SHAPE OF THE QUESTION.
// The levin p2p protocol has no "give me the block at height H". It has
// NOTIFY_REQUEST_GET_OBJECTS (2003), which takes block IDS -- the same message
// the genesis boot already uses to seed row zero, and the same one the sync
// driver uses for every block after it. So the request is for bundle.id, and
// the two halves of the question are answered from the bytes that come back:
//
//   * IS IT THE BLOCK WE NAMED? The id is RECOMPUTED from the blob with this
//     repository's own hasher (consensus/xmr_block_id.hpp) and compared to
//     bundle.id. Nothing is taken from the peer's word: a peer that answers
//     with different bytes is refused, not believed. This is the comparison
//     anchor_confirmed_by_network() performs, and it is that pinned function
//     that performs it here -- not a second copy of the same `!=`.
//   * IS IT AT THE HEIGHT WE NAMED? A by-id fetch cannot answer that by itself,
//     and a bundle whose height was tampered with would otherwise sail through:
//     the id still matches, so anchor_confirmed_by_network() alone says yes.
//     So the block's OWN height is read out of its coinbase (the txin_gen
//     height, which Monero consensus forces to equal the block's height) and
//     compared to bundle.height. A peer cannot lie about it without producing a
//     blob that hashes to a different id, which the first half already refuses.
//
// A peer serving a block at all means the block is in ITS main-chain database
// (monerod's handle_get_objects reads the blockchain, and reports anything it
// does not hold in missed_ids). That is the bound of what this gate proves and
// it is stated rather than overclaimed: gate 4 proves THE NETWORK AGREES THIS
// BLOCK EXISTS AT THIS HEIGHT, not that it has the most work. Fork choice and
// proof of work stay where they are -- in C2c, above the anchor.
//
// FAIL-CLOSED, AND BOUNDED, AND LOUD. Three refusals, no silent trust:
//
//   * MISMATCH. The blob hashes to something else, or its coinbase says a
//     different height: Refused immediately, on the first answer. One honest
//     peer disagreeing is enough, because a peer cannot forge agreement -- the
//     id is a hash of the bytes it sent.
//   * EXHAUSTION. Every peer asked reported the id MISSED, went away, or let
//     its turn expire, up to AnchorConfirmConfig::peers: Refused. "Nobody on
//     this network has ever heard of the block your bundle pins" is the exact
//     shape a fabricated anchor takes, so it must never be a silent pass.
//   * DEADLINE. The whole gate has one wall clock bound
//     (AnchorConfirmConfig::timeout_ms). Expiring it is a refusal, not a
//     shrug: a node that cannot reach the network cannot confirm its trust
//     root, and starting anyway is precisely the posture this gate exists to
//     remove.
//
// THREADING. AnchorNetworkConfirm is internally locked because its two sides
// live on different threads by construction: blobs arrive on the verify thread
// (ChainBoot::on_objects) while the status line is read from the consumer's.
// The lock is held only across a few field writes; the parse and the hash are
// done before it is taken.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. No
// consensus digest, no src/sharechain/v37.
//
// Header-only. STL, plus the tree's own consensus primitives (xmr_coin for
// keccak and the tree hash, via xmr_block_id.hpp).
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_load.hpp"
#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/contracts/anchor.hpp"
#include "impl/xmr/native/contracts/fetcher.hpp"
#include "impl/xmr/native/contracts/types.hpp"

namespace c2pool::xmr::native::rt {

// ---------------------------------------------------------------------------
enum class AnchorConfirmState : std::uint8_t {
    Disarmed = 0,   // this node did not boot from an anchor; the gate is silent
    Pending,        // armed: asking peers, serving nothing
    Confirmed,      // a peer served the anchor block and it IS the one pinned
    Refused,        // fail-closed: a mismatch, an exhausted peer set, or the deadline
};

inline const char* to_string(AnchorConfirmState s) noexcept {
    switch (s) {
        case AnchorConfirmState::Disarmed:  return "disarmed";
        case AnchorConfirmState::Pending:   return "pending";
        case AnchorConfirmState::Confirmed: return "confirmed";
        case AnchorConfirmState::Refused:   return "refused";
    }
    return "?";
}

// The BOUND. Every field here exists so that "we could not confirm" ends in a
// refusal at a known time rather than in a node that waits forever with a
// half-open posture.
struct AnchorConfirmConfig {
    // Distinct handshaked peers to ask before declaring exhaustion. More than
    // one because a single peer can be pruned, syncing, or simply unlucky; not
    // many more because agreement here is about EXISTENCE, and one peer that
    // serves the block settles it.
    std::size_t   peers       = 4;
    // The whole gate's wall bound, from the moment it is armed.
    std::uint64_t timeout_ms  = 60'000;
    // One peer's turn. After this its slot is spent and the next peer is asked,
    // which is what keeps a silent peer from consuming the whole deadline.
    std::uint64_t per_peer_ms = 12'000;

    bool sane() const noexcept {
        return peers >= 1 && timeout_ms >= 1 && per_peer_ms >= 1;
    }
};

// ---------------------------------------------------------------------------
// AnchorNetworkConfirm -- the judgement. No sockets, no timers, no threads of
// its own: it is fed blobs and told when a peer is spent, and it answers with a
// state. Everything that CAN be tested without a network is in here.
// ---------------------------------------------------------------------------
class AnchorNetworkConfirm {
public:
    struct Stats {
        AnchorConfirmState state  = AnchorConfirmState::Disarmed;
        std::uint64_t height      = 0;      // what the bundle pinned
        Hash          id{};                 // what the bundle pinned
        std::uint64_t blobs_seen  = 0;      // blobs offered while pending
        std::uint64_t foreign     = 0;      // blobs that were not the id we asked for
        std::uint64_t peers_asked = 0;
        std::uint64_t peers_spent = 0;      // missed / gone / turn expired
        std::uint64_t served_height = 0;    // the coinbase height of the served block
        Hash          served_id{};          // recomputed, never taken from the peer
        std::string   why;                  // the refusal, or the confirmation note
    };

    // Armed from the bundle the loader just accepted. Only the two fields gate 4
    // judges are kept: anchor_confirmed_by_network() reads exactly `height` (for
    // its message) and `id` (for its comparison), so `key_` carries both
    // verbatim and nothing else -- a full bundle is ~2.4 MB of windows this gate
    // has no opinion about, and holding it for the life of the node to re-read
    // two fields would be a waste with a false air of completeness.
    void arm(const AnchorBundle& b) {
        std::lock_guard<std::mutex> lk(mu_);
        key_          = AnchorBundle{};
        key_.network  = b.network;
        key_.height   = b.height;
        key_.id       = b.id;
        s_            = Stats{};
        s_.state      = AnchorConfirmState::Pending;
        s_.height     = b.height;
        s_.id         = b.id;
        s_.why        = "awaiting a peer that can serve the anchor block";
    }

    bool armed() const {
        std::lock_guard<std::mutex> lk(mu_);
        return s_.state != AnchorConfirmState::Disarmed;
    }
    AnchorConfirmState state() const {
        std::lock_guard<std::mutex> lk(mu_);
        return s_.state;
    }
    bool settled() const {
        const AnchorConfirmState st = state();
        return st == AnchorConfirmState::Confirmed || st == AnchorConfirmState::Refused;
    }
    bool confirmed() const { return state() == AnchorConfirmState::Confirmed; }
    bool refused()   const { return state() == AnchorConfirmState::Refused; }

    // True when this node may forward to the index and serve blocks: either the
    // gate was never armed (genesis boot) or it has been confirmed. A Pending or
    // Refused gate is NOT ready, which is the whole point of the word.
    bool ready() const {
        const AnchorConfirmState st = state();
        return st == AnchorConfirmState::Disarmed || st == AnchorConfirmState::Confirmed;
    }

    Stats stats() const {
        std::lock_guard<std::mutex> lk(mu_);
        return s_;
    }

    // The id the gate is waiting for; the driver asks peers for exactly this.
    Hash wanted() const {
        std::lock_guard<std::mutex> lk(mu_);
        return key_.id;
    }
    std::uint64_t wanted_height() const {
        std::lock_guard<std::mutex> lk(mu_);
        return key_.height;
    }

    // -----------------------------------------------------------------------
    // A blob a peer served. Returns true when THIS blob settled the gate.
    //
    // A blob that is not the block we asked for settles nothing: a 2004 may
    // legitimately carry other blocks, and refusing on one would hand any peer
    // a way to veto our boot. It is counted (`foreign`) so that "we asked and
    // got answers, none of them ours" is visible, and the peer's turn still
    // expires the normal way.
    // -----------------------------------------------------------------------
    bool offer_blob(const std::vector<std::uint8_t>& blob) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (s_.state != AnchorConfirmState::Pending) return false;
            ++s_.blobs_seen;
        }
        if (blob.empty()) { bump_foreign_(); return false; }

        ParsedBlock pb;
        if (parse_block(blob, pb) != BlockParseStatus::Ok) { bump_foreign_(); return false; }
        const BlockIdentity ident = block_identity(blob.data(), pb);

        // --- half one: is it the block the bundle named? ---------------------
        // The comparison itself is anchor_confirmed_by_network()'s, called here
        // rather than re-spelled, so the duty written in xmr_anchor_load.hpp is
        // discharged by the function that states it.
        AnchorBundle key;
        {
            std::lock_guard<std::mutex> lk(mu_);
            key = key_;
        }
        std::string why;
        if (!anchor_confirmed_by_network(key, ident.id, why)) {
            // Not our block. A 2004 answering a one-id request should not carry
            // it, but a peer chooses what it sends and a foreign blob is not by
            // itself a lie about the anchor.
            bump_foreign_();
            return false;
        }

        // --- half two: is it at the height the bundle named? -----------------
        CoinbaseFields cb;
        if (!parse_coinbase_fields(blob.data(), pb, cb)) {
            refuse_("the block that hashes to the anchor id has a coinbase that does not "
                    "read back; refusing to start", ident.id, 0);
            return true;
        }
        if (cb.height != key.height) {
            refuse_("the block that hashes to the anchor id is at height "
                    + std::to_string(cb.height) + " on this network, but the bundle pins "
                    + std::to_string(key.height) + "; refusing to start",
                    ident.id, cb.height);
            return true;
        }

        {
            std::lock_guard<std::mutex> lk(mu_);
            s_.state         = AnchorConfirmState::Confirmed;
            s_.served_id     = ident.id;
            s_.served_height = cb.height;
            s_.why = "the network served block " + anchor_codec::to_hex(ident.id)
                   + " at height " + std::to_string(cb.height)
                   + ", which is the anchor this node booted from";
        }
        return true;
    }

    // A peer's answer named the anchor id as one it does not hold. That peer is
    // spent; whether the gate refuses depends on how many are left, which the
    // driver owns.
    void note_missed(const std::string& peer) {
        std::lock_guard<std::mutex> lk(mu_);
        if (s_.state != AnchorConfirmState::Pending) return;
        ++s_.peers_spent;
        s_.why = "peer " + peer + " does not hold the anchor block";
    }

    void note_asked(const std::string& peer) {
        std::lock_guard<std::mutex> lk(mu_);
        if (s_.state != AnchorConfirmState::Pending) return;
        ++s_.peers_asked;
        s_.why = "asked peer " + peer + " for the anchor block";
    }

    void note_spent(const std::string& peer, const char* how) {
        std::lock_guard<std::mutex> lk(mu_);
        if (s_.state != AnchorConfirmState::Pending) return;
        ++s_.peers_spent;
        s_.why = std::string("peer ") + peer + " " + how
               + " without serving the anchor block";
    }

    // The two fail-closed exits the driver owns the clock for.
    void refuse_exhausted(std::size_t asked) {
        refuse_("asked " + std::to_string(asked)
                + " peer(s) for the block the anchor bundle pins and not one served it; "
                  "refusing to start (fail-closed: an anchor nobody on this network has "
                  "is exactly what a fabricated anchor looks like)",
                Hash{}, 0);
    }
    void refuse_deadline(std::uint64_t ms) {
        refuse_("no peer confirmed the anchor block within " + std::to_string(ms)
                + " ms; refusing to start (fail-closed: an unconfirmed trust root is not "
                  "a trust root)",
                Hash{}, 0);
    }

    // One line for the boot log, whichever way it went.
    std::string log_line() const {
        const Stats s = stats();
        return std::string("[GATE-4] anchor ") + to_string(s.state)
             + ": height " + std::to_string(s.height)
             + " id " + anchor_codec::to_hex(s.id)
             + " (asked " + std::to_string(s.peers_asked)
             + ", spent " + std::to_string(s.peers_spent)
             + ", blobs " + std::to_string(s.blobs_seen) + ") -- " + s.why;
    }

private:
    void bump_foreign_() {
        std::lock_guard<std::mutex> lk(mu_);
        if (s_.state != AnchorConfirmState::Pending) return;
        ++s_.foreign;
    }

    void refuse_(const std::string& why, const Hash& served_id, std::uint64_t served_height) {
        std::lock_guard<std::mutex> lk(mu_);
        if (s_.state != AnchorConfirmState::Pending) return;
        s_.state         = AnchorConfirmState::Refused;
        s_.served_id     = served_id;
        s_.served_height = served_height;
        s_.why           = why;
    }

    mutable std::mutex mu_;
    AnchorBundle       key_{};   // network + height + id; see arm()
    Stats              s_{};
};

// ---------------------------------------------------------------------------
// AnchorConfirmDriver -- the bounded asker.
//
// It is a POLL, not a loop with a sleep in it, so the caller decides which
// thread it runs on. IChainFetcher's contract puts request_objects on the C2
// verify thread, and that is where NativeNode polls it from.
//
// The peer set is read fresh on every poll (`fetcher.peers()` lists handshaked
// peers only), because at boot the pool is still dialling: the gate must be
// able to start with zero peers and pick them up as they arrive, and it must
// still refuse when the deadline arrives and none ever did.
// ---------------------------------------------------------------------------
class AnchorConfirmDriver {
public:
    using ClockMs = std::function<std::uint64_t()>;

    AnchorConfirmDriver(IChainFetcher& fetcher, AnchorNetworkConfirm& confirm,
                        AnchorConfirmConfig cfg, ClockMs now_ms)
        : fetcher_(fetcher), confirm_(confirm), cfg_(std::move(cfg)), now_(std::move(now_ms)) {
        if (!cfg_.sane()) cfg_ = AnchorConfirmConfig{};
        started_ms_ = now_();
    }

    // Drive one step. Idempotent once settled.
    AnchorConfirmState poll() {
        if (confirm_.settled()) return confirm_.state();
        if (!confirm_.armed())  return AnchorConfirmState::Disarmed;

        const std::uint64_t now = now_();
        if (now - started_ms_ >= cfg_.timeout_ms) {
            confirm_.refuse_deadline(cfg_.timeout_ms);
            return AnchorConfirmState::Refused;
        }

        const std::vector<std::pair<PeerRef, PeerSyncData>> peers = fetcher_.peers();

        // Is the peer whose turn it is still worth waiting for?
        if (!outstanding_.empty()) {
            const bool still_here = std::any_of(
                peers.begin(), peers.end(),
                [this](const std::pair<PeerRef, PeerSyncData>& p) {
                    return p.first.addr == outstanding_;
                });
            if (!still_here) {
                confirm_.note_spent(outstanding_, "went away");
                outstanding_.clear();
            } else if (now - outstanding_since_ >= cfg_.per_peer_ms) {
                confirm_.note_spent(outstanding_, "let its turn expire");
                outstanding_.clear();
            } else {
                return AnchorConfirmState::Pending;   // its turn is not up
            }
        }

        if (asked_.size() >= cfg_.peers) {
            confirm_.refuse_exhausted(asked_.size());
            return AnchorConfirmState::Refused;
        }

        for (const std::pair<PeerRef, PeerSyncData>& p : peers) {
            if (std::find(asked_.begin(), asked_.end(), p.first.addr) != asked_.end()) continue;
            // prune=false: we want the canonical block bytes, and the id we
            // recompute from them has to be the id the network agrees on.
            if (!fetcher_.request_objects(p.first, {confirm_.wanted()}, /*prune=*/false)) continue;
            asked_.push_back(p.first.addr);
            outstanding_       = p.first.addr;
            outstanding_since_ = now;
            confirm_.note_asked(p.first.addr);
            return AnchorConfirmState::Pending;
        }

        // Nobody new to ask yet. Not a refusal -- the pool may still be dialling
        // -- but the wall deadline above is what stops this being forever.
        return AnchorConfirmState::Pending;
    }

    // A peer told us it does not hold the anchor id. Its turn ends now.
    void on_missed(const std::string& peer) {
        confirm_.note_missed(peer);
        if (outstanding_ == peer) outstanding_.clear();
    }

    std::size_t asked() const noexcept { return asked_.size(); }

private:
    IChainFetcher&           fetcher_;
    AnchorNetworkConfirm&    confirm_;
    AnchorConfirmConfig      cfg_;
    ClockMs                  now_;
    std::uint64_t            started_ms_ = 0;
    std::vector<std::string> asked_;
    std::string              outstanding_;
    std::uint64_t            outstanding_since_ = 0;
};

} // namespace c2pool::xmr::native::rt
