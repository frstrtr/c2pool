// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/chain/xmr_chain_index.hpp
//
// THE CHAIN INDEX (C2c): the RandomX-verified, checkpoint-anchored index of the
// Monero chain, and the fork choice over it.
//
// It is the piece that turns three independently correct parts into a node's
// view of a chain: the consensus state (C2a) knows how to advance and roll back
// the five windows by one block; the trust anchor (C2b) says where history is
// allowed to start; the RandomX gate says which blocks may be called verified.
// This class decides WHICH blocks go through them, in WHAT order, and WHAT
// happens when the network offers a better chain than the one we are on.
//
// FOUR PROPERTIES, EACH LOAD-BEARING
//
//   1. FORK CHOICE ON RECOMPUTED WORK. A candidate's difficulty is derived from
//      the 735-row window on its own branch and summed onto its parent; the
//      peer's cumulative-difficulty and weight hints are recorded and ignored.
//      A node that trusted the hint could be walked onto a worthless chain for
//      free -- which is the entire attack that proof of work exists to price.
//
//   2. VERIFICATION AT L4, ANCHORED. Above the anchor every block is structure-
//      checked, prev-linked, fork-versioned, timestamp-windowed, weight- and
//      reward-checked against our own median, and RandomX-verified against OUR
//      difficulty with the seed for its epoch. Below the anchor nothing is
//      verified and nothing is reorgable: that is what bounds the cost of a cold
//      start to the anchor's age instead of the chain's, and it is the same
//      trust class as a monerod release's compiled-in checkpoints.
//
//   3. REORGS ARE BOUNDED AND JOURNALED. Every switch is refused unless the fork
//      point is above the anchor, above every pinned checkpoint, inside the
//      retained window, and within max_reorg_depth. Every switch is written to
//      the journal before it starts and closed after it ends, and a candidate
//      that fails consensus half-way is rolled back to the exact chain we were
//      on. There is no path in this file that replays from genesis: an offer we
//      cannot judge inside the window is refused with a reason, loudly.
//
//   4. THE SETTLEMENT CLOCK READS FROM HERE. The v37 section 3 clock accounts a
//      receipt at the height of its parent block once that block is buried N
//      deep. `burial_of()` answers that with a discriminated verdict rather than
//      a number, because "not yet buried", "below the anchor and therefore
//      pinned", "not on this chain any more" and "never heard of it" are four
//      different answers that a bare depth of 0 would flatten into one.
//
// THREADING. One owner (the verify thread) mutates; consumers read. Everything
// public takes the index's mutex, and NO sink is ever called with it held:
// events raised inside a connect or a reorg are queued and flushed after the
// lock is released, which is also what lets a reorg emit one Reorg event instead
// of a burst of Extends for blocks that were only passing through.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_sha256.hpp"
#include "impl/xmr/native/chain/xmr_block_eval.hpp"
#include "impl/xmr/native/chain/xmr_chain_view.hpp"
#include "impl/xmr/native/chain/xmr_consensus_state.hpp"
#include "impl/xmr/native/chain/xmr_fork_choice.hpp"
#include "impl/xmr/native/chain/xmr_pow_gate.hpp"
#include "impl/xmr/native/chain/xmr_reorg_journal.hpp"
#include "impl/xmr/native/chain/xmr_row_store.hpp"
#include "impl/xmr/native/consensus/xmr_epoch.hpp"
#include "impl/xmr/native/consensus/xmr_hf_policy.hpp"
#include "impl/xmr/native/contracts/anchor.hpp"
#include "impl/xmr/native/contracts/chain_index.hpp"
#include "impl/xmr/native/contracts/fetcher.hpp"
#include "impl/xmr/native/contracts/serving.hpp"

// Feature marker: FORK-FUSE-2's UnknownForkWatch (check_unknown_fork(),
// unknown_fork_watch(), the bounded above-version id set) exists.
#define C2POOL_XMR_UNKNOWN_FORK_WATCH 1

namespace c2pool::xmr::native {

// --- wire limits mirrored from monerod ------------------------------------------
// cryptonote_protocol_defs.h / cryptonote_protocol_handler.inl. They are here
// rather than in the codec because they are what the INDEX refuses on, and a
// limit enforced only by the parser is a limit an attacker reaches by a
// different route.
inline constexpr std::size_t MAX_CHAIN_ENTRY_IDS = 25000;   // BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT

// --- options ----------------------------------------------------------------------
struct ChainIndexOptions {
    XmrNet        net             = XmrNet::Mainnet;
    std::size_t   row_retention   = 2048;                  // D-9, one RandomX epoch
    std::uint64_t max_reorg_depth = 720;                   // bounded; never genesis
    std::size_t   alt_max_blocks  = 512;
    std::uint64_t alt_max_bytes   = 32ull * 1024 * 1024;
    std::size_t   entry_cache     = 1024;                  // bodies kept for re-apply
    std::uint64_t entry_cache_bytes = 64ull * 1024 * 1024;
    std::uint64_t burial_depth    = 60;                    // Monero D_conf
    std::uint64_t snapshot_depth  = 64;                    // how far below the tip a snapshot is taken
    // COLD-BOOT-2: the catch-up download window above the CONSUMER's booked
    // frontier (set_consumer_frontier). A chain-entry download is handed out
    // only up to frontier + window, so the settlement books the post-anchor gap
    // in bounded batches while it downloads and no unbooked row or body leaves
    // the row retention / entry cache first. 0 = off (the index downloads as
    // far as its fetch window allows, the pre-COLD-BOOT-2 shape).
    std::uint64_t consumer_window = 0;
    // COLD-BOOT-3: the pacing ceiling is a CATCH-UP device, never a standing
    // limit. It is lifted for the rest of the process (loudly) the first time
    // the index is synced, when a snapshot resume is already past it (the
    // previous process followed the chain past a held cursor), or when the
    // consumer's frontier has not moved for this many consecutive reports while
    // the download is held at the ceiling (a HELD cursor: an undecidable block,
    // a relay repair no peer can serve). Lifted, the index follows the chain as
    // before COLD-BOOT-2; a block whose row then leaves the retention unbooked
    // is HELD by the consumer's tri-state canonical test (Unknown), never
    // dropped. 0 = no stall bound (the synced / resume latches still apply).
    std::uint64_t consumer_stall_reports = 1200;
    TieBreak      tie            = TieBreak::PreferOwn;   // D-14
    VerificationLevel level        = VerificationLevel::L4PrunedAuthenticated;
    // Fail-closed: a block whose PoW we could not check does not join the best
    // chain. Replays of recorded history (parity, KATs) turn it off explicitly
    // and get rows with pow_verified == false, which never advance the frontier.
    bool          require_pow     = true;
    // OWN-FORK LIVENESS GUARD (fork-choice policy on our OWN blocks, not a
    // Monero rule). When the best chain ends in blocks WE mined and, for longer
    // than this, no connected peer advertises a top on that fork -- every peer
    // is on some other tip, or every peer dropped us -- the index leaves its own
    // fork: the own-mined suffix is disconnected and abandoned, and the node
    // follows the peers' chain. A levin-only node cannot see WHY a monerod
    // refused our block; "nobody adopted it" is the evidence it does have.
    // 0 disables. Default: two target block times.
    std::uint64_t own_fork_bound_ms = 240'000;
    // FORK-FUSE-2: how long the tip must go without a v16 extension, while
    // >= 2 distinct peers send above-version blocks, before the unknown-fork
    // trip withdraws templates and tx admission. See UnknownForkWatch for the
    // choice of 30 min against the 120 s target. 0 = the default. A shorter
    // value is a test-only knob (the daemon refuses it on mainnet).
    std::uint64_t unknown_fork_stall_ms = UNKNOWN_FORK_STALL_MS_DEFAULT;
};

// --- what happened to an offered block ---------------------------------------------
enum class OfferOutcome : std::uint8_t {
    Connected = 0,   // extended the best chain
    Reorged,         // arrived on a branch that then won
    StoredAsAlt,     // valid-looking candidate, but the best chain still wins
    ParkedOrphan,    // parent unknown; held while we ask for the chain between
    NeedsBodies,     // announced without its transactions (fluffy); ask and retry
    Duplicate,       // already known
    Rejected,        // refused; `why` says why, `fault` says whose fault
};

inline const char* to_string(OfferOutcome o) noexcept {
    switch (o) {
        case OfferOutcome::Connected:    return "Connected";
        case OfferOutcome::Reorged:      return "Reorged";
        case OfferOutcome::StoredAsAlt:  return "StoredAsAlt";
        case OfferOutcome::ParkedOrphan: return "ParkedOrphan";
        case OfferOutcome::NeedsBodies:  return "NeedsBodies";
        case OfferOutcome::Duplicate:    return "Duplicate";
        case OfferOutcome::Rejected:     return "Rejected";
    }
    return "?";
}

struct OfferResult {
    OfferOutcome  outcome = OfferOutcome::Rejected;
    Hash          id{};
    std::uint64_t height  = 0;

    EvalStatus    eval    = EvalStatus::Ok;
    ConnectStatus connect = ConnectStatus::Ok;
    PowVerdict    pow     = PowVerdict::Skipped;

    bool          peer_fault = false;
    PeerFault     fault      = PeerFault::BadData;
    std::string   why;
};

// --- burial, for the v37 section 3 clock ---------------------------------------------
// A receipt is accounted at bin = height(prev_id) once that block is buried N
// deep. The four answers below are genuinely different instructions to the
// caller, which is why this is an enum and not a depth:
//
//   Buried       -- account it; the block is N deep AND at or below the verified
//                   frontier, so the work under it has actually been checked.
//   PinnedBuried -- the block is at or below the anchor: history we did not
//                   verify but do not question either. Account it.
//   NotYet       -- known, on the best chain, but not deep enough (or the
//                   frontier has not reached it). Ask again later.
//   Orphaned     -- known to us, but not on the best chain any more. The clock
//                   must not account it; W4's monotone high-water decides what
//                   that means for anything already accounted.
//   Unknown      -- we have never seen it, or it has fallen out of the retained
//                   window. Not an answer, and must never be treated as "no".
enum class BurialStatus : std::uint8_t { Unknown = 0, Orphaned, NotYet, Buried, PinnedBuried };

inline const char* to_string(BurialStatus s) noexcept {
    switch (s) {
        case BurialStatus::Unknown:      return "Unknown";
        case BurialStatus::Orphaned:     return "Orphaned";
        case BurialStatus::NotYet:       return "NotYet";
        case BurialStatus::Buried:       return "Buried";
        case BurialStatus::PinnedBuried: return "PinnedBuried";
    }
    return "?";
}

inline constexpr bool burial_status_accounts(BurialStatus s) noexcept {
    return s == BurialStatus::Buried || s == BurialStatus::PinnedBuried;
}

struct Burial {
    BurialStatus  status = BurialStatus::Unknown;
    std::uint64_t height = 0;   // the bin height, when it is known
    std::uint64_t depth  = 0;   // confirmations, tip inclusive
};

// ---------------------------------------------------------------------------------
// The index.
// ---------------------------------------------------------------------------------
class ChainIndex final : public IChainIndexInbound,
                         public IChainView,
                         public IChainServing {
public:
    explicit ChainIndex(const ChainIndexOptions& opts, IPowSource& pow)
        : opts_(opts),
          view_(opts.net),
          pow_(&pow),
          gate_(pow,
                [this](std::uint64_t epoch_height, const Hash& branch_tip)
                    -> std::optional<Hash> { return seed_on_branch_(epoch_height, branch_tip); },
                opts.level) {
        rows_.set_retention(opts_.row_retention);
        uf_watch_ = UnknownForkWatch(opts_.unknown_fork_stall_ms);
        alt_.set_caps(opts_.alt_max_blocks, opts_.alt_max_bytes);
        view_.state().set_row_retention(opts_.row_retention);
        // One sink into the state view; it queues rather than dispatches, so no
        // consumer callback ever runs with our mutex held.
        view_.subscribe([this](const node::MainchainEvent& e) { queued_events_.push_back(e); });
        view_.subscribe_txs([this](const BlockTxEvent& e) {
            note_mined_locked_(e);
            queued_tx_events_.push_back(e);
        });
    }

    ChainIndex(const ChainIndex&)            = delete;
    ChainIndex& operator=(const ChainIndex&) = delete;

    // --- boot ---------------------------------------------------------------------
    // From a loaded, self-checked, network-confirmed anchor bundle. The 60
    // timestamps are not in the bundle (the loader's contract) and are supplied
    // by the boot path from the headers it fetched around the anchor; without
    // them the timestamp rule is simply not enforceable yet, which the state
    // handles by treating a short window as "no median".
    bool boot_from_anchor(const AnchorBundle& b,
                          const std::vector<std::uint64_t>& timestamps_60,
                          std::string& why) {
        std::lock_guard<std::mutex> lk(mu_);
        if (b.network != to_string(opts_.net)) {
            why = "anchor bundle is for '" + b.network + "', the index runs '"
                + to_string(opts_.net) + "'";
            return false;
        }
        reset_locked_();
        view_.seed_from_anchor(b, timestamps_60);
        checkpoints_ = b.monerod_checkpoints;

        const ChainRow* t = view_.state().tip();
        if (!t) { why = "anchor produced no tip row"; return false; }
        rows_.push(*t, /*own_mined=*/false, Hash{});
        for (const auto& s : b.seed_ids) rows_.remember_seed_anchor(s.first, s.second);
        {
            std::vector<DifficultyRow> pre;
            pre.reserve(b.difficulty_window.size());
            for (const auto& p : b.difficulty_window) pre.push_back(DifficultyRow{p.first, p.second});
            rows_.seed_pre_window(b.height, pre);
        }
        seed_long_mirror_(b.long_term_weights);
        anchor_id_ = b.id;
        why.clear();
        return true;
    }

    // Seeding from numbers rather than a bundle: the parity replay and the KATs
    // have monerod's windows but no .inc file. Same invariants.
    void seed_direct(const ChainRow& tip,
                     const std::vector<DifficultyRow>& difficulty_window,
                     const std::vector<std::uint64_t>& short_term_weights,
                     const std::vector<std::uint64_t>& long_term_weights,
                     const std::vector<std::uint64_t>& timestamps_60,
                     const std::vector<std::pair<std::uint64_t, Hash>>& seed_ids = {}) {
        std::lock_guard<std::mutex> lk(mu_);
        reset_locked_();
        view_.seed_direct(tip, difficulty_window, short_term_weights, long_term_weights,
                          timestamps_60, seed_ids);
        rows_.push(tip, false, Hash{});
        for (const auto& s : seed_ids) rows_.remember_seed_anchor(s.first, s.second);
        rows_.seed_pre_window(tip.height, difficulty_window);
        seed_long_mirror_(long_term_weights);
        anchor_id_ = tip.id;
    }

    void set_fetcher(IChainFetcher* f) {
        std::lock_guard<std::mutex> lk(mu_);
        fetcher_ = f;
    }

    // The clock the future-timestamp rule is judged against. Default 0 = "do not
    // judge", which is what a replay of recorded history wants and what a live
    // node must NOT keep.
    void set_clock(std::function<std::uint64_t()> clock) {
        std::lock_guard<std::mutex> lk(mu_);
        clock_ = std::move(clock);
    }

    // OR-C2-8: publication gate. A live node computes it from the peer cohort;
    // regtest and KATs set it directly, and the fact that it was forced is
    // visible in the status line rather than indistinguishable from the real
    // thing.
    void force_synced(bool v) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            forced_synced_ = v;
            synced_forced_ever_ = synced_forced_ever_ || v;
            update_synced_locked_();
        }
        flush_events_();
    }

    // --- the one entry point every block goes through ------------------------------
    OfferResult offer_block(const PeerRef* peer, BlockEntry entry, bool own_mined) {
        OfferResult r;
        {
            std::lock_guard<std::mutex> lk(mu_);
            r = offer_locked_(peer, std::move(entry), own_mined);
        }
        flush_events_();
        return r;
    }

    // The monerod checkpoints fencing reorgs, as boot_from_anchor() installs
    // them from the bundle. Exposed for rigs that seed without a bundle.
    void set_monerod_checkpoints(std::vector<std::pair<std::uint64_t, Hash>> cps) {
        std::lock_guard<std::mutex> lk(mu_);
        checkpoints_ = std::move(cps);
    }

    // --- IChainIndexInbound ---------------------------------------------------------
    void on_peer_sync_data(const PeerRef& p, const PeerSyncData& d) override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            // A peer whose advertised top_version disagrees with our hard-fork
            // table for its own tip is on a chain we do not implement; monerod
            // drops it in process_payload_sync_data and so do we.
            if (d.current_height > 0) {
                const std::uint8_t want =
                    hf_version_for_height(opts_.net, d.current_height - 1);
                if (d.top_version != 0 && d.top_version < want) {
                    peers_.erase(peer_key_(p));
                    penalize_locked_(&p, PeerFault::VersionMismatch,
                                     "advertised top_version " + std::to_string(d.top_version)
                                     + " is below the " + std::to_string(want)
                                     + " our fork table requires at its own tip");
                    update_synced_locked_();
                    return;
                }
            }
            peers_[peer_key_(p)] = d;
            update_synced_locked_();
        }
        flush_events_();
    }

    void on_chain_entry(const PeerRef& p, ChainEntry&& e) override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            std::string why;
            if (!validate_chain_entry_locked_(e, why)) {
                penalize_locked_(&p, PeerFault::BadChainEntry, why);
                return;
            }
            ++chain_entries_accepted_;
            // Everything after the splice point that we do not already have is
            // what we want fetched. The SCHEDULE is the sync driver's business;
            // the index only says what is missing and in what order -- through
            // refetch_wanted(), which hands out the part of this list that fits
            // the fetch window above our tip.
            //
            // The index used to put the WHOLE list (up to 2048 ids) on the wire
            // here as one span. The pool delivers a span only when all of its
            // ~21 chunks are in, so nothing connected for the minutes that took;
            // a peer drop lost all of it silently; every 20 s the driver asked
            // another peer for a chain and a fresh 2048-span went out, until
            // the span caps were full of redundant copies of the same blocks
            // and the batches the driver could still get through landed far
            // from the tip and parked. That was the mainnet catch-up livelock.
            //
            // Heights come from OUR row of the splice point, not the peer's
            // start_height claim.
            std::uint64_t base = e.start_height;
            if (const auto h = rows_.height_of(e.ids[0])) base = *h;
            else if (const AltBlock* a = alt_.find(e.ids[0])) base = a->height;
            wanted_.clear();
            wanted_heights_.clear();
            // FORK-FUSE-3: who announced this want list. Only ids THAT peer
            // announced may be held back when it serves an above-version block.
            wanted_src_ = peer_key_(p);
            for (std::size_t i = 1; i < e.ids.size(); ++i) {
                if (rows_.contains(e.ids[i]) || alt_.contains(e.ids[i])) continue;
                wanted_.push_back(e.ids[i]);
                wanted_heights_.push_back(base + i);
                if (wanted_.size() >= MAX_SPAN_IDS) break;
            }
        }
        flush_events_();
    }

    void on_objects(const PeerRef& p, std::vector<BlockEntry>&& blocks,
                    std::vector<Hash>&& missed, std::uint64_t peer_height) override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (peer_height > cohort_max_) cohort_max_ = peer_height;
            for (BlockEntry& b : blocks) {
                bytes_in_ += b.block_blob.size();
                (void)offer_locked_(&p, std::move(b), /*own_mined=*/false);
            }
            missed_ids_ += missed.size();
            update_synced_locked_();
        }
        flush_events_();
    }

    void on_new_block(const PeerRef& p, BlockEntry&& block, std::uint64_t peer_height,
                      bool fluffy) override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (peer_height > cohort_max_) cohort_max_ = peer_height;
            bytes_in_ += block.block_blob.size();
            const OfferResult r = offer_locked_(&p, std::move(block), /*own_mined=*/false);
            // D3a: a push of a block we HAVE (connected, already on the best
            // chain, or a valid alt candidate) hands its DoS block token back.
            if (fetcher_ && pushed_block_is_known_valid_locked_(r)) fetcher_->credit_known_block(p);
            if (r.outcome == OfferOutcome::NeedsBodies && fluffy && fetcher_) {
                // D-5: ask the announcer for exactly the bodies we are missing.
                // Which indices those are is the txpool's answer (it may hold
                // some); with no pool attached we ask for all of them.
                std::vector<std::uint64_t> want;
                if (const std::size_t total = missing_tx_count_(r.id)) {
                    want.reserve(total);
                    for (std::size_t i = 0; i < total; ++i) want.push_back(i);
                }
                fetcher_->request_fluffy_missing(p, r.id, r.height, std::move(want));
            }
            update_synced_locked_();
        }
        flush_events_();
    }

    void on_peer_gone(const PeerRef& p) override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            peers_.erase(peer_key_(p));
            ++peer_losses_;
            update_synced_locked_();
        }
        flush_events_();
    }

    // --- IChainView -------------------------------------------------------------------
    std::optional<node::ChainMainBlock> tip() const override {
        std::lock_guard<std::mutex> lk(mu_);
        const RowRecord* t = rows_.tip();
        if (!t) return std::nullopt;
        return t->row.to_chain_main_block();
    }

    std::optional<TemplateInputs> template_inputs() const override {
        std::lock_guard<std::mutex> lk(mu_);
        return view_.template_inputs();
    }

    std::uint64_t epoch_seq() const override {
        std::lock_guard<std::mutex> lk(mu_);
        return view_.epoch_seq();
    }

    std::optional<node::ChainMainBlock> by_id(const Hash& id) const override {
        std::lock_guard<std::mutex> lk(mu_);
        const RowRecord* r = rows_.by_id(id);
        if (!r) return std::nullopt;
        return r->row.to_chain_main_block();
    }

    std::optional<node::ChainMainBlock> by_height(std::uint64_t h) const override {
        std::lock_guard<std::mutex> lk(mu_);
        const RowRecord* r = rows_.by_height(h);
        if (!r) return std::nullopt;
        return r->row.to_chain_main_block();
    }

    std::optional<std::uint64_t> height_of(const Hash& id) const override {
        std::lock_guard<std::mutex> lk(mu_);
        return rows_.height_of(id);
    }

    std::uint64_t confirmation_depth(const Hash& id) const override {
        std::lock_guard<std::mutex> lk(mu_);
        const auto h = rows_.height_of(id);
        if (!h) return 0;
        const std::uint64_t tip_h = rows_.tip_height();
        return tip_h >= *h ? (tip_h - *h + 1) : 0;
    }

    bool is_on_best_chain(const Hash& id) const override {
        std::lock_guard<std::mutex> lk(mu_);
        return rows_.contains(id);
    }

    std::uint64_t anchor_height() const override {
        std::lock_guard<std::mutex> lk(mu_);
        return view_.anchor_height();
    }

    std::uint64_t verified_frontier() const override {
        std::lock_guard<std::mutex> lk(mu_);
        return view_.verified_frontier();
    }

    std::optional<Hash> seed_hash_for_height(std::uint64_t h) const override {
        std::lock_guard<std::mutex> lk(mu_);
        return rows_.id_at_epoch_height(rx_seedheight(h));
    }

    void subscribe(EventSink sink) override {
        std::lock_guard<std::mutex> lk(mu_);
        sinks_.push_back(std::move(sink));
    }

    void subscribe_txs(TxEventSink sink) override {
        std::lock_guard<std::mutex> lk(mu_);
        tx_sinks_.push_back(std::move(sink));
    }

    // C5's path. Marked own so D-14 applies, and verified exactly like a
    // stranger's block: a block we cannot verify is not one we should be
    // building on either.
    bool submit_own_block(const BlockEntry& entry, std::string& why) override {
        OfferResult r;
        {
            std::lock_guard<std::mutex> lk(mu_);
            r = offer_locked_(nullptr, entry, /*own_mined=*/true);
        }
        flush_events_();
        why = r.why;
        return r.outcome == OfferOutcome::Connected || r.outcome == OfferOutcome::Reorged
            || r.outcome == OfferOutcome::Duplicate;
    }

    SyncState sync_state() const override {
        std::lock_guard<std::mutex> lk(mu_);
        SyncState s = view_.sync_state();
        s.rows      = static_cast<std::uint64_t>(rows_.size());
        s.alt_rows  = static_cast<std::uint64_t>(alt_.size());
        s.orphans   = orphans_;
        s.chain_entries = chain_entries_accepted_;
        s.reorgs    = journal_.committed();
        s.pow_verified = gate_.verified();
        s.pow_failed   = gate_.failed();
        s.seed_rekeys  = gate_.rekeys();
        s.bans         = bans_;
        s.bytes_in     = bytes_in_;
        s.cohort_height = cohort_height_locked_();
        s.randomx_mode  = pow_->mode();
        s.synced        = synced_;
        return s;
    }

    // Template / own-block hygiene oracle (IChainView::probe_mined). Answered
    // from the mined-tx and spent-key-image maps the index keeps for the
    // retained window, bounded to the chain ending at `parent_id`.
    bool probe_mined(const Hash& parent_id, const std::vector<Hash>& tx_ids,
                     const std::vector<Hash>& key_images, std::vector<Hash>& mined_txs,
                     std::vector<Hash>& spent_key_images) const override {
        std::lock_guard<std::mutex> lk(mu_);
        mined_txs.clear();
        spent_key_images.clear();
        const auto ph = rows_.height_of(parent_id);
        if (!ph) return false;
        probe_mined_locked_(*ph, tx_ids, key_images, mined_txs, spent_key_images);
        return true;
    }

    // The own-fork liveness guard (ChainIndexOptions::own_fork_bound_ms). Driven
    // from the verify thread's periodic tick with a monotone millisecond clock.
    // Returns true when it abandoned our own fork on this call; `why` says what
    // it saw either way when something is being tracked.
    bool check_own_fork(std::uint64_t now_ms, std::string* why = nullptr) {
        bool abandoned = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            abandoned = check_own_fork_locked_(now_ms, why);
        }
        flush_events_();
        return abandoned;
    }

    // Is the best tip an own-mined fork nobody has adopted (yet)? Telemetry.
    bool own_fork_tracking() const { std::lock_guard<std::mutex> lk(mu_); return own_fork_tracking_; }
    std::uint64_t own_forks_abandoned() const { std::lock_guard<std::mutex> lk(mu_); return own_forks_abandoned_; }
    // Own blocks refused at submit because they carry a tx already mined, a key
    // image already spent, or a duplicate within the block.
    std::uint64_t own_blocks_refused_invalid() const { std::lock_guard<std::mutex> lk(mu_); return own_invalid_refused_; }
    // How many tx ids / key images the mined oracle currently covers.
    std::size_t mined_tx_count() const { std::lock_guard<std::mutex> lk(mu_); return mined_tx_.size(); }

    // --- IChainServing -------------------------------------------------------------------
    PeerSyncData our_sync_data() const override {
        std::lock_guard<std::mutex> lk(mu_);
        PeerSyncData d;
        const RowRecord* t = rows_.tip();
        if (t) {
            d.current_height        = t->row.height + 1;
            d.cumulative_difficulty = t->row.cumulative_difficulty;
            d.top_id                = t->row.id;
            d.top_version           = t->row.major_version;
        }
        d.pruning_seed  = 0;      // we never claim to serve a pruning stripe
        d.support_flags = 1;      // fluffy blocks
        return d;
    }

    bool have_block(const Hash& id) const override {
        std::lock_guard<std::mutex> lk(mu_);
        return rows_.contains(id) || alt_.contains(id);
    }

    // Last 10, then powers of two back, then the OLDEST ROW WE RETAIN.
    //
    // monerod's own locator ends at the genesis id; an anchored node has no
    // genesis and must not invent one, so ours ends at the deepest id it can
    // actually prove. A peer's find_blockchain_supplement takes the first id it
    // recognises, and every id we send is on the chain it is following, so the
    // splice succeeds; what we give up is the ability to be spliced by a peer
    // that shares NO block with our retained window, which is a peer we could
    // not sync from anyway.
    std::vector<Hash> locator() const override {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<Hash> out;
        if (rows_.empty()) return out;
        const std::uint64_t tip_h    = rows_.tip_height();
        const std::uint64_t oldest_h = rows_.oldest_height();
        std::uint64_t step = 1;
        std::uint64_t h    = tip_h;
        std::size_t   n    = 0;
        while (true) {
            if (const RowRecord* r = rows_.by_height(h)) out.push_back(r->row.id);
            if (h == oldest_h) break;
            ++n;
            if (n > 10) step *= 2;
            h = (h - oldest_h > step) ? (h - step) : oldest_h;
        }
        return out;
    }

    std::optional<ChainEntry> find_supplement(const std::vector<Hash>& peer_locator) const override {
        std::lock_guard<std::mutex> lk(mu_);
        if (rows_.empty()) return std::nullopt;
        std::optional<std::uint64_t> splice;
        for (const Hash& id : peer_locator) {
            const auto h = rows_.height_of(id);
            if (h) { splice = *h; break; }
        }
        if (!splice) return std::nullopt;   // no common block: the caller closes the peer

        ChainEntry e;
        e.start_height = *splice;
        e.total_height = rows_.tip_height() + 1;
        const RowRecord* t = rows_.tip();
        if (t) e.cumulative_difficulty_hint = t->row.cumulative_difficulty;
        for (std::uint64_t h = *splice; h <= rows_.tip_height(); ++h) {
            const RowRecord* r = rows_.by_height(h);
            if (!r) break;
            e.ids.push_back(r->row.id);
            e.weights_claimed_hint.push_back(r->row.block_weight);
            if (e.ids.size() >= MAX_CHAIN_ENTRY_IDS) break;
        }
        return e;
    }

    std::optional<BlockEntry> get_block_entry(const Hash& id, bool /*prune*/) const override {
        std::lock_guard<std::mutex> lk(mu_);
        const auto it = entries_.find(key_(id));
        if (it == entries_.end()) return std::nullopt;
        return it->second.entry;
    }

    // RC-CTX: the block blob of `id` from the bodies this index retains -- the
    // entry cache (connected blocks, including ones a reorg disconnected) or a
    // held alternative block's entry. Read-only; false when neither holds it.
    // The relay serves a receipt's Monero context (FB_GETCTX) from here, and
    // re-verifies every byte (id recomputed) before it uses one.
    bool block_blob_of(const Hash& id, std::vector<std::uint8_t>& out) const {
        std::lock_guard<std::mutex> lk(mu_);
        const auto it = entries_.find(key_(id));
        if (it != entries_.end() && !it->second.entry.block_blob.empty()) { out = it->second.entry.block_blob; return true; }
        if (const AltBlock* a = alt_.find(id); a && a->has_entry && !a->entry.block_blob.empty()) { out = a->entry.block_blob; return true; }
        return false;
    }

    // --- the settlement clock ------------------------------------------------------------
    Burial burial_of(const Hash& id) const {
        std::lock_guard<std::mutex> lk(mu_);
        return burial_locked_(id, opts_.burial_depth);
    }

    Burial burial_of(const Hash& id, std::uint64_t n) const {
        std::lock_guard<std::mutex> lk(mu_);
        return burial_locked_(id, n);
    }

    // The highest height whose block is buried N deep AND verified: the bin the
    // section 3 clock may account up to. 0 when there is no such height.
    std::uint64_t buried_frontier(std::uint64_t n) const {
        std::lock_guard<std::mutex> lk(mu_);
        if (rows_.empty() || n == 0) return 0;
        const std::uint64_t tip_h = rows_.tip_height();
        if (tip_h + 1 < n) return 0;
        const std::uint64_t by_depth = tip_h + 1 - n;
        const std::uint64_t frontier = view_.verified_frontier();
        const std::uint64_t anchor   = view_.anchor_height();
        const std::uint64_t verified = frontier > anchor ? frontier : anchor;
        return by_depth < verified ? by_depth : verified;
    }

    std::uint64_t buried_frontier() const { return buried_frontier(opts_.burial_depth); }

    // --- observability ---------------------------------------------------------------------
    const ReorgJournal& journal() const noexcept { return journal_; }
    std::uint64_t chain_entries_accepted() const { std::lock_guard<std::mutex> lk(mu_); return chain_entries_accepted_; }
    std::uint64_t chain_entries_refused()  const { std::lock_guard<std::mutex> lk(mu_); return chain_entries_refused_; }
    std::uint64_t bans() const { std::lock_guard<std::mutex> lk(mu_); return bans_; }
    std::uint64_t orphans_parked() const { std::lock_guard<std::mutex> lk(mu_); return orphans_; }
    std::size_t   alt_size() const { std::lock_guard<std::mutex> lk(mu_); return alt_.size(); }

    // Unknown-fork fuse: blocks refused because their major_version is above
    // MAX_IMPLEMENTED_HF_VERSION (never charged to the sender), how many of
    // those did not attach to a block we hold, and a copy of the fuse itself.
    std::uint64_t unknown_fork_blocks() const { std::lock_guard<std::mutex> lk(mu_); return unknown_fork_blocks_; }
    std::uint64_t unknown_fork_unattached() const { std::lock_guard<std::mutex> lk(mu_); return unknown_fork_unattached_; }
    HfFuse        hf_fuse() const { std::lock_guard<std::mutex> lk(mu_); return view_.state().fuse(); }
    // FORK-FUSE-2: the watch (suspect / tripped, distinct peers, trips, clears),
    // the bounded set of above-version block ids the want list no longer hands
    // to the sync driver, and how many times it held one back.
    UnknownForkWatch unknown_fork_watch() const { std::lock_guard<std::mutex> lk(mu_); return uf_watch_; }
    std::size_t   unknown_fork_ids() const { std::lock_guard<std::mutex> lk(mu_); return uf_ids_.size(); }
    std::uint64_t unknown_fork_refetch_held() const { std::lock_guard<std::mutex> lk(mu_); return uf_refetch_held_; }
    // FORK-FUSE-3: has this peer sent an above-version block and not since
    // served a v16 block that connected? The sync driver's back-off predicate.
    bool          unknown_fork_peer_flagged(const PeerRef& p) const {
        std::lock_guard<std::mutex> lk(mu_);
        return uf_peers_flagged_.count(peer_key_(p)) != 0;
    }
    std::size_t   unknown_fork_peers_flagged() const { std::lock_guard<std::mutex> lk(mu_); return uf_peers_flagged_.size(); }
    bool          unknown_fork_id_known(const Hash& id) const {
        std::lock_guard<std::mutex> lk(mu_);
        return uf_ids_.count(key_of_(id)) != 0;
    }

    // FORK-FUSE-2 poll: driven from the verify thread's periodic tick with a
    // monotone millisecond clock (like check_own_fork). Trips the unknown-fork
    // gate on quorum + stall, clears it on a 2-block v16 extension, and says so
    // loudly either way. Returns the event.
    UnknownForkWatch::Event check_unknown_fork(std::uint64_t now_ms) {
        UnknownForkWatch::Event ev = UnknownForkWatch::Event::None;
        {
            std::lock_guard<std::mutex> lk(mu_);
            const std::uint64_t tip_h = rows_.empty() ? 0 : rows_.tip_height();
            ev = uf_watch_.poll(now_ms, tip_h);
            view_.state().set_unknown_fork_tripped(uf_watch_.tripped());
            if (ev == UnknownForkWatch::Event::Tripped) {
                std::fprintf(stderr,
                    "[HF-FUSE] UNKNOWN FORK TRIPPED: %zu distinct peers sent blocks of major_version "
                    "up to %u (above the %u this build implements) and the v16 tip %llu has not "
                    "extended for %llu s. Templates and tx admission WITHDRAWN; no peer penalised. "
                    "Roll the code forward (clears if v16 extends the tip by %llu).\n",
                    uf_watch_.distinct_peers(), static_cast<unsigned>(uf_watch_.highest_version()),
                    static_cast<unsigned>(MAX_IMPLEMENTED_HF_VERSION),
                    static_cast<unsigned long long>(tip_h),
                    static_cast<unsigned long long>(uf_watch_.stalled_ms() / 1000),
                    static_cast<unsigned long long>(UNKNOWN_FORK_CLEAR_BLOCKS));
                std::fflush(stderr);
            } else if (ev == UnknownForkWatch::Event::Cleared) {
                uf_ids_.clear();
                uf_ids_order_.clear();
                std::fprintf(stderr,
                    "[HF-FUSE] UNKNOWN FORK CLEARED: the v16 chain extended the tip to %llu (trip at "
                    "%llu). Templates and tx admission RESUMED.\n",
                    static_cast<unsigned long long>(tip_h),
                    static_cast<unsigned long long>(uf_watch_.trip_tip()));
                std::fflush(stderr);
            }
        }
        flush_events_();
        return ev;
    }

    // c2pool#1551: the same-height candidates this node HOLDS but has not
    // adopted. The settlement accounting above needs them to see a race at all
    // -- in the branch where our own block stays best, the rival produces no
    // mainchain event, and an accounting layer fed only by that stream would
    // credit as if the height had been uncontested.
    struct AltTip {
        Hash          id{};
        Hash          prev_id{};
        std::uint64_t height    = 0;
        bool          own_mined = false;
        bool          resolved  = false;   // difficulty computed on its own branch
    };
    std::vector<AltTip> alt_tips() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<AltTip> out;
        out.reserve(alt_.size());
        alt_.for_each([&out](const AltBlock& b) {
            out.push_back(AltTip{b.id, b.prev_id, b.height, b.own_mined, b.resolved});
        });
        return out;
    }
    PowGate&      pow_gate() noexcept { return gate_; }

    // Ids the index wants fetched: what a chain entry told us we are missing,
    // plus anything a refused reorg needs before it can be retried. The sync
    // driver reads this; the index never schedules its own network traffic
    // beyond the single hint request above.
    //
    // Ids whose BYTES we already hold are filtered out here rather than pruned
    // from the lists: `wanted_` is replaced wholesale by the next chain entry
    // and `refetch_` is deliberately a standing want list, so neither is a
    // record of what is still missing. Without the filter the driver re-asked
    // for a block it was already holding every refetch_reask_ms, forever --
    // which is what a parked branch looks like from the outside, and what made
    // "we are not making progress" indistinguishable from "the peer is not
    // answering". Membership is not enough: a bodiless fluffy announcement and
    // a row whose body has been evicted are both "known" and both still need
    // fetching, so the test is whether we have bytes we could re-apply.
    //
    // THE FETCH WINDOW. Only the part of `wanted_` within fetch_window_() of
    // our tip is handed out: whatever we fetch beyond what the alt pool can
    // hold while the gap below it fills is fetched to be evicted, and the
    // eviction takes the blocks nearest the tip (the ones we asked for first).
    // As the tip moves, the window moves with it.
    std::vector<Hash> refetch_wanted() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<Hash> out;
        out.reserve(wanted_.size() + refetch_.size());
        // An entry id that has since connected is done with, whether or not
        // its body is still cached (the entry cache is smaller than a 2048-id
        // entry); one below the retained rows can no longer be used at all.
        std::uint64_t limit = rows_.tip_height() + fetch_window_();
        // COLD-BOOT-2: never download past the consumer's booked frontier + window.
        if (const std::uint64_t ceil = consumer_ceiling_locked_(); ceil != 0 && ceil < limit) limit = ceil;
        // COLD-BOOT-3: the consumer's mainchain-event queue is full enough that
        // more bulk download would overflow it -- hand out nothing above the tip
        // until it drains (backpressure without blocking the verify thread).
        if (download_hold_ && download_hold_()) limit = rows_.tip_height();
        for (std::size_t k = 0; k < wanted_.size(); ++k) {
            if (wanted_heights_[k] > limit) break;
            if (wanted_heights_[k] < rows_.oldest_height() || rows_.contains(wanted_[k])) continue;
            if (uf_id_held_locked_(wanted_[k])) continue;
            if (!have_body_locked_(wanted_[k])) out.push_back(wanted_[k]);
        }
        for (const Hash& id : refetch_)
            if (!have_body_locked_(id) && !contains_hash_(out, id) && !uf_id_held_locked_(id))
                out.push_back(id);
        return out;
    }

    // #1680: fluffy blocks parked WITH a body blob but WITHOUT their
    // transactions (bodies_missing). have_body_locked_() reports these as
    // "have body" (they hold the bodiless blob), so refetch_wanted() omits them;
    // and on_chain_entry skips any id already in alt_. Nothing in the ordinary
    // paths ever re-asks for one, so a missing-tx reply lost to the DoS bucket
    // (or a disconnect) would strand the park forever and freeze the node one
    // block behind. This is a DELIBERATELY SEPARATE list from refetch_wanted():
    // the driver gives it its own grace timer and re-asks via GET_OBJECTS, so an
    // honest in-flight 2009 reply is not raced by a duplicate whole-block fetch
    // on every non-empty block (which would double inbound block bytes on
    // mainnet, where every non-empty fluffy block parks once). The park is
    // erased on connect, so this list empties itself.
    //
    // Every bodiless park carries the flag, including a push parked before its
    // parent was known (the near-tip stall: such a park used to be resolved on
    // the parent's arrival WITHOUT the flag and was then invisible to every
    // re-ask path). Only RESOLVED parks are listed: an orphan whose parent we
    // have never seen has not been through the proof-of-work gate, so asking
    // for its bytes would let anyone who can push a bogus blob make us issue
    // GET_OBJECTS on a timer. It is listed the moment its parent lands.
    std::vector<Hash> bodies_wanted() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<Hash> out;
        alt_.for_each([&out](const AltBlock& b) {
            if (b.bodies_missing && b.resolved) out.push_back(b.id);
        });
        // COLD-BOOT: best-chain bodies the settlement booking asked back
        // (want_body_for_booking). Same re-ask-by-id path (GET_OBJECTS, any
        // peer, the driver's grace + re-ask timer); these are ids OUR OWN best
        // chain connected, so asking for them is not the abuse surface the
        // RESOLVED-only rule above guards.
        for (const Hash& id : booking_wanted_)
            if (!have_body_locked_(id) && !contains_hash_(out, id)) out.push_back(id);
        return out;
    }

    // ---- COLD-BOOT: body re-read for the settlement booking ----------------------------
    // The coinbase-authority booking decodes EVERY best-chain block from its
    // body (main: fetch_decode -> CbaBlockSource -> block_blob_of). A node that
    // boots from an anchor older than the entry cache downloads the whole gap
    // before its first booking, so the oldest bodies are evicted before they are
    // booked -- and nothing ever fetched them again (the booking HELD forever,
    // the cursor stuck, the lane suspended on lag). This is the safety net: the
    // booking asks for the body back, the sync driver re-asks the network for
    // it by id (bodies_wanted), and offer_block() re-caches it when it arrives.
    // The cache keeps its bounds; the restored body is simply the newest entry,
    // so it survives until the booking reads it. `ahead` also asks for the next
    // best-chain bodies above it that are missing (chain-ordered booking will
    // want them next), so a gap is refetched in batches, not one per round trip.
    // The bytes are authenticated by the id itself (the id is recomputed from
    // the blob in evaluate_block), so a restored body is byte-identical to the
    // one that connected. Bounded: at most kBookingWantedMax ids outstanding.
    static constexpr std::size_t kBookingWantedMax = 256;
    std::size_t want_body_for_booking(const Hash& id, std::size_t ahead = 64) {
        std::lock_guard<std::mutex> lk(mu_);
        if (have_body_locked_(id)) return 0;
        std::size_t added = 0;
        auto want = [&](const Hash& h) {
            if (have_body_locked_(h) || contains_hash_(booking_wanted_, h)) return;
            booking_wanted_.push_back(h);
            ++added;
            while (booking_wanted_.size() > kBookingWantedMax) booking_wanted_.erase(booking_wanted_.begin());
        };
        want(id);
        if (const auto h = rows_.height_of(id)) {
            for (std::size_t k = 1; k < ahead; ++k) {
                const RowRecord* r = rows_.by_height(*h + k);
                if (!r) break;
                want(r->row.id);
            }
        }
        booking_refetch_asked_ += added;
        return added;
    }
    struct BookingRefetchStats { std::uint64_t asked = 0, restored = 0; std::size_t outstanding = 0; };
    BookingRefetchStats booking_refetch_stats() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::size_t n = 0;
        for (const Hash& id : booking_wanted_) if (!have_body_locked_(id)) ++n;
        return BookingRefetchStats{booking_refetch_asked_, booking_bodies_restored_, n};
    }

    // ---- COLD-BOOT-2: the consumer (settlement) paces the catch-up download --------------
    // A node booting from an old anchor used to download the WHOLE post-anchor
    // gap before the settlement consumed any of it: rows older than the row
    // retention were trimmed (the canonical test then had nothing to answer
    // with) and bodies older than the entry cache evicted, before they were
    // booked. With options.consumer_window > 0 the consumer reports the height
    // up to which it has booked (its finalize cursor) and the chain-entry
    // download is handed out only up to that frontier + window; the ceiling
    // moves as the settlement books, so the gap is downloaded and booked in
    // bounded batches, in chain order. Until the first report the frontier is
    // the anchor (a fresh boot books from there). Pushed tip blocks and the
    // re-ask lists (refetch_, bodies_wanted) are not paced: only the bulk
    // download. Pure pacing: which blocks connect, and in what order, is
    // unchanged.
    void set_consumer_frontier(std::uint64_t h) {
        std::lock_guard<std::mutex> lk(mu_);
        const bool first = !consumer_frontier_set_;
        // COLD-BOOT-3 (stall latch): a frontier that does not move while the
        // download is held at the ceiling is a HELD cursor, not a slow booking.
        if (!first && h == consumer_frontier_ && consumer_held_locked_()) ++consumer_stall_n_;
        else consumer_stall_n_ = 0;
        consumer_frontier_ = h;
        consumer_frontier_set_ = true;
        if (pacing_lifted_ || opts_.consumer_window == 0) return;
        // (resume latch) the snapshot this process resumed from is already past
        // the ceiling: the previous process followed the chain past a held
        // cursor. Pacing it again would freeze the node below its own snapshot.
        if (first && resumed_tip_ != 0 && resumed_tip_ > h + opts_.consumer_window) {
            lift_pacing_locked_("snapshot resume at " + std::to_string(resumed_tip_) + " is already past the ceiling " +
                                std::to_string(h + opts_.consumer_window) + " (frontier " + std::to_string(h) + ")");
            return;
        }
        if (opts_.consumer_stall_reports && consumer_stall_n_ >= opts_.consumer_stall_reports)
            lift_pacing_locked_("the consumer frontier is HELD at " + std::to_string(h) + " (" + std::to_string(consumer_stall_n_) +
                                " reports without progress while the download waited at the ceiling " +
                                std::to_string(h + opts_.consumer_window) + ")");
    }
    // COLD-BOOT-3: the catch-up pacing was lifted for the rest of this process
    // (why; empty = still pacing, or pacing off). Once lifted it never re-arms.
    bool consumer_pacing_lifted() const { std::lock_guard<std::mutex> lk(mu_); return pacing_lifted_; }
    std::string consumer_pacing_lifted_why() const { std::lock_guard<std::mutex> lk(mu_); return pacing_lifted_why_; }
    // COLD-BOOT-3: the consumer's event queue asks the bulk download to wait
    // (refetch_wanted hands out nothing above the tip while this answers true).
    // Called under the index lock: it must not take the index lock itself.
    void set_download_hold(std::function<bool()> fn) {
        std::lock_guard<std::mutex> lk(mu_);
        download_hold_ = std::move(fn);
    }
    std::uint64_t consumer_ceiling() const {
        std::lock_guard<std::mutex> lk(mu_);
        return consumer_ceiling_locked_();
    }
    // True while the download is paused at the ceiling (the tip reached it and
    // the index is not yet synced): the consumer must book before more arrives.
    bool consumer_held() const {
        std::lock_guard<std::mutex> lk(mu_);
        return consumer_held_locked_();
    }

    // The state view, for consumers that need the consensus numbers themselves
    // (the parity oracle compares them field by field). Read-only by intent.
    const ChainStateView& view() const noexcept { return view_; }

    // See ChainStateView::reseat_rct_output_count. Under the index lock; the
    // node calls it on the verify thread right after a resume, before any
    // block can connect.
    void reseat_rct_output_count(std::uint64_t n) {
        std::lock_guard<std::mutex> lk(mu_);
        view_.reseat_rct_output_count(n);
    }

    // --- persistence ------------------------------------------------------------------------
    // A snapshot is taken `snapshot_depth` blocks BELOW the tip, and carries the
    // bodies of the blocks above it. Resume therefore re-applies those few
    // blocks through the ordinary consensus path -- with their recorded
    // pow_verified flags, so RandomX is not re-run -- and lands with a rollback
    // horizon instead of a frozen one. Restoring AT the tip would be simpler and
    // would make the resumed node unable to reorg at all until it had connected
    // new blocks, which is precisely the situation a node restarted during a
    // reorg finds itself in.
    bool save_snapshot(std::vector<std::uint8_t>& out, std::string& why) const {
        std::lock_guard<std::mutex> lk(mu_);
        return save_snapshot_locked_(out, why);
    }

    bool load_snapshot(const std::vector<std::uint8_t>& in, std::string& why) {
        bool ok;
        {
            std::lock_guard<std::mutex> lk(mu_);
            ok = load_snapshot_locked_(in, why);
        }
        flush_events_();
        return ok;
    }

private:
    using Key = std::string;

    static Key key_(const Hash& h) {
        return Key(reinterpret_cast<const char*>(h.data()), h.size());
    }

    struct CachedEntry {
        BlockEntry        entry;
        std::vector<Hash> tx_hashes;
        std::uint64_t     bytes = 0;
    };

    // One connected best-chain block's contribution to the mined oracle.
    struct MinedRec {
        std::uint64_t    height = 0;
        Hash             block_id{};
        std::vector<Key> txs;
        std::vector<Key> kis;
    };

    // =====================================================================================
    // offering a block
    // =====================================================================================
    // FORK-FUSE-3: every offer goes through here so a peer that served an
    // above-version block is unflagged the moment it serves a v16 block that
    // connects (to the best chain or as a resolved alt candidate).
    OfferResult offer_locked_(const PeerRef* peer, BlockEntry entry, bool own_mined) {
        OfferResult r = offer_eval_locked_(peer, std::move(entry), own_mined);
        if (peer && r.eval == EvalStatus::Ok
            && (r.outcome == OfferOutcome::Connected || r.outcome == OfferOutcome::Reorged
                || r.outcome == OfferOutcome::StoredAsAlt))
            uf_peers_flagged_.erase(peer_key_(*peer));
        return r;
    }

    OfferResult offer_eval_locked_(const PeerRef* peer, BlockEntry entry, bool own_mined) {
        OfferResult r;

        EvaluatedBlock ev;
        std::string    why;
        r.eval = evaluate_block(entry, ev, why);
        if (r.eval == EvalStatus::UnknownFork)
            return unknown_fork_locked_(peer, entry, ev, std::move(why));
        if (r.eval != EvalStatus::Ok) {
            r.outcome    = OfferOutcome::Rejected;
            r.peer_fault = true;
            r.fault      = PeerFault::BadData;
            r.why        = why;
            penalize_locked_(peer, PeerFault::BadData, why);
            return r;
        }

        r.id = ev.input.identity.id;

        // COLD-BOOT: a body the settlement booking asked back
        // (want_body_for_booking). The id was recomputed from these bytes, so
        // they are the block that connected; re-cache them (bounded cache,
        // newest entry) whatever becomes of the offer below -- it is normally a
        // Duplicate of a best-chain row, or below the retained rows.
        if (ev.input.bodies_complete && contains_hash_(booking_wanted_, r.id)) {
            erase_hash_(booking_wanted_, r.id);
            if (entries_.find(key_(r.id)) == entries_.end()) {
                cache_entry_locked_(r.id, entry, ev.input.parsed.tx_hashes);
                ++booking_bodies_restored_;
            }
        }

        if (rows_.contains(r.id)) {
            r.outcome = OfferOutcome::Duplicate;
            r.height  = rows_.height_of(r.id).value_or(0);
            r.why     = "already on the best chain";
            return r;
        }

        // OUR OWN block: never adopt one every monerod would refuse. A block
        // carrying a tx already mined in the chain it extends, a key image
        // already spent there, or the same tx / key image twice, is invalid on
        // every node that has the history -- and a levin-only node cannot hear
        // their refusal, so PREFER-OWN would build on it forever (the
        // publish-arm verify, 8b2efacf at h=513). Hygiene on our own output,
        // not a rule applied to anyone else's blocks.
        if (own_mined) {
            if (abandoned_own_.count(key_(r.id))) {
                r.outcome = OfferOutcome::Rejected;
                r.why     = "own block was abandoned by the own-fork liveness guard";
                return r;
            }
            std::string bad;
            const RowRecord* mp = rows_.by_id(ev.input.parsed.header.prev_id);
            if (!own_block_hygiene_locked_(ev, mp ? std::optional<std::uint64_t>(mp->row.height)
                                                  : std::nullopt, bad)) {
                ++own_invalid_refused_;
                r.outcome = OfferOutcome::Rejected;
                r.height  = mp ? mp->row.height + 1 : ev.input.coinbase.height;
                r.why     = "own block refused: " + bad;
                return r;
            }
        }

        // A bodiless re-announcement (a fluffy push) of a block we already hold
        // WITH its transactions must not replace the complete copy: every path
        // below re-inserts, and trading bodies for a bare blob is how a block
        // that could connect becomes one that cannot. Carry on with the copy
        // we hold, so a re-push still gets the chance to connect it.
        if (!ev.input.bodies_complete) {
            if (const AltBlock* have = alt_.find(r.id);
                have && have->has_entry && !have->bodies_missing) {
                BlockEntry     held = have->entry;
                EvaluatedBlock hev;
                std::string    hw;
                if (evaluate_block(held, hev, hw) == EvalStatus::Ok && hev.input.bodies_complete) {
                    entry = std::move(held);
                    ev    = std::move(hev);
                }
            }
        }
        // Every park below records whether it holds the transactions. The flag
        // is what bodies_wanted() lists and what the switch refuses on, so it
        // has to be true for EVERY bodiless park, not only the fast-path one.
        const bool bodiless = !ev.input.bodies_complete;
        // It arrived with its bodies: whatever becomes of it now, asking for it
        // again is pointless. Without this the standing refetch list kept every
        // parent it ever named, and once a connected block's body left the
        // entry cache (and its row the retained window) the driver fetched it
        // AGAIN -- to be parked as an orphan below the window.
        if (!bodiless) erase_hash_(refetch_, r.id);

        const Hash prev = ev.input.parsed.header.prev_id;
        const std::uint8_t major = static_cast<std::uint8_t>(ev.input.parsed.header.major_version);
        const std::uint8_t rules = hf_rules_version(major);

        // Where does it attach?
        const RowRecord* main_parent = rows_.by_id(prev);
        const AltBlock*  alt_parent  = alt_.find(prev);

        if (!main_parent && !alt_parent) {
            // Unknown parent. Park it: it may be the tip of a branch we cannot
            // see yet, and throwing it away would mean re-fetching it after the
            // chain entry that explains it arrives.
            if (const AltBlock* have = alt_.find(r.id)) {
                // Already parked. A copy that ADDS the bodies we were missing
                // (or bytes we never had) replaces the park in place, keeping
                // everything already learned about it; anything else is a
                // duplicate. Dropping the complete copy here would leave the
                // park bodiless for good.
                if (have->has_entry && !(have->bodies_missing && !bodiless)) {
                    r.outcome = OfferOutcome::Duplicate;
                    r.why     = "already parked";
                    return r;
                }
                AltBlock up       = *have;
                up.entry          = std::move(entry);
                up.has_entry      = true;
                up.bodies_missing = bodiless;
                alt_.insert(std::move(up));
                r.outcome = OfferOutcome::ParkedOrphan;
                r.height  = ev.input.coinbase.height;
                r.why     = "parent is not in the index yet (park completed)";
                return r;
            }
            // monerod's "Received new block while syncing, ignored": while we
            // are behind, a block claiming a height further above our tip than
            // the alt pool can hold is not parked. Parking it evicts a block we
            // need next, and its unknown parent starts a backward walk of
            // one GET_OBJECTS per round trip from the network tip -- the refetch
            // storm behind 45k-76k orphans on the mainnet dry run. The chain
            // entry fetch reaches it in order; once synced, pushes park as
            // before.
            if (!synced_ && !own_mined && opts_.alt_max_blocks && !rows_.empty()
                && ev.input.coinbase.height > rows_.tip_height() + opts_.alt_max_blocks) {
                r.outcome = OfferOutcome::Rejected;
                r.height  = ev.input.coinbase.height;
                r.why     = "received a block far above our tip while syncing; ignored";
                return r;
            }
            // Nor, ever, one claiming a height below the retained rows: no
            // branch through it can be adopted (the switch refuses a fork point
            // older than the window as OutOfWindow), so holding it only takes a
            // slot from a block that can.
            if (!own_mined && !rows_.empty()
                && ev.input.coinbase.height < rows_.oldest_height()) {
                r.outcome = OfferOutcome::Rejected;
                r.height  = ev.input.coinbase.height;
                r.why     = "parent unknown and below the retained window; ignored";
                return r;
            }
            AltBlock b;
            b.id             = r.id;
            b.prev_id        = prev;
            b.height         = ev.input.coinbase.height;   // the block's own claim
            b.resolved       = false;
            b.own_mined      = own_mined;
            b.entry          = std::move(entry);
            b.has_entry      = true;
            b.bodies_missing = bodiless;
            b.first_seen_seq = ++seq_;
            if (peer) b.source = *peer;
            alt_.insert(std::move(b));
            ++orphans_;
            r.outcome = OfferOutcome::ParkedOrphan;
            r.height  = ev.input.coinbase.height;
            r.why     = "parent is not in the index yet";
            remember_refetch_(prev);   // bounded, like every other refetch entry
            return r;
        }

        const std::uint64_t parent_height = main_parent ? main_parent->row.height
                                                        : alt_parent->height;
        const U128 parent_cumdiff = main_parent ? main_parent->row.cumulative_difficulty
                                                : alt_parent->cumulative_difficulty;
        const bool parent_resolved = main_parent ? true : alt_parent->resolved;
        r.height = parent_height + 1;

        // The difficulty this block had to beat, on ITS branch.
        U128 difficulty{};
        if (!branch_difficulty_locked_(prev, parent_height, rules, difficulty, why)) {
            // We cannot see far enough back to judge it YET. Not a fault, not a
            // rejection -- and, until now, not a park either: this path SAID
            // ParkedOrphan and then returned without storing the block, without
            // asking for anything, and without a line in the journal. The block
            // was destroyed. Every re-delivery hit the same return, so the
            // fork-point child of a rival branch could be handed to this node
            // forever and never be held once; AltPool::heaviest() never had a
            // candidate, the fork choice never ran, and the node sat on its own
            // tip while its peers moved on. Park it for real, so that the moment
            // the missing piece lands -- the parent resolving, or the chain
            // growing past the fork point -- resolve_descendants_locked_ picks
            // it up and the fork choice finally gets to see it.
            //
            // Unresolved and un-adoptable, deliberately: it has no cumulative
            // difficulty on its branch, heaviest() skips it, and the fail-closed
            // bound in the switch refuses any branch containing it. Holding
            // bytes is the whole of what happens here.
            if (const AltBlock* have = alt_.find(r.id);
                have && have->has_entry && !(have->bodies_missing && !bodiless)) {
                r.outcome = OfferOutcome::Duplicate;
                r.why     = "already parked, unjudgeable: " + why;
                return r;
            }
            const bool was_parked = alt_.contains(r.id);
            AltBlock b;
            b.id             = r.id;
            b.prev_id        = prev;
            b.height         = r.height;
            b.resolved       = false;
            b.adoptable      = false;
            b.own_mined      = own_mined;
            b.entry          = std::move(entry);
            b.has_entry      = true;
            b.bodies_missing = bodiless;
            b.first_seen_seq = ++seq_;
            if (peer) b.source = *peer;
            alt_.insert(std::move(b));
            if (!was_parked) ++orphans_;
            r.outcome = OfferOutcome::ParkedOrphan;
            r.why     = why;
            return r;
        }

        // Proof of work, at that difficulty, with the seed from its own branch.
        const PowGate::Result pw =
            gate_.check(r.height, prev, ev.input.identity.hashing_blob, difficulty);
        r.pow = pw.verdict;
        if (pw.verdict == PowVerdict::BelowTarget) {
            r.outcome    = OfferOutcome::Rejected;
            r.peer_fault = true;
            r.fault      = PeerFault::BadPow;
            r.why        = "proof of work does not meet the difficulty we computed";
            alt_.erase_branch(r.id);
            penalize_locked_(peer, PeerFault::BadPow, r.why);
            return r;
        }
        const bool pow_ok = pow_verdict_is_verified(pw.verdict);
        if (opts_.require_pow && !pow_ok && pw.verdict != PowVerdict::Skipped) {
            // Fail-closed: hold it rather than build on work we did not check.
            AltBlock b;
            b.id             = r.id;
            b.prev_id        = prev;
            b.height         = r.height;
            b.difficulty     = difficulty;
            b.resolved       = parent_resolved;
            if (parent_resolved) b.cumulative_difficulty = u128_add(parent_cumdiff, difficulty);
            b.own_mined      = own_mined;
            b.adoptable      = false;   // the gate has not passed it
            b.entry          = std::move(entry);
            b.has_entry      = true;
            b.bodies_missing = bodiless;
            b.first_seen_seq = ++seq_;
            if (peer) b.source = *peer;
            alt_.insert(std::move(b));
            r.outcome = OfferOutcome::StoredAsAlt;
            r.why     = std::string("held: proof of work not checkable yet (")
                      + to_string(pw.verdict) + ")";
            return r;
        }

        // --- the fast path: it extends the best chain -------------------------------
        const RowRecord* tip = rows_.tip();
        if (tip && prev == tip->row.id) {
            const ConnectOutcomeLocal co = connect_to_tip_locked_(entry, ev, pow_ok, pw.pow_hash,
                                                                  own_mined, why);
            r.connect = co.status;
            if (co.status == ConnectStatus::Ok) {
                alt_.erase(r.id);
                // A block that arrived BEFORE its parent was parked in the alt
                // pool, and until now nothing ever revisited it: the branch path
                // below resolves descendants, the fast path did not. So a node
                // that was handed a block out of order kept it forever and
                // stopped following the tip -- while its peers went on relaying
                // blocks it had already been given.
                //
                // This is not a rare case, it is EVERY COLD START: monerod sends
                // its top block to a peer whose advertised height is behind its
                // own (process_payload_sync_data), so the first block a syncing
                // node receives is normally one it cannot connect yet. Found by
                // the M0 assembly on a live regtest run, where the index stopped
                // at the height it had backfilled to and four pushed blocks sat
                // parked behind it.
                resolve_descendants_locked_(r.id);
                connect_parked_children_locked_();
                // And then ask the fork choice, because the two calls above can
                // have RESOLVED a branch that was unjudgeable a moment ago: a
                // block whose difficulty window only became assemblable once the
                // chain grew, or whose parent only just landed. The branch path
                // runs the fork choice on every offer; this one did not, so a
                // branch that became heavier as a side effect of an ordinary
                // extend would sit resolved-and-ignored until the next block
                // happened to arrive on it. maybe_switch_locked_() is a no-op
                // when nothing outweighs the tip, so the cost is one comparison.
                const bool switched = maybe_switch_locked_();
                r.outcome = switched && !rows_.contains(r.id) ? OfferOutcome::StoredAsAlt
                                                              : OfferOutcome::Connected;
                return r;
            }
            if (co.status == ConnectStatus::BodiesMissing) {
                AltBlock b;
                b.id             = r.id;
                b.prev_id        = prev;
                b.height         = r.height;
                b.difficulty     = difficulty;
                b.cumulative_difficulty = u128_add(parent_cumdiff, difficulty);
                b.resolved       = true;
                b.own_mined      = own_mined;
                b.adoptable      = false;   // no bodies, so nothing is judgeable yet
                b.entry          = std::move(entry);
                b.has_entry      = true;
                b.bodies_missing = true;     // #1680: driver re-asks if the reply is lost
                b.first_seen_seq = ++seq_;
                if (peer) b.source = *peer;
                alt_.insert(std::move(b));
                r.outcome = OfferOutcome::NeedsBodies;
                r.why     = why;
                return r;
            }
            r.outcome = OfferOutcome::Rejected;
            r.why     = why;
            if (connect_status_is_peer_fault(co.status)) {
                r.peer_fault = true;
                r.fault      = PeerFault::BadData;
                penalize_locked_(peer, PeerFault::BadData, why);
            }
            return r;
        }

        // --- the branch path -----------------------------------------------------------
        AltBlock b;
        b.id             = r.id;
        b.prev_id        = prev;
        b.height         = r.height;
        b.difficulty     = difficulty;
        b.resolved       = parent_resolved;
        if (parent_resolved) b.cumulative_difficulty = u128_add(parent_cumdiff, difficulty);
        b.pow_verified   = pow_ok;
        b.adoptable      = pow_ok || pw.verdict == PowVerdict::Skipped;
        b.own_mined      = own_mined;
        b.entry          = std::move(entry);
        b.has_entry      = true;
        b.bodies_missing = bodiless;   // listed by bodies_wanted(); the switch refuses it
        b.first_seen_seq = ++seq_;
        if (peer) b.source = *peer;
        alt_.insert(std::move(b));

        resolve_descendants_locked_(r.id);

        const bool switched = maybe_switch_locked_();
        r.outcome = switched && rows_.contains(r.id) ? OfferOutcome::Reorged
                                                     : OfferOutcome::StoredAsAlt;
        if (r.outcome == OfferOutcome::StoredAsAlt)
            r.why = "kept as an alternative branch";
        return r;
    }

    struct ConnectOutcomeLocal {
        ConnectStatus status = ConnectStatus::Ok;
        ChainRow      row{};
    };

    ConnectOutcomeLocal connect_to_tip_locked_(const BlockEntry& entry, const EvaluatedBlock& ev,
                                               bool pow_ok, const Hash& pow_hash,
                                               bool own_mined, std::string& why) {
        ConnectOutcomeLocal out;
        const std::uint64_t now = clock_ ? clock_() : 0;
        const ChainStateView::ConnectOutcome co =
            view_.connect(entry, pow_ok, now, own_mined, why);
        out.status = co.connect;
        if (!co.ok) return out;

        out.row = co.row;
        rows_.push(co.row, own_mined, pow_hash);
        push_long_mirror_(co.row.long_term_weight);
        cache_entry_locked_(co.row.id, entry, ev.input.parsed.tx_hashes);
        update_synced_locked_();
        return out;
    }

    // =====================================================================================
    // difficulty on a branch
    // =====================================================================================
    // The window is the 735 rows ending at the candidate's PARENT, taken from
    // the main chain below the fork point and from the branch above it. When the
    // window cannot be assembled -- the fork is older than the retained rows --
    // the answer is "unjudgeable", never a guess.
    bool branch_difficulty_locked_(const Hash& parent_id, std::uint64_t parent_height,
                                   std::uint8_t rules_version, U128& out,
                                   std::string& why) const {
        // The common case -- a block extending the tip -- is answered by the
        // consensus state's own window, which is the authority: it is seeded
        // whole from the anchor and rolled forward and backward exactly. Only a
        // branch that leaves the tip needs the window rebuilt.
        const RowRecord* tip = rows_.tip();
        if (tip && parent_id == tip->row.id) {
            out = view_.state().difficulty_window().next_difficulty(rules_version);
            return true;
        }

        // Collect the branch part first, walking down from the parent while it
        // is an alt block.
        std::vector<DifficultyRow> upper;   // newest first while collecting
        Hash          cursor = parent_id;
        std::uint64_t h      = parent_height;
        std::size_t   guard  = 0;
        while (const AltBlock* b = alt_.find(cursor)) {
            if (!b->resolved) {
                why = "branch difficulty is unknown until the parent resolves";
                return false;
            }
            upper.push_back(DifficultyRow{alt_timestamp_(*b), b->cumulative_difficulty});
            cursor = b->prev_id;
            if (h == 0) break;
            --h;
            if (++guard > DIFFICULTY_BLOCKS_COUNT + opts_.max_reorg_depth) {
                why = "branch is longer than the bounded horizon";
                return false;
            }
            if (upper.size() >= DIFFICULTY_BLOCKS_COUNT) break;
        }

        std::vector<DifficultyRow> window;
        if (upper.size() < DIFFICULTY_BLOCKS_COUNT) {
            const RowRecord* anchor_row = rows_.by_id(cursor);
            if (!anchor_row) {
                why = "the branch does not reach the retained best chain";
                return false;
            }
            const std::size_t need = DIFFICULTY_BLOCKS_COUNT - upper.size();
            // allow_young_chain: a chain shorter than the window is not a chain
            // we cannot see far enough back on -- it is a chain with nothing
            // more to see. The tip fast path above already answers from a short
            // window (the state's own), so refusing here is the branch path
            // disagreeing with the tip path about the same rows. The store
            // grants it only when it holds the chain from height 0.
            if (!rows_.difficulty_window_ending_at(anchor_row->row.height, need, window,
                                                   /*allow_young_chain=*/true)) {
                why = "the retained window does not reach the fork point";
                return false;
            }
        }
        for (auto it = upper.rbegin(); it != upper.rend(); ++it) window.push_back(*it);
        if (window.size() > DIFFICULTY_BLOCKS_COUNT)
            window.erase(window.begin(),
                         window.begin() + static_cast<long>(window.size() - DIFFICULTY_BLOCKS_COUNT));

        DifficultyWindow dw;
        dw.seed(window);
        out = dw.next_difficulty(rules_version);
        return true;
    }

    // An alt block's timestamp: parsed from its own blob. Kept out of AltBlock
    // as a separate step so the pool stays a pool of bytes plus work, and the
    // parse happens once here rather than at every insert.
    std::uint64_t alt_timestamp_(const AltBlock& b) const {
        const auto it = alt_timestamps_.find(key_(b.id));
        if (it != alt_timestamps_.end()) return it->second;
        ParsedBlock pb;
        if (parse_block(b.entry.block_blob, pb) != BlockParseStatus::Ok) return 0;
        alt_timestamps_[key_(b.id)] = pb.header.timestamp;
        return pb.header.timestamp;
    }

    // A parked block's descendants can be resolved once it has a cumulative
    // difficulty of its own.
    void resolve_descendants_locked_(const Hash& id) {
        std::vector<Hash> stack{id};
        std::size_t guard = 0;
        while (!stack.empty() && ++guard < 4096) {
            const Hash cur = stack.back();
            stack.pop_back();
            const AltBlock* parent = alt_.find(cur);
            const RowRecord* main_parent = rows_.by_id(cur);
            if (!parent && !main_parent) continue;
            const bool          resolved = parent ? parent->resolved : true;
            const std::uint64_t height   = parent ? parent->height : main_parent->row.height;
            const U128          cumdiff  = parent ? parent->cumulative_difficulty
                                                  : main_parent->row.cumulative_difficulty;
            if (!resolved) continue;
            // Copied out of the pool before it is written to: insert() may evict,
            // and an evicting insert invalidates the pointers a live walk holds.
            std::vector<AltBlock> kids;
            for (const AltBlock* child : alt_.children_of(cur)) kids.push_back(*child);
            for (AltBlock& c : kids) {
                const Hash child_id = c.id;
                if (c.resolved && c.adoptable) { stack.push_back(child_id); continue; }
                c.height = height + 1;
                std::string why;
                U128 d{};
                EvaluatedBlock ev;
                if (evaluate_block(c.entry, ev, why) != EvalStatus::Ok) {
                    alt_.erase_branch(child_id);
                    continue;
                }
                const std::uint8_t rules = hf_rules_version(
                    static_cast<std::uint8_t>(ev.input.parsed.header.major_version));
                if (!branch_difficulty_locked_(cur, height, rules, d, why)) continue;
                c.difficulty            = d;
                c.cumulative_difficulty = u128_add(cumdiff, d);
                c.resolved              = true;

                // A block parked before its difficulty existed has never been
                // through the gate. Now that the difficulty is known it goes
                // through -- so a branch fed to us bottom-up out of junk dies
                // here, rather than at the moment it would have been adopted.
                const PowGate::Result pw =
                    gate_.check(c.height, c.prev_id, ev.input.identity.hashing_blob, d);
                if (pw.verdict == PowVerdict::BelowTarget) {
                    const PeerRef src = c.source;
                    penalize_locked_(&src, PeerFault::BadPow,
                                     "a parked block's proof of work does not meet the "
                                     "difficulty we computed for it");
                    alt_.erase_branch(child_id);
                    continue;
                }
                c.pow_verified = pow_verdict_is_verified(pw.verdict);
                c.adoptable    = c.pow_verified || pw.verdict == PowVerdict::Skipped;
                // Resolved and adoptable is not connectable: a fluffy push parked
                // before its parent landed holds the blob and NOT the
                // transactions. Flag it here, where it first becomes a candidate,
                // or nothing ever asks for them -- bodies_wanted() lists only
                // flagged parks, refetch_wanted() skips ids whose blob we hold,
                // and a chain entry skips ids already in the pool -- and the tip
                // freezes one block below it (the mainnet format-2 dry run,
                // h=3768570, fluffy_req=0 for the whole stall).
                c.bodies_missing = !ev.input.bodies_complete;

                alt_.insert(std::move(c));
                stack.push_back(child_id);
            }
        }
    }

    // Drain the parked children of the tip, in order, as ordinary EXTENDS.
    //
    // Going through maybe_switch_locked_() instead would work but would LIE: a
    // switch whose fork point IS the current tip disconnects nothing, and it
    // announces one Reorg of depth 0 for what is simply the next block. A
    // consumer that un-confirms on a reorg would un-confirm nothing, repeatedly.
    void connect_parked_children_locked_() {
        for (std::size_t guard = 0; guard < 4096; ++guard) {
            const RowRecord* tip = rows_.tip();
            if (!tip) return;
            const Hash tip_id = tip->row.id;

            // Copied out of the pool before anything is connected: connecting
            // mutates the caches a live pointer into the pool would outlive.
            std::optional<AltBlock> pick;
            // A bodiless park is skipped, not picked: it cannot connect, and
            // picking it first would hide a complete sibling behind it.
            for (const AltBlock* c : alt_.children_of(tip_id)) {
                if (c->resolved && c->adoptable && c->has_entry && !c->bodies_missing) {
                    pick = *c;
                    break;
                }
            }
            if (!pick) return;

            EvaluatedBlock ev;
            std::string    why;
            if (evaluate_block(pick->entry, ev, why) != EvalStatus::Ok) {
                alt_.erase_branch(pick->id);
                continue;
            }
            const ConnectOutcomeLocal co =
                connect_to_tip_locked_(pick->entry, ev, pick->pow_verified, Hash{},
                                       pick->own_mined, why);
            if (co.status != ConnectStatus::Ok) {
                // Leave it parked, and say nothing new -- but if what it lacks is
                // its bodies, say so to bodies_wanted(), which is the only path
                // that will ever ask for them.
                if (co.status == ConnectStatus::BodiesMissing)
                    if (AltBlock* p = alt_.find_mut(pick->id)) p->bodies_missing = true;
                return;
            }
            alt_.erase(pick->id);
        }
    }

    // =====================================================================================
    // fork choice and the switch
    // =====================================================================================
    bool maybe_switch_locked_() {
        const RowRecord* tip = rows_.tip();
        if (!tip) return false;
        const AltBlock* cand = alt_.heaviest();
        if (!cand) return false;

        BranchTip best;
        best.id                    = tip->row.id;
        best.height                = tip->row.height;
        best.cumulative_difficulty = tip->row.cumulative_difficulty;
        best.own_mined             = tip->own_mined;

        const ForkDecision d = fork_choice(best, cand->as_tip(), opts_.tie);
        if (d.action == ForkAction::Keep) return false;

        // From here the pool is mutated (blocks are parked, adopted, evicted),
        // so nothing below may hold a pointer into it.
        const Hash    cand_id     = cand->id;
        const PeerRef cand_source = cand->source;

        ReorgRecord rec;
        rec.old_tip    = best.id;
        rec.old_height = best.height;
        rec.old_cumulative_difficulty = best.cumulative_difficulty;
        rec.new_tip    = cand->id;
        rec.new_height = cand->height;
        rec.new_cumulative_difficulty = cand->cumulative_difficulty;

        // Assemble the branch, oldest first, down to a block on the best chain.
        std::vector<const AltBlock*> branch_ptrs;
        Hash        fork_parent{};
        std::string why;
        const AltPool::BranchWalk walk =
            alt_.branch_to_main(cand_id,
                                [this](const Hash& id) { return rows_.contains(id); },
                                static_cast<std::size_t>(opts_.max_reorg_depth), branch_ptrs,
                                fork_parent, why);
        if (walk != AltPool::BranchWalk::Ok) {
            journal_.refuse(rec,
                            walk == AltPool::BranchWalk::TooDeep ? ReorgRefusal::TooDeep
                                                                 : ReorgRefusal::OutOfWindow,
                            why);
            ++chain_refusals_;
            return false;
        }
        std::vector<AltBlock> branch;
        branch.reserve(branch_ptrs.size());
        for (const AltBlock* b : branch_ptrs) branch.push_back(*b);

        const RowRecord* fork_row = rows_.by_id(fork_parent);
        if (!fork_row) {
            journal_.refuse(rec, ReorgRefusal::OutOfWindow,
                            "the fork point is not in the retained window");
            ++chain_refusals_;
            return false;
        }
        const std::uint64_t fork_height = fork_row->row.height;
        const std::uint64_t depth       = best.height - fork_height;
        rec.fork_height = fork_height;
        rec.depth       = depth;

        // --- the four bounds, checked BEFORE anything is touched -------------------
        // The anchor is a floor, not a fence post: a fork POINT at the anchor is
        // fine (the anchor itself stays), a fork point below it is history we
        // declared settled at release time and will not reopen for a stranger.
        if (fork_height < view_.anchor_height()) {
            journal_.refuse(rec, ReorgRefusal::BelowAnchor,
                            "the fork point is below the trust anchor at "
                            + std::to_string(view_.anchor_height()));
            ++chain_refusals_;
            return false;
        }
        if (depth > opts_.max_reorg_depth) {
            journal_.refuse(rec, ReorgRefusal::TooDeep,
                            "reorg depth " + std::to_string(depth) + " exceeds the bounded horizon "
                            + std::to_string(opts_.max_reorg_depth));
            ++chain_refusals_;
            return false;
        }
        if (fork_height < rows_.oldest_height()) {
            journal_.refuse(rec, ReorgRefusal::OutOfWindow,
                            "the fork point is older than the retained rows");
            ++chain_refusals_;
            return false;
        }
        // monerod's rule (checkpoints::is_alternative_block_allowed): only the
        // highest checkpoint at or below the chain's HEIGHT (block count, i.e.
        // tip + 1) fences alternatives, and it fences blocks at or below it --
        // a branch whose first block sits at fork_height + 1 is allowed iff
        // that checkpoint < fork_height + 1. A checkpoint ABOVE our chain says
        // nothing yet about a fork beneath it; comparing against every
        // checkpoint refused every reorg, a one-block sibling race at the tip
        // included, whenever a bundle carried one above the anchor (which
        // checkpoints_at_or_above() keeps by construction).
        for (const auto& cp : checkpoints_) {
            if (cp.first > best.height + 1) continue;   // not reached yet
            if (fork_height < cp.first) {
                journal_.refuse(rec, ReorgRefusal::BelowCheckpoint,
                                "the fork point is below the pinned checkpoint at "
                                + std::to_string(cp.first));
                ++chain_refusals_;
                return false;
            }
        }
        // Bodies for BOTH directions: the branch we are adopting, and the branch
        // we are leaving (so a failure can be undone, and so the old branch can
        // be adopted again if it later wins).
        for (const AltBlock& b : branch) {
            // A bodiless fluffy park (#1680) has has_entry set -- it holds the
            // block blob -- but no transactions, so it cannot be connected as
            // part of an adopted branch. Treat it as missing bodies (which it
            // is): refuse the reorg rather than try to connect a txless block,
            // and remember it so the ordinary refetch path re-asks too.
            if (!b.has_entry || b.bodies_missing) {
                journal_.refuse(rec, ReorgRefusal::MissingBodies,
                                "a candidate block's body is not available");
                remember_refetch_(b.id);
                ++chain_refusals_;
                return false;
            }
            // Fail-closed: a branch is adopted only if EVERY block on it went
            // through the proof-of-work gate. Without this, a block parked as an
            // orphan before its difficulty was computable could ride into the
            // best chain on the back of its descendants.
            if (opts_.require_pow && !b.adoptable) {
                journal_.refuse(rec, ReorgRefusal::Unverified,
                                "a candidate block has not passed the proof-of-work gate");
                ++chain_refusals_;
                return false;
            }
        }
        for (std::uint64_t h = best.height; h > fork_height; --h) {
            const RowRecord* rr = rows_.by_height(h);
            if (!rr || entries_.find(key_(rr->row.id)) == entries_.end()) {
                journal_.refuse(rec, ReorgRefusal::MissingBodies,
                                "the body of the block we would disconnect at height "
                                + std::to_string(h) + " is not retained");
                if (rr) remember_refetch_(rr->row.id);
                ++chain_refusals_;
                return false;
            }
        }

        const std::uint64_t seq = journal_.plan(rec);

        // Everything the switch raises is queued behind this mark, so a failed
        // switch can un-say all of it: a consumer must never be told a block was
        // orphaned by a reorg that then did not happen.
        const std::size_t ev_mark = queued_events_.size();
        const std::size_t tx_mark = queued_tx_events_.size();

        // --- disconnect ---------------------------------------------------------------
        std::vector<CachedEntry> unwound;      // newest first, for the restore path
        std::vector<RowRecord>   unwound_rows;
        for (std::uint64_t h = best.height; h > fork_height; --h) {
            const RowRecord* rr = rows_.by_height(h);
            if (!rr) break;
            const CachedEntry ce = entries_[key_(rr->row.id)];
            // The bodies go back with the event, so the pool can re-admit the
            // transactions the losing branch had mined (good citizen): they are
            // valid again on the new branch unless it mined them too, which the
            // pool checks against probe_mined() on re-admission.
            if (!view_.disconnect_tip(ce.tx_hashes, blobs_of_(ce.entry))) break;
            RowRecord popped;
            rows_.pop(popped);
            pop_long_mirror_();
            if (ReorgRecord* jr = journal_.find(seq)) jr->disconnected.push_back(popped.row.id);
            park_disconnected_locked_(popped, ce);
            unwound.push_back(ce);
            unwound_rows.push_back(popped);
        }
        journal_.set_phase(seq, ReorgPhase::Disconnected);

        // --- apply --------------------------------------------------------------------
        bool ok = true;
        bool lacked_bodies = false;   // the failure was OUR missing bytes, not bad data
        Hash lacked_id{};
        std::vector<Hash> applied;
        for (const AltBlock& b : branch) {
            EvaluatedBlock ev;
            std::string    w;
            if (evaluate_block(b.entry, ev, w) != EvalStatus::Ok) { ok = false; why = w; break; }
            const std::uint64_t now = clock_ ? clock_() : 0;
            const ChainStateView::ConnectOutcome co =
                view_.connect(b.entry, b.pow_verified, now, b.own_mined, w);
            if (!co.ok) {
                ok = false;
                why = w;
                if (co.connect == ConnectStatus::BodiesMissing) {
                    lacked_bodies = true;
                    lacked_id     = b.id;
                }
                break;
            }
            // The difficulty the state computed from the rolled-back windows MUST
            // equal the one the branch walk computed, or one of the two is wrong
            // and neither may be trusted with a chain switch.
            if (u128_less(co.row.difficulty, b.difficulty)
                || u128_greater(co.row.difficulty, b.difficulty)) {
                ok = false;
                why = "branch difficulty disagreed with the connected difficulty";
                view_.disconnect_tip(ev.input.parsed.tx_hashes, {});
                break;
            }
            rows_.push(co.row, b.own_mined, Hash{});
            push_long_mirror_(co.row.long_term_weight);
            cache_entry_locked_(co.row.id, b.entry, ev.input.parsed.tx_hashes);
            applied.push_back(co.row.id);
            if (ReorgRecord* jr = journal_.find(seq)) jr->connected.push_back(co.row.id);
        }

        if (!ok) {
            // --- restore: the chain we were on, exactly ---------------------------------
            for (auto it = applied.rbegin(); it != applied.rend(); ++it) {
                const auto ce = entries_.find(key_(*it));
                view_.disconnect_tip(ce != entries_.end() ? ce->second.tx_hashes
                                                          : std::vector<Hash>{}, {});
                RowRecord popped;
                rows_.pop(popped);
                pop_long_mirror_();
            }
            for (std::size_t i = unwound.size(); i-- > 0; ) {
                std::string w;
                const std::uint64_t now = clock_ ? clock_() : 0;
                const RowRecord& orig = unwound_rows[i];
                const ChainStateView::ConnectOutcome co =
                    view_.connect(unwound[i].entry, orig.row.pow_verified, now, orig.own_mined, w);
                if (!co.ok) break;   // cannot happen: it connected from this state before
                rows_.push(co.row, orig.own_mined, orig.pow_hash);
                push_long_mirror_(co.row.long_term_weight);
                alt_.erase(co.row.id);
            }
            // Nothing happened, so nothing is announced.
            queued_events_.resize(ev_mark);
            queued_tx_events_.resize(tx_mark);
            if (lacked_bodies) {
                // Not a consensus failure: a block on the branch is a bodiless
                // park the pre-check above did not know about. Keep the branch
                // (erasing only its top, as the ValidationFailed path does, left
                // the bodiless block in place and peeled one pushed block per
                // arrival, forever), flag the block so bodies_wanted() asks for
                // it, and charge nobody.
                if (AltBlock* p = alt_.find_mut(lacked_id)) p->bodies_missing = true;
                journal_.close_rolled_back(seq, ReorgRefusal::MissingBodies, why);
                ++chain_refusals_;
                return false;
            }
            alt_.erase_branch(cand_id);
            journal_.close_rolled_back(seq, ReorgRefusal::ValidationFailed, why);
            // A branch that fails consensus after passing proof of work is bad
            // data from whoever proposed it.
            if (cand_source.peer_id != 0 || !cand_source.addr.empty())
                penalize_locked_(&cand_source, PeerFault::BadData, why);
            ++chain_refusals_;
            return false;
        }

        journal_.set_phase(seq, ReorgPhase::Applied);
        for (const Hash& id : applied) alt_.erase(id);

        // The consumers see the Orphans the disconnect raised and ONE Reorg for
        // the whole switch; the per-block Extends of blocks that were only being
        // re-applied would be noise that a subscriber would have to un-see.
        drop_queued_extends_after_(ev_mark);
        view_.emit_reorg(depth);
        journal_.close_committed(seq);
        update_synced_locked_();
        return true;
    }

    void park_disconnected_locked_(const RowRecord& rr, const CachedEntry& ce) {
        AltBlock b;
        b.id                    = rr.row.id;
        b.prev_id               = rr.row.prev_id;
        b.height                = rr.row.height;
        b.difficulty            = rr.row.difficulty;
        b.cumulative_difficulty = rr.row.cumulative_difficulty;
        b.resolved              = true;
        b.pow_verified          = rr.row.pow_verified;
        b.adoptable             = true;   // it was on the best chain a moment ago
        b.own_mined             = rr.own_mined;
        b.entry                 = ce.entry;
        b.has_entry             = true;
        b.first_seen_seq        = ++seq_;
        alt_.insert(std::move(b));
    }

    void drop_queued_extends_after_(std::size_t mark) {
        std::vector<node::MainchainEvent> keep(queued_events_.begin(),
                                               queued_events_.begin()
                                                   + static_cast<long>(mark));
        for (std::size_t i = mark; i < queued_events_.size(); ++i)
            if (queued_events_[i].kind != node::MainchainEventKind::Extend)
                keep.push_back(queued_events_[i]);
        queued_events_.swap(keep);
    }

    // =====================================================================================
    // the mined oracle: which txs / key images the best chain already carries
    // =====================================================================================
    // Fed from the state view's own tx events (under mu_, in chain order), so
    // it moves in lock-step with the chain on every path that connects or
    // disconnects a block -- extend, switch, failed-switch restore, snapshot
    // replay, own-fork abandonment -- with no path having to remember it.
    void note_mined_locked_(const BlockTxEvent& e) {
        if (e.kind == BlockTxEvent::Kind::Connected) {
            MinedRec rec;
            rec.height   = e.height;
            rec.block_id = e.block_id;
            rec.txs.reserve(e.tx_hashes.size());
            for (const Hash& id : e.tx_hashes) {
                rec.txs.push_back(key_(id));
                mined_tx_[rec.txs.back()] = e.height;
            }
            rec.kis.reserve(e.key_images.size());
            for (const Hash& ki : e.key_images) {
                rec.kis.push_back(key_(ki));
                mined_ki_[rec.kis.back()] = e.height;
            }
            mined_stack_.push_back(std::move(rec));
            const std::size_t cap = opts_.row_retention ? opts_.row_retention : 2048;
            while (mined_stack_.size() > cap) {
                forget_mined_locked_(mined_stack_.front());
                mined_stack_.pop_front();
            }
            return;
        }
        // Disconnected: LIFO, so it is the newest record -- searched from the
        // back only as a guard against a disconnect of a block the oracle never
        // saw connect (below the window it was seeded with).
        for (auto it = mined_stack_.rbegin(); it != mined_stack_.rend(); ++it) {
            if (!(it->block_id == e.block_id)) continue;
            forget_mined_locked_(*it);
            mined_stack_.erase(std::next(it).base());
            return;
        }
    }

    void forget_mined_locked_(const MinedRec& rec) {
        for (const Key& k : rec.txs) {
            const auto it = mined_tx_.find(k);
            if (it != mined_tx_.end() && it->second == rec.height) mined_tx_.erase(it);
        }
        for (const Key& k : rec.kis) {
            const auto it = mined_ki_.find(k);
            if (it != mined_ki_.end() && it->second == rec.height) mined_ki_.erase(it);
        }
    }

    void probe_mined_locked_(std::uint64_t parent_height, const std::vector<Hash>& tx_ids,
                             const std::vector<Hash>& key_images, std::vector<Hash>& mined,
                             std::vector<Hash>& spent) const {
        for (const Hash& id : tx_ids) {
            const auto it = mined_tx_.find(key_(id));
            if (it != mined_tx_.end() && it->second <= parent_height) mined.push_back(id);
        }
        for (const Hash& ki : key_images) {
            const auto it = mined_ki_.find(key_(ki));
            if (it != mined_ki_.end() && it->second <= parent_height) spent.push_back(ki);
        }
    }

    // Our own block's tx set, judged against the chain it extends (when that
    // parent is on the best chain; a block on a side branch is judged for
    // internal duplicates only -- the oracle answers for the best chain).
    bool own_block_hygiene_locked_(const EvaluatedBlock& ev,
                                   std::optional<std::uint64_t> parent_height,
                                   std::string& why) const {
        const std::vector<Hash>& ids = ev.input.parsed.tx_hashes;
        {
            std::set<Key> seen;
            for (const Hash& id : ids)
                if (!seen.insert(key_(id)).second) {
                    why = "tx " + hex_(id) + " appears twice in the block";
                    return false;
                }
        }
        {
            std::set<Key> seen;
            for (const Hash& ki : ev.key_images)
                if (!seen.insert(key_(ki)).second) {
                    why = "key image " + hex_(ki) + " is spent twice in the block";
                    return false;
                }
        }
        if (!parent_height) return true;
        std::vector<Hash> mined, spent;
        probe_mined_locked_(*parent_height, ids, ev.key_images, mined, spent);
        if (!mined.empty()) {
            why = "tx " + hex_(mined.front()) + " is already in the chain it extends (height "
                + std::to_string(mined_tx_.at(key_(mined.front()))) + ")";
            return false;
        }
        if (!spent.empty()) {
            why = "key image " + hex_(spent.front()) + " is already spent in the chain it extends";
            return false;
        }
        return true;
    }

    static std::vector<std::vector<std::uint8_t>> blobs_of_(const BlockEntry& e) {
        std::vector<std::vector<std::uint8_t>> out;
        out.reserve(e.txs.size());
        for (const TxBlobEntry& t : e.txs) {
            if (t.pruned) return {};   // a pruned body cannot be re-admitted: let relay re-teach it
            out.push_back(t.blob);
        }
        return out;
    }

    static std::string hex_(const Hash& h) {
        static const char* d = "0123456789abcdef";
        std::string s;
        s.reserve(64);
        for (const std::uint8_t b : h) { s.push_back(d[b >> 4]); s.push_back(d[b & 15]); }
        return s;
    }

    // =====================================================================================
    // the own-fork liveness guard
    // =====================================================================================
    bool check_own_fork_locked_(std::uint64_t now_ms, std::string* why) {
        const std::uint64_t losses_prev = losses_at_prev_check_;
        losses_at_prev_check_           = peer_losses_;

        const RowRecord* tip = rows_.tip();
        if (opts_.own_fork_bound_ms == 0 || !tip || !tip->own_mined) {
            own_fork_tracking_ = false;
            return false;
        }
        // The fork base: the lowest block of the own-mined suffix of the chain.
        const RowRecord* base = tip;
        for (std::uint64_t h = tip->row.height; h > rows_.oldest_height(); --h) {
            const RowRecord* below = rows_.by_height(h - 1);
            if (!below || !below->own_mined) break;
            base = below;
        }
        const std::uint64_t base_h = base->row.height;
        if (!own_fork_tracking_ || !(own_fork_base_ == base->row.id)) {
            own_fork_tracking_    = true;
            own_fork_base_        = base->row.id;
            own_fork_since_ms_    = now_ms;
            // Counted from the previous tick: a peer that dropped us right after
            // the block went out did so before this tick could start tracking.
            own_fork_losses_base_ = losses_prev;
            return false;
        }
        // Adopted? A peer whose advertised top is on our chain at or above the
        // fork base has taken our block; the fork is not suspect.
        for (const auto& kv : peers_) {
            const auto ph = rows_.height_of(kv.second.top_id);
            if (ph && *ph >= base_h) {
                own_fork_since_ms_    = now_ms;
                own_fork_losses_base_ = peer_losses_;
                return false;
            }
        }
        // Somebody must have been there to disagree: a node that never had a
        // peer (a solo regtest miner) is not abandoned by anyone.
        const bool lost_peers = peer_losses_ > own_fork_losses_base_;
        if (peers_.empty() && !lost_peers) return false;
        const std::uint64_t age = now_ms >= own_fork_since_ms_ ? now_ms - own_fork_since_ms_ : 0;
        if (why)
            *why = "own fork from h=" + std::to_string(base_h) + " (" + hex_(base->row.id)
                 + ") unadopted for " + std::to_string(age) + " ms, peers="
                 + std::to_string(peers_.size()) + " lost="
                 + std::to_string(peer_losses_ - own_fork_losses_base_);
        if (age < opts_.own_fork_bound_ms) return false;
        return abandon_own_fork_locked_(base_h, why);
    }

    // Disconnect the own-mined suffix down to (not including) its parent,
    // abandon those blocks, and let whatever we hold of the peers' chain in.
    bool abandon_own_fork_locked_(std::uint64_t base_h, std::string* why) {
        const RowRecord* tip = rows_.tip();
        if (!tip || base_h == 0 || base_h > tip->row.height) return false;
        const std::uint64_t tip_h       = tip->row.height;
        const std::uint64_t fork_height = base_h - 1;
        const std::uint64_t depth       = tip_h - fork_height;
        const RowRecord*    fork_row    = rows_.by_height(fork_height);

        ReorgRecord rec;
        rec.old_tip    = tip->row.id;
        rec.old_height = tip_h;
        rec.old_cumulative_difficulty = tip->row.cumulative_difficulty;
        rec.fork_height = fork_height;
        rec.depth       = depth;
        if (fork_row) {
            rec.new_tip    = fork_row->row.id;
            rec.new_height = fork_height;
            rec.new_cumulative_difficulty = fork_row->row.cumulative_difficulty;
        }
        const char* refuse = nullptr;
        ReorgRefusal code  = ReorgRefusal::OutOfWindow;
        if (!fork_row || fork_height < rows_.oldest_height()) refuse = "the fork parent is not retained";
        else if (fork_height < view_.anchor_height()) { refuse = "the fork parent is below the anchor"; code = ReorgRefusal::BelowAnchor; }
        else if (depth > opts_.max_reorg_depth) { refuse = "the own fork is deeper than the reorg horizon"; code = ReorgRefusal::TooDeep; }
        if (refuse) {
            journal_.refuse(rec, code, std::string("own-fork guard: ") + refuse);
            ++chain_refusals_;
            own_fork_tracking_ = false;   // re-armed (and re-timed) by the next check
            if (why) *why += std::string(" -- NOT abandoned: ") + refuse;
            return false;
        }

        const std::uint64_t seq = journal_.plan(rec);
        std::uint64_t n = 0;
        for (std::uint64_t h = tip_h; h > fork_height; --h) {
            const RowRecord* rr = rows_.by_height(h);
            if (!rr) break;
            const auto ce = entries_.find(key_(rr->row.id));
            const bool have = ce != entries_.end();
            if (!view_.disconnect_tip(have ? ce->second.tx_hashes : std::vector<Hash>{},
                                      have ? blobs_of_(ce->second.entry)
                                           : std::vector<std::vector<std::uint8_t>>{}))
                break;
            RowRecord popped;
            rows_.pop(popped);
            pop_long_mirror_();
            if (ReorgRecord* jr = journal_.find(seq)) jr->disconnected.push_back(popped.row.id);
            alt_.erase_branch(popped.row.id);
            remember_abandoned_(popped.row.id);
            ++n;
        }
        journal_.set_phase(seq, ReorgPhase::Disconnected);
        journal_.set_phase(seq, ReorgPhase::Applied);
        view_.emit_reorg(n);
        journal_.close_committed(seq);
        ++own_forks_abandoned_;
        own_fork_tracking_ = false;
        if (why)
            *why += " -- ABANDONED " + std::to_string(n) + " own block(s), tip back to h="
                  + std::to_string(fork_height);

        // Whatever we already hold of the peers' chain goes in now: the
        // children of the fork parent, and any branch that outweighs it.
        if (const RowRecord* t = rows_.tip()) resolve_descendants_locked_(t->row.id);
        connect_parked_children_locked_();
        (void)maybe_switch_locked_();
        update_synced_locked_();
        return n > 0;
    }

    void remember_abandoned_(const Hash& id) {
        const Key k = key_(id);
        if (!abandoned_own_.insert(k).second) return;
        abandoned_order_.push_back(k);
        while (abandoned_order_.size() > 256) {
            abandoned_own_.erase(abandoned_order_.front());
            abandoned_order_.pop_front();
        }
    }

    // =====================================================================================
    // wire validation (mirrors handle_response_chain_entry)
    // =====================================================================================
    bool validate_chain_entry_locked_(const ChainEntry& e, std::string& why) {
        if (e.ids.empty()) {
            why = "chain entry carries no ids";
            ++chain_entries_refused_;
            return false;
        }
        if (e.ids.size() > MAX_CHAIN_ENTRY_IDS) {
            why = "chain entry carries " + std::to_string(e.ids.size())
                + " ids, above the " + std::to_string(MAX_CHAIN_ENTRY_IDS) + " monerod sends";
            ++chain_entries_refused_;
            return false;
        }
        if (e.total_height < e.ids.size()
            || e.start_height > e.total_height - e.ids.size()) {
            why = "chain entry start/total heights do not admit "
                + std::to_string(e.ids.size()) + " ids";
            ++chain_entries_refused_;
            return false;
        }
        if (!e.weights_claimed_hint.empty() && e.weights_claimed_hint.size() != e.ids.size()) {
            why = "chain entry carries " + std::to_string(e.weights_claimed_hint.size())
                + " weight hints for " + std::to_string(e.ids.size()) + " ids";
            ++chain_entries_refused_;
            return false;
        }
        // The splice point must be OURS. monerod's find_blockchain_supplement
        // guarantees it, so a peer that does not honour it is either broken or
        // trying to make us index a chain we have no link to.
        if (!rows_.contains(e.ids[0]) && !alt_.contains(e.ids[0])) {
            why = "chain entry does not start at a block we know";
            ++chain_entries_refused_;
            return false;
        }
        why.clear();
        return true;
    }

    // =====================================================================================
    // seeds, burial, sync flag
    // =====================================================================================
    // The seed id at an epoch height, resolved ON THE BRANCH ending at
    // `branch_tip`: an alt branch that crosses an epoch edge has its own key
    // block, and using the main chain's would verify the wrong thing.
    std::optional<Hash> seed_on_branch_(std::uint64_t epoch_height,
                                        const Hash& branch_tip) const {
        Hash        cursor = branch_tip;
        std::size_t guard  = 0;
        while (const AltBlock* b = alt_.find(cursor)) {
            if (b->height == epoch_height) return b->id;
            if (b->height < epoch_height) break;
            cursor = b->prev_id;
            if (++guard > SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG) break;
        }
        if (const RowRecord* r = rows_.by_id(cursor)) {
            if (r->row.height == epoch_height) return r->row.id;
        }
        return rows_.id_at_epoch_height(epoch_height);
    }

    Burial burial_locked_(const Hash& id, std::uint64_t n) const {
        Burial b;
        const auto h = rows_.height_of(id);
        if (!h) {
            // Not on the best chain. Distinguish "we know it, it lost" from
            // "never heard of it": the clock must not treat the two alike.
            b.status = alt_.contains(id) ? BurialStatus::Orphaned : BurialStatus::Unknown;
            return b;
        }
        b.height = *h;
        const std::uint64_t tip_h = rows_.tip_height();
        b.depth = tip_h >= *h ? (tip_h - *h + 1) : 0;

        if (*h <= view_.anchor_height()) {
            b.status = BurialStatus::PinnedBuried;
            return b;
        }
        if (b.depth < n)                       { b.status = BurialStatus::NotYet; return b; }
        if (*h > view_.verified_frontier())    { b.status = BurialStatus::NotYet; return b; }
        b.status = BurialStatus::Buried;
        return b;
    }

    // One vote per CONNECTION. The levin peer_id is the remote's own claim and
    // is not unique (anonymity-network peers all send 0), so keying the cohort
    // by it collapsed honest peers into one vote -- and let on_peer_gone for
    // one of them erase the others'.
    static std::string peer_key_(const PeerRef& p) {
        return p.addr.empty() ? "#" + std::to_string(p.peer_id) : p.addr;
    }

    std::uint64_t cohort_height_locked_() const {
        // The cohort is the peers that agree with the heaviest claim. We take
        // the MEDIAN of their advertised heights rather than the maximum, so one
        // peer shouting a huge height cannot hold `synced` false forever.
        //
        // Only PLAUSIBLE votes count: a peer advertising a height below our own
        // verified chain (current_height is one past its tip) is behind us and
        // says nothing about whether WE are synced. A fresh-from-genesis
        // monerod advertises ~1, and such peers are a normal fraction of the
        // dialable population: with them in the median, a stale node reported
        // synced=1 and served templates 30+ blocks behind the network. If
        // every peer is level with or behind us, we are at the cohort's tip.
        if (peers_.empty()) return cohort_max_;
        const std::uint64_t frontier = view_.verified_frontier();
        const std::uint64_t anchor   = view_.anchor_height();
        const std::uint64_t level    = (frontier > anchor ? frontier : anchor) + 1;
        std::vector<std::uint64_t> hs;
        hs.reserve(peers_.size());
        for (const auto& kv : peers_)
            if (kv.second.current_height >= level) hs.push_back(kv.second.current_height);
        if (hs.empty()) return level;
        std::sort(hs.begin(), hs.end());
        return hs[hs.size() / 2];
    }

    void update_synced_locked_() {
        if (forced_synced_) {
            synced_ = true; view_.set_synced(true);
            if (opts_.consumer_window && !pacing_lifted_) lift_pacing_locked_("synced (forced)");
            return;
        }
        const std::uint64_t cohort = cohort_height_locked_();
        const std::uint64_t frontier = view_.verified_frontier();
        // OR-C2-8: publish only when the verified frontier has reached the
        // cohort's tip. With no peers at all there is nothing to be synced WITH,
        // and claiming it would be the fail-open answer.
        synced_ = cohort > 0 && frontier + 1 >= cohort;
        view_.set_synced(synced_);
        // COLD-BOOT-3 (synced latch): the catch-up is over for this process; a
        // later missed-push gap is followed at full speed, never re-paced.
        if (synced_ && opts_.consumer_window && !pacing_lifted_)
            lift_pacing_locked_("synced at " + std::to_string(frontier) + " (the initial catch-up is over)");
        view_.set_cohort_height(cohort);
    }

    // =====================================================================================
    // body cache
    // =====================================================================================
    void cache_entry_locked_(const Hash& id, const BlockEntry& e,
                             const std::vector<Hash>& tx_hashes) {
        CachedEntry ce;
        ce.entry     = e;
        ce.tx_hashes = tx_hashes;
        ce.bytes     = e.block_blob.size();
        for (const TxBlobEntry& t : e.txs) ce.bytes += t.blob.size();
        const Key k = key_(id);
        const auto it = entries_.find(k);
        if (it != entries_.end()) entry_bytes_ -= it->second.bytes;
        else entry_order_.push_back(k);
        entry_bytes_ += ce.bytes;
        entries_[k] = std::move(ce);
        while ((opts_.entry_cache && entry_order_.size() > opts_.entry_cache)
               || (opts_.entry_cache_bytes && entry_bytes_ > opts_.entry_cache_bytes)) {
            if (entry_order_.empty()) break;
            // COLD-BOOT-2 (D4a): the oldest-INSERTED body is the victim, EXCEPT the
            // bodies of the best chain's top snapshot_depth + 1 blocks. The snapshot
            // (save_snapshot_locked_) re-carries exactly those and refuses when one
            // is missing, and a reorg disconnects them. Pure FIFO let a burst of
            // older bodies (the cold-boot booking refetch re-caching the post-anchor
            // gap) push every tip-side body out: the node then wrote no snapshot at
            // all until snapshot_depth new blocks had connected (stagenet: hours).
            // Bounded: at most snapshot_depth + 1 bodies are ever skipped, and only
            // when that is at most a quarter of the cache (tip_pin_depth_locked_).
            auto vit = entry_order_.begin();
            while (vit != entry_order_.end() && tip_pinned_locked_(*vit)) ++vit;
            if (vit == entry_order_.end()) break;   // only pinned bodies left: keep them
            const Key victim = *vit;
            entry_order_.erase(vit);
            const auto v = entries_.find(victim);
            if (v != entries_.end()) {
                entry_bytes_ -= v->second.bytes;
                entries_.erase(v);
            }
        }
    }

    // COLD-BOOT-2: a best-chain body within the top snapshot_depth + 1 heights.
    // The pin never takes more than a quarter of the cache (shipped: 65 of 1024);
    // a cache too small for that keeps the plain FIFO order.
    std::uint64_t tip_pin_depth_locked_() const {
        const std::uint64_t pin = opts_.snapshot_depth + 1;
        return (opts_.entry_cache == 0 || opts_.entry_cache >= 4 * pin) ? pin : 0;
    }
    bool tip_pinned_locked_(const Key& k) const {
        const std::uint64_t pin = tip_pin_depth_locked_();
        if (pin == 0 || rows_.empty() || k.size() != sizeof(Hash)) return false;
        Hash id{};
        std::copy(k.begin(), k.end(), reinterpret_cast<char*>(id.data()));
        const auto h = rows_.height_of(id);
        return h && *h + pin > rows_.tip_height();
    }

    bool consumer_held_locked_() const {
        const std::uint64_t ceil = consumer_ceiling_locked_();
        return ceil != 0 && !synced_ && !rows_.empty() && rows_.tip_height() >= ceil;
    }
    void lift_pacing_locked_(const std::string& why) {
        if (pacing_lifted_) return;
        pacing_lifted_ = true;
        pacing_lifted_why_ = why;
    }

    // COLD-BOOT-2: frontier + window, or 0 when pacing is off.
    // COLD-BOOT-3: and 0 once the pacing was lifted for this process.
    std::uint64_t consumer_ceiling_locked_() const {
        if (opts_.consumer_window == 0 || pacing_lifted_) return 0;
        const std::uint64_t base = consumer_frontier_set_ ? consumer_frontier_ : view_.anchor_height();
        return base + opts_.consumer_window;
    }

    std::size_t missing_tx_count_(const Hash& id) const {
        const AltBlock* b = alt_.find(id);
        if (!b) return 0;
        ParsedBlock pb;
        if (parse_block(b->entry.block_blob, pb) != BlockParseStatus::Ok) return 0;
        return pb.tx_hashes.size() > b->entry.txs.size()
             ? pb.tx_hashes.size() - b->entry.txs.size() : 0;
    }

    // How far above our tip the chain-entry want list is handed out: half the
    // alt pool, so the blocks in flight plus whatever parks meanwhile fit in it.
    std::uint64_t fetch_window_() const {
        if (!opts_.alt_max_blocks) return MAX_SPAN_IDS;
        return opts_.alt_max_blocks >= 2 ? opts_.alt_max_blocks / 2 : 1;
    }

    void remember_refetch_(const Hash& id) {
        if (!contains_hash_(refetch_, id)) refetch_.push_back(id);
        while (refetch_.size() > 256) refetch_.erase(refetch_.begin());
    }

    static void erase_hash_(std::vector<Hash>& v, const Hash& h) {
        v.erase(std::remove(v.begin(), v.end(), h), v.end());
    }

    static bool contains_hash_(const std::vector<Hash>& v, const Hash& h) {
        for (const Hash& x : v) if (x == h) return true;
        return false;
    }

    // Do we hold bytes we could re-apply for this id? Deliberately NOT "do we
    // know it": a fluffy announcement parked without its transactions, and a
    // best-chain row whose body has aged out of the entry cache, are both known
    // and both still need fetching -- and a reorg that needs either of them is
    // refused with MissingBodies and asks for exactly this id back.
    bool have_body_locked_(const Hash& id) const {
        if (entries_.find(key_(id)) != entries_.end()) return true;
        const AltBlock* b = alt_.find(id);
        return b && b->has_entry;
    }

    // D3a: is the block a peer just pushed one this index HAS as a valid block?
    // On the best chain (it connected, reorged in, or was already there), or held
    // in the alt pool as a RESOLVED, ADOPTABLE candidate with its bodies. A parked
    // orphan, an unjudgeable park, a bodiless announcement, a block whose proof of
    // work could not be checked yet, and every rejection answer false: those are
    // exactly the pushes the block DoS bucket exists to rate-limit.
    bool pushed_block_is_known_valid_locked_(const OfferResult& r) const {
        switch (r.outcome) {
            case OfferOutcome::Connected:
            case OfferOutcome::Reorged:
            case OfferOutcome::Duplicate:
            case OfferOutcome::StoredAsAlt:
                break;
            case OfferOutcome::ParkedOrphan:
            case OfferOutcome::NeedsBodies:
            case OfferOutcome::Rejected:
                return false;
        }
        if (rows_.contains(r.id)) return true;
        const AltBlock* a = alt_.find(r.id);
        return a && a->resolved && a->adoptable && a->has_entry && !a->bodies_missing;
    }

    void penalize_locked_(const PeerRef* p, PeerFault f, const std::string& why) {
        if (f == PeerFault::BadPow) ++bans_;
        if (fetcher_ && p) fetcher_->penalize(*p, f, why);
    }

    // =====================================================================================
    // a block from a fork above the implemented range (unknown-fork watch)
    // =====================================================================================
    // evaluate_block() read the header first and stopped: the major_version is
    // above MAX_IMPLEMENTED_HF_VERSION, so the body, the id and the PoW all
    // belong to rules this build does not have. The block is refused, never
    // parked, and NEVER charged to the sender: an honest peer that upgraded is
    // exactly who sends it.
    //
    // FORK-FUSE-2. Its PoW cannot be checked, so one such block proves nothing:
    // anyone can bump the version of a header on our tip. It is a SUSPECT
    // alarm only (counted; loud once per distinct peer group per window;
    // templates continue). When it attaches to a block we hold, or claims a
    // height above our tip, it is EVIDENCE for the UnknownForkWatch, which
    // trips only on >= 2 distinct peer groups AND a stalled v16 tip
    // (check_unknown_fork). A block that neither attaches nor claims to be
    // ahead is only counted.
    //
    // Its id goes into a small bounded set so the want list stops handing it
    // to the sync driver: the v16-rule id when the blob still parses as v16
    // (a bumped header on a v16 body), and the chain entry's wanted id at the
    // same height (a real next-fork block, whose id we cannot recompute).
    OfferResult unknown_fork_locked_(const PeerRef* peer, const BlockEntry& entry,
                                     const EvaluatedBlock& ev, std::string why) {
        OfferResult r;
        r.outcome    = OfferOutcome::Rejected;
        r.eval       = EvalStatus::UnknownFork;
        r.peer_fault = false;
        ++unknown_fork_blocks_;

        const std::uint64_t major = ev.input.parsed.header.major_version;
        const Hash&         prev  = ev.input.parsed.header.prev_id;
        std::optional<std::uint64_t> parent_h;
        if (const RowRecord* mp = rows_.by_id(prev)) parent_h = mp->row.height;
        else if (const AltBlock* ap = alt_.find(prev); ap && ap->resolved) parent_h = ap->height;

        const std::uint64_t tip_h = rows_.empty() ? 0 : rows_.tip_height();
        const bool claims_ahead = !parent_h && ev.input.coinbase.height > tip_h;
        r.height = parent_h ? *parent_h + 1 : ev.input.coinbase.height;

        // The ids to hold back from the want list.
        {
            ParsedBlock pb;
            if (parse_block(entry.block_blob, pb) == BlockParseStatus::Ok) {
                r.id = block_identity(entry.block_blob.data(), pb).id;
                uf_remember_id_locked_(r.id);
            }
            // FORK-FUSE-3: only an id THIS peer announced (its own chain
            // entry is the current want list). An id another peer announced
            // at the height this block claims is that peer's honest block, and
            // holding it back let one lying push withhold it for the TTL.
            if ((parent_h || claims_ahead) && peer && wanted_src_ == peer_key_(*peer))
                for (std::size_t k = 0; k < wanted_.size(); ++k)
                    if (wanted_heights_[k] == r.height && !rows_.contains(wanted_[k]))
                        uf_remember_id_locked_(wanted_[k]);
        }

        // FORK-FUSE-3: the sync driver neither routes want-list batches to this
        // peer nor asks it for its chain except on a back-off, until it serves
        // a v16 block that connects (offer_locked_). Not a penalty: the link
        // stays, and so does every other FORK-FUSE-2 property.
        if (peer) {
            if (uf_peers_flagged_.size() >= UF_FLAGGED_CAP
                && !uf_peers_flagged_.count(peer_key_(*peer)))
                uf_peers_flagged_.erase(uf_peers_flagged_.begin());
            ++uf_peers_flagged_[peer_key_(*peer)];
        }

        const std::string src = peer ? peer->addr : std::string("local");
        if (!parent_h) ++unknown_fork_unattached_;
        if (!parent_h && !claims_ahead) {
            r.why = why + "; parent unknown, not placed";
            return r;
        }
        const std::uint8_t v = static_cast<std::uint8_t>(major);
        if (uf_watch_.note_block(uf_peer_group_(peer), v)) {
            std::fprintf(stderr,
                "[HF-FUSE] SUSPECT: block major_version %u at height %llu (prev %s, %s) from %s "
                "is above the highest fork this build implements (%u); its PoW cannot be checked. "
                "NOT stored, NOT penalised, templates CONTINUE. Evidence this window: %zu/%zu "
                "distinct peers, tip stalled %llu/%llu s.\n",
                static_cast<unsigned>(v), static_cast<unsigned long long>(r.height),
                hex_prefix_(prev).c_str(), parent_h ? "attached" : "claims ahead", src.c_str(),
                static_cast<unsigned>(MAX_IMPLEMENTED_HF_VERSION), uf_watch_.distinct_peers(),
                UNKNOWN_FORK_QUORUM_PEERS,
                static_cast<unsigned long long>(uf_watch_.stalled_ms() / 1000),
                static_cast<unsigned long long>(uf_watch_.stall_ms() / 1000));
            std::fflush(stderr);
        }
        r.why = why + (uf_watch_.tripped() ? "; unknown-fork trip standing"
                                           : "; unknown-fork suspect (not tripped)");
        return r;
    }

    // The distinctness key for the quorum: the /16 of an IPv4 peer on
    // mainnet (one operator rarely spans two /16s); the address elsewhere, so a
    // loopback regtest rig can field two distinct peers.
    std::string uf_peer_group_(const PeerRef* peer) const {
        if (!peer) return "local";
        const std::string key = peer_key_(*peer);
        if (opts_.net != XmrNet::Mainnet) return key;
        const std::size_t colon = key.rfind(':');
        const std::string host = (colon == std::string::npos || key.find(':') != colon)
                                     ? key : key.substr(0, colon);
        unsigned a = 0, b = 0, c = 0, d = 0;
        char tail = 0;
        if (std::sscanf(host.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) == 4
            && a < 256 && b < 256 && c < 256 && d < 256)
            return "/16:" + std::to_string(a) + "." + std::to_string(b);
        return host;
    }

    // The bounded above-version id set: at most UF_ID_CAP ids, oldest out
    // first; an id is held back from the want list for UF_ID_TTL_MS of poll
    // time, then may be asked once more (a peer that answered an honest id
    // with a bumped header delays that id by at most the TTL, never forever).
    static constexpr std::size_t   UF_ID_CAP    = 256;
    static constexpr std::uint64_t UF_ID_TTL_MS = 10ull * 60ull * 1000ull;
    static constexpr std::size_t   UF_FLAGGED_CAP = 1024;   // FORK-FUSE-3: flagged-peer map bound

    void uf_remember_id_locked_(const Hash& id) {
        const std::string k = key_of_(id);
        const auto it = uf_ids_.find(k);
        if (it != uf_ids_.end()) return;          // keep the first sighting's clock
        uf_ids_.emplace(k, uf_watch_.last_poll_ms());
        uf_ids_order_.push_back(k);
        while (uf_ids_order_.size() > UF_ID_CAP) {
            uf_ids_.erase(uf_ids_order_.front());
            uf_ids_order_.pop_front();
        }
    }

    bool uf_id_held_locked_(const Hash& id) const {
        if (uf_ids_.empty()) return false;
        const auto it = uf_ids_.find(key_of_(id));
        if (it == uf_ids_.end()) return false;
        const std::uint64_t now = uf_watch_.last_poll_ms();
        if (now >= it->second && now - it->second >= UF_ID_TTL_MS) return false;
        ++uf_refetch_held_;
        return true;
    }

    static std::string key_of_(const Hash& h) {
        return std::string(reinterpret_cast<const char*>(h.data()), h.size());
    }

    static std::string hex_prefix_(const Hash& h) {
        static const char* d = "0123456789abcdef";
        std::string s;
        for (std::size_t i = 0; i < 8; ++i) { s.push_back(d[h[i] >> 4]); s.push_back(d[h[i] & 15]); }
        return s;
    }

    // =====================================================================================
    // the long-term weight mirror
    // =====================================================================================
    // The 100 000-entry long-term window lives inside the consensus state, which
    // exposes its contents but not the values it evicted. A snapshot taken below
    // the tip needs exactly those, so the index keeps a mirror it advances in
    // lock-step, plus the last `snapshot_depth` evictions. The mirror is checked
    // against the state's own window by the KAT, which is what keeps "in
    // lock-step" a fact rather than an intention.
    void seed_long_mirror_(const std::vector<std::uint64_t>& seed) {
        lt_mirror_.assign(seed.begin(), seed.end());
        lt_undo_.clear();
    }

    void push_long_mirror_(std::uint64_t v) {
        std::pair<bool, std::uint64_t> u{false, 0};
        lt_mirror_.push_back(v);
        if (lt_mirror_.size() > CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE) {
            u.first  = true;
            u.second = lt_mirror_.front();
            lt_mirror_.pop_front();
        }
        lt_undo_.push_back(u);
        while (lt_undo_.size() > opts_.snapshot_depth + 8) lt_undo_.pop_front();
    }

    void pop_long_mirror_() {
        if (lt_mirror_.empty() || lt_undo_.empty()) return;
        lt_mirror_.pop_back();
        const auto u = lt_undo_.back();
        lt_undo_.pop_back();
        if (u.first) lt_mirror_.push_front(u.second);
    }

    // The long-term window as it stood `depth` blocks below the tip.
    bool long_window_at_depth_(std::uint64_t depth, std::vector<std::uint64_t>& out) const {
        if (depth > lt_undo_.size()) return false;
        std::deque<std::uint64_t> w = lt_mirror_;
        for (std::uint64_t i = 0; i < depth; ++i) {
            if (w.empty()) return false;
            w.pop_back();
            const auto u = lt_undo_[lt_undo_.size() - 1 - i];
            if (u.first) w.push_front(u.second);
        }
        out.assign(w.begin(), w.end());
        return true;
    }

public:
    // Exposed for the KAT: the mirror must equal the consensus state's own
    // window at every height, or every snapshot taken below the tip is wrong.
    std::vector<std::uint64_t> long_window_mirror() const {
        std::lock_guard<std::mutex> lk(mu_);
        return std::vector<std::uint64_t>(lt_mirror_.begin(), lt_mirror_.end());
    }

private:
    // =====================================================================================
    // snapshot codec
    // =====================================================================================
    static void put_u64_(std::vector<std::uint8_t>& o, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) o.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
    }
    static void put_hash_(std::vector<std::uint8_t>& o, const Hash& h) {
        o.insert(o.end(), h.begin(), h.end());
    }
    static void put_bytes_(std::vector<std::uint8_t>& o, const std::vector<std::uint8_t>& b) {
        put_u64_(o, b.size());
        o.insert(o.end(), b.begin(), b.end());
    }
    struct Reader {
        const std::uint8_t* p; std::size_t n; std::size_t off = 0; bool bad = false;
        std::uint64_t u64() {
            if (off + 8 > n) { bad = true; return 0; }
            std::uint64_t v = 0;
            for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(p[off + i]) << (8 * i);
            off += 8;
            return v;
        }
        Hash hash() {
            Hash h{};
            if (off + 32 > n) { bad = true; return h; }
            for (int i = 0; i < 32; ++i) h[static_cast<std::size_t>(i)] = p[off + i];
            off += 32;
            return h;
        }
        std::vector<std::uint8_t> bytes() {
            const std::uint64_t len = u64();
            std::vector<std::uint8_t> b;
            if (bad || off + len > n) { bad = true; return b; }
            b.assign(p + off, p + off + len);
            off += static_cast<std::size_t>(len);
            return b;
        }
    };

    static constexpr std::uint64_t SNAPSHOT_MAGIC   = 0x3143584449433243ull;  // "C2CIDXC1"
    static constexpr std::uint64_t SNAPSHOT_VERSION = 1;

    static void put_row_(std::vector<std::uint8_t>& o, const RowRecord& r) {
        put_u64_(o, r.row.height);
        put_hash_(o, r.row.id);
        put_hash_(o, r.row.prev_id);
        put_u64_(o, r.row.timestamp);
        put_u64_(o, r.row.major_version);
        put_u64_(o, r.row.minor_version);
        put_u64_(o, r.row.block_weight);
        put_u64_(o, r.row.long_term_weight);
        put_u64_(o, r.row.difficulty.lo);
        put_u64_(o, r.row.difficulty.hi);
        put_u64_(o, r.row.cumulative_difficulty.lo);
        put_u64_(o, r.row.cumulative_difficulty.hi);
        put_u64_(o, r.row.base_reward);
        put_u64_(o, r.row.fees);
        put_u64_(o, r.row.reward);
        put_u64_(o, r.row.already_generated_coins);
        put_u64_(o, r.row.pow_verified ? 1 : 0);
        put_u64_(o, r.own_mined ? 1 : 0);
        put_hash_(o, r.pow_hash);
    }

    static RowRecord get_row_(Reader& r) {
        RowRecord rec;
        rec.row.height        = r.u64();
        rec.row.id            = r.hash();
        rec.row.prev_id       = r.hash();
        rec.row.timestamp     = r.u64();
        rec.row.major_version = static_cast<std::uint8_t>(r.u64());
        rec.row.minor_version = static_cast<std::uint8_t>(r.u64());
        rec.row.block_weight  = r.u64();
        rec.row.long_term_weight = r.u64();
        rec.row.difficulty.lo = r.u64();
        rec.row.difficulty.hi = r.u64();
        rec.row.cumulative_difficulty.lo = r.u64();
        rec.row.cumulative_difficulty.hi = r.u64();
        rec.row.base_reward   = r.u64();
        rec.row.fees          = r.u64();
        rec.row.reward        = r.u64();
        rec.row.already_generated_coins = r.u64();
        rec.row.pow_verified  = r.u64() != 0;
        rec.own_mined         = r.u64() != 0;
        rec.pow_hash          = r.hash();
        return rec;
    }

    bool save_snapshot_locked_(std::vector<std::uint8_t>& out, std::string& why) const {
        out.clear();
        if (rows_.empty()) { why = "nothing to snapshot"; return false; }

        const std::uint64_t tip_h = rows_.tip_height();

        // How far below the tip can this snapshot be based? Only as far as the
        // index can REBUILD every window there from what it retains:
        //
        //   * the difficulty, short-weight and timestamp windows are rebuilt out
        //     of the retained rows, so the rows must reach 735 below the base;
        //   * the long-term window is rebuilt by rolling the mirror back, so the
        //     eviction ring must reach that far.
        //
        // When it cannot -- a node that booted from an anchor minutes ago has one
        // row and 735 window entries that came from the bundle -- the snapshot
        // falls back to the TIP, taking the live windows verbatim. That resume is
        // exact too; what it lacks is a rollback horizon, so a node restored from
        // it cannot reorg until it has connected blocks of its own. Both cases are
        // written into the file (`depth`), so the resumed node knows which it got.
        std::uint64_t depth = opts_.snapshot_depth;
        if (depth > lt_undo_.size()) depth = static_cast<std::uint64_t>(lt_undo_.size());
        if (tip_h - view_.anchor_height() < depth) depth = tip_h - view_.anchor_height();

        std::vector<DifficultyRow> dwin;
        std::vector<std::uint64_t> st, lt, ts;

        // Can every window be rebuilt at tip - depth? If any cannot, fall back
        // to the tip in one step rather than creeping down a height at a time:
        // the shallower base would fail for the same reason.
        if (depth > 0) {
            const std::uint64_t candidate = tip_h - depth;
            const std::uint64_t oldest    = rows_.oldest_height();
            const bool rows_cover =
                candidate >= oldest + CRYPTONOTE_REWARD_BLOCKS_WINDOW - 1
                && candidate >= oldest + BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - 1;
            if (!rows_cover
                || !rows_.difficulty_window_ending_at(candidate, DIFFICULTY_BLOCKS_COUNT, dwin)
                || !long_window_at_depth_(depth, lt)) {
                depth = 0;
                dwin.clear();
                lt.clear();
            }
        }

        const std::uint64_t base_h = tip_h - depth;

        const RowRecord* base = rows_.by_height(base_h);
        if (!base) { why = "the snapshot base height is not retained"; return false; }

        if (depth == 0) {
            // Live windows, straight out of the consensus state.
            const auto& drows = view_.state().difficulty_window().rows();
            dwin.assign(drows.begin(), drows.end());
            st = view_.state().weights().short_window().values();
            lt.assign(lt_mirror_.begin(), lt_mirror_.end());
            // The last 60 timestamps are the tail of the difficulty window, which
            // is one row per height over the same chain.
            const std::size_t n = static_cast<std::size_t>(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW);
            const std::size_t first = dwin.size() > n ? dwin.size() - n : 0;
            for (std::size_t i = first; i < dwin.size(); ++i) ts.push_back(dwin[i].timestamp);
        } else {
            // dwin and lt were filled by the feasibility check above.
            const std::uint64_t st_lo =
                base_h >= CRYPTONOTE_REWARD_BLOCKS_WINDOW - 1
                    ? base_h - (CRYPTONOTE_REWARD_BLOCKS_WINDOW - 1) : rows_.oldest_height();
            for (std::uint64_t h = st_lo; h <= base_h; ++h)
                if (const RowRecord* r = rows_.by_height(h)) st.push_back(r->row.block_weight);
            const std::uint64_t ts_lo =
                base_h >= BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - 1
                    ? base_h - (BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - 1) : rows_.oldest_height();
            for (std::uint64_t h = ts_lo; h <= base_h; ++h)
                if (const RowRecord* r = rows_.by_height(h)) ts.push_back(r->row.timestamp);
        }

        std::vector<std::uint8_t> body;
        put_u64_(body, SNAPSHOT_MAGIC);
        put_u64_(body, SNAPSHOT_VERSION);
        put_u64_(body, static_cast<std::uint64_t>(opts_.net));
        put_u64_(body, view_.anchor_height());
        put_hash_(body, anchor_id_);
        put_u64_(body, base_h);
        put_u64_(body, depth);

        put_row_(body, *base);

        put_u64_(body, dwin.size());
        for (const DifficultyRow& d : dwin) {
            put_u64_(body, d.timestamp);
            put_u64_(body, d.cumulative_difficulty.lo);
            put_u64_(body, d.cumulative_difficulty.hi);
        }
        put_u64_(body, st.size());
        for (std::uint64_t v : st) put_u64_(body, v);
        put_u64_(body, lt.size());
        for (std::uint64_t v : lt) put_u64_(body, v);
        put_u64_(body, ts.size());
        for (std::uint64_t v : ts) put_u64_(body, v);

        // Seed anchors: the epoch ids, which outlive their rows.
        put_u64_(body, rows_.seed_anchors().size());
        for (const auto& kv : rows_.seed_anchors()) {
            put_u64_(body, kv.first);
            put_hash_(body, kv.second);
        }

        // The rows BELOW the base, so a resumed index can answer burial and
        // serving questions about them without refetching anything.
        std::vector<const RowRecord*> below;
        for (std::uint64_t h = rows_.oldest_height(); h < base_h; ++h)
            if (const RowRecord* r = rows_.by_height(h)) below.push_back(r);
        put_u64_(body, below.size());
        for (const RowRecord* r : below) put_row_(body, *r);

        // The blocks ABOVE the base, with their bodies: resume re-applies them
        // through the ordinary consensus path, with their recorded verdicts.
        put_u64_(body, depth);
        for (std::uint64_t h = base_h + 1; h <= tip_h; ++h) {
            const RowRecord* r = rows_.by_height(h);
            const auto it = r ? entries_.find(key_(r->row.id)) : entries_.end();
            if (!r || it == entries_.end()) {
                why = "the body of block " + std::to_string(h) + " is not retained";
                return false;
            }
            put_u64_(body, r->row.pow_verified ? 1 : 0);
            put_u64_(body, r->own_mined ? 1 : 0);
            put_hash_(body, r->pow_hash);
            put_bytes_(body, it->second.entry.block_blob);
            put_u64_(body, it->second.entry.txs.size());
            for (const TxBlobEntry& t : it->second.entry.txs) {
                put_bytes_(body, t.blob);
                put_hash_(body, t.prunable_hash);
                put_u64_(body, t.pruned ? 1 : 0);
            }
        }

        anchor_hash::Sha256 h;
        h.update(body.data(), body.size());
        const std::array<std::uint8_t, 32> digest = h.finish();

        out = std::move(body);
        out.insert(out.end(), digest.begin(), digest.end());
        why.clear();
        return true;
    }

    bool load_snapshot_locked_(const std::vector<std::uint8_t>& in, std::string& why) {
        if (in.size() < 40) { why = "snapshot is too short"; return false; }
        const std::size_t body_len = in.size() - 32;
        anchor_hash::Sha256 hh;
        hh.update(in.data(), body_len);
        const std::array<std::uint8_t, 32> digest = hh.finish();
        for (std::size_t i = 0; i < 32; ++i) {
            if (digest[i] != in[body_len + i]) {
                why = "snapshot digest does not match its contents";
                return false;
            }
        }

        Reader r{in.data(), body_len};
        if (r.u64() != SNAPSHOT_MAGIC)   { why = "snapshot magic is wrong"; return false; }
        if (r.u64() != SNAPSHOT_VERSION) { why = "snapshot version is not one this build writes"; return false; }
        const std::uint64_t net = r.u64();
        if (net != static_cast<std::uint64_t>(opts_.net)) {
            why = "snapshot is for a different network";
            return false;
        }
        const std::uint64_t anchor_h = r.u64();
        const Hash anchor_id = r.hash();
        const std::uint64_t base_h = r.u64();
        const std::uint64_t depth  = r.u64();
        (void)anchor_h;

        const RowRecord base = get_row_(r);
        if (base.row.height != base_h) {
            why = "snapshot base row does not sit at the base height it declares";
            return false;
        }

        std::vector<DifficultyRow> dwin;
        const std::uint64_t nd = r.u64();
        if (nd > DIFFICULTY_BLOCKS_COUNT) { why = "snapshot difficulty window is oversized"; return false; }
        for (std::uint64_t i = 0; i < nd && !r.bad; ++i) {
            DifficultyRow d;
            d.timestamp = r.u64();
            d.cumulative_difficulty.lo = r.u64();
            d.cumulative_difficulty.hi = r.u64();
            dwin.push_back(d);
        }
        std::vector<std::uint64_t> st, lt, ts;
        const std::uint64_t nst = r.u64();
        for (std::uint64_t i = 0; i < nst && !r.bad; ++i) st.push_back(r.u64());
        const std::uint64_t nlt = r.u64();
        if (nlt > CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE) {
            why = "snapshot long-term window is oversized";
            return false;
        }
        for (std::uint64_t i = 0; i < nlt && !r.bad; ++i) lt.push_back(r.u64());
        const std::uint64_t nts = r.u64();
        for (std::uint64_t i = 0; i < nts && !r.bad; ++i) ts.push_back(r.u64());

        std::vector<std::pair<std::uint64_t, Hash>> seeds;
        const std::uint64_t nseed = r.u64();
        if (nseed > 4096) { why = "snapshot seed table is oversized"; return false; }
        for (std::uint64_t i = 0; i < nseed && !r.bad; ++i) {
            const std::uint64_t h = r.u64();
            seeds.push_back({h, r.hash()});
        }

        std::vector<RowRecord> below;
        const std::uint64_t nbelow = r.u64();
        if (nbelow > opts_.row_retention) { why = "snapshot row window is oversized"; return false; }
        for (std::uint64_t i = 0; i < nbelow && !r.bad; ++i) below.push_back(get_row_(r));

        struct Above { bool pow; bool own; Hash pow_hash; BlockEntry entry; };
        std::vector<Above> above;
        const std::uint64_t nabove = r.u64();
        if (nabove != depth) { why = "snapshot depth disagrees with the blocks it carries"; return false; }
        for (std::uint64_t i = 0; i < nabove && !r.bad; ++i) {
            Above a;
            a.pow      = r.u64() != 0;
            a.own      = r.u64() != 0;
            a.pow_hash = r.hash();
            a.entry.block_blob = r.bytes();
            const std::uint64_t ntx = r.u64();
            if (ntx > BLOCK_MAX_TX_HASHES) { why = "snapshot block carries too many bodies"; return false; }
            for (std::uint64_t k = 0; k < ntx && !r.bad; ++k) {
                TxBlobEntry t;
                t.blob          = r.bytes();
                t.prunable_hash = r.hash();
                t.pruned        = r.u64() != 0;
                a.entry.txs.push_back(std::move(t));
            }
            above.push_back(std::move(a));
        }
        if (r.bad) { why = "snapshot is truncated"; return false; }

        // --- install ------------------------------------------------------------------
        reset_locked_();
        view_.seed_direct(base.row, dwin, st, lt, ts, seeds);
        std::vector<RowRecord> all = below;
        all.push_back(base);
        if (!rows_.install(all)) { why = "snapshot rows are not contiguous"; return false; }
        for (const auto& s : seeds) rows_.remember_seed_anchor(s.first, s.second);
        rows_.seed_pre_window(base.row.height, dwin);
        seed_long_mirror_(lt);
        anchor_id_ = anchor_id;

        // --- replay the tail, without re-running RandomX --------------------------------
        for (const Above& a : above) {
            EvaluatedBlock ev;
            std::string    w;
            if (evaluate_block(a.entry, ev, w) != EvalStatus::Ok) {
                why = "a snapshotted block no longer evaluates: " + w;
                return false;
            }
            const ChainStateView::ConnectOutcome co =
                view_.connect(a.entry, a.pow, /*now=*/0, a.own, w);
            if (!co.ok) {
                why = "a snapshotted block no longer connects: " + w;
                return false;
            }
            rows_.push(co.row, a.own, a.pow_hash);
            push_long_mirror_(co.row.long_term_weight);
            cache_entry_locked_(co.row.id, a.entry, ev.input.parsed.tx_hashes);
        }
        // COLD-BOOT-3: where this process resumed (the resume latch of the pacing).
        resumed_tip_ = rows_.tip_height();
        // A resume is not a re-verification: the events it would raise describe a
        // chain the consumers already saw before the restart.
        queued_events_.clear();
        queued_tx_events_.clear();
        update_synced_locked_();
        why.clear();
        return true;
    }

    void reset_locked_() {
        rows_.clear();
        alt_.clear();
        alt_timestamps_.clear();
        entries_.clear();
        entry_order_.clear();
        entry_bytes_ = 0;
        lt_mirror_.clear();
        lt_undo_.clear();
        wanted_.clear();
        wanted_heights_.clear();
        wanted_src_.clear();
        refetch_.clear();
        booking_wanted_.clear();
        queued_events_.clear();
        queued_tx_events_.clear();
        mined_stack_.clear();
        mined_tx_.clear();
        mined_ki_.clear();
        own_fork_tracking_ = false;
    }

    void flush_events_() {
        std::vector<node::MainchainEvent> evs;
        std::vector<BlockTxEvent>         txs;
        std::vector<EventSink>            sinks;
        std::vector<TxEventSink>          tx_sinks;
        {
            std::lock_guard<std::mutex> lk(mu_);
            evs.swap(queued_events_);
            txs.swap(queued_tx_events_);
            sinks    = sinks_;
            tx_sinks = tx_sinks_;
        }
        for (const auto& e : evs)  for (const auto& s : sinks)    s(e);
        for (const auto& t : txs)  for (const auto& s : tx_sinks) s(t);
    }

    // --- state ------------------------------------------------------------------------
    mutable std::mutex mu_;

    ChainIndexOptions opts_;
    ChainStateView    view_;
    RowStore          rows_;
    AltPool           alt_;
    ReorgJournal      journal_;
    IPowSource*       pow_;
    PowGate           gate_;
    IChainFetcher*    fetcher_ = nullptr;

    std::function<std::uint64_t()> clock_;

    std::vector<std::pair<std::uint64_t, Hash>> checkpoints_;
    Hash anchor_id_{};

    std::map<Key, CachedEntry> entries_;
    std::deque<Key>            entry_order_;
    std::uint64_t              entry_bytes_ = 0;

    mutable std::map<Key, std::uint64_t> alt_timestamps_;

    std::deque<std::uint64_t>                   lt_mirror_;
    std::deque<std::pair<bool, std::uint64_t>>  lt_undo_;

    std::map<std::string, PeerSyncData> peers_;   // keyed by peer_key_()
    std::vector<Hash> wanted_;
    std::vector<std::uint64_t> wanted_heights_;   // parallel to wanted_
    std::vector<Hash> refetch_;
    std::vector<Hash> booking_wanted_;            // COLD-BOOT: bodies the booking asked back (bounded)
    std::uint64_t     booking_refetch_asked_   = 0;
    std::uint64_t     booking_bodies_restored_ = 0;
    std::uint64_t     consumer_frontier_       = 0;       // COLD-BOOT-2: the consumer's booked frontier
    bool              consumer_frontier_set_   = false;   // COLD-BOOT-2: false = the anchor until the first report
    std::uint64_t     consumer_stall_n_        = 0;       // COLD-BOOT-3: reports held at the ceiling without progress
    std::uint64_t     resumed_tip_             = 0;       // COLD-BOOT-3: tip a snapshot resume installed (0 = none)
    bool              pacing_lifted_           = false;   // COLD-BOOT-3: latched for the process
    std::string       pacing_lifted_why_;
    std::function<bool()> download_hold_;                 // COLD-BOOT-3: event-queue backpressure

    std::vector<node::MainchainEvent> queued_events_;
    std::vector<BlockTxEvent>         queued_tx_events_;
    std::vector<EventSink>            sinks_;
    std::vector<TxEventSink>          tx_sinks_;

    std::uint64_t seq_        = 0;
    std::uint64_t orphans_    = 0;
    std::uint64_t bans_       = 0;
    std::uint64_t bytes_in_   = 0;
    std::uint64_t missed_ids_ = 0;
    std::uint64_t cohort_max_ = 0;
    std::uint64_t chain_entries_accepted_ = 0;
    std::uint64_t chain_entries_refused_  = 0;
    std::uint64_t chain_refusals_         = 0;
    std::uint64_t unknown_fork_blocks_     = 0;   // above-version blocks refused, never charged
    std::uint64_t unknown_fork_unattached_ = 0;   // ... of which the parent was unknown
    UnknownForkWatch uf_watch_{};                          // FORK-FUSE-2: suspect / trip / clear
    std::map<std::string, std::uint64_t> uf_ids_;          // above-version id -> first-seen poll ms
    std::deque<std::string>              uf_ids_order_;    // FIFO for the UF_ID_CAP bound
    mutable std::uint64_t                uf_refetch_held_ = 0;   // want-list ids held back
    std::string                          wanted_src_;            // FORK-FUSE-3: who announced wanted_
    std::map<std::string, std::uint64_t> uf_peers_flagged_;      // FORK-FUSE-3: peer -> above-version blocks since its last connecting v16 block
    bool          synced_             = false;
    bool          forced_synced_      = false;
    bool          synced_forced_ever_ = false;

    // --- the mined oracle (template / own-block hygiene) ----------------------
    // One record per connected best-chain block, LIFO like the chain itself, so
    // a disconnect removes exactly what its connect added. Bounded to the
    // retained row window.
    std::deque<MinedRec>          mined_stack_;
    std::map<Key, std::uint64_t>  mined_tx_;   // tx id -> height mined at
    std::map<Key, std::uint64_t>  mined_ki_;   // key image -> height spent at
    std::uint64_t own_invalid_refused_ = 0;

    // --- the own-fork liveness guard --------------------------------------------
    bool          own_fork_tracking_    = false;
    Hash          own_fork_base_{};
    std::uint64_t own_fork_since_ms_    = 0;
    std::uint64_t own_fork_losses_base_ = 0;
    std::uint64_t peer_losses_          = 0;
    std::uint64_t losses_at_prev_check_ = 0;
    std::uint64_t own_forks_abandoned_  = 0;
    std::set<Key>   abandoned_own_;
    std::deque<Key> abandoned_order_;
};

} // namespace c2pool::xmr::native
