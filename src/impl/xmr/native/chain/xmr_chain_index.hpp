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
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
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
    TieBreak      tie             = TieBreak::PreferOwn;   // D-14
    VerificationLevel level        = VerificationLevel::L4PrunedAuthenticated;
    // Fail-closed: a block whose PoW we could not check does not join the best
    // chain. Replays of recorded history (parity, KATs) turn it off explicitly
    // and get rows with pow_verified == false, which never advance the frontier.
    bool          require_pow     = true;
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
        alt_.set_caps(opts_.alt_max_blocks, opts_.alt_max_bytes);
        view_.state().set_row_retention(opts_.row_retention);
        // One sink into the state view; it queues rather than dispatches, so no
        // consumer callback ever runs with our mutex held.
        view_.subscribe([this](const node::MainchainEvent& e) { queued_events_.push_back(e); });
        view_.subscribe_txs([this](const BlockTxEvent& e) { queued_tx_events_.push_back(e); });
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
                    peers_.erase(p.peer_id);
                    penalize_locked_(&p, PeerFault::VersionMismatch,
                                     "advertised top_version " + std::to_string(d.top_version)
                                     + " is below the " + std::to_string(want)
                                     + " our fork table requires at its own tip");
                    update_synced_locked_();
                    return;
                }
            }
            peers_[p.peer_id] = d;
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
            // the index only says what is missing and in what order.
            wanted_.clear();
            for (std::size_t i = 1; i < e.ids.size(); ++i) {
                if (rows_.contains(e.ids[i]) || alt_.contains(e.ids[i])) continue;
                wanted_.push_back(e.ids[i]);
                if (wanted_.size() >= MAX_SPAN_IDS) break;
            }
            if (fetcher_ && !wanted_.empty())
                fetcher_->request_objects(p, wanted_, /*prune=*/true);
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
            peers_.erase(p.peer_id);
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
    PowGate&      pow_gate() noexcept { return gate_; }

    // Ids the index wants fetched: what a chain entry told us we are missing,
    // plus anything a refused reorg needs before it can be retried. The sync
    // driver reads this; the index never schedules its own network traffic
    // beyond the single hint request above.
    std::vector<Hash> refetch_wanted() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<Hash> out = wanted_;
        out.insert(out.end(), refetch_.begin(), refetch_.end());
        return out;
    }

    // The state view, for consumers that need the consensus numbers themselves
    // (the parity oracle compares them field by field). Read-only by intent.
    const ChainStateView& view() const noexcept { return view_; }

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

    // =====================================================================================
    // offering a block
    // =====================================================================================
    OfferResult offer_locked_(const PeerRef* peer, BlockEntry entry, bool own_mined) {
        OfferResult r;

        EvaluatedBlock ev;
        std::string    why;
        r.eval = evaluate_block(entry, ev, why);
        if (r.eval != EvalStatus::Ok) {
            r.outcome    = OfferOutcome::Rejected;
            r.peer_fault = true;
            r.fault      = PeerFault::BadData;
            r.why        = why;
            penalize_locked_(peer, PeerFault::BadData, why);
            return r;
        }

        r.id = ev.input.identity.id;

        if (rows_.contains(r.id)) {
            r.outcome = OfferOutcome::Duplicate;
            r.height  = rows_.height_of(r.id).value_or(0);
            r.why     = "already on the best chain";
            return r;
        }

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
            if (alt_.contains(r.id)) {
                r.outcome = OfferOutcome::Duplicate;
                r.why     = "already parked";
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
            b.first_seen_seq = ++seq_;
            if (peer) b.source = *peer;
            alt_.insert(std::move(b));
            ++orphans_;
            r.outcome = OfferOutcome::ParkedOrphan;
            r.height  = ev.input.coinbase.height;
            r.why     = "parent is not in the index yet";
            if (!contains_hash_(refetch_, prev)) refetch_.push_back(prev);
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
            // We cannot see far enough back to judge it. Not a fault, not a
            // rejection: park it and say what is missing.
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
                r.outcome = OfferOutcome::Connected;
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
            if (!rows_.difficulty_window_ending_at(anchor_row->row.height, need, window)) {
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
            for (const AltBlock* c : alt_.children_of(tip_id)) {
                if (c->resolved && c->adoptable && c->has_entry) { pick = *c; break; }
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
            if (co.status != ConnectStatus::Ok) return;   // leave it parked, and say nothing new
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
        for (const auto& cp : checkpoints_) {
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
            if (!b.has_entry) {
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
            if (!view_.disconnect_tip(ce.tx_hashes, {})) break;
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
        std::vector<Hash> applied;
        for (const AltBlock& b : branch) {
            EvaluatedBlock ev;
            std::string    w;
            if (evaluate_block(b.entry, ev, w) != EvalStatus::Ok) { ok = false; why = w; break; }
            const std::uint64_t now = clock_ ? clock_() : 0;
            const ChainStateView::ConnectOutcome co =
                view_.connect(b.entry, b.pow_verified, now, b.own_mined, w);
            if (!co.ok) { ok = false; why = w; break; }
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
            alt_.erase_branch(cand_id);
            journal_.close_rolled_back(seq, ReorgRefusal::ValidationFailed, why);
            // Nothing happened, so nothing is announced.
            queued_events_.resize(ev_mark);
            queued_tx_events_.resize(tx_mark);
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

    std::uint64_t cohort_height_locked_() const {
        // The cohort is the peers that agree with the heaviest claim. We take
        // the MEDIAN of their advertised heights rather than the maximum, so one
        // peer shouting a huge height cannot hold `synced` false forever.
        if (peers_.empty()) return cohort_max_;
        std::vector<std::uint64_t> hs;
        hs.reserve(peers_.size());
        for (const auto& kv : peers_) hs.push_back(kv.second.current_height);
        std::sort(hs.begin(), hs.end());
        return hs[hs.size() / 2];
    }

    void update_synced_locked_() {
        if (forced_synced_) { synced_ = true; view_.set_synced(true); return; }
        const std::uint64_t cohort = cohort_height_locked_();
        const std::uint64_t frontier = view_.verified_frontier();
        // OR-C2-8: publish only when the verified frontier has reached the
        // cohort's tip. With no peers at all there is nothing to be synced WITH,
        // and claiming it would be the fail-open answer.
        synced_ = cohort > 0 && frontier + 1 >= cohort;
        view_.set_synced(synced_);
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
            const Key victim = entry_order_.front();
            entry_order_.pop_front();
            const auto v = entries_.find(victim);
            if (v != entries_.end()) {
                entry_bytes_ -= v->second.bytes;
                entries_.erase(v);
            }
        }
    }

    std::size_t missing_tx_count_(const Hash& id) const {
        const AltBlock* b = alt_.find(id);
        if (!b) return 0;
        ParsedBlock pb;
        if (parse_block(b->entry.block_blob, pb) != BlockParseStatus::Ok) return 0;
        return pb.tx_hashes.size() > b->entry.txs.size()
             ? pb.tx_hashes.size() - b->entry.txs.size() : 0;
    }

    void remember_refetch_(const Hash& id) {
        if (!contains_hash_(refetch_, id)) refetch_.push_back(id);
        while (refetch_.size() > 256) refetch_.erase(refetch_.begin());
    }

    static bool contains_hash_(const std::vector<Hash>& v, const Hash& h) {
        for (const Hash& x : v) if (x == h) return true;
        return false;
    }

    void penalize_locked_(const PeerRef* p, PeerFault f, const std::string& why) {
        if (f == PeerFault::BadPow) ++bans_;
        if (fetcher_ && p) fetcher_->penalize(*p, f, why);
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
        refetch_.clear();
        queued_events_.clear();
        queued_tx_events_.clear();
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

    std::map<std::uint64_t, PeerSyncData> peers_;
    std::vector<Hash> wanted_;
    std::vector<Hash> refetch_;

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
    bool          synced_             = false;
    bool          forced_synced_      = false;
    bool          synced_forced_ever_ = false;
};

} // namespace c2pool::xmr::native
