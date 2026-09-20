// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/chain/xmr_output_set.hpp
//
// The global output set the txpool's input-consensus step resolves rings
// against, and the global spent-key-image oracle it double-spend-checks against,
// both built from the SAME connected-block stream the txpool already consumes --
// no new network surface, no daemon. It is both IRingMemberSource and
// ISpentKeyImageView at once.
//
// AUTHENTICATED ON THE RATIFIED MRR-MERKLE MODEL. The two sets are not just
// in-memory tables: each is an APPEND-ONLY AUTHENTICATED LOG, ordered by the
// mainchain (Monero) block that created its entries -- one leaf per connected
// block, so the leaf's ORIGIN BIN is the committed Monero height (the trustless
// clock of docs/c2pool-v37-the-temporal-levels.md). The log's digest is the
// root of the SHIPPED v37 lane MMR (src/sharechain/v37/v37_lane.hpp): this file
// calls ::v37::Lane::{mmr_append,mmr_bag,mmr_proof,mmr_verify} exactly as
// src/c2pool/v37/record_log.hpp does, so an output-set root is byte-for-byte
// what the same leaves would produce in a lane -- ONE MMR implementation, the
// consensus one, with ZERO edits under src/sharechain/v37. The leaf rule is the
// lane's, mirrored (leaf = sha256d(0x00||payload), interiors hashed only inside
// the lane statics). This buys (a) log-size membership proofs and (b) an
// ANCHOR-SNAPSHOT: the set's roots + minimal state can be committed into the
// AnchorBundle (contracts/anchor.hpp, format 2 -- OPERATOR SEAM, see
// anchor/xmr_anchor_codec.hpp) so a daemonless node booting from an anchor loads
// the historical output/spent set instead of being blind to pre-anchor outputs.
//
// COVERAGE, stated honestly. `first_output_index` is the anchor's
// rct_output_count. On a chain the node followed from genesis (regtest, or a
// from-genesis walk) it is 0 and the set is COMPLETE: every amount-0 output ever
// created is in it, numbered from 0. On a FORMAT-2 anchor boot it is the real
// count at H_a: a ring member below it is pre-anchor, resolve() returns false,
// and the pool fails closed (RingUnresolved) unless the format-2 snapshot has
// been seeded (seed_from_snapshot), which backfills the below-base history so
// those members resolve.
//
// A FORMAT-1 anchor carries NO rct_output_count -- anchor_self_check forces all
// six format-2 fields to zero, so the count is 0 even though the chain's real
// count at H_a is not. The node therefore CANNOT number from the real base: a
// base of 0 would misnumber every post-anchor output, and an HONEST ring whose
// real member sits below the (unknown) real base would resolve to the WRONG
// post-anchor output and be scored a forged ring -- RingSigFail, a DROP OFFENCE
// against an honest peer. So a format-1 boot DISABLES resolution outright
// (disable_resolution(), wired in xmr_native_node.hpp): resolve() returns false
// for every ring, all rings stay RingUnresolved (fail-closed), and no honest
// peer is ever mis-scored. The spent-key-image view is unaffected. The pre-anchor
// history is loaded from a format-2 anchor-committed snapshot -- the O-backfill
// seam.
//
// COINBASE COMMITMENTS. A version-2 coinbase output has a PUBLIC amount and
// carries no outPk, so monerod stores rct::zeroCommit(amount) as its commitment.
// The chain layer (chain_view / block_eval) links no curve code, so it ships the
// coinbase's (amount, pubkey) pairs raw on BlockTxEvent and THIS file synthesises
// the commitment with rct::zero_commit -- the one place output capture touches
// the ed25519 arithmetic. A version-1 coinbase creates no amount-0 output.
//
// REORG SAFETY. Every connected block pushes one undo frame recording the two
// MMR peak sets BEFORE the append, how many outputs it added and which key
// images; a disconnect pops the matching frame, RESTORES THE PEAKS BIT-EXACT,
// truncates the leaves, pops the outputs and erases the key images. Frames are
// LIFO -- the order monerod emits disconnects (tip first). Bit-exact root
// restore is the lane's own reorg rule, applied here.
//
// Header-only; the STL, the shipped lane MMR statics (STL-only), and the rct
// ops (linked into xmr_native_txpool, which every consumer of this header --
// the node and the output-set KAT -- already links). One mutex, because the
// chain thread writes while the pool thread resolves.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>    // ::v37::bytes32, ::v37::sha256d
#include <sharechain/v37/v37_fixed.hpp>   // ::v37::u64
#include <sharechain/v37/v37_lane.hpp>    // ::v37::PeakSet, ::v37::Lane MMR statics

#include "impl/xmr/native/contracts/anchor.hpp"
#include "impl/xmr/native/contracts/outputs.hpp"
#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/rct/xmr_rct_ops.hpp"               // rct::zero_commit
#include "impl/xmr/native/txpool/xmr_relayed_txpool.hpp"     // HashHasher

namespace c2pool::xmr::native {

class ChainOutputSet final : public IRingMemberSource, public ISpentKeyImageView {
public:
    using bytes32 = ::v37::bytes32;

    // Serialization schema version for serialize().
    static constexpr std::uint8_t SER_VER = 1;

    // Domain tags for the leaf and digest payloads (lane "V37P" analogue).
    // OUTPUT leaf, SPENT-key-image leaf, and the SET digest.
    static constexpr std::uint8_t LEAF_VER = 1;

    // `first_output_index` = the anchor's rct_output_count (0 for regtest from
    // genesis). Nothing below it is ever resolvable from this set.
    explicit ChainOutputSet(std::uint64_t first_output_index = 0)
        : base_(first_output_index) {}

    // Re-seat the numbering base after a boot resolves it (genesis => 0, anchor
    // => the bundle's rct_output_count). Only legal on an EMPTY set (before any
    // block connects), or the leaves already appended would be misnumbered.
    bool reset_base(std::uint64_t first_output_index) {
        std::lock_guard<std::mutex> lk(mu_);
        if (!outputs_.empty()) return false;
        base_ = first_output_index;
        return true;
    }

    // Disable ring resolution outright: resolve() then returns false for EVERY
    // ring, so the pool leaves them all RingUnresolved (fail-closed). Called on a
    // FORMAT-1 anchor boot, where the bundle carries no rct_output_count so the
    // real numbering base is unknown -- resolving anything from base=0 would
    // misnumber an honest ring below the real base and RingSigFail it (a drop
    // offence against an honest peer). The spent-key-image view (is_spent) is
    // unaffected, and the from-genesis / format-2 paths never call this and keep
    // resolving. Idempotent.
    void disable_resolution() {
        std::lock_guard<std::mutex> lk(mu_);
        resolution_enabled_ = false;
    }
    bool resolution_enabled() const {
        std::lock_guard<std::mutex> lk(mu_);
        return resolution_enabled_;
    }

    // --- IRingMemberSource --------------------------------------------------
    bool resolve(std::uint64_t amount,
                 const std::vector<std::uint64_t>& absolute_offsets,
                 std::vector<OutputRecord>&        out) const override {
        if (amount != 0) return false;
        std::lock_guard<std::mutex> lk(mu_);
        // Format-1 anchor boot: the numbering base is unknown, so resolution is
        // disabled and every ring is left RingUnresolved (fail-closed) rather
        // than mis-resolved to a wrong post-anchor output.
        if (!resolution_enabled_) return false;
        out.clear();
        out.reserve(absolute_offsets.size());
        for (std::uint64_t off : absolute_offsets) {
            if (off < base_) return false;                 // below the anchor
            const std::uint64_t idx = off - base_;
            if (idx >= outputs_.size()) return false;      // beyond our frontier
            out.push_back(outputs_[static_cast<std::size_t>(idx)]);
        }
        return true;
    }

    // --- ISpentKeyImageView -------------------------------------------------
    bool is_spent(const Hash& ki) const override {
        std::lock_guard<std::mutex> lk(mu_);
        return spent_.find(ki) != spent_.end();
    }

    // --- chain feed ---------------------------------------------------------
    // Append a connected block's outputs (coinbase first, then non-coinbase, in
    // global-index order) and spent key images, and extend both authenticated
    // logs by one leaf. `ev.first_output_index` must equal our current frontier
    // when the block carried outputs, or the stream skipped a block and every
    // ring after the gap would be misnumbered -- we refuse and report it.
    bool on_block_connected(const BlockTxEvent& ev) {
        if (ev.kind != BlockTxEvent::Kind::Connected) return false;
        std::lock_guard<std::mutex> lk(mu_);

        // Materialise this block's outputs in global order: v2 coinbase outputs
        // (commitment = zeroCommit(public amount)) first, then the non-coinbase
        // records already carrying their outPk commitments.
        std::vector<OutputRecord> block_outs;
        block_outs.reserve(ev.coinbase_amount_pubkeys.size() + ev.outputs.size());
        for (const auto& ap : ev.coinbase_amount_pubkeys) {
            OutputRecord r;
            r.pubkey      = ap.second;
            r.commitment  = rct::zero_commit(ap.first);
            r.unlock_time = ev.coinbase_unlock_time;
            r.height      = ev.height;
            block_outs.push_back(r);
        }
        for (const OutputRecord& o : ev.outputs) block_outs.push_back(o);

        const std::uint64_t frontier = base_ + outputs_.size();
        if (!block_outs.empty() && ev.first_output_index != frontier)
            return false;

        UndoFrame f;
        f.height           = ev.height;
        f.block_id         = ev.block_id;
        f.outputs_added    = block_outs.size();
        f.out_peaks_before = out_peaks_;   // bit-exact reorg restore
        f.ki_peaks_before  = ki_peaks_;
        f.prev_tip_height  = tip_height_;
        f.prev_tip_id      = tip_id_;

        // OUTPUT leaf: "XMRO"|ver|height|block_id|first_output_index|n|compose,
        // compose = sha256d(pubkey||commitment||unlock_time per output).
        {
            std::vector<std::uint8_t> rows;
            rows.reserve(block_outs.size() * (32 + 32 + 8));
            for (const OutputRecord& o : block_outs) {
                rows.insert(rows.end(), o.pubkey.begin(), o.pubkey.end());
                rows.insert(rows.end(), o.commitment.begin(), o.commitment.end());
                put_u64(rows, o.unlock_time);
            }
            std::vector<std::uint8_t> p;
            put_tag(p, 'X','M','R','O');
            p.push_back(LEAF_VER);
            put_u64(p, ev.height);
            p.insert(p.end(), ev.block_id.begin(), ev.block_id.end());
            put_u64(p, ev.first_output_index);
            put_u32(p, static_cast<std::uint32_t>(block_outs.size()));
            const bytes32 compose = ::v37::sha256d(rows);
            p.insert(p.end(), compose.begin(), compose.end());
            out_leaf_first_.push_back(ev.first_output_index);
            out_leaves_.push_back(leaf_hash(p));
            ::v37::Lane::mmr_append(out_peaks_, out_leaves_.back());
        }

        // SPENT leaf: "XMRK"|ver|height|block_id|n|sha256d(sorted key images).
        {
            std::vector<Hash> sorted(ev.key_images.begin(), ev.key_images.end());
            std::sort(sorted.begin(), sorted.end());
            std::vector<std::uint8_t> kib;
            kib.reserve(sorted.size() * 32);
            for (const Hash& ki : sorted) kib.insert(kib.end(), ki.begin(), ki.end());
            std::vector<std::uint8_t> p;
            put_tag(p, 'X','M','R','K');
            p.push_back(LEAF_VER);
            put_u64(p, ev.height);
            p.insert(p.end(), ev.block_id.begin(), ev.block_id.end());
            put_u32(p, static_cast<std::uint32_t>(sorted.size()));
            const bytes32 compose = ::v37::sha256d(kib);
            p.insert(p.end(), compose.begin(), compose.end());
            ki_leaves_.push_back(leaf_hash(p));
            ::v37::Lane::mmr_append(ki_peaks_, ki_leaves_.back());
        }

        for (const OutputRecord& o : block_outs) outputs_.push_back(o);
        for (const Hash& ki : ev.key_images) {
            if (spent_.insert(ki).second) f.key_image_list.push_back(ki);
        }
        tip_height_ = ev.height;
        tip_id_     = ev.block_id;
        undo_.push_back(std::move(f));
        return true;
    }

    // Roll back the most-recent connected block: restore both peak sets bit-
    // exact, truncate both leaf logs, pop the outputs, erase the key images.
    bool on_block_disconnected(const BlockTxEvent& ev) {
        std::lock_guard<std::mutex> lk(mu_);
        if (undo_.empty()) return false;
        UndoFrame& f = undo_.back();
        if (f.height != ev.height) return false;
        for (std::size_t i = 0; i < f.outputs_added; ++i) outputs_.pop_back();
        for (const Hash& ki : f.key_image_list) spent_.erase(ki);
        out_peaks_ = f.out_peaks_before;
        ki_peaks_  = f.ki_peaks_before;
        out_leaves_.resize(static_cast<std::size_t>(out_peaks_.leaf_count));
        out_leaf_first_.resize(static_cast<std::size_t>(out_peaks_.leaf_count));
        ki_leaves_.resize(static_cast<std::size_t>(ki_peaks_.leaf_count));
        tip_height_ = f.prev_tip_height;
        tip_id_     = f.prev_tip_id;
        undo_.pop_back();
        return true;
    }

    // --- authenticated roots / digest ---------------------------------------
    bytes32 output_root() const {
        std::lock_guard<std::mutex> lk(mu_);
        return ::v37::Lane::mmr_bag(out_peaks_.peaks);
    }
    bytes32 spent_root() const {
        std::lock_guard<std::mutex> lk(mu_);
        return ::v37::Lane::mmr_bag(ki_peaks_.peaks);
    }
    std::uint64_t output_leaf_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return out_peaks_.leaf_count;
    }
    std::uint64_t spent_leaf_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return ki_peaks_.leaf_count;
    }

    // The single 32-byte value the anchor commits (the lane's digest-leaf
    // analogue): binds tip, base, frontier and both roots.
    bytes32 set_digest() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<std::uint8_t> p;
        put_tag(p, 'X','M','R','S');
        p.push_back(LEAF_VER);
        put_u64(p, tip_height_);
        p.insert(p.end(), tip_id_.begin(), tip_id_.end());
        put_u64(p, base_);
        put_u64(p, base_ + outputs_.size());                     // frontier
        put_u64(p, out_peaks_.leaf_count);
        const bytes32 orr = ::v37::Lane::mmr_bag(out_peaks_.peaks);
        p.insert(p.end(), orr.begin(), orr.end());
        put_u64(p, ki_peaks_.leaf_count);
        const bytes32 krr = ::v37::Lane::mmr_bag(ki_peaks_.peaks);
        p.insert(p.end(), krr.begin(), krr.end());
        return leaf_hash(p);
    }

    // --- membership proofs (log-size) ---------------------------------------
    // Prove the OUTPUT-leaf (one Monero block) that contains a global output
    // index. Verify with ::v37::Lane::mmr_verify against output_root().
    bool prove_output(std::uint64_t global_index,
                      bytes32& leaf_out, ::v37::Lane::MmrProof& proof_out) const {
        std::lock_guard<std::mutex> lk(mu_);
        if (global_index < base_) return false;
        // Locate the leaf whose [first, first+n) covers global_index. Leaves are
        // ordered by first_output_index, so upper_bound - 1 is the block.
        const auto it = std::upper_bound(out_leaf_first_.begin(), out_leaf_first_.end(),
                                         global_index);
        if (it == out_leaf_first_.begin()) return false;
        const std::size_t idx = static_cast<std::size_t>((it - out_leaf_first_.begin()) - 1);
        if (idx >= out_leaves_.size()) return false;
        leaf_out  = out_leaves_[idx];
        proof_out = ::v37::Lane::mmr_proof(out_leaves_, idx);
        return true;
    }
    // Prove the OUTPUT leaf at a leaf index directly (one leaf per connected
    // block), the symmetric form used to cross-check the root against a
    // c2pool::v37 RecordLog built from the same leaves.
    bool prove_output_leaf(std::uint64_t leaf_index,
                           bytes32& leaf_out, ::v37::Lane::MmrProof& proof_out) const {
        std::lock_guard<std::mutex> lk(mu_);
        if (leaf_index >= out_leaves_.size()) return false;
        leaf_out  = out_leaves_[static_cast<std::size_t>(leaf_index)];
        proof_out = ::v37::Lane::mmr_proof(out_leaves_, static_cast<std::size_t>(leaf_index));
        return true;
    }
    bool prove_spent_leaf(std::uint64_t leaf_index,
                          bytes32& leaf_out, ::v37::Lane::MmrProof& proof_out) const {
        std::lock_guard<std::mutex> lk(mu_);
        if (leaf_index >= ki_leaves_.size()) return false;
        leaf_out  = ki_leaves_[static_cast<std::size_t>(leaf_index)];
        proof_out = ::v37::Lane::mmr_proof(ki_leaves_, static_cast<std::size_t>(leaf_index));
        return true;
    }
    static bool verify(const bytes32& root, const bytes32& leaf,
                       const ::v37::Lane::MmrProof& p) {
        return ::v37::Lane::mmr_verify(root, leaf, p);
    }

    // --- persistence (state blob + re-derivation self-check) ----------------
    // A compact restore-from form: base, tip, both peak sets and both leaf
    // vectors + the per-leaf first-index index and the flat output table and the
    // spent set. On load the peaks are RE-DERIVED from the leaves and must match
    // (the record-log rule), else the load fails closed. The file-backed
    // append-only journal that writes this incrementally on the pool thread is a
    // follow-up seam; this is the whole-state snapshot it would checkpoint.
    std::string serialize() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::string s;
        s.push_back(char(SER_VER));
        put_u64(s, base_);
        put_u64(s, tip_height_);
        s.append(reinterpret_cast<const char*>(tip_id_.data()), tip_id_.size());
        // outputs
        put_u64(s, outputs_.size());
        for (const OutputRecord& o : outputs_) {
            s.append(reinterpret_cast<const char*>(o.pubkey.data()), 32);
            s.append(reinterpret_cast<const char*>(o.commitment.data()), 32);
            put_u64(s, o.unlock_time);
            put_u64(s, o.height);
        }
        // out leaves + first-index
        put_u64(s, out_leaves_.size());
        for (std::size_t i = 0; i < out_leaves_.size(); ++i) {
            s.append(reinterpret_cast<const char*>(out_leaves_[i].data()), 32);
            put_u64(s, out_leaf_first_[i]);
        }
        // ki leaves
        put_u64(s, ki_leaves_.size());
        for (const bytes32& h : ki_leaves_)
            s.append(reinterpret_cast<const char*>(h.data()), 32);
        // spent set (order-independent; re-inserted on load)
        put_u64(s, spent_.size());
        for (const Hash& ki : spent_)
            s.append(reinterpret_cast<const char*>(ki.data()), 32);
        return s;
    }
    // Returns nullptr on any malformation (unknown version, truncation, trailing
    // garbage). A std::mutex member makes the set non-movable, so the fallible
    // factory hands back a heap instance rather than a std::optional value.
    static std::unique_ptr<ChainOutputSet> deserialize(const std::string& v) {
        std::size_t o = 0;
        std::uint8_t ver = 0;
        if (!get_u8(v, o, ver) || ver != SER_VER) return nullptr;
        auto set = std::make_unique<ChainOutputSet>();
        if (!get_u64(v, o, set->base_)) return nullptr;
        if (!get_u64(v, o, set->tip_height_)) return nullptr;
        if (!get_bytes(v, o, set->tip_id_.data(), 32)) return nullptr;
        std::uint64_t n = 0;
        if (!get_u64(v, o, n)) return nullptr;
        set->outputs_.reserve(static_cast<std::size_t>(n));
        for (std::uint64_t i = 0; i < n; ++i) {
            OutputRecord r;
            if (!get_bytes(v, o, r.pubkey.data(), 32)) return nullptr;
            if (!get_bytes(v, o, r.commitment.data(), 32)) return nullptr;
            if (!get_u64(v, o, r.unlock_time)) return nullptr;
            if (!get_u64(v, o, r.height)) return nullptr;
            set->outputs_.push_back(r);
        }
        std::uint64_t nol = 0;
        if (!get_u64(v, o, nol)) return nullptr;
        for (std::uint64_t i = 0; i < nol; ++i) {
            bytes32 h{};
            if (!get_bytes(v, o, h.data(), 32)) return nullptr;
            std::uint64_t first = 0;
            if (!get_u64(v, o, first)) return nullptr;
            set->out_leaves_.push_back(h);
            set->out_leaf_first_.push_back(first);
            ::v37::Lane::mmr_append(set->out_peaks_, h);
        }
        std::uint64_t nkl = 0;
        if (!get_u64(v, o, nkl)) return nullptr;
        for (std::uint64_t i = 0; i < nkl; ++i) {
            bytes32 h{};
            if (!get_bytes(v, o, h.data(), 32)) return nullptr;
            set->ki_leaves_.push_back(h);
            ::v37::Lane::mmr_append(set->ki_peaks_, h);
        }
        std::uint64_t ns = 0;
        if (!get_u64(v, o, ns)) return nullptr;
        for (std::uint64_t i = 0; i < ns; ++i) {
            Hash ki{};
            if (!get_bytes(v, o, ki.data(), 32)) return nullptr;
            set->spent_.insert(ki);
        }
        if (o != v.size()) return nullptr;   // trailing garbage
        return set;
    }

    // --- format-2 anchor seed (O-backfill) ----------------------------------
    // Seed the historical set from an operator-supplied snapshot (serialize()
    // form) committed by a format-2 anchor, so a daemonless node booting from
    // that anchor can RESOLVE + CLSAG-verify rings whose members are BELOW the
    // anchor's numbering base, and reject a below-base double-spend. Legal only
    // on an EMPTY set (at boot, before any block feeds).
    //
    // WHAT THE ANCHOR AUTHENTICATES, STATED PRECISELY. The snapshot's peaks are
    // RE-DERIVED from its leaves inside deserialize() (the record-log rule), and
    // this checks the re-derived output/spent ROOTS, the two LEAF COUNTS, the
    // TIP, and the FRONTIER against the bundle -- so the snapshot's authenticated
    // LEAF STRUCTURE is bound to the anchor and any corruption that reaches a
    // leaf (bulk/random damage always does) fails closed, leaving the set empty.
    // The serialize() form (inherited from the input-consensus pass) stores the
    // resolve table and the flat spent set SEPARATELY from the leaves and carries
    // no per-block block_id, so a surgical edit that changes only those tables
    // while leaving every leaf intact is NOT caught here: the operator-supplied
    // snapshot is a TRUSTED input whose structure the anchor verifies, not an
    // untrusted blob made trustless by the roots alone. The fully trustless path
    // -- a peer walking blocks 1..H_a and re-deriving the tables to the same
    // roots -- is the documented O-backfill follow-on (node/xmr_sync_driver).
    bool seed_from_snapshot(const std::string& blob, const AnchorBundle& b, std::string& why) {
        std::lock_guard<std::mutex> lk(mu_);
        if (!outputs_.empty() || tip_height_ != 0 || out_peaks_.leaf_count != 0
            || !spent_.empty()) {
            why = "output set is not empty; seed the anchor snapshot before any block connects";
            return false;
        }
        if (!b.has_output_set()) {
            why = "anchor bundle carries no committed output set to seed against";
            return false;
        }
        std::unique_ptr<ChainOutputSet> t = deserialize(blob);
        if (!t) { why = "output-set snapshot does not deserialize"; return false; }

        // Every committed quantity must match the re-derived snapshot exactly.
        if (t->tip_height_ != b.height) {
            why = "snapshot tip height " + std::to_string(t->tip_height_)
                + " != anchor height " + std::to_string(b.height);
            return false;
        }
        if (t->tip_id_ != b.id) { why = "snapshot tip id != anchor id"; return false; }
        if (t->base_ + t->outputs_.size() != b.rct_output_count) {
            why = "snapshot frontier " + std::to_string(t->base_ + t->outputs_.size())
                + " != anchor rct_output_count " + std::to_string(b.rct_output_count);
            return false;
        }
        if (t->out_peaks_.leaf_count != b.output_set_leaves) {
            why = "snapshot output-leaf count " + std::to_string(t->out_peaks_.leaf_count)
                + " != anchor output_set_leaves " + std::to_string(b.output_set_leaves);
            return false;
        }
        if (::v37::Lane::mmr_bag(t->out_peaks_.peaks) != b.output_set_root) {
            why = "snapshot output-set root does not match the anchor's committed root";
            return false;
        }
        if (t->ki_peaks_.leaf_count != b.spent_set_leaves) {
            why = "snapshot spent-leaf count " + std::to_string(t->ki_peaks_.leaf_count)
                + " != anchor spent_set_leaves " + std::to_string(b.spent_set_leaves);
            return false;
        }
        if (::v37::Lane::mmr_bag(t->ki_peaks_.peaks) != b.spent_set_root) {
            why = "snapshot spent-set root does not match the anchor's committed root";
            return false;
        }

        // Adopt the re-derived, root-checked state. The numbering base becomes
        // the snapshot's (0 on a from-genesis walk), so below-base offsets now
        // satisfy off >= base_ in resolve() and CLSAG runs. undo_ stays empty:
        // pre-anchor blocks are below the reorg floor and are never disconnected.
        base_           = t->base_;
        outputs_        = std::move(t->outputs_);
        spent_          = std::move(t->spent_);
        out_peaks_      = t->out_peaks_;
        out_leaves_     = std::move(t->out_leaves_);
        out_leaf_first_ = std::move(t->out_leaf_first_);
        ki_peaks_       = t->ki_peaks_;
        ki_leaves_      = std::move(t->ki_leaves_);
        tip_height_     = t->tip_height_;
        tip_id_         = t->tip_id_;
        why.clear();
        return true;
    }

    // Membership check for a single global output index against the seeded root:
    // resolves the covering leaf, proves it, and verifies the proof against
    // output_root(). Exposed for the KAT's below-base membership assertion.
    bool verify_member(std::uint64_t global_index) const {
        bytes32 leaf{};
        ::v37::Lane::MmrProof proof;
        bytes32 root;
        {
            std::lock_guard<std::mutex> lk(mu_);
            // Only an index actually inside the set is a member; prove_output
            // returns the covering leaf and does not itself bound the far end.
            if (global_index < base_ || global_index >= base_ + outputs_.size())
                return false;
            root = ::v37::Lane::mmr_bag(out_peaks_.peaks);
        }
        if (!prove_output(global_index, leaf, proof)) return false;
        return ::v37::Lane::mmr_verify(root, leaf, proof);
    }

    // --- introspection (KATs, dashboard) ------------------------------------
    std::uint64_t first_output_index() const {
        std::lock_guard<std::mutex> lk(mu_);
        return base_;
    }
    std::uint64_t frontier() const {
        std::lock_guard<std::mutex> lk(mu_);
        return base_ + outputs_.size();
    }
    std::size_t output_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return outputs_.size();
    }
    std::size_t spent_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return spent_.size();
    }

private:
    struct UndoFrame {
        std::uint64_t     height          = 0;
        Hash              block_id{};
        std::size_t       outputs_added   = 0;
        std::vector<Hash> key_image_list;      // only those actually inserted
        ::v37::PeakSet    out_peaks_before;     // bit-exact reorg restore
        ::v37::PeakSet    ki_peaks_before;
        std::uint64_t     prev_tip_height = 0;
        Hash              prev_tip_id{};
    };

    // The lane leaf rule, mirrored (Lane::leaf_hash is private) -- identical to
    // record_log.hpp and w5_coinbase.hpp: leaf = sha256d(0x00 || payload).
    static bytes32 leaf_hash(const std::vector<std::uint8_t>& payload) {
        std::vector<std::uint8_t> b;
        b.reserve(payload.size() + 1);
        b.push_back(0x00);
        b.insert(b.end(), payload.begin(), payload.end());
        return ::v37::sha256d(b);
    }

    static void put_tag(std::vector<std::uint8_t>& s, char a, char b, char c, char d) {
        s.push_back(std::uint8_t(a)); s.push_back(std::uint8_t(b));
        s.push_back(std::uint8_t(c)); s.push_back(std::uint8_t(d));
    }
    static void put_u32(std::vector<std::uint8_t>& s, std::uint32_t x) {
        for (int i = 0; i < 4; ++i) s.push_back(std::uint8_t((x >> (8 * i)) & 0xff));
    }
    static void put_u64(std::vector<std::uint8_t>& s, std::uint64_t x) {
        for (int i = 0; i < 8; ++i) s.push_back(std::uint8_t((x >> (8 * i)) & 0xff));
    }
    static void put_u64(std::string& s, std::uint64_t x) {
        for (int i = 0; i < 8; ++i) s.push_back(char((x >> (8 * i)) & 0xff));
    }
    static bool get_u8(const std::string& v, std::size_t& o, std::uint8_t& x) {
        if (o + 1 > v.size()) return false;
        x = std::uint8_t(v[o++]);
        return true;
    }
    static bool get_u64(const std::string& v, std::size_t& o, std::uint64_t& x) {
        if (o + 8 > v.size()) return false;
        x = 0;
        for (int i = 0; i < 8; ++i) x |= std::uint64_t(std::uint8_t(v[o++])) << (8 * i);
        return true;
    }
    static bool get_bytes(const std::string& v, std::size_t& o, std::uint8_t* dst, std::size_t n) {
        if (o + n > v.size()) return false;
        for (std::size_t i = 0; i < n; ++i) dst[i] = std::uint8_t(v[o++]);
        return true;
    }

    mutable std::mutex               mu_;
    std::uint64_t                    base_ = 0;   // first_output_index
    // False only after disable_resolution() -- a FORMAT-1 anchor boot, where the
    // real numbering base is unknown. resolve() then fails closed for every ring.
    bool                             resolution_enabled_ = true;
    std::vector<OutputRecord>        outputs_;    // random-access resolve table
    std::unordered_set<Hash, HashHasher> spent_;  // random-access spent oracle

    // Authenticated append-only logs (one leaf per connected block), reusing the
    // shipped consensus MMR. out_leaf_first_[i] is leaf i's first global index.
    ::v37::PeakSet                   out_peaks_;
    std::vector<bytes32>             out_leaves_;
    std::vector<std::uint64_t>       out_leaf_first_;
    ::v37::PeakSet                   ki_peaks_;
    std::vector<bytes32>             ki_leaves_;

    std::uint64_t                    tip_height_ = 0;
    Hash                             tip_id_{};
    std::vector<UndoFrame>           undo_;
};

} // namespace c2pool::xmr::native
