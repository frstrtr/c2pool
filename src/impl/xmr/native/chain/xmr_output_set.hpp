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
// ANCHOR SNAPSHOT SERVED IN PLACE (output-set RAM). A format-2 snapshot is
// immutable once its roots check against the anchor, so the seeded part is NOT
// copied into heap tables: the flat output table and the flat spent-key-image
// table are served straight out of the snapshot bytes -- a read-only mmap of
// the --output-set file (seed_from_snapshot_file), or an owned copy of the blob
// (seed_from_snapshot). Output i below the snapshot frontier is the fixed-width
// 80-byte row i of the table; a spent check binary-searches a DERIVED index --
// a u32 permutation of the table in ascending key order plus a prefix bucket
// directory -- rebuilt in memory from the snapshot bytes on every seed, so it is
// never persisted and can never be stale. Only what the chain adds AFTER the
// anchor (outputs, key images, reorg undo) lives in the heap overlay
// (outputs_, spent_), exactly as before. The snapshot format, its digests and
// every answer resolve()/is_spent() give are unchanged; mainnet heap drops from
// ~22 GB settled (~38 GB peak) to the index (4 bytes per spent key image) and
// the per-block leaves.
//
// Header-only; the STL, POSIX mmap, the shipped lane MMR statics (STL-only),
// and the rct ops (linked into xmr_native_txpool, which every consumer of this
// header -- the node and the output-set KAT -- already links). One mutex,
// because the chain thread writes while the pool thread resolves.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

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
        if (total_outputs_() != 0) return false;
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
            if (idx >= total_outputs_()) return false;     // beyond our frontier
            if (idx < snap_.n) out.push_back(snap_output_(idx));   // anchor snapshot
            else out.push_back(outputs_[static_cast<std::size_t>(idx - snap_.n)]);
        }
        return true;
    }

    // --- ISpentKeyImageView -------------------------------------------------
    bool is_spent(const Hash& ki) const override {
        std::lock_guard<std::mutex> lk(mu_);
        return spent_.find(ki) != spent_.end() || snap_has_ki_(ki);
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
        return connect_locked_(ev);
    }

private:
    bool connect_locked_(const BlockTxEvent& ev) {
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

        const std::uint64_t frontier = base_ + total_outputs_();
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
            // A key image already in the anchor snapshot is not "inserted" (the
            // set semantics the heap table had), so a disconnect never erases it.
            if (!snap_has_ki_(ki) && spent_.insert(ki).second)
                f.key_image_list.push_back(ki);
            else
                f.key_images_skipped.push_back(ki);   // kept only so the overlay can
                                                      // re-derive this block's KI leaf
        }
        tip_height_ = ev.height;
        tip_id_     = ev.block_id;
        undo_.push_back(std::move(f));
        return true;
    }

public:

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
        put_u64(p, base_ + total_outputs_());                    // frontier
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
        // outputs (anchor-snapshot rows verbatim -- same encoding -- then overlay)
        put_u64(s, total_outputs_());
        if (snap_.n)
            s.append(reinterpret_cast<const char*>(snap_.out_rows),
                     static_cast<std::size_t>(snap_.n * OUT_ROW));
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
        put_u64(s, snap_.ns_distinct + spent_.size());
        for (std::size_t i = 0; i < snap_.ki_order.size(); ++i) {
            const std::uint8_t* k = snap_ki_(snap_.ki_order[i]);
            if (i != 0 && std::memcmp(k, snap_ki_(snap_.ki_order[i - 1]), 32) == 0) continue;
            s.append(reinterpret_cast<const char*>(k), 32);
        }
        for (const Hash& ki : spent_)
            s.append(reinterpret_cast<const char*>(ki.data()), 32);
        return s;
    }
    // Returns nullptr on any malformation (unknown version, truncation, trailing
    // garbage). A std::mutex member makes the set non-movable, so the fallible
    // factory hands back a heap instance rather than a std::optional value.
    static std::unique_ptr<ChainOutputSet> deserialize(const std::string& v) {
        Parsed_ t;
        if (!parse_(reinterpret_cast<const std::uint8_t*>(v.data()), v.size(), t)) return nullptr;
        auto set = std::make_unique<ChainOutputSet>();
        set->base_       = t.base;
        set->tip_height_ = t.tip_height;
        set->tip_id_     = t.tip_id;
        set->outputs_.reserve(static_cast<std::size_t>(t.n));
        for (std::uint64_t i = 0; i < t.n; ++i)
            set->outputs_.push_back(decode_row_(t.out_rows + i * OUT_ROW));
        set->out_peaks_      = t.out_peaks;
        set->out_leaves_     = std::move(t.out_leaves);
        set->out_leaf_first_ = std::move(t.out_leaf_first);
        set->ki_peaks_       = t.ki_peaks;
        set->ki_leaves_      = std::move(t.ki_leaves);
        for (std::uint64_t i = 0; i < t.ns; ++i) {
            Hash ki{};
            std::memcpy(ki.data(), t.ki_rows + i * 32, 32);
            set->spent_.insert(ki);
        }
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
    //
    // The seeded tables are NOT copied into the heap: they are served in place
    // from the snapshot bytes (see ANCHOR SNAPSHOT SERVED IN PLACE above). This
    // overload keeps one owned copy of `blob`; the node uses
    // seed_from_snapshot_file(), which maps the file read-only instead.
    bool seed_from_snapshot(const std::string& blob, const AnchorBundle& b, std::string& why) {
        auto keep = std::make_shared<const std::string>(blob);
        std::shared_ptr<const std::uint8_t> bytes(
            keep, reinterpret_cast<const std::uint8_t*>(keep->data()));
        return seed_bytes_(std::move(bytes), keep->size(), /*mapped=*/false, b, why);
    }

    // The node's path: map the --output-set file READ-ONLY and serve the anchor
    // snapshot out of the mapping (page cache, not heap). Identical checks and
    // answers to seed_from_snapshot(read the whole file, ...). The file must not
    // be modified while the node runs (it is a pinned, sha256-checked input).
    bool seed_from_snapshot_file(const std::string& path, const AnchorBundle& b, std::string& why) {
#if defined(_WIN32)
        std::ifstream f(path, std::ios::binary);
        if (!f) { why = "cannot open output-set snapshot '" + path + "'"; return false; }
        const std::string blob((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        return seed_from_snapshot(blob, b, why);
#else
        const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) { why = "cannot open output-set snapshot '" + path + "'"; return false; }
        struct stat st {};
        if (::fstat(fd, &st) != 0 || st.st_size < 0) {
            ::close(fd);
            why = "cannot stat output-set snapshot '" + path + "'";
            return false;
        }
        const std::size_t len = static_cast<std::size_t>(st.st_size);
        if (len == 0) { ::close(fd); why = "output-set snapshot does not deserialize"; return false; }
        void* m = ::mmap(nullptr, len, PROT_READ, MAP_PRIVATE, fd, 0);
        ::close(fd);   // the mapping keeps the file referenced
        if (m == MAP_FAILED) { why = "cannot map output-set snapshot '" + path + "'"; return false; }
        std::shared_ptr<const std::uint8_t> bytes(
            static_cast<const std::uint8_t*>(m),
            [len](const std::uint8_t* p) { ::munmap(const_cast<std::uint8_t*>(p), len); });
        return seed_bytes_(std::move(bytes), len, /*mapped=*/true, b, why);
#endif
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
            if (global_index < base_ || global_index >= base_ + total_outputs_())
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
        return base_ + total_outputs_();
    }
    std::size_t output_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return static_cast<std::size_t>(total_outputs_());
    }
    std::size_t spent_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return static_cast<std::size_t>(snap_.ns_distinct) + spent_.size();
    }
    // How many outputs / key images are served in place from the anchor
    // snapshot (0 when nothing was seeded) rather than held in the heap.
    std::uint64_t snapshot_output_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return snap_.n;
    }
    std::uint64_t snapshot_spent_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return snap_.ns_distinct;
    }
    bool has_anchor_snapshot() const {
        std::lock_guard<std::mutex> lk(mu_);
        return snap_.bytes != nullptr;
    }
    std::uint64_t tip_height() const {
        std::lock_guard<std::mutex> lk(mu_);
        return tip_height_;
    }
    Hash tip_id() const {
        std::lock_guard<std::mutex> lk(mu_);
        return tip_id_;
    }
    // How many post-anchor blocks the overlay holds (one undo frame each).
    std::size_t overlay_block_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return undo_.size();
    }

    // --- post-anchor OVERLAY persistence (restart resume) -------------------
    // The anchor snapshot is immutable and stays exactly where it is (the
    // read-only --output-set file). What a restart loses is only the overlay the
    // chain added on top of it: the post-anchor outputs, the post-anchor spent
    // key images, one leaf per block in each log and the per-block undo frames.
    // serialize_overlay() writes exactly that, per connected block in chain
    // order, BOUND to the snapshot it sits on (base, snapshot frontier, both
    // snapshot leaf counts and roots, snapshot tip) and closed by the final
    // tip / frontier / leaf counts / roots and a sha256d over the whole blob.
    //
    // load_overlay() does not trust any stored leaf, peak or table: it REPLAYS
    // every block through the same connect path a live block takes, so the
    // leaves, peaks, spent overlay and undo frames are re-derived, and then
    // requires the re-derived tip, frontier, counts and roots to equal the
    // ones recorded at save time. Any mismatch -- digest, binding, truncation,
    // height gap, a replay the connect path refuses, a root that differs --
    // rolls the set back to the bare anchor snapshot and returns false, so the
    // caller can fall back to the from-anchor re-walk. Consensus answers are
    // unchanged: after a successful load the set is bit-identical (roots,
    // counts, resolve, is_spent, reorg frames) to the one that was saved.
    static constexpr std::uint64_t OVERLAY_MAGIC = 0x31594C564F583243ull;   // "C2XOVLY1"
    static constexpr std::uint64_t OVERLAY_VER   = 1;

    bool serialize_overlay(std::vector<std::uint8_t>& out, std::string& why) const {
        std::lock_guard<std::mutex> lk(mu_);
        out.clear();
        if (!snap_.bytes) { why = "no anchor snapshot is seeded; there is no overlay to persist"; return false; }
        const std::size_t so = static_cast<std::size_t>(snap_.out_peaks.leaf_count);
        const std::size_t sk = static_cast<std::size_t>(snap_.ki_peaks.leaf_count);
        if (out_leaves_.size() != so + undo_.size() || ki_leaves_.size() != sk + undo_.size()
            || out_leaf_first_.size() != out_leaves_.size()) {
            why = "overlay undo frames disagree with the leaf logs";
            return false;
        }
        std::vector<std::uint8_t> p;
        p.reserve(256 + outputs_.size() * OUT_ROW + spent_.size() * 32 + undo_.size() * 80);
        put_u64(p, OVERLAY_MAGIC);
        put_u64(p, OVERLAY_VER);
        put_u64(p, base_);
        put_u64(p, snap_.n);
        put_u64(p, snap_.out_peaks.leaf_count);
        put_h32_(p, ::v37::Lane::mmr_bag(snap_.out_peaks.peaks));
        put_u64(p, snap_.ki_peaks.leaf_count);
        put_h32_(p, ::v37::Lane::mmr_bag(snap_.ki_peaks.peaks));
        put_u64(p, snap_.tip_height);
        put_h32_(p, snap_.tip_id);
        put_u64(p, tip_height_);
        put_h32_(p, tip_id_);
        put_u64(p, base_ + total_outputs_());
        put_u64(p, out_peaks_.leaf_count);
        put_h32_(p, ::v37::Lane::mmr_bag(out_peaks_.peaks));
        put_u64(p, ki_peaks_.leaf_count);
        put_h32_(p, ::v37::Lane::mmr_bag(ki_peaks_.peaks));
        put_u64(p, undo_.size());
        std::size_t oi = 0;
        for (std::size_t k = 0; k < undo_.size(); ++k) {
            const UndoFrame& f = undo_[k];
            put_u64(p, f.height);
            put_h32_(p, f.block_id);
            put_u64(p, out_leaf_first_[so + k]);
            put_u64(p, f.outputs_added);
            if (f.outputs_added > outputs_.size() - oi) { why = "overlay frames overrun the output table"; return false; }
            for (std::size_t i = 0; i < f.outputs_added; ++i, ++oi) {
                const OutputRecord& o = outputs_[oi];
                p.insert(p.end(), o.pubkey.begin(), o.pubkey.end());
                p.insert(p.end(), o.commitment.begin(), o.commitment.end());
                put_u64(p, o.unlock_time);
                put_u64(p, o.height);
            }
            put_u64(p, f.key_image_list.size());
            for (const Hash& ki : f.key_image_list) p.insert(p.end(), ki.begin(), ki.end());
            put_u64(p, f.key_images_skipped.size());
            for (const Hash& ki : f.key_images_skipped) p.insert(p.end(), ki.begin(), ki.end());
        }
        if (oi != outputs_.size()) { why = "overlay output table is longer than its frames"; return false; }
        const bytes32 d = ::v37::sha256d(p);
        p.insert(p.end(), d.begin(), d.end());
        out = std::move(p);
        why.clear();
        return true;
    }

    bool load_overlay(const std::vector<std::uint8_t>& blob, std::string& why) {
        std::lock_guard<std::mutex> lk(mu_);
        if (!snap_.bytes) { why = "no anchor snapshot is seeded to lay the overlay over"; return false; }
        if (!undo_.empty() || !outputs_.empty() || !spent_.empty()
            || out_peaks_.leaf_count != snap_.out_peaks.leaf_count
            || ki_peaks_.leaf_count != snap_.ki_peaks.leaf_count
            || tip_height_ != snap_.tip_height || tip_id_ != snap_.tip_id) {
            why = "output set has already advanced past its anchor snapshot";
            return false;
        }
        const bool ok = load_overlay_locked_(blob, why);
        if (!ok) rollback_to_snapshot_locked_();
        return ok;
    }

    // Drop every post-anchor block and return to the bare anchor snapshot (the
    // state seed_from_snapshot*() left). A caller that loaded an overlay and
    // then could not use it (the chain image it belongs to was refused) calls
    // this before falling back to the from-anchor re-walk.
    bool drop_overlay() {
        std::lock_guard<std::mutex> lk(mu_);
        if (!snap_.bytes) return false;
        rollback_to_snapshot_locked_();
        return true;
    }

private:
    static void put_h32_(std::vector<std::uint8_t>& s, const bytes32& h) {
        s.insert(s.end(), h.begin(), h.end());
    }

    void rollback_to_snapshot_locked_() {
        std::vector<OutputRecord>().swap(outputs_);
        spent_.clear();
        undo_.clear();
        out_leaves_.resize(static_cast<std::size_t>(snap_.out_peaks.leaf_count));
        out_leaf_first_.resize(static_cast<std::size_t>(snap_.out_peaks.leaf_count));
        ki_leaves_.resize(static_cast<std::size_t>(snap_.ki_peaks.leaf_count));
        out_peaks_  = snap_.out_peaks;
        ki_peaks_   = snap_.ki_peaks;
        tip_height_ = snap_.tip_height;
        tip_id_     = snap_.tip_id;
    }

    bool load_overlay_locked_(const std::vector<std::uint8_t>& blob, std::string& why) {
        if (blob.size() < 32) { why = "overlay is truncated (shorter than its digest)"; return false; }
        const std::size_t len = blob.size() - 32;
        const std::uint8_t* d = blob.data();
        {
            const bytes32 dg = ::v37::sha256d(d, len);
            if (std::memcmp(dg.data(), d + len, 32) != 0) {
                why = "overlay digest does not match its contents (truncated or corrupt)";
                return false;
            }
        }
        std::size_t o = 0;
        bool bad = false;
        auto u64 = [&]() -> std::uint64_t {
            if (bad || len - o < 8) { bad = true; return 0; }
            const std::uint64_t x = rd_u64_(d + o); o += 8; return x;
        };
        auto h32 = [&]() -> bytes32 {
            bytes32 h{};
            if (bad || len - o < 32) { bad = true; return h; }
            std::memcpy(h.data(), d + o, 32); o += 32; return h;
        };
        if (u64() != OVERLAY_MAGIC) { why = "overlay magic is wrong"; return false; }
        if (u64() != OVERLAY_VER)   { why = "overlay version is not one this build writes"; return false; }
        const std::uint64_t base = u64(), sn = u64();
        const std::uint64_t sol = u64(); const bytes32 sor = h32();
        const std::uint64_t skl = u64(); const bytes32 skr = h32();
        const std::uint64_t sth = u64(); const bytes32 sti = h32();
        const std::uint64_t th  = u64(); const bytes32 ti  = h32();
        const std::uint64_t fr  = u64();
        const std::uint64_t ol  = u64(); const bytes32 orr = h32();
        const std::uint64_t kl  = u64(); const bytes32 krr = h32();
        const std::uint64_t nb  = u64();
        if (bad) { why = "overlay header is truncated"; return false; }
        if (base != base_ || sn != snap_.n
            || sol != snap_.out_peaks.leaf_count || sor != ::v37::Lane::mmr_bag(snap_.out_peaks.peaks)
            || skl != snap_.ki_peaks.leaf_count || skr != ::v37::Lane::mmr_bag(snap_.ki_peaks.peaks)
            || sth != snap_.tip_height || sti != snap_.tip_id) {
            why = "overlay is bound to a different anchor snapshot than the one seeded";
            return false;
        }
        if (nb != th - sth || th < sth) {
            why = "overlay block count disagrees with its tip height";
            return false;
        }
        std::uint64_t expect_h = sth + 1;
        for (std::uint64_t k = 0; k < nb; ++k, ++expect_h) {
            BlockTxEvent ev;
            ev.kind               = BlockTxEvent::Kind::Connected;
            ev.height             = u64();
            ev.block_id           = h32();
            ev.first_output_index = u64();
            const std::uint64_t no = u64();
            if (bad || no > (len - o) / OUT_ROW) { why = "overlay block " + std::to_string(k) + " is truncated"; return false; }
            ev.outputs.reserve(static_cast<std::size_t>(no));
            for (std::uint64_t i = 0; i < no; ++i, o += OUT_ROW) ev.outputs.push_back(decode_row_(d + o));
            const std::uint64_t ni = u64();
            if (bad || ni > (len - o) / 32) { why = "overlay block " + std::to_string(k) + " is truncated"; return false; }
            ev.key_images.reserve(static_cast<std::size_t>(ni));
            for (std::uint64_t i = 0; i < ni; ++i) ev.key_images.push_back(h32());
            const std::uint64_t ns = u64();
            if (bad || ns > (len - o) / 32) { why = "overlay block " + std::to_string(k) + " is truncated"; return false; }
            for (std::uint64_t i = 0; i < ns; ++i) ev.key_images.push_back(h32());
            if (bad) { why = "overlay block " + std::to_string(k) + " is truncated"; return false; }
            if (ev.height != expect_h) {
                why = "overlay block " + std::to_string(k) + " sits at height " + std::to_string(ev.height)
                    + ", expected " + std::to_string(expect_h);
                return false;
            }
            // Re-derive through the live connect path (leaves, peaks, spent
            // overlay, undo frame). The replay must split the key images into
            // inserted / already-spent exactly as the saving node did.
            if (!connect_locked_(ev)) {
                why = "overlay block at height " + std::to_string(ev.height) + " does not connect";
                return false;
            }
            const UndoFrame& f = undo_.back();
            if (f.key_image_list.size() != ni || f.key_images_skipped.size() != ns) {
                why = "overlay block at height " + std::to_string(ev.height)
                    + " re-derives a different spent set";
                return false;
            }
        }
        if (o != len) { why = "overlay carries trailing bytes"; return false; }
        if (tip_height_ != th || tip_id_ != ti) { why = "overlay re-derived tip differs from its recorded tip"; return false; }
        if (base_ + total_outputs_() != fr) { why = "overlay re-derived frontier differs from its recorded frontier"; return false; }
        if (out_peaks_.leaf_count != ol || ::v37::Lane::mmr_bag(out_peaks_.peaks) != orr) {
            why = "overlay re-derived output root differs from its recorded root";
            return false;
        }
        if (ki_peaks_.leaf_count != kl || ::v37::Lane::mmr_bag(ki_peaks_.peaks) != krr) {
            why = "overlay re-derived spent root differs from its recorded root";
            return false;
        }
        why.clear();
        return true;
    }

    // One flat output row of the serialize() form: pubkey|commitment|unlock|height.
    static constexpr std::size_t OUT_ROW = 32 + 32 + 8 + 8;

    // The immutable anchor-snapshot part, served in place. `bytes` owns the
    // backing (a read-only file mapping or an owned blob copy); out_rows / ki_rows
    // point into it. ki_order is the derived spent index: the snapshot's key-image
    // rows in ascending byte order, as u32 row numbers; ki_dir[b] is the first
    // position in ki_order whose top dir_bits bits are >= b (ki_dir has
    // 2^dir_bits + 1 entries), so a lookup binary-searches one small bucket.
    struct SnapshotPart {
        std::shared_ptr<const std::uint8_t> bytes;
        const std::uint8_t*        out_rows    = nullptr;
        std::uint64_t              n           = 0;
        const std::uint8_t*        ki_rows     = nullptr;
        std::uint64_t              ns          = 0;
        std::uint64_t              ns_distinct = 0;
        std::vector<std::uint32_t> ki_order;
        std::vector<std::uint32_t> ki_dir;
        unsigned                   dir_bits    = 0;
        // The authenticated state AT the snapshot (the overlay binds to it and
        // a rollback returns to it): both peak sets and the snapshot's tip.
        ::v37::PeakSet             out_peaks;
        ::v37::PeakSet             ki_peaks;
        std::uint64_t              tip_height  = 0;
        Hash                       tip_id{};
    };

    // The serialize() form, located in place (no table copied). Leaves are
    // copied (one per block, small) and the peaks RE-DERIVED from them.
    struct Parsed_ {
        std::uint64_t              base = 0, tip_height = 0;
        Hash                       tip_id{};
        const std::uint8_t*        out_rows = nullptr;
        std::uint64_t              n = 0;
        std::vector<bytes32>       out_leaves;
        std::vector<std::uint64_t> out_leaf_first;
        ::v37::PeakSet             out_peaks;
        std::vector<bytes32>       ki_leaves;
        ::v37::PeakSet             ki_peaks;
        const std::uint8_t*        ki_rows = nullptr;
        std::uint64_t              ns = 0;
    };

    // False on any malformation (unknown version, truncation, trailing garbage)
    // -- exactly the inputs the heap deserialize() refused.
    static bool parse_(const std::uint8_t* d, std::size_t len, Parsed_& t) {
        std::size_t o = 0;
        auto u64 = [&](std::uint64_t& x) {
            if (len - o < 8) return false;
            x = rd_u64_(d + o); o += 8; return true;
        };
        auto take = [&](std::uint64_t count, std::size_t width, const std::uint8_t*& at) {
            if (count > (len - o) / width) return false;       // truncated (overflow-safe)
            at = d + o; o += static_cast<std::size_t>(count) * width; return true;
        };
        if (len < 1 || d[0] != SER_VER) return false;
        o = 1;
        if (!u64(t.base) || !u64(t.tip_height)) return false;
        if (len - o < 32) return false;
        std::memcpy(t.tip_id.data(), d + o, 32); o += 32;
        if (!u64(t.n) || !take(t.n, OUT_ROW, t.out_rows)) return false;
        std::uint64_t nol = 0;
        const std::uint8_t* ol = nullptr;
        if (!u64(nol) || !take(nol, 40, ol)) return false;
        t.out_leaves.reserve(static_cast<std::size_t>(nol));
        t.out_leaf_first.reserve(static_cast<std::size_t>(nol));
        for (std::uint64_t i = 0; i < nol; ++i) {
            bytes32 h{};
            std::memcpy(h.data(), ol + i * 40, 32);
            t.out_leaves.push_back(h);
            t.out_leaf_first.push_back(rd_u64_(ol + i * 40 + 32));
            ::v37::Lane::mmr_append(t.out_peaks, h);
        }
        std::uint64_t nkl = 0;
        const std::uint8_t* kl = nullptr;
        if (!u64(nkl) || !take(nkl, 32, kl)) return false;
        t.ki_leaves.reserve(static_cast<std::size_t>(nkl));
        for (std::uint64_t i = 0; i < nkl; ++i) {
            bytes32 h{};
            std::memcpy(h.data(), kl + i * 32, 32);
            t.ki_leaves.push_back(h);
            ::v37::Lane::mmr_append(t.ki_peaks, h);
        }
        if (!u64(t.ns) || !take(t.ns, 32, t.ki_rows)) return false;
        return o == len;                                         // trailing garbage
    }

    static std::uint64_t rd_u64_(const std::uint8_t* p) {
        std::uint64_t x = 0;
        for (int i = 0; i < 8; ++i) x |= std::uint64_t(p[i]) << (8 * i);
        return x;
    }
    static std::uint64_t be_prefix_(const std::uint8_t* p) {    // byte order == memcmp order
        std::uint64_t x = 0;
        for (int i = 0; i < 8; ++i) x = (x << 8) | p[i];
        return x;
    }
    static OutputRecord decode_row_(const std::uint8_t* r) {
        OutputRecord o;
        std::memcpy(o.pubkey.data(), r, 32);
        std::memcpy(o.commitment.data(), r + 32, 32);
        o.unlock_time = rd_u64_(r + 64);
        o.height      = rd_u64_(r + 72);
        return o;
    }

    std::uint64_t total_outputs_() const { return snap_.n + outputs_.size(); }
    OutputRecord snap_output_(std::uint64_t i) const { return decode_row_(snap_.out_rows + i * OUT_ROW); }
    const std::uint8_t* snap_ki_(std::uint32_t row) const { return snap_.ki_rows + std::size_t(row) * 32; }

    bool snap_has_ki_(const Hash& ki) const {
        if (snap_.ns == 0) return false;
        std::size_t lo = 0, hi = snap_.ki_order.size();
        if (snap_.dir_bits != 0) {
            const std::size_t bkt = static_cast<std::size_t>(be_prefix_(ki.data()) >> (64 - snap_.dir_bits));
            lo = snap_.ki_dir[bkt];
            hi = snap_.ki_dir[bkt + 1];
        }
        while (lo < hi) {
            const std::size_t mid = lo + (hi - lo) / 2;
            const int c = std::memcmp(snap_ki_(snap_.ki_order[mid]), ki.data(), 32);
            if (c == 0) return true;
            if (c < 0) lo = mid + 1; else hi = mid;
        }
        return false;
    }

    // Build the derived spent index over the snapshot's key-image rows. One
    // sequential pass reads each row's 8-byte prefix; the (prefix,row) pairs are
    // sorted (a full-key compare breaks prefix ties) and only the row numbers
    // are kept.
    static bool build_ki_index_(SnapshotPart& sp) {
        if (sp.ns > std::numeric_limits<std::uint32_t>::max()) return false;
        const std::size_t ns = static_cast<std::size_t>(sp.ns);
        std::vector<std::pair<std::uint64_t, std::uint32_t>> keyed;
        keyed.reserve(ns);
        for (std::size_t i = 0; i < ns; ++i)
            keyed.emplace_back(be_prefix_(sp.ki_rows + i * 32), static_cast<std::uint32_t>(i));
        const std::uint8_t* rows = sp.ki_rows;
        std::sort(keyed.begin(), keyed.end(),
                  [rows](const std::pair<std::uint64_t, std::uint32_t>& a,
                         const std::pair<std::uint64_t, std::uint32_t>& b) {
                      if (a.first != b.first) return a.first < b.first;
                      const int c = std::memcmp(rows + std::size_t(a.second) * 32,
                                                rows + std::size_t(b.second) * 32, 32);
                      if (c != 0) return c < 0;
                      return a.second < b.second;
                  });
        sp.dir_bits = 0;
        if (ns >= 256) {
            unsigned lg = 0;
            while ((std::size_t(1) << (lg + 1)) <= ns) ++lg;
            sp.dir_bits = std::min(24u, lg - 3);                  // ~8-16 rows per bucket
        }
        sp.ki_order.resize(ns);
        sp.ki_dir.assign((std::size_t(1) << sp.dir_bits) + 1, 0);
        sp.ns_distinct = 0;
        std::size_t bkt = 0;
        for (std::size_t i = 0; i < ns; ++i) {
            sp.ki_order[i] = keyed[i].second;
            if (i == 0 || keyed[i].first != keyed[i - 1].first
                || std::memcmp(rows + std::size_t(keyed[i].second) * 32,
                               rows + std::size_t(keyed[i - 1].second) * 32, 32) != 0)
                ++sp.ns_distinct;
            if (sp.dir_bits != 0) {
                const std::size_t b = static_cast<std::size_t>(keyed[i].first >> (64 - sp.dir_bits));
                while (bkt < b) sp.ki_dir[++bkt] = static_cast<std::uint32_t>(i);
            }
        }
        for (std::size_t b = bkt + 1; b < sp.ki_dir.size(); ++b)
            sp.ki_dir[b] = static_cast<std::uint32_t>(ns);
        if (sp.dir_bits == 0) sp.ki_dir[1] = static_cast<std::uint32_t>(ns);
        std::vector<std::pair<std::uint64_t, std::uint32_t>>().swap(keyed);
        return true;
    }

    // Shared by both seed entry points: parse in place, check every committed
    // quantity against the anchor, build the spent index, adopt.
    bool seed_bytes_(std::shared_ptr<const std::uint8_t> bytes, std::size_t len, bool mapped,
                     const AnchorBundle& b, std::string& why) {
        std::lock_guard<std::mutex> lk(mu_);
        if (total_outputs_() != 0 || tip_height_ != 0 || out_peaks_.leaf_count != 0
            || !spent_.empty() || snap_.ns != 0) {
            why = "output set is not empty; seed the anchor snapshot before any block connects";
            return false;
        }
        if (!b.has_output_set()) {
            why = "anchor bundle carries no committed output set to seed against";
            return false;
        }
        Parsed_ t;
        if (!parse_(bytes.get(), len, t)) { why = "output-set snapshot does not deserialize"; return false; }

        // Every committed quantity must match the re-derived snapshot exactly.
        if (t.tip_height != b.height) {
            why = "snapshot tip height " + std::to_string(t.tip_height)
                + " != anchor height " + std::to_string(b.height);
            return false;
        }
        if (t.tip_id != b.id) { why = "snapshot tip id != anchor id"; return false; }
        if (t.base + t.n != b.rct_output_count) {
            why = "snapshot frontier " + std::to_string(t.base + t.n)
                + " != anchor rct_output_count " + std::to_string(b.rct_output_count);
            return false;
        }
        if (t.out_peaks.leaf_count != b.output_set_leaves) {
            why = "snapshot output-leaf count " + std::to_string(t.out_peaks.leaf_count)
                + " != anchor output_set_leaves " + std::to_string(b.output_set_leaves);
            return false;
        }
        if (::v37::Lane::mmr_bag(t.out_peaks.peaks) != b.output_set_root) {
            why = "snapshot output-set root does not match the anchor's committed root";
            return false;
        }
        if (t.ki_peaks.leaf_count != b.spent_set_leaves) {
            why = "snapshot spent-leaf count " + std::to_string(t.ki_peaks.leaf_count)
                + " != anchor spent_set_leaves " + std::to_string(b.spent_set_leaves);
            return false;
        }
        if (::v37::Lane::mmr_bag(t.ki_peaks.peaks) != b.spent_set_root) {
            why = "snapshot spent-set root does not match the anchor's committed root";
            return false;
        }

        SnapshotPart sp;
        sp.out_rows = t.out_rows;
        sp.n        = t.n;
        sp.ki_rows  = t.ki_rows;
        sp.ns       = t.ns;
#if !defined(_WIN32)
        if (mapped && t.ns != 0) (void)::madvise(page_floor_(t.ki_rows), page_span_(t.ki_rows, t.ns * 32), MADV_SEQUENTIAL);
#endif
        if (!build_ki_index_(sp)) {
            why = "output-set snapshot carries more spent key images than the index addresses";
            return false;
        }
#if !defined(_WIN32)
        if (mapped) {
            // Resolution and spent checks touch rows at random; drop what the
            // load scanned from this mapping (it stays in the page cache).
            (void)::madvise(page_floor_(bytes.get()), page_span_(bytes.get(), len), MADV_DONTNEED);
            (void)::madvise(page_floor_(bytes.get()), page_span_(bytes.get(), len), MADV_RANDOM);
        }
#endif
        sp.bytes      = std::move(bytes);
        sp.out_peaks  = t.out_peaks;
        sp.ki_peaks   = t.ki_peaks;
        sp.tip_height = t.tip_height;
        sp.tip_id     = t.tip_id;

        // Adopt the re-derived, root-checked state. The numbering base becomes
        // the snapshot's (0 on a from-genesis walk), so below-base offsets now
        // satisfy off >= base_ in resolve() and CLSAG runs. undo_ stays empty:
        // pre-anchor blocks are below the reorg floor and are never disconnected,
        // so the overlay (outputs_, spent_) only ever holds post-anchor state.
        base_           = t.base;
        snap_           = std::move(sp);
        out_peaks_      = t.out_peaks;
        out_leaves_     = std::move(t.out_leaves);
        out_leaf_first_ = std::move(t.out_leaf_first);
        ki_peaks_       = t.ki_peaks;
        ki_leaves_      = std::move(t.ki_leaves);
        tip_height_     = t.tip_height;
        tip_id_         = t.tip_id;
        why.clear();
        return true;
    }

#if !defined(_WIN32)
    static void* page_floor_(const void* p) {
        const std::uintptr_t pg = static_cast<std::uintptr_t>(::sysconf(_SC_PAGESIZE));
        return reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(p) & ~(pg - 1));
    }
    static std::size_t page_span_(const void* p, std::uint64_t n) {
        const std::uintptr_t a = reinterpret_cast<std::uintptr_t>(page_floor_(p));
        return static_cast<std::size_t>(reinterpret_cast<std::uintptr_t>(p) + n - a);
    }
#endif

    struct UndoFrame {
        std::uint64_t     height          = 0;
        Hash              block_id{};
        std::size_t       outputs_added   = 0;
        std::vector<Hash> key_image_list;      // only those actually inserted
        std::vector<Hash> key_images_skipped;  // listed but already spent (overlay replay)
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

    mutable std::mutex               mu_;
    std::uint64_t                    base_ = 0;   // first_output_index
    // False only after disable_resolution() -- a FORMAT-1 anchor boot, where the
    // real numbering base is unknown. resolve() then fails closed for every ring.
    bool                             resolution_enabled_ = true;
    // The immutable anchor snapshot, served in place (outputs [0, snap_.n) above
    // base_, and the snapshot's spent key images). Empty unless seeded.
    SnapshotPart                     snap_;
    // The heap OVERLAY: outputs from blocks after the snapshot (global index
    // base_ + snap_.n + i) and post-snapshot spent key images (never one the
    // snapshot already holds), so a reorg only ever touches the overlay.
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
