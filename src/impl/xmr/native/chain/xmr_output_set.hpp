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
// against, built from the SAME connected-block stream the txpool already
// consumes -- no new network surface, no daemon. It is both surfaces at once:
//
//   * IRingMemberSource: an append-only vector of every RCT output the chain
//     created from `first_output_index` onward, in monerod's global-index
//     order (coinbase outputs first, then each tx's outputs in block order), so
//     a ring's absolute offsets index straight into it;
//   * ISpentKeyImageView: the set of key images those blocks spent, which is
//     the GLOBAL double-spend oracle the pool could not build before.
//
// COVERAGE, stated honestly. `first_output_index` is the anchor's
// rct_output_count (0 on a regtest chain from genesis). A ring member BELOW that
// index was created before the anchor and is NOT in this set: resolve() returns
// false for it and the pool fails closed (RingUnresolved). So this is complete
// input consensus for a regtest-from-genesis chain and for any mainnet ring
// whose members are all above the anchor; the history below the anchor is a
// pass-2 job (an anchor-minted output snapshot, or a pruned-body backfill).
//
// REORG SAFETY. Every connected block pushes one undo frame recording how many
// outputs it appended and which key images it added; a disconnect pops the
// matching frame, truncates the outputs and erases the key images. Frames are
// LIFO, which is the order monerod emits disconnects (tip first).
//
// Header-only, STL only; one mutex, because the chain thread writes while the
// pool thread resolves.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <mutex>
#include <unordered_set>
#include <vector>

#include "impl/xmr/native/contracts/outputs.hpp"
#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/txpool/xmr_relayed_txpool.hpp"   // HashHasher

namespace c2pool::xmr::native {

class ChainOutputSet final : public IRingMemberSource, public ISpentKeyImageView {
public:
    // `first_output_index` = the anchor's rct_output_count (0 for regtest from
    // genesis). Nothing below it is ever resolvable from this set.
    explicit ChainOutputSet(std::uint64_t first_output_index = 0)
        : base_(first_output_index) {}

    // --- IRingMemberSource --------------------------------------------------
    bool resolve(std::uint64_t amount,
                 const std::vector<std::uint64_t>& absolute_offsets,
                 std::vector<OutputRecord>&        out) const override {
        // Only RCT (amount 0) inputs are resolvable here; a pre-RCT amount has
        // its own (unnumbered) output table this set never built.
        if (amount != 0) return false;
        std::lock_guard<std::mutex> lk(mu_);
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
    // Append a connected block's outputs (in global-index order) and spent key
    // images. `ev.first_output_index` must equal our current frontier, or the
    // stream skipped a block and the set would silently misnumber every ring
    // after the gap -- we refuse and report it so the caller can rebuild.
    bool on_block_connected(const BlockTxEvent& ev) {
        if (ev.kind != BlockTxEvent::Kind::Connected) return false;
        std::lock_guard<std::mutex> lk(mu_);
        const std::uint64_t frontier = base_ + outputs_.size();
        // A block that carried no outputs (producer did not capture) still
        // advances key images; but if it DID carry outputs, they must start
        // exactly at the frontier.
        if (!ev.outputs.empty() && ev.first_output_index != frontier)
            return false;

        UndoFrame f;
        f.height          = ev.height;
        f.outputs_added   = ev.outputs.size();
        f.key_images_added = 0;
        for (const OutputRecord& o : ev.outputs) outputs_.push_back(o);
        for (const Hash& ki : ev.key_images) {
            if (spent_.insert(ki).second) {
                ++f.key_images_added;
                f.key_image_list.push_back(ki);   // only erase what we inserted
            }
        }
        undo_.push_back(std::move(f));
        return true;
    }

    // Roll back the most-recent connected block. Best-effort match on height:
    // if the top frame is not this height the stream is out of order and we
    // refuse rather than corrupt the numbering.
    bool on_block_disconnected(const BlockTxEvent& ev) {
        std::lock_guard<std::mutex> lk(mu_);
        if (undo_.empty()) return false;
        UndoFrame& f = undo_.back();
        if (f.height != ev.height) return false;
        for (std::size_t i = 0; i < f.outputs_added; ++i) outputs_.pop_back();
        for (const Hash& ki : f.key_image_list) spent_.erase(ki);
        undo_.pop_back();
        return true;
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
        std::size_t       outputs_added   = 0;
        std::size_t       key_images_added = 0;
        std::vector<Hash> key_image_list;   // only those actually inserted
    };

    mutable std::mutex               mu_;
    std::uint64_t                    base_ = 0;   // first_output_index
    std::vector<OutputRecord>        outputs_;
    std::unordered_set<Hash, HashHasher> spent_;
    std::vector<UndoFrame>           undo_;
};

} // namespace c2pool::xmr::native
