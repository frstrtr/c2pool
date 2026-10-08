// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_window_chain.hpp
// Path B, slice S3b-1b: window(t, v) on t's own chain. [C38, C13, C41, C35]
//
//   TipBins(store, t)   the bins of t's window newest first, from b = H(pos(t))
//                       + Fresh down to b0, read on view_at(t):
//                         sealed at t (H(pos(t)) >= b + F): its bucket; a bucket
//                           not held -> MissingBucket(b);
//                         open at t: the live placements of b with q <= pos(t)
//                           as WinEntry{miner = payee, owner, work, p,
//                           give_author_bp, position = q, id}; placements not
//                           held -> MissingEntries(b).
//                       Read lazily: the window reads a bin only while it needs
//                       one (coverage, W_max), so a bin past the back edge is
//                       never asked for, and a bin it needs is never skipped.
//   win_bins_at(store, t)  every bin of t down to b0 (or the first one missing).
//   window_params(in, v)   B = B(A_t); f_spend(B, M(A_t), v); N(B) = n_rule(Z(A_t),
//                       v, B); D_net(t).
//   tip_window(store, t, params, v)  window(t, v), window_root, sum and
//                       mmr_root_at(t) on t's chain; or the DEFER that stopped it.
//   evaluate_window_at(store, t, P_t, mon, v, author)  the inputs read on P_t's
//                       branch (FollowerBranchView), then tip_window.
//
// A DEFER names what to fetch (a Monero block, A_t's weights, a bucket) or
// rebuild (placements); it is never a verdict and is never cached.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "pathb_bin_store.hpp"
#include "pathb_branch.hpp"
#include "pathb_branch_follower.hpp"
#include "pathb_emission.hpp"
#include "pathb_params.hpp"
#include "pathb_receipt_admission.hpp"  // open_at
#include "pathb_window.hpp"

namespace c2pool::xmr::pathb {

// D_net(t) as the window reads it (u128).
inline DNet dnet_of(const U128& d) noexcept { return (static_cast<DNet>(d.hi) << 64) | d.lo; }

// ---------------------------------------------------------------------------
// The bins of t's window, newest first (crediting: placements -> WinBin).
// ---------------------------------------------------------------------------
class TipBins {
public:
    TipBins(const BinStore& s, const Hash32& t) : v_(s.view_at(t)), b0_(s.b0()), f_(s.params().open_bins) {
        if (!v_.ok()) {
            done_ = true;
            return;
        }
        pos_t_ = v_.pos();
        h_t_ = v_.record(pos_t_);
        next_ = h_t_ + s.params().fresh_max;
    }

    ViewStatus status() const noexcept { return v_.status(); }
    const LaneView& view() const noexcept { return v_; }

    BinPull operator()() {
        if (done_ || next_ < b0_) return BinPull{};
        const std::uint64_t b = next_;
        if (b == b0_)
            done_ = true;
        else
            --next_;
        if (!open_at(h_t_, b, f_)) {  // sealed at t
            const SealedBin* sb = v_.bucket(b);
            if (sb == nullptr) return BinPull{PullKind::MissingBucket, WinBin{}, b};
            BinPull p;
            p.kind = PullKind::Bin;
            p.bin.bin = b;
            p.bin.sealed = &sb->bucket;
            return p;
        }
        if (!v_.entries_held(b)) return BinPull{PullKind::MissingEntries, WinBin{}, b};
        BinPull p;
        p.kind = PullKind::Bin;
        p.bin.bin = b;
        for (const Placement* x : v_.live_entries(b, pos_t_)) p.bin.entries.push_back(win_entry_of(*x));
        return p;
    }

private:
    LaneView v_;
    std::uint64_t b0_;
    std::uint64_t f_;
    std::uint64_t pos_t_ = 0;
    std::uint64_t h_t_ = 0;
    std::uint64_t next_ = 0;
    bool done_ = false;
};

// Every bin of t's window down to b0, newest first; stops at the first bin not
// held (status MissingBucket / MissingEntries, missing_bin).
struct WinResult {
    ViewStatus view = ViewStatus::Unknown;
    WinStatus status = WinStatus::Ok;
    std::uint64_t missing_bin = 0;
    std::vector<WinBin> bins;
};

inline WinResult win_bins_at(const BinStore& s, const Hash32& t) {
    WinResult out;
    TipBins src(s, t);
    out.view = src.status();
    if (out.view != ViewStatus::Ok) return out;
    for (;;) {
        BinPull p = src();
        if (p.kind == PullKind::End) break;
        if (p.kind != PullKind::Bin) {
            out.status = p.kind == PullKind::MissingBucket ? WinStatus::MissingBucket : WinStatus::MissingEntries;
            out.missing_bin = p.missing_bin;
            out.bins.clear();
            break;
        }
        out.bins.push_back(std::move(p.bin));
    }
    return out;
}

// ---------------------------------------------------------------------------
// window(t, v)
// ---------------------------------------------------------------------------
struct WindowParams {
    DNet d_net = 0;              // D_net(t)
    std::uint64_t B = 0;         // B(A_t)
    std::uint64_t f_spend = 0;   // f_spend(B(A_t), M(A_t), v)
    std::uint64_t N = 0;         // N(B) = n_rule(Z(A_t), v, B(A_t))
    Hash32 author{};             // the donation identity (K16)
};

inline WindowParams window_params(const WindowInputs& in, std::uint8_t v, const Hash32& author) {
    WindowParams p;
    p.d_net = dnet_of(in.d_net);
    p.B = in.weights.base_reward;
    p.f_spend = f_spend(p.B, in.weights.fee_median, v);
    p.N = n_rule(in.weights.zone, v, p.B);
    p.author = author;
    return p;
}

enum class WindowDefer : std::uint8_t {
    None,
    TipNotHeld,      // t is not held by the store
    TipDeep,         // t's fork point lies below the journal
    MissingBlock,    // missing_id: a Monero block of P_t's branch
    MissingWeights,  // missing_id: A_t (its RowWeights)
    Inconsistent,    // missing_id: a parent whose height does not follow its child
    MissingBucket,   // missing_bin: a sealed bin's bucket (fetch)
    MissingEntries,  // missing_bin: an open bin's placements (rebuild)
    SealedCut,       // a cut by carrier position in a sealed bin (t's own receipt not placed)
};

struct TipWindow {
    WindowDefer defer = WindowDefer::None;
    Hash32 tip{};
    std::uint8_t v = 0;
    Hash32 missing_id{};
    std::uint64_t missing_bin = 0;
    WindowInputs inputs{};
    std::shared_ptr<const Window> window;  // set iff ok()
    Hash32 window_root{};
    Work sum{};
    Hash32 mmr_root{};          // mmr_root_at(t) on t's chain
    std::uint64_t bins_read = 0;   // bins read newest first from H(pos(t)) + Fresh
    std::uint64_t oldest_bin = 0;  // the oldest bin in the window (0: none)

    bool ok() const noexcept { return defer == WindowDefer::None && window != nullptr; }
};

inline WindowDefer defer_of(DeferReason r) noexcept {
    switch (r) {
        case DeferReason::MissingBlock: return WindowDefer::MissingBlock;
        case DeferReason::MissingWeights: return WindowDefer::MissingWeights;
        case DeferReason::Inconsistent: return WindowDefer::Inconsistent;
        case DeferReason::None: break;
    }
    return WindowDefer::Inconsistent;
}

inline WindowDefer defer_of(WinStatus s) noexcept {
    switch (s) {
        case WinStatus::MissingBucket: return WindowDefer::MissingBucket;
        case WinStatus::MissingEntries: return WindowDefer::MissingEntries;
        case WinStatus::SealedCut: return WindowDefer::SealedCut;
        case WinStatus::Ok: break;
    }
    return WindowDefer::None;
}

// window(t, v) over t's own chain with the given parameters.
inline TipWindow tip_window(const BinStore& s, const Hash32& t, const WindowParams& wp, std::uint8_t v) {
    TipWindow out;
    out.tip = t;
    out.v = v;
    TipBins src(s, t);
    if (src.status() != ViewStatus::Ok) {
        out.defer = src.status() == ViewStatus::Deep ? WindowDefer::TipDeep : WindowDefer::TipNotHeld;
        return out;
    }
    const LaneView& view = src.view();
    const Hash32 mmr_root = view.mmr_root_at(view.pos());
    WinEval e = window_from(src, wp.d_net, wp.B, wp.f_spend, wp.N, wp.author);
    out.bins_read = e.read;
    out.oldest_bin = e.oldest_bin;
    if (e.status != WinStatus::Ok) {
        out.defer = defer_of(e.status);
        out.missing_bin = e.missing_bin;
        return out;
    }
    auto w = std::make_shared<const Window>(std::move(e.window));
    out.window_root = window_root(*w, &out.sum);
    out.mmr_root = mmr_root;
    out.window = std::move(w);
    return out;
}

// window(t, v) with every Monero input read on the branch ending at p_t (the
// Monero parent committed by t).
inline TipWindow evaluate_window_at(const BinStore& s, const Hash32& t, const Hash32& p_t,
                                    const FollowerBranchView& mon, std::uint8_t v, const Hash32& author) {
    {
        const ViewStatus vs = s.view_at(t).status();
        if (vs != ViewStatus::Ok) {
            TipWindow out;
            out.tip = t;
            out.v = v;
            out.defer = vs == ViewStatus::Deep ? WindowDefer::TipDeep : WindowDefer::TipNotHeld;
            return out;
        }
    }
    WindowInputs in;
    const BranchStatus bs = mon.window_inputs(p_t, v, in);
    if (!bs.selected()) {
        TipWindow out;
        out.tip = t;
        out.v = v;
        out.defer = defer_of(bs.reason);
        out.missing_id = bs.missing;
        return out;
    }
    TipWindow out = tip_window(s, t, window_params(in, v, author), v);
    out.inputs = in;
    return out;
}

}  // namespace c2pool::xmr::pathb
