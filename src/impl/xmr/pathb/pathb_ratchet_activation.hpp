// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_ratchet_activation.hpp
// Path B rules ratchet: the deployment table, the derived deployment states,
// the activation (rs_step step 1 through act / rs_step_at), E_impl, HOLD,
// the frame verdict under a HOLD, the ballot writer, the activation record
// and epoch_at, the HELLO trailer values. Companion of pathb_ratchet_state.hpp.
//
// Every function is a function of (S = S_{x-1}, x, T): x is the position
// judged or built, S the state the carrier at x commits.
//
//   Deployment (compiled; never on the wire) = epoch_no u16 | rules_digest b32 |
//     kind u8 | start u64 | timeout u64 | fixed u64; digest = sha256d of the
//     59 bytes in that order, little-endian.
//     kind 1 (vote): start % L == 0, timeout = start + N_W L, fixed 0.
//     kind 2 (fixed position; refused on mainnet): fixed >= start + GRACE,
//     timeout 0.
//   T: per epoch_no the attempts in ascending start; the last is the node's
//     own attempt D; consecutive attempts of one epoch_no, and the first
//     attempt of e + 1 after the last of e, start at or after
//     timeout(a) + GRACE (kind 2: fixed(a) + 1).
//   compiled(e): the rules digest the build runs at e (G at e = 0).
//   r_T(e) = G at e = 0; else D(e).rules_digest when compiled(e) equals it
//            (a kind-2 attempt the build does not run gives none).
//   base     : r_T(epoch_cur) == rules_cur
//   kept     : in S_{x-1}, slot i (0..3) is the level of grid window
//              floor(x / L) - 4 + i; the newest W_R slots are kept
//   open     : base, D = D(epoch_cur + 1) kind 1, start <= x < timeout
//   locked   : base, D kind 1, the earliest kept window k with level >= 1
//              inside [start, timeout) has x <= (k + 1) L - 1 + GRACE;
//              D kind 2: compiled(e) == D.rules_digest and start <= x <= fixed
//   h_act    : (k + 1) L - 1 + GRACE (kind 2: fixed)
//   act      : locked and x == h_act -> D.rules_digest
//   E_impl   : below if ~base; epoch_cur + 1 if open or locked; else epoch_cur
//   H_hold   : below -> x; else h_act of the earliest kept window with level
//              >= E_impl - epoch_cur + 1, infinity if none; a kind-2 D the
//              build does not run, x <= fixed -> min(that, fixed)
//   hold     : x >= H_hold
//   frame    : x < H_hold: JUDGE iff r == epoch_at, else STRIKE;
//              x >= H_hold: DEFER iff epoch_at <= r <= 2^15 - 1, else STRIKE
//   ballot   : stated vote=n when n == epoch_cur + 1 and open, or n <=
//              epoch_cur (own flag); else epoch_cur with --vote no; else
//              epoch_cur + 1 while open; else epoch_cur
//   epoch_at : in this order, f = the fork point of t's branch with the
//              best chain (f = pos(t) on it):
//              (iii) x > f + GRACE: DEFER on every node, whatever it holds;
//              a joiner's tips below p0: CLAIMED;
//              (i) S_{pos(t)} held on t's branch: epoch_cur + [act at x];
//              (ii) the activation record up to min(x, pos(best)), + 1 when a
//              lock-in seen from S_best at pos(best) + 1 activates at y with
//              pos(best) < y <= x
//
// Header-only. Not included by any running component.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "sharechain/v37/v37_hash.hpp"  // ::v37::sha256d

#include "pathb_caps.hpp"     // relay_horizons (P-09)
#include "pathb_hello.hpp"
#include "pathb_joiner.hpp"   // join_span (P-34)
#include "pathb_lane_rules.hpp"
#include "pathb_params.hpp"
#include "pathb_ratchet_state.hpp"

namespace c2pool::xmr::pathb {

// Highest epoch_no a ballot can name (15 bits).
inline constexpr std::uint16_t kEpochMax = kBallotEpochMask;

// H_hold when nothing holds.
inline constexpr std::uint64_t kNoHold = std::numeric_limits<std::uint64_t>::max();

// ---------------------------------------------------------------------------
// Deployments
// ---------------------------------------------------------------------------
inline constexpr std::uint8_t kKindVote = 1;
inline constexpr std::uint8_t kKindFixed = 2;

struct Deployment {
    std::uint16_t epoch_no = 0;
    Hash32 rules_digest{};
    std::uint8_t kind = 0;
    std::uint64_t start = 0;
    std::uint64_t timeout = 0;
    std::uint64_t fixed = 0;

    friend bool operator==(const Deployment&, const Deployment&) = default;
};

inline constexpr std::size_t kDescriptorBytes =
        sizeof(std::uint16_t) + kHashBytes + sizeof(std::uint8_t) + 3 * sizeof(std::uint64_t);
static_assert(kDescriptorBytes == 59);

using DescriptorBytes = std::array<std::uint8_t, kDescriptorBytes>;

inline DescriptorBytes encode_descriptor(const Deployment& d) noexcept {
    DescriptorBytes b{};
    std::size_t o = 0;
    b[o++] = static_cast<std::uint8_t>(d.epoch_no);
    b[o++] = static_cast<std::uint8_t>(d.epoch_no >> 8);
    for (std::uint8_t x : d.rules_digest) b[o++] = x;
    b[o++] = d.kind;
    for (std::uint64_t v : {d.start, d.timeout, d.fixed})
        for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) b[o++] = static_cast<std::uint8_t>(v >> (8 * i));
    return b;
}

// A descriptor record of the configured deployment file (C-DEP field order).
inline std::optional<Deployment> decode_descriptor(std::span<const std::uint8_t> b) noexcept {
    if (b.size() != kDescriptorBytes) return std::nullopt;
    Deployment d;
    std::size_t o = 0;
    d.epoch_no = static_cast<std::uint16_t>(b[0] | (b[1] << 8));
    o = 2;
    for (std::size_t i = 0; i < kHashBytes; ++i) d.rules_digest[i] = b[o++];
    d.kind = b[o++];
    for (std::uint64_t* v : {&d.start, &d.timeout, &d.fixed}) {
        *v = 0;
        for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) *v |= std::uint64_t{b[o++]} << (8 * i);
    }
    return d;
}

inline Hash32 descriptor_digest(const Deployment& d) {
    const DescriptorBytes b = encode_descriptor(d);
    return ::v37::sha256d(std::vector<std::uint8_t>(b.begin(), b.end()));
}

// The rules a build runs at an epoch (G at epoch 0). `rules` is the list the
// digest was computed from (lane_rules_valid recomputes it).
struct CompiledEpoch {
    std::uint16_t epoch_no = 0;
    Hash32 digest{};
    std::optional<PathbLaneRules> rules;
};

struct EpochTable {
    std::vector<CompiledEpoch> compiled;  // ascending epoch_no, epoch 0 first
    std::vector<Deployment> attempts;     // ascending (epoch_no, start); the last of an epoch_no is the own attempt
};

inline const Deployment* own_attempt(const EpochTable& T, std::uint32_t e) noexcept {
    const Deployment* d = nullptr;
    for (const Deployment& a : T.attempts)
        if (a.epoch_no == e) d = &a;
    return d;
}

inline std::optional<Hash32> compiled_digest(const EpochTable& T, std::uint32_t e) noexcept {
    for (const CompiledEpoch& c : T.compiled)
        if (c.epoch_no == e) return c.digest;
    return std::nullopt;
}

// kind 2: the build compiles rules_of(e) with the descriptor's digest.
inline bool implements2(const EpochTable& T, const Deployment& d) noexcept {
    const std::optional<Hash32> c = compiled_digest(T, d.epoch_no);
    return c.has_value() && *c == d.rules_digest;
}

// r_T(e).
inline std::optional<Hash32> rules_of_table(const EpochTable& T, std::uint32_t e) noexcept {
    if (e == 0) return compiled_digest(T, 0);
    const Deployment* d = own_attempt(T, e);
    if (d == nullptr) return std::nullopt;
    const std::optional<Hash32> c = compiled_digest(T, e);
    if (!c.has_value() || *c != d->rules_digest) return std::nullopt;
    return d->rules_digest;
}

inline bool base(const RatchetState& s, const EpochTable& T) noexcept {
    const std::optional<Hash32> r = rules_of_table(T, s.epoch_cur);
    return r.has_value() && *r == s.rules_cur;
}

// ---------------------------------------------------------------------------
// Kept windows and the lock-in window
// ---------------------------------------------------------------------------
struct KeptWindow {
    std::uint64_t k = 0;
    std::uint8_t level = 0;
};

struct KeptWindows {
    std::array<KeptWindow, kRatchetKeptWindows> w{};
    std::size_t n = 0;  // oldest first
};

inline KeptWindows kept_windows(const RatchetParams& p, const RatchetState& s, std::uint64_t x) noexcept {
    KeptWindows out;
    const std::uint64_t wr = ratchet_kept_windows(p);
    const std::uint64_t cur = x / p.window;
    for (std::size_t i = kRatchetKeptWindows - static_cast<std::size_t>(wr); i < kRatchetKeptWindows; ++i) {
        if (cur + i < kRatchetKeptWindows) continue;  // before the first grid window
        out.w[out.n++] = KeptWindow{cur + i - kRatchetKeptWindows, s.levels[i]};
    }
    return out;
}

inline constexpr std::uint64_t window_h_act(const RatchetParams& p, std::uint64_t k) noexcept {
    return (k + 1) * p.window - 1 + p.grace;
}

inline constexpr bool window_in_range(const RatchetParams& p, const Deployment& d, std::uint64_t k) noexcept {
    return d.start <= k * p.window && (k + 1) * p.window <= d.timeout;
}

// The earliest kept window with level >= 1 inside D's range (kind 1).
inline std::optional<std::uint64_t> lock_window(const RatchetParams& p, const RatchetState& s, std::uint64_t x,
                                                const Deployment& d) noexcept {
    const KeptWindows kw = kept_windows(p, s, x);
    for (std::size_t i = 0; i < kw.n; ++i)
        if (kw.w[i].level >= kLevelNext && window_in_range(p, d, kw.w[i].k)) return kw.w[i].k;
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// open / locked / h_act / act / E_impl
// ---------------------------------------------------------------------------
inline const Deployment* next_attempt(const RatchetState& s, const EpochTable& T) noexcept {
    return own_attempt(T, std::uint32_t{s.epoch_cur} + 1);
}

inline bool open(const RatchetParams&, const RatchetState& s, std::uint64_t x, const EpochTable& T) noexcept {
    const Deployment* d = next_attempt(s, T);
    return d != nullptr && d->kind == kKindVote && base(s, T) && d->start <= x && x < d->timeout;
}

inline std::optional<std::uint64_t> h_act(const RatchetParams& p, const RatchetState& s, std::uint64_t x,
                                          const EpochTable& T) noexcept {
    const Deployment* d = next_attempt(s, T);
    if (d == nullptr) return std::nullopt;
    if (d->kind == kKindFixed) return d->fixed;
    if (d->kind != kKindVote) return std::nullopt;
    const std::optional<std::uint64_t> k = lock_window(p, s, x, *d);
    if (!k.has_value()) return std::nullopt;
    return window_h_act(p, *k);
}

inline bool locked(const RatchetParams& p, const RatchetState& s, std::uint64_t x, const EpochTable& T) noexcept {
    const Deployment* d = next_attempt(s, T);
    if (d == nullptr || !base(s, T)) return false;
    if (d->kind == kKindFixed) return implements2(T, *d) && d->start <= x && x <= d->fixed;
    if (d->kind != kKindVote) return false;
    const std::optional<std::uint64_t> y = h_act(p, s, x, T);
    return y.has_value() && x <= *y;
}

inline bool implements(const RatchetParams& p, const RatchetState& s, std::uint64_t x, const EpochTable& T) noexcept {
    return open(p, s, x, T) || locked(p, s, x, T);
}

struct EImpl {
    std::uint16_t value = 0;  // epoch_cur when below
    bool below = false;       // ~base: HOLD at once
};

inline EImpl e_impl(const RatchetParams& p, const RatchetState& s, std::uint64_t x, const EpochTable& T) noexcept {
    if (!base(s, T)) return EImpl{s.epoch_cur, true};
    if (implements(p, s, x, T)) return EImpl{static_cast<std::uint16_t>(s.epoch_cur + 1), false};
    return EImpl{s.epoch_cur, false};
}

// The activation predicate: the activating descriptor's rules digest at x == H_act.
inline std::optional<Hash32> act(const RatchetParams& p, const RatchetState& s, std::uint64_t x,
                                 const EpochTable& T) noexcept {
    if (!locked(p, s, x, T)) return std::nullopt;
    const std::optional<std::uint64_t> y = h_act(p, s, x, T);
    if (!y.has_value() || *y != x) return std::nullopt;
    return next_attempt(s, T)->rules_digest;
}

// ---------------------------------------------------------------------------
// Activation record AR: one row per activation on the chain; persistent (never
// trimmed with the journal); a rewind to f pops the rows above f.
// ---------------------------------------------------------------------------
struct ActivationRow {
    std::uint16_t epoch = 0;
    std::uint64_t h_act = 0;
    Hash32 rules_digest{};

    friend bool operator==(const ActivationRow&, const ActivationRow&) = default;
};

inline constexpr std::size_t kActivationRowBytes = sizeof(std::uint16_t) + sizeof(std::uint64_t) + kHashBytes;
static_assert(kActivationRowBytes == 42);
inline constexpr std::size_t kActivationRowsMax = std::size_t{kEpochMax} + 1;

enum class ArRewind : std::uint8_t {
    Rewound,          // rows above p removed
    BelowJoinerSeed,  // p below a joiner's first row: refused, AR unchanged
};

class ActivationRecord {
public:
    // Appends a row of an activation at a position above every row. false: refused.
    bool append(const ActivationRow& r) {
        if (rows_.size() >= kActivationRowsMax) return false;
        if (!rows_.empty() && (r.h_act <= rows_.back().h_act || r.epoch != rows_.back().epoch + 1)) return false;
        rows_.push_back(r);
        return true;
    }

    // S restored at position p (a rewind by journal, or a rebuild from a
    // snapshot at p): AR keeps exactly its rows with h_act <= p. A joiner's
    // AR refuses a p below its first row (p0 - 1) and stays unchanged.
    [[nodiscard]] ArRewind rewind(std::uint64_t p) {
        if (joiner_ && !rows_.empty() && p < rows_.front().h_act) return ArRewind::BelowJoinerSeed;
        while (!rows_.empty() && rows_.back().h_act > p) rows_.pop_back();
        return ArRewind::Rewound;
    }

    // The journal no longer holds positions below oldest; AR keeps every row.
    void note_journal_trim(std::uint64_t /*oldest*/) noexcept {}

    // A joiner seeds AR from the adopted S_{p0 - 1} with the row (epoch_cur,
    // p0 - 1, rules_cur): no rewind it can make goes below p0 - 1. Tips below
    // p0 are claimed. A re-join replaces AR. Precondition: p0 >= 1.
    void seed_joiner(const RatchetState& adopted, std::uint64_t p0) {
        rows_.clear();
        rows_.push_back(ActivationRow{adopted.epoch_cur, p0 - 1, adopted.rules_cur});
        joiner_ = true;
    }

    std::optional<std::uint64_t> joiner_p0() const noexcept {
        if (!joiner_ || rows_.empty()) return std::nullopt;
        return rows_.front().h_act + 1;
    }

    // max{e : (e, h) in AR, h <= x}; 0 if none.
    std::uint16_t epoch_at(std::uint64_t x) const noexcept {
        std::uint16_t e = 0;
        for (const ActivationRow& r : rows_)
            if (r.h_act <= x) e = r.epoch;
        return e;
    }

    const std::vector<ActivationRow>& rows() const noexcept { return rows_; }

private:
    std::vector<ActivationRow> rows_;
    bool joiner_ = false;
};

// ---------------------------------------------------------------------------
// rs_step_at: the only entry point the wiring calls
// ---------------------------------------------------------------------------
struct StepAt {
    RatchetState s;
    std::optional<ActivationRow> row;
};

inline StepAt rs_step_at(const RatchetParams& p, const RatchetState& prev, std::uint64_t x,
                         std::span<const RatchetPlacement> placed, const EpochTable& T) {
    const std::optional<Hash32> a = act(p, prev, x, T);
    StepAt out{rs_step(p, prev, x, placed, a.has_value(), a.value_or(Hash32{})), std::nullopt};
    if (a.has_value()) out.row = ActivationRow{out.s.epoch_cur, x, *a};
    return out;
}

// ---------------------------------------------------------------------------
// Derived deployment states (of the node's own attempts)
// ---------------------------------------------------------------------------
enum class DeploymentState : std::uint8_t { Defined, Waiting, Started, LockedIn, Active, Failed };

inline constexpr std::string_view deployment_state_name(DeploymentState st) noexcept {
    switch (st) {
        case DeploymentState::Defined: return "DEFINED";
        case DeploymentState::Waiting: return "WAITING";
        case DeploymentState::Started: return "STARTED";
        case DeploymentState::LockedIn: return "LOCKED_IN";
        case DeploymentState::Active: return "ACTIVE";
        case DeploymentState::Failed: break;
    }
    return "FAILED";
}

// Precondition: d is the node's own attempt of d.epoch_no.
inline DeploymentState step(const RatchetParams& p, const RatchetState& s, std::uint64_t x, const EpochTable& T,
                            const Deployment& d) noexcept {
    const bool bs = base(s, T);
    if (s.epoch_cur >= d.epoch_no && bs) return DeploymentState::Active;
    const bool next = std::uint32_t{d.epoch_no} == std::uint32_t{s.epoch_cur} + 1;
    if (next && locked(p, s, x, T)) return DeploymentState::LockedIn;
    if (next && open(p, s, x, T)) return DeploymentState::Started;
    const bool in_span = d.kind == kKindFixed ? d.start <= x && x <= d.fixed : d.start <= x && x < d.timeout;
    if (next && !bs && in_span) return DeploymentState::Waiting;
    if (x < d.start) return DeploymentState::Defined;
    return DeploymentState::Failed;
}

// ---------------------------------------------------------------------------
// HOLD
// ---------------------------------------------------------------------------
// H_hold at x = tip + 1 from S = S_tip.
inline std::uint64_t h_hold(const RatchetParams& p, const RatchetState& s, std::uint64_t x, const EpochTable& T) noexcept {
    const EImpl ei = e_impl(p, s, x, T);
    if (ei.below) return x;
    const std::uint32_t need = std::uint32_t{ei.value} - std::uint32_t{s.epoch_cur} + 1;
    std::uint64_t h = kNoHold;
    const KeptWindows kw = kept_windows(p, s, x);
    for (std::size_t i = 0; i < kw.n; ++i)
        if (kw.w[i].level >= need) h = std::min(h, window_h_act(p, kw.w[i].k));
    const Deployment* d = next_attempt(s, T);
    if (d != nullptr && d->kind == kKindFixed && !implements2(T, *d) && x <= d->fixed) h = std::min(h, d->fixed);
    return h;
}

// The node at tip `tip` with S_tip stops building iff x = tip + 1 >= H_hold.
inline bool hold(const RatchetParams& p, const RatchetState& s_tip, std::uint64_t tip, const EpochTable& T) noexcept {
    const std::uint64_t x = tip + 1;
    return x >= h_hold(p, s_tip, x, T);
}

// ---------------------------------------------------------------------------
// Frames: the rules_epoch verdict (S2.3 #4)
// ---------------------------------------------------------------------------
enum class FrameVerdict : std::uint8_t { Judge, Strike, Defer };

inline constexpr FrameVerdict frame_epoch_verdict(std::uint64_t x, std::uint32_t rules_epoch, std::uint64_t hold_at,
                                                  std::uint16_t epoch_at_x) noexcept {
    if (x < hold_at) return rules_epoch == epoch_at_x ? FrameVerdict::Judge : FrameVerdict::Strike;
    if (epoch_at_x <= rules_epoch && rules_epoch <= kEpochMax) return FrameVerdict::Defer;
    return FrameVerdict::Strike;
}

// The deferred store under a HOLD (P-34, P-09): frames of H_hold .. H_hold +
// span - 1 that pass the header-level checks are stored; any other is dropped
// (never struck, never banned).
enum class DeferVerdict : std::uint8_t { Stored, Drop };

// P-34 default: one joiner span of positions (1,176); P-09 default: the pending cap (18,432 receipts).
inline std::uint64_t deferred_frame_span_default() { return join_span(kRuledLaneParams, kSealDepth); }
inline std::uint64_t deferred_receipt_cap_default() { return relay_horizons(kRuledLaneParams).pending_cap; }

inline constexpr DeferVerdict defer_frame(std::uint64_t x, std::uint64_t hold_at, bool header_ok,
                                          std::uint64_t span) noexcept {
    if (!header_ok || x < hold_at || x - hold_at >= span) return DeferVerdict::Drop;
    return DeferVerdict::Stored;
}

inline constexpr DeferVerdict defer_receipt(std::uint64_t pending, std::uint64_t pending_cap, bool header_ok) noexcept {
    return header_ok && pending < pending_cap ? DeferVerdict::Stored : DeferVerdict::Drop;
}

// ---------------------------------------------------------------------------
// epoch_at
// ---------------------------------------------------------------------------
enum class EpochAtKind : std::uint8_t { Epoch, Claimed, Defer };

struct EpochAt {
    EpochAtKind kind = EpochAtKind::Epoch;
    std::uint16_t epoch = 0;

    friend bool operator==(const EpochAt&, const EpochAt&) = default;
};

// (i): the node holds S_{pos(t)} on t's branch; x = pos(t) + 1.
inline std::uint16_t epoch_at_held(const RatchetParams& p, const RatchetState& s_tip, std::uint64_t x,
                                   const EpochTable& T) noexcept {
    return static_cast<std::uint16_t>(s_tip.epoch_cur + (act(p, s_tip, x, T).has_value() ? 1 : 0));
}

// (ii) / (iii): from headers (the fork point f of t's branch with the best
// chain; f = pos(t) on the best chain), AR and S at the best tip.
inline EpochAt epoch_at_fork_local(const RatchetParams& p, const EpochTable& T, const ActivationRecord& ar,
                                   std::uint64_t pos_best, const RatchetState& s_best, std::uint64_t f,
                                   std::uint64_t x) noexcept {
    if (x > f && x - f > p.grace) return EpochAt{EpochAtKind::Defer, 0};
    const std::optional<std::uint64_t> p0 = ar.joiner_p0();
    if (p0.has_value() && x - 1 < *p0) return EpochAt{EpochAtKind::Claimed, 0};
    std::uint16_t e = ar.epoch_at(std::min(x, pos_best));
    const std::uint64_t xb = pos_best + 1;
    if (locked(p, s_best, xb, T)) {
        const std::optional<std::uint64_t> y = h_act(p, s_best, xb, T);
        if (y.has_value() && *y > pos_best && *y <= x) e = static_cast<std::uint16_t>(e + 1);
    }
    return EpochAt{EpochAtKind::Epoch, e};
}

// The #4 epoch of a tip, cases in order: (iii) DEFER for x > f + GRACE
// whatever the node holds; CLAIMED below a joiner's p0; (i) when s_tip_held
// is given; else (ii).
inline EpochAt epoch_at(const RatchetParams& p, const EpochTable& T, const std::optional<RatchetState>& s_tip_held,
                        const ActivationRecord& ar, std::uint64_t pos_best, const RatchetState& s_best,
                        std::uint64_t f, std::uint64_t x) noexcept {
    if (x > f && x - f > p.grace) return EpochAt{EpochAtKind::Defer, 0};
    const std::optional<std::uint64_t> p0 = ar.joiner_p0();
    if (p0.has_value() && x - 1 < *p0) return EpochAt{EpochAtKind::Claimed, 0};
    if (s_tip_held.has_value()) return EpochAt{EpochAtKind::Epoch, epoch_at_held(p, *s_tip_held, x, T)};
    return epoch_at_fork_local(p, T, ar, pos_best, s_best, f, x);
}

// The #4 verdict from epoch_at: DEFER (iii) whatever H_hold; CLAIMED takes the
// receipt's rules_epoch as its epoch (S3.1a); else frame_epoch_verdict.
inline constexpr FrameVerdict frame_verdict(std::uint64_t x, std::uint32_t rules_epoch, std::uint64_t hold_at,
                                            const EpochAt& ea) noexcept {
    if (ea.kind == EpochAtKind::Defer) return FrameVerdict::Defer;
    if (ea.kind == EpochAtKind::Claimed) {
        if (rules_epoch > kEpochMax) return FrameVerdict::Strike;
        return frame_epoch_verdict(x, rules_epoch, hold_at, static_cast<std::uint16_t>(rules_epoch));
    }
    return frame_epoch_verdict(x, rules_epoch, hold_at, ea.epoch);
}

// ---------------------------------------------------------------------------
// The ballot writer (job binder)
// ---------------------------------------------------------------------------
enum class BallotSource : std::uint8_t { Default, Own, OptOut };

struct BallotChoice {
    std::uint16_t ballot = 0;
    BallotSource source = BallotSource::Default;

    friend bool operator==(const BallotChoice&, const BallotChoice&) = default;
};

inline constexpr std::string_view ballot_source_name(BallotSource s) noexcept {
    return s == BallotSource::Own ? "own" : s == BallotSource::OptOut ? "opt-out" : "default";
}

// stated: the miner's vote=n (stratum password field); opt_out: --vote no.
inline BallotChoice ballot_to_write(const RatchetParams& p, const RatchetState& s, std::uint64_t x, const EpochTable& T,
                                    std::optional<std::uint32_t> stated, bool opt_out) noexcept {
    const std::uint32_t ec = s.epoch_cur;
    const bool op = open(p, s, x, T);
    if (stated.has_value() && *stated <= kEpochMax && ((*stated == ec + 1 && op) || *stated <= ec))
        return BallotChoice{make_ballot(static_cast<std::uint16_t>(*stated), true), BallotSource::Own};
    if (opt_out) return BallotChoice{make_ballot(static_cast<std::uint16_t>(ec), false), BallotSource::OptOut};
    if (op) return BallotChoice{make_ballot(static_cast<std::uint16_t>(ec + 1), false), BallotSource::Default};
    return BallotChoice{make_ballot(static_cast<std::uint16_t>(ec), false), BallotSource::Default};
}

// The login reply's vote object.
inline std::string vote_json(const BallotChoice& c) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string hex = "0x";
    for (int sh = 12; sh >= 0; sh -= 4) hex.push_back(kDigits[(c.ballot >> sh) & 0x0f]);
    return "\"vote\": {\"ballot\": \"" + hex + "\", \"source\": \"" + std::string(ballot_source_name(c.source)) + "\"}";
}

// ---------------------------------------------------------------------------
// Start-up checks
// ---------------------------------------------------------------------------
struct StartupCheck {
    bool ok = true;
    std::string why;
};

// The spacing threshold of an attempt: timeout + GRACE (kind 2: fixed + 1).
inline std::optional<std::uint64_t> spacing_threshold(const RatchetParams& p, const Deployment& a) noexcept {
    if (a.kind == kKindFixed) {
        if (a.fixed == std::numeric_limits<std::uint64_t>::max()) return std::nullopt;
        return a.fixed + 1;
    }
    if (a.timeout > std::numeric_limits<std::uint64_t>::max() - p.grace) return std::nullopt;
    return a.timeout + p.grace;
}

inline StartupCheck deployment_table_valid(const RatchetParams& p, LaneNet net, const EpochTable& T) {
    auto refuse = [](std::string why) { return StartupCheck{false, std::move(why)}; };
    if (!ratchet_params_valid(p)) return refuse("K30: W_R above the kept windows");
    const std::uint64_t nw = ratchet_vote_windows(p);
    if (nw < 1) return refuse("K30: TIMEOUT below one vote window");
    const std::uint64_t span = nw * p.window;
    for (std::size_t i = 0; i < T.attempts.size(); ++i) {
        const Deployment& a = T.attempts[i];
        const std::string at = "attempt " + std::to_string(i) + " (epoch " + std::to_string(a.epoch_no) + ")";
        if (a.epoch_no < 1 || a.epoch_no > kEpochMax) return refuse(at + ": epoch_no outside 1..32767");
        if (i == 0 && a.epoch_no != 1) return refuse(at + ": epoch numbers start at 1");
        if (i > 0) {
            const Deployment& b = T.attempts[i - 1];
            if (a.epoch_no < b.epoch_no || a.epoch_no > b.epoch_no + 1) return refuse(at + ": epoch numbers not ascending by one");
            if (a.epoch_no == b.epoch_no && a.start <= b.start) return refuse(at + ": attempts not in ascending start");
        }
        if (a.kind == kKindVote) {
            if (a.start % p.window != 0) return refuse(at + ": start not a multiple of L");
            if (a.start > std::numeric_limits<std::uint64_t>::max() - span) return refuse(at + ": start out of range");
            if (a.timeout != a.start + span) return refuse(at + ": timeout != start + N_W L");
            if (a.fixed != 0) return refuse(at + ": kind 1 with fixed != 0");
        } else if (a.kind == kKindFixed) {
            if (net == LaneNet::Mainnet) return refuse(at + ": kind 2 on mainnet");
            if (a.start > std::numeric_limits<std::uint64_t>::max() - p.grace || a.fixed < a.start + p.grace)
                return refuse(at + ": kind 2 fixed < start + GRACE");
            if (a.timeout != 0) return refuse(at + ": kind 2 with timeout != 0");
        } else {
            return refuse(at + ": unknown kind");
        }
        // spacing: every earlier attempt of this epoch_no, and the last attempt of epoch_no - 1
        for (std::size_t j = 0; j < i; ++j) {
            const Deployment& b = T.attempts[j];
            const bool same = b.epoch_no == a.epoch_no;
            const bool pred = b.epoch_no + 1 == a.epoch_no && own_attempt(T, b.epoch_no) == &b;
            if (!same && !pred) continue;
            const std::optional<std::uint64_t> th = spacing_threshold(p, b);
            if (!th.has_value() || a.start < *th) return refuse(at + ": start before timeout + GRACE of an earlier attempt");
        }
    }
    return StartupCheck{};
}

// The compiled lane rules: epoch 0 is the network's list with digest G (on
// regtest a rig list differing in K30 only: rules_digest of it); every
// compiled epoch's digest equals rules_digest of its list; every own kind-1
// attempt's digest equals the compiled digest of its epoch.
inline StartupCheck lane_rules_valid(LaneNet net, const EpochTable& T) {
    auto refuse = [](std::string why) { return StartupCheck{false, std::move(why)}; };
    if (T.compiled.empty() || T.compiled.front().epoch_no != 0 || !T.compiled.front().rules.has_value())
        return refuse("no epoch-0 lane rules");
    const std::optional<Hash32> g = genesis_digest_for(net, *T.compiled.front().rules);
    if (!g.has_value()) return refuse("epoch-0 lane rules are not the network's list, or G differs");
    if (*g != T.compiled.front().digest) return refuse("compiled G differs from rules_digest of the epoch-0 list");
    for (std::size_t i = 1; i < T.compiled.size(); ++i) {
        const CompiledEpoch& c = T.compiled[i];
        if (c.epoch_no <= T.compiled[i - 1].epoch_no) return refuse("compiled epochs not ascending");
        if (!c.rules.has_value() || rules_digest(*c.rules) != c.digest)
            return refuse("compiled epoch " + std::to_string(c.epoch_no) + ": digest differs from its rules");
    }
    for (const Deployment& a : T.attempts) {
        if (own_attempt(T, a.epoch_no) != &a || a.kind != kKindVote) continue;
        const std::optional<Hash32> c = compiled_digest(T, a.epoch_no);
        if (!c.has_value() || *c != a.rules_digest)
            return refuse("own attempt of epoch " + std::to_string(a.epoch_no) + " is not the compiled rules");
    }
    return StartupCheck{};
}

// The configured deployment file (testnet / stagenet / regtest): kind-2
// descriptors merged into T before the start-up checks; never from a peer.
inline StartupCheck merge_configured_deployments(LaneNet net, EpochTable& T, std::span<const Deployment> file) {
    if (file.empty()) return StartupCheck{};
    if (net == LaneNet::Mainnet) return StartupCheck{false, "configured deployment file on mainnet"};
    for (const Deployment& d : file) {
        if (d.kind != kKindFixed) return StartupCheck{false, "configured deployment file: kind 2 only"};
        T.attempts.push_back(d);
    }
    std::stable_sort(T.attempts.begin(), T.attempts.end(), [](const Deployment& a, const Deployment& b) {
        return a.epoch_no != b.epoch_no ? a.epoch_no < b.epoch_no : a.start < b.start;
    });
    return StartupCheck{};
}

// ---------------------------------------------------------------------------
// HELLO trailer values
// ---------------------------------------------------------------------------
inline HelloTrailer hello_trailer(const RatchetParams& p, const RatchetState& s, std::uint64_t x, const EpochTable& T) {
    HelloTrailer t;
    t.epoch_cur = s.epoch_cur;
    const EImpl ei = e_impl(p, s, x, T);
    t.deploy_top = ei.below ? s.epoch_cur : ei.value;
    if (t.deploy_top > s.epoch_cur) {
        const Deployment* d = own_attempt(T, t.deploy_top);
        if (d != nullptr) t.deploy_digest = descriptor_digest(*d);
    }
    const Deployment* n = next_attempt(s, T);
    if (n != nullptr && step(p, s, x, T, *n) != DeploymentState::Failed) t.next_digest = descriptor_digest(*n);
    return t;
}

}  // namespace c2pool::xmr::pathb
