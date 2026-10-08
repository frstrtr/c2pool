#pragma once
// nr_ladder.hpp — the NATIVE RIDGE's shared arithmetic and record types
// (v37, stage S12 + the sealed-cell/reorg redesign "S12-R", the S14
// assembly and the S15 rulings of 2026-09-10).
//
// Split out of shadow_native_ridge.hpp so that the WIRED lane path
// (v37_lane.hpp, behind NrGate / nr_active()) and the STANDALONE
// reference (the proto shadow_native_ridge.hpp, KAT-ND) share EXACTLY one
// definition of
//   * the ladder  (lambda^d as the base-R digit product of 30 cited entries of
//                 the ratified golden d659c801 — ND-R1, LSB-first),
//   * the dimensions and their guard set (check_dims — the FLAG-1 replacement),
//   * the OPEN HORIZON H_open and the sealed() predicate (mechanism A),
//   * the record types FinePair / FineBin / Cell with the CARRIED SPLIT
//                 (mechanism B),
//   * the pure pair value  pair_value(bin, raw, cell)  (order-independence,
//                 found by KAT-ND4),
// and nothing else: no hashing, no lane state, no journal. Everything here is a
// pure function. The lane and the shadow are two INDEPENDENT realizations of
// the rules on top of this header, and KAT-ND-EQ pins them against each other.
//
// ── THE TWO MECHANISMS THIS HEADER CARRIES (PAPER = CANON) ─────────────────
// §4  "The recent bins are OPEN: the present, accepting on-time work and the
//      receipts that credit work already done. As a bin ages it is SETTLED —
//      frozen into an immutable past".
// §15 "nor backdate one, for the committed block fixes its time and EXPIRES it".
// §12 "The total work and the per-worker composition of each summary are
//      preserved exactly".
//
// MECHANISM A — THE OPEN HORIZON.  sealed(b) := b + H_open <= t_now.  The open
// bins are exactly (t_now - H_open, t_now], H_open of them. A receipt credits
// ONLY an open bin; a receipt whose origin is sealed is Expired-sealed (never a
// re-derivation of a settled summary — that option is REJECTED: it would make
// the seal a non-event and un-pin the permanence leaf). A level-l group folds
// only when its NEWEST bin is sealed (sealed(p_hi)), so no receipt can ever
// target a folded bin: the owner of an accepted event is ALWAYS the level-0
// open cell, and the level>=1 materialization of the S12 shadow (target_level /
// owner_cell) is DELETED. Fold timing is a pure function of the clock
// (jump-invariant, KAT-ND13). H_open derives from a RATIFIED constant: W2
// admission bounds every event to origin_bin >= carrier_bin - N_CTX with N_CTX
// = 2 (w2_admission.hpp:180, W2_N_CTX); with 1 bin = 1 buried block (ruling A)
// any H_open > N_CTX makes Expired-sealed UNREACHABLE for W2-admitted events
// whose carrier is within (H_open - N_CTX - 1) bins of the clock (KAT-ND12b).
// Guards: N_CTX < H_open < W_MIN, and W_MIN >= H_open + R^fold_cap so every
// cell reaches its top level BEFORE any of its bins is shed (fold-before-shed).
//
// MECHANISM B — THE IMMUTABLE SEAL RECORD + THE CARRIED SPLIT.  At the seal a
// cell's {level, bin_lo, bin_hi, raw_work, comp, prov} is FROZEN: nothing ever
// writes to them again. The exact-bin shed no longer subtracts from comp:
// shedding bin b of cell c moves b's fine pairs into c.carried[miner] += p.v
// (the IDENTICAL stored frame value — exactness kept, KAT-ND5') and erases the
// fine bin. Reads split the record:
//     live_c  = G_c * (comp_c[m] - carried_c[m])      (U256 subtraction: exact)
//     carry_c = G_c *  carried_c[m]
// A cell entirely below the floor has carried == comp, pays only through the
// carry ledger, stays a cell (no new frame, no rebase) until lambda^(t - bin_hi)
// leaves the ladder domain (ND-R4) and is then dropped deterministically.
//
// bin_lo is the LATTICE span start idx * R^level (a pure function of the cell's
// key), so it is frozen trivially and never "raised" by a shed.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <vector>

#include "v37_fixed.hpp"   // v37::U256, mul_q64, Q_ONE, decay_canonical

namespace v37 {

// The parent chain a lane rides. It fixes the bin unit (ruling A: one bin ==
// one buried parent-chain block, so bin_seconds IS the parent's target block
// spacing) and therefore the whole ruled width table below. It is NOT digested
// and never reaches a leaf: like the version selector, it SELECTS consensus
// constants rather than being one.
//
// S12: this enum lives HERE rather than in v37_lane.hpp so that the ND-R6
// dimension table (nr::for_version(1, lane), below) and the S4 width law's
// constant set name the SAME type and read the SAME numbers. One enum, one
// table, one source of truth.
enum class LaneKind : std::uint32_t { BTC = 0, LTC = 1, DASH = 2, DOGE = 3 };

namespace nr {

namespace dc = decay_canonical;

using MinerId = std::uint32_t;

// R, the roll-up. FROZEN at the shipped rollup. (ND-R3 RE-RULED ruling G:
// c0 / E are NO LONGER consensus dimensions; the native cell ladder REPLACES
// the positional pyramid. R survives as §12's "fixed multiple".)
inline constexpr u64 ROLLUP = 8;
// Deepest ladder level the strict golden subset can reach: R^4 = 4096 <= 8192.
inline constexpr u64 LADDER_TOP_LEVEL = 4;
// Hard cap on in-window cell levels (memory/perf dial only under the exact floor).
inline constexpr u64 MAX_FOLD_CAP = 4;
// W2's context window in bins (W2_N_CTX == 2 mainchain blocks, ruling A: 1 bin
// = 1 buried block). Cited, not owned: the disposition of an event belongs to
// W2; the lane's sealed guard is belt-and-braces (KAT-ND12b).
inline constexpr u64 N_CTX_BINS = 2;
// The RECOMMENDED open horizon: 2R bins (> N_CTX by a wide margin, < every
// ruled W_MIN). A consensus constant carried per lane in NrGate /
// RidgeDim::open_horizon_bins; this is the for_version(1) SHAPE value.
inline constexpr u64 OPEN_HORIZON_DEFAULT = 2 * ROLLUP;

// ── U256 helpers, FREE functions (v37_fixed.hpp is NOT touched) ────────────
// raw * 2^FRAC_BITS as a U256 — the ONLY place raw work becomes Q62, and it is
// an exact SHIFT, not a table read. raw < 2^128 => result < 2^190, no overflow.
inline U256 lift_q62(u128 raw) {
    static_assert(FRAC_BITS == 62, "nr: lift_q62 is written for Q62");
    U256 out;
    const u64 lo = static_cast<u64>(raw);
    const u64 hi = static_cast<u64>(raw >> 64);
    out.v[0] = lo << 62;
    out.v[1] = (lo >> 2) | (hi << 62);
    out.v[2] = (hi >> 2);
    out.v[3] = 0;
    return out;
}

// ── THE LADDER — the only arithmetic NR needs ──────────────────────────────
// LAD(l, k) = lambda^(k * R^l), Q62, k in [0, R). Every in-domain value is an
// entry the ratified golden d659c801 ALREADY publishes (30 entries, deepest
// 8192 == CANON_MAX_DEPTH). ND-R4 closure: a digit beyond the domain has no
// single golden entry; `allow_digit_repeat` closes it as k successive mul_q64
// by decay[R^l] — OFF by default (strict subset of the ratified table).
struct LadderOpts {
    bool allow_digit_repeat = false;   // ND-R4
};

inline u64 pow_R(u64 level) {
    u64 s = 1;
    for (u64 i = 0; i < level; ++i) s *= ROLLUP;
    return s;
}

inline u64 lad(u64 level, u64 k, const LadderOpts& o = LadderOpts{}) {
    if (k == 0) return Q_ONE;                     // identity: no multiply
    if (k >= ROLLUP)
        throw std::invalid_argument("nr: ladder digit out of range [0,R)");
    const u64 span = pow_R(level);
    const u128 d = u128(k) * span;
    if (d <= dc::CANON_MAX_DEPTH) return dc::DECAY[static_cast<std::size_t>(d)];
    if (!o.allow_digit_repeat)
        throw std::invalid_argument(
            "nr: ladder entry beyond the ratified golden domain and the "
            "ND-R4 digit-repeat closure is not enabled");
    if (span > dc::CANON_MAX_DEPTH)
        throw std::invalid_argument("nr: ladder span beyond the golden domain");
    u64 g = Q_ONE;
    const u64 base = dc::DECAY[static_cast<std::size_t>(span)];
    for (u64 i = 0; i < k; ++i) g = mul_q64(g, base);
    return g;
}

// lambda^d as the base-R DIGIT PRODUCT, LSB-first (ND-R1) — RECOMPUTED, never
// accumulated. Exactly the order a fold chain lifts a unit, so late credit
// within the horizon is byte-identical to on-time credit.
inline u64 lambda_pow(u64 d, const LadderOpts& o = LadderOpts{}) {
    u64 g = Q_ONE, level = 0;
    while (d) {
        const u64 k = d % ROLLUP;
        if (k) g = mul_q64(g, lad(level, k, o));
        d /= ROLLUP;
        ++level;
    }
    return g;
}

// The strict ladder domain in BINS: ages must stay below 3 * 4096 = 12288.
// This is ALSO the deterministic drop edge of a fully-carried cell (mechanism
// B): a cell with t - bin_hi >= ladder_domain_bins() has no G and is deleted.
inline constexpr u64 ladder_domain_bins() {
    return (dc::CANON_MAX_DEPTH / 4096 + 1) * 4096;   // = 12288 at R=8
}

// The 30 (level, digit) ladder points, enumerated in canonical order.
struct LadderPoint { u64 level, digit, depth, value; };
inline std::vector<LadderPoint> ladder_points() {
    std::vector<LadderPoint> out;
    for (u64 l = 0; l <= LADDER_TOP_LEVEL; ++l) {
        const u64 span = pow_R(l);
        for (u64 k = 1; k < ROLLUP; ++k) {
            const u128 d = u128(k) * span;
            if (d > dc::CANON_MAX_DEPTH) break;
            out.push_back(LadderPoint{l, k, static_cast<u64>(d),
                                      dc::DECAY[static_cast<std::size_t>(d)]});
        }
    }
    return out;
}

// ── DIMENSIONS — the FLAG-1 replacement guard set + the open horizon ──────
struct RidgeDim {
    u64  rollup          = ROLLUP;
    u64  fold_cap        = 2;      // LAMBDA: max in-window cell level [ND-R2]
    u64  half_life_bins  = dc::CANON_HALF_LIFE;   // ND-R8: 2160 BINS, uniform
    u64  bin_seconds     = 0;      // parent-chain spacing; traceability only
    u64  w_min_bins      = 0;
    u64  w_max_bins      = 0;
    u64  w_default_bins  = 0;
    u64  retarget_bins   = ROLLUP;
    u64  damp_factor     = 4;
    u64  open_horizon_bins = OPEN_HORIZON_DEFAULT;   // H_open (mechanism A)
    // S14 (assembly): the two remaining BIN-CLOCK cadences the wired lane
    // drives natively — the S4 width law's period (retarget_bins above) and
    // the I-3 checkpoint cadence. Both are operator-baked consensus constants
    // (ND-R6); the guard set below only pins their SHAPE.
    u64  ckpt_bins       = 64;     // I-3 checkpoint cadence, a top-lattice multiple
    u64  n_ctx_bins      = N_CTX_BINS;   // mirror of W2_N_CTX (w2_admission.hpp:180)
    LadderOpts ladder{};

    u64 q() const { return pow_R(fold_cap); }     // coarsest in-window span
};

inline void check_dims(const RidgeDim& d) {
    if (d.rollup != ROLLUP)
        throw std::invalid_argument("nr: rollup is frozen at R = 8");
    if (d.fold_cap == 0 || d.fold_cap > MAX_FOLD_CAP)
        throw std::invalid_argument("nr: fold cap outside [1, ladder top level]");
    if (d.half_life_bins == 0)
        throw std::invalid_argument("nr: zero half-life");
    if (d.half_life_bins != dc::CANON_HALF_LIFE)
        throw std::invalid_argument(
            "nr: half_life != 2160 bins would need a ladder golden of its own "
            "(ND-R8 RULED: 2160 BINS uniform, d659c801 reused bit-for-bit)");
    if (d.w_min_bins == 0 || d.w_max_bins == 0 || d.w_default_bins == 0)
        throw std::invalid_argument("nr: width params unset");
    if (d.w_min_bins < ROLLUP)
        throw std::invalid_argument("nr: W_MIN below one fold group (R bins)");
    for (u64 w : {d.w_min_bins, d.w_max_bins, d.w_default_bins}) {
        if (w % ROLLUP)
            throw std::invalid_argument("nr: width not a whole fold-group multiple");
        if (d.retarget_bins && (w % d.retarget_bins))
            throw std::invalid_argument("nr: width not retarget-aligned (ruling F)");
        if (d.damp_factor && (w % d.damp_factor))
            throw std::invalid_argument("nr: damp factor does not divide the width bounds");
    }
    if (!(d.w_min_bins <= d.w_default_bins && d.w_default_bins <= d.w_max_bins))
        throw std::invalid_argument("nr: W_default outside [W_MIN, W_MAX]");
    if (!d.ladder.allow_digit_repeat && d.w_max_bins > ladder_domain_bins())
        throw std::invalid_argument(
            "nr: W_MAX beyond the ratified ladder domain (12288 bins at R=8); "
            "enable the ND-R4 digit-repeat closure or lower W_MAX");
    // ── S14: the bin-clock cadences (width law + checkpoints) ──
    // The width law steps in WHOLE R-bin periods (ruling F) and a checkpoint
    // must stand on the TOP-LEVEL lattice, so a rebuild's fine-layer replay
    // never starts inside a half-folded group. Both are uniform throws.
    if (d.retarget_bins == 0 || (d.retarget_bins % ROLLUP) != 0)
        throw std::invalid_argument(
            "nr: retarget_bins must be a non-zero whole-R multiple (ruling F)");
    if (d.ckpt_bins == 0 || (d.ckpt_bins % pow_R(d.fold_cap)) != 0)
        throw std::invalid_argument(
            "nr: checkpoint cadence must be a non-zero multiple of R^fold_cap "
            "(a checkpoint stands on the top-level lattice)");
    // ── mechanism A: the open horizon ──
    if (d.n_ctx_bins == 0)
        throw std::invalid_argument("nr: N_CTX mirror unset (0 is not the shipped 2)");
    if (d.open_horizon_bins <= d.n_ctx_bins)
        throw std::invalid_argument(
            "nr: open horizon must exceed N_CTX (W2-admitted receipts must never "
            "be Expired-sealed)");
    if (d.open_horizon_bins >= d.w_min_bins)
        throw std::invalid_argument("nr: open horizon must be below W_MIN");
    // fold-before-shed: a level-l group folds at p_hi + H_open and its oldest
    // bin sheds at p_lo + W = p_hi - R^l + 1 + W, so W >= H_open + R^l - 1
    // for every l <= fold_cap keeps every cell fully folded before any of its
    // bins leaves the window. Required so a fold always rebuilds from a
    // COMPLETE fine layer and a shed always finds its cell at its top level.
    if (d.w_min_bins < d.open_horizon_bins + pow_R(d.fold_cap))
        throw std::invalid_argument(
            "nr: W_MIN must be >= H_open + R^fold_cap (fold-before-shed)");
}

// The SHIPPED guard, kept verbatim so the KAT can prove what FLAG-1 actually
// broke: ruling C's `w_min_bins >= c0` with c0 = E = 4096 bins.
inline void check_dims_shipped_c0(const RidgeDim& d, u64 c0 = dc::CANON_EPOCH_LEN) {
    if (d.w_min_bins < c0)
        throw std::invalid_argument(
            "v37: window must be >= C0 (eviction needs whole buckets) "
            "[the FLAG-1 clause]");
    if (!(d.w_min_bins <= d.w_max_bins))
        throw std::invalid_argument("v37: w_min_bins > w_max_bins");
}

// ── for_version(1): the ruled lanes, ~24 h adaptive window ─────────────────
// ND-R6 **RULED** (operator, 2026-09-10). The numbers below are no longer a
// proto proposal: they are the operator-baked per-lane consensus table, and
// this function is their SINGLE SOURCE OF TRUTH: LaneParams::for_version(v, lane)
// and winlaw::ruled(lane) both READ IT, never a second copy of the numbers.
//
//   lane  bin_s   W_MIN   W_default          W_MAX             LAMBDA  H_open  R_b  ckpt
//   BTC   600     80      144   (24.0 h)     1152  ( 8.0 d)    1       16      8    64
//   LTC   150     528     576   (24.0 h)     4608  ( 8.0 d)    2       16      8    64
//   DASH  150     528     576   (24.0 h)     4608  ( 8.0 d)    2       16      8    64
//   DOGE   60     528     1440  (24.0 h)     8640  ( 6.0 d)    2       16      8    64
//
// Every row is checked by check_dims below and, unlike the earlier review
// CANDIDATE (nd_r6_candidate, kept for the record), every row PASSES:
//   * a whole multiple of R = 8, of retarget_bins = 8 and of damp_factor = 4;
//   * W_MIN >= H_open + R^LAMBDA (fold-before-shed) — the clause that refused
//     the candidate; the ruling clears it with margin on all four lanes
//     (BTC 80 >= 24, LTC/DASH/DOGE 528 >= 80);
//   * W_MIN <= W_default <= W_MAX, and W_MAX <= ladder_domain_bins() = 12288
//     (DOGE's W_MAX came down from the candidate's 11520 to 8640).
// The RESOLUTION taken is option (b) of the S14 finding — raise W_MIN — with
// the proto LAMBDA (1/2/2) kept, so LAMBDA stays the perf/memory dial it was
// described as and W_MIN carries the coupling.
//
// H_open = 2R = 16 on every lane (consensus, ND-R6). retarget_bins = R and
// ckpt_bins = 8R remain the proto cadence values (ND-R6 note (i), still OWED);
// coverage_blocks has no derivable value and is pinned to W_default by the
// callers, flagged OWED.
// LaneKind is the canon enum declared above (v37::LaneKind): unqualified
// here by the enclosing namespace, so there is exactly one definition.

inline const char* lane_name(LaneKind k) {
    switch (k) {
        case LaneKind::BTC:  return "BTC";
        case LaneKind::LTC:  return "LTC";
        case LaneKind::DASH: return "DASH";
        case LaneKind::DOGE: return "DOGE";
    }
    return "?";
}

inline RidgeDim for_version(std::uint32_t v, LaneKind lane) {
    RidgeDim d;
    if (v != 1) return d;                       // v0: NR inert, gate OFF
    switch (lane) {
        case LaneKind::BTC:
            d.bin_seconds = 600;  d.w_default_bins = 144;
            d.w_min_bins  = 80;   d.w_max_bins     = 1152;  d.fold_cap = 1;
            break;
        case LaneKind::LTC:
        case LaneKind::DASH:
            d.bin_seconds = 150;  d.w_default_bins = 576;
            d.w_min_bins  = 528;  d.w_max_bins     = 4608;  d.fold_cap = 2;
            break;
        case LaneKind::DOGE:
            d.bin_seconds = 60;   d.w_default_bins = 1440;
            d.w_min_bins  = 528;  d.w_max_bins     = 8640;  d.fold_cap = 2;
            break;
    }
    d.retarget_bins = ROLLUP;        // the PROTO value (ND-R6 note (i)); owed
    d.ckpt_bins     = 8 * ROLLUP;    // 64 bins = R^2, a top-lattice multiple on every lane
    d.open_horizon_bins = OPEN_HORIZON_DEFAULT;
    d.n_ctx_bins    = N_CTX_BINS;
    check_dims(d);
    return d;
}

// ── ND-R6 CANDIDATE TABLE — the review's SHAPE-derived numbers ─────────────
// RULING GIVEN 2026-09-10 — this candidate is SUPERSEDED, and is kept only as
// the negative control that makes the finding checkable: the operator resolved
// ND-R6 by option (b) below (raise W_MIN, keep the proto LAMBDA), and
// for_version(1) above now carries the ruled table. KAT-ND-CTOR still proves
// this candidate is refused 4/4 by the same guard set that accepts the ruled
// one, so the two are never confused and the coupling stays documented.
//
// (historical, as circulated with the redesign brief:)
// This is the alternative dimension set circulated
// with the redesign brief: W_MIN = W_default/4 rounded to R^LAMBDA alignment,
// LAMBDA = the smallest level with W_MAX / R^LAMBDA <= 64 live top cells, and
// retarget_bins = ckpt_bins = R^LAMBDA. It is NOT the default and is NOT
// wired: it is returned RAW (check_dims is deliberately NOT called) so a KAT
// can put it through the guard set and pin what happens.
//
// S14 FINDING (KAT-ND-CTOR, clause "fold-before-shed"): every row of this
// table is REFUSED by check_dims. LAMBDA is described in the brief as "a pure
// perf/memory dial under the exact floor", but it is not free — it is coupled
// to W_MIN through fold-before-shed, W_MIN >= H_open + R^LAMBDA:
//     BTC   W_MIN 32  vs H_open 16 + R^2 64  = 80   -> refused
//     LTC   W_MIN 128 vs H_open 16 + R^3 512 = 528  -> refused
//     DASH  W_MIN 128 vs 528                        -> refused
//     DOGE  W_MIN 384 vs 528                        -> refused
// The proto table above (LAMBDA 1/2/2, W_MIN 32/144/144/360, retarget R)
// satisfies it on all four lanes. Resolving the candidate table needs ONE of:
//   (a) keep the proto LAMBDA (1/2/2) and the proto W_MIN — the default here;
//   (b) raise W_MIN to >= H_open + R^LAMBDA (breaks the W_default/4 shape:
//       LTC would need W_MIN 528 = 0.92 * W_default);
//   (c) lower H_open (bounded below by N_CTX = 2, buys at most 14 bins);
//   (d) drop fold-before-shed — REJECTED here, not offered: it is what lets a
//       fold rebuild a parent from a COMPLETE fine layer and lets a shed find
//       its cell already at its top level. Without it a cell can lose bins to
//       the floor before it ever folds, and the seal record is no longer a
//       frozen function of the cell's own bins.
// The operator picks; the lane refuses anything that does not pass the guards.
struct NdR6Candidate { RidgeDim dim; const char* lane; };
inline RidgeDim nd_r6_candidate(LaneKind lane) {
    RidgeDim d;
    switch (lane) {
        case LaneKind::BTC:
            d.bin_seconds = 600;  d.w_default_bins = 144;
            d.w_min_bins  = 32;   d.w_max_bins     = 1152;  d.fold_cap = 2;
            break;
        case LaneKind::LTC:
        case LaneKind::DASH:
            d.bin_seconds = 150;  d.w_default_bins = 576;
            d.w_min_bins  = 128;  d.w_max_bins     = 4608;  d.fold_cap = 3;
            break;
        case LaneKind::DOGE:
            d.bin_seconds = 60;   d.w_default_bins = 1440;
            d.w_min_bins  = 384;  d.w_max_bins     = 11520; d.fold_cap = 3;
            break;
    }
    d.retarget_bins = pow_R(d.fold_cap);
    d.ckpt_bins     = pow_R(d.fold_cap);
    d.open_horizon_bins = OPEN_HORIZON_DEFAULT;
    d.n_ctx_bins    = N_CTX_BINS;
    return d;                     // RAW — the caller runs check_dims
}

// lambda^W in Q62 — the weight a unit still carries at the window floor.
inline u64 lambda_pow_W(u64 W, const LadderOpts& o = LadderOpts{}) {
    return lambda_pow(W, o);
}

// ── ADMISSION (ruling I: never silent) ─────────────────────────────────────
// Expired       — origin below the burial floor B_bin (ruling I).
// ExpiredSealed — origin inside the settled past (sealed(origin)): the paper's
//                 §15 "expires it". Distinct from Expired so the two guards are
//                 attributable separately (W2 gains REJECT_SEALED beside
//                 REJECT_EXPIRED — seam, flagged).
enum class Disposition { Accepted, Duplicate, Expired, ExpiredSealed };

inline const char* disposition_name(Disposition d) {
    switch (d) {
        case Disposition::Accepted:      return "Accepted";
        case Disposition::Duplicate:     return "Duplicate";
        case Disposition::Expired:       return "Expired";
        case Disposition::ExpiredSealed: return "ExpiredSealed";
    }
    return "?";
}

// ── THE OPEN HORIZON predicate (mechanism A) ───────────────────────────────
// sealed(b, t, H) := b + H <= t. Pure; the same function on every node.
inline bool sealed_bin(u64 bin, u64 t_now, u64 open_horizon) {
    return bin + open_horizon <= t_now;
}
// The lattice span of the level-l group containing `bin`.
inline u64 group_lo(u64 bin, u64 level) { return (bin / pow_R(level)) * pow_R(level); }
inline u64 group_hi(u64 bin, u64 level) { return group_lo(bin, level) + pow_R(level) - 1; }
// The level a bin's cell HAS reached at clock t under the sealed() fold rule:
// the deepest l <= fold_cap whose lattice group's newest bin is sealed. A pure
// function of (bin, t, H_open, fold_cap) — this is what makes fold timing
// jump-invariant (KAT-ND13) and what the reference recompute uses.
inline u64 level_at(u64 bin, u64 t_now, u64 open_horizon, u64 fold_cap) {
    for (u64 l = fold_cap; l >= 1; --l)
        if (sealed_bin(group_hi(bin, l), t_now, open_horizon)) return l;
    return 0;
}

// ── THE RECORD TYPES ───────────────────────────────────────────────────────

// One (bin, miner) residency. `v` is the unit's value IN ITS CELL'S CURRENT
// FRAME. Retaining it per bin is what buys the EXACT window floor: the value
// moved to `carried` when the bin expires is the IDENTICAL value that was
// added, so the split is exact with no re-derivation and no second truncation.
struct FinePair {
    u128 raw = 0;
    U256 v{};
    bool operator==(const FinePair&) const = default;
};

// The non-v37 provenance key (protocol version, miner) — I-6, raw only.
using ProvKey = std::pair<std::uint16_t, MinerId>;

struct FineBin {
    u64                      bin = 0;
    u128                     raw_sum = 0;
    std::map<MinerId, FinePair> rows;    // ascending miner: deterministic
    // The bin's non-v37 provenance mix (I-6). Part of the FINE LAYER so a
    // cell's prov rows are a PURE FUNCTION of its bins (fold, fold-undo and
    // the reference recompute all derive them) — found by KAT-ND10: with
    // provenance on the cell record only, a fold-undo could not restore it.
    std::map<ProvKey, u128>  prov;
    // Lane-only bookkeeping (the shadow leaves it at the sentinel): the lowest
    // POSITION of any atom resident in this bin — the checkpoint's replay
    // start (rebuild_from_checkpoint rebuilds the fine layer from the tracker
    // from min over live bins). NOT a digest input.
    u64 pos_lo = UINT64_MAX;
    bool operator==(const FineBin&) const = default;
};

// A provenance row of a cell (I-6 MV-OQ1 = A: version is leaf provenance only,
// never a weight input). Same shape as the lane's ProvEntry; kept local so this
// header stays lane-independent.
struct ProvRow {
    std::uint16_t version = 0;
    MinerId       miner = 0;
    u128          raw = 0;
    bool operator==(const ProvRow&) const = default;
};

// A ladder cell. §12: total work and per-worker composition, both EXACT.
//
// THE SEAL RECORD (frozen once sealed(bin_hi)): level, bin_lo, bin_hi,
// raw_work, comp, prov, record_only. NOTHING writes to these after the seal.
// The only later events on a cell are (i) G recomputed per tick (a scalar
// OUTSIDE the record), (ii) a carried entry (the split), (iii) deletion at the
// ladder-domain edge. An OPEN level-0 cell's record changes with every credit
// — it is the present; the KAT asserts immutability from the seal tick on.
struct Cell {
    u64  level  = 0;
    u64  bin_lo = 0;      // LATTICE span start: idx * R^level (pure function)
    u64  bin_hi = 0;      // the ANCHOR: the cell's newest bin, its frame
    u128 raw_work = 0;
    std::map<MinerId, U256> comp;        // ascending miner: deterministic
    std::vector<ProvRow>    prov;        // non-v37 provenance mix (lane); empty in the shadow
    // record_only: a cell with NO fine layer behind it — the activation
    // migration cell (ruling K, seal-to-t0_bin realized under NR: the
    // pre-gate positional state frozen as ONE level-0 record at t0_bin).
    // Never folds, never re-derived; fully carried the tick its bin leaves
    // the window; dropped at the ladder-domain edge like any other cell.
    bool record_only = false;
    // ── outside the record ──
    u64  G = Q_ONE;                      // lambda^(t_now - bin_hi), per tick
    // ── the CARRIED SPLIT (mechanism B) ──
    // carried[m] == the exact sum of the stored frame values of m's pairs in
    // this cell's bins that have been SHED; carried_raw the raw work of those
    // bins. Invariant: carried[m] <= comp[m]; fully carried <=> carried_raw
    // == raw_work (then carried == comp exactly).
    std::map<MinerId, U256> carried;
    u128 carried_raw = 0;

    // Fully carried <=> every bin shed. For a fine-backed cell that is
    // carried_raw == raw_work; the size clause makes the predicate correct for
    // a record-only prologue cell whose positional prologue held carry-only
    // weight (raw_work == 0 from the start) — it is carried only once its
    // rows were moved.
    bool fully_carried() const {
        return carried_raw == raw_work && carried.size() == comp.size();
    }
    bool operator==(const Cell&) const = default;
};

// THE pair value: a PURE FUNCTION of (bin, accumulated raw, owning cell).
// Found by KAT-ND4, not assumed: an incrementally maintained pair value makes
// the digest depend on arrival order (two credits straddling a fold truncate
// in a different order). Deriving from the accumulated raw every time is
// order-independent by construction; the lift chain is the base-R digits of
// (anchor - bin) applied LSB-first (ND-R1) — the fold's own constants in the
// fold's own order — so late credit within the horizon is byte-identical to
// on-time credit.
inline U256 pair_value(u64 bin, u128 raw, u64 level, u64 bin_hi,
                       const LadderOpts& o = LadderOpts{}) {
    U256 v = lift_q62(raw);
    const u64 off = bin_hi - bin;
    for (u64 l = 0; l < level; ++l) {
        const u64 k = (off / pow_R(l)) % ROLLUP;
        if (k) v = v.mul_q(lad(l, k, o));
    }
    return v;
}
inline U256 pair_value(u64 bin, u128 raw, const Cell& c, const LadderOpts& o = LadderOpts{}) {
    return pair_value(bin, raw, c.level, c.bin_hi, o);
}

// The provenance rows of a (version, miner) -> raw map, (version, miner) order.
inline std::vector<ProvRow> prov_rows_of(const std::map<ProvKey, u128>& m) {
    std::vector<ProvRow> out;
    out.reserve(m.size());
    for (const auto& [k, raw] : m) out.push_back(ProvRow{k.first, k.second, raw});
    return out;
}

// The per-cell scalar for clock t: lambda^(t - bin_hi). Throws (attributable)
// at or beyond the ladder-domain edge — the caller drops such a cell BEFORE
// refreshing, so the throw is unreachable on the consensus path.
inline u64 cell_scalar(u64 t_now, u64 bin_hi, const LadderOpts& o = LadderOpts{}) {
    return lambda_pow(t_now > bin_hi ? t_now - bin_hi : 0, o);
}

// The read split of one cell for miner m: {live, carry} in Q62 at clock t.
// Two truncating products (the pinned CARRY-ARITH shape: each ledger's product
// is truncated separately, never (live + carry).mul_q).
struct CellRead { U256 live, carry; };
inline CellRead cell_read(const Cell& c, MinerId m) {
    CellRead r;
    auto it = c.comp.find(m);
    if (it == c.comp.end()) return r;
    U256 live_frame = it->second;
    auto ic = c.carried.find(m);
    if (ic != c.carried.end()) {
        live_frame -= ic->second;                 // exact
        r.carry = ic->second.mul_q(c.G);
    }
    r.live = live_frame.mul_q(c.G);
    return r;
}

// Fixed-width LE serializers for the record bytes (shared by the shadow's
// digest and the KATs' seal fingerprints; the lane has its own append_*).
inline void put_u64(std::vector<std::uint8_t>& b, u64 x) {
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
}
inline void put_u128(std::vector<std::uint8_t>& b, u128 x) {
    for (int i = 0; i < 16; ++i) b.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
}
inline void put_tag(std::vector<std::uint8_t>& b, const char* t) {
    b.insert(b.end(), t, t + 4);
}
// The SEAL RECORD as bytes, raw-MinerId keyed (the resolver-free form the
// shadow digests and the KATs fingerprint; the lane's NRC1 leaf is the same
// record keyed by canonical identity). record_only is IN the record so the
// migration cell can never alias a fine cell at the same bin.
inline std::vector<std::uint8_t> seal_record_bytes(const Cell& c) {
    std::vector<std::uint8_t> b;
    put_tag(b, "NRC1");
    put_u64(b, c.level);
    put_u64(b, c.bin_hi);
    put_u64(b, c.bin_lo);
    put_u128(b, c.raw_work);
    put_u64(b, c.record_only ? 1 : 0);
    put_u64(b, static_cast<u64>(c.comp.size()));
    for (const auto& [m, w] : c.comp) {
        put_u64(b, m);
        for (int i = 0; i < 4; ++i) put_u64(b, w.v[i]);
    }
    put_u64(b, static_cast<u64>(c.prov.size()));
    for (const auto& p : c.prov) { put_u64(b, p.version); put_u64(b, p.miner); put_u128(b, p.raw); }
    return b;
}
// The carried split as bytes (the shadow's NRX1 form).
inline std::vector<std::uint8_t> carried_record_bytes(const Cell& c) {
    std::vector<std::uint8_t> b;
    put_tag(b, "NRX1");
    put_u64(b, c.level);
    put_u64(b, c.bin_hi);
    put_u64(b, c.record_only ? 1 : 0);
    put_u128(b, c.carried_raw);
    put_u64(b, static_cast<u64>(c.carried.size()));
    for (const auto& [m, w] : c.carried) {
        put_u64(b, m);
        for (int i = 0; i < 4; ++i) put_u64(b, w.v[i]);
    }
    return b;
}

} // namespace nr
} // namespace v37
