#pragma once
// v37 payout economics — CarriageGate (capacity-based carriage bonus) +
// FeeFloorGate (dynamic emission floor h_min_dyn). STANDALONE module:
// header-only, integer-only, no translation unit in consensus canon includes it,
// so every pinned golden (lane digest, owed_digest V37Q, w3 wire freeze, XMR
// V37C tail, BTC canonical coinbase) is unchanged by construction. Both gates
// are OFF by default; OFF is bit-for-bit the shipped behaviour (KAT A/F).
//
// ── (1) CarriageGate — the bonus is paid for CAPACITY, never for n_out ─────
//
//   cap(class) = floor((class_bytes(class) - overhead_min) / vb_ref)
//                (class table = rb_cb_class.hpp, merged in c2pool#1709)
//   F_incl     = cb_total_out - subsidy(height)   (cb_total_out < subsidy => REJECT)
//   n_fee      = n_floor + floor(F_incl / (f_ref * vb_ref))
//   n_b        = min(cap(class), Q_fin, n_fee, n_ref)
//   w'         = w + floor(w * beta_ppm * n_b / (10^6 * n_ref))    (u128, saturate u64)
//
//   Gate OFF <=> beta_ppm == 0 (or pos < activation_pos) => w' == w bit-for-bit.
//
//   ANTI-DISPLACEMENT PROPERTY: no input of w' is the number of payout outputs
//   the coinbase actually carries. A node that displaces fee-paying txs to emit
//   more outputs gains nothing (n_out is not an input) and can only LOSE
//   (displacing txs lowers F_incl, and n_b is non-decreasing in F_incl).
//   KAT C pins it.
//
//   Q_fin = number of keys with EffectiveOwed > 0 in the FINALIZED ledger
//   partition at the receipt's cut. R-A LAW (c2pool#1704): it must never be read
//   from a pending / node-local view — that is exactly the input class that
//   forked owed_digest in c2pool#1697. This module takes Q_fin as a number; the
//   caller owns where it comes from (WIRING SEAM, see the bottom of this file).
//
//   Zero-sum: the bonus only reweights the PPLNS window; payout_i =
//   floor(R * w'_i / sum w'), leftover -> donation residual. window_split()
//   below is the REFERENCE normaliser used by the KATs; the canon one is not
//   replaced. A miner whose n_b is 0 loses at most beta/(1+beta) of its gate-OFF
//   payout (KAT E).
//
//   XMR: CarriageGate is PERMANENTLY OFF. Monero miners receive only the hashing
//   blob and the node builds the whole miner_tx, so every XMR miner is
//   effectively class 5; a per-share bonus would be pure node-farming with
//   nothing to motivate. carriage_gate_xmr() / validate_for_xmr() pin it.
//
// ── (2) FeeFloorGate — the emission floor rises with the block's fee rate ──
//
//   D          = block_limit - cb_fixed          (both known BEFORE any payout
//                                                 output is chosen; floored at 1)
//   fbar_ub    = F_incl / D                      (never materialised: one final
//                                                 rounding only, see below)
//   h_min_dyn  = max(k_floor * vb(kind), ceil(m * F_incl * vb(kind) / D))
//   emit iff amount >= h_min_dyn, else CARRY (skip-and-continue, identical to
//   the w4_settlement.hpp propose_coinbase sub-floor carry; oldest-first order
//   and the K_max stop-at-first-exceed are untouched).
//
//   Gate OFF <=> m == 0 (or pos < activation_pos) => h_min_dyn == k_floor * vb
//   == w5_coinbase.hpp h_min(kind, k_floor) exactly (KAT F).
//
//   DISPLACEMENT BOUND: every emitted output satisfies a >= m * fbar * vb, so
//   the block space it occupies is worth at most a/m at the block's mean fee
//   rate; summed over the coinbase, socialised displacement <= sum(a)/m <= R/m.
//   The dynamic term uses CEIL (not floor) so the bound is exact in integers:
//   m * F_incl * sum(vb) <= D * sum(a) (KAT H).
//
//   NON-CIRCULARITY: the design text writes (L - cb_bytes). The coinbase's
//   payout bytes depend on which outputs clear h_min_dyn, so this module reads
//   cb_bytes as the coinbase FIXED (non-payout) bytes — rb_cb_class.hpp
//   BlockFacts::coinbase_fixed_overhead — which both propose_coinbase and the
//   canonical rebuild know before emission. Rebuild-deterministic given the
//   block (F_incl = coinbase total - subsidy(h) is block-intrinsic).
//
//   k_floor is NOT owned by this gate. It is a lane consensus constant (the
//   k_floor -> LaneParams hotfix, branch v37/kfloor-laneparam): a node-config
//   k_floor changes the canonical coinbase and forks owed_digest silently. The
//   caller passes the lane's k_floor; this module never defaults one.
//
//   XMR: FeeFloorGate is applicable (m = 100 recommended); XMR has no
//   ScriptKind, so the XMR caller passes its per-output miner_tx byte size to
//   the vb-taking overload (h_min_dyn_vb).
//
// Balance inequality (design K9, static_assert below): the bonus never exceeds
// the value of the drain service to the pool,
//   beta <= r_max * Q_ref * (1/C_lo - 1/C_hi) / (2 * b_ref * 365)
//   with r_max = 20 %, Q_ref = 2000, C 20 -> 200, b_ref = 1.44 blocks/day
//   => beta <= 17,123 ppm (1.71 %); V1 = 5,000 ppm, V2 = 10,000 ppm both hold.

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

#include <c2pool/v37/roundabout/rb_cb_class.hpp>   // CbClass, class_bytes, BlockFacts
#include <c2pool/v37/roundabout/rb_params.hpp>     // put_* LE helpers, hash_bytes
#include <sharechain/v37/v37_descriptor.hpp>       // ScriptKind
#include <sharechain/v37/v37_fixed.hpp>            // u64, u128
#include <sharechain/v37/v37_hash.hpp>             // bytes32

namespace c2pool::v37n::payout::carriage {

using ::v37::bytes32;
using ::v37::ScriptKind;
using ::v37::u128;
using ::v37::u64;
namespace rb = ::c2pool::v37n::rb;

inline constexpr u64 PPM = 1'000'000;
inline constexpr u64 U64_MAX = std::numeric_limits<u64>::max();

inline constexpr u64 sat_u64(u128 x) { return x > u128(U64_MAX) ? U64_MAX : static_cast<u64>(x); }

// ── recommended constants (design wf_3198adbe-1b3, operator-approved 09-23) ──
inline constexpr std::uint32_t CARRIAGE_BETA_PPM_V1 = 5'000;    // 0.5 % (trust-the-node bound)
inline constexpr std::uint32_t CARRIAGE_BETA_PPM_V2 = 10'000;   // 1.0 % (after merkle-branch proof)
inline constexpr std::uint16_t CARRIAGE_N_REF       = 500;
inline constexpr std::uint16_t CARRIAGE_N_FLOOR     = 16;
inline constexpr std::uint32_t CARRIAGE_F_REF       = 10;       // sat/vB
inline constexpr std::uint8_t  CARRIAGE_VB_REF_BTC  = 31;       // P2WPKH output
inline constexpr std::uint8_t  CARRIAGE_VB_REF_DASH = 34;       // P2PKH output
// Coinbase fixed overhead used for the capacity table. The design quotes
// "~250 B" and publishes two tables (BTC P2WPKH {16, 64, 201, 520, ~2100},
// DASH P2PKH {14, 59, 184, 474, ~1900}); overhead_min in (240, 244] reproduces
// both exactly for classes 0..3. 244 is the largest such value (conservative).
inline constexpr std::uint16_t CARRIAGE_OVERHEAD_MIN = 244;
inline constexpr std::uint32_t FEE_FLOOR_M_DEFAULT = 100;       // <= 1 % of R socialised
inline constexpr std::uint32_t FEE_FLOOR_M_MIN     = 100;       // design K9 fee bound: m >= 100 when ON

// ── K9 balance inequality (integers, ppm) ──────────────────────────────────
inline constexpr u64 BAL_R_MAX_PPM   = 200'000;   // r_max = 20 % / year
inline constexpr u64 BAL_Q_REF       = 2'000;     // reference queue length
inline constexpr u64 BAL_C_LO        = 20;        // stock drain rate (outputs/block)
inline constexpr u64 BAL_C_HI        = 200;       // carrier drain rate
inline constexpr u64 BAL_B_REF_MILLI = 1'440;     // 1.44 pool blocks/day (x1000)

// Service value of the C_lo -> C_hi drain, in ppm of R per block.
inline constexpr u64 drain_service_value_ppm(u64 r_ppm) {
    const u128 num = u128(r_ppm) * BAL_Q_REF * (BAL_C_HI - BAL_C_LO) * 1000;
    const u128 den = u128(2) * BAL_B_REF_MILLI * 365 * BAL_C_LO * BAL_C_HI;
    return static_cast<u64>(num / den);
}
inline constexpr u64 CARRIAGE_BETA_PPM_MAX = drain_service_value_ppm(BAL_R_MAX_PPM);

static_assert(CARRIAGE_BETA_PPM_MAX == 17'123, "K9: service value at r_max = 20 % is 1.71 % of R");
static_assert(CARRIAGE_BETA_PPM_V1 <= CARRIAGE_BETA_PPM_MAX, "K9: V1 beta must not exceed the drain service value");
static_assert(CARRIAGE_BETA_PPM_V2 <= CARRIAGE_BETA_PPM_MAX, "K9: V2 beta must not exceed the drain service value");
static_assert(drain_service_value_ppm(50'000) == 4'280, "K9: 0.43 % of R/block at r = 5 % (design numbers)");
static_assert(FEE_FLOOR_M_DEFAULT >= FEE_FLOOR_M_MIN, "K9: fee bound m >= 100 (displacement <= 1 % of R)");
// u128 headroom of the bonus product: w < 2^64, beta_ppm < 2^32, n_b <= n_ref < 2^16.
static_assert(64 + 32 + 16 < 128, "bonus product fits u128");

// ── output virtual size by kind (mirror of w5_coinbase.hpp output_size) ────
// 8 (value) + 1 (script-length prefix) + scriptPubKey. Non-witness bytes, so
// 1 byte == 1 vB. KAT F cross-checks this table against w5 output_size().
inline constexpr u64 output_vb(ScriptKind k) {
    switch (k) {
        case ScriptKind::P2PKH:  return 8 + 1 + 25;
        case ScriptKind::P2SH:   return 8 + 1 + 23;
        case ScriptKind::P2WPKH: return 8 + 1 + 22;
        case ScriptKind::P2WSH:  return 8 + 1 + 34;
        case ScriptKind::P2TR:   return 8 + 1 + 34;
        case ScriptKind::RAW:
        default:                 return 8 + 1 + 34;
    }
}

// ═════════════════════════════════════════════════════════════════════════
// (1) CarriageGate
// ═════════════════════════════════════════════════════════════════════════

struct CarriageGate {
    std::uint32_t beta_ppm = 0;                       // 0 => OFF (default)
    std::uint16_t n_ref = CARRIAGE_N_REF;
    std::uint16_t n_floor = CARRIAGE_N_FLOOR;
    std::uint32_t f_ref_sat_vb = CARRIAGE_F_REF;
    std::uint8_t  vb_ref = CARRIAGE_VB_REF_BTC;       // lane reference output vB
    std::uint16_t overhead_min = CARRIAGE_OVERHEAD_MIN;
    u64           activation_pos = U64_MAX;           // position-gated flip

    bool off() const { return beta_ppm == 0; }
    bool active_at(u64 pos) const { return !off() && pos >= activation_pos; }
    bool operator==(const CarriageGate&) const = default;

    // The V1 recommended parameterisation (still position-gated by the caller).
    static CarriageGate v1(std::uint8_t vb_ref_lane, u64 activation) {
        CarriageGate g;
        g.beta_ppm = CARRIAGE_BETA_PPM_V1;
        g.vb_ref = vb_ref_lane;
        g.activation_pos = activation;
        return g;
    }
};

// A parameter set a lane may carry. OFF is always valid. ON requires positive
// divisors and a beta within the K9 service-value bound.
inline bool validate(const CarriageGate& g) {
    if (g.off()) return true;
    return g.n_ref > 0 && g.f_ref_sat_vb > 0 && g.vb_ref > 0 &&
           g.beta_ppm <= CARRIAGE_BETA_PPM_MAX;
}

// XMR: permanently OFF (see header). Any XMR lane carrying beta != 0 is invalid.
inline constexpr bool XMR_CARRIAGE_PERMANENTLY_OFF = true;
inline CarriageGate carriage_gate_xmr() { return CarriageGate{}; }
inline bool validate_for_xmr(const CarriageGate& g) { return g.beta_ppm == 0; }

// cap(class) = floor((class_bytes - overhead_min) / vb_ref); 0 when the fixed
// overhead eats the whole class. lane_kmax follows rb_cb_class (0 = unbounded,
// so class 5 under an unbounded lane has an effectively infinite cap that n_ref
// saturates).
inline u64 carriage_cap(const CarriageGate& g, rb::CbClass c, u64 lane_kmax) {
    if (g.vb_ref == 0) return 0;
    const u64 cb = rb::class_bytes(c, lane_kmax);
    if (cb <= g.overhead_min) return 0;
    return (cb - g.overhead_min) / g.vb_ref;
}

// F_incl = cb_total_out - subsidy. nullopt => the receipt claims a coinbase
// total below the subsidy: REJECT (never clamp to 0).
inline std::optional<u64> fees_included(u64 cb_total_out, u64 subsidy) {
    if (cb_total_out < subsidy) return std::nullopt;
    return cb_total_out - subsidy;
}

// n_fee = n_floor + floor(F_incl / (f_ref * vb_ref)), saturating.
inline u64 carriage_n_fee(const CarriageGate& g, u64 f_incl) {
    const u128 unit = u128(g.f_ref_sat_vb) * g.vb_ref;
    if (unit == 0) return g.n_floor;
    return sat_u64(u128(g.n_floor) + u128(f_incl) / unit);
}

// n_b = min(cap(class), Q_fin, n_fee, n_ref).
inline u64 carriage_n_b(const CarriageGate& g, rb::CbClass c, u64 q_fin, u64 f_incl, u64 lane_kmax) {
    u64 n = carriage_cap(g, c, lane_kmax);
    n = std::min(n, q_fin);
    n = std::min(n, carriage_n_fee(g, f_incl));
    n = std::min<u64>(n, g.n_ref);
    return n;
}

// w' = w + floor(w * beta_ppm * n_b / (10^6 * n_ref)), saturating at u64 max.
// beta_ppm == 0 or n_b == 0 => w exactly.
inline u64 carriage_bonus_weight(const CarriageGate& g, u64 w, u64 n_b) {
    if (g.beta_ppm == 0 || g.n_ref == 0 || n_b == 0) return w;
    const u64 nb = std::min<u64>(n_b, g.n_ref);
    const u128 bonus = (u128(w) * g.beta_ppm * nb) / (u128(PPM) * g.n_ref);
    return sat_u64(u128(w) + bonus);
}

enum class CarriageVerdict : std::uint8_t {
    OK = 0,
    REJECT_CLASS_BYTE = 1,          // committed class byte > 5
    REJECT_CB_TOTAL_BELOW_SUBSIDY = 2,
    REJECT_PARAMS = 3,              // lane parameter set fails validate()
};

// The receipt-carried / ledger-derived facts one share is weighed with. There
// is deliberately NO n_out field: the number of outputs the coinbase actually
// emitted is not an input of the bonus (anti-displacement property).
struct CarriageFacts {
    std::uint8_t cb_class_byte = 0;   // receipt-carried, PoW-bound (S3 seam)
    u64 cb_total_out = 0;             // receipt-carried, PoW-bound (S3 seam)
    u64 subsidy = 0;                  // subsidy(height): deterministic per coin
    u64 q_fin = 0;                    // FINALIZED eligible-queue length at the cut
};

struct CarriageResult {
    CarriageVerdict verdict = CarriageVerdict::OK;
    u64 w_prime = 0;
    u64 n_b = 0;
    u64 cap = 0;
    u64 n_fee = 0;
    u64 f_incl = 0;
};

// Weigh one share. Gate OFF / not yet active => w' == w and NOTHING is read
// (so an OFF lane never rejects on facts it does not carry yet).
inline CarriageResult carriage_apply(const CarriageGate& g, u64 w, const CarriageFacts& f,
                                     u64 lane_kmax, u64 pos) {
    CarriageResult r;
    r.w_prime = w;
    if (!g.active_at(pos)) return r;
    if (!validate(g)) { r.verdict = CarriageVerdict::REJECT_PARAMS; return r; }
    const auto c = rb::decode_cb_class(f.cb_class_byte);
    if (!c) { r.verdict = CarriageVerdict::REJECT_CLASS_BYTE; return r; }
    const auto fi = fees_included(f.cb_total_out, f.subsidy);
    if (!fi) { r.verdict = CarriageVerdict::REJECT_CB_TOTAL_BELOW_SUBSIDY; return r; }
    r.f_incl = *fi;
    r.cap = carriage_cap(g, *c, lane_kmax);
    r.n_fee = carriage_n_fee(g, r.f_incl);
    r.n_b = carriage_n_b(g, *c, f.q_fin, r.f_incl, lane_kmax);
    r.w_prime = carriage_bonus_weight(g, w, r.n_b);
    return r;
}

// Reference zero-sum PPLNS normaliser (KAT use; canon keeps its own):
// pay_i = floor(R * w_i / sum w); residual = R - sum pay_i (-> donation).
// R * w_i < 2^128 always (u64 x u64); sum w accumulates in u128.
struct WindowSplit {
    std::vector<u64> pay;
    u64 residual = 0;
};
inline WindowSplit window_split(u64 R, const std::vector<u64>& w) {
    WindowSplit s;
    s.pay.assign(w.size(), 0);
    u128 tot = 0;
    for (u64 x : w) tot += x;
    if (tot == 0) { s.residual = R; return s; }
    u64 paid = 0;
    for (std::size_t i = 0; i < w.size(); ++i) {
        s.pay[i] = static_cast<u64>((u128(R) * w[i]) / tot);
        paid += s.pay[i];
    }
    s.residual = R - paid;
    return s;
}

// ═════════════════════════════════════════════════════════════════════════
// (2) FeeFloorGate
// ═════════════════════════════════════════════════════════════════════════

struct FeeFloorGate {
    std::uint32_t m = 0;              // 0 => OFF (default)
    u64 activation_pos = U64_MAX;

    bool off() const { return m == 0; }
    bool active_at(u64 pos) const { return !off() && pos >= activation_pos; }
    bool operator==(const FeeFloorGate&) const = default;

    static FeeFloorGate on(std::uint32_t m_, u64 activation) { return FeeFloorGate{m_, activation}; }
};

inline bool validate(const FeeFloorGate& g) { return g.off() || g.m >= FEE_FLOOR_M_MIN; }

// Block-intrinsic inputs of the dynamic floor (all known before emission).
struct FeeFloorFacts {
    u64 f_incl = 0;          // coinbase total - subsidy(height)
    u64 block_limit = 0;     // L, in the lane's size unit (vB for BTC)
    u64 cb_fixed = 0;        // coinbase fixed (non-payout) bytes
};

inline u64 fee_floor_denominator(const FeeFloorFacts& f) {
    return f.block_limit > f.cb_fixed ? f.block_limit - f.cb_fixed : 1;
}

// From the S2 BlockFacts (rb_cb_class.hpp) + the coinbase total. nullopt when
// the coinbase total is below the subsidy (block invalid anyway).
inline std::optional<FeeFloorFacts> fee_floor_facts_from_block(const rb::BlockFacts& b,
                                                               u64 cb_total_out, u64 subsidy) {
    const auto fi = fees_included(cb_total_out, subsidy);
    if (!fi) return std::nullopt;
    return FeeFloorFacts{*fi, b.block_limit_bytes, b.coinbase_fixed_overhead};
}

// The static floor: k_floor * vb. Equals w5 h_min(kind, k_floor) for vb =
// output_vb(kind). Saturating (never wraps to a small floor).
inline u64 h_min_static_vb(u64 vb, u64 k_floor) { return sat_u64(u128(k_floor) * vb); }

// h_min_dyn for an explicit per-output size (XMR entry point).
inline constexpr u64 VB_MAX = 0xFFFF'FFFFull;   // u128 headroom: m (<2^32) * F (<2^64) * vb (<2^32)

inline u64 h_min_dyn_vb(const FeeFloorGate& g, u64 vb, u64 k_floor, const FeeFloorFacts& f, u64 pos) {
    const u64 stat = h_min_static_vb(vb, k_floor);
    if (!g.active_at(pos)) return stat;
    if (vb > VB_MAX) return U64_MAX;                     // nonsense output size: never emits
    const u128 d = fee_floor_denominator(f);
    const u128 num = u128(g.m) * f.f_incl * vb;          // < 2^128 (VB_MAX guard)
    const u64 dyn = sat_u64((num + d - 1) / d);          // CEIL: exact displacement bound
    return std::max(stat, dyn);
}

inline u64 h_min_dyn(const FeeFloorGate& g, ScriptKind k, u64 k_floor, const FeeFloorFacts& f, u64 pos) {
    return h_min_dyn_vb(g, output_vb(k), k_floor, f, pos);
}

// Emission predicate: emit iff amount >= h_min_dyn, else CARRY.
inline bool fee_floor_emits(u64 amount, u64 h) { return amount >= h; }

// Drop-in HminOf for OwedLedger::propose_coinbase (w4_settlement.hpp): the
// SAME skip-and-carry loop, only the floor changes. Gate OFF => identical to
// w5 assemble()'s h_min_of lambda.
struct FeeFloorHmin {
    FeeFloorGate gate;
    u64 k_floor = 0;
    FeeFloorFacts facts;
    u64 pos = 0;
    u64 operator()(ScriptKind k) const { return h_min_dyn(gate, k, k_floor, facts, pos); }
};

// Displacement-bound check over a set of emitted outputs:
//   m * F_incl * sum(vb) <= D * sum(amount)   (<=> displacement <= sum(a)/m <= R/m)
inline bool displacement_within_bound(const FeeFloorGate& g, const FeeFloorFacts& f,
                                      u64 sum_vb, u64 sum_amount) {
    if (sum_vb > VB_MAX) return false;                   // > 4 GB of outputs: not a block
    const u128 lhs = u128(g.m) * f.f_incl * sum_vb;
    const u128 rhs = u128(fee_floor_denominator(f)) * sum_amount;
    return lhs <= rhs;
}

// ═════════════════════════════════════════════════════════════════════════
// (3) Lane-tag fold material (consumed at the wiring seam, not here)
// ═════════════════════════════════════════════════════════════════════════
// A lane running a gate ON must fold its parameters into the lane identity so
// a mixed fleet fails as an explicit REJECT_ROUNDABOUT(TAG_MISMATCH), never a
// silent owed_digest fork. OFF gates are NOT folded, so an OFF lane's tag is
// byte-identical to master.
inline constexpr const char* TAG_CARRIAGE  = "V37PCG";
inline constexpr const char* TAG_FEE_FLOOR = "V37PFF";

inline std::vector<std::uint8_t> carriage_params_leaf(const CarriageGate& g) {
    std::vector<std::uint8_t> b;
    rb::put_tag(b, TAG_CARRIAGE);
    rb::put_u32(b, g.beta_ppm);
    rb::put_u16(b, g.n_ref);
    rb::put_u16(b, g.n_floor);
    rb::put_u32(b, g.f_ref_sat_vb);
    rb::put_u8(b, g.vb_ref);
    rb::put_u16(b, g.overhead_min);
    rb::put_u64(b, g.activation_pos);
    return b;
}
inline std::vector<std::uint8_t> fee_floor_params_leaf(const FeeFloorGate& g) {
    std::vector<std::uint8_t> b;
    rb::put_tag(b, TAG_FEE_FLOOR);
    rb::put_u32(b, g.m);
    rb::put_u64(b, g.activation_pos);
    return b;
}
inline bool fold_required(const CarriageGate& g) { return !g.off(); }
inline bool fold_required(const FeeFloorGate& g) { return !g.off(); }
inline bytes32 params_digest(const CarriageGate& g) { return rb::hash_bytes(carriage_params_leaf(g)); }
inline bytes32 params_digest(const FeeFloorGate& g) { return rb::hash_bytes(fee_floor_params_leaf(g)); }

// ═════════════════════════════════════════════════════════════════════════
// WIRING SEAM (not done here — consensus canon; the classifier-gated hand-off)
// ═════════════════════════════════════════════════════════════════════════
//  S-C1 LaneParams (src/sharechain/v37/v37_lane.hpp ~380-440): ADD-ONLY
//       `CarriageGate carriage{}; FeeFloorGate fee_floor{};` beside
//       Subthreshold/Mrr/Win/Nr; defaults OFF => every golden unchanged.
//  S-C2 Lane tag: in rb_lane_tag.hpp LaneTagContext::of(), when
//       fold_required(gate), fold params_digest(gate) into the geometry
//       digest (or a new tag field); OFF => no fold => tag byte-identical.
//  S-C3 Admission (w2_admission.hpp EmittedPush::w_raw): w_raw :=
//       carriage_apply(gate, w_raw, facts, lane_kmax, pos).w_prime BEFORE the
//       c2pool#1710 give-author split; a non-OK verdict rejects the receipt.
//       facts.cb_class_byte + cb_total_out come from the receipt wire bump
//       (c2pool#1710 S3 seam: cb_class u8 + cb_total_out u64, PoW-bound);
//       facts.q_fin MUST be counted over the FINALIZED partition at the
//       receipt's cut (R-A law) — never EffectiveOwed over pending.
//  S-C4 Emission: in w5_coinbase.hpp assemble() replace
//       `h_min_of = [&](ScriptKind k){ return h_min(k, budget.k_floor); }`
//       with `FeeFloorHmin{gate, lane.k_floor, facts, pos}`, and use the SAME
//       functor in the canonical rebuild (BTC RECON verify-vs-on-chain, XMR
//       xmr_settlement_coinbase_shape.hpp) with facts from the block being
//       validated. owed_digest changes once ON => position gate + tag fold
//       (S-C2) mandatory.
//  S-C5 XMR: carriage stays OFF (validate_for_xmr); fee floor via
//       h_min_dyn_vb with the miner_tx per-output byte size.
//  ORDER: the k_floor -> LaneParams hotfix (v37/kfloor-laneparam) lands
//       first; S-C4 reads lane.k_floor, never node config.

}  // namespace c2pool::v37n::payout::carriage
