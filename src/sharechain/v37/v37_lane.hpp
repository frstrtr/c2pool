#pragma once
// V37 MRR roundabout — one sharechain lane.
// Spec: docs/c2pool-v37-mrr-roundabout-buffer.md §3 (data model), §4.1
// (roll-up pyramid), §4.2 (epoch-scaled incremental decay + OQ-2 exact
// rebuild), §6.1 (quantized window, OQ-1), §6.2 (reorg journal, OQ-7).
//
// CONSENSUS-DETERMINISM (§8.3): the operation order inside push() is fixed —
//   (1) epoch rebuild when next_pos - B == E,
//   (2) L0 fold when L0 is full,
//   (3) level-k fold cascade when a level ring is full,
//   (4) insert,
//   (5) whole-bucket eviction while cover > W.
// All folds/evicts/rebuilds happen at positionally defined points; no input
// to the sequence is node-local.

#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include "v37_fixed.hpp"
#include "v37_hash.hpp"
#include "nr_ladder.hpp"       // S12: the native ridge's shared rules /
                               // record types AND the ND-R6 table + LaneKind

namespace v37 {

using MinerId = std::uint32_t;

// RDWR-OQ2 sub-threshold estimator gate (the "raindrops -> bucket" DROPS half).
// A self-contained POD carried in LaneParams so W4 (the consumer-tree settlement
// fold, src/c2pool/v37/w4_settlement.hpp) can read the gate WITHOUT this pure
// consensus header ever taking a consumer-tree include: the header stays
// header-only, stdlib-only. W4 translates this POD into the merged estimator
// module's c2pool::v37::subthreshold::SubthresholdParams at its own seam.
//
// ★★ DIGEST-NEUTRAL BY CONSTRUCTION (the PRIME invariant for the lane digest):
// build_leaves() hashes the geometry by APPENDING each field explicitly
// (window, c0, rollup, half_life, level_caps.size(), level_caps[...]) into the
// "V37H" header leaf — it never serializes the whole LaneParams struct — so
// ADDING this field appends nothing to any leaf and changes NO lane digest, on
// any schedule. This is exactly the L0F_RECEIPT annotation-bit argument (§6):
// a consensus-header addition that is digest-neutral by construction. DEFAULT
// OFF (enabled == false) => W4's seam credits nothing, so the owed_digest, the
// add-only receipt/share carrier, and the lane digest are byte-identical to
// master. Turning it ON is the RDWR-OQ2 consensus activation (owed_digest
// changes because credited amounts change); `version` names the V37.x consensus
// version that the activation ships under.
struct SubthresholdGate {
    bool enabled = false;        // ★ DEFAULT OFF (RDWR-OQ2; flip = consensus change)
    std::uint32_t K = 4;         // K-best near-misses; estimator enforces K >= 3
    std::uint32_t mode = 0;      // 0 = EstimateOnly (S==0 only), 1 = Combined (sybil-neutral)
    std::uint32_t version = 0;   // consensus version marker: 0 = base; 1 = V37.1 estimator-on

    // ── CANONICAL version → gate map (the ADD-ONLY consensus version marker).
    // for_version() is the SINGLE SOURCE OF TRUTH translating a V37.x consensus
    // version into its gate configuration, so the (version, enabled, mode) triple
    // can never drift out of agreement when built through the LaneParams factories
    // below:
    //   version 0  → V37.0 base: gate OFF. Byte-identical to master on every
    //                schedule (owed_digest, add-only receipt/share carrier, lane
    //                digest) — the bare {} default equals this, so all pre-existing
    //                goldens stay valid for replay/audit.
    //   version 1  → V37.1 activation: gate ON, the RDWR-OQ2 sub-threshold
    //                estimator LIVE under the E-2-corrected sybil-neutral COMBINED
    //                rule  Hhat_comb = (S + K - 1) * D'_K  (measures <= 1.00, no
    //                sybil profit; a 2000-identity split collects <= ~1.0x). The
    //                broken clamp  max(S*T, Hhat)  (double-counts, sybil-profits
    //                ~1.98x) is NEVER selected — it exists only as the
    //                v37_subthreshold_estimator.hpp NEVER_CONSENSUS witness. K = 4
    //                (the module enforces K >= 3).
    // An unrecognised future version keeps the OFF default (fail-safe: it credits
    // nothing rather than guessing a rule).
    static SubthresholdGate for_version(std::uint32_t v) {
        SubthresholdGate g{};              // v == 0 (or unknown): V37.0 base, OFF
        if (v == 1) {                      // V37.1: RDWR-OQ2 consensus activation
            g.enabled = true;
            g.K       = 4;
            g.mode    = 1;                 // Combined => Hhat_comb = (S + K - 1) * D'_K
            g.version = 1;
        }
        return g;
    }
};

// MRR retrofit position gate (V37.1 lane retrofit, seam S1).
// activation_pos = UINT64_MAX (default) => the retrofit never activates and
// the lane is byte-for-byte the pre-retrofit v37::Lane (KAT-0 pins this).
// activation_pos is the consensus activation position: from the share at
// that position onward the lane runs the evict-to-carry rule (see
// evict_oldest_bucket / m_carry below).
struct MrrGate {
    std::uint64_t activation_pos = UINT64_MAX;   // DEFAULT OFF (never activates)
    // I-3 (CKPT-OQ1): committed checkpoints retained in the lane's ring.
    // Ruled minimum 2 (the constructor refuses less). NOT digested: the
    // retention depth bounds the rebuildable reorg depth, it is not
    // consensus state — two nodes with different retention agree on every
    // digest and differ only in which forks they can still serve.
    std::uint64_t ckpt_retain = 2;
};

// SCOPE NOTE (the V37.1 cut). This retrofit carries the MRR carry ledger,
// the permanence peaks, the committed checkpoints and the version-agnostic
// work atom — and NOTHING that re-shapes the decay geometry. The half-life
// band overlay and the scheduled window / half-life retarget that an earlier
// draft of this header carried are RETIRED BEFORE FIRST USE: the native
// decay geometry replaces the overlay, and the time-denominated width law
// replaces the retarget schedule. Consequently there is exactly ONE position
// gate in this header (MrrGate above); no geometry gate and no retarget
// schedule exist, and the ACTIVE geometry is always params() — window and
// half_life never move over the life of a lane built from this header.

// ── V37.1 TIME-DENOMINATED, VARIABLE-LENGTH WINDOW (seams S6-S7) ──────────
// PURPLE-PAPER §3 (the clock is the buried mainchain height, "a fixed distance
// behind the present ... the same for every node"), §4 (bins; "weight falls
// with the age of its own bin"; "late work decays exactly as if it had never
// been late"), §6 (the width law: the window is "denominated in time ...
// widens as the pool's share of the network's work falls ... its width is set
// only from the underlying chain's own difficulty and the pool's demonstrated
// work"), §12 (levels).
//
// The parent chain a lane rides (LaneKind) is declared in nr_ladder.hpp
// beside the ND-R6 dimension table it selects. S12 moved it there so the
// native ridge's constants and the S4 width law's constants are ONE table
// read through ONE call, nr::for_version(1, lane), and cannot drift apart.

// The time-window gate — the second stacked position gate beside MrrGate.
// activation_pos == UINT64_MAX (the default in every factory in this header)
// => the overlay never activates, no window state is ever live, and the "WIN1"
// header sub-block is never appended, so the lane is byte-for-byte the
// pre-window lane (KAT-0 pins this). DIGEST-NEUTRAL WHEN OFF by exactly the
// construction SubthresholdGate and MrrGate use: build_leaves() appends "WIN1"
// only under win_active() and never serializes this struct.
//
// GATE CO-LOCATION (ruling M). The V37.1 activation is ONE position shared by
// the estimator, the MRR retrofit and the window: a FINITE win_activation_pos
// must EQUAL mrr.activation_pos, and the constructor refuses anything else, so
// there is one atomic flip and one gate-ON owed_digest golden rather than N
// "safe-additive" flips that two nodes could disagree about. Declaring
// win_version 1 with the width constants is NOT the flip — the flip is the
// finite position, and it is the operator's separate, explicitly ruled step.
struct WinGate {
    std::uint64_t win_activation_pos = UINT64_MAX;  // DEFAULT OFF (never activates)
    std::uint32_t win_version = 0;   // 0 = positional window; 1 = time-denominated
    // ── the width-law constants. Read ONLY when win_version == 1; every one
    // is a consensus constant, never runtime config.
    std::uint64_t coverage_blocks = 0;   // C: expected pool block-finds kept in view
    std::uint64_t bin_seconds = 0;       // ruling A: parent target spacing (see note)
    std::uint64_t w_min_bins = 0;        // W_MIN
    std::uint64_t w_default_bins = 0;    // W_default: bootstrap + degenerate fail-safe
    std::uint64_t w_max_bins = 0;        // W_MAX
    std::uint64_t retarget_bins = 0;     // R: the whole-bucket width step (ruling F)
    std::uint64_t damp_factor = 0;       // ruling F: one retarget moves W by <= xF / divF
    std::uint64_t burial_depth = 0;      // ruling L: N (== journal_depth)
    // ND-R6 rules a per-lane LAMBDA beside the width table. NO branch in this
    // header reads it and it is never serialized: it is recorded here so the
    // ruled table has ONE source of truth in the consensus header, and the
    // native-decay seam consumes it. REQUIRED-OPERATOR-RULING (WIN-R3):
    // confirm this placement or move LAMBDA onto the native-decay gate.
    std::uint64_t lambda_levels = 0;
};

// Ruling D: the exogenous, committed parent-chain difficulty. The width law
// reads it ONCE per retarget, at the epoch-base bin. It is INJECTED and never
// derived from lane state, which is what makes the width uninflatable
// (PURPLE-PAPER §6, "quantities no participant can inflate"). A null pointer
// reads zero difficulty, which routes the law to its W_default fail-safe: it
// never divides by zero and never guesses a value.
struct IMainchainDifficulty {
    virtual ~IMainchainDifficulty() = default;
    virtual U256 difficulty_at_bin(u64 bin) const = 0;
};

// ── the width law (PURPLE-PAPER §6 / temporal-levels §5a), integer-only ──────
// A pure function of committed state: nothing here reads lane or global state,
// so it is trivially identical on every node. Proven standalone in the proto
// shadow (KAT-TW, 10372/0; the integer matrix golden 9253fa42...c1ab8f).
namespace winlaw {

// The fold-group / width step R. The constructor refuses a retarget step that
// is not the lane's own roll-up factor, so the two can never drift apart.
inline constexpr u64 R_BINS = 8;
// Ruling F: one retarget moves W by at most a factor of 4 either way.
inline constexpr u64 DAMP_FACTOR = 4;
// Ruling B / ND-R8: half-life 2160 and epoch 4096 are kept and RELABELLED as
// bins. The ratified decay table (golden d659c801) is reused BIT-IDENTICAL:
// the table takes the (half_life, epoch_len) PAIR only and the unit of the
// index is not a table input. Proven, not asserted, by the proto KAT-TW7
// (element-wise equality plus the full-array SHA against the canon pin).
inline constexpr u64 HALF_LIFE_BINS = 2160;
// ND-R4 / ND-R6: the ceiling W_MAX may not exceed. DOGE's W_MAX was ruled down
// from 11520 to 8640 to sit inside it with margin.
inline constexpr u64 LADDER_DOMAIN_BINS = 12288;

// The ND-R6 per-lane width table, RULED 2026-09-10.
//
// S12 INTEGRATION — ONE SOURCE OF TRUTH. The numbers are NOT written here.
// They are read from nr::for_version(1, lane) (nr_ladder.hpp), which is the
// single source of truth for the whole ruled dimension set — the width bounds
// the law below clamps to, the LAMBDA / H_open the cell ladder folds on, and
// the retarget / checkpoint cadences. The width law and the native ridge
// therefore cannot be fed two different tables: there is only one.
//
//   lane  bin_s  W_MIN  W_default        W_MAX          LAMBDA  H_open  R_b  ckpt
//   BTC   600    80     144  (24.0 h)    1152 ( 8.0 d)  1       16      8    64
//   LTC   150    528    576  (24.0 h)    4608 ( 8.0 d)  2       16      8    64
//   DASH  150    528    576  (24.0 h)    4608 ( 8.0 d)  2       16      8    64
//   DOGE   60    528    1440 (24.0 h)    8640 ( 6.0 d)  2       16      8    64
//
// nr::for_version() runs nr::check_dims() on the row it returns, so a table
// that could not carry the cell ladder cannot reach the width law either.
struct LaneTable {
    u64 bin_seconds;      // ruling A: one bin == one buried parent block
    u64 w_min_bins;
    u64 w_default_bins;   // ~24 h at the lane's bin spacing
    u64 w_max_bins;
    u64 lambda_levels;    // ND-R6 LAMBDA == nr::RidgeDim::fold_cap
};
inline LaneTable ruled(LaneKind k) {
    const nr::RidgeDim d = nr::for_version(1, k);
    return LaneTable{d.bin_seconds, d.w_min_bins, d.w_default_bins,
                     d.w_max_bins, d.fold_cap};
}

// version -> window gate. v == 1 folds the ruled table and DECLARES
// win_version 1; the activation POSITION stays at its OFF default, so a lane
// built here is byte-for-byte the pre-window lane until the operator bakes a
// finite position (the P-1-class flip).
//
// ⚠ coverage_blocks is the ONE number ND-R6 left OWED (it is economic policy —
// "how many expected block-finds the window keeps in view" — with no derivable
// value). It is pinned to W_default here exactly as the proto pins it so the
// mechanism runs; it is NOT a ruling, and the gate-ON golden must not be
// minted over it. REQUIRED-OPERATOR-RULING (WIN-R5). retarget_bins (= R) is
// likewise the proto cadence value and is OWED inside ND-R6.
inline WinGate for_version(std::uint32_t v, LaneKind lane) {
    WinGate g{};
    if (v != 1) return g;                 // v == 0 / unknown: OFF, byte-identical
    const LaneTable& t = ruled(lane);
    g.win_version     = 1;
    g.bin_seconds     = t.bin_seconds;
    g.w_min_bins      = t.w_min_bins;
    g.w_default_bins  = t.w_default_bins;
    g.w_max_bins      = t.w_max_bins;
    g.lambda_levels   = t.lambda_levels;
    g.retarget_bins   = R_BINS;
    g.damp_factor     = DAMP_FACTOR;
    g.coverage_blocks = t.w_default_bins;   // [OWED — WIN-R5]
    return g;                               // burial_depth: filled from journal_depth
}

inline u64 clamp_u64(u64 x, u64 lo, u64 hi) {
    return x < lo ? lo : (x > hi ? hi : x);
}
// Floor toward zero to a multiple of R (ruling F). R == 0 is the identity, so
// this is never a divide-by-zero.
inline u64 floor_to_R(u64 w, u64 R) { return R == 0 ? w : (w / R) * R; }
// Ratio-bounded damping (ruling F): one retarget moves W by at most a factor
// of f. Integer, truncating, saturating upward. f <= 1 leaves no room to move.
inline u64 damp_ratio(u64 w_old, u64 w_target, u64 f) {
    if (f <= 1) return w_old;
    const u64 hi = (w_old > UINT64_MAX / f) ? UINT64_MAX : w_old * f;
    const u64 lo = w_old / f;
    return w_target < lo ? lo : (w_target > hi ? hi : w_target);
}
// Is w a whole multiple of R? The constructor asserts this of W_MIN / W_MAX /
// W_default: under the ND-R14 trailing floor it is what keeps the CLAMP intact
// (an R-unaligned W_MIN would be floored below itself, 145 -> 144).
inline bool w_is_r_aligned(u64 w, u64 R) { return R == 0 || (w % R) == 0; }

// THE width law. Returns the new W in bins.
//
//   W_target = coverage_blocks * D_net@base * W_cur / raw_total_prev_epoch
//
// derivation (PURPLE-PAPER §6, specialized by ruling A so the factor
// network_block_time / bin_seconds is exactly 1 and cancels):
//   pool_work_rate              = raw_total_prev_epoch / W_cur   (ruling E lag)
//   expected_time_to_pool_block = network_block_time * D_net / pool_work_rate
//   W_target (bins)             = coverage_blocks * expected_time / bin_seconds
// then, in FIXED ORDER (ND-R14, RULED 2026-09-10):
//   ratio-damp xF/divF  ->  clamp [W_MIN, W_MAX]  ->  FLOOR TO R **LAST**.
//
// ND-R14 — why the floor is last. The earlier order (floor -> damp -> clamp)
// could return an off-lattice W, because the damper's lower bound w_old / f is
// an integer division that does not preserve R-alignment (152 -> 38) and the
// clamp cannot put it back on the lattice; 39 widths over 249 measured period
// boundaries were off it. Flooring last closes that unconditionally and does
// not weaken the clamp, because the bounds are R-aligned by constructor guard.
// It IS a consensus formula change: any gate-ON golden minted under the old
// order must be re-minted.
//
// Ruling E (the one-epoch lag) and the W_old cancellation: raw_total_prev_epoch
// is the raw work committed over the PRIOR full window of width W_cur, so under
// a constant hashrate it is proportional to W_cur and the explicit W_cur factor
// cancels — W converges to coverage_blocks * D_net / rate, a fixed point
// independent of W_cur. That cancellation is why the retarget is stable rather
// than oscillating.
//
// Degenerate (ruling F): raw_total_prev_epoch == 0 or W_cur == 0 (bootstrap, no
// demonstrated work) => W_default, deterministically, with no division.
inline u64 retarget_width(const U256& d_net_at_base, u64 w_cur_bins,
                          u128 raw_total_prev_epoch, const WinGate& w) {
    if (raw_total_prev_epoch == 0 || w_cur_bins == 0)
        return floor_to_R(clamp_u64(w.w_default_bins, w.w_min_bins, w.w_max_bins),
                          w.retarget_bins);
    const U256 num = d_net_at_base.mul_small(w.coverage_blocks).mul_small(w_cur_bins);
    u64 w_target = num.div_u128_to_u64(raw_total_prev_epoch);   // truncate toward zero
    w_target = damp_ratio(w_cur_bins, w_target, w.damp_factor); // ruling F
    w_target = clamp_u64(w_target, w.w_min_bins, w.w_max_bins); // ruling C
    return floor_to_R(w_target, w.retarget_bins);               // ND-R14: LAST
}

} // namespace winlaw

// The consensus version the node SHIPS as its default lane configuration. V37.1
// turns the RDWR-OQ2 sub-threshold estimator ON under the sybil-neutral Combined
// rule; the earlier versions stay selectable byte-for-byte via
// LaneParams::for_version()/v37_0() for replay and audit. Bumping this constant
// is the consensus-activation lever. (No live v37 lane is instantiated yet, so
// shipping V37.1 forks no running lane — it declares the default the node adopts.)
constexpr std::uint32_t SHIPPED_CONSENSUS_VERSION = 1;   // V37.1

// NATIVE RIDGE gate (v37, S12 + the S12-R sealed-cell/reorg redesign).
// Consensus constants, not runtime config. nr_version == 1 with a finite,
// epoch-aligned nr_activation_pos >= mrr.activation_pos switches the lane,
// from the share AFTER that position on, from the positional table path to
// the native cell ladder (nr_ladder.hpp / Lane::nr_*): decay AS the level
// geometry (paper §4 through §12), the OPEN HORIZON H_open (mechanism A: a
// receipt credits only an open bin; sealed(origin) is Expired-sealed, paper
// §15), the IMMUTABLE SEAL RECORD + CARRIED SPLIT (mechanism B), and the
// journaled reorg undo (Op::Nr*). RULED: ND-R3 (ruling G re-ruled — c0/E are
// no longer consensus dimensions; the ladder REPLACES the positional pyramid),
// ND-R9 (S12 joins the ONE atomic V37.1 flip; the S11 ridge overlay and the
// S3 bin-band pyramid are RETIRED — the S11 overlay is already absent from
// this cut, and the constructor refuses a finite WINDOW gate beside
// nr_version 1), ND-R8 (half_life 2160 BINS, d659c801 reused).
// DEFAULT OFF (nr_version 0, UINT64_MAX) => byte-identical to the p1+p2
// lane and, with every gate OFF, to canon (KAT-0 2479d5b6...fda4fd). DIGEST-
// NEUTRAL WHEN OFF by the same construction as every gate above: build_leaves
// appends the "NRG1" sub-block and the NRC1/NRX1 leaves only under
// nr_active(); the ON path is on the REAL push/read/rewind/digest paths and
// is guarded, not absent — the gate-OFF identity is non-vacuous.
struct NrGate {
    std::uint64_t nr_activation_pos = UINT64_MAX;   // DEFAULT OFF; epoch-aligned, >= mrr.activation_pos
    std::uint32_t nr_version = 0;                   // 0 = shipped table path; 1 = native ridge
    std::uint64_t fold_cap = 0;                     // LAMBDA, max in-window cell level     [ND-R2]
    std::uint64_t open_horizon_bins = 0;            // H_open (mechanism A); N_CTX < H < W_MIN [ND-R6]
    std::uint64_t w_min_bins = 0;                   // the FLAG-1 replacement width bounds  [ND-R6]
    std::uint64_t w_max_bins = 0;
    std::uint64_t w_default_bins = 0;
    // ── S14 (assembly): the width law and the checkpoint cadence are NATIVE
    // to this gate. ND-R9 rules ONE atomic V37.1 flip "with window": under
    // nr_version == 1 the window IS the native ridge's window — m_W_bins,
    // driven by the S4 law (winlaw::retarget_width, unchanged and already
    // ND-R14-ordered) on the NR bin clock at retarget_bins cadence. The S3
    // bin-band pyramid (WinGate) is RETIRED (ND-R9), so its gate stays OFF
    // and the law reads its constants from HERE rather than from a gate that
    // never fires. Every field below is an operator-baked constant [ND-R6],
    // and every one of them is the value nr::for_version(1, lane) returns —
    // the SAME call winlaw::ruled() reads, so the two can never disagree.
    // REQUIRED-OPERATOR-RULING (NR-R1): the width-law constants are carried
    // on BOTH gates in this cut — here (digest-committed in NRG1, what the
    // NR law reads) and, unread and never serialized, on the RETIRED
    // WinGate. Deleting the WinGate copies is a p2 FORMAT change and is not
    // self-picked; SPEC v4's integrated form is the NrGate one, realized here.
    std::uint64_t coverage_blocks = 0;   // C: buried parent blocks the window covers (ruling C)
    std::uint64_t bin_seconds = 0;       // parent spacing; traceability (ruling A cancels it)
    std::uint64_t retarget_bins = 0;     // the width law's whole-R period (ruling F)
    std::uint64_t ckpt_bins = 0;         // I-3 checkpoint cadence on the bin clock
    std::uint64_t n_ctx_bins = 0;        // mirror of W2_N_CTX (0 == the shipped 2)
    bool allow_digit_repeat = false;                // ND-R4 closure; default = strict golden subset
};

struct LaneParams {
    u64 window = 8640;          // W   (OQ-5 default)
    u64 c0 = 4096;              // C0, power of two; also E (epoch length)
    u64 rollup = 8;             // R
    std::vector<u64> level_caps = {568};  // slot counts for levels >= 1
    u64 half_life = 2160;       // W/4 (OQ-5)
    u64 journal_depth = 64;     // D   (OQ-7)
    // ADD-ONLY, NOT part of the digested geometry (see SubthresholdGate above):
    // the RDWR-OQ2 estimator gate, default OFF => digest byte-identical to master.
    SubthresholdGate subthreshold{};
    // ADD-ONLY, same digest-neutral-by-construction argument: the MRR
    // retrofit gate, default OFF (UINT64_MAX) => byte-identical to canon.
    MrrGate mrr{};
    // ADD-ONLY, same digest-neutral-by-construction argument (S6-S7): the
    // time-denominated window gate, default OFF => byte-identical to the
    // pre-window lane on every schedule.
    WinGate win{};
    // ADD-ONLY, same digest-neutral-by-construction argument (S12): the
    // native-ridge gate, default OFF (nr_version 0, UINT64_MAX) =>
    // byte-identical to the p1+p2 lane on every schedule.
    NrGate nr{};

    u64 epoch_len() const { return c0; }
    std::size_t levels() const { return 1 + level_caps.size(); }

    // ── Named consensus versions (ADD-ONLY). The digested geometry is IDENTICAL
    // across every version — only the non-digested `subthreshold` gate differs —
    // so the lane digest is version-invariant and the bare {} default constructor
    // is retained as the V37.0 base (gate OFF): every pre-existing owed_digest /
    // lane-digest golden built from a default LaneParams stays byte-identical.
    // shipped() is the node's default lane configuration, currently V37.1 (gate
    // ON, Combined). v37_0()/v37_1() name the endpoints for KATs and audit replay.
    static LaneParams for_version(std::uint32_t v) {
        LaneParams p;
        p.subthreshold = SubthresholdGate::for_version(v);
        return p;
    }
    static LaneParams v37_0()   { return for_version(0); }  // pre-activation base
    static LaneParams v37_1()   { return for_version(1); }  // RDWR-OQ2 activation
    static LaneParams shipped() { return for_version(SHIPPED_CONSENSUS_VERSION); }

    // ── S6-S7: the window constants are PER-LANE (ruling A / ND-R6), so the
    // single source of truth needs the parent chain the lane rides. This
    // overload is that source: it folds the ruled ND-R6 table and declares
    // win_version 1, and it leaves win_activation_pos at UINT64_MAX exactly
    // as the 1-argument factories leave mrr.activation_pos there. Baking the
    // finite position is the P-1-class flip and is not done here.
    //
    // The 1-argument for_version(v) above is UNCHANGED: it names no parent
    // chain, so it may not name a bin unit either, and it therefore leaves the
    // window gate at its OFF default in every version.
    // REQUIRED-OPERATOR-RULING (WIN-R2): whether shipped() / for_version(v)
    // should name a default LaneKind, or whether every V37.1 lane must be
    // constructed through for_version(v, LaneKind). Nothing is self-picked.
    static LaneParams for_version(std::uint32_t v, LaneKind lane) {
        LaneParams p = for_version(v);
        p.win = winlaw::for_version(v, lane);
        if (p.win.win_version == 1)
            p.win.burial_depth = p.journal_depth;   // ruling L: N == D
        // ── S12 (ND-R6 RULED, ND-R9): the native-ridge dimension set, read
        // from nr::for_version(1, lane) — the SINGLE SOURCE OF TRUTH, the same
        // call winlaw::ruled() above reads. nr_version 1 is DECLARED and every
        // consensus constant is folded, but nr_activation_pos STAYS at
        // UINT64_MAX exactly as win_activation_pos and mrr.activation_pos do:
        // declaring the table is not the flip. The flip is the finite,
        // epoch-aligned position the operator bakes on mrr.activation_pos AND
        // nr.nr_activation_pos TOGETHER (ruling M / ND-R9 co-location, which
        // the constructor enforces), and it is a separate, explicitly ruled
        // step. Nothing here can move the gate-OFF lane digest.
        if (v == 1) {
            const nr::RidgeDim d = nr::for_version(1, lane);
            p.nr.nr_version        = 1;
            p.nr.fold_cap          = d.fold_cap;            // LAMBDA   [ND-R2]
            p.nr.open_horizon_bins = d.open_horizon_bins;   // H_open   [ND-R6]
            p.nr.w_min_bins        = d.w_min_bins;
            p.nr.w_max_bins        = d.w_max_bins;
            p.nr.w_default_bins    = d.w_default_bins;
            p.nr.bin_seconds       = d.bin_seconds;         // ruling A (cancels)
            p.nr.retarget_bins     = d.retarget_bins;       // OWED inside ND-R6
            p.nr.ckpt_bins         = d.ckpt_bins;           // OWED inside ND-R6
            p.nr.n_ctx_bins        = d.n_ctx_bins;          // mirror of W2_N_CTX
            // coverage_blocks is ECONOMIC POLICY with no derivable value: the
            // ONE number ND-R6 left OWED. Pinned to W_default exactly as the
            // proto pins it so the mechanism runs and the KATs execute; it is
            // NOT a ruling, it is digest-committed in NRG1, and the gate-ON
            // golden must not be minted over it. (Same footing as WIN-R5.)
            p.nr.coverage_blocks   = d.w_default_bins;      // [OWED — ND-R6]
            p.mrr.activation_pos   = 4096;   // V37.1 flip (R-5 = 4096, epoch 1)
            p.nr.nr_activation_pos = 4096;   // ND-R9 co-location; win stays OFF
        }
        return p;
    }
    static LaneParams v37_1(LaneKind lane) { return for_version(1, lane); }

    // ── Named consensus versions (ADD-ONLY), continued for the V37.1 lane
    // retrofit: the MRR gate below stays at its OFF default in EVERY version
    // produced here. Baking a finite mrr.activation_pos into for_version(1)
    // IS the P-1-class consensus activation and is a separate, explicitly
    // ruled step: until then shipped() == for_version(1) is byte-identical to
    // for_version(0) on the lane digest, and the retrofit machinery below is
    // unreachable.
};

// L0 slot flag bits. Annotation-only: flags are NOT digest leaves and never
// affect weights. Bit 0x08 mirrors V36 share_messages FLAG_PROTOCOL_AUTHORITY
// for operator familiarity: it marks shares whose message_data carried
// validated authority messages (V36 share_messages.hpp — envelope under the
// authority pubkeys, ECDSA-signed, ref_hash/PoW-protected; validation happens
// in share_check BEFORE push, payloads stay in the share store). Views join
// message payloads by `pos`; messages age out of visibility at fold, which
// matches their per-share nature (FLAG_PERSISTENT semantics: operator OQ).
constexpr std::uint32_t L0F_FEE_SHARE     = 0x01;
constexpr std::uint32_t L0F_STALE_DOA     = 0x02;
constexpr std::uint32_t L0F_RECEIPT       = 0x04;  // RDWR work-receipt credit
// (Track A2 / W2 — src/c2pool/v37/w2_admission.hpp). Annotation-only, exactly
// like every other L0F_* bit: NOT a digest leaf and never weight-bearing
// (build_leaves() below hashes geometry, B, next_pos, counts, L0/bucket sums,
// and acc — never `flags`), so ADDING this constant changes no golden, no
// weight, no digest. It marks an L0 slot whose weight credit came from an
// admitted RDWR receipt (a stale share re-presented within N_CTX) rather than
// a freshly-chained share; the lane treats it as an opaque pass-through set by
// the W2 admission emitter BEFORE push. CONSENSUS-SURFACE NOTE (W2-F-B): this
// one-line addition is digest-neutral by construction, but it touches the
// consensus header, so it lands under the integrator's digest-neutral tap
// (standing no-self-merge rule), not by W2's own hand. It does not block the
// W2 impl or its tests.
constexpr std::uint32_t L0F_AUTHORITY_MSG = 0x08;
constexpr std::uint32_t L0F_MINER_MSG     = 0x10;  // permissionless miner
// message present (c2pool-v37-miner-messages.md: plaintext envelope, sig
// bound to the payout identity, TTL funded by decayed_weight() — the lane
// is the budget ledger; the live-message index is view-layer, not here)

// L0F_RECEIPT must be the one free low bit (spec §6) and must collide with no
// already-assigned annotation.
static_assert(L0F_RECEIPT == 0x04,
              "W2 spec §6 pins the receipt bit to the one free low bit (0x04)");
static_assert((L0F_RECEIPT & (L0F_FEE_SHARE | L0F_STALE_DOA |
                              L0F_AUTHORITY_MSG | L0F_MINER_MSG)) == 0,
              "L0F_RECEIPT must occupy the free bit, colliding with no "
              "assigned L0F_* annotation bit");

// ── Version-agnostic work atom (v37, I-6 — MV-OQ1 ruled = A) ────────
// The operator's ruling: legacy v35 / v36 work is RE-SCORED under the single
// Q62 v37 rule, and a share's protocol version is LEAF PROVENANCE ONLY. The
// lane therefore carries a provenance tag on every atom so the permanent
// record preserves which protocol version produced the share, while the
// SCORING is a pure function of (w_raw, age) with no version input:
//     w_scaled = w_raw x InvD[pos - B]     (push, the one and only rule)
// and no fold / eviction / carry / rebuild path ever reads the tag.
// The WorkAtomCore is (w_raw, pos); the version is a label on it.
//
// DIGEST-NEUTRAL BY CONSTRUCTION for the pure-v37 case (the same argument as
// every other gate in this header): the tag defaults to PROV_V37, and the
// only serialization of provenance is the "V37V" sub-block, appended
//   (a) INSIDE the bucket's "V37B" leaf payload iff the bucket's provenance
//       mix is non-empty (non-v37 rows only; the v37 share is the implicit
//       remainder raw_work - sum(rows)). That payload is also the MMR
//       permanence leaf (bucket_leaf), so the version mix is permanent;
//   (b) at the END of the "V37H" header leaf iff any live L0 slot is
//       non-v37 (the L0 ring is otherwise committed only through its sums).
// No leaf is added and no leaf index moves; an all-v37 stream produces the
// canon bytes everywhere (KAT-0 unchanged; KAT-W pins the mixed case).
using ProtoVersion = std::uint16_t;
constexpr ProtoVersion PROV_V35 = 35;
constexpr ProtoVersion PROV_V36 = 36;
constexpr ProtoVersion PROV_V37 = 37;    // the DEFAULT: an unmarked atom is v37
// The closed set of admissible provenance tags: a share is produced by a
// protocol version that exists. push() refuses anything else BEFORE any
// state mutation (a consensus rule, like the zero-work refusal).
constexpr bool prov_admissible(ProtoVersion v) {
    return v == PROV_V35 || v == PROV_V36 || v == PROV_V37;
}
// The push input: the atom with its provenance. The canon-signature
// push(miner, w_raw, flags) is exactly push(WorkAtom{miner, w_raw, flags}).
struct WorkAtom {
    MinerId miner = 0;
    u64 w_raw = 0;
    std::uint32_t flags = 0;
    ProtoVersion version = PROV_V37;
    // ── S6-S7 (window). Annotation-only while the window gate is OFF: no
    // pre-window path reads either field, exactly as the admission emitter
    // computes the origin height today and then drops it. Under win_active()
    // origin_bin is the buried parent-chain block the work belongs to and
    // carrier_bin is the buried height that delivered it (origin_bin <=
    // carrier_bin, equal for a freshly-chained share). UINT64_MAX == unset.
    u64 origin_bin = UINT64_MAX;
    u64 carrier_bin = UINT64_MAX;
    // A RECEIPT (a stale share re-presented inside the window) credits its
    // origin bin but NEVER advances the clock (ruling H).
    bool is_receipt = false;
    // S14: D_net@base (ruling D) — the SINGLE committed parent-chain
    // difficulty read the S4 width law consumes at a retarget boundary. It is
    // exogenous (IMainchainDifficulty at the lane, the 04-WIDTH-LAW-FOLD
    // seam), never derived from lane state, never inflatable. Zero == unset:
    // the gate-OFF path never reads it, and an NR retarget on a zero read
    // HOLDS W (ND-R11 default, flagged).
    U256 d_net{};
};
// One provenance row of a bucket: raw work of `miner` produced under
// `version` (never PROV_V37 — those rows are the implicit remainder).
struct ProvEntry {
    ProtoVersion version = 0;
    MinerId miner = 0;
    u128 raw = 0;
    bool operator==(const ProvEntry&) const = default;
};

// Level-0 slot (SoA in the production layout; AoS here for clarity — the
// arrays are contiguous std::vector rings either way).
struct L0Slot {
    u64 pos = 0;
    u64 w_raw = 0;       // work(target), verbatim (F-1; feeds epoch rebuild)
    u128 w_scaled = 0;   // w_raw x InvD[pos - B] at insert, Q62
    MinerId miner = 0;
    std::uint32_t flags = 0;   // L0F_* bits above
    ProtoVersion version = PROV_V37;   // I-6: provenance only (never weight)
    // S6-S7: the bin the work belongs to. Annotation-only while the window
    // gate is OFF (it stays 0 and nothing reads it); under win_active() it is
    // the decay index (w_scaled = w_raw x InvD[origin_bin - B_bin]) and the
    // key the bin ring and the bin-band fold address the slot by.
    u64 origin_bin = 0;
};

// S6-S7: one materialized bin of the parallel bin ring. Live ONLY under
// win_active(). Bins are CONTIGUOUS from the oldest live bin to the clock —
// a parent block that carried no share for this lane is an EMPTY bin that
// still ages, still occupies a ring slot and still counts toward the bin span
// (PURPLE-PAPER §6.1). The events are the same L0 slots the flat ring holds,
// grouped by their origin bin.
struct L0Bin {
    u64 bin = 0;
    std::vector<L0Slot> events;
    U256 scaled_sum;
    u128 raw_sum = 0;
};

struct CompEntry {              // (miner, w_scaled, w_raw) triple, F-1
    MinerId miner = 0;
    U256 scaled;                // stored in the bucket's epoch frame
    u128 raw = 0;
};

struct Bucket {                 // immutable after close (§4.1)
    u64 pos_lo = 0, pos_hi = 0;
    // S6-S7: the BIN band the bucket covers, set only by the bin-band fold
    // (both 0 off the gate; pos_lo/pos_hi keep their canon meaning and their
    // canon bytes, so no digested field moves).
    u64 bin_lo = 0, bin_hi = 0;
    u64 epoch_tag = 0;          // B at close; shift applied at read/evict
    U256 scaled_sum;
    u128 raw_work = 0;          // F-1: per-band settlement leaf
    std::vector<CompEntry> comp;  // sorted by miner id (deterministic)
    // I-6: the non-v37 provenance mix, (version, miner) order, raw only
    // (the scoring lives in comp under the single rule). Empty for an
    // all-v37 bucket => the "V37B" payload is canon's.
    std::vector<ProvEntry> prov;
};

// MRR permanence layer (v37, I-2): Merkle Mountain Range peaks over the
// evicted-bucket leaves. Append-only; O(log n) state (one peak per set bit
// of leaf_count, tallest first). The lane commits to the bagged root in the
// "V37P" digest leaf; archival nodes keep the leaf log and serve inclusion
// proofs (Lane::mmr_proof) that any lite client verifies statelessly
// (Lane::mmr_verify) against the committed root. Same hash discipline as the
// lane digest: leaf = sha256d(0x00||payload), interior = sha256d(0x01||l||r).
struct PeakSet {
    std::vector<bytes32> peaks;   // tallest first; size() == popcount(leaf_count)
    u64 leaf_count = 0;
    bool operator==(const PeakSet&) const = default;
};

// MRR checkpoint (v37, I-3 — CKPT-OQ1, ruled). The shipped Lane is a
// pure function of the RETAINED shares (the tracker window), but the carry
// is truncating and non-invertible: it depends on every carried eviction
// since activation, so no bounded tracker can re-derive it. The committed
// checkpoint is what makes a post-carry full rebuild deterministic:
//   {B, next_pos, carry rows, peaks, seg-table}
// taken INSIDE epoch_rebuild() AFTER the carry shift and BEFORE the
// triggering insert (push() rebuilds first, then inserts), at every rebuild
// whose new epoch base is at/after activation_pos — a positional rule, so
// every conforming node holds the same checkpoints. A ring of >= 2 is
// retained (MrrGate::ckpt_retain). Carry finality = one epoch: a rewind can
// never cross a rebuild, so the newest checkpoint is final the moment it is
// taken; a fork BEFORE the oldest retained checkpoint is a deterministic
// hard-fail (RebuildUnavailable — the same class as today's beyond-tracker
// reorg). The checkpoint digest (Lane::checkpoint_digest) is committed via
// the existing "V37C"/"V37P" leaf forms and echoed in the "MRR1" header
// extension of every active lane digest (no new leaf class).
// The seg-table row (I-3): EXACTLY ONE row, {0, half_life, activation_pos}.
// It records the geometry the carry accrued under, so a rebuild can refuse a
// checkpoint taken under a different one. There is no sealed sequence and no
// retarget in this cut (see the SCOPE NOTE above): the table is a one-row
// record, and the width law that will make the window time-denominated
// arrives with its own gate, not through this row.
struct CarrySegment {
    u64 id = 0;
    u64 half_life = 0;
    u64 from_pos = 0;
    bool operator==(const CarrySegment&) const = default;
};
struct Checkpoint {
    u64 B = 0;                        // epoch base of the checkpointed frame
    u64 next_pos = 0;                 // == B (before the triggering insert)
    std::map<MinerId, U256> carry;    // post-shift rows, frame B
    U256 carry_total;
    PeakSet mmr;                      // permanence range at B
    std::vector<CarrySegment> segments;
    // S12-R: the native-ridge record, present only in a checkpoint taken by
    // an NR push (Op::NrCkpt at every epoch-aligned position after the
    // activation). nr_present == false in every pre-NR checkpoint, so the
    // I-3 / I-5 checkpoint bytes and goldens are unchanged. Under NR the
    // checkpoint is taken at the START of the push at next_pos (before its
    // clock move), so `next_pos` is its replay point and `B` the frozen
    // positional base. The FINE LAYER IS NOT IN THE CHECKPOINT: a rebuild
    // replays the tracker atoms from nr_fine_lo_pos (the lowest position
    // resident in any live fine bin) to re-derive it, then verifies every
    // cell against it (KAT-ND11 measures the bytes and the replay).
    bool nr_present = false;
    bool nr_started = false;
    u64  nr_t = 0, nr_W = 0, nr_t0 = 0;
    u64  nr_fine_lo_pos = UINT64_MAX;
    // S14: the bin-clock cadence anchors and the width law's period state.
    // Without them a rebuilt lane would re-open the current period from
    // scratch and could elect a DIFFERENT W than the linear lane at the same
    // position — the rebuild would be deterministic but WRONG.
    u64  nr_last_ckpt_bin = 0, nr_last_retarget_bin = 0;
    u128 nr_raw_cur = 0, nr_raw_prev = 0;
    U256 nr_dnet_at_base;
    std::array<std::map<u64, nr::Cell>, nr::MAX_FOLD_CAP + 1> nr_cells;
    std::map<u64, nr::Cell> nr_record_cells;
    bool operator==(const Checkpoint&) const = default;
};
// One tracker record (the durable primaries a full rebuild replays).
struct ShareRec {
    MinerId miner = 0;
    u64 w_raw = 0;
    std::uint32_t flags = 0;
    ProtoVersion version = PROV_V37;   // I-6: replayed, so a rebuild keeps provenance
    // S12-R: the bin coordinates an NR-era rebuild replays (the tracker
    // holds ShareRec + origin_bin; unset == UINT64_MAX off the gate).
    u64 origin_bin = UINT64_MAX;
    u64 carrier_bin = UINT64_MAX;
    bool is_receipt = false;
    U256 d_net{};              // S14: replayed so a rebuild re-drives the width law
};
// Deterministic hard-fail of Lane::rebuild_from_checkpoint: a fork deeper
// than the retained checkpoints, or a tracker that does not reach the
// replay start. Pure function of (lane state, fork_pos, tracker_lo): nodes
// with identical state refuse with the identical message. The lane is
// untouched when thrown.
class RebuildUnavailable : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Marker for the canon-signature push(miner, w_raw, flags): no canonical
// identity resolver is available. Fine while the MRR gate is OFF (KAT-0:
// the code path is canon's); an MRR-active CARRIED eviction needs the
// resolver to form the evicted bucket's leaf and refuses (throws BEFORE
// any state mutation) when only this marker is present.
struct NoResolver {};

class Lane {
private:
    // Tag of the replay lane rebuild_from_checkpoint builds (gate OFF).
    struct ReplayTag {};

public:
    explicit Lane(const LaneParams& p) : m_p(p) {
        if (p.c0 == 0 || (p.c0 & (p.c0 - 1)) != 0)
            throw std::invalid_argument("v37: C0 must be a power of two");
        if (p.rollup == 0 || p.c0 % p.rollup != 0)
            throw std::invalid_argument("v37: R must divide C0");
        if (p.window < p.c0)
            throw std::invalid_argument("v37: window must be >= C0 "
                                        "(eviction needs whole buckets)");
        if (p.level_caps.empty())
            throw std::invalid_argument("v37: at least one bucket level");
        // Inner bucket levels must hold at least one roll-up group; the
        // outermost level never folds, so its cap is not load-bearing.
        for (std::size_t k = 0; k + 1 < p.level_caps.size(); ++k)
            if (p.level_caps[k] < p.rollup)
                throw std::invalid_argument(
                    "v37: inner level cap smaller than roll-up factor");
        // ── S6-S7: the time-window gate's construction guards. UNIFORM
        // refusal on every node — a mis-set constant fails to construct
        // identically everywhere rather than diverging quietly at some later
        // share. The whole block is inert while win_version == 0 (the
        // default), so the gate-OFF constructor path is the pre-window one.
        if (p.win.win_version == 1) {
            const WinGate& w = p.win;
            if (w.coverage_blocks == 0 || w.bin_seconds == 0 || w.w_min_bins == 0 ||
                w.w_default_bins == 0 || w.w_max_bins == 0 || w.retarget_bins == 0 ||
                w.damp_factor == 0 || w.burial_depth == 0)
                throw std::invalid_argument("v37(win): win_version 1 needs the "
                                            "complete width-law constant set");
            if (w.burial_depth != p.journal_depth)
                throw std::invalid_argument("v37(win): the burial depth is the "
                                            "journal depth (ruling L)");
            if (w.retarget_bins != p.rollup)
                throw std::invalid_argument("v37(win): the width step must be the "
                                            "lane's roll-up factor");
            // ND-R3 struck ruling C's "W_MIN >= C0" clause (C0 stopped being a
            // window floor once the width law replaced the fixed window); the
            // structural guard set below replaces it. R-alignment is what keeps
            // the CLAMP intact under the ND-R14 trailing floor: an R-unaligned
            // W_MIN would be floored below itself (145 -> 144).
            if (!winlaw::w_is_r_aligned(w.w_min_bins, p.rollup) ||
                !winlaw::w_is_r_aligned(w.w_default_bins, p.rollup) ||
                !winlaw::w_is_r_aligned(w.w_max_bins, p.rollup))
                throw std::invalid_argument("v37(win): W_MIN / W_default / W_MAX "
                                            "must be whole roll-up multiples");
            if (w.w_min_bins < p.rollup)
                throw std::invalid_argument("v37(win): W_MIN must hold at least "
                                            "one fold group");
            if (w.w_min_bins % w.damp_factor != 0 || w.w_max_bins % w.damp_factor != 0)
                throw std::invalid_argument("v37(win): the damping factor must "
                                            "divide W_MIN and W_MAX");
            if (!(w.w_min_bins <= w.w_default_bins && w.w_default_bins <= w.w_max_bins))
                throw std::invalid_argument("v37(win): W_MIN <= W_default <= W_MAX");
            if (w.w_max_bins > winlaw::LADDER_DOMAIN_BINS)
                throw std::invalid_argument("v37(win): W_MAX above the ratified "
                                            "ladder domain");
            // Ruling B: the bin window keeps the ratified (half_life, epoch_len)
            // pair, merely relabelled, so the golden decay table is reused
            // bit-identical. A lane that moved the half-life would silently be
            // scoring bins on a non-golden base.
            if (p.half_life != winlaw::HALF_LIFE_BINS)
                throw std::invalid_argument("v37(win): the bin window keeps the "
                                            "ratified half-life (ruling B)");
        }
        // Ruling M — ONE atomic V37.1 flip. A FINITE window gate must be
        // epoch-aligned and must sit at exactly the MRR/estimator activation
        // position. The OFF sentinel is exempt from both (it never fires), so
        // the default construction path is untouched.
        if (p.win.win_activation_pos != UINT64_MAX) {
            if (p.win.win_version != 1)
                throw std::invalid_argument("v37(win): a finite window gate needs "
                                            "win_version 1");
            if (p.win.win_activation_pos % p.epoch_len() != 0)
                throw std::invalid_argument("v37(win): the window activation must "
                                            "be epoch-aligned");
            if (p.win.win_activation_pos != p.mrr.activation_pos)
                throw std::invalid_argument("v37(win): ruling M co-locates the "
                                            "window gate with the MRR / estimator "
                                            "activation position");
        }
        // ── S12: the NATIVE RIDGE gate's preconditions. Decided from the
        // arguments alone and only when nr_version != 0, so the default
        // constructor path is the p1+p2 lane's (and canon's, KAT-0). Every
        // clause is an attributable, UNIFORM throw on every node.
        //
        // The block is split exactly as the window block above is: the
        // CONSTANT SET is validated whenever the table is DECLARED (version 1,
        // which for_version(1, lane) does with the position still OFF), and
        // the POSITION / co-location clauses fire only for a FINITE position.
        // Declaring the ruled table is not the flip.
        if (p.nr.nr_version != 0) {
            if (p.nr.nr_version != 1)
                throw std::invalid_argument("v37(nr): unknown nr_version "
                                            "(0 = table path, 1 = native ridge)");
            // S14: the width law's own constants (ND-R6). coverage_blocks is
            // the economic policy input — it has no derivable value, so its
            // absence is an attributable refusal, never a silent default.
            if (p.nr.coverage_blocks == 0)
                throw std::invalid_argument("v37(nr): nr_version 1 needs "
                                            "coverage_blocks (ND-R6: the "
                                            "operator-baked economic constant "
                                            "of the S4 width law)");
            if (p.nr.bin_seconds == 0)
                throw std::invalid_argument("v37(nr): nr_version 1 needs "
                                            "bin_seconds (ruling A: one bin == "
                                            "one buried parent block)");
            nr::check_dims(nr_dims_of(p));   // the FLAG-1 replacement guard set:
                                             // rollup 8, fold_cap in [1,4],
                                             // half_life == 2160 (ND-R8), widths
                                             // R-/retarget-/damp-aligned,
                                             // W_MAX <= 12288, N_CTX < H_open <
                                             // W_MIN, W_MIN >= H_open + R^LAMBDA
            // The width BOUNDS must sit on the R lattice the cell ladder folds
            // on. ND-R14 RULED 2026-09-10: the width law's order is damp
            // x4/div4 -> clamp [W_MIN, W_MAX] -> FLOOR-TO-R LAST, so every
            // reachable W is R-aligned by construction. This guard is what
            // keeps the other half of that ruling true: with the floor applied
            // last, an R-UNALIGNED W_MIN would be floored BELOW itself and the
            // clamp's lower bound would stop holding (145 -> 144).
            for (u64 w : {p.nr.w_min_bins, p.nr.w_max_bins, p.nr.w_default_bins})
                if (!winlaw::w_is_r_aligned(w, p.rollup))
                    throw std::invalid_argument("v37(nr): a width bound off the "
                                                "R lattice would let the width "
                                                "law leave it");
            // ND-R9 / ruling M — ONE atomic V37.1 flip. A FINITE ridge gate is
            // epoch-aligned and sits at exactly the MRR / estimator activation
            // position, and the RETIRED window gate must stay OFF beside it
            // (S12 SUPERSEDES the S3 bin-band pyramid rather than stacking on
            // it; the S11 overlay is already absent from this cut). The OFF
            // sentinel is exempt from all of it, so the default construction
            // path and for_version(1, lane) are untouched.
            if (p.nr.nr_activation_pos != UINT64_MAX) {
                if (p.mrr.activation_pos == UINT64_MAX)
                    throw std::invalid_argument("v37(nr): the native ridge sits "
                                                "above the MRR retrofit (S10): a "
                                                "finite ridge gate needs a finite "
                                                "mrr.activation_pos");
                if (p.nr.nr_activation_pos % p.epoch_len() != 0)
                    throw std::invalid_argument("v37(nr): the ridge activation "
                                                "must be epoch-aligned (the "
                                                "activation share is a rebuild / "
                                                "checkpoint point)");
                if (p.nr.nr_activation_pos != p.mrr.activation_pos)
                    throw std::invalid_argument("v37(nr): ruling M / ND-R9 "
                                                "co-locate the ridge gate with "
                                                "the MRR / estimator activation "
                                                "position");
                if (p.win.win_activation_pos != UINT64_MAX)
                    throw std::invalid_argument("v37(nr): ND-R9 — the S3 bin-band "
                                                "pyramid is RETIRED; S12 "
                                                "supersedes it (a finite window "
                                                "gate beside nr_version 1 is "
                                                "refused)");
            }
        } else if (p.nr.nr_activation_pos != UINT64_MAX) {
            throw std::invalid_argument("v37(nr): nr_activation_pos set with "
                                        "nr_version 0");
        }
        // decay[] must cover query depths [0,E) and rebuild depths [1,E];
        // epoch_shift[] must cover the max bucket age in epochs. Under a
        // declared window the ladder must also span a bin window as wide as
        // W_MAX. This is TABLE SIZING only — epoch_shift[] is never serialized
        // — and it is inert while the window gate is OFF.
        u64 ladder_span = p.window;
        if (p.win.win_version == 1 && p.win.w_max_bins > ladder_span)
            ladder_span = p.win.w_max_bins;
        u64 max_epochs = (ladder_span / p.epoch_len()) + 4;
        m_tab.init(p.half_life, p.epoch_len(), p.epoch_len() + p.c0, max_epochs);
        m_levels.resize(p.level_caps.size());
        // MRR (I-3): the ruled minimum checkpoint retention. The default (2)
        // passes, so the gate-OFF constructor path is canon's.
        if (p.mrr.ckpt_retain < MRR_CKPT_RETAIN_MIN)
            throw std::invalid_argument("v37: CKPT-OQ1 requires >= 2 retained checkpoints");
        // MRR (I-3): the seg-table's one and only row —
        // {0, half_life, activation_pos}. Pure state initialization: nothing
        // here is serialized under an OFF gate (checkpoints exist only under
        // the MRR gate), so the gate-OFF constructor path is canon's.
        m_segments.assign(1, CarrySegment{0, p.half_life, p.mrr.activation_pos});
    }

public:
    // The ratified per-half-life decay registry (seam S7) as a PREDICATE the
    // callers of a future geometry change consult before adopting one: on the
    // frozen c0 == E == 4096 only the ratified half_life 2160 has a golden
    // exact-root base (d659c801); every other half_life falls on the
    // non-golden first-order base (it differs at decay[1] already) and the
    // smaller ones trip the inverse-decay headroom outright (1080:
    // lambda^-(4095) = 2^3.79 > 4.0). Argument-only and side-effect free.
    // NOTHING in this header changes geometry, so nothing here calls it: it
    // is the registry surface the width-law gate will consult when it lands.
    static bool half_life_golden_safe(u64 half_life, u64 epoch_len) {
        namespace dc = decay_canonical;
        return epoch_len != dc::CANON_EPOCH_LEN || half_life == dc::CANON_HALF_LIFE;
    }

    // MRR (v37, I-3): a lane that STARTS at position start_pos with an
    // empty prefix — the replay head of a full rebuild (rebuild_from_checkpoint
    // below). With a single bucket level the live state of the canon Lane at
    // any post-rebuild point is a pure function of the retained primaries:
    // bucket boundaries are R-aligned from position 0, a bucket's fold-time
    // frame is positional (epoch_tag = epoch(pos_lo) + E for C0 == E), whole
    // -bucket eviction keeps the oldest retained bucket at
    // R * ceil((next_pos - W) / R), and acc / L0 sums are re-summed from the
    // primaries at every rebuild. A lane started at an R-aligned start_pos
    // therefore replays into the SAME live state once start_pos is at or
    // before the genesis lane's oldest retained position (KAT-RB pins this
    // bit-exactly). Multi-level pyramids cascade on ring fill counts since
    // start and are NOT replay-equivalent from a mid-stream start: refused.
    // start_pos == 0 is the canon constructor.
    Lane(const LaneParams& p, u64 start_pos) : Lane(p) { start_mid_stream(start_pos); }

private:
    Lane(const LaneParams& p, u64 start_pos, ReplayTag) : Lane(p) { start_mid_stream(start_pos); }
    void start_mid_stream(u64 start_pos) {
        if (start_pos == 0) return;
        if (m_p.level_caps.size() != 1)
            throw std::invalid_argument("v37: mid-stream start needs a single "
                                        "bucket level (multi-level cascade is not "
                                        "replay-equivalent)");
        if (start_pos % m_p.rollup != 0)
            throw std::invalid_argument("v37: mid-stream start must be R-aligned");
        m_next_pos = start_pos;
        m_B = (start_pos / m_p.epoch_len()) * m_p.epoch_len();
    }

public:

    const LaneParams& params() const { return m_p; }
    const DecayTables& tables() const { return m_tab; }
    u64 next_pos() const { return m_next_pos; }
    u64 epoch_base() const { return m_B; }
    u64 cover() const { return m_cover; }
    const U256& acc_total() const { return m_acc_total; }
    u128 raw_total() const { return m_raw_total; }
    const std::map<MinerId, U256>& acc() const { return m_acc; }
    const std::deque<L0Slot>& l0() const { return m_l0; }
    const std::vector<std::deque<Bucket>>& levels() const { return m_levels; }
    const U256& l0_scaled_sum() const { return m_l0_scaled_sum; }
    u128 l0_raw_sum() const { return m_l0_raw_sum; }

    // ── I-6 provenance reads (MV-OQ1 = A) ─────────────────────────────────
    // The L0 ring's non-v37 provenance mix, (version, miner) order — what
    // the header's "V37V" sub-block commits (empty => no sub-block). A
    // stateless scan of the ring (O(C0)), so the journal has nothing to undo.
    std::vector<ProvEntry> l0_provenance() const {
        std::map<std::pair<ProtoVersion, MinerId>, u128> m;
        for (const auto& s : m_l0)
            if (s.version != PROV_V37) m[{s.version, s.miner}] += s.w_raw;
        return prov_rows(m);
    }
    // True iff any LIVE atom (L0 slot or bucket row) carries non-v37
    // provenance — exactly when the lane digest differs from the digest the
    // same stream re-tagged as all-v37 would produce. The permanent record
    // (MMR peaks, checkpoints) may still remember evicted non-v37 work.
    bool prov_marked() const {
        for (const auto& s : m_l0) if (s.version != PROV_V37) return true;
        for (const auto& lvl : m_levels)
            for (const auto& b : lvl) if (!b.prov.empty()) return true;
        return false;
    }

    // ── MRR retrofit (V37.1, seam S2): evict-to-carry v1 ──────────────────
    // ACTIVE from the share at activation_pos onward, i.e. when the head
    // position (next_pos - 1) >= activation_pos  <=>  next_pos > activation_pos.
    // The default UINT64_MAX can never satisfy this, so a gate-OFF lane runs
    // the canon code paths byte-for-byte (KAT-0). A rewind that lands before
    // activation_pos deactivates again (the digest reverts to canon form;
    // the carry is necessarily empty there — see evict_oldest_bucket).
    bool mrr_active() const { return m_next_pos > m_p.mrr.activation_pos; }

    // ── S6-S7: the time-window gate ───────────────────────────────────────
    // ACTIVE from the share AFTER win_activation_pos onward. The window is its
    // OWN gate: ruling M's co-location with the MRR / estimator activation is
    // enforced ONCE, at construction (a finite window position must EQUAL
    // mrr.activation_pos), so the predicate never has to consult another gate
    // that could be moved independently. The default UINT64_MAX never
    // satisfies it, so a win-OFF lane runs the pre-window code paths
    // byte-for-byte (KAT-0 pins that).
    bool win_active() const {
        return m_p.win.win_version == 1 && m_next_pos > m_p.win.win_activation_pos;
    }
    // The one-time activation migration (ruling K) has run. It runs at the END
    // of the push AT win_activation_pos — the last positional push — so no
    // single push ever straddles the two engines.
    bool win_started() const { return m_win_started; }

    // ── NATIVE RIDGE (S12 + S12-R): the public surface ────────────────────
    // ACTIVE from the share AFTER nr_activation_pos onward AND only while the
    // MRR gate is active (S12 sits above S10; ND-R9 co-locates it with the
    // V37.1 flip). The default never satisfies this. The push at
    // nr_activation_pos itself is the last POSITIONAL push (and, being
    // epoch-aligned, a rebuild + shipped-checkpoint point); at its END the
    // one-time activation migration runs (ruling K realized under NR: the
    // whole positional prologue — L0 ring, buckets, acc, carry — is CONSUMED
    // into ONE level-0 record-only cell at t0_bin = the activation share's
    // carrier_bin, whose composition is the shipped payout_map at the flip,
    // so the divided reward is continuous across the flip byte-for-byte;
    // ND-R10 flags this as the operator's ruling). nr_active() therefore
    // always implies nr_started().
    bool nr_active() const {
        return m_p.nr.nr_version == 1 && m_next_pos > m_p.nr.nr_activation_pos && mrr_active();
    }
    bool nr_started()      const { return m_nr_started; }
    u64  nr_t_now()        const { return m_nr_t; }
    u64  nr_t0_bin()       const { return m_nr_t0; }
    u64  nr_W_bins()       const { return m_W_bins; }
    u64  nr_open_horizon() const { return m_p.nr.open_horizon_bins; }
    u64  nr_fold_cap()     const { return m_p.nr.fold_cap; }
    // S14 — TEST OBSERVABILITY. `nr_declared()` is true whenever the gate is
    // CONFIGURED (version 1) whether or not it has fired, and nr_branch_hits()
    // counts NR-path pushes. KAT-0m asserts the counter is 0 under OFF and
    // moves under ON: that is what makes the gate-OFF byte-identity
    // NON-VACUOUS (a dead wire would keep it at 0 in both).
    bool nr_declared()     const { return m_p.nr.nr_version == 1; }
    u64  nr_branch_hits()  const { return m_nr_branch_hits; }
    u64  nr_retargets()    const { return m_nr_retargets; }
    u64  nr_ckpts_taken()  const { return m_nr_ckpts_taken; }
    u64  nr_last_retarget_bin() const { return m_nr_last_retarget_bin; }
    u64  nr_last_ckpt_bin()     const { return m_nr_last_ckpt_bin; }
    u128 nr_raw_cur()      const { return m_nr_raw_cur; }
    u128 nr_raw_prev()     const { return m_nr_raw_prev; }
    const U256& nr_dnet_at_base() const { return m_nr_dnet_at_base; }
    // The burial floor (ruling I) and the open horizon (mechanism A).
    u64  nr_B_bin() const {
        if (!m_nr_started) return 0;
        return m_nr_t + 1 > m_W_bins ? m_nr_t - m_W_bins + 1 : 0;
    }
    bool nr_sealed(u64 bin) const {
        return m_nr_started && nr::sealed_bin(bin, m_nr_t, m_p.nr.open_horizon_bins);
    }
    const std::array<std::map<u64, nr::Cell>, nr::MAX_FOLD_CAP + 1>& nr_cells() const { return m_nr_cells; }
    const std::map<u64, nr::FineBin>& nr_fine() const { return m_nr_fine; }
    const std::map<u64, nr::Cell>& nr_record_cells() const { return m_nr_record; }
    std::size_t nr_cell_count() const {
        std::size_t n = m_nr_record.size();
        for (const auto& lvl : m_nr_cells) n += lvl.size();
        return n;
    }
    std::size_t nr_carried_cell_count() const {
        std::size_t n = 0;
        for (const nr::Cell* c : nr_ordered_cells()) if (!c->carried.empty()) ++n;
        return n;
    }
    // S15 / ND-R15b: the oldest group end this tick's folds could still have to
    // score — the minimum bin_hi over cells BELOW the fold cap. A cell at the
    // cap is never folded again, and a record cell is never folded at all, so
    // neither can be scored ahead of the domain-edge drop. UINT64_MAX when no
    // such cell exists (an empty or fully-folded ridge), in which case the
    // clause is vacuous and only the RULED t_now bound applies.
    u64 nr_oldest_unfolded_bin_hi() const {
        u64 best = UINT64_MAX;
        for (u64 l = 0; l < m_p.nr.fold_cap; ++l)
            for (const auto& [idx, c] : m_nr_cells[static_cast<std::size_t>(l)]) {
                (void)idx;
                if (c.bin_hi < best) best = c.bin_hi;
            }
        return best;
    }
    // The two ledgers of the carried split, read at the current clock:
    //   live[m]  = SUM_c G_c * (comp_c[m] - carried_c[m])
    //   carry[m] = SUM_c G_c *  carried_c[m]
    // payout_map() / decayed_weight() under nr_active() return live + carry
    // per miner (the pinned two-product CARRY-ARITH shape); under a carry-OFF
    // ruling (ND-R11) the settlement reads nr_live_map() alone.
    const std::map<MinerId, U256>& nr_live_map()  const { if (!m_nr_cache_ok) nr_rebuild_cache(); return m_nr_live; }
    const std::map<MinerId, U256>& nr_carry_map() const { if (!m_nr_cache_ok) nr_rebuild_cache(); return m_nr_carry; }
    // The GLOBAL reference (KAT-ND10b's oracle): every fine-backed cell
    // re-derived from (fine layer, clock, H_open, fold_cap, carried) — the
    // pure function the localized journal undos must land on exactly. Fully
    // carried cells (no fine layer) are the frozen record they are.
    std::array<std::map<u64, nr::Cell>, nr::MAX_FOLD_CAP + 1> nr_reference_cells() const {
        std::array<std::map<u64, nr::Cell>, nr::MAX_FOLD_CAP + 1> out;
        const nr::LadderOpts lo = nr_ladder_opts();
        for (const auto& lvl : m_nr_cells)
            for (const auto& [idx, c] : lvl)
                if (c.fully_carried()) out[static_cast<std::size_t>(c.level)][idx] = c;
        std::map<std::pair<u64, u64>, std::map<nr::ProvKey, u128>> pv;   // (level, idx) -> prov
        std::set<std::pair<u64, u64>> partial;                             // partially shed cells
        for (const auto& [b, fb] : m_nr_fine) {
            const u64 l = nr::level_at(b, m_nr_t, m_p.nr.open_horizon_bins, m_p.nr.fold_cap);
            const u64 idx = b / nr::pow_R(l);
            nr::Cell& c = out[static_cast<std::size_t>(l)][idx];
            if (c.raw_work == 0 && c.comp.empty()) {
                c.level = l;
                c.bin_lo = idx * nr::pow_R(l);
                c.bin_hi = c.bin_lo + nr::pow_R(l) - 1;
                c.G = nr::cell_scalar(m_nr_t, c.bin_hi, lo);
                auto it = m_nr_cells[static_cast<std::size_t>(l)].find(idx);
                if (it != m_nr_cells[static_cast<std::size_t>(l)].end() && it->second.carried_raw != 0) {
                    // the shed part is the frozen record's (carried split + its
                    // provenance): not derivable from the surviving fine bins
                    c.carried = it->second.carried; c.carried_raw = it->second.carried_raw;
                    c.raw_work = it->second.carried_raw; c.comp = it->second.carried;
                    c.prov = it->second.prov;
                    partial.insert({l, idx});
                }
            }
            c.raw_work += fb.raw_sum;
            for (const auto& [m, p] : fb.rows) c.comp[m] += nr::pair_value(b, p.raw, c, lo);
            for (const auto& [k, raw] : fb.prov) pv[{l, idx}][k] += raw;
        }
        for (auto& [key, m] : pv)                       // derived provenance (unshed cells)
            if (!partial.count(key))
                out[static_cast<std::size_t>(key.first)][key.second].prov = nr::prov_rows_of(m);
        return out;
    }
    // Cells in DIGEST order: newest-first by (bin_hi desc, level desc,
    // record_only desc) — the order of the NRC1 leaves.
    std::vector<const nr::Cell*> nr_ordered_cells() const {
        return nr_ordered_cells_of(m_nr_cells, m_nr_record);
    }
    // The width law's output (stage S4) applied to the live window: journaled
    // as Op::NrWidth (attributed to the push that follows it), followed by the
    // exact-bin sheds it triggers. Needs the resolver (a full shed appends a
    // permanence leaf).
    template <typename Resolver>
    void nr_set_width(u64 W, Resolver&& id_key) {
        if constexpr (std::is_same_v<std::decay_t<Resolver>, NoResolver>) {
            (void)W;
            throw std::logic_error("v37: nr_set_width needs the canonical identity resolver");
        } else {
        if (!nr_active() || !m_nr_started)
            throw std::logic_error("v37: nr_set_width before the native ridge is live");
        if (W < m_p.nr.w_min_bins || W > m_p.nr.w_max_bins)
            throw std::invalid_argument("v37: NR width outside [W_MIN, W_MAX]");
        if (W % m_p.rollup)
            throw std::invalid_argument("v37: NR width not R-aligned");
        Op ow; ow.type = Op::Type::NrWidth; ow.nr_a = m_W_bins;
        m_journal.push_back(std::move(ow));
        m_W_bins = W;
        nr_shed_below_floor(id_key);
        nr_drop_beyond_domain();
        nr_refresh_scalars();
        m_nr_cache_ok = false;
        }
    }
    // Structural counters (KAT-ND12 / ND14 / the non-vacuity check).
    u64 nr_pushes()       const { return m_nr_pushes; }
    u64 nr_full_carries() const { return m_nr_full_carries; }
    u64 nr_dropped_cells() const { return m_nr_dropped; }
    // The NRC1 seal-record leaf payload and the NRX1 carried-split leaf
    // payload (canonical-identity keyed). Public so a harness can fingerprint
    // a cell's record at its seal and prove it never changes (KAT-ND12).
    //   "NRC1" || level || bin_hi || bin_lo || raw_work || record_only
    //          || |comp| || sha256d(rows: key || U256, canonical order)
    //          || [V37V prov block iff non-empty]
    //   "NRX1" || level || bin_hi || record_only || carried_raw
    //          || |carried| || sha256d(rows: key || U256, canonical order)
    template <typename Resolver>
    static std::vector<std::uint8_t> nr_cell_leaf_payload(const nr::Cell& c, Resolver&& id_key) {
        std::vector<std::uint8_t> b;
        append_bytes(b, "NRC1", 4);
        append_u64(b, c.level);
        append_u64(b, c.bin_hi);
        append_u64(b, c.bin_lo);
        append_u128(b, c.raw_work);
        append_u64(b, c.record_only ? 1 : 0);
        append_u64(b, static_cast<u64>(c.comp.size()));
        const bytes32 ch = nr_rows_hash(c.comp, id_key);
        b.insert(b.end(), ch.begin(), ch.end());
        if (!c.prov.empty()) {
            std::vector<ProvEntry> pe;
            pe.reserve(c.prov.size());
            for (const auto& r : c.prov) pe.push_back(ProvEntry{r.version, r.miner, r.raw});
            append_prov_block(b, pe, id_key);
        }
        return b;
    }
    template <typename Resolver>
    static std::vector<std::uint8_t> nr_carried_leaf_payload(const nr::Cell& c, Resolver&& id_key) {
        std::vector<std::uint8_t> b;
        append_bytes(b, "NRX1", 4);
        append_u64(b, c.level);
        append_u64(b, c.bin_hi);
        append_u64(b, c.record_only ? 1 : 0);
        append_u128(b, c.carried_raw);
        append_u64(b, static_cast<u64>(c.carried.size()));
        const bytes32 ch = nr_rows_hash(c.carried, id_key);
        b.insert(b.end(), ch.begin(), ch.end());
        return b;
    }
    static constexpr std::size_t NRG1_HEADER_EXT_BYTES = 4 + 10 * 8;
    static constexpr std::size_t NRC1_BASE_PAYLOAD_BYTES = 4 + 8 + 8 + 8 + 16 + 8 + 8 + 32;
    static constexpr std::size_t NRX1_PAYLOAD_BYTES = 4 + 8 + 8 + 8 + 16 + 8 + 32;
    // The clock: the buried parent-chain height at the reorg horizon (ruling L,
    // N == journal_depth). Monotone-max over the carriers seen (ruling H), so
    // two nodes that see the same buried heights hold the same clock whatever
    // order the shares arrive in.
    u64 t_now_bin() const { return m_t_now_bin; }
    u64 win_epoch_base_bin() const { return m_B_bin; }   // == the burial floor (ruling I)
    u64 oldest_live_bin() const { return m_oldest_live_bin; }
    u64 active_window_bins() const { return m_W_bins; }  // the LIVE width (ruling J)
    u64 t0_bin() const { return m_t0_bin; }              // the activation bin (ruling K)
    u128 raw_total_prev_epoch() const { return m_raw_total_prev_epoch; }
    const U256& dnet_at_base() const { return m_dnet_at_base; }
    const std::deque<L0Bin>& l0_bins() const { return m_l0_bins; }
    // bin_span == t_now_bin - oldest_live_bin + 1, counting the EMPTY bins in
    // any gap (§6.1); 0 while nothing is live. This is the eviction predicate's
    // left-hand side: eviction is TIME-driven, not push-count-driven.
    u64 bin_span() const {
        if (m_l0_bins.empty() && levels_empty()) return 0;
        return m_t_now_bin - m_oldest_live_bin + 1;
    }
    // Ruling D: the exogenous committed parent-chain difficulty seam. Node-local
    // WIRING of a committed read — the VALUE it returns is consensus input, and
    // a node that wires a different source diverges visibly at the WIN1 leaf
    // (the D_net the last retarget read is committed there).
    void set_mainchain_difficulty(const IMainchainDifficulty* d) { m_maindiff = d; }
    // The block-event driver (the executor calls this on every buried-height
    // tick, even when no share arrived): the clock advances, the empty bins age,
    // and the oldest band leaves the window on TIME rather than on arrivals.
    // Without it a quiet lane would never evict.
    template <typename Resolver>
    void advance_clock(u64 carrier_bin, Resolver&& id_key) {
        if (!win_active() || !m_win_started) return;
        if (carrier_bin <= m_t_now_bin) return;          // ruling H: monotone-max
        win_grow_to(carrier_bin);
        while (bin_span() > m_W_bins) evict_oldest_bucket(id_key);
    }
    void advance_clock(u64 carrier_bin) { advance_clock(carrier_bin, NoResolver{}); }
    // Carry: a SEPARATE accumulator of evicted scaled work (epoch frame B),
    // per miner + total. It drains by decay only (one epoch factor per
    // rebuild) and never re-enters m_acc.
    const std::map<MinerId, U256>& carry() const { return m_carry; }
    const U256& carry_total() const { return m_carry_total; }

    // ── MRR seg-table (I-3): the one-row geometry record ─────────────────
    // Row 0 is the implicit activation segment {0, half_life, activation_pos}
    // and it is the ONLY row: nothing in this cut seals or retargets. What
    // make_checkpoint records, so a rebuild can refuse a checkpoint taken
    // under a different geometry.
    const std::vector<CarrySegment>& segments() const { return m_segments; }

    // ── MRR permanence layer (I-2): MMR peaks over evicted buckets ────────
    // One leaf per CARRIED eviction (the same whole-bucket predicate as the
    // carry: mrr_active() && pos_lo >= activation_pos), appended at
    // evict_oldest_bucket; the leaf is the bucket's "V37B" digest leaf
    // (level, pos_lo, pos_hi, raw_work, epoch_tag, comp_hash) — byte-equal to
    // the leaf the bucket had in the lane digest while it was live. The
    // Evict journal op records the pre-append peaks so undo_evict truncates
    // the range back bit-exactly (rewind restores peaks like it restores
    // carry). Epoch rebuilds never touch the peaks: the leaf payload is in
    // the bucket's own immutable epoch frame. Empty whenever the gate is
    // inactive (a carried eviction happens at next_pos >= pos_lo + W + 1 >
    // activation_pos + journal_depth, so no rewind can deactivate the gate
    // with a non-empty range).
    const PeakSet& mmr() const { return m_mmr; }
    bytes32 mmr_root() const { return mmr_bag(m_mmr.peaks); }
    struct MerkleProof;   // defined with digest() below; used by mmr_root_proof

    // ── MRR checkpoints (I-3, CKPT-OQ1): ring + rebuild contract ─────────
    // The retained ring, oldest -> newest; empty unless a rebuild with
    // B_new >= activation_pos has happened (never under the default gate).
    const std::deque<Checkpoint>& checkpoints() const { return m_ckpts; }
    static constexpr u64 MRR_CKPT_RETAIN_MIN = 2;
    // The checkpoint digest: sha256d("CKP1" || B || next_pos || seg-table ||
    // carry_count || carry_total || mmr_leaf_count || root), where root is
    // the Merkle root (lane digest discipline) over the checkpoint's "V37C"
    // carry leaves in canonical-identity order followed by its "V37P" leaf —
    // i.e. the very leaves the lane digest carried at the moment the
    // checkpoint was taken. Needs the identity resolver (canonical order).
    // Seg-table: seg_count || {id, half_life, from_pos} x n — with the one
    // row this cut ever holds, n == 1.
    template <typename Resolver>
    static bytes32 checkpoint_digest(const Checkpoint& c, Resolver&& id_key) {
        std::vector<bytes32> leaves;
        leaves.reserve(c.carry.size() + 1);
        append_carry_leaves(leaves, c.carry, id_key);
        leaves.push_back(leaf_hash(mmr_root_payload(c.mmr.leaf_count, mmr_bag(c.mmr.peaks))));
        const bytes32 root = merkle_root(leaves);
        std::vector<std::uint8_t> b;
        append_bytes(b, "CKP1", 4);
        append_u64(b, c.B);
        append_u64(b, c.next_pos);
        append_u64(b, static_cast<u64>(c.segments.size()));
        for (const auto& s : c.segments) {
            append_u64(b, s.id);
            append_u64(b, s.half_life);
            append_u64(b, s.from_pos);
        }
        append_u64(b, static_cast<u64>(c.carry.size()));
        append_u256(b, c.carry_total);
        append_u64(b, c.mmr.leaf_count);
        b.insert(b.end(), root.begin(), root.end());
        if (c.nr_present) {
            // S12-R: the native-ridge record — appended ONLY to an NR
            // checkpoint, so every pre-NR checkpoint digest is unchanged.
            //   "NRK1" || started || t || W || t0 || fine_lo_pos || leaf_count
            //          || merkle_root(NRC1 leaves ++ NRX1 leaves, digest order)
            append_bytes(b, "NRK1", 4);
            append_u64(b, c.nr_started ? 1 : 0);
            append_u64(b, c.nr_t);
            append_u64(b, c.nr_W);
            append_u64(b, c.nr_t0);
            append_u64(b, c.nr_fine_lo_pos);
            // S14: the cadence anchors and the width law's period state are
            // part of the committed base a rebuild installs, so they are part
            // of what the checkpoint digest attests.
            append_u64(b, c.nr_last_ckpt_bin);
            append_u64(b, c.nr_last_retarget_bin);
            append_u256(b, U256::from_u128(c.nr_raw_cur));
            append_u256(b, U256::from_u128(c.nr_raw_prev));
            append_u256(b, c.nr_dnet_at_base);
            std::vector<bytes32> cl;
            for (const nr::Cell* cell : nr_ordered_cells_of(c.nr_cells, c.nr_record_cells)) {
                cl.push_back(leaf_hash(nr_cell_leaf_payload(*cell, id_key)));
                if (!cell->carried.empty())
                    cl.push_back(leaf_hash(nr_carried_leaf_payload(*cell, id_key)));
            }
            append_u64(b, static_cast<u64>(cl.size()));
            const bytes32 cr = cl.empty() ? bytes32{} : merkle_root(cl);
            b.insert(b.end(), cr.begin(), cr.end());
        }
        return sha256d(b);
    }
    // The echo carried in the "MRR1" header extension: the newest retained
    // checkpoint's digest, all-zero while none is retained.
    template <typename Resolver>
    bytes32 newest_checkpoint_digest(Resolver&& id_key) const {
        if (m_ckpts.empty()) return bytes32{};
        return checkpoint_digest(m_ckpts.back(), id_key);
    }
    // The seg-table (I-3: the single activation segment — see segments()).
    std::vector<CarrySegment> mrr_segments() const { return m_segments; }
    // The checkpoint this lane would commit right now (used at the rebuild
    // point; exposed so a harness can compare against the ring).
    Checkpoint make_checkpoint() const {
        Checkpoint c;
        c.B = m_B;
        c.next_pos = m_next_pos;
        c.carry = m_carry;
        c.carry_total = m_carry_total;
        c.mmr = m_mmr;
        c.segments = mrr_segments();
        if (m_p.nr.nr_version == 1 && m_nr_started) {   // S12-R: the NR record
            c.nr_present = true;
            c.nr_started = m_nr_started;
            c.nr_t = m_nr_t;
            c.nr_W = m_W_bins;
            c.nr_t0 = m_nr_t0;
            c.nr_last_ckpt_bin     = m_nr_last_ckpt_bin;      // S14
            c.nr_last_retarget_bin = m_nr_last_retarget_bin;
            c.nr_raw_cur           = m_nr_raw_cur;
            c.nr_raw_prev          = m_nr_raw_prev;
            c.nr_dnet_at_base      = m_nr_dnet_at_base;
            c.nr_cells = m_nr_cells;
            c.nr_record_cells = m_nr_record;
            u64 lo = UINT64_MAX;
            for (const auto& [b, fb] : m_nr_fine) { (void)b; if (fb.pos_lo < lo) lo = fb.pos_lo; }
            c.nr_fine_lo_pos = lo;
        }
        return c;
    }
    // The position a checkpoint stands at: its replay point. A shipped
    // checkpoint is taken at the rebuild (next_pos == B); an NR checkpoint at
    // the start of the push at next_pos (B is the frozen positional base).
    static u64 ckpt_at(const Checkpoint& c) { return c.nr_present ? c.next_pos : c.B; }

    // The full-rebuild contract (the RefusedJournal escalation path, W6 >D).
    // Rebuilds *this* to the state whose next push is the share at fork_pos:
    //   base   = the newest retained checkpoint with B_ckpt <= fork_pos;
    //            with none retained, the epoch base of fork_pos is a valid
    //            EMPTY base iff it is <= activation_pos (carry and range are
    //            provably empty there: the first carried eviction is at
    //            activation_pos + W + 1 at the earliest) — that is today's
    //            plain tracker rebuild; otherwise RebuildUnavailable;
    //   replay = a gate-OFF lane started at the R-aligned position
    //            <= base_B - W (0 when base_B <= W) replays the tracker
    //            [start, base_B) — the live state is gate-independent
    //            (KAT-0b) — then the explicit epoch_rebuild() at base_B;
    //            tracker_lo > start is RebuildUnavailable (beyond-tracker);
    //            W is params().window throughout: the geometry never moves
    //            in this cut, and the rebuilt seg-table must still equal the
    //            base checkpoint's record;
    //   install = the base's carry rows, total, peaks; the ring inherits the
    //            retained checkpoints with B <= base_B (the abandoned
    //            branch's newer ones are dropped);
    //   forward = [base_B, fork_pos) replayed with the gate ON (needs the
    //            resolver: carried evictions).
    // The resulting frame is base_B's: for fork_pos > base_B it is
    // bit-identical to the linear node's state at fork_pos; for fork_pos ==
    // base_B it is the POST-rebuild frame — the linear node's pre-push
    // state at base_B is the pre-rebuild frame, unreachable by rule (rewind
    // refuses to land on the rebuild-triggering push; the pre-shift carry is
    // not recoverable), and the next push converges both (KAT-RB).
    // rec(pos) -> ShareRec for every pos in [tracker_lo, fork_pos). Strong
    // exception safety: *this is untouched on any throw. Returns base_B.
    template <typename Records, typename Resolver>
    u64 rebuild_from_checkpoint(u64 fork_pos, u64 tracker_lo, Records&& rec,
                                Resolver&& id_key) {
        if (fork_pos > m_next_pos)
            throw std::invalid_argument("v37: rebuild fork_pos beyond the head");
        const u64 E = m_p.epoch_len();
        const u64 act = m_p.mrr.activation_pos;
        const Checkpoint* base = nullptr;
        for (auto it = m_ckpts.rbegin(); it != m_ckpts.rend(); ++it)
            if (ckpt_at(*it) <= fork_pos) { base = &*it; break; }
        // S12-R: an NR-era base rebuilds through the native-ridge contract
        // (install the record, re-derive the fine layer from the tracker,
        // verify, replay forward). A fork in the NR era whose base is still
        // the shipped checkpoint at the activation replays through the
        // positional prologue below and crosses the activation naturally.
        if (base && base->nr_present)
            return nr_rebuild_from(*base, fork_pos, tracker_lo, rec, id_key);
        const u64 base_B = base ? base->B : (fork_pos / E) * E;
        const u64 W = m_p.window, R = m_p.rollup;
        const u64 start = base_B > W ? ((base_B - W) / R) * R : 0;
        if (!base && base_B > act)
            throw RebuildUnavailable(rebuild_fail_msg("beyond retained checkpoints",
                                                      fork_pos, base_B, tracker_lo, start));
        if (tracker_lo > start)
            throw RebuildUnavailable(rebuild_fail_msg("beyond tracker retention",
                                                      fork_pos, base_B, tracker_lo, start));
        LaneParams off = m_p;
        off.mrr.activation_pos = UINT64_MAX;            // gate OFF: live state only
        off.nr = NrGate{};                              // S12-R: the ridge too
        Lane fresh(off, start, ReplayTag{});
        for (u64 p = start; p < base_B; ++p) {
            const ShareRec r = rec(p);
            fresh.push(WorkAtom{r.miner, r.w_raw, r.flags, r.version});   // I-6: provenance replayed
        }
        if (base_B > start) {
            if (fresh.m_next_pos - fresh.m_B != E)
                throw std::logic_error("v37: replay did not land on the epoch boundary");
            fresh.epoch_rebuild();                      // frame base_B, no checkpoint (gate OFF)
        }
        fresh.restore_gates(m_p);                       // gate back ON (row 0's from_pos too)
        if (base) {
            if (fresh.m_segments != base->segments)     // the replayed geometry record
                throw std::logic_error("v37: replayed seg-table differs from the "
                                       "base checkpoint's record");
            fresh.m_carry = base->carry;
            fresh.m_carry_total = base->carry_total;
            fresh.m_mmr = base->mmr;
        }
        for (const auto& c : m_ckpts)
            if (ckpt_at(c) <= base_B) fresh.m_ckpts.push_back(c);
        if (!base && base_B >= act)                     // the (empty) checkpoint a
            fresh.m_ckpts.push_back(fresh.make_checkpoint());   // linear node took at act
        while (fresh.m_ckpts.size() > m_p.mrr.ckpt_retain) fresh.m_ckpts.pop_front();
        for (u64 p = base_B; p < fork_pos; ++p)
            fresh.push(atom_of(rec(p)), id_key);        // S12-R: bins replayed too
        *this = std::move(fresh);
        return base_B;
    }
    // S12-R: the tracker record as the atom the lane pushed (bins included).
    static WorkAtom atom_of(const ShareRec& r) {
        WorkAtom a;
        a.miner = r.miner; a.w_raw = r.w_raw; a.flags = r.flags; a.version = r.version;
        a.origin_bin = r.origin_bin; a.carrier_bin = r.carrier_bin; a.is_receipt = r.is_receipt;
        a.d_net = r.d_net;          // S14: the width law re-drives from the tracker
        return a;
    }
    // S12-R: the NR-era full rebuild. Installs the base record {clock, W, t0,
    // cells with their carried maps, record cells, peaks, ring}, re-derives
    // the FINE LAYER by replaying the tracker atoms [nr_fine_lo_pos,
    // base.next_pos) whose origin lies in the base's window (pair raw sums,
    // then the pure pair value in the owning cell's frame), VERIFIES every
    // cell's composition against it (an attributable logic_error on a
    // tracker/checkpoint mismatch — never a silent divergence), then replays
    // [base.next_pos, fork_pos) with the gate ON. Strong exception safety.
    template <typename Records, typename Resolver>
    u64 nr_rebuild_from(const Checkpoint& base, u64 fork_pos, u64 tracker_lo,
                        Records&& rec, Resolver&& id_key) {
        if constexpr (std::is_same_v<std::decay_t<Resolver>, NoResolver>) {
            (void)base; (void)fork_pos; (void)tracker_lo; (void)rec;
            throw std::logic_error("v37: an NR-era rebuild needs the canonical identity resolver");
        } else {
            const u64 start = base.nr_fine_lo_pos == UINT64_MAX ? base.next_pos : base.nr_fine_lo_pos;
            if (tracker_lo > start)
                throw RebuildUnavailable(rebuild_fail_msg("beyond tracker retention (NR fine layer)",
                                                          fork_pos, base.next_pos, tracker_lo, start));
            Lane fresh(m_p);
            fresh.m_next_pos = base.next_pos;
            fresh.m_B = base.B;
            fresh.m_mmr = base.mmr;
            fresh.m_segments = base.segments;
            fresh.m_nr_started = base.nr_started;
            fresh.m_nr_t = base.nr_t;
            fresh.m_W_bins = base.nr_W;
            fresh.m_nr_t0 = base.nr_t0;
            fresh.m_nr_cells = base.nr_cells;
            fresh.m_nr_record = base.nr_record_cells;
            fresh.m_nr_last_ckpt_bin     = base.nr_last_ckpt_bin;      // S14
            fresh.m_nr_last_retarget_bin = base.nr_last_retarget_bin;
            fresh.m_nr_raw_cur           = base.nr_raw_cur;
            fresh.m_nr_raw_prev          = base.nr_raw_prev;
            fresh.m_nr_dnet_at_base      = base.nr_dnet_at_base;
            const u64 floor = fresh.nr_B_bin();
            for (u64 p = start; p < base.next_pos; ++p) {
                const ShareRec r = rec(p);
                if (r.origin_bin == UINT64_MAX || r.origin_bin < floor || r.origin_bin > base.nr_t)
                    continue;                                   // not resident at the base
                nr::FineBin& fb = fresh.m_nr_fine[r.origin_bin];
                fb.bin = r.origin_bin;
                fb.raw_sum += r.w_raw;
                fb.rows[r.miner].raw += r.w_raw;
                if (r.version != PROV_V37) fb.prov[{r.version, r.miner}] += r.w_raw;
                if (p < fb.pos_lo) fb.pos_lo = p;
            }
            const nr::LadderOpts lo = fresh.nr_ladder_opts();
            for (auto& [b, fb] : fresh.m_nr_fine) {
                nr::Cell* c = fresh.nr_find_owner(b);
                if (!c)
                    throw std::logic_error("v37: NR rebuild — a replayed fine bin has no "
                                           "owning cell in the base checkpoint");
                for (auto& [m, pr] : fb.rows) pr.v = nr::pair_value(b, pr.raw, *c, lo);
            }
            fresh.nr_verify_cells_against_fine();
            fresh.nr_refresh_scalars();
            // The ring the LINEAR lane held at this position. An NR checkpoint
            // at position p is taken DURING push p, so at position p it is not
            // in the ring yet — the forward replay of push p re-takes it. A
            // shipped checkpoint is taken AT the rebuild point, so B == p is
            // already in the ring there.
            for (const auto& c : m_ckpts)
                if (c.nr_present ? (c.next_pos < base.next_pos) : (c.B <= base.next_pos))
                    fresh.m_ckpts.push_back(c);
            while (fresh.m_ckpts.size() > m_p.mrr.ckpt_retain) fresh.m_ckpts.pop_front();
            fresh.m_nr_cache_ok = false;
            const u64 at = base.next_pos;               // `base` aliases m_ckpts: read before the move
            for (u64 p = at; p < fork_pos; ++p)
                fresh.push(atom_of(rec(p)), id_key);
            *this = std::move(fresh);
            return at;
        }
    }

    // Format bounds: leaf_count is a u64, so at most 64 peaks and an MMR
    // path of at most 63 siblings; the "V37P" payload is fixed-width.
    static constexpr std::size_t MRR_MMR_MAX_PEAKS = 64;
    static constexpr std::size_t MRR_MMR_MAX_PATH = 63;
    static constexpr std::size_t V37P_PAYLOAD_BYTES = 4 + 8 + 32;
    // I-3: + the 32-byte checkpoint-digest echo (60 -> 92).
    static constexpr std::size_t MRR1_HEADER_EXT_BYTES = 4 + 8 + 8 + 32 + 8 + 32;
    static constexpr std::size_t CKP1_PREAMBLE_BYTES = 4 + 8 + 8 + 8 + 8 + 32 + 8;   // + segments x 24 + root 32
    static_assert(sizeof(u64) == 8 && std::tuple_size<bytes32>::value == 32,
                  "v37: fixed-width MMR formats assume u64 / 32-byte hashes");

    // MMR append: the binary-counter rule. With n = leaf_count, the peaks
    // are the roots of the perfect subtrees for the set bits of n, tallest
    // first; appending merges the new leaf upward while the low bit is set.
    static void mmr_append(PeakSet& ps, const bytes32& leaf) {
        bytes32 h = leaf;
        u64 n = ps.leaf_count;
        while (n & 1) {
            h = interior_hash(ps.peaks.back(), h);
            ps.peaks.pop_back();
            n >>= 1;
        }
        ps.peaks.push_back(h);
        ps.leaf_count += 1;
    }
    // Bag the peaks to one root: right fold, tallest peak outermost.
    // bag([p0, p1, ..., pk]) = H(p0, H(p1, ... H(p(k-1), pk))); a single peak
    // is its own bag; the empty range bags to all-zero bytes.
    static bytes32 mmr_bag(const std::vector<bytes32>& peaks) {
        bytes32 r{};
        if (peaks.empty()) return r;
        r = peaks.back();
        for (std::size_t i = peaks.size() - 1; i-- > 0;)
            r = interior_hash(peaks[i], r);
        return r;
    }
    // The evicted-bucket leaf (== the bucket's live "V37B" digest leaf at and
    // after the flip). RULING-B: the permanence leaf keeps the provenance mix
    // unconditionally — it is minted only by a CARRIED eviction, which is
    // reachable only while mrr_active(), so `true` here is the same value
    // build_leaves passes at that point and the two leaves stay identical.
    // The public 3-argument signature is UNCHANGED (KAT-P1 (L) calls it).
    template <typename Resolver>
    static bytes32 bucket_leaf(std::size_t level, const Bucket& b, Resolver&& id_key) {
        return leaf_hash(bucket_leaf_payload(level, b, id_key, true));
    }
    // The "V37P" lane-digest leaf payload: tag || leaf_count || bagged root.
    static std::vector<std::uint8_t> mmr_root_payload(u64 leaf_count, const bytes32& root) {
        std::vector<std::uint8_t> b;
        b.reserve(V37P_PAYLOAD_BYTES);
        append_bytes(b, "V37P", 4);
        append_u64(b, leaf_count);
        b.insert(b.end(), root.begin(), root.end());
        return b;
    }

    // Inclusion proof of one MMR leaf: siblings bottom-up inside the leaf's
    // perfect subtree (path.size() == that peak's height) plus every peak,
    // tallest first, so the verifier re-bags the root itself.
    struct MmrProof {
        u64 leaf_count = 0;
        u64 index = 0;
        std::vector<bytes32> path;
        std::vector<bytes32> peaks;
    };
    // Archival side: build the proof from the full leaf log (leaves.size()
    // must equal the leaf_count the root was committed at).
    static MmrProof mmr_proof(const std::vector<bytes32>& leaves, u64 idx) {
        MmrProof p;
        p.leaf_count = static_cast<u64>(leaves.size());
        p.index = idx;
        if (idx >= p.leaf_count) return p;
        const u64 n = p.leaf_count;
        u64 offset = 0;
        for (int h = 63; h >= 0; --h) {
            if (!((n >> h) & 1)) continue;
            const u64 span = u64(1) << h;
            std::vector<bytes32> level(leaves.begin() + static_cast<long>(offset),
                                       leaves.begin() + static_cast<long>(offset + span));
            if (idx >= offset && idx < offset + span) {
                u64 j = idx - offset;
                std::vector<bytes32> lv = level;
                while (lv.size() > 1) {
                    p.path.push_back(lv[j ^ 1]);
                    std::vector<bytes32> next;
                    next.reserve(lv.size() / 2);
                    for (std::size_t i = 0; i + 1 < lv.size(); i += 2)
                        next.push_back(interior_hash(lv[i], lv[i + 1]));
                    lv = std::move(next);
                    j >>= 1;
                }
            }
            p.peaks.push_back(perfect_root(std::move(level)));
            offset += span;
        }
        return p;
    }
    // Stateless verifier (lite client): climbs the path to the peak the
    // index falls in, checks it against the supplied peak, and re-bags all
    // peaks to the committed root. Structure comes from leaf_count only.
    static bool mmr_verify(const bytes32& bagged_root, const bytes32& leaf,
                           const MmrProof& p) {
        const u64 n = p.leaf_count;
        if (n == 0 || p.index >= n) return false;
        if (p.peaks.size() != popcount64(n)) return false;
        u64 offset = 0;
        std::size_t peak_idx = 0;
        int height = -1;
        for (int h = 63; h >= 0; --h) {
            if (!((n >> h) & 1)) continue;
            const u64 span = u64(1) << h;
            if (p.index >= offset && p.index < offset + span) { height = h; break; }
            offset += span;
            ++peak_idx;
        }
        if (height < 0 || p.path.size() != static_cast<std::size_t>(height)) return false;
        bytes32 hh = leaf;
        u64 j = p.index - offset;
        for (const bytes32& sib : p.path) {
            hh = (j & 1) ? interior_hash(sib, hh) : interior_hash(hh, sib);
            j >>= 1;
        }
        if (hh != p.peaks[peak_idx]) return false;
        return mmr_bag(p.peaks) == bagged_root;
    }
    // Lane-digest proof of the "V37P" leaf (the last leaf whenever the gate
    // is active). Chained with mmr_verify this proves an evicted bucket
    // against the committed lane digest. False when inactive (no V37P leaf).
    template <typename Resolver>
    bool mmr_root_proof(Resolver&& id_key, bytes32& leaf_out,
                        MerkleProof& proof_out) const {
        if (!mrr_active()) return false;
        auto leaves = build_leaves(id_key);
        leaf_out = leaves.back();
        proof_out = make_proof(leaves, static_cast<u64>(leaves.size() - 1));
        return true;
    }

    // Carry headroom (U256). One position's scaled work is w_raw (u64) x
    // InvD (< 4.0 in Q62, i.e. < 2^64) < 2^128. In frame B a share at
    // position p < B is worth at most 2^126 x lambda^(B-p), so the carry —
    // a sum over DISTINCT evicted positions — is bounded by the geometric
    // series 2^126 x sum_d lambda^d = 2^126 / (1 - lambda) ~ 2^126 x hl/ln2,
    // which is ~3117x one position's scaled work at hl = 2160 (< 2^12), i.e.
    // < 2^138; truncation only ever reduces it. 256 bits leave > 100 bits.
    static constexpr unsigned MRR_SCALED_BITS = 128;
    static constexpr unsigned MRR_GEOM_BITS = 12;     // 3117 < 4096 (hl <= 2838)
    static constexpr unsigned MRR_CARRY_BOUND_BITS = MRR_SCALED_BITS + MRR_GEOM_BITS;
    static_assert(MRR_CARRY_BOUND_BITS + 16 <= 256,
                  "v37: U256 lacks headroom for the MRR carry accumulation");

    // ── push: O(1) amortized (§7) ─────────────────────────────────────────
    // Canon signature. Byte-for-byte canon's push while the MRR gate is OFF.
    // Under an ACTIVE gate a CARRIED eviction needs the canonical identity
    // resolver (the evicted bucket's leaf is its "V37B" digest leaf, whose
    // comp_hash is in canonical-identity order) — use the overload below;
    // this one refuses such an eviction before mutating anything.
    void push(MinerId miner, u64 w_raw, std::uint32_t flags) {
        push(WorkAtom{miner, w_raw, flags, PROV_V37}, NoResolver{});
    }
    // MRR (v37, I-2): push with the canonical identity resolver
    // (bytes32 id_key(MinerId) — the same resolver digest() takes; the
    // Roundabout has it at push time via MinerIntern::key). SEAM NOTE
    // (S5-adjacent): under v1 the Roundabout must pass its resolver here.
    template <typename Resolver>
    void push(MinerId miner, u64 w_raw, std::uint32_t flags, Resolver&& id_key) {
        push(WorkAtom{miner, w_raw, flags, PROV_V37}, id_key);
    }
    // I-6 (MV-OQ1 = A): the version-agnostic atom push. The canon
    // signatures above are exactly this with PROV_V37, so an all-v37 stream
    // runs the canon path byte-for-byte. The tag is stored on the L0 slot
    // and folded into the bucket's provenance mix; it is NEVER an input to
    // w_scaled, the folds, the carry or a rebuild.
    void push(const WorkAtom& a) { push(a, NoResolver{}); }
    // S6-S7: the origin-bin push. The pre-window 3-argument signature above is
    // exactly this with the bins DROPPED, which is what makes the pre-gate
    // path byte-identical by construction: the admission emitter already knows
    // the origin height today and throws it away before calling the lane.
    void push(MinerId miner, u64 w_raw, u64 origin_bin, std::uint32_t flags) {
        WorkAtom a{miner, w_raw, flags, PROV_V37};
        a.origin_bin = origin_bin;
        a.carrier_bin = origin_bin;
        push(a, NoResolver{});
    }
    template <typename Resolver>
    void push(MinerId miner, u64 w_raw, u64 origin_bin, std::uint32_t flags,
              Resolver&& id_key) {
        WorkAtom a{miner, w_raw, flags, PROV_V37};
        a.origin_bin = origin_bin;
        a.carrier_bin = origin_bin;
        push(a, id_key);
    }
    template <typename Resolver>
    void push(const WorkAtom& a, Resolver&& id_key) {
        const MinerId miner = a.miner;
        const u64 w_raw = a.w_raw;
        const std::uint32_t flags = a.flags;
        if (w_raw == 0)
            throw std::invalid_argument("v37: zero-work share");
            // (a zero-weight acc entry would be committed by the digest but
            //  erased by undo_push — rewind would not be bit-exact)
        if (!prov_admissible(a.version))
            throw std::invalid_argument("v37: inadmissible share provenance "
                                        "(not one of v35 / v36 / v37)");
        // ── S12-R: the NATIVE RIDGE path. Guarded on the REAL push path (the
        // gate-OFF identity is non-vacuous): under nr_active() the positional
        // steps below do not run at all — no rebuild, no frame, no table read,
        // no whole-bucket eviction — the atom is credited by its origin bin
        // into the open level-0 cell (mechanism A) and the clock's move drives
        // folds / the exact-bin shed / the domain-edge drop, each journaled
        // (Op::Nr*) for the localized reorg undo.
        if (nr_active()) { nr_push(a, id_key); return; }
        // S12-R: the ACTIVATION SHARE (position nr_activation_pos) is the last
        // positional push; its carrier_bin is t0_bin (ruling K: the buried
        // mainchain height at the activation position) and the migration runs
        // at the END of this push, so nr_active() always implies a started
        // ridge. Decided before any mutation.
        const bool nr_activating =
            m_p.nr.nr_version == 1 && m_next_pos == m_p.nr.nr_activation_pos;
        if (nr_activating && a.carrier_bin == UINT64_MAX)
            throw std::invalid_argument("v37(nr): the ridge activation share "
                                        "needs its carrier_bin (t0_bin, ruling K)");
        // ── S6-S7: the window predicate is read ONCE, before anything is
        // touched, and drives the whole call. The push AT win_activation_pos
        // is the LAST positional push (win is false through its body); the
        // one-time activation migration runs at its END, so no single push
        // ever straddles the positional and the bin engine.
        const bool win = win_active() && m_win_started;
        u64 win_t_prev = m_t_now_bin;
        u64 win_bins_added = 0;
        if (win) {
            if (a.origin_bin == UINT64_MAX || a.carrier_bin == UINT64_MAX)
                throw std::invalid_argument("v37(win): an active window needs "
                                            "origin_bin and carrier_bin");
            if (a.origin_bin > a.carrier_bin)
                throw std::invalid_argument("v37(win): origin_bin above its "
                                            "carrier_bin (work in its carrier's "
                                            "future)");
            // Ruling H: the clock is the monotone-max of the carriers seen; a
            // RECEIPT credits its origin bin but never advances it. The
            // prospective clock is computed BEFORE any mutation so the burial
            // floor the expiry test sees is the one every node will see.
            const u64 prospective = a.is_receipt
                                        ? m_t_now_bin
                                        : std::max(m_t_now_bin, a.carrier_bin);
            // Ruling I: a share whose origin bin sits below the settled floor,
            // or above the clock that would deliver it, is a hard Expired —
            // decided BEFORE any mutation (a refused share does not move the
            // clock, so a rewind stays exact) and never a silent drop.
            if (a.origin_bin < m_B_bin || a.origin_bin > prospective)
                throw std::invalid_argument("v37(win): origin_bin outside the "
                                            "open window (Expired)");
            // Growing the clock materializes every intervening bin and runs the
            // bin-denominated rebuild / fold at the boundaries it crosses, so
            // the empty bins age exactly like the occupied ones.
            win_bins_added = win_grow_to(prospective);
            if (m_l0_bins.empty() ||
                a.origin_bin < m_l0_bins.front().bin ||
                a.origin_bin > m_l0_bins.back().bin)
                throw std::invalid_argument("v37(win): origin_bin names a bin "
                                            "the ring no longer holds (Expired)");
        } else {
            if (m_next_pos - m_B == m_p.epoch_len())
                epoch_rebuild();                          // (1) — clears journal
            if (m_l0.size() == m_p.c0)
                fold_l0();                                // (2)
        }
        cascade_folds();                                  // (3)

        u64 p = m_next_pos++;
        // ── the ONE and only scoring change: the index. Positional lane
        // InvD[pos - B]; bin window InvD[origin_bin - B_bin]. Same table, same
        // Q62 product, same range guard — only the monotone index it scales by
        // changes, which is why the golden decay table is reused bit-identical
        // and why late work decays exactly as if it had never been late.
        u64 j = win ? (a.origin_bin - m_B_bin) : (p - m_B);   // in [0, E)
        u128 w_scaled = u128(w_raw) * m_tab.inv_decay[j]; // Q62, fits u128
                                                          // (I-6: no version input)
        L0Slot s{p, w_raw, w_scaled, miner, flags, a.version,
                 win ? a.origin_bin : u64(0)};
        m_l0.push_back(s);                                // (4)
        if (win) win_bin_insert(s);                       // (4b) the bin ring
        m_acc[miner] += U256::from_u128(w_scaled);
        m_acc_total += U256::from_u128(w_scaled);
        m_raw_total += w_raw;
        m_l0_scaled_sum += U256::from_u128(w_scaled);
        m_l0_raw_sum += w_raw;
        if (!win) m_cover += 1;                           // positional cover only
        {
            Op op = Op::push(s);
            op.win_t_prev = win_t_prev;
            op.win_bins_added = win_bins_added;
            journal_push(std::move(op));
        }

        if (win) {
            // (5) TIME-denominated eviction: whole buckets while the bin span
            // exceeds the live width. Empty bins count toward the span, so a
            // quiet lane still ages its oldest band out.
            while (bin_span() > m_W_bins) evict_oldest_bucket(id_key);
        } else {
            while (m_cover > m_p.window)                  // (5) OQ-1
                evict_oldest_bucket(id_key);
        }
        // The one-time activation migration (ruling K), at the very end of the
        // last positional push: everything above this line is byte-for-byte the
        // pre-window lane, which is what makes the boundary replayable.
        if (!m_win_started && win_active()) win_migrate(a.carrier_bin);
        // S12-R: the one-time NR activation migration (journaled AFTER this
        // push's Push record: [Folds][Push][Evicts][NrMigrate]).
        if (nr_activating && nr_active() && !m_nr_started) nr_migrate(a.carrier_bin);
    }

    // ── queries ───────────────────────────────────────────────────────────
    // Decayed weight of one miner at the current head (O(1) + map lookup).
    // MRR (v37) — CARRY-ARITH: the arithmetic form of the carry term in
    // every payout read is an OPERATOR-PENDING ruling. The form implemented
    // here and PINNED by KAT-C1 is the RECOMMENDED one:
    //     acc.mul_q(f) + carry.mul_q(f)      (two truncating products, summed)
    // and NOT (acc + carry).mul_q(f): the two differ by truncation (KAT-C1
    // tallies the steps on which they do), so a different ruling re-pins the
    // v1 goldens but changes no structure. With an empty carry (gate OFF)
    // every result is the canon value bit-for-bit.
    U256 decayed_weight(MinerId m) const {
        if (nr_active()) {                       // S12-R: live + carry (two products)
            const auto& pm = nr_payout_map();
            auto it = pm.find(m);
            return it == pm.end() ? U256{} : it->second;
        }
        U256 out;
        u64 f = head_decay();
        auto it = m_acc.find(m);
        if (it != m_acc.end()) out += it->second.mul_q(f);
        auto ic = m_carry.find(m);
        if (ic != m_carry.end()) out += ic->second.mul_q(f);
        return out;
    }
    U256 decayed_total() const {
        if (nr_active()) {                       // S12-R
            U256 t;
            for (const auto& [m, w] : nr_payout_map()) { (void)m; t += w; }
            return t;
        }
        u64 f = head_decay();
        return m_acc_total.mul_q(f) + m_carry_total.mul_q(f);
    }

    // Full payout map: O(active miners) (§7).
    std::map<MinerId, U256> payout_map() const {
        if (nr_active()) return nr_payout_map();   // S12-R
        return payout_map_positional();
    }
    // The shipped read, byte-for-byte (also what the activation migration
    // freezes into the prologue record cell).
    std::map<MinerId, U256> payout_map_positional() const {
        std::map<MinerId, U256> out;
        u64 f = head_decay();
        for (const auto& [m, a] : m_acc) out[m] = a.mul_q(f);
        for (const auto& [m, c] : m_carry) out[m] += c.mul_q(f);   // pinned form (CARRY-ARITH)
        return out;
    }

    // Per-band raw delivered work over [lo, hi] positions, bucket-granular
    // at coarse levels (settlement-grade reading, F-1 / market §4.1).
    u128 raw_work_in_span(u64 lo, u64 hi) const {
        u128 sum = 0;
        for (const auto& s : m_l0)
            if (s.pos >= lo && s.pos <= hi) sum += s.w_raw;
        for (const auto& lvl : m_levels)
            for (const auto& b : lvl)
                if (b.pos_lo >= lo && b.pos_hi <= hi) sum += b.raw_work;
        return sum;
    }

    // ── reorg rewind (§6.2, OQ-7) ─────────────────────────────────────────
    // Rewind the last d pushes. Returns false when the journal cannot serve
    // the request (d > recorded pushes, or the span crosses an epoch-rebuild
    // boundary — the journal is cleared at rebuilds); the caller then does
    // the full lane rebuild from the tracker (the >D path).
    bool rewind(u64 d) {
        u64 pushes = 0;
        bool boundary = false;
        for (const auto& op : m_journal) {
            if (op.type == Op::Type::Push || op.type == Op::Type::NrCredit) ++pushes;
            else if (op.type == Op::Type::RebuildBoundary) boundary = true;
        }
        if (d > pushes) return false;
        // The push that TRIGGERED an epoch rebuild cannot be undone without
        // undoing the rebuild itself (the canonical pre-share state is the
        // pre-rebuild frame, which the journal cannot restore). When the
        // boundary sentinel is in the journal, the rebuild-triggering push
        // is the oldest journaled push — refuse to land on it.
        if (boundary && d == pushes) return false;
        u64 undone = 0;
        while (undone < d) {
            Op op = std::move(m_journal.back());
            m_journal.pop_back();
            if (op.type == Op::Type::RebuildBoundary)
                throw std::logic_error("v37: rewind crossed rebuild sentinel"
                                       " (guarded above — unreachable)");
            if (undo_op(op)) ++undone;
        }
        // One push() call journals [Folds][Push][Evicts]. The loop above
        // stops at the d-th Push; any folds IMMEDIATELY preceding it were
        // triggered by that same share's arrival and must be undone too —
        // the restored state is "before the share arrived", not "after its
        // folds". Trailing folds are unambiguous: nothing else sits between
        // a push's folds and its Push record.
        // (S12-R: the NR pre-ops too — see is_pre_op().)
        while (!m_journal.empty() && is_pre_op(m_journal.back().type)) {
            Op op = std::move(m_journal.back());
            m_journal.pop_back();
            undo_op(op);
        }
        m_nr_cache_ok = false;
        return true;
    }

    // ── digest (§8.5, OQ-4 + OQ-M5) — Merkle root, consensus-committed ────
    // CONSENSUS: intern ids are NODE-LOCAL (assigned at first global
    // sighting, which interleaves differently across lanes on different
    // nodes). All consensus bytes use the CANONICAL identity key
    // (PayoutDescriptor identity, 32 bytes) supplied by the resolver, sorted
    // by those bytes — never raw intern ids.
    //
    // OQ-M5 (resolved): the digest is the root of a Merkle tree over the
    // canonical leaves, so lite clients can verify one accumulator entry
    // (message-TTL budget) or one bucket's raw work (market settlement band)
    // with a log-size proof against the on-chain commitment. Tree rule:
    //   leaf node     = sha256d(0x00 || leaf payload)
    //   interior node = sha256d(0x01 || left || right)   (domain-separated)
    //   odd node      = promoted unchanged (no duplication ambiguity)
    // Leaf order (fixed): [0] header leaf (geometry, B, next_pos, counts,
    // L0 sums); then acc leaves in canonical-identity order; then bucket
    // leaves level-by-level, oldest -> newest.
    template <typename Resolver>  // bytes32 resolver(MinerId)
    bytes32 digest(Resolver&& id_key) const {
        return merkle_root(build_leaves(id_key));
    }

    // Inclusion proof for one miner's accumulator leaf (lite-client TTL
    // verification). Returns false if the miner has no acc entry.
    struct MerkleProof {
        u64 leaf_count = 0;
        u64 index = 0;
        std::vector<bytes32> path;  // siblings bottom-up; promote-odd levels
                                    // contribute no entry (structure is
                                    // derivable from leaf_count + index)
    };
    template <typename Resolver>
    bool acc_proof(MinerId m, Resolver&& id_key, bytes32& leaf_out,
                   MerkleProof& proof_out) const {
        if (!m_acc.count(m)) return false;
        auto leaves = build_leaves(id_key);
        // locate the miner's acc leaf: header is leaf 0; acc leaves follow
        // in canonical order — recompute its leaf hash and find it.
        bytes32 key = id_key(m);
        std::vector<std::uint8_t> payload;
        append_bytes(payload, "V37A", 4);
        payload.insert(payload.end(), key.begin(), key.end());
        append_u256(payload, m_acc.at(m));
        bytes32 target = leaf_hash(payload);
        u64 idx = 0;
        for (; idx < leaves.size(); ++idx)
            if (leaves[idx] == target) break;
        if (idx == leaves.size()) return false;
        leaf_out = target;
        proof_out = make_proof(leaves, idx);
        return true;
    }

    // Stateless verifier (what a lite client runs against the committed
    // root): recomputes the path using only leaf_count/index for structure.
    static bool verify_proof(const bytes32& root, const bytes32& leaf,
                             const MerkleProof& p) {
        bytes32 h = leaf;
        u64 idx = p.index, size = p.leaf_count;
        std::size_t used = 0;
        if (idx >= size || size == 0) return false;
        while (size > 1) {
            bool odd_last = (size & 1) && idx == size - 1;
            if (!odd_last) {
                if (used >= p.path.size()) return false;
                const bytes32& sib = p.path[used++];
                h = (idx & 1) ? interior_hash(sib, h) : interior_hash(h, sib);
            }
            idx /= 2;
            size = (size + 1) / 2;
        }
        return used == p.path.size() && h == root;
    }

    // ── OQ-2 exact epoch rebuild, exposed for tests/reference checks ──────
    // Re-derives every scaled quantity from durable records (w_raw + pos for
    // L0; immutable bucket records with the epoch-shift rule). This IS the
    // reference function the fast path re-converges to (§8.4).
    void epoch_rebuild() {
        // S6-S7: under the window the epoch boundary is BIN-denominated (the
        // clock crossing a full epoch of bins), not position-denominated. Both
        // are committed, positional facts about the chain, so every node
        // rebuilds at the identical share either way.
        const bool win = m_win_started;
        u64 B_new_bin = 0;
        if (win) {
            B_new_bin = m_B_bin + m_p.epoch_len();
            if (m_t_now_bin + 1 != B_new_bin)
                throw std::logic_error("v37(win): epoch_rebuild outside the bin "
                                       "epoch boundary");
        } else if (m_next_pos - m_B != m_p.epoch_len()) {
            throw std::logic_error("v37: epoch_rebuild outside the epoch "
                                   "boundary (positionally defined, §8.3)");
        }
        u64 B_new = m_B + m_p.epoch_len();
        m_acc.clear();
        m_acc_total = U256();
        m_l0_scaled_sum = U256();
        // L0: recompute from primary inputs, oldest -> newest. Under the
        // window the depth is the age of the share's own BIN in the new frame
        // (B_new_bin - origin_bin), so the re-based weight is a pure function
        // of the origin bin and arrival position cannot survive as a hidden
        // term across the rebuild.
        for (auto& s : m_l0) {
            u64 depth = win ? (B_new_bin - s.origin_bin) : (B_new - s.pos);
            if (win && depth >= m_tab.decay.size())
                throw std::logic_error("v37(win): rebuild depth beyond the decay "
                                       "table (a bin older than the table span "
                                       "is still live)");
            s.w_scaled = u128(s.w_raw) * m_tab.decay[depth];
            m_acc[s.miner] += U256::from_u128(s.w_scaled);
            m_acc_total += U256::from_u128(s.w_scaled);
            m_l0_scaled_sum += U256::from_u128(s.w_scaled);
        }
        // The bin ring holds the SAME primaries grouped by origin bin; the same
        // transform is applied to them so the two views cannot drift apart.
        if (win) {
            for (auto& lb : m_l0_bins) {
                lb.scaled_sum = U256();
                for (auto& e : lb.events) {
                    u64 depth = B_new_bin - e.origin_bin;
                    if (depth >= m_tab.decay.size())
                        throw std::logic_error("v37(win): rebuild depth beyond "
                                               "the decay table");
                    e.w_scaled = u128(e.w_raw) * m_tab.decay[depth];
                    lb.scaled_sum += U256::from_u128(e.w_scaled);
                }
            }
        }
        // Buckets: immutable; shifted by lambda^(E*age) at read.
        for (const auto& lvl : m_levels) {
            for (const auto& b : lvl) {
                u64 age = (B_new - b.epoch_tag) / m_p.epoch_len();
                u64 f = m_tab.epoch_shift[age];
                for (const auto& e : b.comp) {
                    U256 c = e.scaled.mul_q(f);
                    m_acc[e.miner] += c;
                    m_acc_total += c;
                }
            }
        }
        // MRR (v37): re-base the carry by exactly ONE epoch factor —
        // the same iterated truncating rule the epoch_shift ladder is
        // defined by (epoch_shift[i] = trunc(epoch_shift[i-1] * decay[E])).
        // Applied to the per-miner SUM (one mul_q per entry per rebuild),
        // and the total is re-summed from the shifted entries so the
        // carry_total == sum(carry) invariant is exact. No-op when empty.
        mrr_rebase_carry();
        m_B = B_new;
        if (win) {
            m_B_bin = B_new_bin;
            // Ruling E — the ONE-EPOCH LAG. The raw work accrued over the epoch
            // that just closed becomes the divisor of the NEXT retarget,
            // snapshotted AFTER the re-base and BEFORE the fresh epoch accrues
            // (the same "after the shift, before the insert" point the
            // checkpoint is taken at). It is that lag which makes the W_old
            // factor cancel, and the retarget converge instead of oscillate.
            m_raw_total_prev_epoch = m_raw_total;
            // Ruling F — the retarget cadence. The boundary bin is committed, so
            // every node recomputes the width at the identical bin.
            if (m_p.win.retarget_bins &&
                (m_B_bin % m_p.win.retarget_bins) == 0)
                win_retarget_width(m_B_bin);
        }
        // MRR (I-3, CKPT-OQ1): the committed checkpoint — AFTER the carry
        // shift, BEFORE the triggering insert (push() runs us first, then
        // inserts; next_pos == B_new here). Positional rule: every rebuild
        // whose new epoch base is at/after activation_pos; the default gate
        // (UINT64_MAX) never matches, so the gate-OFF path is canon's. Ring
        // of ckpt_retain (>= 2), oldest dropped.
        if (B_new >= m_p.mrr.activation_pos) {
            m_ckpts.push_back(make_checkpoint());
            while (m_ckpts.size() > m_p.mrr.ckpt_retain) m_ckpts.pop_front();
        }
        m_journal.clear();   // rewind cannot cross a rebuild (see notes)
        Op b2; b2.type = Op::Type::RebuildBoundary;
        m_journal.push_back(std::move(b2));  // sentinel: see rewind()
    }

private:
    // ── journal ───────────────────────────────────────────────────────────
    struct Op {
        enum class Type { Push, FoldL0, FoldLevel, Evict, RebuildBoundary,
                          // S12-R native-ridge ops
                          NrClock, NrFold, NrShed, NrDrop, NrWidth, NrCredit,
                          NrCkpt, NrMigrate };
        Type type;
        // Push
        L0Slot slot;
        // FoldL0 / FoldLevel / Evict
        Bucket bucket;                 // created (folds) or removed (evict)
        std::vector<L0Slot> folded_slots;     // FoldL0: removed L0 slots
        std::vector<Bucket> folded_children;  // FoldLevel: removed buckets
        std::size_t level_index = 0;          // FoldLevel/Evict: which level
        std::vector<std::pair<MinerId, U256>> subtracted;  // Evict: exact subs
        bool carried = false;   // MRR (v37): Evict also credited m_carry
                                // with the same `subtracted` amounts
        bool mmr_appended = false;  // MRR (I-2): Evict appended the bucket's
        PeakSet mmr_pre;            // leaf; the PRE-append peaks (O(log n))
                                    // so undo_evict truncates the range back
        // S6-S7 (window). Push: the clock and the bins this call materialized,
        // so an undo restores the clock exactly rather than approximately.
        // FoldL0: the bins the band consumed, so an undo restores the ring.
        // The journal is never digested, so these are digest-neutral outright.
        u64 win_t_prev = 0;
        u64 win_bins_added = 0;
        std::vector<L0Bin> folded_bins;
        // ── S12-R native-ridge payloads (default-empty; unused by the shipped ops) ──
        //   NrClock : nr_a = t_before, nr_flag = started_before
        //   NrFold  : nr_a = level, nr_b = parent idx          (undo re-derives the children)
        //   NrShed  : nr_a = bin, nr_fine = the erased rows, nr_flag = record cell;
        //             mmr_appended/mmr_pre iff the shed completed the cell
        //   NrDrop  : nr_a = level, nr_b = idx (or bin), nr_flag = record cell, nr_cell = the record
        //   NrWidth : nr_a = W_before
        //   NrCredit: nr_a = bin, nr_miner, nr_raw, nr_pos_lo_before  (undo re-derives the pair)
        //   NrCkpt  : ckpt_dropped / ckpt_front = the ring entry the retain rule dropped
        //   NrMigrate: the consumed positional prologue (restored verbatim on undo); nr_a = W_before
        //   NrWidth (S14, auto) : + nr_b = last_retarget_bin before,
        //             nr_raw = raw_cur before, nr_raw2 = raw_prev before,
        //             nr_dnet = D_net@base before, nr_flag = driven by the law
        //   NrCkpt  (S14)       : + nr_a = last_ckpt_bin before
        u64 nr_a = 0, nr_b = 0;
        bool nr_flag = false;
        MinerId nr_miner = 0;
        u128 nr_raw = 0;
        u128 nr_raw2 = 0;
        U256 nr_dnet;
        u64 nr_pos_lo_before = UINT64_MAX;
        nr::FineBin nr_fine;
        nr::Cell nr_cell;
        bool ckpt_dropped = false;
        Checkpoint ckpt_front;
        std::deque<L0Slot> mig_l0;
        std::vector<std::deque<Bucket>> mig_levels;
        std::map<MinerId, U256> mig_acc, mig_carry;
        U256 mig_acc_total, mig_l0_scaled_sum, mig_carry_total;
        u128 mig_raw_total = 0, mig_l0_raw_sum = 0;
        u64 mig_cover = 0;

        static Op push(const L0Slot& s) { Op o; o.type = Type::Push; o.slot = s; return o; }
    };
    // The ops that PRECEDE a push record inside one push() call (plus the
    // between-push NrWidth, attributed to the push that follows, and the
    // sentinel, kept adjacent so rewind() can still see it). NrMigrate is
    // NOT one: it FOLLOWS the activation share's Push record (like an Evict)
    // and is undone only when that push itself is undone.
    static bool is_pre_op(Op::Type t) {
        switch (t) {
            case Op::Type::FoldL0: case Op::Type::FoldLevel:
            case Op::Type::NrClock: case Op::Type::NrFold: case Op::Type::NrShed:
            case Op::Type::NrDrop: case Op::Type::NrWidth: case Op::Type::NrCkpt:
                return true;
            default:
                return false;
        }
    }
    // Undo one op; returns true iff it was a push record (Push / NrCredit).
    bool undo_op(const Op& op) {
        switch (op.type) {
            case Op::Type::Push:      undo_push(op);        return true;
            case Op::Type::FoldL0:    undo_fold_l0(op);     return false;
            case Op::Type::FoldLevel: undo_fold_level(op);  return false;
            case Op::Type::Evict:     undo_evict(op);       return false;
            case Op::Type::NrCredit:  nr_undo_credit(op);   return true;
            case Op::Type::NrClock:   nr_undo_clock(op);    return false;
            case Op::Type::NrFold:    nr_undo_fold(op);     return false;
            case Op::Type::NrShed:    nr_undo_shed(op);     return false;
            case Op::Type::NrDrop:    nr_undo_drop(op);     return false;
            case Op::Type::NrWidth:   nr_undo_width(op);    return false;
            case Op::Type::NrCkpt:    nr_undo_ckpt(op);     return false;
            case Op::Type::NrMigrate: nr_undo_migrate(op);  return false;
            case Op::Type::RebuildBoundary:
                throw std::logic_error("v37: undo of the rebuild sentinel (unreachable)");
        }
        return false;
    }

    // ── MRR carry helpers (v37) ──────────────────────────────────────
    void mrr_rebase_carry() {
        if (m_carry.empty()) return;
        const u64 dE = m_tab.decay[m_p.epoch_len()];
        U256 total;
        for (auto it = m_carry.begin(); it != m_carry.end();) {
            it->second = it->second.mul_q(dE);
            if (it->second.is_zero()) { it = m_carry.erase(it); continue; }
            total += it->second;
            ++it;
        }
        m_carry_total = total;
    }
    void mrr_check_headroom() const {
        // carry_total < 2^(MRR_CARRY_BOUND_BITS + 16) = 2^156: limb 3 zero,
        // limb 2 below 2^28. The analytic bound is 2^138 (see the header).
        constexpr unsigned limit = MRR_CARRY_BOUND_BITS + 16;
        static_assert(limit > 128 && limit < 192, "bound expressed in limb 2");
        if (m_carry_total.v[3] != 0 ||
            (m_carry_total.v[2] >> (limit - 128)) != 0)
            throw std::logic_error("v37: MRR carry exceeded its headroom bound");
    }

    u64 head_decay() const {
        // S6-S7: under the window the head factor is the age of the CLOCK,
        // lambda^(t_now_bin - B_bin), not the age of any arrival position. A
        // share-less advance of the buried height decays the head exactly as a
        // busy one does.
        if (m_win_started)
            return m_t_now_bin <= m_B_bin ? Q_ONE
                                          : m_tab.decay[m_t_now_bin - m_B_bin];
        // factor lambda^(H - B) with H = next_pos - 1; H - B in [0, E).
        if (m_next_pos == m_B) return Q_ONE;
        return m_tab.decay[(m_next_pos - 1) - m_B];
    }

    // rebuild_from_checkpoint: the replay lane was built gate-OFF; restore
    // the gate and row 0's from_pos (the activation position it was built
    // without).
    void restore_gates(const LaneParams& on) {
        m_p = on;
        m_segments[0].from_pos = on.mrr.activation_pos;
    }

    // ── S6-S7: the bin ring, the migration, the fold and the width law ────
    // Every function below runs ONLY under an active window gate. None of them
    // is reachable while win_version == 0, which is the whole gate-OFF
    // byte-identity argument.

    bool levels_empty() const {
        for (const auto& lvl : m_levels)
            if (!lvl.empty()) return false;
        return true;
    }

    // The oldest live bin = the smallest band low bin across the bucket levels
    // and the front of the bin ring. Recomputed after every fold and eviction
    // rather than tracked incrementally: it is a pure function of the ring, so
    // it cannot drift out of step with it.
    void recompute_oldest_live_bin() {
        u64 best = UINT64_MAX;
        for (const auto& lvl : m_levels)
            for (const auto& b : lvl) best = std::min(best, b.bin_lo);
        if (!m_l0_bins.empty()) best = std::min(best, m_l0_bins.front().bin);
        if (best != UINT64_MAX) m_oldest_live_bin = best;
    }

    // Advance the clock to `target`, MATERIALIZING every intervening bin. The
    // per-bin operation order mirrors the positional one (§8.3): (1) the epoch
    // rebuild when a full epoch of bins has elapsed, (2) the L0 fold when the
    // ring is full, then open the bin. A parent block that carried no share is
    // an empty bin that still ages, still occupies a ring slot and still counts
    // toward the span. Returns how many bins were opened, so an undo can close
    // exactly those again. Eviction is NOT run here: the caller runs it once,
    // after its insert, so one push journals [folds][push][evicts] exactly as
    // the positional path does and rewind's contract is unchanged.
    u64 win_grow_to(u64 target) {
        u64 opened = 0;
        while (m_t_now_bin < target) {
            const u64 nb = m_t_now_bin + 1;
            if (nb - m_B_bin == m_p.epoch_len()) epoch_rebuild();   // (1)
            if (m_l0_bins.size() == m_p.c0) fold_l0();              // (2)
            L0Bin lb;
            lb.bin = nb;
            m_l0_bins.push_back(std::move(lb));
            m_t_now_bin = nb;
            ++opened;
        }
        return opened;
    }

    // Credit an admitted slot to the bin its work was produced in. The ring is
    // contiguous, so the bin is addressed directly; push has already refused an
    // origin bin the ring no longer holds.
    void win_bin_insert(const L0Slot& s) {
        L0Bin& lb = m_l0_bins[static_cast<std::size_t>(s.origin_bin -
                                                       m_l0_bins.front().bin)];
        lb.events.push_back(s);
        lb.raw_sum += s.w_raw;
        lb.scaled_sum += U256::from_u128(s.w_scaled);
    }

    // Undo the bin-ring half of one push: take the slot back out of its bin
    // (it is that bin's last event, so the removal is exact), then close the
    // bins this push opened and restore the clock it advanced.
    void win_undo_push(const Op& op) {
        const L0Slot& s = op.slot;
        if (!m_l0_bins.empty() && s.origin_bin >= m_l0_bins.front().bin &&
            s.origin_bin <= m_l0_bins.back().bin) {
            L0Bin& lb = m_l0_bins[static_cast<std::size_t>(s.origin_bin -
                                                          m_l0_bins.front().bin)];
            if (!lb.events.empty()) {
                lb.events.pop_back();
                lb.raw_sum -= s.w_raw;
                lb.scaled_sum -= U256::from_u128(s.w_scaled);
            }
        }
        for (u64 i = 0; i < op.win_bins_added && !m_l0_bins.empty(); ++i)
            m_l0_bins.pop_back();
        m_t_now_bin = op.win_t_prev;
        recompute_oldest_live_bin();
    }

    // ── the bin-band fold (ruling G / §12) ────────────────────────────────
    // Fold the oldest R BINS — all of their events, and the empty ones too —
    // into one immutable bucket whose comp[] is the per-miner composition of
    // the whole band. Total raw work and per-worker composition are preserved
    // byte-exactly; only single-unit addressability of old work is dropped.
    void win_fold_l0() {
        Bucket b;
        b.epoch_tag = m_B;
        std::map<MinerId, CompEntry> agg;
        std::map<std::pair<ProtoVersion, MinerId>, u128> prov;   // I-6 rows
        Op op;
        op.type = Op::Type::FoldL0;
        op.level_index = 0;
        for (u64 i = 0; i < m_p.rollup; ++i) {
            L0Bin lb = m_l0_bins.front();
            m_l0_bins.pop_front();
            if (i == 0) b.bin_lo = lb.bin;
            b.bin_hi = lb.bin;
            b.scaled_sum += lb.scaled_sum;
            for (const auto& s : lb.events) {
                b.raw_work += s.w_raw;
                auto& e = agg[s.miner];
                e.miner = s.miner;
                e.scaled += U256::from_u128(s.w_scaled);
                e.raw += s.w_raw;
                if (s.version != PROV_V37) prov[{s.version, s.miner}] += s.w_raw;
                op.folded_slots.push_back(s);
            }
            op.folded_bins.push_back(std::move(lb));
        }
        std::sort(op.folded_slots.begin(), op.folded_slots.end(),
                  [](const L0Slot& x, const L0Slot& y) { return x.pos < y.pos; });
        // A folded band is a contiguous BIN range, NOT a contiguous position
        // range — a receipt can put an old bin's work at a young position — so
        // the flat ring is filtered by origin bin rather than drained from its
        // front. This is the fold's other half: leaving those slots live in the
        // flat ring while their value moved into the bucket would double-count
        // them at the next rebuild.
        std::deque<L0Slot> keep;
        for (const auto& s : m_l0) {
            if (s.origin_bin >= b.bin_lo && s.origin_bin <= b.bin_hi) {
                m_l0_scaled_sum -= U256::from_u128(s.w_scaled);
                m_l0_raw_sum -= s.w_raw;
            } else {
                keep.push_back(s);
            }
        }
        m_l0.swap(keep);
        // pos_lo/pos_hi keep their canon meaning (the position span the band's
        // events occupy). An EMPTY band has no positions of its own, so it is
        // stamped at the head — which also keeps the MRR whole-bucket carry
        // rule (pos_lo >= activation_pos) reading true for a band that closed
        // after the activation.
        if (!op.folded_slots.empty()) {
            b.pos_lo = op.folded_slots.front().pos;
            b.pos_hi = op.folded_slots.back().pos;
        } else {
            b.pos_lo = m_next_pos;
            b.pos_hi = m_next_pos;
        }
        for (auto& [m, e] : agg) b.comp.push_back(e);  // miner-id order
        b.prov = prov_rows(prov);                      // I-6: (version, miner) order
        op.bucket = b;
        m_levels[0].push_back(std::move(b));
        m_journal.push_back(std::move(op));
        recompute_oldest_live_bin();
        // acc is untouched: the fold relocates scaled value, it does not change it.
    }

    // Undo one bin-band fold: put the bins back at the front of the ring and
    // merge the folded slots back into the flat ring in position order.
    void win_undo_fold_l0(const Op& op) {
        m_levels[0].pop_back();
        for (auto it = op.folded_bins.rbegin(); it != op.folded_bins.rend(); ++it)
            m_l0_bins.push_front(*it);
        std::deque<L0Slot> merged;
        auto a = op.folded_slots.begin();
        auto b = m_l0.begin();
        while (a != op.folded_slots.end() || b != m_l0.end()) {
            if (b == m_l0.end() ||
                (a != op.folded_slots.end() && a->pos < b->pos)) {
                merged.push_back(*a);
                ++a;
            } else {
                merged.push_back(*b);
                ++b;
            }
        }
        m_l0.swap(merged);
        for (const auto& s : op.folded_slots) {
            m_l0_scaled_sum += U256::from_u128(s.w_scaled);
            m_l0_raw_sum += s.w_raw;
        }
        recompute_oldest_live_bin();
    }

    // ── the width law's call site (rulings D / E / F) ─────────────────────
    // One committed difficulty read at the boundary bin, then the pure law.
    // The value read is kept so the WIN1 leaf can commit it (ruling J).
    void win_retarget_width(u64 boundary_bin) {
        m_dnet_at_base = m_maindiff ? m_maindiff->difficulty_at_bin(boundary_bin)
                                    : U256();
        m_W_bins = winlaw::retarget_width(m_dnet_at_base, m_W_bins,
                                          m_raw_total_prev_epoch, m_p.win);
    }

    // ── the ONE-TIME activation migration (ruling K: seal-to-t0_bin) ──────
    // Runs at the END of the push AT win_activation_pos — the last positional
    // push — so the digest up to and including that share is byte-for-byte the
    // pre-window lane's, which is exactly what lets a cold from-genesis
    // replayer reach this point without ever consuming bin data.
    //
    // t0_bin is the buried parent height that share carried (ruling L: the
    // horizon is journal_depth deep). It is committed chain state, so every
    // node computes the identical value; the prologue disposition is then a
    // pure function of the byte-identical pre-gate state plus t0_bin, which is
    // why linear sync, a reorg rebuild across the boundary and a cold replay
    // all converge on the same post-activation state.
    //
    // Ruling K freezes the positional prologue as buckets and L0 events tagged
    // origin_bin == t0_bin: the whole pre-gate window ages TOGETHER from the
    // activation bin, each share keeping the weight it earned under the rule it
    // was earned under.
    void win_migrate(u64 t0_bin) {
        if (t0_bin == UINT64_MAX)
            throw std::invalid_argument("v37(win): the activation share must "
                                        "carry its carrier_bin (ruling K/L: it "
                                        "fixes t0_bin)");
        m_t0_bin = t0_bin;
        m_B_bin = t0_bin;
        m_t_now_bin = t0_bin;
        m_oldest_live_bin = t0_bin;
        m_W_bins = m_p.win.w_default_bins;   // ruling F bootstrap
        m_raw_total_prev_epoch = 0;          // degenerate until an epoch closes
        for (auto& lvl : m_levels)
            for (auto& bk : lvl) { bk.bin_lo = t0_bin; bk.bin_hi = t0_bin; }
        L0Bin lb;
        lb.bin = t0_bin;
        for (auto& s : m_l0) {
            s.origin_bin = t0_bin;
            lb.events.push_back(s);
            lb.raw_sum += s.w_raw;
            lb.scaled_sum += U256::from_u128(s.w_scaled);
        }
        m_l0_bins.clear();
        m_l0_bins.push_back(std::move(lb));
        m_win_started = true;
    }

    void journal_push(Op op) {
        m_journal.push_back(std::move(op));
        // Trim: keep ops back to (and including) the D-th most recent push,
        // PLUS that push's immediately preceding folds — rewind(D) must be
        // able to undo the full push() call it lands on.
        u64 pushes = 0;
        std::size_t keep_from = 0;
        for (std::size_t i = m_journal.size(); i-- > 0;) {
            if (m_journal[i].type == Op::Type::Push ||
                m_journal[i].type == Op::Type::NrCredit) {
                if (++pushes == m_p.journal_depth) { keep_from = i; break; }
            }
        }
        if (pushes < m_p.journal_depth || keep_from == 0) return;
        while (keep_from > 0 &&
               (is_pre_op(m_journal[keep_from - 1].type) ||
                m_journal[keep_from - 1].type == Op::Type::RebuildBoundary))
            --keep_from;
            // the boundary sentinel is kept when adjacent: rewind() must
            // still see it to refuse landing on the rebuild-triggering push
        if (keep_from > 0)
            m_journal.erase(m_journal.begin(),
                            m_journal.begin() + static_cast<long>(keep_from));
    }

    // ── fold: L0 -> level 1 (§4.1) ────────────────────────────────────────
    void fold_l0() {
        if (m_win_started) { win_fold_l0(); return; }
        Bucket b;
        b.epoch_tag = m_B;
        std::map<MinerId, CompEntry> agg;
        std::map<std::pair<ProtoVersion, MinerId>, u128> prov;   // I-6: non-v37 rows
        Op op; op.type = Op::Type::FoldL0; op.level_index = 0;
        for (u64 i = 0; i < m_p.rollup; ++i) {
            const L0Slot& s = m_l0.front();
            if (i == 0) b.pos_lo = s.pos;
            b.pos_hi = s.pos;
            b.scaled_sum += U256::from_u128(s.w_scaled);
            b.raw_work += s.w_raw;
            auto& e = agg[s.miner];
            e.miner = s.miner;
            e.scaled += U256::from_u128(s.w_scaled);
            e.raw += s.w_raw;
            if (s.version != PROV_V37) prov[{s.version, s.miner}] += s.w_raw;
            m_l0_scaled_sum -= U256::from_u128(s.w_scaled);
            m_l0_raw_sum -= s.w_raw;
            op.folded_slots.push_back(s);
            m_l0.pop_front();
        }
        for (auto& [m, e] : agg) b.comp.push_back(e);  // miner-id order
        b.prov = prov_rows(prov);                      // I-6: (version, miner) order
        op.bucket = b;
        m_levels[0].push_back(std::move(b));
        m_journal.push_back(std::move(op));
        // acc is untouched: fold relocates scaled value, it does not change it.
    }

    // ── fold cascade: level k -> k+1 when ring k is full ──────────────────
    void cascade_folds() {
        for (std::size_t k = 0; k + 1 < m_levels.size(); ++k) {
            if (m_levels[k].size() < m_p.level_caps[k]) continue;
            Bucket b;
            b.epoch_tag = m_B;
            std::map<MinerId, CompEntry> agg;
            std::map<std::pair<ProtoVersion, MinerId>, u128> prov;   // I-6
            Op op; op.type = Op::Type::FoldLevel; op.level_index = k;
            for (u64 i = 0; i < m_p.rollup; ++i) {
                Bucket child = m_levels[k].front();
                m_levels[k].pop_front();
                u64 age = (m_B - child.epoch_tag) / m_p.epoch_len();
                u64 f = m_tab.epoch_shift[age];
                if (i == 0) b.pos_lo = child.pos_lo;
                b.pos_hi = child.pos_hi;
                b.scaled_sum += child.scaled_sum.mul_q(f);
                b.raw_work += child.raw_work;
                for (const auto& e : child.comp) {
                    auto& a = agg[e.miner];
                    a.miner = e.miner;
                    a.scaled += e.scaled.mul_q(f);
                    a.raw += e.raw;
                }
                for (const auto& pe : child.prov) prov[{pe.version, pe.miner}] += pe.raw;   // I-6: raw merges
                op.folded_children.push_back(std::move(child));
            }
            for (auto& [m, e] : agg) b.comp.push_back(e);
            b.prov = prov_rows(prov);                          // I-6
            op.bucket = b;
            m_levels[k + 1].push_back(std::move(b));
            m_journal.push_back(std::move(op));
            // NOTE: shifting children to the current frame at fold changes
            // their stored frame; acc tracked them in their OLD frame, so a
            // truncation residual is created here. It is deterministic and
            // flushed at the next epoch rebuild (§4.2 determinism note) —
            // and with default L = 2 this path never runs.
        }
    }

    // ── eviction: whole outermost buckets (OQ-1) ──────────────────────────
    template <typename Resolver>
    void evict_oldest_bucket(Resolver&& id_key) {
        // Globally oldest bucket = the one with the smallest pos_lo across
        // all bucket levels (data is strictly ordered through the pyramid).
        // S6-S7: under the window "oldest" means oldest in TIME, so the
        // ordering key is the band's low bin. With one bucket level the two
        // agree; the bin key is what stays correct when a receipt puts an old
        // bin's work at a young position.
        const bool win = m_win_started;
        std::size_t best = SIZE_MAX;
        for (std::size_t k = 0; k < m_levels.size(); ++k) {
            if (m_levels[k].empty()) continue;
            if (best == SIZE_MAX ||
                (win ? (m_levels[k].front().bin_lo < m_levels[best].front().bin_lo)
                     : (m_levels[k].front().pos_lo < m_levels[best].front().pos_lo)))
                best = k;
        }
        if (best == SIZE_MAX) {
            // ⚠ REQUIRED-OPERATOR-RULING (WIN-R1) — see the patch header. The
            // bin-band pyramid folds a bucket every C0 BINS (ruling G keeps the
            // frozen pyramid), but ND-R3 struck the "W_MIN >= C0" clause, so
            // every ruled W_default (144..1440 bins) is far SHORTER than one
            // epoch of bins (4096). A window narrower than the fold cadence
            // reaches its eviction edge before any band has been folded, and
            // there is then no whole bucket to evict. The refusal is uniform on
            // every node — the conflict surfaces identically everywhere rather
            // than as a quiet divergence — and it is the shape ruling C's own
            // FLAG-1 was written in. It is NOT self-resolved here.
            if (win)
                throw std::logic_error("v37(win): the bin span exceeds W with no "
                                       "folded bucket to evict (W below the C0 "
                                       "fold cadence - RULING OWED)");
            throw std::logic_error("v37: cover > W with no buckets");
        }
        // MRR (v37): evict-to-carry. Whole-bucket rule — the bucket is
        // carried iff ALL its positions are >= activation_pos (pos_lo is the
        // smallest); the bucket straddling the activation is not carried.
        // (pos_lo >= activation_pos already implies mrr_active(): the head is
        // beyond pos_hi + W. The default UINT64_MAX never matches.)
        const bool carried = mrr_active() &&
                             m_levels[best].front().pos_lo >= m_p.mrr.activation_pos;
        // MRR (I-2): the evicted bucket's permanence leaf — formed from the
        // still-live bucket BEFORE any mutation, so a missing resolver
        // refuses with the lane untouched.
        bytes32 mmr_leaf{};
        if (carried) {
            if constexpr (std::is_same_v<std::decay_t<Resolver>, NoResolver>) {
                throw std::logic_error("v37: MRR-active carried eviction needs "
                                       "the canonical identity resolver "
                                       "(use push(miner, w_raw, flags, id_key))");
            } else {
                mmr_leaf = bucket_leaf(best, m_levels[best].front(), id_key);
            }
        }
        Bucket b = m_levels[best].front();
        m_levels[best].pop_front();
        u64 age = (m_B - b.epoch_tag) / m_p.epoch_len();
        u64 f = m_tab.epoch_shift[age];
        Op op; op.type = Op::Type::Evict; op.level_index = best;
        op.carried = carried;
        for (const auto& e : b.comp) {
            U256 sub = e.scaled.mul_q(f);
            m_acc[e.miner] -= sub;          // live acc is STILL subtracted (as canon)
            m_acc_total -= sub;
            if (m_acc[e.miner].is_zero()) m_acc.erase(e.miner);
            if (carried && !sub.is_zero()) {   // never create a zero carry row
                m_carry[e.miner] += sub;    // the SAME exact amount, separate ledger
                m_carry_total += sub;
            }
            op.subtracted.emplace_back(e.miner, sub);
        }
        if (carried) {
            mrr_check_headroom();
            // MRR (I-2): append the leaf; the op keeps the pre-append peaks.
            op.mmr_appended = true;
            op.mmr_pre = m_mmr;
            mmr_append(m_mmr, mmr_leaf);
        }
        m_raw_total -= b.raw_work;
        if (win) {
            // The bin span is DERIVED from the ring (t_now - oldest + 1), so
            // there is no second cover counter to keep in step with it — one
            // fewer divergence surface than the positional path carries.
            op.bucket = std::move(b);
            m_journal.push_back(std::move(op));
            recompute_oldest_live_bin();
            return;
        }
        m_cover -= (b.pos_hi - b.pos_lo + 1);
        op.bucket = std::move(b);
        m_journal.push_back(std::move(op));
    }

    // ── undo ops (exact bit-restoration; no rebuild in between by rule) ───
    void undo_push(const Op& op) {
        const L0Slot& s = op.slot;
        if (m_win_started) win_undo_push(op);
        m_l0.pop_back();
        m_acc[s.miner] -= U256::from_u128(s.w_scaled);
        if (m_acc[s.miner].is_zero()) m_acc.erase(s.miner);
        m_acc_total -= U256::from_u128(s.w_scaled);
        m_raw_total -= s.w_raw;
        m_l0_scaled_sum -= U256::from_u128(s.w_scaled);
        m_l0_raw_sum -= s.w_raw;
        if (!m_win_started) m_cover -= 1;
        m_next_pos -= 1;
    }
    void undo_fold_l0(const Op& op) {
        if (!op.folded_bins.empty()) { win_undo_fold_l0(op); return; }
        m_levels[0].pop_back();
        for (auto it = op.folded_slots.rbegin(); it != op.folded_slots.rend(); ++it) {
            m_l0.push_front(*it);
            m_l0_scaled_sum += U256::from_u128(it->w_scaled);
            m_l0_raw_sum += it->w_raw;
        }
    }
    void undo_fold_level(const Op& op) {
        m_levels[op.level_index + 1].pop_back();
        for (auto it = op.folded_children.rbegin();
             it != op.folded_children.rend(); ++it)
            m_levels[op.level_index].push_front(*it);
    }
    void undo_evict(const Op& op) {
        m_levels[op.level_index].push_front(op.bucket);
        for (const auto& [m, sub] : op.subtracted) {
            m_acc[m] += sub;
            m_acc_total += sub;
            if (op.carried && !sub.is_zero()) {   // MRR: debit the exact credit
                m_carry[m] -= sub;
                m_carry_total -= sub;
                if (m_carry[m].is_zero()) m_carry.erase(m);
            }
        }
        m_raw_total += op.bucket.raw_work;
        if (m_win_started) recompute_oldest_live_bin();
        else m_cover += (op.bucket.pos_hi - op.bucket.pos_lo + 1);
        if (op.mmr_appended) m_mmr = op.mmr_pre;   // MRR (I-2): truncate the range
    }

    // ── digest serialization helpers (fixed-width LE, §8.3) ───────────────
    static void append_bytes(std::vector<std::uint8_t>& b, const char* p, std::size_t n) {
        b.insert(b.end(), p, p + n);
    }
    static void append_u64(std::vector<std::uint8_t>& b, u64 x) {
        for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
    }
    static void append_u128(std::vector<std::uint8_t>& b, u128 x) {
        append_u64(b, static_cast<u64>(x));
        append_u64(b, static_cast<u64>(x >> 64));
    }
    static void append_u256(std::vector<std::uint8_t>& b, const U256& x) {
        for (int i = 0; i < 4; ++i) append_u64(b, x.v[i]);
    }
    // ── Merkle digest machinery (OQ-M5) ───────────────────────────────────
    static bytes32 leaf_hash(const std::vector<std::uint8_t>& payload) {
        std::vector<std::uint8_t> b;
        b.reserve(payload.size() + 1);
        b.push_back(0x00);
        b.insert(b.end(), payload.begin(), payload.end());
        return sha256d(b);
    }
    static bytes32 interior_hash(const bytes32& l, const bytes32& r) {
        std::uint8_t b[65];
        b[0] = 0x01;
        std::copy(l.begin(), l.end(), b + 1);
        std::copy(r.begin(), r.end(), b + 33);
        return sha256d(b, 65);
    }
    static bytes32 merkle_root(std::vector<bytes32> level) {
        // never empty: build_leaves always emits the header leaf
        while (level.size() > 1) {
            std::vector<bytes32> next;
            next.reserve((level.size() + 1) / 2);
            std::size_t i = 0;
            for (; i + 1 < level.size(); i += 2)
                next.push_back(interior_hash(level[i], level[i + 1]));
            if (i < level.size()) next.push_back(level[i]);  // promote odd
            level = std::move(next);
        }
        return level[0];
    }
    // Root of a perfect (power-of-two) leaf level — MMR peak computation.
    static bytes32 perfect_root(std::vector<bytes32> level) {
        while (level.size() > 1) {
            std::vector<bytes32> next;
            next.reserve(level.size() / 2);
            for (std::size_t i = 0; i + 1 < level.size(); i += 2)
                next.push_back(interior_hash(level[i], level[i + 1]));
            level = std::move(next);
        }
        return level[0];
    }
    static std::size_t popcount64(u64 x) {
        std::size_t c = 0;
        while (x) { x &= x - 1; ++c; }
        return c;
    }
    static MerkleProof make_proof(const std::vector<bytes32>& leaves, u64 idx) {
        MerkleProof p;
        p.leaf_count = static_cast<u64>(leaves.size());
        p.index = idx;
        std::vector<bytes32> level = leaves;
        while (level.size() > 1) {
            bool odd_last = (level.size() & 1) && idx == level.size() - 1;
            if (!odd_last) p.path.push_back(level[idx ^ 1]);
            std::vector<bytes32> next;
            next.reserve((level.size() + 1) / 2);
            std::size_t i = 0;
            for (; i + 1 < level.size(); i += 2)
                next.push_back(interior_hash(level[i], level[i + 1]));
            if (i < level.size()) next.push_back(level[i]);
            level = std::move(next);
            idx /= 2;
        }
        return p;
    }

    // Canonical leaf list — the fixed order every conforming node produces.
    template <typename Resolver>
    std::vector<bytes32> build_leaves(Resolver&& id_key) const {
        std::vector<bytes32> leaves;
        u64 bucket_total = 0;
        for (const auto& lvl : m_levels) bucket_total += lvl.size();
        leaves.reserve(1 + m_acc.size() + bucket_total +
                       (mrr_active() ? m_carry.size() + 1 : 0));
        {   // [0] header leaf: geometry (consensus parameters — a mismatch
            // becomes an attributable digest difference), position state,
            // counts, and the L0 ring sums (F-1 leaves).
            std::vector<std::uint8_t> h;
            append_bytes(h, "V37H", 4);
            append_u64(h, m_p.window);
            append_u64(h, m_p.c0);
            append_u64(h, m_p.rollup);
            append_u64(h, m_p.half_life);
            append_u64(h, static_cast<u64>(m_p.level_caps.size()));
            for (u64 c : m_p.level_caps) append_u64(h, c);
            append_u64(h, m_B);
            append_u64(h, m_next_pos);
            append_u64(h, static_cast<u64>(m_acc.size()));
            append_u64(h, static_cast<u64>(m_l0.size()));
            append_u256(h, m_l0_scaled_sum);
            append_u128(h, m_l0_raw_sum);
            for (const auto& lvl : m_levels)
                append_u64(h, static_cast<u64>(lvl.size()));
            if (mrr_active()) {
                // MRR (v37): the activation is digest-visible — appended
                // ONLY when active, so the gate-OFF header bytes are canon's.
                append_bytes(h, "MRR1", 4);
                append_u64(h, m_p.mrr.activation_pos);
                append_u64(h, static_cast<u64>(m_carry.size()));
                append_u256(h, m_carry_total);
                append_u64(h, m_mmr.leaf_count);   // I-2: V37H' mmr_leaf_count
                // I-3 (CKPT-OQ1): echo of the newest retained checkpoint's
                // digest (all-zero until the first active-epoch rebuild).
                const bytes32 ck = newest_checkpoint_digest(id_key);
                h.insert(h.end(), ck.begin(), ck.end());
            }
            if (win_active()) {
                // S6-S7 (ruling J): the window sub-block, appended to the SAME
                // header leaf and ONLY when active — no leaf index moves and a
                // win-OFF lane serializes zero new bytes. It commits the LIVE
                // width AND the two width-law inputs that produced it, so a
                // node that forges a width, or that read a different committed
                // difficulty, is an ATTRIBUTABLE digest divergence rather than
                // a silent fork. (m_W_bins alone would let a consistent-looking
                // width hide which inputs it came from.)
                append_bytes(h, "WIN1", 4);
                append_u64(h, m_t_now_bin);
                append_u64(h, m_B_bin);
                append_u64(h, m_oldest_live_bin);
                append_u64(h, m_W_bins);
                append_u128(h, m_raw_total_prev_epoch);
                append_u256(h, m_dnet_at_base);
            }
            if (nr_active()) {
                // S12-R: the native ridge is digest-visible — the "NRG1"
                // sub-block, appended ONLY under nr_active() and AFTER the
                // MRR1 block (geo/win are refused beside it, ND-R9). The
                // positional fields above are the RETIRED prologue's
                // (consumed at the activation: all empty / zero). ND-R7.
                append_bytes(h, "NRG1", 4);
                append_u64(h, m_p.nr.nr_activation_pos);
                append_u64(h, m_p.nr.nr_version);
                append_u64(h, m_p.nr.fold_cap);
                append_u64(h, m_p.nr.open_horizon_bins);
                // S14: the width law's own consensus constants ride in the
                // header, so a node running a different ND-R6 table produces a
                // different digest at the FIRST NR-active push rather than
                // silently paying a different window's decay.
                append_u64(h, m_p.nr.w_min_bins);
                append_u64(h, m_p.nr.w_max_bins);
                append_u64(h, m_p.nr.w_default_bins);
                append_u64(h, m_p.nr.coverage_blocks);
                append_u64(h, m_p.nr.bin_seconds);
                append_u64(h, m_p.nr.retarget_bins);
                append_u64(h, m_p.nr.ckpt_bins);
                append_u64(h, m_p.nr.n_ctx_bins ? m_p.nr.n_ctx_bins : nr::N_CTX_BINS);
                append_u64(h, m_W_bins);
                append_u64(h, m_nr_t);
                append_u64(h, nr_B_bin());
                append_u64(h, m_nr_t0);
                append_u64(h, static_cast<u64>(nr_cell_count()));
                append_u64(h, static_cast<u64>(nr_carried_cell_count()));
            }
            if (mrr_active()) {
                // I-6: the L0 ring's non-v37 provenance mix — the "V37V"
                // sub-block, appended LAST and ONLY when a non-v37 slot is
                // live in L0, so an all-v37 ring keeps the header bytes above
                // (canon's under OFF gates). No index moves.
                //
                // RULING-B (2026-09-10) — POSITION-GATED. The V37V emission
                // now rides the SAME activation gate as the rest of the V37.1
                // surface (mrr_active()); "the mix is non-empty" is no longer
                // sufficient on its own. Before this guard an atom tagged
                // PROV_V35 / PROV_V36 could move the lane digest of a
                // GATE-OFF lane: a pre-flip consensus surface any peer could
                // reach by setting one version byte, with no activation
                // position ever having been crossed. It cannot now — pre-flip
                // the header leaf carries canon's bytes for EVERY tag, so a
                // v35/v36 atom is byte-INERT until the operator's flip, and
                // the KAT-0 gate-OFF identity extends from all-v37 streams to
                // arbitrarily tagged ones. The provenance STATE is untouched
                // (l0_provenance(), prov_marked(), the bucket rows and the
                // I-2 permanence leaf all still carry the mix), so nothing is
                // lost; only the PRE-FLIP digest emission is withheld. At and
                // after the flip the bytes are exactly the ones above.
                const std::vector<ProvEntry> lp = l0_provenance();
                if (!lp.empty()) append_prov_block(h, lp, id_key);
            }
            leaves.push_back(leaf_hash(h));
        }
        {   // acc leaves, canonical-identity order
            std::vector<std::pair<bytes32, const U256*>> rows;
            rows.reserve(m_acc.size());
            for (const auto& [m, a] : m_acc) rows.emplace_back(id_key(m), &a);
            std::sort(rows.begin(), rows.end(),
                      [](const auto& a, const auto& b) { return a.first < b.first; });
            for (const auto& [k, a] : rows) {
                std::vector<std::uint8_t> b;
                append_bytes(b, "V37A", 4);
                b.insert(b.end(), k.begin(), k.end());
                append_u256(b, *a);
                leaves.push_back(leaf_hash(b));
            }
        }
        // bucket leaves, level-by-level, oldest -> newest (F-1 settlement
        // bands provable individually)
        for (std::size_t k = 0; k < m_levels.size(); ++k)
            for (const auto& bkt : m_levels[k])
                leaves.push_back(leaf_hash(
                    bucket_leaf_payload(k, bkt, id_key, mrr_active())));   // RULING-B
        if (nr_active()) {
            // S12-R: the IMMUTABLE SEAL RECORDS — one "NRC1" leaf per cell in
            // digest order (newest-first), then one "NRX1" carried-split leaf
            // per cell with a non-empty carried map, same order. A sealed
            // cell's NRC1 leaf is a FIXED byte string from its seal to its
            // deletion (KAT-ND12) and is the very leaf the MMR appends when
            // the cell becomes fully carried (I-2 permanence). The fine layer
            // is DERIVED and is NOT a leaf.
            const auto cs = nr_ordered_cells();
            for (const nr::Cell* c : cs)
                leaves.push_back(leaf_hash(nr_cell_leaf_payload(*c, id_key)));
            for (const nr::Cell* c : cs)
                if (!c->carried.empty())
                    leaves.push_back(leaf_hash(nr_carried_leaf_payload(*c, id_key)));
        }
        if (mrr_active()) {
            // MRR (v37): carry leaves AFTER the bucket leaves (acc leaf
            // indices are untouched), canonical-identity order, tag "V37C"
            // (shared with the I-3 checkpoint digest: append_carry_leaves).
            append_carry_leaves(leaves, m_carry, id_key);
            // MRR (I-2): the permanence root, always the LAST leaf when
            // active (an empty range commits leaf_count 0 + all-zero root).
            leaves.push_back(leaf_hash(mmr_root_payload(m_mmr.leaf_count,
                                                        mmr_bag(m_mmr.peaks))));
        }
        return leaves;
    }

    // The "V37C" carry leaves (key || U256 carry), canonical-identity order.
    template <typename Resolver>
    static void append_carry_leaves(std::vector<bytes32>& leaves,
                                    const std::map<MinerId, U256>& carry,
                                    Resolver&& id_key) {
        std::vector<std::pair<bytes32, const U256*>> rows;
        rows.reserve(carry.size());
        for (const auto& [m, c] : carry) rows.emplace_back(id_key(m), &c);
        std::sort(rows.begin(), rows.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        for (const auto& [k, c] : rows) {
            std::vector<std::uint8_t> b;
            append_bytes(b, "V37C", 4);
            b.insert(b.end(), k.begin(), k.end());
            append_u256(b, *c);
            leaves.push_back(leaf_hash(b));
        }
    }

    // MRR (I-3): the deterministic refusal text — a pure function of the
    // lane's retained ring and the call's arguments.
    std::string rebuild_fail_msg(const char* why, u64 fork_pos, u64 base_B,
                                 u64 tracker_lo, u64 start) const {
        auto d = [](u64 x) { return std::to_string(static_cast<unsigned long long>(x)); };
        std::string s = "v37: rebuild ";
        s += why;
        s += ": fork_pos=" + d(fork_pos) + " base_B=" + d(base_B) +
             " activation_pos=" + d(m_p.mrr.activation_pos) +
             " retained=" + d(static_cast<u64>(m_ckpts.size()));
        if (!m_ckpts.empty())
            s += "[" + d(m_ckpts.front().B) + ".." + d(m_ckpts.back().B) + "]";
        s += " tracker_lo=" + d(tracker_lo) + " replay_start=" + d(start);
        return s;
    }

    // The "V37B" bucket leaf payload (level, pos_lo, pos_hi, raw_work,
    // epoch_tag, comp_hash) — shared by build_leaves and the MMR leaf.
    // I-6: + the "V37V" provenance sub-block iff the bucket's mix is
    // non-empty (an all-v37 bucket's payload is canon's, 84 bytes). Because
    // this is the MMR leaf too, an evicted bucket's version mix is permanent.
    //
    // RULING-B (2026-09-10): `prov_active` POSITION-GATES that sub-block on
    // the LIVE digest path. build_leaves passes mrr_active(), so a pre-flip
    // bucket leaf is canon's 84 bytes whatever its rows are tagged. The
    // permanence path (bucket_leaf, the I-2 MMR leaf) passes true: it is
    // reachable ONLY from a carried eviction, which already implies
    // mrr_active(), and the evicted mix must stay permanent (I-6). The flag
    // is a PARAMETER, never a gate and never serialized.
    template <typename Resolver>
    static std::vector<std::uint8_t> bucket_leaf_payload(std::size_t k, const Bucket& bkt,
                                                         Resolver&& id_key, bool prov_active) {
        std::vector<std::uint8_t> b;
        append_bytes(b, "V37B", 4);
        append_u64(b, static_cast<u64>(k));
        append_u64(b, bkt.pos_lo);
        append_u64(b, bkt.pos_hi);
        append_u128(b, bkt.raw_work);
        append_u64(b, bkt.epoch_tag);
        auto ch = comp_hash(bkt, id_key);
        b.insert(b.end(), ch.begin(), ch.end());
        if (prov_active && !bkt.prov.empty())
            append_prov_block(b, bkt.prov, id_key);   // I-6, RULING-B position-gated
        return b;
    }

    // ── I-6 provenance helpers ────────────────────────────────────────────
    // The "V37V" sub-block: tag || row_count || rows, each row
    //   u64 version || 32-byte canonical key || u128 raw
    // in (version, canonical-identity) order — consensus bytes never see
    // intern ids, exactly like comp_hash. Fixed-width LE.
    static constexpr std::size_t V37V_PREAMBLE_BYTES = 4 + 8;
    static constexpr std::size_t V37V_ROW_BYTES = 8 + 32 + 16;
    static constexpr std::size_t V37B_BASE_PAYLOAD_BYTES = 4 + 8 + 8 + 8 + 16 + 8 + 32;
    template <typename Resolver>
    static void append_prov_block(std::vector<std::uint8_t>& b,
                                  const std::vector<ProvEntry>& prov, Resolver&& id_key) {
        std::vector<std::pair<std::pair<u64, bytes32>, const ProvEntry*>> rows;
        rows.reserve(prov.size());
        for (const auto& e : prov)
            rows.emplace_back(std::make_pair(static_cast<u64>(e.version), id_key(e.miner)), &e);
        std::sort(rows.begin(), rows.end(),
                  [](const auto& x, const auto& y) { return x.first < y.first; });
        append_bytes(b, "V37V", 4);
        append_u64(b, static_cast<u64>(rows.size()));
        for (const auto& [vk, e] : rows) {
            append_u64(b, vk.first);
            b.insert(b.end(), vk.second.begin(), vk.second.end());
            append_u128(b, e->raw);
        }
    }
    // (version, miner) -> raw map to the stored row form, (version, miner)
    // order (deterministic: the map's own order).
    static std::vector<ProvEntry> prov_rows(const std::map<std::pair<ProtoVersion, MinerId>, u128>& m) {
        std::vector<ProvEntry> out;
        out.reserve(m.size());
        for (const auto& [vm, raw] : m) out.push_back(ProvEntry{vm.first, vm.second, raw});
        return out;
    }

    // Composition hash, also in canonical-identity order (see digest()).
    template <typename Resolver>
    static bytes32 comp_hash(const Bucket& b, Resolver&& id_key) {
        std::vector<std::pair<bytes32, const CompEntry*>> rows;
        rows.reserve(b.comp.size());
        for (const auto& e : b.comp) rows.emplace_back(id_key(e.miner), &e);
        std::sort(rows.begin(), rows.end(),
                  [](const auto& a, const auto& c) { return a.first < c.first; });
        std::vector<std::uint8_t> buf;
        for (const auto& [k, e] : rows) {
            buf.insert(buf.end(), k.begin(), k.end());
            append_u256(buf, e->scaled);
            append_u128(buf, e->raw);
        }
        return sha256d(buf);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ── NATIVE RIDGE engine (S12 + S12-R) — private ─────────────────────────
    // Rules and record types: nr_ladder.hpp. Reference realization:
    // shadow_native_ridge.hpp (KAT-ND-EQ pins this engine against it).
    // ═══════════════════════════════════════════════════════════════════════
    static nr::RidgeDim nr_dims_of(const LaneParams& p) {
        nr::RidgeDim d;
        d.fold_cap = p.nr.fold_cap;
        d.half_life_bins = p.half_life;
        d.w_min_bins = p.nr.w_min_bins;
        d.w_max_bins = p.nr.w_max_bins;
        d.w_default_bins = p.nr.w_default_bins;
        d.open_horizon_bins = p.nr.open_horizon_bins;
        d.retarget_bins = p.nr.retarget_bins;   // S14: native to NrGate, not p.rollup
        d.ckpt_bins = p.nr.ckpt_bins;
        d.n_ctx_bins = p.nr.n_ctx_bins ? p.nr.n_ctx_bins : nr::N_CTX_BINS;
        d.damp_factor = 4;
        d.ladder.allow_digit_repeat = p.nr.allow_digit_repeat;
        return d;
    }
    // The S4 width law's constant set, VIEWED off NrGate (ND-R9: the window
    // gate is RETIRED, so the law may not read a gate that never fires). This
    // is a parameter view built per call — never a gate, never serialized. The
    // NUMBERS are nr::for_version(1, lane)'s, and they are the ones NRG1
    // commits, so a node running a different ND-R6 table forks visibly at its
    // first NR-active push instead of silently paying a different window.
    WinGate nr_width_params() const {
        WinGate w{};
        w.coverage_blocks = m_p.nr.coverage_blocks;
        w.bin_seconds     = m_p.nr.bin_seconds;
        w.w_min_bins      = m_p.nr.w_min_bins;
        w.w_default_bins  = m_p.nr.w_default_bins;
        w.w_max_bins      = m_p.nr.w_max_bins;
        w.retarget_bins   = m_p.nr.retarget_bins;
        w.damp_factor     = 4;                      // ND-R6, uniform
        return w;
    }
    nr::LadderOpts nr_ladder_opts() const {
        nr::LadderOpts o;
        o.allow_digit_repeat = m_p.nr.allow_digit_repeat;
        return o;
    }
    static std::vector<const nr::Cell*> nr_ordered_cells_of(
            const std::array<std::map<u64, nr::Cell>, nr::MAX_FOLD_CAP + 1>& cells,
            const std::map<u64, nr::Cell>& record) {
        std::vector<const nr::Cell*> cs;
        for (const auto& lvl : cells)
            for (const auto& [idx, c] : lvl) { (void)idx; cs.push_back(&c); }
        for (const auto& [b, c] : record) { (void)b; cs.push_back(&c); }
        std::sort(cs.begin(), cs.end(), [](const nr::Cell* a, const nr::Cell* c) {
            if (a->bin_hi != c->bin_hi) return a->bin_hi > c->bin_hi;
            if (a->level != c->level) return a->level > c->level;
            return a->record_only && !c->record_only;
        });
        return cs;
    }
    template <typename Resolver>
    static bytes32 nr_rows_hash(const std::map<MinerId, U256>& rows, Resolver&& id_key) {
        std::vector<std::pair<bytes32, const U256*>> rs;
        rs.reserve(rows.size());
        for (const auto& [m, w] : rows) rs.emplace_back(id_key(m), &w);
        std::sort(rs.begin(), rs.end(),
                  [](const auto& a, const auto& c) { return a.first < c.first; });
        std::vector<std::uint8_t> buf;
        for (const auto& [k, w] : rs) {
            buf.insert(buf.end(), k.begin(), k.end());
            append_u256(buf, *w);
        }
        return sha256d(buf);
    }

    // ── the push ──────────────────────────────────────────────────────────
    template <typename Resolver>
    void nr_push(const WorkAtom& a, Resolver&& id_key) {
        if constexpr (std::is_same_v<std::decay_t<Resolver>, NoResolver>) {
            (void)a;
            throw std::logic_error("v37: an NR-active push needs the canonical identity "
                                   "resolver (a fully carried cell's permanence leaf) — "
                                   "use push(atom, id_key)");
        } else {
            if (a.origin_bin == UINT64_MAX || a.carrier_bin == UINT64_MAX)
                throw std::invalid_argument("v37: NR push needs origin_bin / carrier_bin "
                                            "(set by the W2 admission emitter)");
            if (a.origin_bin > a.carrier_bin)
                throw std::invalid_argument("v37: NR origin_bin above its carrier_bin");
            // ── ADMISSION, decided BEFORE any mutation (ruling I: never silent).
            // Two attributable throws: the disposition authority is W2
            // (REJECT_EXPIRED / REJECT_SEALED — seam, flagged); the lane's
            // guards are the last-resort consensus fence.
            if (!m_nr_started)
                throw std::logic_error("v37: NR push before the activation migration "
                                       "(nr_active() must imply a started ridge)");
            const u64 H = m_p.nr.open_horizon_bins;
            const u64 prospective = a.is_receipt ? m_nr_t : std::max(m_nr_t, a.carrier_bin);
            const u64 W = m_W_bins;
            const u64 floor = prospective + 1 > W ? prospective - W + 1 : 0;
            if (a.origin_bin < floor)
                throw std::invalid_argument("v37: NR Expired — origin_bin below the burial "
                                            "floor B_bin (ruling I; W2 REJECT_EXPIRED)");
            if (nr::sealed_bin(a.origin_bin, prospective, H))
                throw std::invalid_argument("v37: NR Expired-sealed — origin_bin inside the "
                                            "settled past (paper §15; W2 REJECT_SEALED)");
            // ── F1 (S15): the FORWARD CLOCK JUMP, refused BEFORE any mutation.
            // RULED 2026-09-10. A carrier_bin that would drag t_now a whole
            // ladder domain (12288 bins at R=8) forward is refused here, in the
            // pre-mutation block, as an Expired disposition. It changes NO ruled
            // formula: it only decides admission, and the value it compares
            // against is a compile-time constant of the ratified golden.
            //
            // WHY IT MUST BE PRE-MUTATION (the wedge it closes): the tick order
            // (ND-R13) is folds -> retarget -> shed -> DROP -> scalars, so the
            // due folds are scored BEFORE the domain-edge drop can delete what
            // fell out of the ladder. A jump that puts a pending fold's group
            // end at age >= 12288 makes nr::lad() throw from INSIDE the tick,
            // after m_nr_t and the journal have already moved — the lane is then
            // permanently wedged: every subsequent honest push re-enters the
            // same tick and throws again. Measured pre-fix on a 400-push LTC-
            // shaped ridge: t_now moved 1133 -> 13420 and every later push died
            // with "ladder entry beyond the ratified golden domain".
            const u64 domain = nr::ladder_domain_bins();
            if (a.carrier_bin > m_nr_t && a.carrier_bin - m_nr_t >= domain)
                throw std::invalid_argument(
                    "v37: NR Expired — carrier_bin a whole ladder domain past the clock "
                    "(a forward clock jump; ruling I, W2 REJECT_EXPIRED)");
            // ND-R15b — SURFACED, NOT SELF-PICKED (see 05-NATIVE-RIDGE-SPEC §11).
            // The ruled bound above is measured from t_now, but the quantity the
            // tick actually needs in domain is the group end of every fold that
            // is still DUE — i.e. the oldest bin_hi among cells BELOW the fold
            // cap, which is what nr_fold_group scores before the drop runs. That
            // is <= t_now, so this clause is a strict SUBSET of the admissible
            // set the ruled clause leaves, never a superset: it rejects the
            // residual band [oldest_unfolded_hi + domain, t_now + domain) that
            // the ruled bound alone still lets through (measured: 14 bins wide
            // on the KAT lane; in general ~ H_open + R^LAMBDA). It costs nothing
            // in normal operation — an unfolded cell is at most H_open + R^LAMBDA
            // bins old — and it is what makes "a refused push can never leave the
            // ridge half-applied" literally true. It is a FENCE (it only ever
            // refuses), it changes no weight, no width and no digest, and the
            // operator can drop it, keep it, or replace it by moving the drop
            // ahead of the folds in the ND-R13 tick order.
            const u64 unfolded_hi = nr_oldest_unfolded_bin_hi();
            if (unfolded_hi != UINT64_MAX && a.carrier_bin > unfolded_hi &&
                a.carrier_bin - unfolded_hi >= domain)
                throw std::invalid_argument(
                    "v37: NR Expired — carrier_bin a whole ladder domain past the oldest "
                    "cell still awaiting its fold (forward clock jump, ND-R15b fence)");
            // ── mutation; every step journals ──
            // S14 tick order (ND-R13): clock -> folds -> RETARGET -> shed ->
            // drop -> scalars -> CHECKPOINT -> position -> credit. The
            // retarget sits BEFORE the shed so the period's eviction happens
            // under the width that period elected; the checkpoint sits LAST
            // so it records the settled post-tick state.
            ++m_nr_branch_hits;
            // The CHECKPOINT is taken at the position boundary IMMEDIATELY
            // BEFORE the tick that opens a new cadence period — not at the end
            // of that tick. Cadence is still decided from the bin clock (the
            // prospective clock this push would install), but the recorded
            // state is the committed state AT next_pos, which is exactly what
            // ckpt_at() promises and what rebuild_from_checkpoint installs and
            // replays from. Taking it after the tick makes the record the
            // state of a HALF-APPLIED push, and a rebuild that forks exactly
            // at the checkpoint position then lands one tick ahead of the
            // linear lane. (KAT-ND11 found this: forks landing exactly on a
            // checkpoint diverged while forks a few pushes past it converged,
            // because the clock move is idempotent on replay.)
            nr_maybe_checkpoint(prospective);
            {
                Op oc; oc.type = Op::Type::NrClock;
                oc.nr_a = m_nr_t; oc.nr_flag = m_nr_started;
                m_journal.push_back(std::move(oc));
            }
            if (prospective > m_nr_t) {
                m_nr_t = prospective;
                nr_after_clock_move(a, id_key);
            }
            nr_credit(a, m_next_pos);
            m_nr_raw_cur += a.w_raw;        // S14: the width law's period accumulator
            m_next_pos += 1;
            ++m_nr_pushes;
            m_nr_cache_ok = false;
        }
    }

    // ── the activation migration (ruling K under NR; ND-R10) ──────────────
    // Runs at the END of the activation share's push. Consumes the positional
    // prologue into ONE record-only level-0 cell at t0_bin (= the activation
    // share's carrier_bin) whose composition is the shipped payout read at
    // the flip (the pinned two-product form, carry included) and whose
    // raw_work is the prologue's raw total. The prologue state is moved into
    // the op so a rewind across the activation restores it verbatim.
    void nr_migrate(u64 t0) {
        Op om; om.type = Op::Type::NrMigrate;
        nr::Cell cell;
        cell.level = 0;
        cell.bin_lo = cell.bin_hi = t0;
        cell.record_only = true;
        cell.G = Q_ONE;
        for (auto& [m, w] : payout_map_positional())
            if (!w.is_zero()) cell.comp[m] = w;
        cell.raw_work = m_raw_total;
        {
            std::map<std::pair<ProtoVersion, MinerId>, u128> pv;
            for (const auto& s : m_l0)
                if (s.version != PROV_V37) pv[{s.version, s.miner}] += s.w_raw;
            for (const auto& lvl : m_levels)
                for (const auto& b : lvl)
                    for (const auto& pe : b.prov) pv[{pe.version, pe.miner}] += pe.raw;
            for (const auto& [vm, raw] : pv)
                cell.prov.push_back(nr::ProvRow{vm.first, vm.second, raw});
        }
        om.mig_l0 = std::move(m_l0);            m_l0.clear();
        om.mig_levels = m_levels;               for (auto& l : m_levels) l.clear();
        om.mig_acc = std::move(m_acc);          m_acc.clear();
        om.mig_acc_total = m_acc_total;         m_acc_total = U256();
        om.mig_raw_total = m_raw_total;         m_raw_total = 0;
        om.mig_l0_scaled_sum = m_l0_scaled_sum; m_l0_scaled_sum = U256();
        om.mig_l0_raw_sum = m_l0_raw_sum;       m_l0_raw_sum = 0;
        om.mig_cover = m_cover;                 m_cover = 0;
        om.mig_carry = std::move(m_carry);      m_carry.clear();
        om.mig_carry_total = m_carry_total;     m_carry_total = U256();
        om.nr_a = m_W_bins;
        if (cell.raw_work != 0 || !cell.comp.empty()) m_nr_record[t0] = std::move(cell);
        m_nr_started = true;
        m_nr_t = t0;
        m_nr_t0 = t0;
        m_W_bins = m_p.nr.w_default_bins;
        // S14: the bin-clock cadences are anchored at the flip's own period
        // boundaries, so the first retarget / checkpoint fires at the first
        // tick that LEAVES the activation period — never at the flip itself
        // (there is no prior period to lag against, ruling E).
        m_nr_last_retarget_bin = (t0 / m_p.nr.retarget_bins) * m_p.nr.retarget_bins;
        m_nr_last_ckpt_bin     = (t0 / m_p.nr.ckpt_bins) * m_p.nr.ckpt_bins;
        m_nr_raw_cur = 0;
        m_nr_raw_prev = 0;
        m_nr_dnet_at_base = U256();
        m_journal.push_back(std::move(om));
    }
    void nr_undo_migrate(const Op& op) {
        for (const auto& lvl : m_nr_cells)
            if (!lvl.empty())
                throw std::logic_error("v37: NR migration undo with live cells (journal order)");
        if (!m_nr_fine.empty())
            throw std::logic_error("v37: NR migration undo with a live fine layer (journal order)");
        m_nr_record.clear();
        m_l0 = op.mig_l0;
        m_levels = op.mig_levels;
        m_acc = op.mig_acc;
        m_acc_total = op.mig_acc_total;
        m_raw_total = op.mig_raw_total;
        m_l0_scaled_sum = op.mig_l0_scaled_sum;
        m_l0_raw_sum = op.mig_l0_raw_sum;
        m_cover = op.mig_cover;
        m_carry = op.mig_carry;
        m_carry_total = op.mig_carry_total;
        m_W_bins = op.nr_a;
        m_nr_started = false;
        m_nr_t = 0;
        m_nr_t0 = 0;
        m_nr_last_retarget_bin = 0;     // S14: the cadence anchors go with it
        m_nr_last_ckpt_bin = 0;
        m_nr_raw_cur = 0;
        m_nr_raw_prev = 0;
        m_nr_dnet_at_base = U256();
    }

    // ── the clock move: folds, shed, drop, scalars — in the consensus order ─
    template <typename Resolver>
    void nr_after_clock_move(const WorkAtom& a, Resolver&& id_key) {
        nr_run_due_folds();
        nr_maybe_retarget(a);          // S14 (ND-R13): before the shed
        nr_shed_below_floor(id_key);
        nr_drop_beyond_domain();
        nr_refresh_scalars();
        m_nr_cache_ok = false;
    }
    // The PRIVATE clock reset for the rewind path (the verdict's item 2b):
    // the public S1 advance_clock keeps its monotone clamp; only an undo may
    // move the clock backwards, and it re-derives every scalar from the
    // ladder afterwards (G is a pure function of the clock).
    void nr_reset_clock_for_rewind(u64 t_before, bool started_before) {
        m_nr_t = t_before;
        m_nr_started = started_before;
        nr_refresh_scalars();
    }
    void nr_undo_clock(const Op& op) { nr_reset_clock_for_rewind(op.nr_a, op.nr_flag); }

    void nr_refresh_scalars() {
        const nr::LadderOpts lo = nr_ladder_opts();
        for (auto& lvl : m_nr_cells)
            for (auto& [idx, c] : lvl) { (void)idx; c.G = nr::cell_scalar(m_nr_t, c.bin_hi, lo); }
        for (auto& [b, c] : m_nr_record) { (void)b; c.G = nr::cell_scalar(m_nr_t, c.bin_hi, lo); }
    }

    nr::Cell* nr_find_owner(u64 bin) {
        for (u64 l = m_p.nr.fold_cap; l >= 1; --l) {
            auto& lvl = m_nr_cells[static_cast<std::size_t>(l)];
            auto it = lvl.find(bin / nr::pow_R(l));
            if (it != lvl.end()) return &it->second;
        }
        auto it0 = m_nr_cells[0].find(bin);
        return it0 == m_nr_cells[0].end() ? nullptr : &it0->second;
    }

    // Build the level-`level` cell idx from the FINE LAYER (the authority):
    // the pure function every fold, every fold-undo and the reference share.
    bool nr_build_cell_from_fine(u64 level, u64 idx, nr::Cell& P) {
        const nr::LadderOpts lo = nr_ladder_opts();
        const u64 span = nr::pow_R(level);
        const u64 p_lo = idx * span, p_hi = p_lo + span - 1;
        P = nr::Cell{};
        P.level = level;
        P.bin_lo = p_lo;
        P.bin_hi = p_hi;
        bool any = false;
        std::map<nr::ProvKey, u128> pv;
        for (auto it = m_nr_fine.lower_bound(p_lo);
             it != m_nr_fine.end() && it->first <= p_hi; ++it) {
            any = true;
            P.raw_work += it->second.raw_sum;
            for (auto& [mid, p] : it->second.rows) {
                p.v = nr::pair_value(it->first, p.raw, P, lo);
                P.comp[mid] += p.v;
            }
            for (const auto& [k, raw] : it->second.prov) pv[k] += raw;   // I-6: pure function too
        }
        P.prov = nr::prov_rows_of(pv);
        P.G = nr::cell_scalar(m_nr_t, p_hi, lo);
        return any;
    }

    // ── FOLD under the SEALED rule (mechanism A) ──────────────────────────
    void nr_run_due_folds() {
        const u64 H = m_p.nr.open_horizon_bins;
        for (u64 l = 1; l <= m_p.nr.fold_cap; ++l) {
            const u64 pspan = nr::pow_R(l);
            auto& child = m_nr_cells[static_cast<std::size_t>(l - 1)];
            std::vector<u64> due;
            for (const auto& [key, c] : child) {
                (void)key;
                const u64 pidx = c.bin_lo / pspan;
                if (nr::sealed_bin((pidx + 1) * pspan - 1, m_nr_t, H) &&
                    (due.empty() || due.back() != pidx))
                    due.push_back(pidx);
            }
            for (u64 pidx : due) nr_fold_group(l, pidx);
        }
    }
    void nr_fold_group(u64 level, u64 pidx) {
        auto& child = m_nr_cells[static_cast<std::size_t>(level - 1)];
        const u64 c_lo = pidx * nr::ROLLUP, c_hi = c_lo + nr::ROLLUP - 1;
        for (auto it = child.lower_bound(c_lo); it != child.end() && it->first <= c_hi;) {
            if (!it->second.carried.empty())
                throw std::logic_error("v37: NR fold of a carried child (fold-before-shed)");
            it = child.erase(it);
        }
        nr::Cell P;
        if (!nr_build_cell_from_fine(level, pidx, P))
            throw std::logic_error("v37: NR fold group with children but no fine layer");
        m_nr_cells[static_cast<std::size_t>(level)][pidx] = std::move(P);
        Op of; of.type = Op::Type::NrFold; of.nr_a = level; of.nr_b = pidx;
        m_journal.push_back(std::move(of));
        m_nr_cache_ok = false;
    }
    // Undo: erase the parent and RE-MATERIALIZE its children from the fine
    // layer at level-1 with the pair value in the child frame — a pure
    // function, so bit-identical to the pre-fold state (KAT-ND10b).
    void nr_undo_fold(const Op& op) {
        const u64 level = op.nr_a, pidx = op.nr_b;
        auto& lvl = m_nr_cells[static_cast<std::size_t>(level)];
        auto it = lvl.find(pidx);
        if (it == lvl.end())
            throw std::logic_error("v37: NR fold undo — parent cell missing");
        if (!it->second.carried.empty())
            throw std::logic_error("v37: NR fold undo — parent carried (journal order)");
        lvl.erase(it);
        const u64 pspan = nr::pow_R(level);
        const u64 p_lo = pidx * pspan, p_hi = p_lo + pspan - 1;
        auto& child = m_nr_cells[static_cast<std::size_t>(level - 1)];
        if (level - 1 == 0) {
            for (auto f = m_nr_fine.lower_bound(p_lo); f != m_nr_fine.end() && f->first <= p_hi; ++f) {
                nr::Cell c;
                nr_build_cell_from_fine(0, f->first, c);
                child[f->first] = std::move(c);
            }
        } else {
            for (u64 cidx = pidx * nr::ROLLUP; cidx < pidx * nr::ROLLUP + nr::ROLLUP; ++cidx) {
                nr::Cell c;
                if (nr_build_cell_from_fine(level - 1, cidx, c)) child[cidx] = std::move(c);
            }
        }
        m_nr_cache_ok = false;
    }

    // ── SHED as the CARRIED SPLIT (mechanism B) ───────────────────────────
    template <typename Resolver>
    void nr_shed_below_floor(Resolver&& id_key) {
        const u64 floor = nr_B_bin();
        while (!m_nr_fine.empty() && m_nr_fine.begin()->first < floor) {
            auto it = m_nr_fine.begin();
            const u64 b = it->first;
            nr::Cell* cp = nr_find_owner(b);
            if (!cp) throw std::logic_error("v37: NR shed of a bin with no owning cell");
            nr::Cell& c = *cp;
            Op os; os.type = Op::Type::NrShed; os.nr_a = b;
            os.nr_fine = std::move(it->second);
            for (const auto& [mid, p] : os.nr_fine.rows) c.carried[mid] += p.v;   // the IDENTICAL value
            c.carried_raw += os.nr_fine.raw_sum;
            m_nr_fine.erase(it);
            if (c.fully_carried()) nr_on_full_carry(c, os, id_key);
            m_journal.push_back(std::move(os));
        }
        for (auto& [bin, c] : m_nr_record) {
            if (bin >= floor || c.fully_carried()) continue;
            Op os; os.type = Op::Type::NrShed; os.nr_a = bin; os.nr_flag = true;
            c.carried = c.comp;                    // the whole record leaves the window at once
            c.carried_raw = c.raw_work;
            nr_on_full_carry(c, os, id_key);
            m_journal.push_back(std::move(os));
        }
        m_nr_cache_ok = false;
    }
    // I-2 permanence: the cell's seal leaf is appended the tick it becomes
    // fully carried (mirrors the shipped evict-time append + journaled
    // mmr_pre undo). The leaf bytes were final at the seal; only the timing
    // of the permanence root's move is decided here.
    template <typename Resolver>
    void nr_on_full_carry(const nr::Cell& c, Op& os, Resolver&& id_key) {
        if (c.carried != c.comp)
            throw std::logic_error("v37: NR fully carried cell with carried != comp");
        os.mmr_appended = true;
        os.mmr_pre = m_mmr;
        mmr_append(m_mmr, leaf_hash(nr_cell_leaf_payload(c, id_key)));
        ++m_nr_full_carries;
    }
    void nr_undo_shed(const Op& op) {
        if (op.nr_flag) {
            auto it = m_nr_record.find(op.nr_a);
            if (it == m_nr_record.end())
                throw std::logic_error("v37: NR shed undo — record cell missing");
            it->second.carried.clear();
            it->second.carried_raw = 0;
        } else {
            nr::Cell* cp = nr_find_owner(op.nr_a);
            if (!cp) throw std::logic_error("v37: NR shed undo — owning cell missing");
            for (const auto& [mid, p] : op.nr_fine.rows) {
                auto ci = cp->carried.find(mid);
                if (ci == cp->carried.end())
                    throw std::logic_error("v37: NR shed undo — carried row missing");
                ci->second -= p.v;
                if (ci->second.is_zero()) cp->carried.erase(ci);
            }
            cp->carried_raw -= op.nr_fine.raw_sum;
            m_nr_fine[op.nr_a] = op.nr_fine;
        }
        if (op.mmr_appended) { m_mmr = op.mmr_pre; --m_nr_full_carries; }
        m_nr_cache_ok = false;
    }

    // ── the ladder-domain edge: deterministic deletion ────────────────────
    void nr_drop_beyond_domain() {
        const u64 edge = nr::ladder_domain_bins();
        for (u64 l = 0; l <= m_p.nr.fold_cap; ++l) {
            auto& lvl = m_nr_cells[static_cast<std::size_t>(l)];
            for (auto it = lvl.begin(); it != lvl.end();) {
                if (m_nr_t >= it->second.bin_hi + edge) {
                    if (!it->second.fully_carried())
                        throw std::logic_error("v37: NR domain-edge drop of a cell with live bins");
                    Op od; od.type = Op::Type::NrDrop; od.nr_a = l; od.nr_b = it->first;
                    od.nr_cell = std::move(it->second);
                    it = lvl.erase(it);
                    m_journal.push_back(std::move(od));
                    ++m_nr_dropped;
                } else ++it;
            }
        }
        for (auto it = m_nr_record.begin(); it != m_nr_record.end();) {
            if (m_nr_t >= it->second.bin_hi + edge) {
                if (!it->second.fully_carried())
                    throw std::logic_error("v37: NR domain-edge drop of a live record cell");
                Op od; od.type = Op::Type::NrDrop; od.nr_a = 0; od.nr_b = it->first; od.nr_flag = true;
                od.nr_cell = std::move(it->second);
                it = m_nr_record.erase(it);
                m_journal.push_back(std::move(od));
                ++m_nr_dropped;
            } else ++it;
        }
        m_nr_cache_ok = false;
    }
    void nr_undo_drop(const Op& op) {
        if (op.nr_flag) m_nr_record[op.nr_b] = op.nr_cell;
        else m_nr_cells[static_cast<std::size_t>(op.nr_a)][op.nr_b] = op.nr_cell;
        --m_nr_dropped;
        m_nr_cache_ok = false;
    }

    // ── CREDIT into the open level-0 cell (mechanism A) ───────────────────
    void nr_credit(const WorkAtom& a, u64 pos) {
        const u64 bin = a.origin_bin;
        if (nr_sealed(bin))
            throw std::logic_error("v37: NR credit into a sealed bin (guarded by admission)");
        const nr::LadderOpts lo = nr_ladder_opts();
        nr::Cell& c = m_nr_cells[0][bin];
        if (c.raw_work == 0 && c.comp.empty()) {
            c.level = 0;
            c.bin_lo = c.bin_hi = bin;
            c.G = nr::cell_scalar(m_nr_t, bin, lo);
        }
        nr::FineBin& fb = m_nr_fine[bin];
        Op oc; oc.type = Op::Type::NrCredit;
        oc.nr_a = bin; oc.nr_miner = a.miner; oc.nr_raw = a.w_raw; oc.nr_pos_lo_before = fb.pos_lo;
        fb.bin = bin;
        fb.raw_sum += a.w_raw;
        if (pos < fb.pos_lo) fb.pos_lo = pos;
        nr::FinePair& p = fb.rows[a.miner];
        const U256 old_v = p.v;
        p.raw += a.w_raw;
        p.v = nr::pair_value(bin, p.raw, c, lo);
        U256& cm = c.comp[a.miner];
        cm -= old_v;
        cm += p.v;
        c.raw_work += a.w_raw;
        if (a.version != PROV_V37) {                    // I-6: provenance, in the FINE layer
            fb.prov[{a.version, a.miner}] += a.w_raw;
            c.prov = nr::prov_rows_of(fb.prov);         // level 0: one bin == the cell
            oc.nr_flag = true;
            oc.nr_b = a.version;
        }
        journal_push(std::move(oc));
        m_nr_cache_ok = false;
    }
    void nr_undo_credit(const Op& op) {
        const u64 bin = op.nr_a;
        auto ci = m_nr_cells[0].find(bin);
        auto fi = m_nr_fine.find(bin);
        if (ci == m_nr_cells[0].end() || fi == m_nr_fine.end())
            throw std::logic_error("v37: NR credit undo — open cell / fine bin missing");
        nr::Cell& c = ci->second;
        nr::FineBin& fb = fi->second;
        auto pi = fb.rows.find(op.nr_miner);
        if (pi == fb.rows.end())
            throw std::logic_error("v37: NR credit undo — pair missing");
        const U256 old_v = pi->second.v;
        U256 new_v;
        pi->second.raw -= op.nr_raw;
        if (pi->second.raw == 0) fb.rows.erase(pi);
        else {
            pi->second.v = nr::pair_value(bin, pi->second.raw, c, nr_ladder_opts());
            new_v = pi->second.v;
        }
        U256& cm = c.comp[op.nr_miner];
        cm -= old_v;
        cm += new_v;
        if (cm.is_zero()) c.comp.erase(op.nr_miner);
        c.raw_work -= op.nr_raw;
        m_nr_raw_cur -= op.nr_raw;      // S14: the width law's period accumulator
        fb.raw_sum -= op.nr_raw;
        fb.pos_lo = op.nr_pos_lo_before;
        if (op.nr_flag) {                                // I-6: provenance, fine layer
            const nr::ProvKey k{static_cast<std::uint16_t>(op.nr_b), op.nr_miner};
            auto pi2 = fb.prov.find(k);
            if (pi2 == fb.prov.end())
                throw std::logic_error("v37: NR credit undo — provenance row missing");
            pi2->second -= op.nr_raw;
            if (pi2->second == 0) fb.prov.erase(pi2);
            c.prov = nr::prov_rows_of(fb.prov);
        }
        if (fb.rows.empty()) m_nr_fine.erase(fi);
        if (c.raw_work == 0 && c.comp.empty()) m_nr_cells[0].erase(ci);
        m_next_pos -= 1;
        --m_nr_pushes;
        m_nr_cache_ok = false;
    }

    // ── checkpoints under NR (no journal clearing, no sentinel) ──────────
    void nr_take_checkpoint(u64 last_ckpt_bin_before) {
        Op ok; ok.type = Op::Type::NrCkpt;
        ok.nr_a = last_ckpt_bin_before;       // S14: the cadence anchor's undo
        m_ckpts.push_back(make_checkpoint());
        while (m_ckpts.size() > m_p.mrr.ckpt_retain) {
            ok.ckpt_dropped = true;
            ok.ckpt_front = m_ckpts.front();
            m_ckpts.pop_front();
        }
        ++m_nr_ckpts_taken;
        m_journal.push_back(std::move(ok));
    }
    void nr_undo_ckpt(const Op& op) {
        if (m_ckpts.empty())
            throw std::logic_error("v37: NR checkpoint undo with an empty ring");
        m_ckpts.pop_back();
        if (op.ckpt_dropped) m_ckpts.push_front(op.ckpt_front);
        m_nr_last_ckpt_bin = op.nr_a;         // S14
        --m_nr_ckpts_taken;
    }
    void nr_undo_width(const Op& op) {
        m_W_bins = op.nr_a;
        if (op.nr_flag) {               // S14: the law-driven retarget's period state
            m_nr_last_retarget_bin = op.nr_b;
            m_nr_raw_cur  = op.nr_raw;
            m_nr_raw_prev = op.nr_raw2;
            m_nr_dnet_at_base = op.nr_dnet;
            --m_nr_retargets;
        }
        m_nr_cache_ok = false;
    }

    // ── S14: the WIDTH LAW (S4) on the NR bin clock ───────────────────────
    // Period k = [k*R_b, (k+1)*R_b) in bins. At the FIRST tick that enters a
    // new period the law fires ONCE, deterministically, from committed state:
    //   * D_net@base — the entering atom's committed read (ruling D: a single
    //     read at the boundary; it IS the first fresh atom at or past it);
    //   * the divisor — the raw work admitted over the period JUST ENDED
    //     (ruling E's one-period lag, which is what cancels W_cur and makes
    //     the fixed point independent of the current width);
    //   * formula / floor-to-R / x4-div4 damping / clamp — shadow_widthlaw.hpp
    //     unchanged (ruling F), the same pure function the S4 KATs pin.
    // A ZERO read HOLDS W [ND-R11 default, OWED — the alternative is
    // W_default, i.e. treating an unavailable difficulty as bootstrap].
    // Ordering (ND-R13): folds run BEFORE this, the shed AFTER it, so a
    // period's shed always happens under the width that period elected —
    // never one tick of shedding under the retired width.
    void nr_maybe_retarget(const WorkAtom& a) {
        const u64 Rb = m_p.nr.retarget_bins;
        const u64 due = (m_nr_t / Rb) * Rb;
        if (due <= m_nr_last_retarget_bin) return;
        Op op; op.type = Op::Type::NrWidth;
        op.nr_flag = true;
        op.nr_a = m_W_bins;
        op.nr_b = m_nr_last_retarget_bin;
        op.nr_raw = m_nr_raw_cur;
        op.nr_raw2 = m_nr_raw_prev;
        op.nr_dnet = m_nr_dnet_at_base;
        m_nr_last_retarget_bin = due;
        m_nr_raw_prev = m_nr_raw_cur;
        m_nr_raw_cur = 0;
        m_nr_dnet_at_base = a.d_net;
        if (!a.d_net.is_zero()) {
            // The width law is winlaw::retarget_width — the SAME pure function
            // the positional window declares and the S4 KATs pin (width-matrix
            // 9253fa42..., ND-R14 order: damp -> clamp -> floor-to-R LAST). It
            // is NOT re-implemented here. What is built below is a PARAMETER
            // VIEW of NrGate, never a gate: the ridge's own operator-baked
            // constants, in the shape the law reads them.
            m_W_bins = winlaw::retarget_width(a.d_net, m_W_bins, m_nr_raw_prev,
                                              nr_width_params());
        }
        ++m_nr_retargets;
        m_journal.push_back(std::move(op));
        m_nr_cache_ok = false;
    }

    // ── S14: CHECKPOINTS (I-3) on the NR bin clock ────────────────────────
    // The shipped lane checkpoints POSITIONALLY (every epoch_len pushes). Under
    // the native ridge the state is denominated in BINS, so the cadence is too:
    // a checkpoint fires on the push whose PROSPECTIVE clock enters a new
    // ckpt_bins period, which check_dims pins to the TOP-LEVEL lattice
    // (ckpt_bins % R^fold_cap == 0). That is what makes the rebuild's
    // fine-layer replay start on a whole fold group rather than inside a
    // half-folded one. It is taken BEFORE that push's tick — see the call
    // site: a checkpoint must be the committed state at its own position.
    void nr_maybe_checkpoint(u64 prospective_t) {
        const u64 C = m_p.nr.ckpt_bins;
        const u64 due = (prospective_t / C) * C;
        if (due <= m_nr_last_ckpt_bin) return;
        // The snapshot is taken with the anchor STILL AT ITS OLD VALUE, and
        // the anchor advances after it. A rebuild therefore installs the old
        // anchor and the forward replay of this very push re-takes the
        // identical checkpoint — the base is reproduced rather than assumed.
        nr_take_checkpoint(m_nr_last_ckpt_bin);
        m_nr_last_ckpt_bin = due;
    }

    // The rebuild's verification: every cell's frozen record must equal the
    // re-derived fine layer plus its carried split (attributable on mismatch).
    void nr_verify_cells_against_fine() const {
        for (const auto& lvl : m_nr_cells)
            for (const auto& [idx, c] : lvl) {
                (void)idx;
                std::map<MinerId, U256> sum = c.carried;
                u128 raw = c.carried_raw;
                for (auto it = m_nr_fine.lower_bound(c.bin_lo);
                     it != m_nr_fine.end() && it->first <= c.bin_hi; ++it) {
                    raw += it->second.raw_sum;
                    for (const auto& [m, p] : it->second.rows) sum[m] += p.v;
                }
                if (sum != c.comp || raw != c.raw_work)
                    throw std::logic_error("v37: NR rebuild — a checkpointed cell does not "
                                           "match the tracker-replayed fine layer");
            }
    }

    // ── reads ─────────────────────────────────────────────────────────────
    const std::map<MinerId, U256>& nr_payout_map() const {
        if (!m_nr_cache_ok) nr_rebuild_cache();
        return m_nr_cache;
    }
    void nr_rebuild_cache() const {
        m_nr_cache.clear(); m_nr_live.clear(); m_nr_carry.clear();
        auto add = [&](const nr::Cell& c) {
            for (const auto& [m, w] : c.comp) {
                (void)w;
                const nr::CellRead r = nr::cell_read(c, m);
                if (!r.live.is_zero())  m_nr_live[m]  += r.live;
                if (!r.carry.is_zero()) m_nr_carry[m] += r.carry;
                U256 s = r.live; s += r.carry;
                if (!s.is_zero()) m_nr_cache[m] += s;
            }
        };
        for (const auto& lvl : m_nr_cells)
            for (const auto& [idx, c] : lvl) { (void)idx; add(c); }
        for (const auto& [b, c] : m_nr_record) { (void)b; add(c); }
        m_nr_cache_ok = true;
    }

    LaneParams m_p;
    DecayTables m_tab;
    u64 m_next_pos = 0;
    u64 m_B = 0;
    u64 m_cover = 0;
    std::deque<L0Slot> m_l0;
    std::vector<std::deque<Bucket>> m_levels;
    std::map<MinerId, U256> m_acc;           // ordered: digest determinism
    U256 m_acc_total;
    u128 m_raw_total = 0;
    U256 m_l0_scaled_sum;
    u128 m_l0_raw_sum = 0;
    std::deque<Op> m_journal;
    // MRR (v37): evicted-work carry, epoch frame B. Empty unless the
    // gate is active AND a bucket with pos_lo >= activation_pos was evicted.
    std::map<MinerId, U256> m_carry;         // ordered: digest determinism
    U256 m_carry_total;
    // MRR (I-2): permanence range over carried-evicted buckets (peaks only).
    PeakSet m_mmr;
    // MRR (I-3): the retained committed checkpoints, oldest -> newest.
    std::deque<Checkpoint> m_ckpts;
    // ── S6-S7 (window): live ONLY once the activation migration has run.
    // Every field below is zero while the gate is OFF and none of them is
    // serialized then, so a win-OFF lane carries no new bytes anywhere.
    bool m_win_started = false;      // ruling K: the migration has run
    u64 m_t_now_bin = 0;             // the clock (rulings H / L)
    u64 m_B_bin = 0;                 // the epoch base in bins == the burial floor
    u64 m_oldest_live_bin = 0;
    u64 m_W_bins = 0;                // the LIVE window width, in bins
    u64 m_t0_bin = 0;                // the activation bin (ruling K)
    u128 m_raw_total_prev_epoch = 0; // ruling E: the one-epoch-lagged divisor
    U256 m_dnet_at_base;             // ruling J: the D_net the last retarget read
    std::deque<L0Bin> m_l0_bins;     // the contiguous per-bin ring
    // Ruling D: the exogenous committed difficulty seam. Null => the width law
    // takes its W_default fail-safe; it never divides by zero and never guesses.
    const IMainchainDifficulty* m_maindiff = nullptr;
    // MRR (I-3): the one-row seg-table (row 0 from construction). The
    // geometry never moves in this cut, so the row never changes after the
    // constructor except for restore_gates()'s from_pos fix-up.
    // S12-R: the NATIVE RIDGE state — ALL default-empty / zero, live only
    // under nr_active(), never serialized while OFF (KAT-0 unmoved). m_W_bins
    // above is the live window under NR (the S1 slot, re-used).
    //   m_nr_started / m_nr_t / m_nr_t0 — the clock, started at the migration
    //   m_nr_fine    — the fine layer (bin -> pairs); the eviction authority
    //   m_nr_cells   — level -> lattice idx -> cell (the seal records)
    //   m_nr_record  — record-only cells (the prologue), by bin
    bool m_nr_started = false;
    u64 m_nr_t = 0, m_nr_t0 = 0;
    std::map<u64, nr::FineBin> m_nr_fine;
    std::array<std::map<u64, nr::Cell>, nr::MAX_FOLD_CAP + 1> m_nr_cells;
    std::map<u64, nr::Cell> m_nr_record;
    mutable std::map<MinerId, U256> m_nr_cache, m_nr_live, m_nr_carry;
    mutable bool m_nr_cache_ok = false;
    u64 m_nr_pushes = 0, m_nr_full_carries = 0, m_nr_dropped = 0;
    // S14: the two BIN-CLOCK cadence anchors and the width law's period
    // accumulators. All zero while the gate is OFF; installed at the
    // migration and carried in the NR checkpoint record so a rebuild
    // re-drives the law from the identical state.
    //   m_nr_last_ckpt_bin / m_nr_last_retarget_bin — the last fired boundary
    //   m_nr_raw_cur  — raw admitted since the current period opened
    //   m_nr_raw_prev — raw admitted over the period just ended (ruling E lag)
    //   m_nr_dnet_at_base — the committed D_net read of the current period
    u64 m_nr_last_ckpt_bin = 0, m_nr_last_retarget_bin = 0;
    u128 m_nr_raw_cur = 0, m_nr_raw_prev = 0;
    U256 m_nr_dnet_at_base;
    u64 m_nr_retargets = 0, m_nr_branch_hits = 0, m_nr_ckpts_taken = 0;
    std::vector<CarrySegment> m_segments;
};

} // namespace v37
