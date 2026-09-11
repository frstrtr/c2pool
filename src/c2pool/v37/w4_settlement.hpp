#pragma once
// V37 per-lane settlement — Track A2 bring-up step W4. CONSUMER-tree code:
// it lives here (src/c2pool/v37/), NOT in src/sharechain/v37/, which stays the
// pure header-only consensus module. W4 is a READER of the W0/W1 engine seam
// and the SINGLE WRITER of its own off-coin-chain OWED ledger (ledger #2); it
// touches no Lane/Roundabout/LaneExecutor internal.
//
// Binding spec: /home/ubuntu/v37-work/v37-a2-w4-settlement-spec.md.
// Design of record: landed rev3 §1 (per-chain settlement as a pure function of
// the shared accounting spine) + §4 (effect boundary; SETTLED terminal; the two
// post-broadcast crossings) + obligations O2/O4/O5 (consistent cut; forward
// repair; D_spine/D_conf; O5.5 monotone-height + persisted high-water) + the M4
// accounting boundary (OWED off the coin chain; on-chain emit = SETTLED +
// opaque; no address monitoring). Acceptance SHAPES: proto/rev3-falsifiers
// (golden 3692d922 — F-REPAIR/F-SPINE/F-BROADCAST + monotone_height).
//
// What this header provides (spec §1.4 contract, expressed against the real API):
//   (1) split_reward()       — the consensus exact-integer split of a block
//                              reward over a lane payout map (§2.3), largest
//                              remainder, ties by canonical identity key. Its
//                              own wide (320-bit) helper (v37_fixed U256 has no
//                              division). KAT-pinned in the test.
//   (2) SettlementProjectionView / project() / settle_block()
//                            — the per-chain PURE FOLD (§2.1/§2.2): resolve a
//                              SettlementView's MinerId-keyed payout map to
//                              canonical identities via the #1485 identity view,
//                              split the reward → per-key entitlement E_b.
//   (3) OwedLedger           — the KEYED_CRDT finality-gated overlay (§4.2,
//                              Settlement.tla form): FOUND/FINALIZE/ORPHAN,
//                              EffectiveOwed, K_fair selection + h_min carry,
//                              SETTLED terminal, priced-residual detection, the
//                              owed commitment (§4.5), forward repair (§4.4).
//   (4) SettleHW             — O5.5 persisted, monotonically non-decreasing
//                              best-chain high-water (§5), restart-surviving.
//   (5) CutToken / read_cut()— the O2 consistent-cut read (§6), keyed on lane
//                              INCARNATION (not (chain,version)); read every
//                              leg, re-read, mismatch → discard+retry, no lock.
//   (6) geometry ratified seam (§7) — a FLAGGED SEAM: assert-hook at the
//                              settlement boundary. Its final form (Lane-
//                              boundary check vs canonical flag) awaits the
//                              integrator D-B ruling (OI-W4-8); this does NOT
//                              hard-decide D-B and does not block. EXTENDED
//                              for V37.1 (S8): the native-ridge dimension set.
//   (7) S8 / S-1              — the ONE owed commitment, in both directions:
//                              S8 is the fold that puts value into the ledger,
//                              S-1 is the template-build emission of
//                              ledger.owed_digest() of that SAME ledger. The
//                              emission NEVER recomputes; see §S8 below.

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <c2pool/v37/v37_engine.hpp>          // V37Engine, SettlementView
#include <c2pool/v37/v37_subthreshold_estimator.hpp>  // RDWR-OQ2 DROPS estimator (merged, gated)
#include <sharechain/v37/v37_lane_executor.hpp>  // LaneSnapshot, IdentityView
#include <sharechain/v37/v37_descriptor.hpp>     // ScriptRef, ScriptKind
#include <sharechain/v37/v37_fixed.hpp>          // U256, u64
#include <sharechain/v37/v37_hash.hpp>           // bytes32, sha256d
#include <c2pool/v37/w4_owed_incremental.hpp>    // R3: DigestMemo, EffectiveOwedIndex

namespace c2pool::v37n::settle {

using ::v37::bytes32;
using ::v37::ScriptKind;
using ::v37::ScriptRef;
using ::v37::U256;
using ::v37::u64;

// ─────────────────────────────────────────────────────────────────────────
// (1) The consensus split — exact integer, largest-remainder, tie by key.
//
// amount_m = floor(R · weight_m / Σ weight); the R − Σfloor leftover is handed
// out one unit at a time to the largest fractional remainders, ties broken by
// canonical identity key ASCENDING (C-1: node-local intern ids never influence
// a consensus byte). Requires a 320-bit intermediate (u64 × U256) and a
// 320÷256 division that v37_fixed::U256 does not provide, so W4 carries its own
// wide helper HERE (never in the consensus header). Σ amount == R exactly.
// ─────────────────────────────────────────────────────────────────────────

namespace wide {

// (a · b) as a 320-bit little-endian value (5 × u64), a=u64, b=U256.
inline std::array<u64, 5> mul_u64_u256(u64 a, const U256& b) {
    std::array<u64, 5> r{0, 0, 0, 0, 0};
    ::v37::u128 carry = 0;
    for (int i = 0; i < 4; ++i) {
        ::v37::u128 p = ::v37::u128(b.v[i]) * a + carry;
        r[i] = static_cast<u64>(p);
        carry = p >> 64;
    }
    r[4] = static_cast<u64>(carry);
    return r;
}

inline void shl1(std::array<u64, 5>& x) {
    u64 carry = 0;
    for (int i = 0; i < 5; ++i) {
        u64 nc = x[i] >> 63;
        x[i] = (x[i] << 1) | carry;
        carry = nc;
    }
}

// rem (5 limbs) >= den (U256, 4 limbs; limb 4 == 0).
inline bool ge_u256(const std::array<u64, 5>& rem, const U256& den) {
    if (rem[4]) return true;  // rem has a bit >= 2^256; den < 2^256
    for (int i = 3; i >= 0; --i)
        if (rem[i] != den.v[i]) return rem[i] > den.v[i];
    return true;  // equal
}

inline void sub_u256(std::array<u64, 5>& rem, const U256& den) {
    ::v37::u128 borrow = 0;
    for (int i = 0; i < 5; ++i) {
        u64 d = (i < 4) ? den.v[i] : 0;
        ::v37::u128 diff = ::v37::u128(rem[i]) - d - borrow;
        rem[i] = static_cast<u64>(diff);
        borrow = (diff >> 64) ? 1 : 0;
    }
}

struct DivResult { u64 quot; U256 rem; };

// 320-bit ÷ 256-bit → (u64 quotient, U256 remainder), bitwise long division.
// The quotient fits u64 whenever weight_m <= Σ (always true for one map entry
// against the map sum), so only the low limb is kept; higher quotient bits are
// asserted zero by construction of the caller.
inline DivResult divmod(const std::array<u64, 5>& num, const U256& den) {
    if (den.is_zero()) return {0, U256{}};
    std::array<u64, 5> rem{0, 0, 0, 0, 0};
    std::array<u64, 5> q{0, 0, 0, 0, 0};
    for (int bit = 319; bit >= 0; --bit) {
        shl1(rem);
        u64 nb = (num[bit / 64] >> (bit % 64)) & 1ull;
        rem[0] |= nb;
        if (ge_u256(rem, den)) {
            sub_u256(rem, den);
            q[bit / 64] |= (1ull << (bit % 64));
        }
    }
    U256 r;
    r.v[0] = rem[0]; r.v[1] = rem[1]; r.v[2] = rem[2]; r.v[3] = rem[3];
    return {q[0], r};
}

}  // namespace wide

// One weighted payee, canonical-key-keyed (the fold's identity-resolved unit).
struct WeightedPayee {
    bytes32   key{};     // canonical identity (MinerIntern::key) — consensus name
    U256      weight;    // decayed payout weight from the lane map
    ScriptRef pay{};     // payout ScriptRef, for coinbase emission (W5)
};

// Exact split of `reward` over `payees` (order-independent input). Returns the
// per-payee integer amount in the SAME order as `payees`. Σ result == reward
// (when reward>0 and Σweight>0), else all zero.
inline std::vector<u64> split_reward(u64 reward,
                                     const std::vector<WeightedPayee>& payees) {
    std::vector<u64> amt(payees.size(), 0);
    if (reward == 0 || payees.empty()) return amt;
    U256 sum;
    for (const auto& p : payees) sum += p.weight;
    if (sum.is_zero()) return amt;

    std::vector<U256> rem(payees.size());
    u64 base_total = 0;
    for (std::size_t i = 0; i < payees.size(); ++i) {
        auto d = wide::divmod(wide::mul_u64_u256(reward, payees[i].weight), sum);
        amt[i] = d.quot;
        rem[i] = d.rem;
        base_total += d.quot;
    }
    u64 leftover = reward - base_total;   // < payees.size() by construction
    // Largest remainder first; ties by canonical identity key ASCENDING.
    std::vector<std::size_t> order(payees.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) {
        if (rem[a] != rem[b]) return rem[b] < rem[a];       // larger remainder first
        return payees[a].key < payees[b].key;               // then key ascending
    });
    for (u64 k = 0; k < leftover && k < order.size(); ++k) amt[order[k]]++;
    return amt;
}

// ─────────────────────────────────────────────────────────────────────────
// (2) The per-chain pure fold (§2.2). project() resolves the MinerId-keyed
// payout map of a SettlementView to canonical-identity WeightedPayees via the
// #1485 identity view; settle_block() splits a block reward over them → the
// per-key entitlement vector E_b. Both are pure functions of the (immutable)
// projection value — no engine access, no lock.
// ─────────────────────────────────────────────────────────────────────────

// Resolve + drop zero weights. A payout entry whose MinerId does not resolve in
// the view is a broken invariant (the view is a superset of payout keys,
// OI-W4-1); such an entry is skipped and reported via `unresolved`. Templated
// over the view type so it reads BOTH the tip LaneSnapshot (V37Engine::snapshot)
// and the burial-gated SettlementView (settlement_view_at ring) — both carry a
// MinerId-keyed `payout` map and the OI-W4-1 `identities` view.
template <class View>
inline std::vector<WeightedPayee> project(const View& v,
                                          std::size_t* unresolved = nullptr) {
    std::vector<WeightedPayee> out;
    std::size_t miss = 0;
    if (!v.identities) { if (unresolved) *unresolved = v.payout.size(); return out; }
    for (const auto& [mid, w] : v.payout) {
        if (w.is_zero()) continue;                       // §2.3: floored-to-0 dropped
        const ::v37::IdentityEntry* e = v.identities->find(mid);
        if (!e) { ++miss; continue; }
        out.push_back(WeightedPayee{e->key, w, e->pay});
    }
    if (unresolved) *unresolved = miss;
    return out;
}

// E_b = split(reward, project(view)) as a key→amount map (per-block entitlement).
//
// ★★ S8 — THE E_b SINGLE-SOURCE RULE (V37.0 / V37.1). E_b is a pure function
// of (reward, v.payout, v.identities) and of NOTHING else. This fold does not
// read v.params, v.next_pos, v.digest or any lane gate, and it must never grow
// a live-vs-ridge branch of its own. The V37.0/V37.1 choice of WHICH map
// v.payout carries is made ONCE, at the engine's single view-build site —
// LaneExecutor's `s->payout = l.payout_map()`, and Lane::payout_map()
// dispatches on its own nr_active():
//     gate OFF  →  payout_map_positional()   (live only)          ≡ master
//     gate ON   →  nr_payout_map()           (live + carry, CARRY-ARITH:
//                                             two SEPARATELY truncated
//                                             products summed, never
//                                             (live+carry).mul_q)
// — with ND-R11 RULED (the carried ledger is PAID) selecting the live+carry
// form at the flip. Keeping the decision at that one site is what makes S8 and
// S-1 auto-consistent: every node at the same cut credits the ledger from the
// identical map and therefore emits the identical owed_digest. A second branch
// HERE would be a fork surface, not an optimisation.
template <class View>
inline std::map<bytes32, u64> settle_block(u64 reward, const View& v) {
    std::vector<WeightedPayee> payees = project(v);
    std::vector<u64> amt = split_reward(reward, payees);
    std::map<bytes32, u64> e;
    for (std::size_t i = 0; i < payees.size(); ++i)
        if (amt[i] > 0) e[payees[i].key] += amt[i];
    return e;
}

// Which map the view-build site put in v.payout. DIAGNOSTIC ONLY — nothing in
// the fold, the ledger or the commitment branches on it; it exists so a node
// can LOG and a KAT can ASSERT which E_b source produced a given credit, and
// so an operator reading two nodes' logs at one cut can see a mis-set gate
// instead of inferring it from a diverged digest. It re-derives the lane's own
// predicate from the view's own frozen fields (Lane::nr_active() is
// `nr_version == 1 && next_pos > nr_activation_pos && mrr_active()`, and
// Lane::mrr_active() is `next_pos > mrr.activation_pos`), so it cannot drift
// from the site it describes.
enum class EbSource : std::uint8_t { LiveOnly = 0, LiveAndCarry = 1 };

inline const char* eb_source_name(EbSource s) {
    return s == EbSource::LiveAndCarry ? "live+carry (V37.1 native ridge)"
                                       : "live-only (V37.0 positional)";
}

template <class View>
inline EbSource eb_source_of(const View& v) {
    const ::v37::LaneParams& p = v.params;
    const bool mrr_on = v.next_pos > p.mrr.activation_pos;
    const bool nr_on  = p.nr.nr_version == 1 &&
                        v.next_pos > p.nr.nr_activation_pos && mrr_on;
    return nr_on ? EbSource::LiveAndCarry : EbSource::LiveOnly;
}

// ─────────────────────────────────────────────────────────────────────────
// (5) The O2 consistent-cut token (§6) — keyed on lane INCARNATION.
// A cut holds iff every leg re-reads equal; the incarnation defeats the F2
// RemoveLane→AddLane ABA that (chain,version) alone cannot (§6.2).
// ─────────────────────────────────────────────────────────────────────────

struct CutToken {
    // lane leg (the spine of chain c)
    ::v37::ChainId chain = 0;
    u64  incarnation = 0;   // executor-minted, node-monotone, never reused
    u64  version = 0;       // lane version at the burial-gated prefix P
    u64  next_pos = 0;      // == P (sanity, not a key)
    bytes32 spine_digest{}; // LaneSnapshot::digest at (incarnation, version)
    // ledger leg (W4's own single-writer state)
    u64  ledger_seq = 0;
    bytes32 owed_digest{};  // §4.5 at ledger_seq
    // coin-chain leg (legacy domain, O2.5 degenerate lane)
    u64  hw_height = 0;     // SettleHW high-water (monotone, persisted)
    bytes32 hw_tip{};
    bool operator==(const CutToken&) const = default;
};

// ─────────────────────────────────────────────────────────────────────────
// (4) O5.5 — the persisted, monotonically non-decreasing best-chain high-water.
// hw_height NEVER decreases; a candidate branch that would leave the chain
// shorter is not adopted (settlement is never advanced or re-evaluated against
// a lower height). ledger_seq is the OWED ledger's monotonic event sequence
// (the ledger leg of the cut token). serialize()/deserialize() model the
// LevelDB persistence (MD-3 option A: an in-memory high-water does NOT satisfy
// the clause) so the restart test can round-trip it.
// ─────────────────────────────────────────────────────────────────────────

struct SettleHW {
    u64     hw_height = 0;
    bytes32 hw_tip{};
    u64     ledger_seq = 0;
    u64     refused = 0;   // count of refused (shorter-branch) advances

    // Try to advance the high-water. A height below the current high-water is
    // REFUSED (recorded, never silently swallowed) and the state is untouched.
    bool advance(u64 height, const bytes32& tip) {
        if (height < hw_height) { ++refused; return false; }
        hw_height = height;
        hw_tip = tip;
        return true;
    }

    // MD-3 ruling A (§5): a candidate branch that would leave the chain SHORTER
    // than the persisted high-water is NOT ADOPTED — settlement is never
    // advanced or re-evaluated against a lower height. Returns false (recording
    // the refusal) for such a candidate, without mutating the high-water.
    bool admit_candidate_height(u64 candidate_height) {
        if (candidate_height < hw_height) { ++refused; return false; }
        return true;
    }

    // The persisted record, as an opaque byte string (LevelDB value model).
    std::string serialize() const {
        std::string s;
        auto put_u64 = [&](u64 x) {
            for (int i = 0; i < 8; ++i) s.push_back(char((x >> (8 * i)) & 0xff));
        };
        put_u64(hw_height);
        s.append(reinterpret_cast<const char*>(hw_tip.data()), hw_tip.size());
        put_u64(ledger_seq);
        put_u64(refused);
        return s;
    }
    static SettleHW deserialize(const std::string& s) {
        SettleHW hw;
        std::size_t o = 0;
        auto get_u64 = [&]() {
            u64 x = 0;
            for (int i = 0; i < 8; ++i)
                x |= u64(std::uint8_t(s[o++])) << (8 * i);
            return x;
        };
        hw.hw_height = get_u64();
        for (std::size_t i = 0; i < hw.hw_tip.size(); ++i)
            hw.hw_tip[i] = std::uint8_t(s[o++]);
        hw.ledger_seq = get_u64();
        hw.refused = get_u64();
        return hw;
    }
};

// ─────────────────────────────────────────────────────────────────────────
// (6) D-B ratified-geometry enforcement — a FLAGGED SEAM (§7). W4 does NOT
// hard-decide the D-B ruling (OI-W4-8): the settlement boundary carries a
// ratified-geometry assert hook that a settlement read must pass. Its final
// form — a Lane-boundary check here vs a canonical flag stamped at the
// executor's AddLane — awaits the integrator D-B ruling. Defense in depth
// covers Phase A regardless: a settlement over a non-ratified geometry is not
// consensus and is refused (hard, not a retry). The registry below is the
// OQ-5 canonical default; the seam is the single place to swap in the ruled
// form without touching the fold or the ledger.
// ─────────────────────────────────────────────────────────────────────────

// ★★ S8 (V37.1) — THE NATIVE-RIDGE HALF OF THE PIN, AND WHY IT IS NOT TYPED
// OUT HERE. Under the native ridge (S12 / ND-R9) the ratified geometry is the
// per-lane ND-R6 dimension set carried on NrGate and committed in the "NRG1"
// header sub-block — NOT a tuple this header could restate. A settlement pin
// that RE-TYPED that table would itself become a fork surface the first time
// the table moved on one side only. So the pin reconstructs its reference
// through the lane's OWN single source of truth,
// ::v37::LaneParams::for_version(1, lane) (which folds nr::for_version(1,
// lane) and runs nr::check_dims() on the row it returns), and compares. An
// edit to nr_ladder.hpp therefore moves the lane guard and this pin TOGETHER,
// bit for bit, by construction.
//
// Field coverage is kept honest by a size tripwire rather than by hope: adding
// a field to NrGate changes sizeof and fails the static_assert below, which
// names the function that must then be extended.
static_assert(sizeof(::v37::NrGate) == 104,
              "S8: NrGate changed shape — extend nr_gate_dims_equal() to cover "
              "the new field before this pin can be trusted again");

// Every NrGate field EXCEPT nr_activation_pos. The activation POSITION is the
// operator's economic flip decision (R-5 / V371_ACTIVATION_POS), not part of
// the ratified GEOMETRY: two nodes on the same ruled dimensions with different
// positions are a mis-configuration the lane's own co-location guard refuses,
// and they are not two different geometries.
inline bool nr_gate_dims_equal(const ::v37::NrGate& a, const ::v37::NrGate& b) {
    return a.nr_version         == b.nr_version         &&
           a.fold_cap           == b.fold_cap           &&
           a.open_horizon_bins  == b.open_horizon_bins  &&
           a.w_min_bins         == b.w_min_bins         &&
           a.w_max_bins         == b.w_max_bins         &&
           a.w_default_bins     == b.w_default_bins     &&
           a.coverage_blocks    == b.coverage_blocks    &&
           a.bin_seconds        == b.bin_seconds        &&
           a.retarget_bins      == b.retarget_bins      &&
           a.ckpt_bins          == b.ckpt_bins          &&
           a.n_ctx_bins         == b.n_ctx_bins         &&
           a.allow_digit_repeat == b.allow_digit_repeat;
}

// True iff `g` is the ruled ND-R6 dimension set of SOME ruled lane. Reads the
// table only through the lane's factory — no value is restated here.
inline bool nr_dims_are_ratified(const ::v37::NrGate& g) {
    if (g.nr_version != 1) return false;
    for (const ::v37::LaneKind k : {::v37::LaneKind::BTC, ::v37::LaneKind::LTC,
                                    ::v37::LaneKind::DASH, ::v37::LaneKind::DOGE}) {
        const ::v37::NrGate ref = ::v37::LaneParams::for_version(1, k).nr;
        if (nr_gate_dims_equal(ref, g)) return true;
    }
    return false;
}

inline bool geometry_is_ratified(const ::v37::LaneParams& p) {
    // (a) V37.0 — the digest-committed geometry tuple (journal_depth excluded
    // — not committed): the OQ-5 canonical default. Any other geometry is
    // refused at the settlement boundary until the D-B registry ships
    // (OI-W4-8). UNCHANGED, byte for byte: every LaneParams the canon can
    // construct (v37_0(), v37_1(), for_version(1, lane) on all four ruled
    // lanes, and the bare default) carries this tuple, so this clause decides
    // exactly what it decided before S8.
    if (!(p.window == 8640 && p.c0 == 4096 && p.rollup == 8 &&
          p.half_life == 2160))
        return false;
    if (!(p.level_caps.size() == 1 && p.level_caps[0] == 568)) return false;

    // (b) V37.1 — the native ridge. Inert unless the ridge is DECLARED, so a
    // GATE-OFF lane (nr_version 0, every position UINT64_MAX) takes exactly
    // the pre-S8 decision above and nothing else runs.
    if (p.nr.nr_version == 0) {
        // A position without a version is the lane constructor's own refusal;
        // mirrored here so a hand-built LaneParams cannot slip past the
        // settlement boundary if it ever reaches one un-constructed.
        return p.nr.nr_activation_pos == UINT64_MAX;
    }
    if (!nr_dims_are_ratified(p.nr)) return false;
    // ND-R9: the S3 bin-band pyramid is RETIRED; S12 supersedes it. The lane
    // constructor refuses a finite window gate beside a FINITE ridge gate —
    // this mirrors that clause with the same guard condition, so the two are
    // the same predicate and not two nearly-identical ones.
    if (p.nr.nr_activation_pos != UINT64_MAX &&
        p.win.win_activation_pos != UINT64_MAX)
        return false;
    return true;

    // REQUIRED-OPERATOR-RULING (S8-R2, = spec §5 R-2). Under ND-R3, c0 /
    // rollup / E are no longer consensus dimensions once the ridge is ACTIVE,
    // so clause (a) is arguably SUPERSEDED there rather than additional. This
    // patch takes the strictly CONSERVATIVE reading — (a) always holds, (b)
    // adds on top — because every LaneParams the canon constructs satisfies
    // both, so the conservative reading refuses nothing the ruled one admits
    // TODAY, while the reverse would silently widen the pin. Whether (a) is
    // dropped under nr_active() is the operator's ruling, not this patch's.
}

// The assert hook. Returns false (a HARD refusal, never a retry) when the
// projection's geometry is not ratified. `strict` lets a test drive small
// non-canonical geometries through the fold/ledger while still exercising the
// seam call-site (the production call site passes strict=true).
template <class View>
inline bool assert_ratified_geometry(const View& v, bool strict) {
    if (!strict) return true;
    return geometry_is_ratified(v.params);
}

// ★ S8 — the ONE credit-path entry point. One call does the ratified-geometry
// refusal AND the E_b fold, so a settlement over a non-ratified geometry
// cannot reach the ledger by a caller that simply forgot the seam. `source` is
// the diagnostic stamp of which map the view-build site produced; `next_pos`
// is the prefix P the fold read at (the cut's own witness). Returns nullopt on
// the HARD refusal — never a retry, never a partial credit.
struct EbFold {
    std::map<bytes32, u64> credit;   // E_b, canonical-key keyed
    EbSource source = EbSource::LiveOnly;
    u64      next_pos = 0;           // == P, the burial-gated prefix read
    std::size_t unresolved = 0;      // OI-W4-1 broken-invariant counter
};

template <class View>
inline std::optional<EbFold> fold_eb(u64 reward, const View& v, bool strict = true) {
    if (!assert_ratified_geometry(v, strict)) return std::nullopt;
    EbFold f;
    std::vector<WeightedPayee> payees = project(v, &f.unresolved);
    std::vector<u64> amt = split_reward(reward, payees);
    for (std::size_t i = 0; i < payees.size(); ++i)
        if (amt[i] > 0) f.credit[payees[i].key] += amt[i];
    f.source = eb_source_of(v);
    f.next_pos = v.next_pos;
    return f;
}

// ─────────────────────────────────────────────────────────────────────────
// RDWR-OQ2 seam — the sub-threshold work estimator ("DROPS") wired into the W4
// OwedLedger credit path, behind the ::v37::LaneParams::subthreshold gate.
//
// The estimator MODULE (src/c2pool/v37/v37_subthreshold_estimator.hpp, merged)
// owns the CORRECTED sybil-neutral arithmetic (the E-2 fix): apply_credit() is
// "the ONLY entry point that turns receipts into OwedLedger credit". This seam
// is the ONLY caller of it in the engine; it does NOT re-implement any estimator
// maths. It translates the LaneParams POD gate into the module's params and, for
// each harvested interval, folds apply_credit()'s per-payee delta into a credit
// map shaped exactly like settle_block()'s E_b (bytes32 -> i64), ready to merge
// into on_block_found().
//
// ★★ PRIME SAFETY INVARIANT. Gate OFF (SubthresholdGate::enabled == false, the
// default): to_subthreshold_params() carries enabled==false, apply_credit()
// returns {} for every interval, subthreshold_credit() returns an EMPTY map, and
// on_block_found_with_estimator() forwards a credit map byte-identical to its
// base_credit argument to the plain on_block_found() — so the composed
// owed_digest, the add-only receipt/share carrier, and the lane digest are all
// byte-identical to master on any shared schedule. Gate ON is the RDWR-OQ2
// consensus activation (owed_digest changes because credited amounts change).
//
// F1 CONTRACT: `interval` is the per-coin-height, in-order monotone bin_height
// (the same K_fair clock the ledger's rearm uses) — the caller supplies it from
// OUT-of-interval, BURIED data and never jumps to tip. Dedup is per (payee,
// interval): a given (payee, interval) yields at most one estimator credit no
// matter how many carriers replay the stream (the module's DedupKey/straddle
// rule). No-double-count: in EstimateOnly the module credits the estimate ONLY
// where the worker's shares do not already account for its work (S == 0 in the
// interval); a share-covered worker is credited by its shares (E_b), never the
// estimate.
// ─────────────────────────────────────────────────────────────────────────

namespace subthreshold = ::c2pool::v37::subthreshold;

// One harvested interval's receipt evidence for a payee: the K-best near-miss
// hashes and the in-interval share count, presented as the module's own
// ReceiptCollector (the caller builds it from the interval's observed hashes
// during ingestion — the module's supported "out-of-interval data" surface).
// `payee` is the canonical identity key (== OwedLedger key / DedupKey::payee,
// both std::array<uint8_t,32>); `interval` is the F1 monotone bin_height.
struct HarvestedReceipt {
    bytes32 payee{};
    u64     interval = 0;
    subthreshold::ReceiptCollector collector;  // built by the caller (K, h_T, observe())
};

// Translate the LaneParams POD gate into the merged estimator module's params.
inline subthreshold::SubthresholdParams to_subthreshold_params(
    const ::v37::LaneParams& p) {
    subthreshold::SubthresholdParams sp;
    sp.enabled = p.subthreshold.enabled;          // ★ default false => gate OFF
    sp.K       = p.subthreshold.K;
    sp.mode    = (p.subthreshold.mode == 1) ? subthreshold::CreditMode::Combined
                                            : subthreshold::CreditMode::EstimateOnly;
    return sp;
}

// The gated estimator credit delta for a set of harvested intervals. GATE OFF =>
// EMPTY map (nothing merged; on_block_found stays byte-identical to master).
// GATE ON => the additive, per-(payee,interval)-deduped, sybil-neutral estimator
// credit. Never emits the broken clamp (the module refuses it structurally).
// Shape == OwedLedger::Amounts (std::map<bytes32, long long>, the E_b shape).
inline std::map<bytes32, long long> subthreshold_credit(
    const ::v37::LaneParams& params,
    const std::vector<HarvestedReceipt>& harvested) {
    std::map<bytes32, long long> credit;
    const subthreshold::SubthresholdParams sp = to_subthreshold_params(params);
    if (!sp.enabled) return credit;                 // ★ GATE OFF: nothing enters
    std::map<subthreshold::DedupKey, bool> already_seen;
    for (const auto& hr : harvested) {
        subthreshold::DedupKey key;
        key.payee = hr.payee;                       // bytes32 == array<uint8_t,32>
        key.seq   = hr.interval;                    // F1 monotone bin_height
        // apply_credit is the module's ONLY receipts->credit entry point; it
        // enforces K>=3, per-(payee,interval) dedup, J>=K, and no-double-count.
        const auto delta =
            subthreshold::apply_credit(sp, key, hr.collector, already_seen);
        for (const auto& [payee, amt] : delta)
            if (amt != 0) credit[payee] += amt;     // bytes32-keyed, add-only
    }
    return credit;
}

// ─────────────────────────────────────────────────────────────────────────
// (3) The OWED ledger — ledger #2, KEYED_CRDT overlay, finality-gated, SETTLED
// terminal (§4). Off the coin chain (M4 lock): every node computes it from the
// same events. Single-writer fold; ledger_seq is its monotonic version. Amounts
// are signed (long long) so over-credit from a re-derived E_b nets forward as a
// negative EffectiveOwed (§4.4, forward repair, unclamped) — never a clawback.
// ─────────────────────────────────────────────────────────────────────────

class OwedLedger {
public:
    using Amounts = std::map<bytes32, long long>;

    explicit OwedLedger(::v37::ChainId chain) : m_chain(chain) {}

    ::v37::ChainId chain() const { return m_chain; }
    u64 ledger_seq() const { return m_seq; }

    // ── FOUND(b): the pool's own block b, with its per-key entitlement E_b
    // (the fold at b's burial-gated prefix) and the coinbase outputs broadcast
    // in b (K_fair over EffectiveOwed, from propose()). No finalW mutation —
    // deferred to finality. Durable, write-ahead (§5.2). Idempotent per bid.
    void on_block_found(const std::string& bid, const Amounts& credit,
                        const Amounts& payout) {
        if (m_pending.count(bid) || m_settled.count(bid)) return;
        Pending p;
        for (const auto& [k, v] : credit) if (v != 0) p.credit[k] = v;
        for (const auto& [k, v] : payout) if (v != 0) p.payout[k] = v;
        m_eo_index.on_found(p.payout,                 // R3: eo -= payout (fe frozen)
                            [this](const bytes32& k) { return fe_at(k); });
        m_pending.emplace(bid, std::move(p));
        bump();
    }

    // ── RDWR-OQ2 wiring: FOUND(b) with the gated sub-threshold estimator folded
    // into the per-key credit. `base_credit` is the ordinary E_b entitlement
    // (settle_block over b's burial-gated prefix); `harvested` carries the
    // OUT-of-interval, buried near-miss receipts (F1 monotone bin_height, never
    // tip). GATE OFF (default) => subthreshold_credit() returns {} and this
    // forwards `base_credit` UNCHANGED to on_block_found() — byte-identical to
    // master (the estimator credit is add-only and materialises only when ON).
    // GATE ON => the corrected sybil-neutral estimate is added to the credit for
    // the UNCOVERED (S==0) workers whose near-misses reached J>=K, deduped per
    // (payee, interval); a share-covered worker keeps ONLY its E_b (no double
    // count). This is the single call site of the estimator in the fold.
    void on_block_found_with_estimator(
        const std::string& bid, const Amounts& base_credit, const Amounts& payout,
        const ::v37::LaneParams& params,
        const std::vector<HarvestedReceipt>& harvested) {
        const Amounts est = subthreshold_credit(params, harvested);
        if (est.empty()) {                       // ★ GATE OFF (or nothing eligible):
            on_block_found(bid, base_credit, payout);  // identical to master path
            return;
        }
        Amounts credit = base_credit;            // GATE ON: add-only merge
        for (const auto& [k, v] : est) credit[k] += v;
        on_block_found(bid, credit, payout);
    }

    // ── FINALIZE(b): b is canonical AND buried >= D_conf on its own chain AND
    // the O5.5 gate passed (the caller checks all three). finalW += credit;
    // finalW -= payout (Settlement.tla G: the coinbase was built against
    // EffectiveOwed, so aggregate finalW stays >= 0); re-arm first_eligible;
    // mark b SETTLED (TERMINAL); drop the pending keys. `bin_height` is the
    // monotone K_fair clock (the coin high-water).
    void on_block_finalized(const std::string& bid, u64 bin_height) {
        auto it = m_pending.find(bid);
        if (it == m_pending.end()) return;
        for (const auto& [k, v] : it->second.credit) m_finalW[k] += v;
        for (const auto& [k, v] : it->second.payout) m_finalW[k] -= v;
        m_eo_index.apply_finalize_credit(it->second.credit);  // R3: eo += credit
        m_pending.erase(it);
        m_settled.insert(bid);
        rearm_first_eligible(bin_height);
        prune_finalized_zero_rows();                          // R3: drop 0/unarmed rows
        bump();
    }

    // ── ORPHAN(b): a pure disposition of the pending state, or a priced
    // residual if b was already SETTLED (§4.2 / MD-2 ruling (a)).
    //   pre-SETTLED : remove both pending keys. The credit returns to owed BY
    //                 DERIVATION (it was never in finalW); the payout's funds
    //                 never moved. A later block re-mints from the unchanged
    //                 spine. Never a snapshot restore or delta subtraction (the
    //                 two non-commutative semantics P3-F1 refuted).
    //   post-SETTLED: SETTLED is terminal — nothing reverts. The orphaned
    //                 payout is the O3.5 third-crossing priced residual: it is
    //                 DETECTED and SURFACED (amount accumulated in
    //                 m_residual), never re-owed, never conserved.
    void on_block_orphaned(const std::string& bid, const Amounts& settled_payout) {
        auto it = m_pending.find(bid);
        if (it != m_pending.end()) {
            m_eo_index.on_orphan_pre(it->second.payout,  // R3: eo += payout
                                     [this](const bytes32& k) { return fe_at(k); });
            m_pending.erase(it);   // pre-SETTLED: pure key removal
            bump();
            return;
        }
        if (m_settled.count(bid)) {
            long long residual = 0;
            for (const auto& [k, v] : settled_payout) residual += v;
            if (residual > 0) {
                m_residual += residual;
                m_residual_events.push_back({bid, residual});
            }
            bump();  // surfaced as a ledger event; finalW untouched (terminal)
        }
    }

    // EffectiveOwed(key) = finalW - Σ_{pending} payout. A coinbase draws on this
    // only (§4.4). Signed: a negative value is over-credit netted forward.
    long long effective_owed(const bytes32& k) const {
        // R3: served from the incrementally-maintained index in O(log K); its
        // value equals finalW(k) − Σ_pending payout(k) by construction (the
        // delta algebra in w4_owed_incremental.hpp), byte-for-byte identical to
        // the former rescan (oracle KAT v37_w4_owed_incremental_test).
        return m_eo_index.value(k);
    }

    // The full EffectiveOwed vector over every key the ledger has ever touched.
    Amounts effective_owed_all() const {
        std::set<bytes32> keys;
        for (const auto& [k, v] : m_finalW) { (void)v; keys.insert(k); }
        for (const auto& [bid, p] : m_pending)
            for (const auto& [k, v] : p.payout) { (void)v; keys.insert(k); }
        Amounts out;
        for (const auto& k : keys) out[k] = effective_owed(k);
        return out;
    }

    // K_fair coinbase proposal (§4.6): eligible = {EffectiveOwed > 0}; order
    // (first_eligible_height ASC, key ASC); take first C; amount =
    // min(EffectiveOwed, budget); emit iff amount >= h_min(kind) else CARRY
    // (skip, first_eligible untouched — no starvation, the entry keeps its age).
    struct ProposedOut { bytes32 key; ScriptRef pay; u64 amount; };
    struct Proposal { std::vector<ProposedOut> outs; };

    // `pay_of` resolves a key to its payout ScriptRef (from the fold's identity
    // view); `h_min_of` gives the byte-denominated floor for a script kind.
    template <typename PayOf, typename HminOf>
    Proposal propose_coinbase(u64 block_reward, unsigned slot_budget_C,
                              PayOf&& pay_of, HminOf&& h_min_of) const {
        // R3: the (first_eligible ASC, key ASC) positive view is maintained in
        // m_eo_index, so we take the first C in O(C log K) instead of rebuilding
        // and re-sorting the whole eligible set. The loop body — count cap,
        // budget stop, h_min CARRY (skip, no budget/age change), amount bound —
        // is byte-for-byte the shipped one; the ordered view yields the identical
        // sequence of keys (oracle KAT v37_w4_owed_incremental_test).
        Proposal prop;
        u64 budget = block_reward;
        m_eo_index.for_each_eligible([&](const bytes32& k) -> bool {
            // R1: slot_budget_C == 0 means UNBOUNDED output count (symmetric with
            // W5's max_payout_bytes == 0) — a 0 cap means "no count limit", NOT
            // "emit nothing". A positive C caps at the first C oldest-owed entries.
            if (slot_budget_C != 0 && prop.outs.size() >= slot_budget_C)
                return false;              // count cap (R1: 0 = unbounded)
            if (budget == 0) return false;
            long long owed = m_eo_index.value(k);
            if (owed <= 0) return true;    // (index holds only >0; defensive)
            u64 take = std::min<u64>(static_cast<u64>(owed), budget);
            ScriptRef pay = pay_of(k);
            if (take < h_min_of(pay.kind)) return true;   // sub-floor: CARRY
            budget -= take;
            prop.outs.push_back(ProposedOut{k, pay, take});
            return true;
        });
        return prop;
    }

    // The §4.5 OWED commitment over the FINALIZED partition only (pending keys
    // are re-derivable from the spine + FOUND set). Domain-separated sha256d,
    // sorted by key: "V37O" || key || i64 finalW || u64 first_eligible.
    bytes32 owed_digest() const {
        // R3: memoized on m_seq. owed_digest is a pure function of ledger state
        // and m_seq bumps on every mutation, so a hit at an equal seq is the
        // byte-identical digest (read_cut hashes twice per attempt at one seq).
        if (const bytes32* c = m_digest_memo.get(m_seq)) return *c;
        // R3: m_finalW is std::map<bytes32,long long>, already iterated in
        // ascending bytes32 order under std::less — the SAME comparator the old
        // std::sort used — so the removed sort reordered nothing; `pre` is
        // built byte-for-byte identically.
        std::vector<std::uint8_t> pre;
        const char tag[4] = {'V', '3', '7', 'O'};
        pre.insert(pre.end(), tag, tag + 4);
        for (const auto& [k, w] : m_finalW) {
            if (w == 0) continue;  // zero rows carry no commitment weight
            pre.insert(pre.end(), k.begin(), k.end());
            std::uint64_t uw = static_cast<std::uint64_t>(w);
            for (int i = 0; i < 8; ++i) pre.push_back((uw >> (8 * i)) & 0xff);
            u64 fe = 0;
            auto it = m_first_eligible.find(k);
            if (it != m_first_eligible.end()) fe = it->second;
            for (int i = 0; i < 8; ++i) pre.push_back((fe >> (8 * i)) & 0xff);
        }
        bytes32 d = ::v37::sha256d(pre);
        m_digest_memo.put(m_seq, d);
        return d;
    }

    // Diagnostics for the acceptance tests (never consensus).
    long long residual_total() const { return m_residual; }
    const std::vector<std::pair<std::string, long long>>& residual_events()
        const { return m_residual_events; }
    bool is_settled(const std::string& bid) const {
        return m_settled.count(bid) != 0;
    }
    bool is_pending(const std::string& bid) const {
        return m_pending.count(bid) != 0;
    }
    std::size_t pending_count() const { return m_pending.size(); }
    const Amounts& finalW() const { return m_finalW; }

private:
    struct Pending { Amounts credit; Amounts payout; };

    void bump() { ++m_seq; }

    // Re-arm/disarm first_eligible: a key whose EffectiveOwed just went from
    // <=0 to >0 is armed at `bin_height` (its age start); a key back at <=0 is
    // disarmed. Monotone bin_height (the coin high-water) is the K_fair clock.
    void rearm_first_eligible(u64 bin_height) {
        // R3: arm/disarm over every key the index tracks. That key set is the
        // shipped (finalW ∪ pending-payout) union PLUS only keys whose eo ≤ 0
        // and which carry no fe (disarm is a no-op on them, since fe(k) is set
        // only when eo>0 and fe implies a finalW row that keeps k in the union),
        // so the resulting m_first_eligible map is identical to iterating
        // effective_owed_all() (oracle KAT v37_w4_owed_incremental_test).
        m_eo_index.for_each_eo([&](const bytes32& k, long long e) {
            if (e > 0) {
                if (!m_first_eligible.count(k)) m_first_eligible[k] = bin_height;
            } else {
                m_first_eligible.erase(k);
            }
        });
        // Re-establish the ordered positive view from the just-updated fe.
        m_eo_index.rebuild_order([this](const bytes32& k) { return fe_at(k); });
    }

    // R3 (prune): drop finalW rows that are exactly 0 AND unarmed. owed_digest
    // already skips w==0 (so the commitment is unchanged), StateCommitment reads
    // only w>0 rows, and effective_owed on an absent key reads 0 identically to
    // a present 0 row (a later credit recreates the row via m_finalW[k]+=v). The
    // "unarmed" conjunct guarantees no live K_fair age state is dropped. Bounds
    // finalW growth so it does not retain settled-to-zero payees forever.
    void prune_finalized_zero_rows() {
        for (auto it = m_finalW.begin(); it != m_finalW.end();) {
            if (it->second == 0 && !m_first_eligible.count(it->first))
                it = m_finalW.erase(it);
            else
                ++it;
        }
    }

    // fe(k) with a 0 default — the value the index reads to order the positive
    // view (first_eligible stays owned HERE; the index is never a second
    // source of truth for the age key). Concrete return type so it can be
    // called from the mutation methods defined earlier in the class.
    u64 fe_at(const bytes32& k) const {
        auto it = m_first_eligible.find(k);
        return it == m_first_eligible.end() ? u64(0) : it->second;
    }

    ::v37::ChainId m_chain;
    u64 m_seq = 0;
    Amounts m_finalW;                              // finalized owed partition
    std::map<std::string, Pending> m_pending;      // FOUND, not yet finalized
    std::set<std::string> m_settled;               // SETTLED — terminal
    std::map<bytes32, u64> m_first_eligible;       // K_fair age key
    long long m_residual = 0;                      // priced post-SETTLED loss
    std::vector<std::pair<std::string, long long>> m_residual_events;
    detail::EffectiveOwedIndex m_eo_index;         // R3: incremental EffectiveOwed + ordered view
    mutable detail::DigestMemo m_digest_memo;      // R3: seq-keyed owed_digest memo
};

// ─────────────────────────────────────────────────────────────────────────
// ★★ S-1 (Track A2) — THE EMISSION SURFACE. S-1 does NOT recompute the owed
// commitment. It EMITS OwedLedger::owed_digest() of the very ledger object the
// S8 fold populated — one value, read once, carried to whichever template leg
// this lane rides:
//   BTC / DASH : the "V37S" summary leaf of w5_coinbase's StateCommitment,
//                whose Merkle root is committed in the coinbase at TEMPLATE
//                time (whitepaper §13), before the block hash is fixed.
//   XMR        : the merge-mining leaf (0x03 MM tag) via
//                xmr_o2_settlement_source's lane_commitment_from_owed_digest.
// Because both legs read the SAME accessor of the SAME object, S8 ≡ S-1 is
// automatic; the only way to break it is to emit at a DIFFERENT ledger state
// than the one the cut was taken at. emit_owed_at_cut() is the guard against
// exactly that: it refuses (nullopt, a hard refusal) unless the ledger still
// stands at the cut's (chain, ledger_seq, owed_digest). A template built on a
// refusal is simply not built this tick — never built on a stale commitment.
// ──────────────────────────────────────────────────────────────────────

struct OwedEmission {
    ::v37::ChainId chain = 0;
    u64            ledger_seq = 0;
    bytes32        owed_digest{};   // == OwedLedger::owed_digest() at ledger_seq
    bool operator==(const OwedEmission&) const = default;
};

// The unconditional read — the value S-1 emits. Never recomputes: it is the
// ledger's own accessor, memoized on the ledger's seq.
inline OwedEmission emit_owed(const OwedLedger& ledger) {
    OwedEmission e;
    e.chain       = ledger.chain();
    e.ledger_seq  = ledger.ledger_seq();
    e.owed_digest = ledger.owed_digest();
    return e;
}

// The cut-BOUND read — what a template build must use. Refuses unless the
// ledger is still exactly where the O2 cut token found it.
inline std::optional<OwedEmission> emit_owed_at_cut(const OwedLedger& ledger,
                                                    const CutToken& cut) {
    const OwedEmission e = emit_owed(ledger);
    if (e.chain != cut.chain) return std::nullopt;
    if (e.ledger_seq != cut.ledger_seq) return std::nullopt;
    if (e.owed_digest != cut.owed_digest) return std::nullopt;
    return e;
}

// ─────────────────────────────────────────────────────────────────────────
// The O2 consistent-cut read (§6.3), lock-free. Reads the lane leg at the
// burial-gated (incarnation, version) via the ring, the ledger leg, and the
// coin high-water leg; re-reads all; mismatch → discard + retry; exhausting
// the retry budget returns nullopt (W5 tries again next tick). Never a lock,
// never a read on a neighbouring version (a ring miss → nullopt).
// ─────────────────────────────────────────────────────────────────────────

inline std::optional<CutToken> read_cut(const V37Engine& engine,
                                        ::v37::ChainId chain, u64 incarnation,
                                        u64 version, const OwedLedger& ledger,
                                        const SettleHW& hw,
                                        unsigned retry_budget = 4) {
    for (unsigned attempt = 0; attempt < retry_budget; ++attempt) {
        auto sv0 = engine.settlement_view_at(chain, incarnation, version);
        if (!sv0) return std::nullopt;                 // ring miss → slow path
        u64 seq0 = ledger.ledger_seq();
        bytes32 od0 = ledger.owed_digest();
        u64 hwh0 = hw.hw_height;
        bytes32 hwt0 = hw.hw_tip;

        // re-read every leg; any change means the cut did not hold
        auto sv1 = engine.settlement_view_at(chain, incarnation, version);
        if (!sv1 || sv1->digest != sv0->digest) continue;
        if (ledger.ledger_seq() != seq0 || ledger.owed_digest() != od0) continue;
        if (hw.hw_height != hwh0 || hw.hw_tip != hwt0) continue;

        CutToken t;
        t.chain = chain;
        t.incarnation = incarnation;
        t.version = version;
        t.next_pos = sv0->next_pos;
        t.spine_digest = sv0->digest;
        t.ledger_seq = seq0;
        t.owed_digest = od0;
        t.hw_height = hwh0;
        t.hw_tip = hwt0;
        return t;
    }
    return std::nullopt;
}

}  // namespace c2pool::v37n::settle
