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
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <c2pool/v37/v37_engine.hpp>          // V37Engine, SettlementView
#include <c2pool/v37/v37_subthreshold_estimator.hpp>
#include <c2pool/v37/v37_drops_enrollment.hpp>   // ★ R-SYBIL: the ex-ante enrolment book  // RDWR-OQ2 DROPS estimator (merged, gated)
#include <sharechain/v37/v37_lane_executor.hpp>  // LaneSnapshot, IdentityView
#include <sharechain/v37/v37_descriptor.hpp>     // ScriptRef, ScriptKind
#include <sharechain/v37/v37_descriptor_xmr.hpp> // A2: XMR_LANE_GA split in project()
#include <sharechain/v37/v37_fixed.hpp>          // U256, u64
#include <sharechain/v37/v37_hash.hpp>           // bytes32, sha256d
#include <c2pool/v37/w4_owed_incremental.hpp>    // R3: DigestMemo, EffectiveOwedIndex
#include <c2pool/v37/owed_event_log.hpp>         // owed-event MMR: the record log BESIDE owed_digest

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
    // A2: a composite give_author lane identity (XMR_LANE_GA) is split here,
    // once, for every consumer. Fast path: no composite -> the vector above,
    // byte-identical to before A2.
    bool any_ga = false;
    for (const auto& wp : out) if (wp.pay.kind == ::v37::xmr::XMR_LANE_GA) { any_ga = true; break; }
    if (!any_ga) return out;
    std::vector<WeightedPayee> merged;
    std::map<bytes32, std::size_t> at;          // key -> index in `merged` (first appearance)
    auto add = [&](const bytes32& key, const U256& w, const ScriptRef& pay) {
        if (w.is_zero()) return;
        auto it = at.find(key);
        if (it == at.end()) { at.emplace(key, merged.size()); merged.push_back(WeightedPayee{key, w, pay}); }
        else merged[it->second].weight += w;
    };
    for (const auto& wp : out) {
        ::v37::xmr::XmrGiveAuthor g;
        if (wp.pay.kind == ::v37::xmr::XMR_LANE_GA && ::v37::xmr::decode_xmr_give_author(wp.pay, g)) {
            const auto sp = ::v37::xmr::xmr_ga_split(wp.weight, g.d);
            add(::v37::xmr::xmr_identity_key(g.payee), sp.payee, g.payee);
            add(::v37::xmr::xmr_identity_key(g.donation), sp.donation, g.donation);
        } else {
            add(wp.key, wp.weight, wp.pay);
        }
    }
    return merged;
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
// rule).
//
// ★ NO-DOUBLE-COUNT (DROPS-R2, operator-ruled: REPLACE, never ADD). The canon
// rule is mode = 1, COMBINED, which estimates a worker's TOTAL interval work —
// the S shares included. It is therefore composed by REPLACEMENT: the estimate
// stands in for the interval's share-derived contribution W_shares = S*T rather
// than being added to it. subthreshold_credit() returns the REPLACE DELTA
// Hhat_comb - W_shares and compose_credit_replace() is the only composition. In
// mode = 0, EstimateOnly, a covered interval (S > 0) is refused outright and the
// worker keeps only its E_b. Both modes credit exactly ONE unbiased estimate of
// the interval per (payee, interval); neither can pay for the same share twice.
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
    sp.mode    = (p.subthreshold.mode == 2) ? subthreshold::CreditMode::Count
               : (p.subthreshold.mode == 1) ? subthreshold::CreditMode::Combined
                                            : subthreshold::CreditMode::EstimateOnly;
    sp.count_floor_shift = p.subthreshold.count_floor_shift;
    return sp;
}

// ★ PRE-RULING REFERENCE, NEVER THE SHIPPED CREDIT PATH. This is the raw
// HASH-COUNT delta with no enrolment question asked — the shape the seam had
// before DROPS-R1 (denomination) and R-SYBIL (ex-ante enrolment) were ruled. It
// stays because several merged KATs measure the estimator's sybil-neutrality
// through it and their goldens are minted on it. The SHIPPED path is
// subthreshold_credit(params, harvested, ctx) further down: it denominates both
// sides through the ordinary share -> E_b conversion and credits ONLY enrolled
// identities. Do not call this one from a node.
//
// The gated estimator REPLACE DELTA for a set of harvested intervals. GATE OFF
// => EMPTY map (nothing merged; on_block_found stays byte-identical to master).
// GATE ON => the per-(payee,interval)-deduped, sybil-neutral REPLACE delta
//            Hhat_comb - W_shares (see the module preamble). Never the broken
//            clamp, never the broken add: the module refuses both structurally.
// Shape == OwedLedger::Amounts (std::map<bytes32, long long>, the E_b shape).
//
// ★ VALUES MAY BE NEGATIVE. This is a DELTA, not a credit: adding it to E_b is
// what performs the REPLACEMENT. Do not clamp, do not drop negatives, and do not
// use it on its own as "the estimator's credit" — compose_credit_replace() below
// is the supported way to turn it into a credit map.
inline std::map<bytes32, long long> subthreshold_credit_raw_PRE_RULING(
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
            if (amt != 0) credit[payee] += amt;     // bytes32-keyed, signed delta
    }
    return credit;
}

// ★★ THE COMPOSITION — REPLACE, NEVER ADD (DROPS-R2, operator-ruled shape (b)).
//
// The ONE supported way to turn E_b plus a harvest into the credit map the
// OwedLedger folds. For every harvested (payee, interval) the estimator's
// TOTAL-interval-work figure REPLACES the interval's share-derived contribution:
//
//     credit(p) = E_b(p) + SUM_i [ Hhat_comb(p,i) - W_shares(p,i) ]
//
// and NEVER  E_b(p) + SUM_i Hhat_comb(p,i), which pays a share-covered worker
// for its shares twice and measures 1.92..2.01x the work performed.
//
// The "+=" below is not the additive rule: subthreshold_credit() returns the
// REPLACE DELTA (Hhat - W_shares), and the module cannot emit Hhat without the
// matching -W_shares, so there is no reachable code path that adds an estimate
// on top of an intact E_b row. Adding a delta IS the replacement.
//
// GATE OFF (default) => the delta map is empty and this returns `base_credit`
// itself, byte for byte. USE THIS, not a hand-rolled merge, at every fold site:
// a second merge written somewhere else is how the double count came back.
inline std::map<bytes32, long long> compose_credit_replace_raw_PRE_RULING(
    const ::v37::LaneParams& params,
    const std::map<bytes32, long long>& base_credit,
    const std::vector<HarvestedReceipt>& harvested) {
    const auto delta = subthreshold_credit_raw_PRE_RULING(params, harvested);
    if (delta.empty()) return base_credit;          // ★ gate OFF / nothing eligible
    std::map<bytes32, long long> out = base_credit;
    for (const auto& [k, v] : delta) out[k] += v;   // E_b - W_shares + Hhat
    return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// ★★ DROPS-R1 (DENOMINATION) — RULED: REUSE THE NORMAL share -> E_b CONVERSION.
//
// THE DEFECT. The pre-ruling delta above is a HASH COUNT (fold63 of Hhat). E_b
// is a split of the block REWARD in coin units. Merging the two 1:1 dropped a
// raw hash count into a satoshi row: on the verify pass's fixture a 503,350,526
// sat entitlement met a 3,299,038,233,853 "credit" at share difficulty 2^40 — a
// factor of ~6553 in the wrong denomination, with the SIGN of the error set by
// the lane's difficulty, so it is not even a consistent bias.
//
// THE RULING. Do not invent a constant. The ordinary share path ALREADY turns
// work into an E_b row, in exactly one expression, split_reward():
//
//     E_b(p) = floor( reward * weight(p) / SUM weight )
//
// and on a live node weight(p) IS a hash count — the lane's payout weight is
// built from work(T) = 2^lz (w2_receipt.hpp work_of_lz), the same quantity the
// estimator produces. So the hashes -> satoshi conversion at a cut is the pair
// (reward, SUM weight) the fold has already read, and nothing else. WorkPrice is
// that pair, taken at the SAME cut through the SAME project() call the fold
// uses; entitlement_of_work() is split_reward's own floor(reward * w / SUM) with
// a wider numerator. Estimated work and real work of equal magnitude therefore
// map to the SAME number of satoshi. That is the whole content of R1, and it is
// a reuse, not a new spec constant.
//
// ★ WHAT IS NOT CLAIMED (stated here rather than quietly corrected). The lane's
// weights are DECAYED payout weights and a harvested interval is BURIED, so a
// buried interval's undecayed estimate is priced against a partly-decayed
// denominator. That residual is a second-order property of the ruled
// conversion, not a second conversion; it is called out in the PR body.
// ═══════════════════════════════════════════════════════════════════════════
struct WorkPrice {
    u64  reward = 0;       // the block reward this cut splits
    U256 sum_weight{};     // SUM weight over the projected payees AT THE CUT
    bool valid = false;    // false => no conversion expressible (no weight at P)
};

// Build the price from the SAME view the fold reads, through the SAME project().
template <class View>
inline WorkPrice work_price_at(u64 reward, const View& v) {
    WorkPrice wp;
    wp.reward = reward;
    for (const auto& p : project(v)) wp.sum_weight += p.weight;
    wp.valid = !wp.sum_weight.is_zero();
    return wp;
}

// ★ THE Q-SCALE — THE OTHER HALF OF THE REUSE, AND THE EASY ONE TO MISS.
// A push does not put a payee's raw work into the lane; it puts
//     w_scaled = w_raw x InvD[age]          (v37_lane.hpp SCORING, Q62)
// so the lane's payout weights — and therefore SUM weight in a WorkPrice — are
// in Q62 WORK UNITS, not in hashes. Reusing "the normal share -> E_b
// conversion" therefore means putting the estimate through the SAME scaling
// before pricing it. Skipping it is the quiet half of the denomination defect:
// it does not blow the credit up, it FLOORS EVERY COMPOSED CREDIT TO ZERO
// (2^62 is ~4.6e18, so reward * hashes / SUM weight underflows to 0) — a "fix"
// that would have looked perfectly harmless in a digest.
//
// ★ WHAT IS REUSED, AND WHAT IS NOT. The Q62 UNIT is reused exactly. The AGE
// factor InvD[age] is NOT: the estimate is priced as work AT THE CUT
// (InvD == 1.0), while the buried interval's real shares carry their own
// lambda^k. The residual is therefore bounded by the decay over the burial
// depth, it is in the direction of crediting an estimate slightly RICHER than a
// same-aged real share, and it is stated in the PR body rather than quietly
// corrected here — folding a decay lookup into this seam would be a second
// conversion, which is exactly what the ruling said not to invent.
inline constexpr unsigned kWeightQBits = ::v37::FRAC_BITS;   // 62

namespace wide {

// The numerator of the R1 conversion as a 576-bit little-endian value (9 x u64):
//     (work << kWeightQBits) * reward
// work is a u320 (5 limbs) and reward a u64, so the product is at most 384 bits
// and the Q-shift takes it to at most 446; 9 limbs leaves head-room for the
// shift to be applied AFTER the multiply without a second carry pass.
inline std::array<u64, 9> work_numerator(const subthreshold::u320& work, u64 reward) {
    std::array<u64, 9> r{0, 0, 0, 0, 0, 0, 0, 0, 0};
    ::v37::u128 carry = 0;
    for (int i = 0; i < 5; ++i) {
        ::v37::u128 p = ::v37::u128(work.w[static_cast<std::size_t>(i)]) * reward + carry;
        r[static_cast<std::size_t>(i)] = static_cast<u64>(p);
        carry = p >> 64;
    }
    r[5] = static_cast<u64>(carry);
    constexpr unsigned sft = kWeightQBits;
    static_assert(sft > 0 && sft < 64, "the Q-shift must be a single-limb shift");
    for (int i = 8; i > 0; --i)
        r[static_cast<std::size_t>(i)] =
            (r[static_cast<std::size_t>(i)] << sft) |
            (r[static_cast<std::size_t>(i - 1)] >> (64 - sft));
    r[0] = r[0] << sft;
    return r;
}
inline void shl1_9(std::array<u64, 9>& x) {
    u64 carry = 0;
    for (int i = 0; i < 9; ++i) {
        u64 nc = x[static_cast<std::size_t>(i)] >> 63;
        x[static_cast<std::size_t>(i)] = (x[static_cast<std::size_t>(i)] << 1) | carry;
        carry = nc;
    }
}
inline bool ge_u256_9(const std::array<u64, 9>& rem, const U256& den) {
    for (int i = 8; i >= 4; --i) if (rem[static_cast<std::size_t>(i)]) return true;
    for (int i = 3; i >= 0; --i)
        if (rem[static_cast<std::size_t>(i)] != den.v[static_cast<std::size_t>(i)])
            return rem[static_cast<std::size_t>(i)] > den.v[static_cast<std::size_t>(i)];
    return true;   // equal
}
inline void sub_u256_9(std::array<u64, 9>& rem, const U256& den) {
    ::v37::u128 borrow = 0;
    for (int i = 0; i < 9; ++i) {
        u64 d = (i < 4) ? den.v[static_cast<std::size_t>(i)] : 0;
        ::v37::u128 diff = ::v37::u128(rem[static_cast<std::size_t>(i)]) - d - borrow;
        rem[static_cast<std::size_t>(i)] = static_cast<u64>(diff);
        borrow = (diff >> 64) ? 1 : 0;
    }
}
// floor(num / den), clamped into [0, INT64_MAX]. Bit for bit the same long
// division wide::divmod() already runs for split_reward, just wider.
// `saturated` reports the clamp: it does not fire on a live cut (a payee's work
// is bounded by the weight sum, so the quotient is bounded by the reward), and
// the KAT asserts it stays false across the whole mint.
inline long long divfloor_clamped_576(const std::array<u64, 9>& num, const U256& den,
                                      bool* saturated) {
    if (saturated) *saturated = false;
    if (den.is_zero()) return 0;
    constexpr unsigned __int128 kI64Max = (unsigned __int128)9223372036854775807ull;
    std::array<u64, 9> rem{0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned __int128 q = 0;
    bool sat = false;
    for (int bit = 575; bit >= 0; --bit) {
        shl1_9(rem);
        rem[0] |= (num[static_cast<std::size_t>(bit / 64)] >> (bit % 64)) & 1ull;
        q <<= 1;
        if (ge_u256_9(rem, den)) { sub_u256_9(rem, den); q |= 1; }
        if (q > kI64Max) { sat = true; q = kI64Max; }
    }
    if (saturated) *saturated = sat;
    return static_cast<long long>(q);
}

}  // namespace wide

// The R1 conversion: a hash count at this cut -> the entitlement (coin) the
// ordinary share path would have produced for the SAME magnitude of work:
//     floor( reward * (work << Q) / SUM weight )
// which is split_reward()'s own floor(reward * weight / SUM weight) with the
// estimate put into lane-weight units first. Nothing else, and no new constant.
inline long long entitlement_of_work(const WorkPrice& price,
                                     const subthreshold::u320& work,
                                     bool* saturated = nullptr) {
    if (saturated) *saturated = false;
    if (!price.valid || price.reward == 0) return 0;
    return wide::divfloor_clamped_576(wide::work_numerator(work, price.reward),
                                      price.sum_weight, saturated);
}

// The inverse view, for a KAT or an operator that wants to read a lane weight
// back as hashes: weight >> Q. Diagnostic only; nothing on the credit path
// calls it (the credit path never leaves weight units).
inline u64 hashes_of_weight_lo(const U256& weight) {
    constexpr unsigned sft = kWeightQBits;
    // (weight >> 62), low limb only: 62 is a single-limb shift, so limb 0 takes
    // the top (64 - 62) bits of limb 0 and the bottom 62 bits of limb 1.
    return (weight.v[0] >> sft) | (weight.v[1] << (64 - sft));
}

// ★★ THE COMPOSITION CONTEXT. Both operator rulings that a composition cannot be
// correct without, in one value that every call site must supply:
//   price       R1  — how work becomes coin AT THIS CUT.
//   enrollment  R-SYBIL — who may be composed at all, decided ex ante.
// There is deliberately NO default constructor shortcut on the seam: a caller
// that has neither gets an invalid price (credits 0) and a null book (nobody
// enrolled, so nothing is credited), which is the fail-closed shape. What it
// never gets is the pre-ruling raw-hash-count, everybody-in behaviour.
struct DropsCompose {
    WorkPrice price{};
    const ::c2pool::v37n::EnrollmentBook* enrollment = nullptr;   // null => nobody
    bool enrolled(const bytes32& payee, u64 interval) const {
        return enrollment != nullptr && enrollment->enrolled(payee, interval);
    }
    ::v37::bytes32 enrollment_digest() const {
        return enrollment ? enrollment->book_digest()
                          : ::c2pool::v37n::empty_enrollment_digest();
    }
};

// ★ THE SHIPPED DELTA. Gate OFF => EMPTY. Gate ON => for every harvested
// (payee, interval) whose payee is ENROLLED at that interval, the DENOMINATED
// replace delta
//     entitlement_of_work(price, Hhat_comb) - entitlement_of_work(price, W_shares)
// deduped per (payee, interval). A non-enrolled payee contributes NOTHING — not
// a zero row, nothing — and keeps its ordinary S*T entitlement intact.
//
// Both sides are denominated SEPARATELY and then subtracted, the same shape the
// pre-ruling fold used, so a from-spec re-derivation lands on the same integer.
inline std::map<bytes32, long long> subthreshold_credit(
    const ::v37::LaneParams& params,
    const std::vector<HarvestedReceipt>& harvested,
    const DropsCompose& ctx,
    bool* saturated = nullptr) {
    std::map<bytes32, long long> credit;
    if (saturated) *saturated = false;
    const subthreshold::SubthresholdParams sp = to_subthreshold_params(params);
    if (!sp.enabled) return credit;                 // ★ GATE OFF: nothing enters
    std::map<subthreshold::DedupKey, bool> already_seen;
    for (const auto& hr : harvested) {
        subthreshold::DedupKey key;
        key.payee = hr.payee;
        key.seq   = hr.interval;
        const subthreshold::IntervalWork w =
            subthreshold::interval_work(sp, key, hr.collector, already_seen,
                                        ctx.enrolled(hr.payee, hr.interval));
        if (!w.credited) continue;
        bool s1 = false, s2 = false;
        const long long amt = entitlement_of_work(ctx.price, w.est, &s1)
                            - entitlement_of_work(ctx.price, w.covered, &s2);
        if (saturated && (s1 || s2)) *saturated = true;
        if (amt != 0) credit[hr.payee] += amt;      // may be NEGATIVE: not clamped
    }
    return credit;
}

// Add an already-composed DROPS delta map to an E_b map. This is the ONE place
// a delta becomes a credit, and it is shared by both settlement paths:
//   own win    the delta this node composed from its OWN harvest;
//   peer win   the delta the WINNER composed, read off the v0x03 wire trailer
//              (operator ruling R3 — the peer folds the RECEIVED map, because a
//              raindrop is a node-local observation the peer never saw and so
//              cannot recompute).
inline std::map<bytes32, long long> compose_credit_from_delta(
    const std::map<bytes32, long long>& base_credit,
    const std::map<bytes32, long long>& delta) {
    if (delta.empty()) return base_credit;          // byte for byte the base map
    std::map<bytes32, long long> out = base_credit;
    for (const auto& [k, v] : delta) out[k] += v;   // E_b - W_shares + Hhat
    return out;
}

// ★★ THE SHIPPED COMPOSITION — REPLACE, NEVER ADD, DENOMINATED, ENROLLED-ONLY.
// GATE OFF (default) => the delta map is empty and this returns `base_credit`
// itself, byte for byte. USE THIS, not a hand-rolled merge, at every fold site.
inline std::map<bytes32, long long> compose_credit_replace(
    const ::v37::LaneParams& params,
    const std::map<bytes32, long long>& base_credit,
    const std::vector<HarvestedReceipt>& harvested,
    const DropsCompose& ctx) {
    return compose_credit_from_delta(base_credit,
                                     subthreshold_credit(params, harvested, ctx));
}

// ─────────────────────────────────────────────────────────────────────────
// (3) The OWED ledger — ledger #2, KEYED_CRDT overlay, finality-gated, SETTLED
// terminal (§4). Off the coin chain (M4 lock): every node computes it from the
// same events. Single-writer fold; ledger_seq is its monotonic version. Amounts
// are signed (long long) so over-credit from a re-derived E_b nets forward as a
// negative EffectiveOwed (§4.4, forward repair, unclamped) — never a clawback.
// ─────────────────────────────────────────────────────────────────────────

// Ledger rules only the XMR lane turns on (docs/xmr-lane/payout-threshold.md
// §6, §6a). Default: off, so Family A ledgers stay byte-identical.
//   arm_floor          first_eligible (the K_fair age) is armed only while
//                      finalW >= arm_floor, never below it: a parked sub-floor
//                      balance earns no seniority (external review 02). A key
//                      without an age is not paid by the owed pass.
//   rotate_on_payment  a key paid in a finalized block that still has a
//                      balance re-arms at that block's bin_height: paid ->
//                      back of the queue (external review 04, audit O-1).
//   decay_horizon,     DUST DECAY (payout-threshold.md §5; needs arm_floor).
//   decay_half_life    A balance with 0 < finalW < arm_floor decays only when
//                      its key is GONE: a FINALIZE credited other keys but not
//                      it (while a miner works, every lane block credits it,
//                      DROPS near-miss credit included; a pool that finds no
//                      block decays nobody). From that bin it keeps its balance
//                      for decay_horizon more bins (one lane window to come
//                      back), then halves at the FINALIZE that enters each
//                      decay_half_life, down to 0. A new credit clears it. Never a donation: the write-off only
//                      lowers the pool's liability. Each FINALIZE that writes
//                      off carries the amounts in its owed-event leaf.
//
//   anchor_cut         (XMR, share-level canonical coinbase, ruling A
//                      2026-09-29): the ledger carries the ANCHOR, the
//                      on-chain credit cut (P, spine) of the most recent lane
//                      block FINALIZED into it. A lane block pays its pay-now
//                      and books its E_b at the anchor of the ledger it builds
//                      on, not at its own cut, so every input of its coinbase
//                      is finalized state, the same on every node, and a
//                      relayed share can be checked against it without
//                      reproducing the builder's node-local lane. The block's
//                      own cut becomes the anchor when it finalizes. Committed
//                      in owed_digest ("V37A").
// DROPS WINDOW (OwedLedgerRules::drops_window, handoff A4b): the lane geometry
// the window weights are read with. A share at age a (positions behind the
// cut) weighs rw * 2^62 * lambda^a (Q62, lambda = 2^(-1/half_life)) while
// a < window; sub-threshold work w (the estimator's unit, 2^work_lz per share)
// weighs (w << (62 - work_lz)) * rw * lambda^a, the same unit. All integer.
struct DropsWindowRule {
    u64      window = 0;      // W, lane positions (0 = rule off)
    u64      half_life = 0;   // the lane's half_life (positions)
    u64      epoch_len = 0;   // the lane's E (DecayTables geometry)
    u64      rw = 0;          // one receipt's lane weight (Q62 units of 2^62)
    unsigned work_lz = 0;     // log2 of one share's work in the estimator unit
    bool on() const { return window && half_life && epoch_len && rw && work_lz && work_lz <= 62; }
    bool operator==(const DropsWindowRule&) const = default;
};
#define C2POOL_XMR_DROPS_WINDOW 1   // the A4b window API is present (KATs test for it)

struct OwedLedgerRules {
    long long arm_floor = 0;
    bool      rotate_on_payment = false;
    u64       decay_horizon = 0;     // 0 = off
    u64       decay_half_life = 0;
    bool      anchor_cut = false;
    // MERKLE ROWS (XMR, paper §13): owed_digest commits the balances as the
    // ROOT of a Merkle tree over the rows, so a light client proves one
    // balance with a path of log2(rows) hashes instead of every row:
    //   leaf  = sha256d("V37L" || key || i64 finalW || u64 first_eligible)
    //   node  = sha256d("V37M" || left || right); an odd last node is carried up
    //   rest  = sha256d("V37X" || the V37K / V37A sections, as before)
    //   owed_digest = sha256d("V37Y" || u64 rows || root || rest)
    // Off: owed_digest is the flat "V37Q" hash, byte-identical.
    bool      merkle_rows = false;
    // DROPS DUE (XMR, handoff A5, ruling 2026-09-30; turned on with the anchor):
    // a lane block's composed DROPS delta D_B is never credit. It is held in
    // B's pending row as a DEPOSIT and enters the committed map `due` at B's
    // FINALIZE. Every canonical lane block C booked on this ledger CLAIMS the
    // whole avail = due - SUM(pending claims): its E_b becomes
    // max(0, E_b + avail) per key (apply_drops_due), anything negative left over
    // is written off, and at FINALIZE(C) due -= claimed, due += D_C. `due` is
    // committed in owed_digest ("V37U"). Off: no deposit, no claim, no section.
    bool      drops_due = false;
    // RAINDROP ENROL (XMR, handoff A3, ruling 2026-09-30; turned on with the
    // DROPS due): the ledger keeps the DROPS enrolment REGISTRY, one record
    // per payee {effective_from, payout ref}. A lane block's FOUND carries the
    // payees its composition enrolled by raindrop (enrol_add: the first
    // raindrop bin + 1 inside its harvest range, for payees absent from the
    // registry); they join the registry at its FINALIZE and leave with an
    // ORPHAN before it. The next composition's enrolment book reads the
    // registry (finalized + pending), and a DROPS-only payee is paid through
    // the registry ref (ledger state, never node-local). The finalized
    // registry is committed in owed_digest ("V37G"). Off: no registry, no
    // section, byte-identical.
    bool      raindrop_enrol = false;
    // DROPS WINDOW (XMR, handoff A4b, operator ruling 2026-10-01 "Window
    // price"; turned on with the DROPS due): sub-threshold work is not priced
    // once. A lane block's composition books each payee's credited
    // sub-threshold work per bin (the Count REPLACE delta in work units, signed)
    // as WINDOW WEIGHT at that bin's lane position; it joins the committed
    // window `dwin` at the block's FINALIZE and is paid in EVERY lane block
    // whose cut holds it in the window, decayed by its age exactly like a
    // share (drops_window_merge). The deposit / due path then carries nothing
    // (no one-shot price, never paid twice). Committed in owed_digest ("V37W").
    // Off (window == 0): no window, no section, byte-identical.
    DropsWindowRule drops_window{};
};

// ANCHOR (OwedLedgerRules::anchor_cut): a lane block's on-chain credit cut, raw
// (w4 is chain-generic; the XMR tree maps it to credit::CreditCut).
struct AnchorCut {
    u64     next_pos = 0;
    bytes32 spine{};
    bool operator==(const AnchorCut&) const = default;
};

#define C2POOL_V37_DROPS_DUE 1   // the A5 DROPS-due API is present (KATs test for it)

// DROPS DUE (OwedLedgerRules::drops_due): what one FOUND carries for the due.
//   deposit   D_B, the block's composed DROPS delta (signed). It enters `due`
//             at FINALIZE(B), never B's credit.
//   claim     the booking is canonical: it took `claimed` into its E_b.
//   claimed   the avail snapshot the booking folded (drops_available() of the
//             booking-point ledger), the folded part and the written-off part
//             together. It leaves `due` at FINALIZE(B); ORPHAN(B) returns it.
//   writeoff  diagnostics only: the negative part apply_drops_due could not
//             net (never carried, never a clawback). Not persisted.
//   enrol_add (raindrop_enrol rule only) the payees this block's composition
//             enrolled by raindrop; they join the registry at FINALIZE(B).
// RAINDROP ENROL (OwedLedgerRules::raindrop_enrol): one registry record, a
// payee enrolled by raindrop, effective from `eff` (its first raindrop bin + 1:
// ex ante) and paid through `ref` (the PoW-bound payee ref the raindrop named;
// identity == xmr_identity_key(ref), so every node derives the same ref).
struct DropsEnrolRec {
    u64              eff = 0;
    ::v37::ScriptRef ref;
    bool operator==(const DropsEnrolRec& o) const { return eff == o.eff && ref == o.ref; }
};
using DropsEnrolRegistry = std::map<bytes32, DropsEnrolRec>;
#define C2POOL_XMR_RAINDROP_ENROL 1   // the A3 registry API is present (KATs test for it)

// DROPS WINDOW (A4b): window entries, (c, n, payee) -> signed sub-threshold
// work in the estimator's unit. c is the bin's END position on the lane prefix
// (the number of receipts at or below the bin), so at a cut with next_pos N the
// bin's last slot is N - c positions old: the age of the bin's last share.
// A4c (ruling 2026-10-01: withholding a share never pays): n is the number of
// the bin's receipts on the prefix (its slots are the n positions up to c), and
// the entry weighs the MEAN of lambda^age over those n slots
// (drops_window_weights), which is what a share of the same work weighs at a
// slot of its bin: the same work weighs the same as a share or as raindrops.
// n == 0 (a bin without a receipt) weighs at c.
struct DropsWindowKey {
    u64     c = 0;
    u64     n = 0;
    bytes32 payee{};
    DropsWindowKey() = default;
    DropsWindowKey(u64 c_, const bytes32& k) : c(c_), payee(k) {}
    DropsWindowKey(u64 c_, u64 n_, const bytes32& k) : c(c_), n(n_), payee(k) {}
    bool operator<(const DropsWindowKey& o) const {
        if (c != o.c) return c < o.c;
        if (n != o.n) return n < o.n;
        return payee < o.payee;
    }
    bool operator==(const DropsWindowKey& o) const { return c == o.c && n == o.n && payee == o.payee; }
};
using DropsWindow = std::map<DropsWindowKey, long long>;
#define C2POOL_XMR_DROPS_WINDOW_SPAN 1   // A4c: entries carry the bin span (KATs test for it)

// A bin on the lane prefix: its end position c and its receipt count n
// (subthreshold_window's pos_of returns it).
struct DropsBinSpan {
    u64 c = 0;
    u64 n = 0;
};

struct DropsFound {
    std::map<bytes32, long long> deposit;
    bool                         claim = false;
    std::map<bytes32, long long> claimed;
    std::map<bytes32, long long> writeoff;
    DropsEnrolRegistry           enrol_add;
    DropsWindow                  window;   // DROPS WINDOW (drops_window rule only): the block's window entries
    bool empty() const { return deposit.empty() && !claim && claimed.empty() && enrol_add.empty() && window.empty(); }
    bool operator==(const DropsFound& o) const {
        return deposit == o.deposit && claim == o.claim && claimed == o.claimed && enrol_add == o.enrol_add &&
               window == o.window;
    }
};

// The canonical bytes of window entries (the V37W section and the FOUND leaf):
// u64 count, then per entry u64 c || u64 n || key(32) || i64 work, (c, n, key)
// ascending.
inline void put_drops_window(std::vector<std::uint8_t>& b, const DropsWindow& w) {
    const std::uint64_t n = w.size();
    for (int i = 0; i < 8; ++i) b.push_back((n >> (8 * i)) & 0xff);
    for (const auto& [ck, v] : w) {
        for (int i = 0; i < 8; ++i) b.push_back((ck.c >> (8 * i)) & 0xff);
        for (int i = 0; i < 8; ++i) b.push_back((ck.n >> (8 * i)) & 0xff);
        b.insert(b.end(), ck.payee.begin(), ck.payee.end());
        const std::uint64_t uv = static_cast<std::uint64_t>(v);
        for (int i = 0; i < 8; ++i) b.push_back((uv >> (8 * i)) & 0xff);
    }
}

// lambda^age in Q62 on the lane's own decay tables (decay[age mod E] x
// epoch_shift[age / E]), for age < rule.window. Integer only.
class DropsWindowDecay {
public:
    explicit DropsWindowDecay(const DropsWindowRule& r) : m_E(r.epoch_len) {
        m_tab.init(r.half_life, r.epoch_len, r.epoch_len, r.window / r.epoch_len + 4);
    }
    u64 at(u64 age) const {
        const u64 d = m_tab.decay[age % m_E];
        const u64 e = age / m_E;
        return e == 0 ? d : ::v37::mul_q64(d, m_tab.epoch_shift[e]);
    }
private:
    u64 m_E;
    ::v37::DecayTables m_tab;
};

// A4c: the decay of an entry whose bin's last slot is `a0` positions old and
// which spans n slots (ages a0 .. a0 + n - 1): the MEAN of lambda^age over the
// slots, a slot at or beyond the window weighing zero exactly like a share
// there. floor(SUM / n), integer only; n == 0 => lambda^a0 (the entry at c).
inline u64 drops_window_mean_decay(const DropsWindowDecay& dec, u64 a0, u64 n, u64 W) {
    if (n == 0) return dec.at(a0);
    ::v37::u128 sum = 0;
    for (u64 i = 0; i < n && a0 + i < W; ++i) sum += dec.at(a0 + i);
    return static_cast<u64>(sum / n);
}

// Per payee, the window weight at a cut with next_pos N, split by sign:
// (positive part, negative part), each a SUM of |work| << (62 - lz) * rw *
// mean_{slots} lambda^age (drops_window_mean_decay) over the entries with
// c <= N and N - c < W.
using DropsWindowWeights = std::map<bytes32, std::pair<U256, U256>>;
inline DropsWindowWeights drops_window_weights(const DropsWindow& w, u64 N, const DropsWindowRule& r) {
    DropsWindowWeights out;
    if (!r.on() || w.empty()) return out;
    const DropsWindowDecay dec(r);
    for (const auto& [ck, v] : w) {
        if (v == 0 || ck.c > N || N - ck.c >= r.window) continue;
        const u64 mag = v < 0 ? (v == std::numeric_limits<long long>::min() ? (u64(1) << 63) : u64(-v)) : u64(v);
        U256 x = U256::from_u128(static_cast<::v37::u128>(mag) << (62 - r.work_lz)).mul_small(r.rw);
        x = x.mul_q(drops_window_mean_decay(dec, N - ck.c, ck.n, r.window));
        auto& e = out[ck.payee];
        if (v > 0) e.first += x; else e.second += x;
    }
    return out;
}

// THE WINDOW SPLIT INPUT: the cut's projected share payees with the window's
// DROPS weight added per key (a DROPS-only payee joins with `pay_of(key)`),
// each key's total clamped at zero (a net-negative key weighs nothing and is
// dropped). split_reward over the result divides the reward exactly once: the
// DROPS work is in every payee's weight AND in the SUM. Rule off or no entry
// in the window: the input vector itself, byte for byte.
template <class PayOf>
inline std::vector<WeightedPayee> drops_window_merge(const std::vector<WeightedPayee>& shares,
                                                     const DropsWindow& w, u64 N,
                                                     const DropsWindowRule& r, PayOf&& pay_of) {
    const DropsWindowWeights dw = drops_window_weights(w, N, r);
    if (dw.empty()) return shares;
    // One row per key (key ascending): share weight + DROPS positive part,
    // minus the DROPS negative part, clamped at zero.
    std::map<bytes32, std::pair<U256, ScriptRef>> acc;
    for (const auto& p : shares) {
        auto [it, fresh] = acc.try_emplace(p.key, p.weight, p.pay);
        if (!fresh) it->second.first += p.weight;
    }
    for (const auto& [k, pn] : dw) {
        (void)pn;
        if (!acc.count(k)) acc.emplace(k, std::make_pair(U256{}, pay_of(k)));
    }
    std::vector<WeightedPayee> out;
    for (const auto& [k, wp] : acc) {
        U256 pos = wp.first;
        U256 neg{};
        if (auto it = dw.find(k); it != dw.end()) { pos += it->second.first; neg = it->second.second; }
        if (!(neg < pos)) continue;                        // net <= 0: weighs nothing
        out.push_back(WeightedPayee{k, pos - neg, wp.second});
    }
    return out;
}

// The canonical bytes of registry records (the V37G section and the FOUND
// leaf): u64 n, then per record key(32) || u64 eff || u8 kind || u8 len || payload.
// The V37G record writes a ref's payload length in ONE byte. A longer ref
// would make the section ambiguous, so the wiring refuses such a raindrop
// before it is harvested (XmrDropsWiring::on_raindrop); XMR refs are <= 132.
inline constexpr std::size_t kEnrolRefMaxPayload = 255;
inline void put_enrol_records(std::vector<std::uint8_t>& b, const DropsEnrolRegistry& m) {
    const std::uint64_t n = m.size();
    for (int i = 0; i < 8; ++i) b.push_back((n >> (8 * i)) & 0xff);
    for (const auto& [k, r] : m) {
        b.insert(b.end(), k.begin(), k.end());
        for (int i = 0; i < 8; ++i) b.push_back((r.eff >> (8 * i)) & 0xff);
        b.push_back(static_cast<std::uint8_t>(r.ref.kind));
        b.push_back(static_cast<std::uint8_t>(r.ref.payload.size() & 0xff));
        b.insert(b.end(), r.ref.payload.begin(), r.ref.payload.end());
    }
}

// Saturating signed add (integer audit: no wrap on a consensus path).
inline long long drops_sat_add(long long a, long long b) {
    long long r = 0;
    if (__builtin_add_overflow(a, b, &r)) return b > 0 ? std::numeric_limits<long long>::max()
                                                       : std::numeric_limits<long long>::min();
    return r;
}

// THE CLAMP (A5): E'(k) = max(0, E(k) + avail(k)) for every key of `avail`;
// the negative remainder min(0, E(k) + avail(k)) goes to *writeoff. Keys of E
// that are not in `avail` are untouched; a zero E' drops the key. Applied
// BEFORE the pay-now allocation (the builder) and before the spend-floor
// credit_delta (the receiver), so both see the same E'.
inline void apply_drops_due(std::map<bytes32, long long>& credit,
                            const std::map<bytes32, long long>& avail,
                            std::map<bytes32, long long>* writeoff = nullptr) {
    for (const auto& [k, a] : avail) {
        if (a == 0) continue;
        auto it = credit.find(k);
        const long long v = drops_sat_add(it == credit.end() ? 0 : it->second, a);
        if (v > 0) { credit[k] = v; continue; }
        if (it != credit.end()) credit.erase(it);
        if (v < 0 && writeoff) (*writeoff)[k] = v;
    }
}

// ★ DROPS WINDOW (A4b): the SAME composition as subthreshold_credit, the same
// rows, the same enrolment and the same per-(payee, interval) dedup, but in
// WORK, not coin: each credited (payee, bin) row books est - covered (the
// Count REPLACE delta, signed, saturated into i64) at the bin's span on the
// lane prefix, pos_of(bin) = DropsBinSpan{end position c, receipts n} (A4c:
// the entry weighs the mean over the bin's slots). Nothing is priced here: the window
// prices it in every lane block that holds it (drops_window_merge). Gate OFF
// => EMPTY.
template <class PosOf>
inline DropsWindow subthreshold_window(const ::v37::LaneParams& params,
                                       const std::vector<HarvestedReceipt>& harvested,
                                       const DropsCompose& ctx, PosOf&& pos_of) {
    DropsWindow out;
    const subthreshold::SubthresholdParams sp = to_subthreshold_params(params);
    if (!sp.enabled) return out;
    std::map<subthreshold::DedupKey, bool> already_seen;
    constexpr u64 kMax = static_cast<u64>(std::numeric_limits<long long>::max());
    const auto low_i64 = [&](const subthreshold::u320& x) -> u64 {   // saturated at INT64_MAX
        for (int i = 1; i < 5; ++i) if (x.w[static_cast<std::size_t>(i)]) return kMax;
        return x.w[0] > kMax ? kMax : x.w[0];
    };
    for (const auto& hr : harvested) {
        subthreshold::DedupKey key;
        key.payee = hr.payee;
        key.seq   = hr.interval;
        const subthreshold::IntervalWork w =
            subthreshold::interval_work(sp, key, hr.collector, already_seen,
                                        ctx.enrolled(hr.payee, hr.interval));
        if (!w.credited) continue;
        long long v = 0;
        if (w.est.ge(w.covered)) { subthreshold::u320 d = w.est; d.sub(w.covered); v = static_cast<long long>(low_i64(d)); }
        else { subthreshold::u320 d = w.covered; d.sub(w.est); v = -static_cast<long long>(low_i64(d)); }
        if (v == 0) continue;
        const DropsBinSpan sp_of = pos_of(hr.interval);
        const DropsWindowKey ck(sp_of.c, sp_of.n, hr.payee);
        const long long e = drops_sat_add(out.count(ck) ? out.at(ck) : 0, v);
        if (e == 0) out.erase(ck); else out[ck] = e;
    }
    return out;
}

class OwedLedger {
public:
    using Amounts = std::map<bytes32, long long>;

    explicit OwedLedger(::v37::ChainId chain, OwedLedgerRules rules = {}) : m_chain(chain), m_rules(rules) {}

    const OwedLedgerRules& rules() const { return m_rules; }
    // The K_fair age of `k` (its first_eligible; 0 = none). Finalized-only, so
    // it is the same on every node at a booking point.
    u64 first_eligible_of(const bytes32& k) const { return fe_at(k); }

    ::v37::ChainId chain() const { return m_chain; }
    u64 ledger_seq() const { return m_seq; }

    // ── FOUND(b): the pool's own block b, with its per-key entitlement E_b
    // (the fold at b's burial-gated prefix) and the coinbase outputs broadcast
    // in b (K_fair over EffectiveOwed, from propose()). No finalW mutation —
    // deferred to finality. Durable, write-ahead (§5.2). Idempotent per bid.
    // ANCHOR: `cut` is the block's own on-chain credit cut; it becomes the
    // ledger's anchor when the block finalizes (anchor_cut rule only). A
    // block with no cut to offer (a seed, a debit-only non-canonical block)
    // passes none and leaves the anchor where it is.
    // DROPS DUE: `drops` (drops_due rule only; ignored otherwise) carries the
    // block's deposit D_B and, for a canonical booking, the avail snapshot it
    // claimed (drops_available() of the booking-point ledger). The caller has
    // already folded that snapshot into `credit` (apply_drops_due).
    void on_block_found(const std::string& bid, const Amounts& credit,
                        const Amounts& payout, std::optional<AnchorCut> cut = std::nullopt,
                        const DropsFound* drops = nullptr) {
        if (m_pending.count(bid) || m_settled.count(bid)) return;
        Pending p;
        for (const auto& [k, v] : credit) if (v != 0) p.credit[k] = v;
        for (const auto& [k, v] : payout) if (v != 0) p.payout[k] = v;
        if (m_rules.anchor_cut) p.cut = cut;
        if (m_rules.drops_due && drops) {
            for (const auto& [k, v] : drops->deposit) if (v != 0) p.deposit[k] = v;
            if (drops->claim)
                for (const auto& [k, v] : drops->claimed) if (v != 0) p.claimed[k] = v;
            for (const auto& [k, v] : drops->writeoff) { (void)k; p.writeoff = drops_sat_add(p.writeoff, v); }
        }
        if (m_rules.raindrop_enrol && drops)   // RAINDROP ENROL: the payees this block enrolled
            for (const auto& [k, r] : drops->enrol_add) if (r.eff != 0) p.enrol_add[k] = r;
        if (m_rules.drops_window.on() && drops)   // DROPS WINDOW: the block's window entries
            for (const auto& [ck, v] : drops->window) if (v != 0) p.window[ck] = v;
        m_eo_index.on_found(p.payout,                 // R3: eo -= payout (fe frozen)
                            [this](const bytes32& k) { return fe_at(k); });
        auto ins = m_pending.emplace(bid, std::move(p));
        // The leaf carries the NORMALIZED maps the ledger kept (zero rows
        // already dropped above), not the raw arguments.
        std::vector<std::uint8_t> leaf = owedevent::found_payload(bid, ins.first->second.credit,
                                                                  ins.first->second.payout);
        const Pending& q = ins.first->second;
        if (!q.deposit.empty() || !q.claimed.empty()) {   // DROPS DUE: never under the rule off
            const char tu[4] = {'V', '3', '7', 'U'};
            leaf.insert(leaf.end(), tu, tu + 4);
            owedevent::detail::put_amap(leaf, q.deposit);
            owedevent::detail::put_amap(leaf, q.claimed);
        }
        if (!q.enrol_add.empty()) {   // RAINDROP ENROL: never under the rule off
            const char tg[4] = {'V', '3', '7', 'G'};
            leaf.insert(leaf.end(), tg, tg + 4);
            put_enrol_records(leaf, q.enrol_add);
        }
        if (!q.window.empty()) {   // DROPS WINDOW: never under the rule off
            const char tw[4] = {'V', '3', '7', 'W'};
            leaf.insert(leaf.end(), tw, tw + 4);
            put_drops_window(leaf, q.window);
        }
        bump(leaf);
    }

    // RAINDROP ENROL: the registry at this booking point, the finalized records
    // plus the enrol_add of every pending row (the earliest eff wins; a payee
    // is enrolled once). Empty with the rule off.
    DropsEnrolRegistry drops_enrol_registry() const {
        DropsEnrolRegistry r;
        if (!m_rules.raindrop_enrol) return r;
        r = m_enrol;
        for (const auto& [bid, p] : m_pending) {
            (void)bid;
            for (const auto& [k, e] : p.enrol_add) {
                auto [it, fresh] = r.try_emplace(k, e);
                if (!fresh && e.eff < it->second.eff) it->second = e;
            }
        }
        return r;
    }
    // RAINDROP ENROL: the payout ref the registry holds for `k` (finalized or pending).
    std::optional<::v37::ScriptRef> drops_enrol_ref(const bytes32& k) const {
        if (!m_rules.raindrop_enrol) return std::nullopt;
        if (auto it = m_enrol.find(k); it != m_enrol.end()) return it->second.ref;
        for (const auto& [bid, p] : m_pending) {
            (void)bid;
            if (auto e = p.enrol_add.find(k); e != p.enrol_add.end()) return e->second.ref;
        }
        return std::nullopt;
    }
    // RAINDROP ENROL: the committed (finalized) registry.
    const DropsEnrolRegistry& drops_enrol_finalized() const { return m_enrol; }

    // DROPS DUE: what the next canonical booking on this ledger claims,
    // avail = due - SUM(claims of the pending rows), zero keys dropped. Empty
    // with the rule off.
    Amounts drops_available() const {
        Amounts a;
        if (!m_rules.drops_due) return a;
        a = m_due;
        for (const auto& [bid, p] : m_pending) {
            (void)bid;
            for (const auto& [k, v] : p.claimed) a[k] = drops_sat_add(a[k], -v);
        }
        for (auto it = a.begin(); it != a.end();) it = it->second == 0 ? a.erase(it) : std::next(it);
        return a;
    }
    // DROPS WINDOW: the committed (finalized) window, and THE split input of a
    // lane block booked on this ledger at a cut with next_pos N: the cut's
    // projected payees plus the window's DROPS weight at N
    // (drops_window_merge). A DROPS-only payee is paid through its registry
    // ref (RAINDROP ENROL, ledger state). Rule off: `shares` unchanged.
    const DropsWindow& drops_window() const { return m_dwin; }
    std::vector<WeightedPayee> drops_window_merge(const std::vector<WeightedPayee>& shares, u64 N) const {
        if (!m_rules.drops_window.on() || m_dwin.empty()) return shares;
        return ::c2pool::v37n::settle::drops_window_merge(shares, m_dwin, N, m_rules.drops_window,
            [this](const bytes32& k) { const auto r = drops_enrol_ref(k); return r ? *r : ScriptRef{}; });
    }
    // DROPS DUE: the committed (finalized) map and the written-off total.
    const Amounts& drops_due() const { return m_due; }
    long long drops_written_off() const { return m_drops_writeoff; }

    // ── RDWR-OQ2 wiring: FOUND(b) with the gated sub-threshold estimator folded
    // into the per-key credit. `base_credit` is the ordinary E_b entitlement
    // (settle_block over b's burial-gated prefix); `harvested` carries the
    // OUT-of-interval, buried near-miss receipts (F1 monotone bin_height, never
    // tip). GATE OFF (default) => subthreshold_credit() returns {} and this
    // forwards `base_credit` UNCHANGED to on_block_found() — byte-identical to
    // master (the estimator credit is add-only and materialises only when ON).
    // GATE ON => for every harvested (payee, interval) with J >= K, the corrected
    // sybil-neutral Hhat_comb REPLACES that interval's share-derived contribution
    // to E_b (compose_credit_replace above), deduped per (payee, interval). An
    // UNCOVERED worker (S == 0) has nothing to replace and is credited the whole
    // estimate; a SHARE-COVERED worker is credited Hhat_comb INSTEAD of its S*T,
    // never on top of it. This is the single call site of the estimator in the
    // fold, and compose_credit_replace is the single composition.
    void on_block_found_estimator_raw_PRE_RULING(
        const std::string& bid, const Amounts& base_credit, const Amounts& payout,
        const ::v37::LaneParams& params,
        const std::vector<HarvestedReceipt>& harvested) {
        on_block_found(bid,
                       compose_credit_replace_raw_PRE_RULING(params, base_credit,
                                                             harvested),
                       payout);
    }

    // ★ THE SHIPPED SEAM. Same shape, with the two rulings the pre-ruling form
    // is missing: `ctx.price` denominates the estimate into the SAME units as
    // E_b (R1) and `ctx.enrollment` decides, ex ante, whose interval may be
    // composed at all (R-SYBIL). GATE OFF => forwards base_credit unchanged.
    void on_block_found_with_drops(
        const std::string& bid, const Amounts& base_credit, const Amounts& payout,
        const ::v37::LaneParams& params,
        const std::vector<HarvestedReceipt>& harvested,
        const DropsCompose& ctx) {
        on_block_found(bid,
                       compose_credit_replace(params, base_credit, harvested, ctx),
                       payout);
    }

    // ★ THE CARRIED-DELTA SEAM (R3). The winner's composed DROPS map, folded as
    // it was received. No harvest, no estimator call: the map IS the estimate.
    void on_block_found_with_carried_drops(
        const std::string& bid, const Amounts& base_credit, const Amounts& payout,
        const Amounts& carried_delta) {
        on_block_found(bid, compose_credit_from_delta(base_credit, carried_delta),
                       payout);
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
        std::vector<bytes32> paid;                            // rotate_on_payment
        if (m_rules.rotate_on_payment)
            for (const auto& [k, v] : it->second.payout) if (v > 0) paid.push_back(k);
        if (decay_on()) {                                     // DUST DECAY: a credit restarts the clock
            bool credits = false;
            for (const auto& [k, v] : it->second.credit) if (v > 0) credits = true;
            for (const auto& [k, v] : it->second.credit)
                if (v > 0) { m_gone_since.erase(k); m_decay_steps.erase(k); }
            if (credits)   // every sub-floor key this lane block passed by is gone from now
                for (const auto& [k, w] : m_finalW)
                    if (w > 0 && w < m_rules.arm_floor && !m_gone_since.count(k) &&
                        !(it->second.credit.count(k) && it->second.credit.at(k) > 0))
                        m_gone_since[k] = bin_height;
        }
        if (m_rules.anchor_cut && it->second.cut) m_anchor = *it->second.cut;   // ANCHOR
        if (m_rules.drops_due) {   // DROPS DUE: due -= claimed (the whole snapshot), due += D_B
            for (const auto& [k, v] : it->second.claimed) m_due[k] = drops_sat_add(m_due[k], -v);
            for (const auto& [k, v] : it->second.deposit) m_due[k] = drops_sat_add(m_due[k], v);
            for (auto d = m_due.begin(); d != m_due.end();) d = d->second == 0 ? m_due.erase(d) : std::next(d);
            m_drops_writeoff = drops_sat_add(m_drops_writeoff, it->second.writeoff);
        }
        if (m_rules.raindrop_enrol)   // RAINDROP ENROL: the block's enrolments join the registry
            for (const auto& [k, e] : it->second.enrol_add) {
                auto [r, fresh] = m_enrol.try_emplace(k, e);
                if (!fresh && e.eff < r->second.eff) r->second = e;
            }
        if (m_rules.drops_window.on()) {   // DROPS WINDOW: the block's entries join; entries past the window leave
            for (const auto& [ck, v] : it->second.window) m_dwin[ck] = drops_sat_add(m_dwin[ck], v);
            const u64 N = m_anchor ? m_anchor->next_pos : 0;
            for (auto d = m_dwin.begin(); d != m_dwin.end();)
                d = (d->second == 0 || (d->first.c <= N && N - d->first.c >= m_rules.drops_window.window))
                        ? m_dwin.erase(d) : std::next(d);
        }
        m_pending.erase(it);
        m_settled.insert(bid);
        const Amounts decayed = decay_dust(bin_height);
        rearm_first_eligible(bin_height, paid);
        prune_finalized_zero_rows();                          // R3: drop 0/unarmed rows
        // FINALIZE consumes only (bid, bin_height); the amounts came from the
        // pending row the ledger already held, so the leaf carries no maps,
        // except the dust written off at this FINALIZE (empty when decay is off).
        bump(decayed.empty() ? owedevent::finalize_payload(bid, bin_height)
                             : owedevent::leaf_payload(owedevent::EV_FINALIZE, bid, bin_height, {}, {}, decayed));
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
            // The settled_payout argument is IGNORED on this branch, so it is
            // kept out of the leaf too: two nodes whose ledgers are identical
            // must not commit different roots because one caller passed {} and
            // the other passed the payout map.
            bump(owedevent::orphan_pre_payload(bid));
            return;
        }
        if (m_settled.count(bid)) {
            long long residual = 0;
            for (const auto& [k, v] : settled_payout) residual += v;
            if (residual > 0) {
                m_residual += residual;
                m_residual_events.push_back({bid, residual});
            }
            // surfaced as a ledger event; finalW untouched (terminal)
            bump(owedevent::orphan_settled_payload(bid, settled_payout));
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
        for_each_in_turn([&](const bytes32& k, int) -> bool {
            // R1: slot_budget_C == 0 means UNBOUNDED output count (symmetric with
            // W5's max_payout_bytes == 0) — a 0 cap means "no count limit", NOT
            // "emit nothing". A positive C caps at the first C oldest-owed entries.
            if (slot_budget_C != 0 && prop.outs.size() >= slot_budget_C)
                return false;              // count cap (R1: 0 = unbounded)
            if (budget == 0) return false;
            long long owed = m_eo_index.value(k);
            if (owed <= 0) return true;    // (index holds only >0; defensive)
            if (m_rules.arm_floor > 0 && !m_first_eligible.count(k)) return true;   // no age yet: below the floor
            u64 take = std::min<u64>(static_cast<u64>(owed), budget);
            ScriptRef pay = pay_of(k);
            if (take < h_min_of(pay.kind)) return true;   // sub-floor: CARRY
            budget -= take;
            prop.outs.push_back(ProposedOut{k, pay, take});
            return true;
        });
        return prop;
    }

    // SALTED TIE-BREAK (external review finding 08, #1867). Every key that
    // turns positive at one FINALIZE is armed at the same bin_height, so ties on
    // first_eligible are the normal case, and the unsalted secondary key (the
    // raw identity, ASC) lets a miner who grinds a low identity win every tie
    // cohort for good. This overload keeps first_eligible as the primary key
    // and orders each equal-age cohort by sha256d("V37T" || salt || key)
    // instead. The salt is a value the builder cannot choose and nobody can
    // predict before the parent block exists (the XMR builder passes the
    // parent block id). Take rules (count cap, budget stop, h_min CARRY, amount
    // bound) are exactly propose_coinbase's. Builder-side only: the order is
    // not committed in owed_digest, and the generic W5 path does not call it.
    template <typename PayOf, typename HminOf>
    Proposal propose_coinbase_salted(u64 block_reward, unsigned slot_budget_C,
                                     const bytes32& salt, PayOf&& pay_of,
                                     HminOf&& h_min_of) const {
        Proposal prop;
        u64 budget = block_reward;
        bool stop = false;
        // Returns false once a stop condition (count cap / budget) is reached.
        auto take = [&](const bytes32& k) -> bool {
            if (slot_budget_C != 0 && prop.outs.size() >= slot_budget_C) return false;
            if (budget == 0) return false;
            long long owed = m_eo_index.value(k);
            if (owed <= 0) return true;
            if (m_rules.arm_floor > 0 && !m_first_eligible.count(k)) return true;   // no age yet: below the floor
            u64 amt = std::min<u64>(static_cast<u64>(owed), budget);
            ScriptRef pay = pay_of(k);
            if (amt < h_min_of(pay.kind)) return true;   // sub-floor: CARRY
            budget -= amt;
            prop.outs.push_back(ProposedOut{k, pay, amt});
            return true;
        };
        std::uint8_t pre[4 + 32 + 32] = {'V', '3', '7', 'T'};   // one buffer: no allocation per key
        std::memcpy(pre + 4, salt.data(), 32);
        auto salted = [&](const bytes32& k) {
            std::memcpy(pre + 36, k.data(), 32);
            return ::v37::sha256d(pre, sizeof(pre));
        };
        std::vector<std::pair<bytes32, bytes32>> cohort;   // (salted, key)
        u64 cohort_fe = 0;
        int cohort_pass = 0;
        auto flush = [&]() {
            std::sort(cohort.begin(), cohort.end());
            for (const auto& [h, k] : cohort) {
                (void)h;
                if (!take(k)) { stop = true; break; }
            }
            cohort.clear();
        };
        for_each_in_turn([&](const bytes32& k, int pass) -> bool {
            const u64 fe = fe_at(k);
            if (!cohort.empty() && (fe != cohort_fe || pass != cohort_pass)) {
                flush();
                if (stop) return false;
            }
            cohort_fe = fe;
            cohort_pass = pass;
            cohort.emplace_back(salted(k), k);
            return true;
        });
        if (!stop && !cohort.empty()) flush();
        return prop;
    }

    // The §4.5 OWED commitment over the FINALIZED partition only (pending keys
    // are re-derivable from the spine + FOUND set). Domain-separated sha256d,
    // sorted by key: "V37Q" || key || i64 finalW || u64 first_eligible.
    // (R-A: tag bumped V37O->V37Q when fe became finalized-only; the "over the
    //  FINALIZED partition only" contract below is now literally enforced.)
    // ---- MERKLE ROWS (paper §13) --------------------------------------------
    static bytes32 owed_leaf(const bytes32& k, long long w, u64 fe) {
        std::uint8_t b[4 + 32 + 8 + 8] = {'V', '3', '7', 'L'};
        std::memcpy(b + 4, k.data(), 32);
        const std::uint64_t uw = static_cast<std::uint64_t>(w);
        for (int i = 0; i < 8; ++i) b[36 + i] = static_cast<std::uint8_t>(uw >> (8 * i));
        for (int i = 0; i < 8; ++i) b[44 + i] = static_cast<std::uint8_t>(fe >> (8 * i));
        return ::v37::sha256d(b, sizeof(b));
    }
    static bytes32 owed_node(const bytes32& l, const bytes32& r) {
        std::uint8_t b[4 + 64] = {'V', '3', '7', 'M'};
        std::memcpy(b + 4, l.data(), 32);
        std::memcpy(b + 36, r.data(), 32);
        return ::v37::sha256d(b, sizeof(b));
    }
    // Root of the leaves (bytes32{} for none). An odd last node is carried up
    // unchanged, never paired with itself, so no two leaf lists share a root
    // for the same count (the count is committed beside it).
    static bytes32 owed_merkle_root(std::vector<bytes32> level) {
        if (level.empty()) return bytes32{};
        while (level.size() > 1) {
            std::vector<bytes32> up;
            up.reserve((level.size() + 1) / 2);
            for (std::size_t i = 0; i + 1 < level.size(); i += 2) up.push_back(owed_node(level[i], level[i + 1]));
            if (level.size() % 2) up.push_back(level.back());
            level.swap(up);
        }
        return level[0];
    }
    static bytes32 owed_digest_of(u64 rows, const bytes32& root, const bytes32& rest) {
        std::uint8_t b[4 + 8 + 64] = {'V', '3', '7', 'Y'};
        for (int i = 0; i < 8; ++i) b[4 + i] = static_cast<std::uint8_t>(rows >> (8 * i));
        std::memcpy(b + 12, root.data(), 32);
        std::memcpy(b + 44, rest.data(), 32);
        return ::v37::sha256d(b, sizeof(b));
    }
    // A balance and its path to owed_digest: the row, its index among the
    // non-zero rows (key order), the row count, the sibling hashes root-ward
    // (a level where the node is carried up has none), and the digest of the
    // rest of the state.
    struct OwedProof {
        bytes32              key{};
        long long            finalW = 0;
        u64                  first_eligible = 0;
        u64                  index = 0;
        u64                  rows = 0;
        std::vector<bytes32> path;
        bytes32              rest{};
    };
    // The owed_digest this proof reproduces (nullopt: malformed). A verifier
    // compares it with the digest a block commits.
    static std::optional<bytes32> owed_digest_from_proof(const OwedProof& p) {
        if (p.rows == 0 || p.index >= p.rows || p.finalW == 0) return std::nullopt;
        bytes32 h = owed_leaf(p.key, p.finalW, p.first_eligible);
        u64 i = p.index, m = p.rows;
        std::size_t used = 0;
        while (m > 1) {
            if (i % 2 == 1) {                       // right child: sibling on the left
                if (used >= p.path.size()) return std::nullopt;
                h = owed_node(p.path[used++], h);
            } else if (i + 1 < m) {                 // left child with a right sibling
                if (used >= p.path.size()) return std::nullopt;
                h = owed_node(h, p.path[used++]);
            }                                       // else: odd last, carried up
            i /= 2;
            m = (m + 1) / 2;
        }
        if (used != p.path.size()) return std::nullopt;
        return owed_digest_of(p.rows, h, p.rest);
    }
    // The proof for a key's finalized balance under merkle_rows (nullopt: the
    // rule is off, or the key has no non-zero row).
    std::optional<OwedProof> prove_owed(const bytes32& k) const {
        if (!m_rules.merkle_rows) return std::nullopt;
        std::vector<bytes32> level;
        OwedProof p;
        bool found = false;
        for (const auto& [kk, w] : m_finalW) {
            if (w == 0) continue;
            if (kk == k) {
                found = true; p.key = kk; p.finalW = w; p.index = level.size();
                auto it = m_first_eligible.find(kk);
                p.first_eligible = it == m_first_eligible.end() ? 0 : it->second;
            }
            u64 fe = 0;
            if (auto it = m_first_eligible.find(kk); it != m_first_eligible.end()) fe = it->second;
            level.push_back(owed_leaf(kk, w, fe));
        }
        if (!found) return std::nullopt;
        p.rows = level.size();
        u64 i = p.index;
        while (level.size() > 1) {
            if (i % 2 == 1) p.path.push_back(level[i - 1]);
            else if (i + 1 < level.size()) p.path.push_back(level[i + 1]);
            std::vector<bytes32> up;
            for (std::size_t j = 0; j + 1 < level.size(); j += 2) up.push_back(owed_node(level[j], level[j + 1]));
            if (level.size() % 2) up.push_back(level.back());
            level.swap(up);
            i /= 2;
        }
        p.rest = rest_digest();
        return p;
    }

    bytes32 owed_digest() const {
        // R3: memoized on m_seq. owed_digest is a pure function of ledger state
        // and m_seq bumps on every mutation, so a hit at an equal seq is the
        // byte-identical digest (read_cut hashes twice per attempt at one seq).
        if (const bytes32* c = m_digest_memo.get(m_seq)) return *c;
        if (m_rules.merkle_rows) {   // MERKLE ROWS: root over the rows + the rest
            std::vector<bytes32> leaves;
            for (const auto& [k, w] : m_finalW) {
                if (w == 0) continue;
                u64 fe = 0;
                if (auto it = m_first_eligible.find(k); it != m_first_eligible.end()) fe = it->second;
                leaves.push_back(owed_leaf(k, w, fe));
            }
            const u64 rows = leaves.size();
            const bytes32 d = owed_digest_of(rows, owed_merkle_root(std::move(leaves)), rest_digest());
            m_digest_memo.put(m_seq, d);
            return d;
        }
        // R3: m_finalW is std::map<bytes32,long long>, already iterated in
        // ascending bytes32 order under std::less — the SAME comparator the old
        // std::sort used — so the removed sort reordered nothing; `pre` is
        // built byte-for-byte identically.
        std::vector<std::uint8_t> pre;
        const char tag[4] = {'V', '3', '7', 'Q'};   // R-A: bumped V37O->V37Q; fe is now finalized-only
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
        append_rest(pre);
        bytes32 d = ::v37::sha256d(pre);
        m_digest_memo.put(m_seq, d);
        return d;
    }

    // The V37K / V37A sections, byte for byte as the flat digest carries them.
    void append_rest(std::vector<std::uint8_t>& pre) const {
        if (decay_on()) {   // DUST DECAY state: it decides future balances, so it is committed
            const char kt[4] = {'V', '3', '7', 'K'};
            pre.insert(pre.end(), kt, kt + 4);
            for (const auto& [k, g] : m_gone_since) {
                auto ds = m_decay_steps.find(k);
                const u64 b = ds == m_decay_steps.end() ? 0 : ds->second;
                pre.insert(pre.end(), k.begin(), k.end());
                for (int i = 0; i < 8; ++i) pre.push_back((g >> (8 * i)) & 0xff);
                for (int i = 0; i < 8; ++i) pre.push_back((b >> (8 * i)) & 0xff);
            }
        }
        if (m_rules.drops_due) {   // DROPS DUE: it decides the E_b of the next canonical lane block
            const char ut[4] = {'V', '3', '7', 'U'};
            pre.insert(pre.end(), ut, ut + 4);
            const std::uint64_t n = m_due.size();
            for (int i = 0; i < 8; ++i) pre.push_back((n >> (8 * i)) & 0xff);
            for (const auto& [k, v] : m_due) {
                pre.insert(pre.end(), k.begin(), k.end());
                const std::uint64_t uv = static_cast<std::uint64_t>(v);
                for (int i = 0; i < 8; ++i) pre.push_back((uv >> (8 * i)) & 0xff);
            }
        }
        if (m_rules.raindrop_enrol) {   // RAINDROP ENROL: it decides the next enrolment book and DROPS-only refs
            const char gt[4] = {'V', '3', '7', 'G'};
            pre.insert(pre.end(), gt, gt + 4);
            put_enrol_records(pre, m_enrol);
        }
        if (m_rules.drops_window.on()) {   // DROPS WINDOW: it decides the E_b of every lane block it reaches
            const char wt[4] = {'V', '3', '7', 'W'};
            pre.insert(pre.end(), wt, wt + 4);
            put_drops_window(pre, m_dwin);
        }
        if (m_rules.anchor_cut) {   // ANCHOR: it decides every coinbase built on this state
            const char at[4] = {'V', '3', '7', 'A'};
            pre.insert(pre.end(), at, at + 4);
            pre.push_back(m_anchor ? 1 : 0);
            if (m_anchor) {
                for (int i = 0; i < 8; ++i) pre.push_back((m_anchor->next_pos >> (8 * i)) & 0xff);
                pre.insert(pre.end(), m_anchor->spine.begin(), m_anchor->spine.end());
            }
        }
    }
    bytes32 rest_digest() const {
        std::vector<std::uint8_t> pre = {'V', '3', '7', 'X'};
        append_rest(pre);
        return ::v37::sha256d(pre);
    }

    // ANCHOR: the credit cut of the most recent lane block finalized into this
    // state (nullopt: none yet, or the rule is off).
    std::optional<AnchorCut> anchor_cut() const { return m_anchor; }

    // DUST DECAY: the total written off so far (diagnostics / status line).
    long long decayed_total() const { return m_decayed_total; }

    // LEDGER HEALTH (diagnostics only, never consensus, digest-neutral). One
    // pass over the finalized partition and the pending payouts:
    //   sum_final        Σ finalW over every row: what the pool still owes net
    //                    of forward-repair debt. The owed-sign ruling C-3
    //                    requires sum_final >= 0 (aggregate_ok()).
    //   positive_*       the rows the pool owes (what K_fair will pay).
    //   negative_*       rows below zero: over-payment netted forward (C-1),
    //                    a negative DROPS delta (C-6), or a double pay. A
    //                    negative row whose owner stopped mining is never
    //                    repaid, so its sum is money the rest of the pool
    //                    carries.
    //   min_row/min_key  the most negative row (0 when none).
    //   pending_payout   Σ payout of FOUND-not-finalized blocks (deducted from
    //                    EffectiveOwed already, from finalW at FINALIZE).
    struct Health {
        std::size_t rows = 0;
        long long   sum_final = 0;
        std::size_t positive_rows = 0;
        long long   positive_sum = 0;
        std::size_t negative_rows = 0;
        long long   negative_sum = 0;
        long long   min_row = 0;
        bytes32     min_key{};
        long long   pending_payout = 0;
        std::size_t pending_blocks = 0;
        bool aggregate_ok() const { return sum_final >= 0; }
    };
    Health health() const {
        Health h;
        for (const auto& [k, v] : m_finalW) {
            ++h.rows;
            h.sum_final += v;
            if (v > 0) { ++h.positive_rows; h.positive_sum += v; }
            if (v < 0) {
                ++h.negative_rows; h.negative_sum += v;
                if (v < h.min_row) { h.min_row = v; h.min_key = k; }
            }
        }
        for (const auto& [bid, p] : m_pending) {
            (void)bid;
            ++h.pending_blocks;
            for (const auto& [k, v] : p.payout) { (void)k; h.pending_payout += v; }
        }
        return h;
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

    // ─────────────────────────────────────────────────────────────────────
    // ★ THE OWED-EVENT MMR — the append-only authenticated record of this
    // ledger's HISTORY, beside (never instead of) owed_digest().
    //
    // ADDITIVE AND ALWAYS-ON: computing and exposing this root changes no
    // existing commitment. owed_digest() above is the record's peer, not part of
    // it: adding this MMR root leaves owed_digest's body untouched. (R-A did
    // rebake owed_digest's own value — it bumped the tag to "V37Q" and made fe
    // finalized-only — but that is a change to owed_digest itself, orthogonal to
    // this MMR.) The w5 StateCommitment tree only carries this MMR root
    // when the compile-time gate V37_OWED_EVENT_MMR_COMMIT is 1, which it is
    // not by default.
    //
    // CONVERGENCE BY CONSTRUCTION: bump() is private and is the ONLY way
    // m_seq advances, and it cannot advance without appending exactly one
    // leaf. So leaf_count() == ledger_seq() always, the append order is the
    // mutation order, and two ledgers handed the same events in the same order
    // append the same leaves and bag the same root — there is no separate
    // "record the event" step that could be skipped, reordered or duplicated.
    // (LIVE cross-node convergence additionally requires that both nodes SEE
    // the same events; for a non-winning peer that is what the S-1c cut
    // descriptor propagation supplies, and it is out of this module's scope.)
    // ─────────────────────────────────────────────────────────────────────
    bytes32 owed_event_mmr_root() const { return m_evlog.root(); }
    u64 owed_event_leaf_count() const { return m_evlog.leaf_count(); }
    const ::v37::PeakSet& owed_event_peaks() const { return m_evlog.peaks(); }
    const owedevent::OwedEventLog& owed_event_log() const { return m_evlog; }
    // The structural invariant, as a checkable predicate (asserted by the KAT
    // and by w6 recovery, never assumed).
    bool owed_event_log_consistent() const {
        return m_evlog.consistent() && m_evlog.leaf_count() == m_seq;
    }

private:
    struct Pending {
        Amounts credit; Amounts payout; std::optional<AnchorCut> cut;
        Amounts deposit, claimed;   // DROPS DUE (rule on only)
        DropsEnrolRegistry enrol_add;   // RAINDROP ENROL (rule on only)
        DropsWindow window;         // DROPS WINDOW (rule on only)
        long long writeoff = 0;     // DROPS DUE diagnostics (never committed)
    };

    // The K_fair walk (first_eligible ASC, key ASC). With
    // OwedLedgerRules::rotate_on_payment, a key paid in a block that is still
    // pending walks after every other key (pass 1): its first_eligible moves to
    // the back only at FINALIZE, D_conf blocks later, and until then it must
    // not keep the front. The pending set at the booking point is the same on
    // every node (R6), so this order is too. fn(k, pass) -> false stops.
    template <typename Fn>
    void for_each_in_turn(Fn&& fn) const {
        if (!m_rules.rotate_on_payment) {
            m_eo_index.for_each_eligible([&](const bytes32& k) -> bool { return fn(k, 0); });
            return;
        }
        std::set<bytes32> recent;
        for (const auto& [bid, p] : m_pending) {
            (void)bid;
            for (const auto& [k, v] : p.payout) if (v > 0) recent.insert(k);
        }
        bool go = true;
        m_eo_index.for_each_eligible([&](const bytes32& k) -> bool {
            if (recent.count(k)) return true;
            go = fn(k, 0);
            return go;
        });
        if (!go || recent.empty()) return;
        m_eo_index.for_each_eligible([&](const bytes32& k) -> bool {
            if (!recent.count(k)) return true;
            return fn(k, 1);
        });
    }

    // The ONLY sequence advance. It mints the record-log leaf for the mutation
    // in the same step, so "one leaf per ledger_seq increment" is not a
    // convention a future edit can drift away from — there is no bump() that
    // records nothing.
    void bump(const std::vector<std::uint8_t>& leaf_payload) {
        m_evlog.append_payload(leaf_payload);
        ++m_seq;
    }

    // Re-arm/disarm first_eligible: a key whose EffectiveOwed just went from
    // <=0 to >0 is armed at `bin_height` (its age start); a key back at <=0 is
    // disarmed. Monotone bin_height (the coin high-water) is the K_fair clock.
    void rearm_first_eligible(u64 bin_height, const std::vector<bytes32>& paid = {}) {
        // R-A (P0 lane_commitment race-fork fix, RECON #1697): arm/disarm
        // first_eligible on the FINALIZED weight finalW(k) ALONE — NOT the
        // pending-netted EffectiveOwed(k) = finalW − Σ_pending payout. fe feeds
        // owed_digest() (§4.5), whose own contract (see owed_digest below) is
        // "over the FINALIZED partition only"; reading pending here was the sole
        // leak that let two nodes with identical SETTLED prefixes but different
        // in-flight pending sets commit different digests — the RECON
        // lane_commitment fork. Arming on finalW alone makes fe, and therefore
        // owed_digest(), a pure function of the buried/settled prefix.
        //
        // m_eo_index STILL serves propose_coinbase()'s value+order (it holds the
        // eo>0 positive view, ordered by fe_at), so the payout path is unchanged
        // and there is no double-pay: eo>0 ⇒ finalW>eo>0, so every eligible key
        // still has an fe; only the fe TIMESTAMP can move earlier (to when finalW
        // first went positive), which is the more-correct oldest-owed clock.
        //
        // Iterate m_finalW: every armed key has a finalW row (fe is set only for
        // a finalW>0 key, and prune_finalized_zero_rows never drops an armed row,
        // so fe-keys ⊆ finalW-keys — the iteration covers every disarm too).
        // OwedLedgerRules::arm_floor: armed only at or above the floor (0 = the
        // shipped w > 0 rule, byte-identical).
        const long long floor = m_rules.arm_floor > 1 ? m_rules.arm_floor : 1;
        for (const auto& [k, w] : m_finalW) {
            if (w >= floor) {
                if (!m_first_eligible.count(k)) m_first_eligible[k] = bin_height;
            } else {
                m_first_eligible.erase(k);
            }
        }
        // OwedLedgerRules::rotate_on_payment: paid in this block and still owed
        // -> its age restarts here (the back of the queue).
        for (const bytes32& k : paid) {
            auto fe = m_first_eligible.find(k);
            if (fe != m_first_eligible.end()) fe->second = bin_height;
        }
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
            if (it->second == 0 && !m_first_eligible.count(it->first)) {
                m_gone_since.erase(it->first);    // DUST DECAY state goes with the row
                m_decay_steps.erase(it->first);
                it = m_finalW.erase(it);
            } else {
                ++it;
            }
        }
    }

    bool decay_on() const { return m_rules.arm_floor > 0 && m_rules.decay_horizon > 0 && m_rules.decay_half_life > 0; }

    // DUST DECAY (OwedLedgerRules::decay_*). For every balance 0 < w < arm_floor
    // whose key has had no credit for decay_horizon bins: the number of halvings
    // due is 1 + (elapsed - horizon) / half_life; apply the ones not applied
    // yet. Returns the amounts written off at this FINALIZE, per key.
    Amounts decay_dust(u64 bin_height) {
        Amounts off;
        if (!decay_on()) return off;
        for (auto& [k, w] : m_finalW) {
            if (w <= 0 || w >= m_rules.arm_floor) continue;
            auto gs = m_gone_since.find(k);
            if (gs == m_gone_since.end()) continue;           // not gone: no lane block has passed it by
            if (bin_height < gs->second + m_rules.decay_horizon) continue;
            const u64 due = 1 + (bin_height - gs->second - m_rules.decay_horizon) / m_rules.decay_half_life;
            u64& done = m_decay_steps[k];
            if (due <= done) continue;
            const u64 n = due - done;
            const long long nw = n >= 63 ? 0 : (w >> n);
            off[k] = w - nw;
            done = due;
        }
        for (const auto& [k, v] : off) {
            m_finalW[k] -= v;
            m_decayed_total += v;
        }
        if (!off.empty()) {
            Amounts neg;
            for (const auto& [k, v] : off) neg[k] = -v;
            m_eo_index.apply_finalize_credit(neg);   // eo follows finalW
        }
        return off;
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
    OwedLedgerRules m_rules;
    std::map<bytes32, u64> m_gone_since;           // DUST DECAY: bin of the first lane block that passed it by
    std::map<bytes32, u64> m_decay_steps;          // DUST DECAY: halvings already applied
    long long m_decayed_total = 0;
    std::optional<AnchorCut> m_anchor;   // ANCHOR (OwedLedgerRules::anchor_cut)
    Amounts   m_due;                     // DROPS DUE (OwedLedgerRules::drops_due), finalized, committed "V37U"
    long long m_drops_writeoff = 0;      // DROPS DUE diagnostics: written off at FINALIZE (never committed)
    DropsWindow        m_dwin;           // DROPS WINDOW (OwedLedgerRules::drops_window), finalized, committed "V37W"
    DropsEnrolRegistry m_enrol;          // RAINDROP ENROL (OwedLedgerRules::raindrop_enrol), finalized, committed "V37G"
    u64 m_seq = 0;
    Amounts m_finalW;                              // finalized owed partition
    std::map<std::string, Pending> m_pending;      // FOUND, not yet finalized
    std::set<std::string> m_settled;               // SETTLED — terminal
    std::map<bytes32, u64> m_first_eligible;       // K_fair age key
    long long m_residual = 0;                      // priced post-SETTLED loss
    std::vector<std::pair<std::string, long long>> m_residual_events;
    detail::EffectiveOwedIndex m_eo_index;         // R3: incremental EffectiveOwed + ordered view
    mutable detail::DigestMemo m_digest_memo;      // R3: seq-keyed owed_digest memo
    owedevent::OwedEventLog m_evlog;               // owed-event MMR (additive; see bump())
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
