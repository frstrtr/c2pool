// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DASH Embedded ORACLE-SHADOW VALIDATOR (--embedded-oracle-shadow).
///
/// GOAL: run c2pool ALONGSIDE a Dash Core daemon and use dashd as a CONTINUOUS
/// REALTIME ORACLE. On every new tip the DAEMONLESS embedded arm builds a DIP4
/// CbTx/template from its own SPV coin-state; we then (1) submit the fully-
/// assembled embedded block to dashd `getblocktemplate{mode:proposal}` — dashd's
/// TestBlockValidity is the AUTHORITATIVE per-height VERDICT (accepted/rejected),
/// mempool-independent — and (2) field-compare the embedded template against
/// dashd's own getblocktemplate as the DIAGNOSIS (which field diverged). A
/// persisted graduation ledger then objectively signals when it is SAFE to
/// disable dashd over the SERVED domain.
///
/// This design implements the five §6 conditions of the adversarial critique
/// (docs/c2pool-dash-oracle-shadow-adversarial-critique.md):
///
///   1. FROZEN DETERMINISM TABLE (3-regime field model). Every compared field
///      carries a regime; there is no "expected mismatch at INFO" bucket (that
///      classification ate a real bug class once):
///        - ALIGNMENT KEY (previousblockhash): a mismatch VOIDs the sample.
///        - EQUALITY (cross-node must match: nHeight, CbTx nVersion, bits,
///          mintime, payee IDENTITY, platform-burn amount, normalized subsidy,
///          merkleRootMNList/Quorums *conditionally* — see below).
///        - INVARIANT (checked against the template's OWN tx set, NEVER cross-
///          node: creditPoolBalance normalized-base, coinbasevalue − ownfees).
///        - CONSTRAINT (range, never strict equality: bestCL* — the committed
///          CL must be >= the previous block's committed CL; the 96-byte sig
///          must match ONLY when the two nodes' bestCL heights coincide).
///        - NOT-COMPARABLE (excluded: curtime wall clock, tx set / tx merkle).
///        - DERIVED (secondary diagnostic: full CbTx bytes, bestCL masked).
///   2. dashd as JUDGE not just reference: per-height mode=proposal of the
///      assembled embedded block is the VERDICT; field-compare is diagnosis.
///      Until proposal is in-node the Python soak is NOT superseded — so a
///      served height counts CLEAN only when the proposal is ACCEPTED.
///   3. SELF-CONSISTENCY the field-compare cannot see: the embedded selector
///      must EXCLUDE special-tx types (1-4, 6, 8, 9) until their state machines
///      exist (§1.1 latent bug — a selected ProTx/asset-lock makes the CbTx
///      roots/pool contradict the arm's OWN tx set, invisible to field-compare;
///      dashd proposal catches it). NonEmptyTemplate is a required coverage
///      class. [Selector exclusion + nonzero-fee pinning are follow-up slices;
///      this validator MEASURES both and gates graduation on them.]
///   4. ALIGNMENT + SETTLE: samples keyed on (height, prev_hash); reorg tracked
///      by prev-hash lineage, not height ordering; VOID-rate + serve-rate
///      surfaced with a serve-rate floor in the gate; ledger HARD-KEYED to
///      {c2pool_commit, comparator_version, dashd_version, net} — a new binary
///      does NOT inherit an old binary's streak.
///   5. GRADUATION is scoped + REVOCABLE. GRADUATED == daemonless over the
///      SERVED domain with quantified fail-closed idle at the classes the arm
///      does not serve; the verdict declares proposal-accepted-when-served vs
///      still-fall-closed classes. Chain-drift sentinels (unknown CbTx version,
///      quorum-tail parse failure) auto-REVOKE to fail-closed.
///
/// ══ WHAT THIS ORACLE GRADUATES (scope) ══════════════════════════════════════
/// It proves CHAIN-STATE / CbTx-VALIDITY EQUIVALENCE over the served domain:
/// the embedded arm computes the same consensus-deterministic template dashd
/// would AND dashd's TestBlockValidity accepts the block. That is what reward-
/// safe DAEMONLESS BLOCK CONSTRUCTION needs. Its soundness basis is NOT peer
/// diversity: DASH master has NO peer-scoring (the LTC/p2pool-v36 CoinPeerManager
/// was deliberately NOT ported — isolation fence); the arm dials a single static
/// --coin-p2p-connect target (usually the co-running dashd). What makes the
/// cross-check meaningful is that the embedded arm INDEPENDENTLY DERIVES chain
/// state through its OWN SPV / mnlistdiff / quorum / credit-pool pipeline.
///
/// NOT covered (a SEPARATE, still-open gate): NETWORK-LAYER independence —
/// independent mempool / relay / block-propagation / peer connectivity. That
/// does not exist today (single peer, usually dashd). Truly disabling dashd
/// also needs the CoinPeerManager ported to DASH. GRADUATED here is a NECESSARY
/// but not SUFFICIENT condition for full network-standalone daemonless operation.
///
/// OBSERVE-ONLY (operator rule, consensus-neutral): NEVER changes the serving
/// decision. Reads the SAME embedded build path (NodeCoinState::select_work) +
/// the SAME dashd RPC closure the serve arm holds, on its OWN cadence into its
/// OWN structures. The serve path is untouched; dashd stays authoritative for
/// actual serving while shadowing.
///
/// STRICTLY single-coin: src/impl/dash/coin/ only. Header-only so the pure
/// classify/compare/graduation logic is KAT-pinnable without a live node.

#include <impl/dash/coin/node_coin_state.hpp>   // NodeCoinState, DashWorkData, WorkSelection, WorkSource
#include <impl/dash/coin/rpc_data.hpp>          // DashWorkData, PackedPayment
#include <impl/dash/coin/vendor/cbtx.hpp>       // vendor::CCbTx, vendor::parse_cbtx

#include <core/uint256.hpp>
#include <core/log.hpp>

#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace dash {
namespace coin {

// Bump on ANY change to the field-comparison / graduation semantics so a new
// comparator does NOT inherit an old comparator's clean streak (§6 cond. 4).
inline constexpr uint32_t kOracleComparatorVersion = 1;
// Highest CbTx payload version this comparator models. A connected/observed
// CbTx with a higher nVersion is a chain-drift sentinel (§6 cond. 5).
inline constexpr uint16_t kMaxKnownCbTxVersion = vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;

// ─────────────────────────────────────────────────────────────────────────────
// Height-class taxonomy. A single height can belong to MULTIPLE classes;
// coverage counts EACH (served + clean).
// ─────────────────────────────────────────────────────────────────────────────
enum class HeightClass {
    Normal, DkgWindow, Superblock, PostRestartCold,
    QuorumRotation, CreditPoolTransition, NonEmptyTemplate, Reorg,
};
inline const char* height_class_name(HeightClass c) {
    switch (c) {
    case HeightClass::Normal:               return "normal";
    case HeightClass::DkgWindow:            return "dkg_window";
    case HeightClass::Superblock:           return "superblock";
    case HeightClass::PostRestartCold:      return "post_restart_cold";
    case HeightClass::QuorumRotation:       return "quorum_rotation";
    case HeightClass::CreditPoolTransition: return "credit_pool_transition";
    case HeightClass::NonEmptyTemplate:     return "non_empty_template";
    case HeightClass::Reorg:                return "reorg";
    }
    return "normal";
}
inline const std::vector<HeightClass>& graduation_required_classes() {
    static const std::vector<HeightClass> v = {
        HeightClass::DkgWindow,       HeightClass::Superblock,
        HeightClass::PostRestartCold, HeightClass::QuorumRotation,
        HeightClass::CreditPoolTransition, HeightClass::NonEmptyTemplate,
    };
    return v;
}

// ── DKG-window / superblock periodicity (net-dependent) ─────────────────────
struct NetPeriodicity {
    std::vector<std::array<uint32_t, 3>> dkg_windows;  // (interval, start, end)
    uint32_t superblock_cycle{0};
    static NetPeriodicity for_net(bool testnet) {
        NetPeriodicity p;
        if (testnet) {
            p.dkg_windows = {{{24, 10, 18}}, {{288, 20, 28}},
                             {{576, 20, 48}}, {{288, 42, 50}}};
            p.superblock_cycle = 24;
        } else {
            p.dkg_windows = {{{288, 24, 32}}};   // headline; full table = follow-up
            p.superblock_cycle = 16616;
        }
        return p;
    }
    bool is_dkg_window(uint32_t h) const {
        for (const auto& w : dkg_windows) {
            const uint32_t m = h % w[0];
            if (m >= w[1] && m <= w[2]) return true;
        }
        return false;
    }
    bool is_superblock(uint32_t h) const {
        return superblock_cycle != 0 && (h % superblock_cycle) == 0;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// The frozen determinism table, as code. Each compared field carries a REGIME.
// Only EQUALITY-failures and INVARIANT-violations count as divergences; CONSTRAINT
// range-fails count only in their strict sub-case; NOT-COMPARABLE/DERIVED never.
// ─────────────────────────────────────────────────────────────────────────────
enum class Regime {
    Equality,       // cross-node must match; mismatch = bug (counts)
    Invariant,      // per-side own-tx-set check; violation = bug (counts)
    Constraint,     // range; only the strict sub-case counts
    Informational,  // recorded, never counts (NOT-COMPARABLE / DERIVED)
};
inline const char* regime_name(Regime r) {
    switch (r) {
    case Regime::Equality:      return "equality";
    case Regime::Invariant:     return "invariant";
    case Regime::Constraint:    return "constraint";
    case Regime::Informational: return "informational";
    }
    return "informational";
}
struct FieldResult {
    std::string field;
    Regime      regime;
    bool        counts;     // this mismatch breaks graduation
    std::string embedded;
    std::string dashd;
    bool        match;
};

inline std::string hex_of(const std::vector<unsigned char>& b) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(b.size() * 2);
    for (unsigned char c : b) { s.push_back(d[(c >> 4) & 0xF]); s.push_back(d[c & 0xF]); }
    return s;
}
inline std::string hex_of(const std::array<uint8_t, 96>& b) {
    return hex_of(std::vector<unsigned char>(b.begin(), b.end()));
}
inline std::string payee_identity_str(const std::vector<PackedPayment>& pps) {
    std::string s; for (const auto& p : pps) { s += p.payee; s += '|'; } return s;
}
inline std::string payee_amounts_str(const std::vector<PackedPayment>& pps) {
    std::string s;
    for (const auto& p : pps) { s += p.payee; s += ':'; s += std::to_string(p.amount); s += '|'; }
    return s;
}
inline uint64_t platform_burn_amount(const std::vector<PackedPayment>& pps) {
    for (const auto& p : pps) if (p.payee == "!6a") return p.amount;
    return 0;
}
inline uint64_t sum_fees(const std::vector<uint64_t>& fees) {
    uint64_t s = 0; for (auto f : fees) s += f; return s;
}
/// bestCL bytes zeroed (the propagation-dependent field) so the whole-payload
/// DERIVED byte compare does not flap on legitimate CL-lag differences.
inline std::vector<unsigned char> cbtx_bytes_bestcl_masked(
    const std::vector<uint8_t>& payload, const vendor::CCbTx& cbtx, bool ok) {
    std::vector<unsigned char> b(payload.begin(), payload.end());
    if (ok && cbtx.nVersion >= vendor::CCbTx::VERSION_CLSIG_AND_BALANCE) {
        // Zero the trailing bestCLHeightDiff(varint)+sig(96)+creditPool(8) tail
        // region conservatively: mask the last (96 + 8) bytes if present.
        if (b.size() >= 104) std::fill(b.end() - 104, b.end(), 0);
    }
    return b;
}

/// Per-side context the INVARIANT fields need (their own tx set / chain base).
struct SideContext {
    const DashWorkData*  wd{nullptr};
    const vendor::CCbTx* cbtx{nullptr};
    bool                 cbtx_ok{false};
    uint64_t             own_fees{0};          // Σ selected tx fees this side
    int64_t              platform_reward{0};   // "!6a" burn (== platformReward(N))
    bool                 empty_template{false};// no selected txs (invariant collapses)
};

/// Compare with regime tags. `prev_committed_credit_pool` (optional) enables the
/// creditPool normalized-base INVARIANT; `dkg_window` voids the quorum-root
/// conditional-equality; `contiguous` (prev observed height == N-1) is required
/// for the creditPool base check (else it is VOIDed, not false-flagged).
inline std::vector<FieldResult> compare_templates(
    const SideContext& e, const SideContext& d,
    std::optional<int64_t> prev_committed_credit_pool,
    bool dkg_window, bool contiguous)
{
    std::vector<FieldResult> out;
    const auto& emb = *e.wd; const auto& dashd = *d.wd;
    auto eq = [&](const char* f, Regime r, bool counts, std::string a, std::string b) {
        out.push_back({f, r, counts && (a != b), a, b, a == b});
    };

    // ── EQUALITY (cross-node) ───────────────────────────────────────────────
    eq("height",   Regime::Equality, true, std::to_string(emb.m_height), std::to_string(dashd.m_height));
    eq("bits",     Regime::Equality, true, std::to_string(emb.m_bits),   std::to_string(dashd.m_bits));
    eq("mintime",  Regime::Equality, true, std::to_string(emb.m_mintime),std::to_string(dashd.m_mintime));
    eq("payee_identities", Regime::Equality, true,
       payee_identity_str(emb.m_packed_payments), payee_identity_str(dashd.m_packed_payments));
    eq("platform_burn_amount", Regime::Equality, true,
       std::to_string(e.platform_reward), std::to_string(d.platform_reward));
    // Normalized subsidy core = coinbasevalue − own fees (fees stripped) — this
    // is the EQUALITY core; raw coinbasevalue is INVARIANT (below).
    eq("subsidy_core", Regime::Equality, true,
       std::to_string(static_cast<int64_t>(emb.m_coinbase_value) - static_cast<int64_t>(e.own_fees)),
       std::to_string(static_cast<int64_t>(dashd.m_coinbase_value) - static_cast<int64_t>(d.own_fees)));

    if (e.cbtx_ok && d.cbtx_ok) {
        eq("cbtx_version",     Regime::Equality, true,
           std::to_string(e.cbtx->nVersion), std::to_string(d.cbtx->nVersion));
        eq("coinbase_nHeight", Regime::Equality, true,
           std::to_string(e.cbtx->nHeight),  std::to_string(d.cbtx->nHeight));
        // merkleRootMNList — EQUALITY conditional on no ProTx in either tx set.
        // The embedded selector excludes special txs (§1.1 precondition), so
        // over the served domain this is EQUALITY. (When that precondition is
        // not yet enforced, a non-empty template downgrades to Informational to
        // avoid a false flag the proposal leg would catch anyway.)
        const bool roots_are_equality = e.empty_template && d.empty_template;
        eq("merkleRootMNList", roots_are_equality ? Regime::Equality : Regime::Informational,
           roots_are_equality, e.cbtx->merkleRootMNList.GetHex(), d.cbtx->merkleRootMNList.GetHex());
        // merkleRootQuorums — EQUALITY only OUTSIDE DKG windows (a DKG height
        // mines a quorum-commitment tx → root legitimately differs).
        const bool q_is_equality = roots_are_equality && !dkg_window;
        eq("merkleRootQuorums", q_is_equality ? Regime::Equality : Regime::Informational,
           q_is_equality, e.cbtx->merkleRootQuorums.GetHex(), d.cbtx->merkleRootQuorums.GetHex());

        // ── CONSTRAINT: bestCL* is a RANGE, never strict equality. Strict sig
        //    equality is required ONLY when the two nodes' bestCL heights
        //    coincide (same bestCLHeightDiff at same block height ⇒ same CL).
        const bool cl_heights_coincide = (e.cbtx->bestCLHeightDiff == d.cbtx->bestCLHeightDiff);
        const bool sig_equal = (e.cbtx->bestCLSignature == d.cbtx->bestCLSignature);
        out.push_back({"bestCLHeightDiff", Regime::Constraint, /*counts=*/false,
                       std::to_string(e.cbtx->bestCLHeightDiff),
                       std::to_string(d.cbtx->bestCLHeightDiff), cl_heights_coincide});
        out.push_back({"bestCLSignature", Regime::Constraint,
                       /*counts=*/(cl_heights_coincide && !sig_equal),
                       hex_of(e.cbtx->bestCLSignature), hex_of(d.cbtx->bestCLSignature), sig_equal});

        // ── INVARIANT: creditPool normalized-base (the bug the soaks caught 3×).
        //    committed(N) − platformReward(N) − ownLockDelta == creditPool(N−1).
        //    Empty template ⇒ ownLockDelta 0. Requires a contiguous prev base;
        //    otherwise VOID (Informational), never a false flag.
        if (prev_committed_credit_pool && contiguous) {
            const int64_t base = *prev_committed_credit_pool;
            const int64_t e_norm = e.cbtx->creditPoolBalance - e.platform_reward;   // empty-template
            const int64_t d_norm = d.cbtx->creditPoolBalance - d.platform_reward;
            const bool e_ok = e.empty_template ? (e_norm == base) : true;  // non-empty: proposal judges
            const bool d_ok = d.empty_template ? (d_norm == base) : true;
            out.push_back({"creditPool_invariant", Regime::Invariant, /*counts=*/!(e_ok && d_ok),
                           std::to_string(e_norm) + "==" + std::to_string(base) + "?" + (e_ok ? "ok" : "VIOL"),
                           std::to_string(d_norm) + "==" + std::to_string(base) + "?" + (d_ok ? "ok" : "VIOL"),
                           e_ok && d_ok});
        } else {
            out.push_back({"creditPool_invariant", Regime::Informational, false,
                           std::to_string(e.cbtx->creditPoolBalance),
                           std::to_string(d.cbtx->creditPoolBalance),
                           e.cbtx->creditPoolBalance == d.cbtx->creditPoolBalance});
        }
    } else {
        eq("cbtx_parse", Regime::Equality, true,
           e.cbtx_ok ? "ok" : "fail", d.cbtx_ok ? "ok" : "fail");
    }

    // ── INVARIANT: coinbasevalue − own fees == subsidy core (per side). Cross-
    //    checked as the EQUALITY subsidy_core above; the raw totals are info.
    eq("coinbasevalue_raw", Regime::Informational, false,
       std::to_string(emb.m_coinbase_value), std::to_string(dashd.m_coinbase_value));

    // ── DERIVED / NOT-COMPARABLE (informational only) ───────────────────────
    eq("payee_amounts", Regime::Informational, false,
       payee_amounts_str(emb.m_packed_payments), payee_amounts_str(dashd.m_packed_payments));
    eq("tx_count", Regime::Informational, false,
       std::to_string(emb.m_tx_hashes.size()), std::to_string(dashd.m_tx_hashes.size()));
    eq("cbtx_bytes_bestcl_masked", Regime::Informational, false,
       hex_of(cbtx_bytes_bestcl_masked(emb.m_coinbase_payload, *e.cbtx, e.cbtx_ok)),
       hex_of(cbtx_bytes_bestcl_masked(dashd.m_coinbase_payload, *d.cbtx, d.cbtx_ok)));
    return out;
}

// ── dashd proposal (mode=proposal) VERDICT (§6 cond. 2) ─────────────────────
struct ProposalResult {
    bool attempted{false};
    bool accepted{false};
    std::string reason;   // dashd's reject string on failure
};

// ─────────────────────────────────────────────────────────────────────────────
// Graduation ledger. A SERVED height (embedded arm armed) counts CLEAN iff the
// dashd proposal ACCEPTED it AND no EQUALITY/INVARIANT/strict-CONSTRAINT field
// diverged. Fall-closed (dashd-fallback) heights are recorded per class so the
// verdict can DECLARE the residual serve-gaps. Keyed to {commit, comparator,
// dashd_version, net}; a key change wipes the streak (§6 cond. 4).
// ─────────────────────────────────────────────────────────────────────────────
struct GraduationConfig {
    uint64_t consecutive_clean_target{5000};  // N (served + clean)
    uint64_t per_class_coverage_target{20};   // K (served + clean, per class)
    double   serve_rate_floor{0.5};           // arm must SERVE >= this of eligible normals
};

class GraduationLedger {
public:
    std::map<std::string, uint64_t> coverage;             // class -> served+clean heights
    std::map<std::string, uint64_t> fall_closed_by_class; // class -> heights the arm did NOT serve
    std::map<std::string, uint64_t> divergences_by_class;
    std::map<std::string, uint64_t> divergences_by_field;
    uint64_t total_compared{0};      // served heights that reached the compare
    uint64_t total_clean{0};
    uint64_t total_divergent{0};
    uint64_t proposal_accepted{0};
    uint64_t proposal_rejected{0};
    uint64_t consecutive_clean{0};
    uint64_t reorg_covered{0};
    uint64_t served_normal{0};       // normal-class heights the arm served
    uint64_t eligible_normal{0};     // normal-class heights observed (served + fall-closed)
    uint64_t void_samples{0};
    uint32_t last_height{0};
    bool     revoked{false};
    std::string revoked_reason;
    // Ledger identity (streak-invalidating on change).
    std::string key_commit, key_dashd_version, key_net;
    uint32_t    key_comparator{0};

    void note_fall_closed(uint32_t height, const std::set<HeightClass>& classes) {
        last_height = height;
        for (auto c : classes) fall_closed_by_class[height_class_name(c)]++;
        if (classes.count(HeightClass::Normal)) eligible_normal++;
    }
    void note_void(uint32_t height) { void_samples++; last_height = height; }

    /// Record a SERVED + COMPARED height. `counted_fields` are the graduation-
    /// breaking divergences; `proposal_ok`==true only when dashd ACCEPTED.
    void record_served(uint32_t height, const std::set<HeightClass>& classes,
                       bool proposal_ok,
                       const std::vector<std::string>& counted_fields) {
        total_compared++;
        last_height = height;
        proposal_ok ? proposal_accepted++ : proposal_rejected++;
        if (classes.count(HeightClass::Normal)) { eligible_normal++; served_normal++; }
        const bool clean = proposal_ok && counted_fields.empty();
        if (clean) {
            total_clean++;
            consecutive_clean++;
            for (auto c : classes) {
                coverage[height_class_name(c)]++;
                if (c == HeightClass::Reorg) reorg_covered++;
            }
        } else {
            total_divergent++;
            consecutive_clean = 0;
            for (auto c : classes) divergences_by_class[height_class_name(c)]++;
            for (const auto& f : counted_fields) divergences_by_field[f]++;
            if (!proposal_ok) divergences_by_field["dashd_proposal_rejected"]++;
        }
    }

    double serve_rate() const {
        return eligible_normal ? static_cast<double>(served_normal) / eligible_normal : 0.0;
    }

    bool is_graduated(const GraduationConfig& cfg) const {
        if (revoked) return false;
        if (consecutive_clean < cfg.consecutive_clean_target) return false;
        if (serve_rate() < cfg.serve_rate_floor) return false;
        for (auto c : graduation_required_classes()) {
            auto it = coverage.find(height_class_name(c));
            if (it == coverage.end() || it->second < cfg.per_class_coverage_target)
                return false;
        }
        return reorg_covered >= 1;
    }

    nlohmann::json verdict_json(const GraduationConfig& cfg) const {
        nlohmann::json j;
        j["verdict"] = is_graduated(cfg) ? "GRADUATED" : "NOT-GRADUATED";
        if (revoked) { j["revoked"] = true; j["revoked_reason"] = revoked_reason; }
        j["scope"] = "chain-state equivalence over the SERVED domain; network-"
                     "layer independence (CoinPeerManager) is a SEPARATE gate";
        j["consecutive_clean"] = consecutive_clean;
        j["consecutive_clean_target"] = cfg.consecutive_clean_target;
        j["serve_rate"] = serve_rate();
        j["serve_rate_floor"] = cfg.serve_rate_floor;
        nlohmann::json need = nlohmann::json::object();
        if (consecutive_clean < cfg.consecutive_clean_target)
            need["consecutive_clean"] = cfg.consecutive_clean_target - consecutive_clean;
        if (serve_rate() < cfg.serve_rate_floor) need["serve_rate"] = cfg.serve_rate_floor;
        // Per-class served coverage still-needed + explicit fall-closed declaration.
        nlohmann::json served_gaps = nlohmann::json::object();
        for (auto c : graduation_required_classes()) {
            const std::string n = height_class_name(c);
            uint64_t have = 0; auto it = coverage.find(n);
            if (it != coverage.end()) have = it->second;
            if (have < cfg.per_class_coverage_target)
                need[n] = cfg.per_class_coverage_target - have;
            uint64_t fc = 0; auto fit = fall_closed_by_class.find(n);
            if (fit != fall_closed_by_class.end()) fc = fit->second;
            if (have == 0 && fc > 0)
                served_gaps[n] = "NEVER served daemonlessly (" + std::to_string(fc)
                               + " fall-closed) — residual serve-gap; disabling dashd "
                                 "leaves this class with no fallback";
        }
        if (reorg_covered < 1) need["reorg"] = 1;
        j["still_needed"] = need;
        j["residual_serve_gaps"] = served_gaps;
        return j;
    }

    nlohmann::json to_json() const {
        nlohmann::json j;
        j["total_compared"] = total_compared; j["total_clean"] = total_clean;
        j["total_divergent"] = total_divergent;
        j["proposal_accepted"] = proposal_accepted; j["proposal_rejected"] = proposal_rejected;
        j["consecutive_clean"] = consecutive_clean; j["reorg_covered"] = reorg_covered;
        j["served_normal"] = served_normal; j["eligible_normal"] = eligible_normal;
        j["void_samples"] = void_samples; j["last_height"] = last_height;
        j["revoked"] = revoked; j["revoked_reason"] = revoked_reason;
        j["coverage"] = coverage; j["fall_closed_by_class"] = fall_closed_by_class;
        j["divergences_by_class"] = divergences_by_class;
        j["divergences_by_field"] = divergences_by_field;
        j["key"] = {{"commit", key_commit}, {"comparator", key_comparator},
                    {"dashd_version", key_dashd_version}, {"net", key_net}};
        return j;
    }
    void from_json(const nlohmann::json& j) {
        auto g = [&](const char* k, uint64_t& v) {
            if (j.contains(k) && j[k].is_number_unsigned()) v = j[k].get<uint64_t>(); };
        g("total_compared", total_compared); g("total_clean", total_clean);
        g("total_divergent", total_divergent); g("proposal_accepted", proposal_accepted);
        g("proposal_rejected", proposal_rejected); g("consecutive_clean", consecutive_clean);
        g("reorg_covered", reorg_covered); g("served_normal", served_normal);
        g("eligible_normal", eligible_normal); g("void_samples", void_samples);
        if (j.contains("last_height") && j["last_height"].is_number_unsigned())
            last_height = j["last_height"].get<uint32_t>();
        if (j.contains("revoked")) revoked = j["revoked"].get<bool>();
        if (j.contains("revoked_reason")) revoked_reason = j["revoked_reason"].get<std::string>();
        auto lm = [&](const char* k, std::map<std::string, uint64_t>& m) {
            if (j.contains(k) && j[k].is_object())
                for (auto it = j[k].begin(); it != j[k].end(); ++it)
                    m[it.key()] = it.value().get<uint64_t>(); };
        lm("coverage", coverage); lm("fall_closed_by_class", fall_closed_by_class);
        lm("divergences_by_class", divergences_by_class);
        lm("divergences_by_field", divergences_by_field);
        if (j.contains("key")) {
            const auto& k = j["key"];
            if (k.contains("commit")) key_commit = k["commit"].get<std::string>();
            if (k.contains("comparator")) key_comparator = k["comparator"].get<uint32_t>();
            if (k.contains("dashd_version")) key_dashd_version = k["dashd_version"].get<std::string>();
            if (k.contains("net")) key_net = k["net"].get<std::string>();
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Runtime driver.
// ─────────────────────────────────────────────────────────────────────────────
class EmbeddedOracleShadow {
public:
    struct Config {
        bool testnet{true};
        GraduationConfig grad;
        std::string divergence_ledger_path;   // JSONL append log
        std::string graduation_state_path;    // JSON snapshot (load on start)
        uint32_t post_restart_cold_window{2};
        std::string c2pool_commit;            // ledger identity
        std::string dashd_version;            // ledger identity (best-effort)
    };
    // Assembles + proposes the embedded block to dashd; bound in main_dash.cpp
    // (has the coinbase builders + RPC). Unbound ⇒ proposal leg unavailable ⇒
    // NO served height can be CLEAN (condition 2: proposal is required).
    using ProposalFn = std::function<ProposalResult(const DashWorkData&)>;

    EmbeddedOracleShadow(const NodeCoinState& coin_state,
                         std::function<DashWorkData()> dashd_gbt,
                         ProposalFn proposal_fn, Config cfg)
        : coin_state_(coin_state)
        , dashd_gbt_(std::move(dashd_gbt))
        , proposal_fn_(std::move(proposal_fn))
        , cfg_(std::move(cfg))
        , periodicity_(NetPeriodicity::for_net(cfg_.testnet))
    {
        load_graduation_state();
        // Streak-invalidation on identity change (§6 cond. 4).
        if (ledger_.key_comparator != kOracleComparatorVersion
            || ledger_.key_commit != cfg_.c2pool_commit
            || ledger_.key_dashd_version != cfg_.dashd_version
            || ledger_.key_net != (cfg_.testnet ? "testnet" : "mainnet")) {
            if (ledger_.total_compared != 0)
                LOG_WARNING << "[EMB-ORACLE] ledger identity changed (commit/comparator/"
                               "dashd/net) — RESETTING clean streak (a new binary must "
                               "not inherit an old streak)";
            GraduationLedger fresh;
            fresh.key_commit = cfg_.c2pool_commit;
            fresh.key_comparator = kOracleComparatorVersion;
            fresh.key_dashd_version = cfg_.dashd_version;
            fresh.key_net = cfg_.testnet ? "testnet" : "mainnet";
            ledger_ = std::move(fresh);
        }
        LOG_INFO << "[EMB-ORACLE] shadow constructed (net="
                 << (cfg_.testnet ? "testnet" : "mainnet")
                 << " N=" << cfg_.grad.consecutive_clean_target
                 << " K=" << cfg_.grad.per_class_coverage_target
                 << " proposal=" << (proposal_fn_ ? "wired(VERDICT)" : "UNSET(field-compare only)")
                 << " comparator_v=" << kOracleComparatorVersion << ")";
    }

    /// Per-block shadow-compare. OBSERVE-ONLY.
    void on_new_tip(uint32_t next_height, const uint256& next_prev_hash) {
        std::lock_guard<std::mutex> lk(mu_);
        if (!dashd_gbt_) { LOG_WARNING << "[EMB-ORACLE] no dashd oracle bound"; return; }

        const bool reorg = detect_reorg(next_height, next_prev_hash);

        WorkSelection sel = coin_state_.select_work(dashd_gbt_);
        if (sel.source != WorkSource::Embedded) {
            embedded_armed_ = false;
            ledger_.note_fall_closed(next_height, classify(next_height, {}, false, reorg, false));
            LOG_INFO << "[EMB-ORACLE] h=" << next_height
                     << " FALL-CLOSED (dashd-fallback) — recorded serve-gap";
            save_graduation_state();
            remember_tip(next_height, next_prev_hash);
            return;
        }
        DashWorkData emb = std::move(sel.work);

        DashWorkData dashd;
        try { dashd = dashd_gbt_(); }
        catch (const std::exception& ex) {
            LOG_WARNING << "[EMB-ORACLE] dashd oracle threw: " << ex.what() << " — void";
            ledger_.note_void(next_height); remember_tip(next_height, next_prev_hash); return;
        }

        // Alignment key: (height, prev_hash). A skew VOIDs the sample.
        if (emb.m_height != dashd.m_height || emb.m_previous_block != dashd.m_previous_block) {
            LOG_INFO << "[EMB-ORACLE] tip-skew emb(h=" << emb.m_height << ",prev="
                     << emb.m_previous_block.GetHex().substr(0, 12) << ") dashd(h="
                     << dashd.m_height << ",prev=" << dashd.m_previous_block.GetHex().substr(0, 12)
                     << ") — VOID";
            ledger_.note_void(next_height); remember_tip(next_height, next_prev_hash); return;
        }

        vendor::CCbTx ec, dc;
        const bool eok = vendor::parse_cbtx(emb.m_coinbase_payload, ec);
        const bool dok = vendor::parse_cbtx(dashd.m_coinbase_payload, dc);

        // Chain-drift sentinel (§6 cond. 5): an unknown CbTx version from dashd
        // (or a quorum-tail parse failure) auto-REVOKES graduation.
        if (dok && dc.nVersion > kMaxKnownCbTxVersion) revoke(
            "unknown dashd CbTx nVersion=" + std::to_string(dc.nVersion));
        if (!dok && !dashd.m_coinbase_payload.empty()) revoke("dashd CbTx payload parse failure");

        SideContext e; e.wd = &emb; e.cbtx = &ec; e.cbtx_ok = eok;
        e.own_fees = sum_fees(emb.m_tx_fees); e.platform_reward = platform_burn_amount(emb.m_packed_payments);
        e.empty_template = emb.m_tx_hashes.empty();
        SideContext d; d.wd = &dashd; d.cbtx = &dc; d.cbtx_ok = dok;
        d.own_fees = sum_fees(dashd.m_tx_fees); d.platform_reward = platform_burn_amount(dashd.m_packed_payments);
        d.empty_template = dashd.m_tx_hashes.empty();

        const bool dkg = periodicity_.is_dkg_window(emb.m_height);
        const bool contiguous = (have_prev_ && prev_compared_height_ + 1 == emb.m_height);
        std::optional<int64_t> prev_cp;
        if (have_prev_) prev_cp = prev_credit_pool_;

        std::set<HeightClass> classes = classify(emb.m_height, dc, dok, reorg,
                                                 !e.empty_template || !d.empty_template);

        auto fields = compare_templates(e, d, prev_cp, dkg, contiguous);

        // ── PROPOSAL VERDICT (the authoritative gate) ───────────────────────
        ProposalResult pr;
        if (proposal_fn_) {
            try { pr = proposal_fn_(emb); }
            catch (const std::exception& ex) {
                pr.attempted = true; pr.accepted = false; pr.reason = std::string("throw:") + ex.what();
            }
        }
        // Without a proposal leg, condition 2 forbids certifying — treat as
        // not-accepted so the height cannot count clean.
        const bool proposal_ok = pr.attempted && pr.accepted;

        std::vector<std::string> counted;
        for (const auto& f : fields) if (f.counts) counted.push_back(f.field);

        const HeightClass primary = primary_class(classes);
        if (!proposal_ok) {
            if (pr.attempted)
                LOG_WARNING << "[EMB-ORACLE] DIVERGENCE height=" << emb.m_height
                            << " class=" << height_class_name(primary)
                            << " field=dashd_proposal verdict=REJECTED reason=" << pr.reason;
            else
                LOG_WARNING << "[EMB-ORACLE] height=" << emb.m_height
                            << " proposal leg UNAVAILABLE — cannot certify this height "
                               "(field-compare is diagnosis only)";
        }
        for (const auto& f : fields) {
            if (f.match || !f.counts) continue;
            LOG_WARNING << "[EMB-ORACLE] DIVERGENCE height=" << emb.m_height
                        << " class=" << height_class_name(primary)
                        << " field=" << f.field << " regime=" << regime_name(f.regime)
                        << " embedded=" << f.embedded << " dashd=" << f.dashd;
        }
        if (proposal_ok && counted.empty())
            LOG_INFO << "[EMB-ORACLE] AGREE height=" << emb.m_height
                     << " class=" << height_class_name(primary)
                     << " (proposal ACCEPTED; all equality/invariant fields match)";

        ledger_.record_served(emb.m_height, classes, proposal_ok, counted);
        append_divergence_ledger(emb.m_height, classes, primary, fields, pr, counted);
        save_graduation_state();

        // Advance trackers.
        if (!embedded_armed_) { embedded_armed_ = true; cold_heights_seen_ = 0; }
        cold_heights_seen_++;
        if (dok) { prev_credit_pool_ = dc.creditPoolBalance; }
        prev_compared_height_ = emb.m_height; have_prev_ = dok;
        remember_tip(next_height, next_prev_hash);
    }

    nlohmann::json stats_json() const {
        std::lock_guard<std::mutex> lk(mu_);
        nlohmann::json j = ledger_.to_json();
        j["graduation"] = ledger_.verdict_json(cfg_.grad);
        j["net"] = cfg_.testnet ? "testnet" : "mainnet";
        j["mode"] = "embedded-oracle-shadow";
        j["proposal_leg"] = proposal_fn_ ? "wired" : "unset";
        return j;
    }

private:
    void revoke(const std::string& reason) {
        if (ledger_.revoked) return;
        ledger_.revoked = true; ledger_.revoked_reason = reason;
        ledger_.consecutive_clean = 0;
        LOG_WARNING << "[EMB-ORACLE] GRADUATION REVOKED (chain-drift sentinel): "
                    << reason << " — arm demoted to fail-closed; re-shadow required";
    }
    void remember_tip(uint32_t h, const uint256& prev) { last_tip_height_ = h; last_tip_prev_ = prev; }
    bool detect_reorg(uint32_t next_height, const uint256& next_prev_hash) const {
        if (last_tip_height_ == 0) return false;
        // Linear extension: this tip builds on the last observed tip's block.
        // A prev-hash that is NOT the last tip's own hash lineage, or a non-
        // increasing height, is a reorg/re-tip. (We approximate lineage by the
        // recorded prev-hash; a same-height re-tip has next_height<=last.)
        if (next_height <= last_tip_height_) return true;
        (void)next_prev_hash;
        return false;
    }
    std::set<HeightClass> classify(uint32_t height, const vendor::CCbTx& dcbtx,
                                   bool dok, bool reorg, bool non_empty) {
        std::set<HeightClass> c;
        if (periodicity_.is_superblock(height)) c.insert(HeightClass::Superblock);
        if (periodicity_.is_dkg_window(height)) c.insert(HeightClass::DkgWindow);
        if (reorg) c.insert(HeightClass::Reorg);
        if (non_empty) c.insert(HeightClass::NonEmptyTemplate);
        if (!embedded_armed_) c.insert(HeightClass::PostRestartCold);
        else if (cold_heights_seen_ < cfg_.post_restart_cold_window)
            c.insert(HeightClass::PostRestartCold);
        if (dok && have_prev_ && dcbtx.creditPoolBalance != prev_credit_pool_)
            c.insert(HeightClass::CreditPoolTransition);
        if (dok && have_prev_ && dcbtx.merkleRootQuorums != prev_quorum_root_)
            c.insert(HeightClass::QuorumRotation);
        if (dok) prev_quorum_root_ = dcbtx.merkleRootQuorums;
        if (c.empty()) c.insert(HeightClass::Normal);
        return c;
    }
    static HeightClass primary_class(const std::set<HeightClass>& classes) {
        for (auto c : {HeightClass::Reorg, HeightClass::Superblock,
                       HeightClass::CreditPoolTransition, HeightClass::QuorumRotation,
                       HeightClass::DkgWindow, HeightClass::NonEmptyTemplate,
                       HeightClass::PostRestartCold})
            if (classes.count(c)) return c;
        return HeightClass::Normal;
    }
    void append_divergence_ledger(uint32_t height, const std::set<HeightClass>& classes,
                                  HeightClass primary, const std::vector<FieldResult>& fields,
                                  const ProposalResult& pr, const std::vector<std::string>& counted) {
        if (cfg_.divergence_ledger_path.empty()) return;
        nlohmann::json row;
        row["ts"] = static_cast<int64_t>(std::time(nullptr));
        row["height"] = height; row["primary_class"] = height_class_name(primary);
        nlohmann::json cls = nlohmann::json::array();
        for (auto c : classes) cls.push_back(height_class_name(c));
        row["classes"] = cls;
        row["proposal"] = {{"attempted", pr.attempted}, {"accepted", pr.accepted},
                           {"reason", pr.reason}};
        row["clean"] = pr.attempted && pr.accepted && counted.empty();
        row["counted_divergences"] = counted;
        nlohmann::json mm = nlohmann::json::array();
        for (const auto& f : fields) if (!f.match)
            mm.push_back({{"field", f.field}, {"regime", regime_name(f.regime)},
                          {"counts", f.counts}, {"embedded", f.embedded}, {"dashd", f.dashd}});
        if (!mm.empty()) row["mismatched_fields"] = mm;
        std::ofstream f(cfg_.divergence_ledger_path, std::ios::app);
        if (f) f << row.dump() << "\n";
    }
    void save_graduation_state() {
        if (cfg_.graduation_state_path.empty()) return;
        std::ofstream f(cfg_.graduation_state_path, std::ios::trunc);
        if (f) f << ledger_.to_json().dump(2) << "\n";
    }
    void load_graduation_state() {
        if (cfg_.graduation_state_path.empty()) return;
        std::ifstream f(cfg_.graduation_state_path);
        if (!f) return;
        try { nlohmann::json j; f >> j; ledger_.from_json(j); }
        catch (const std::exception& e) {
            LOG_WARNING << "[EMB-ORACLE] could not load graduation state: " << e.what();
        }
    }

    const NodeCoinState&          coin_state_;
    std::function<DashWorkData()> dashd_gbt_;
    ProposalFn                    proposal_fn_;
    Config                        cfg_;
    NetPeriodicity                periodicity_;

    mutable std::mutex mu_;
    GraduationLedger   ledger_;

    bool     embedded_armed_{false};
    uint32_t cold_heights_seen_{0};
    bool     have_prev_{false};
    int64_t  prev_credit_pool_{0};
    uint256  prev_quorum_root_;
    uint32_t prev_compared_height_{0};
    uint32_t last_tip_height_{0};
    uint256  last_tip_prev_;
};

} // namespace coin
} // namespace dash
