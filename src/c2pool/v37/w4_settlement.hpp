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
//                              hard-decide D-B and does not block.

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
#include <sharechain/v37/v37_lane_executor.hpp>  // LaneSnapshot, IdentityView
#include <sharechain/v37/v37_descriptor.hpp>     // ScriptRef, ScriptKind
#include <sharechain/v37/v37_fixed.hpp>          // U256, u64
#include <sharechain/v37/v37_hash.hpp>           // bytes32, sha256d

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
template <class View>
inline std::map<bytes32, u64> settle_block(u64 reward, const View& v) {
    std::vector<WeightedPayee> payees = project(v);
    std::vector<u64> amt = split_reward(reward, payees);
    std::map<bytes32, u64> e;
    for (std::size_t i = 0; i < payees.size(); ++i)
        if (amt[i] > 0) e[payees[i].key] += amt[i];
    return e;
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

inline bool geometry_is_ratified(const ::v37::LaneParams& p) {
    // Digest-committed geometry tuple (journal_depth excluded — not committed):
    // the OQ-5 canonical default. Any other geometry is refused at the
    // settlement boundary until the D-B registry ships (OI-W4-8).
    if (!(p.window == 8640 && p.c0 == 4096 && p.rollup == 8 &&
          p.half_life == 2160))
        return false;
    return p.level_caps.size() == 1 && p.level_caps[0] == 568;
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
        m_pending.emplace(bid, std::move(p));
        bump();
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
        m_pending.erase(it);
        m_settled.insert(bid);
        rearm_first_eligible(bin_height);
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
        long long e = 0;
        auto it = m_finalW.find(k);
        if (it != m_finalW.end()) e = it->second;
        for (const auto& [bid, p] : m_pending) {
            auto pit = p.payout.find(k);
            if (pit != p.payout.end()) e -= pit->second;
        }
        return e;
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
        std::vector<std::pair<u64, bytes32>> elig;  // (first_eligible, key)
        for (const auto& [k, e] : effective_owed_all()) {
            if (e <= 0) continue;
            u64 fe = 0;
            auto it = m_first_eligible.find(k);
            if (it != m_first_eligible.end()) fe = it->second;
            elig.emplace_back(fe, k);
        }
        std::sort(elig.begin(), elig.end());  // (fe ASC, key ASC) — pair order
        Proposal prop;
        u64 budget = block_reward;
        for (const auto& [fe, k] : elig) {
            (void)fe;
            if (prop.outs.size() >= slot_budget_C) break;
            if (budget == 0) break;
            long long owed = effective_owed(k);
            if (owed <= 0) continue;
            u64 take = std::min<u64>(static_cast<u64>(owed), budget);
            ScriptRef pay = pay_of(k);
            if (take < h_min_of(pay.kind)) continue;   // sub-floor: CARRY
            budget -= take;
            prop.outs.push_back(ProposedOut{k, pay, take});
        }
        return prop;
    }

    // The §4.5 OWED commitment over the FINALIZED partition only (pending keys
    // are re-derivable from the spine + FOUND set). Domain-separated sha256d,
    // sorted by key: "V37O" || key || i64 finalW || u64 first_eligible.
    bytes32 owed_digest() const {
        std::vector<std::pair<bytes32, long long>> rows(m_finalW.begin(),
                                                        m_finalW.end());
        std::sort(rows.begin(), rows.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        std::vector<std::uint8_t> pre;
        const char tag[4] = {'V', '3', '7', 'O'};
        pre.insert(pre.end(), tag, tag + 4);
        for (const auto& [k, w] : rows) {
            if (w == 0) continue;  // zero rows carry no commitment weight
            pre.insert(pre.end(), k.begin(), k.end());
            std::uint64_t uw = static_cast<std::uint64_t>(w);
            for (int i = 0; i < 8; ++i) pre.push_back((uw >> (8 * i)) & 0xff);
            u64 fe = 0;
            auto it = m_first_eligible.find(k);
            if (it != m_first_eligible.end()) fe = it->second;
            for (int i = 0; i < 8; ++i) pre.push_back((fe >> (8 * i)) & 0xff);
        }
        return ::v37::sha256d(pre);
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
        for (const auto& [k, e] : effective_owed_all()) {
            if (e > 0) {
                if (!m_first_eligible.count(k)) m_first_eligible[k] = bin_height;
            } else {
                m_first_eligible.erase(k);
            }
        }
    }

    ::v37::ChainId m_chain;
    u64 m_seq = 0;
    Amounts m_finalW;                              // finalized owed partition
    std::map<std::string, Pending> m_pending;      // FOUND, not yet finalized
    std::set<std::string> m_settled;               // SETTLED — terminal
    std::map<bytes32, u64> m_first_eligible;       // K_fair age key
    long long m_residual = 0;                      // priced post-SETTLED loss
    std::vector<std::pair<std::string, long long>> m_residual_events;
};

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
