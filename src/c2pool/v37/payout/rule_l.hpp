#pragma once
// Rule L — coinbase payout rule for the slot-bounded (cb_class) coinbase.
//
// STANDALONE MODULE. Nothing in consensus canon calls this yet: it is NOT wired
// into src/sharechain/v37, the W4 owed_digest fold, or the OwedLedger /
// W5 propose_coinbase call sites. The wiring seam is written up at the bottom
// of this header (§ WIRING SEAM). Integer-only, deterministic, u128 for every
// intermediate that multiplies or sums amounts.
//
// ── INPUTS ─────────────────────────────────────────────────────────────────
//   R        block reward (subsidy + fees) the coinbase distributes
//   D_min    mandatory donation floor, 1 <= D_min <= R
//   s        payout slots = floor(payout_byte_budget / S_max)
//            (slots_from_budget(); kUnboundedSlots = no count limit)
//   rows     one row per ledger key: eo (EffectiveOwed, clamped >= 0),
//            first_eligible (the K_fair age clock), credit_b (the block's own
//            fresh PPLNS credit, not yet armed), h_min (per-kind dust floor)
//   params   M (h_slot divisor, default 50), h_min_dust (global dust floor),
//            reserve_ppm (r, default 0 = pure L), genesis_p2prime (default OFF)
//
// ── RULE ───────────────────────────────────────────────────────────────────
//   B      = R - D_min
//   floor_k = max(h_min_dust, h_min_k)                (the row's dust floor)
//   h_slot = ceil(R / (M * s));  h_slot_k = max(floor_k, h_slot)
//   E      = { k : eo_k >= h_slot_k } in (first_eligible ASC, key ASC)
//
//   RESERVE (r > 0 only): the first floor(r * s) slots go to the OLDEST rows of
//     E in strict FIFO, each paid its full owed min(eo_k, B - reserved_paid);
//     no feasibility test. r = 0 -> no reserve -> pure L.
//
//   P1: E_rest = E minus the reserved rows, s_rest = s - reserved slots,
//     T = min(B - reserved_paid, topsum(E_rest, s_rest))   (topsum(X, m) = sum
//     of the m largest eo in X). Walk E_rest FIFO; take = min(eo_k, T - paid);
//     ACCEPT iff paid + take == T  or  paid + take + topsum(unvisited \ k,
//     s_left - 1) >= T; otherwise CARRY (skip; first_eligible untouched). A
//     skip therefore happens ONLY when accepting k would make T unreachable.
//     Every accepted take except possibly the last is the full eo_k.
//
//   SUB-DUST PARTIAL: if the last accepted take is < floor_k it is not emitted
//     (k carries, its eo untouched) and the amount is FOLDED into the previous
//     accepted payee's output, booked against that payee's fresh credit_b
//     (so it never pays more than eo + credit_b). Whatever credit_b cannot
//     absorb, or all of it when there is no previous payee, stays in the
//     leftover (P2 / donation).
//
//   P2 (with the p2x extension): leftover = B - paid. If leftover > 0, top up
//     the emitted payees proportionally to their remaining credit_b[k]
//     (credit_b minus anything already prepaid), X = min(leftover, sum), each
//     share <= its remaining credit_b, largest remainder with key ASC ties.
//     Fires whether P1 ran out of slots or E was exhausted with slots left.
//
//   P2' (genesis backstop): OFF by default. Only when params.genesis_p2prime
//     AND input.in_genesis AND leftover > 0 AND slots remain: non-emitted rows
//     with credit_b > 0 in (credit_b DESC, key ASC), amt = min(credit_b,
//     leftover), CARRY if amt < floor_k. Mirrors surplus-sim-L P2'.
//
//   P3: donation = D_min + leftover.  sum(outputs) + donation == R exactly.
//
// ── OUTPUT / LEDGER BOOKING CONTRACT ────────────────────────────────────────
//   Every Payout splits into owed_debit (<= eo_k, debits the armed owed now)
//   and prepaid (<= credit_b_k, paid AGAINST the block's own fresh credit).
//   The caller books: eo_k -= owed_debit; and when block b arms, the armed
//   credit is credit_b_k - prepaid_k (never the gross credit_b_k). With that
//   booking owed never goes negative (surplus-sim-L ledger model).
//
// ── DETERMINISM ────────────────────────────────────────────────────────────
//   The result is a pure function of (params, R, D_min, s, in_genesis, the SET
//   of rows): rows are re-sorted internally, so caller order is irrelevant.
//   Keys must be unique (DUPLICATE_KEY otherwise). Key needs operator< and
//   operator== (bytes32 = std::array<uint8_t,32> in production).
//
// ── WIRING SEAM (not done here — consensus canon is out of scope) ──────────
//   1. Slot count: s = slots_from_budget(rb::cb_budget(class, overhead,
//      free_after_txs, K_max), S_max(kind)) — the cb_class byte budget from
//      roundabout/rb_cb_class.hpp, divided by the largest admitted output.
//   2. Row source: OwedLedger::m_eo_index (eo > 0, already in (fe ASC, key
//      ASC)) for eo/first_eligible; credit_b = the block's E_b credit map
//      (on_block_found's `credit`); h_min = h_min_of(pay_of(k).kind).
//   3. Replace the loop body of OwedLedger::propose_coinbase
//      (w4_settlement.hpp ~729-766) / W5 assemble() with rule_l::compute().
//      With s = kUnboundedSlots, reserve_ppm = 0, empty credit_b and a uniform
//      per-kind floor the outputs are byte-identical to today's K_fair
//      propose_coinbase(B, 0, ...) (KAT D1); with mixed floors they are an
//      in-order prefix of it (KAT D2).
//   4. Booking: on_block_found(bid, credit, payout) must record
//      payout = owed_debit ONLY and credit = credit_b - prepaid, while the
//      coinbase output amount is owed_debit + prepaid. Recording the gross
//      amount as payout would drive EffectiveOwed negative until finalize.
//      This changes what the FOUND leaf commits (owed_event payload) and is a
//      consensus change: it needs a v37.x subversion gate + validator-side
//      recompute of the same Result from the block's committed inputs.
//   5. Validator: recompute compute() from (R, D_min, class byte, ledger at
//      the burial-gated prefix, E_b) and require the coinbase payout outputs
//      and the donation output to match exactly.

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

namespace c2pool::v37n::payout::rule_l {

using u64 = std::uint64_t;
using u128 = unsigned __int128;

// "No output-count limit". s == 0 is literally zero slots (everything goes to
// the donation) — unlike W5's max_payout_bytes, 0 never means unbounded here.
inline constexpr u64 kUnboundedSlots = ~u64(0);
inline constexpr std::uint32_t kPpm = 1000000;

struct Params {
    u64 M = 50;                    // h_slot divisor (>= 1)
    u64 h_min_dust = 1;            // global dust floor (per-row h_min can raise it)
    std::uint32_t reserve_ppm = 0; // r in ppm; 0 = pure L; <= 1e6
    bool genesis_p2prime = false;  // P2' backstop, only while input.in_genesis
};

template <class Key>
struct Row {
    Key key{};
    u64 eo = 0;              // EffectiveOwed, clamped at 0 by the caller
    u64 first_eligible = 0;  // K_fair age (ignored when eo == 0)
    u64 credit_b = 0;        // this block's fresh (unarmed) credit
    u64 h_min = 0;           // per-kind dust floor (0 -> params.h_min_dust)
};

template <class Key>
struct Input {
    u64 R = 0;
    u64 D_min = 1;
    u64 slots = 0;
    bool in_genesis = false;
    std::vector<Row<Key>> rows;
};

enum class Status : std::uint8_t { OK = 0, BAD_D_MIN, BAD_M, BAD_RESERVE, DUPLICATE_KEY };
enum class Phase : std::uint8_t { RESERVE = 0, P1 = 1, P2PRIME = 2 };

template <class Key>
struct Payout {
    Key key{};
    u64 amount = 0;      // == owed_debit + prepaid
    u64 owed_debit = 0;  // <= eo
    u64 prepaid = 0;     // <= credit_b (fold + P2 + P2')
    Phase phase = Phase::P1;
};

template <class Key>
struct Result {
    Status status = Status::OK;
    std::vector<Payout<Key>> outputs;  // emission order (reserve, P1, P2')
    u64 donation = 0;                  // D_min + leftover
    // diagnostics
    u64 B = 0;
    u64 slots = 0;
    u64 h_slot = 0;            // ceil(R / (M*s)) before the per-row floor
    u64 eligible = 0;          // |E|
    u64 reserve_slots = 0;     // floor(r*s)
    u64 reserved_used = 0;     // slots the reserve actually filled
    u64 reserved_paid = 0;
    u64 T = 0;                 // P1 target
    u64 p1_paid = 0;           // == T
    std::vector<Key> skipped;  // P1 FIFO carries (infeasible rows)
    bool sub_dust = false;     // the last take was sub-dust and was not emitted
    Key sub_dust_key{};
    u64 sub_dust_amount = 0;
    u64 folded = 0;            // part of it absorbed by the previous payee
    u64 topup_total = 0;       // P2
    u64 p2prime_total = 0;     // P2'
};

inline u64 slots_from_budget(u64 payout_byte_budget, u64 S_max) {
    return S_max == 0 ? 0 : payout_byte_budget / S_max;
}

namespace detail {

// Fenwick tree over value ranks (value DESC): remove(rank), topsum(m) = sum of
// the m largest values still present. Counts in u64, sums in u128.
class TopSum {
public:
    explicit TopSum(std::vector<u64> vals_desc)
        : m_v(std::move(vals_desc)), m_n(m_v.size()), m_cnt(m_n + 1, 0), m_sum(m_n + 1, 0) {
        for (std::size_t i = 0; i < m_n; ++i) {
            m_cnt[i + 1] += 1;
            m_sum[i + 1] += m_v[i];
            const std::size_t j = (i + 1) + ((i + 1) & (~(i + 1) + 1));
            if (j <= m_n) { m_cnt[j] += m_cnt[i + 1]; m_sum[j] += m_sum[i + 1]; }
            m_tot_s += m_v[i];
        }
        m_tot_c = m_n;
        m_lg = 1;
        while (m_lg * 2 <= m_n) m_lg *= 2;
        if (m_n == 0) m_lg = 0;
    }
    void remove(std::size_t r) {
        const u64 v = m_v[r];
        for (std::size_t i = r + 1; i <= m_n; i += i & (~i + 1)) { m_cnt[i] -= 1; m_sum[i] -= v; }
        m_tot_c -= 1;
        m_tot_s -= v;
    }
    u128 topsum(u64 m) const {
        if (m == 0 || m_tot_c == 0) return 0;
        if (m >= m_tot_c) return m_tot_s;
        std::size_t pos = 0;
        u64 ac = 0;
        u128 as = 0;
        for (std::size_t step = m_lg; step; step >>= 1) {
            const std::size_t nx = pos + step;
            if (nx <= m_n && ac + m_cnt[nx] < m) { pos = nx; ac += m_cnt[nx]; as += m_sum[nx]; }
        }
        // pos is the (0-based) rank of the m-th present value; it is present
        // because the prefix count reaches m exactly there.
        return as + m_v[pos];
    }

private:
    std::vector<u64> m_v;
    std::size_t m_n;
    std::vector<u64> m_cnt;
    std::vector<u128> m_sum;
    u64 m_tot_c = 0;
    u128 m_tot_s = 0;
    std::size_t m_lg = 0;
};

inline u64 floor_of(const Params& p, u64 row_h_min) { return std::max(p.h_min_dust, row_h_min); }

// Split X over weights w (sum(w) >= X) proportionally: floor(X*w/S) each, the
// remainder units to the largest fractional remainders, key ASC on ties.
// Returns shares with shares[j] <= w[j] and sum == X (X <= S required).
template <class Key>
std::vector<u64> largest_remainder(u64 X, const std::vector<u64>& w, const std::vector<Key>& keys) {
    std::vector<u64> out(w.size(), 0);
    u128 S = 0;
    for (u64 x : w) S += x;
    if (X == 0 || S == 0) return out;
    std::vector<u128> rem(w.size(), 0);
    u128 given = 0;
    for (std::size_t j = 0; j < w.size(); ++j) {
        const u128 num = static_cast<u128>(X) * w[j];
        out[j] = static_cast<u64>(num / S);
        rem[j] = num % S;
        given += out[j];
    }
    u64 r = static_cast<u64>(static_cast<u128>(X) - given);
    if (r) {
        std::vector<std::size_t> ord(w.size());
        for (std::size_t j = 0; j < ord.size(); ++j) ord[j] = j;
        std::sort(ord.begin(), ord.end(), [&](std::size_t a, std::size_t b) {
            if (rem[a] != rem[b]) return rem[a] > rem[b];
            return keys[a] < keys[b];
        });
        for (std::size_t q = 0; q < r; ++q) out[ord[q]] += 1;
    }
    return out;
}

}  // namespace detail

template <class Key>
Result<Key> compute(const Params& P, const Input<Key>& in) {
    Result<Key> res;
    if (P.M == 0) { res.status = Status::BAD_M; return res; }
    if (in.D_min < 1 || in.D_min > in.R) { res.status = Status::BAD_D_MIN; return res; }
    if (P.reserve_ppm > kPpm) { res.status = Status::BAD_RESERVE; return res; }
    const auto& rows = in.rows;
    {
        std::vector<std::size_t> byk(rows.size());
        for (std::size_t i = 0; i < byk.size(); ++i) byk[i] = i;
        std::sort(byk.begin(), byk.end(), [&](std::size_t a, std::size_t b) { return rows[a].key < rows[b].key; });
        for (std::size_t i = 1; i < byk.size(); ++i)
            if (rows[byk[i - 1]].key == rows[byk[i]].key) { res.status = Status::DUPLICATE_KEY; return res; }
    }

    const u64 R = in.R, s = in.slots;
    const u64 B = R - in.D_min;
    res.B = B;
    res.slots = s;
    if (s == 0) { res.donation = R; return res; }

    // h_slot = ceil(R / (M*s)) in u128 (M*s may exceed u64); <= R so fits u64.
    const u128 Ms = static_cast<u128>(P.M) * s;
    res.h_slot = static_cast<u64>((static_cast<u128>(R) + Ms - 1) / Ms);

    // E in (first_eligible ASC, key ASC)
    std::vector<std::size_t> E;
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const u64 hs = std::max(detail::floor_of(P, rows[i].h_min), res.h_slot);
        if (rows[i].eo > 0 && rows[i].eo >= hs) E.push_back(i);
    }
    std::sort(E.begin(), E.end(), [&](std::size_t a, std::size_t b) {
        if (rows[a].first_eligible != rows[b].first_eligible)
            return rows[a].first_eligible < rows[b].first_eligible;
        return rows[a].key < rows[b].key;
    });
    res.eligible = E.size();

    std::vector<Payout<Key>>& out = res.outputs;
    std::vector<std::size_t> out_row;  // row index per output

    // ── RESERVE: strict FIFO, full owed, no feasibility test
    res.reserve_slots = static_cast<u64>(static_cast<u128>(P.reserve_ppm) * s / kPpm);
    std::size_t e0 = 0;
    u64 rpaid = 0;
    while (e0 < E.size() && res.reserved_used < res.reserve_slots && rpaid < B) {
        const Row<Key>& r = rows[E[e0]];
        const u64 take = std::min(r.eo, B - rpaid);
        out.push_back(Payout<Key>{r.key, take, take, 0, Phase::RESERVE});
        out_row.push_back(E[e0]);
        rpaid += take;
        ++res.reserved_used;
        ++e0;
    }
    res.reserved_paid = rpaid;

    // ── P1 over E_rest with s_rest slots
    const u64 s_rest = s - res.reserved_used;
    const u64 B1 = B - rpaid;
    const std::size_t n = E.size() - e0;
    if (n > 0 && s_rest > 0 && B1 > 0) {
        std::vector<u64> vals(n);
        for (std::size_t i = 0; i < n; ++i) vals[i] = rows[E[e0 + i]].eo;
        // rank by value DESC, FIFO position ASC on ties
        std::vector<std::size_t> order(n);
        for (std::size_t i = 0; i < n; ++i) order[i] = i;
        std::stable_sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) { return vals[a] > vals[b]; });
        std::vector<std::size_t> rank(n);
        std::vector<u64> vdesc(n);
        for (std::size_t r = 0; r < n; ++r) { rank[order[r]] = r; vdesc[r] = vals[order[r]]; }
        detail::TopSum ts(std::move(vdesc));
        const u128 top = ts.topsum(s_rest);
        const u64 T = static_cast<u64>(std::min<u128>(B1, top));
        res.T = T;
        u64 paid = 0, s_left = s_rest;
        for (std::size_t i = 0; i < n && s_left > 0 && paid < T; ++i) {
            ts.remove(rank[i]);
            const Row<Key>& r = rows[E[e0 + i]];
            const u64 take = std::min(vals[i], T - paid);
            bool accept = (paid + take == T);
            if (!accept) {
                const u64 need = T - paid - take;
                accept = ts.topsum(s_left - 1) >= need;
            }
            if (accept) {
                out.push_back(Payout<Key>{r.key, take, take, 0, Phase::P1});
                out_row.push_back(E[e0 + i]);
                paid += take;
                --s_left;
            } else {
                res.skipped.push_back(r.key);
            }
        }
        res.p1_paid = paid;  // == T (reached by construction)
    }

    // ── SUB-DUST PARTIAL: fold the last take into the previous payee
    if (!out.empty()) {
        const std::size_t li = out_row.back();
        if (out.back().owed_debit < detail::floor_of(P, rows[li].h_min)) {
            res.sub_dust = true;
            res.sub_dust_key = out.back().key;
            res.sub_dust_amount = out.back().amount;
            const u64 x = out.back().amount;
            out.pop_back();
            out_row.pop_back();
            if (!out.empty()) {
                Payout<Key>& prev = out.back();
                const u64 room = rows[out_row.back()].credit_b - prev.prepaid;
                const u64 f = std::min(x, room);
                prev.amount += f;
                prev.prepaid += f;
                res.folded = f;
            }
        }
    }

    u128 sum = 0;
    for (const auto& o : out) sum += o.amount;
    u64 left = static_cast<u64>(static_cast<u128>(B) - sum);

    // ── P2 (+p2x): top up emitted payees against their remaining credit_b
    if (left > 0 && !out.empty()) {
        std::vector<u64> cb(out.size());
        std::vector<Key> ks(out.size());
        u128 S = 0;
        for (std::size_t j = 0; j < out.size(); ++j) {
            cb[j] = rows[out_row[j]].credit_b - out[j].prepaid;
            ks[j] = out[j].key;
            S += cb[j];
        }
        const u64 X = static_cast<u64>(std::min<u128>(left, S));
        const auto sh = detail::largest_remainder(X, cb, ks);
        for (std::size_t j = 0; j < out.size(); ++j) {
            out[j].amount += sh[j];
            out[j].prepaid += sh[j];
        }
        left -= X;
        res.topup_total = X;
    }

    // ── P2' (genesis backstop, default OFF)
    if (P.genesis_p2prime && in.in_genesis && left > 0 && out.size() < s) {
        std::vector<Key> em;
        em.reserve(out.size());
        for (const auto& o : out) em.push_back(o.key);
        std::sort(em.begin(), em.end());
        std::vector<std::size_t> cand;
        for (std::size_t i = 0; i < rows.size(); ++i)
            if (rows[i].credit_b > 0 && !std::binary_search(em.begin(), em.end(), rows[i].key)) cand.push_back(i);
        std::sort(cand.begin(), cand.end(), [&](std::size_t a, std::size_t b) {
            if (rows[a].credit_b != rows[b].credit_b) return rows[a].credit_b > rows[b].credit_b;
            return rows[a].key < rows[b].key;
        });
        for (std::size_t i : cand) {
            if (out.size() >= s || left == 0) break;
            const u64 amt = std::min(rows[i].credit_b, left);
            if (amt < detail::floor_of(P, rows[i].h_min)) continue;  // CARRY
            out.push_back(Payout<Key>{rows[i].key, amt, 0, amt, Phase::P2PRIME});
            out_row.push_back(i);
            left -= amt;
            res.p2prime_total += amt;
        }
    }

    // ── P3: donation
    res.donation = in.D_min + left;
    return res;
}

}  // namespace c2pool::v37n::payout::rule_l
