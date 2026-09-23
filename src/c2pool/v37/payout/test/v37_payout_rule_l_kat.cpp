// v37_payout_rule_l_kat — Rule L coinbase payout rule (src/c2pool/v37/payout/rule_l.hpp).
//
//   A  input validation (D_min, M, reserve, duplicate keys, s == 0)
//   B  hand-computed scenarios: P1 accept/skip, h_slot, reserve, sub-dust fold
//      (absorbed / not absorbed / no previous payee), P2 largest remainder with
//      key-ASC ties, P2 on E exhausted (p2x), P2' default OFF + genesis gating
//   C  P1 brute-force oracle: on small random instances an independent naive
//      P1 (subset enumeration for T and for every accept/skip decision) agrees
//      decision-for-decision -> a row is skipped ONLY when it is infeasible
//   D  byte-for-byte vs the REAL OwedLedger::propose_coinbase (K_fair master,
//      w4_settlement.hpp): C unbounded, r = 0 -> identical outputs (uniform
//      floor), in-order prefix (mixed per-kind floors), owed_debit sequence ==
//      K_fair with fresh credit present
//   E  cross-check vs surplus-sim-L sim_l.py (generated vectors, P1 + P2 + P2')
//   F  randomized invariants over every feature: exact sum, <= s outputs,
//      owed_debit <= eo, prepaid <= credit_b, amount >= floor, permutation
//      invariance, u64-extreme amounts (u128 intermediates)
//   G  multi-block ledger with the booking contract: exact sum every block,
//      owed never negative, conservation credit = paid + owed + pending
//   H  scale: 200k rows / 4000 slots
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

#include <c2pool/v37/payout/rule_l.hpp>
#include <c2pool/v37/w4_settlement.hpp>

#include "rule_l_sim_vectors.hpp"

namespace L = ::c2pool::v37n::payout::rule_l;
namespace S = ::c2pool::v37n::settle;
using ::v37::bytes32;
using ::v37::ScriptKind;
using ::v37::ScriptRef;
using u64 = std::uint64_t;
using u128 = unsigned __int128;

static int g_checks = 0, g_fail = 0;
static void ok(bool c, const std::string& what) {
    ++g_checks;
    if (!c) { ++g_fail; std::printf("   FAIL  %s\n", what.c_str()); }
}

static bytes32 key(u64 v) {  // big-endian in the tail: bytes32 order == integer order
    bytes32 k{};
    for (int i = 0; i < 8; ++i) k[31 - i] = std::uint8_t(v >> (8 * i));
    return k;
}
static u64 kval(const bytes32& k) {
    u64 v = 0;
    for (int i = 0; i < 8; ++i) v |= u64(k[31 - i]) << (8 * i);
    return v;
}

using Row = L::Row<bytes32>;
using In = L::Input<bytes32>;
using Res = L::Result<bytes32>;

static Row row(u64 k, u64 eo, u64 fe, u64 cb = 0, u64 hmin = 0) { return Row{key(k), eo, fe, cb, hmin}; }

static std::vector<std::pair<u64, u64>> outs(const Res& r) {
    std::vector<std::pair<u64, u64>> v;
    for (const auto& o : r.outputs) v.push_back({kval(o.key), o.amount});
    return v;
}
using PV = std::vector<std::pair<u64, u64>>;

static u128 out_sum(const Res& r) {
    u128 s = 0;
    for (const auto& o : r.outputs) s += o.amount;
    return s;
}

// Full invariant check for one computed block. Returns true when all hold.
static bool invariants(const L::Params& P, const In& in, const Res& r, std::string* why = nullptr) {
    auto bad = [&](const char* w) { if (why) *why = w; return false; };
    if (r.status != L::Status::OK) return bad("status");
    if (out_sum(r) + r.donation != in.R) return bad("exact sum");
    if (r.donation < in.D_min) return bad("donation < D_min");
    if (in.slots != L::kUnboundedSlots && r.outputs.size() > in.slots) return bad("> s outputs");
    std::map<bytes32, const Row*> by;
    for (const auto& x : in.rows) by[x.key] = &x;
    std::set<bytes32> seen;
    for (const auto& o : r.outputs) {
        if (!seen.insert(o.key).second) return bad("duplicate payee");
        const Row* x = by.at(o.key);
        if (o.amount != o.owed_debit + o.prepaid) return bad("amount split");
        if (o.owed_debit > x->eo) return bad("owed_debit > eo");
        if (o.prepaid > x->credit_b) return bad("prepaid > credit_b");
        if (o.amount < std::max(P.h_min_dust, x->h_min)) return bad("amount < floor");
        if (o.amount == 0) return bad("zero output");
        if (o.phase == L::Phase::P2PRIME && !(P.genesis_p2prime && in.in_genesis)) return bad("P2' while off");
    }
    return true;
}

// ── C: independent naive P1 (subset enumeration) ────────────────────────────
struct NaiveP1 { std::vector<std::pair<int, u64>> em; std::vector<int> sk; u64 T; };
static u64 best_subset(const std::vector<u64>& v, const std::vector<int>& idx, u64 m) {
    u64 best = 0;
    const int n = int(idx.size());
    for (u64 mask = 0; mask < (u64(1) << n); ++mask) {
        if (u64(__builtin_popcountll(mask)) > m) continue;
        u64 s = 0;
        for (int j = 0; j < n; ++j) if (mask >> j & 1) s += v[idx[j]];
        best = std::max(best, s);
    }
    return best;
}
static NaiveP1 naive_p1(const std::vector<u64>& v, u64 s, u64 B) {
    NaiveP1 r;
    std::vector<int> all(v.size());
    for (std::size_t i = 0; i < v.size(); ++i) all[i] = int(i);
    r.T = std::min(B, best_subset(v, all, s));
    u64 paid = 0, sl = s;
    for (std::size_t i = 0; i < v.size() && sl > 0 && paid < r.T; ++i) {
        const u64 take = std::min(v[i], r.T - paid);
        bool feas = paid + take == r.T;
        if (!feas) {
            std::vector<int> rest;
            for (std::size_t j = i + 1; j < v.size(); ++j) rest.push_back(int(j));
            feas = paid + take + best_subset(v, rest, sl - 1) >= r.T;
        }
        if (feas) { r.em.push_back({int(i), take}); paid += take; --sl; }
        else r.sk.push_back(int(i));
    }
    return r;
}

static std::map<bytes32, ScriptRef> g_pay;
static ScriptRef pay_of(const bytes32& k) {
    auto it = g_pay.find(k);
    return it == g_pay.end() ? ScriptRef{} : it->second;
}
static u64 floor_kind(ScriptKind k) {
    switch (k) {
        case ScriptKind::P2PKH: return 546;
        case ScriptKind::P2WPKH: return 294;
        case ScriptKind::P2TR: return 330;
        default: return 546;
    }
}

int main() {
    std::printf("v37_payout_rule_l_kat\n");
    std::mt19937_64 rng(0x5eed1a2b3c4dULL);
    auto U = [&](u64 lo, u64 hi) { return lo + rng() % (hi - lo + 1); };

    // ── A: validation ──
    {
        L::Params P;
        In in; in.R = 100; in.D_min = 0; in.slots = 4;
        ok(L::compute(P, in).status == L::Status::BAD_D_MIN, "A1 D_min = 0 rejected");
        in.D_min = 101;
        ok(L::compute(P, in).status == L::Status::BAD_D_MIN, "A2 D_min > R rejected");
        in.D_min = 1;
        L::Params P0; P0.M = 0;
        ok(L::compute(P0, in).status == L::Status::BAD_M, "A3 M = 0 rejected");
        L::Params Pr; Pr.reserve_ppm = 1000001;
        ok(L::compute(Pr, in).status == L::Status::BAD_RESERVE, "A4 reserve > 1e6 ppm rejected");
        in.rows = {row(1, 50, 1), row(1, 60, 2)};
        ok(L::compute(P, in).status == L::Status::DUPLICATE_KEY, "A5 duplicate key rejected");
        in.rows = {row(1, 50, 1, 10), row(2, 60, 2, 10)};
        in.slots = 0;
        auto r = L::compute(P, in);
        ok(r.status == L::Status::OK && r.outputs.empty() && r.donation == 100,
           "A6 s == 0 is ZERO slots (not unbounded): everything to donation");
        in.slots = 4; in.rows.clear();
        r = L::compute(P, in);
        ok(r.outputs.empty() && r.donation == 100, "A7 no rows -> donation = R");
        ok(L::slots_from_budget(688, 43) == 16 && L::slots_from_budget(100, 0) == 0,
           "A8 s = floor(budget / S_max) (750-B class, BTC S_max 43 -> 16)");
    }

    // ── B: hand-computed ──
    {
        L::Params P; P.M = 1; P.h_min_dust = 1;
        In in; in.R = 1000; in.D_min = 1; in.slots = 2;
        in.rows = {row(1, 600, 1), row(2, 700, 2), row(3, 300, 3), row(4, 450, 0)};
        auto r = L::compute(P, in);
        ok(r.h_slot == 500 && r.eligible == 2, "B1 h_slot = ceil(R/(M*s)) = 500 excludes eo 300/450");
        ok(outs(r) == PV{{1, 600}, {2, 399}} && r.donation == 1 && r.T == 999,
           "B2 P1 FIFO: T = min(B, top2) = 999; a full, b partial 399");
    }
    // skip + P2 top-up
    L::Params P50; P50.M = 50; P50.h_min_dust = 1;
    {
        In in; in.R = 5001; in.D_min = 1; in.slots = 2;
        in.rows = {row(10, 100, 1, 100), row(20, 2000, 2, 300), row(30, 2500, 3, 100)};
        auto r = L::compute(P50, in);
        ok(r.T == 4500 && r.skipped.size() == 1 && kval(r.skipped[0]) == 10,
           "B3 T = top2 = 4500 < B; oldest row (100) skipped: accepting it makes T unreachable");
        ok(outs(r) == PV{{20, 2300}, {30, 2600}} && r.topup_total == 400 && r.donation == 101,
           "B4 P2 tops up emitted payees by credit_b (300, 100); leftover 100 -> donation 101");
        ok(r.outputs[0].owed_debit == 2000 && r.outputs[0].prepaid == 300, "B5 owed_debit/prepaid split");
        // reserve r = 0.5 -> 1 slot to the oldest row, paid in full, no feasibility test
        L::Params Pr = P50; Pr.reserve_ppm = 500000;
        auto rr = L::compute(Pr, in);
        ok(rr.reserve_slots == 1 && rr.reserved_used == 1 && rr.reserved_paid == 100,
           "B6 reserve floor(0.5*2) = 1 slot, oldest row paid full owed");
        ok(outs(rr) == PV{{10, 200}, {30, 2600}} && rr.skipped.size() == 1 && kval(rr.skipped[0]) == 20 &&
               rr.donation == 2201 && rr.outputs[0].phase == L::Phase::RESERVE,
           "B7 reserve then P1 over the rest (T=2500, b skipped), P2 top-ups; donation 2201");
        L::Params Pr0 = P50; Pr0.reserve_ppm = 0;
        ok(outs(L::compute(Pr0, in)) == outs(r), "B8 reserve_ppm = 0 == pure L");
    }
    // sub-dust fold
    {
        L::Params P; P.M = 50; P.h_min_dust = 50;
        In in; in.R = 1001; in.D_min = 1; in.slots = 3;
        in.rows = {row(1, 600, 1, 40), row(2, 380, 2, 0), row(3, 500, 3, 0)};
        auto r = L::compute(P, in);
        ok(r.sub_dust && kval(r.sub_dust_key) == 3 && r.sub_dust_amount == 20 && r.folded == 0,
           "B9 last take 20 < dust 50: not emitted, row 3 carries; prev has no credit_b -> fold 0");
        ok(outs(r) == PV{{1, 620}, {2, 380}} && r.donation == 1,
           "B10 unfolded 20 goes to P2 (row 1 credit_b 40) -> exact sum, donation D_min");
        in.rows[1].credit_b = 30;
        r = L::compute(P, in);
        ok(r.folded == 20 && outs(r) == PV{{1, 600}, {2, 400}} && r.outputs[1].prepaid == 20 &&
               r.outputs[1].owed_debit == 380 && r.donation == 1,
           "B11 fold absorbed by the previous payee against its credit_b (380 + 20)");
        in.rows[1].credit_b = 7; in.rows[0].credit_b = 0;
        r = L::compute(P, in);
        ok(r.folded == 7 && outs(r) == PV{{1, 600}, {2, 387}} && r.donation == 14,
           "B12 fold capped at credit_b (7); the 13 it cannot absorb -> donation");
        In one; one.R = 21; one.D_min = 1; one.slots = 1;
        one.rows = {row(9, 500, 1, 0)};
        L::Params P1s; P1s.M = 1; P1s.h_min_dust = 50;
        auto r1 = L::compute(P1s, one);
        ok(r1.sub_dust && r1.outputs.empty() && r1.donation == 21,
           "B13 sub-dust partial with no previous payee: carried, amount to donation");
    }
    // P2 largest remainder, key ASC tie; P2 when E exhausted (p2x)
    {
        In in; in.R = 202; in.D_min = 1; in.slots = 2;
        in.rows = {row(2, 100, 1, 5), row(1, 100, 2, 5)};
        auto r = L::compute(P50, in);
        ok(outs(r) == PV{{2, 100}, {1, 101}} && r.donation == 1,
           "B14 P2 remainder unit on an exact tie goes to the lower key");
        In ex; ex.R = 1001; ex.D_min = 1; ex.slots = 5;
        ex.rows = {row(1, 100, 1, 300), row(2, 50, 2, 0), row(3, 0, 0, 500)};
        auto re = L::compute(P50, ex);
        ok(outs(re) == PV{{1, 400}, {2, 50}} && re.donation == 551,
           "B15 E exhausted with slots left: P2 still tops up (p2x); no P2' by default");
    }
    // P2' default OFF, genesis gating
    {
        In in; in.R = 1001; in.D_min = 1; in.slots = 3;
        in.rows = {row(1, 100, 1, 300), row(2, 0, 0, 500), row(3, 0, 0, 200)};
        L::Params P = P50; P.h_min_dust = 10;
        auto off = L::compute(P, in);
        ok(outs(off) == PV{{1, 400}} && off.donation == 601, "B16 P2' OFF by default");
        P.genesis_p2prime = true;
        auto ng = L::compute(P, in);
        ok(outs(ng) == outs(off), "B17 P2' flag on but not in genesis -> no P2'");
        in.in_genesis = true;
        auto g = L::compute(P, in);
        ok(outs(g) == PV{{1, 400}, {2, 500}, {3, 100}} && g.donation == 1 && g.p2prime_total == 600,
           "B18 genesis P2': fresh-credit rows (credit DESC), capped by leftover");
    }

    // ── C: P1 brute-force oracle ──
    {
        int n_cases = 0, n_skips = 0, agree = 0;
        bool Tmax = true;
        for (int it = 0; it < 20000; ++it) {
            const int n = int(U(1, 10));
            const u64 s = U(1, 7);
            const u64 B = U(1, 500);
            std::vector<u64> v(n);
            static const u64 base[] = {1, 2, 3, 5, 8, 13, 50, 100};
            for (auto& x : v) x = base[U(0, 7)] * U(1, 3);
            L::Params P; P.M = u64(1) << 40; P.h_min_dust = 1;
            In in; in.R = B + 1; in.D_min = 1; in.slots = s;
            for (int i = 0; i < n; ++i) in.rows.push_back(row(u64(i) + 1, v[i], u64(i)));
            const auto r = L::compute(P, in);
            const auto nv = naive_p1(v, s, B);
            PV want;
            for (auto& [i, t] : nv.em) want.push_back({u64(i) + 1, t});
            std::vector<u64> wsk, gsk;
            for (int i : nv.sk) wsk.push_back(u64(i) + 1);
            for (auto& k : r.skipped) gsk.push_back(kval(k));
            if (outs(r) == want && wsk == gsk && r.T == nv.T && r.p1_paid == nv.T) ++agree;
            if (r.T != nv.T) Tmax = false;
            ++n_cases;
            n_skips += int(gsk.size());
        }
        std::printf("   C: %d instances, %d skips, %d agree\n", n_cases, n_skips, agree);
        ok(agree == n_cases, "C1 P1 == brute-force oracle decision-for-decision (skip ONLY when infeasible)");
        ok(Tmax, "C2 T == max payable (subset enumeration) on every instance");
        ok(n_skips > 1000, "C3 oracle exercised the skip path (non-hollow)");
    }

    // ── D: byte-for-byte vs the real K_fair OwedLedger::propose_coinbase ──
    {
        int eq_uniform = 0, n_uniform = 0, mixed_tail = 0, pref_mixed = 0, n_mixed = 0, owed_eq = 0, n_owed = 0, partial_cases = 0;
        for (int it = 0; it < 300; ++it) {
            const bool mixed = it % 3 == 1;        // categories: 0 uniform, 1 mixed floors,
            const bool with_credit = it % 3 == 2;  // 2 uniform + fresh credit
            S::OwedLedger Lg(3);
            In in; in.D_min = 1; in.slots = L::kUnboundedSlots;
            const int n = int(U(1, 50));
            u64 tot = 0;
            for (int i = 0; i < n; ++i) {
                const u64 kv = U(1, u64(1) << 40);
                const bytes32 k = key(kv);
                if (g_pay.count(k)) continue;
                ScriptRef sr;
                sr.kind = !mixed ? ScriptKind::P2WPKH
                                 : (i % 3 == 0 ? ScriptKind::P2PKH : i % 3 == 1 ? ScriptKind::P2WPKH : ScriptKind::P2TR);
                sr.payload.assign(sr.kind == ScriptKind::P2TR ? 32 : 20, std::uint8_t(i));
                g_pay[k] = sr;
                const u64 eo = U(0, 3) == 0 ? U(1, 600) : U(1, 200000);
                const u64 fe = U(100, 140);
                const std::string bid = "d" + std::to_string(it) + "_" + std::to_string(i);
                Lg.on_block_found(bid, S::OwedLedger::Amounts{{k, (long long)eo}}, {});
                Lg.on_block_finalized(bid, fe);
                in.rows.push_back(Row{k, eo, fe, with_credit ? U(0, 5000) : 0, floor_kind(sr.kind)});
                tot += eo;
            }
            u64 B = U(1, tot + tot / 4 + 1);
            if (U(0, 1) == 0 && !in.rows.empty()) {
                // aim the budget just past a K_fair prefix so the final take is
                // a small partial (the sub-dust / per-kind-floor boundary)
                std::vector<const Row*> ord;
                for (const auto& x : in.rows) if (x.eo >= x.h_min) ord.push_back(&x);
                std::sort(ord.begin(), ord.end(), [](const Row* a, const Row* b) {
                    return a->first_eligible != b->first_eligible ? a->first_eligible < b->first_eligible : a->key < b->key;
                });
                u64 pre = 0;
                const std::size_t j = ord.empty() ? 0 : std::size_t(U(0, ord.size() - 1));
                for (std::size_t q = 0; q < j; ++q) pre += ord[q]->eo;
                B = pre + U(1, 700);
            }
            in.R = B + 1;
            const auto master = Lg.propose_coinbase(B, 0, pay_of, [](ScriptKind k) { return floor_kind(k); });
            L::Params P; P.M = 50; P.h_min_dust = 1;
            const auto r = L::compute(P, in);
            PV mv;
            for (const auto& o : master.outs) mv.push_back({kval(o.key), o.amount});
            PV owed;
            for (const auto& o : r.outputs) owed.push_back({kval(o.key), o.owed_debit});
            if (r.sub_dust) ++partial_cases;
            if (!with_credit && !mixed) {
                ++n_uniform;
                if (outs(r) == mv) ++eq_uniform;
            } else if (!with_credit && mixed) {
                ++n_mixed;
                const PV lv = outs(r);
                bool pre = lv.size() <= mv.size() && mv.size() - lv.size() <= 1 &&
                           std::equal(lv.begin(), lv.end(), mv.begin());
                if (pre) ++pref_mixed;
                if (mv.size() == lv.size() + 1) ++mixed_tail;
            } else {
                ++n_owed;
                if (owed == mv) ++owed_eq;
            }
        }
        std::printf("   D: uniform %d/%d identical, mixed %d/%d prefix (%d with a K_fair tail), credit %d/%d owed-seq, "
                    "%d sub-dust partials\n", eq_uniform, n_uniform, pref_mixed, n_mixed, mixed_tail, owed_eq, n_owed,
                    partial_cases);
        ok(n_uniform > 50 && eq_uniform == n_uniform,
           "D1 C unbounded, r=0, no fresh credit, uniform floor: outputs == K_fair propose_coinbase byte-for-byte");
        ok(n_mixed > 50 && pref_mixed == n_mixed,
           "D2 mixed per-kind floors: outputs are an in-order prefix of K_fair (<= 1 trailing K_fair output)");
        ok(n_owed > 50 && owed_eq == n_owed,
           "D3 with fresh credit: the owed_debit sequence == K_fair (P2 only adds prepaid)");
        ok(mixed_tail > 0, "D5 the mixed-floor divergence (K_fair pays a later lower-floor row) was exercised");
        ok(partial_cases > 20, "D4 the sub-dust-partial path was exercised");
    }

    // ── E: surplus-sim-L cross-check ──
    {
        int agree = 0, n = 0;
        u64 skips = 0, gen = 0;
        for (const auto& v : rule_l_simvec::vectors()) {
            L::Params P; P.M = v.M; P.h_min_dust = v.dust; P.genesis_p2prime = v.genesis;
            In in; in.R = v.R; in.D_min = v.D_min; in.slots = v.s; in.in_genesis = v.genesis;
            for (const auto& x : v.rows) in.rows.push_back(row(x.key, x.eo, x.fe, x.credit_b));
            const auto r = L::compute(P, in);
            PV want;
            for (const auto& o : v.outs) want.push_back({o.key, o.amount});
            const bool eq = outs(r) == want && r.donation == v.donation && r.skipped.size() == v.skips && !r.sub_dust;
            if (eq) ++agree;
            else std::printf("   E mismatch: %s\n", v.name);
            ++n;
            skips += v.skips;
            gen += v.genesis;
        }
        std::printf("   E: %d/%d sim vectors agree (%llu P1 skips, %llu genesis P2')\n", agree, n,
                    (unsigned long long)skips, (unsigned long long)gen);
        ok(n >= 100 && agree == n, "E1 outputs + donation + skip count == sim_l.py on every vector");
    }

    // ── F: randomized invariants ──
    {
        int good = 0, n = 0, perm_ok = 0;
        std::string why;
        for (int it = 0; it < 4000; ++it) {
            L::Params P;
            P.M = U(1, 3) == 1 ? 1 : U(1, 100);
            P.h_min_dust = U(1, 60);
            P.reserve_ppm = U(0, 2) == 0 ? 0 : std::uint32_t(U(0, 1000000));
            P.genesis_p2prime = U(0, 1);
            In in;
            in.R = U(50, 200000);
            in.D_min = U(1, std::min<u64>(in.R, 30));
            const u64 sc = U(0, 9);
            in.slots = sc == 0 ? 0 : sc == 9 ? L::kUnboundedSlots : U(1, 30);
            in.in_genesis = U(0, 1);
            const int nr = int(U(0, 60));
            for (int i = 0; i < nr; ++i) {
                const u64 eo = U(0, 3) == 0 ? 0 : U(0, 1) ? U(1, 100) : U(1, 60000);
                in.rows.push_back(row(u64(i) * 97 + 5, eo, U(0, 20), U(0, 2) == 0 ? 0 : U(0, 4000),
                                      U(0, 3) == 0 ? U(0, 120) : 0));
            }
            const auto r = L::compute(P, in);
            if (invariants(P, in, r, &why)) ++good;
            else std::printf("   F fail it=%d: %s\n", it, why.c_str());
            In sh = in;
            std::shuffle(sh.rows.begin(), sh.rows.end(), rng);
            const auto r2 = L::compute(P, sh);
            std::vector<std::array<u64, 4>> a, b;
            for (const auto& o : r.outputs) a.push_back({kval(o.key), o.amount, o.owed_debit, o.prepaid});
            for (const auto& o : r2.outputs) b.push_back({kval(o.key), o.amount, o.owed_debit, o.prepaid});
            if (a == b && r.donation == r2.donation) ++perm_ok;
            ++n;
        }
        ok(good == n, "F1 invariants on " + std::to_string(n) + " random blocks (exact sum, <= s, bounds, floors)");
        ok(perm_ok == n, "F2 caller row order is irrelevant (deterministic)");
        // u64 extremes: XMR-scale piconero amounts near 2^64 exercise the u128 paths
        L::Params P; P.M = 50; P.h_min_dust = 1; P.genesis_p2prime = true; P.reserve_ppm = 250000;
        In in; in.R = ~u64(0); in.D_min = 1; in.slots = 4; in.in_genesis = true;
        const u64 big = u64(1) << 62;
        in.rows = {row(1, big, 1, big), row(2, big + 7, 2, big), row(3, big - 3, 3, big),
                   row(4, u64(1) << 61, 4, big), row(5, 0, 0, ~u64(0) >> 1), row(6, 3 * big, 5, 12345)};
        const auto r = L::compute(P, in);
        ok(invariants(P, in, r, &why), "F3 near-2^64 R and owed: exact sum holds (u128) " + why);
    }

    // ── G: multi-block ledger with the booking contract ──
    {
        struct Cfg { const char* name; u64 R, dust; std::uint32_t reserve; bool gen; };
        const Cfg cfgs[] = {{"BTC pure L", 320000000, 330, 0, false},
                            {"DASH r=0.25", 40000000, 546, 250000, false},
                            {"BTC genesis P2'", 320000000, 330, 0, true}};
        for (const auto& c : cfgs) {
            const int N = 150, lag = 10, G0 = 60, blocks = 800;
            std::vector<u64> eo(N, 0), fe(N, 0), hw(N);
            for (auto& h : hw) h = U(1, 1000) * U(1, 1000) * (U(0, 20) == 0 ? 400 : 1);
            std::map<int, std::pair<std::vector<u64>, std::vector<u64>>> pending;  // credit, prepaid
            u128 credit_tot = 0, paid_tot = 0;
            bool sum_ok = true, neg_ok = true, inv_ok = true;
            L::Params P; P.M = 50; P.h_min_dust = c.dust; P.reserve_ppm = c.reserve; P.genesis_p2prime = c.gen;
            const u64 D_min = 1, B = c.R - D_min;
            u64 outs_n = 0, skips = 0, subd = 0;
            for (int b = 0; b < blocks; ++b) {
                // this block's PPLNS credit over a random share sample
                std::vector<u64> w(N, 0);
                u64 tot = 0;
                for (u64 h : hw) tot += h;
                for (int q = 0; q < 300; ++q) {
                    u64 x = rng() % tot;
                    int i = 0; while (x >= hw[i]) { x -= hw[i]; ++i; }
                    ++w[i];
                }
                std::vector<bytes32> ks(N);
                for (int i = 0; i < N; ++i) ks[i] = key(u64(i) + 1);
                auto cr = L::detail::largest_remainder<bytes32>(B, w, ks);
                pending[b] = {cr, std::vector<u64>(N, 0)};
                for (u64 x : cr) credit_tot += x;
                if (b - lag >= 0) {  // finalized-only arming: armed = credit - prepaid
                    auto& [pc, pp] = pending[b - lag];
                    for (int i = 0; i < N; ++i) {
                        const u64 net = pc[i] - pp[i];
                        if (eo[i] == 0 && net > 0) fe[i] = u64(b);
                        eo[i] += net;
                    }
                    pending.erase(b - lag);
                }
                In in; in.R = c.R; in.D_min = D_min; in.in_genesis = b < G0;
                static const u64 cls[] = {750, 750, 750, 2250, 6500};
                in.slots = L::slots_from_budget(cls[U(0, 4)] - 62, 43);
                for (int i = 0; i < N; ++i)
                    if (eo[i] > 0 || pending[b].first[i] > 0) in.rows.push_back(Row{ks[i], eo[i], fe[i], pending[b].first[i], 0});
                const auto r = L::compute(P, in);
                if (!invariants(P, in, r)) inv_ok = false;
                if (out_sum(r) + r.donation != c.R) sum_ok = false;
                for (const auto& o : r.outputs) {
                    const int i = int(kval(o.key)) - 1;
                    if (o.owed_debit > eo[i]) neg_ok = false;
                    eo[i] -= o.owed_debit;
                    pending[b].second[i] += o.prepaid;
                    if (pending[b].second[i] > pending[b].first[i]) neg_ok = false;
                    paid_tot += o.amount;
                    if (eo[i] == 0) fe[i] = 0;
                }
                outs_n += r.outputs.size();
                skips += r.skipped.size();
                subd += r.sub_dust;
            }
            u128 owed = 0, pend = 0;
            for (u64 x : eo) owed += x;
            for (auto& [bb, pr] : pending) for (int i = 0; i < N; ++i) pend += pr.first[i] - pr.second[i];
            std::printf("   G %-16s %d blocks, %llu outputs, %llu skips, %llu sub-dust folds\n", c.name, blocks,
                        (unsigned long long)outs_n, (unsigned long long)skips, (unsigned long long)subd);
            ok(sum_ok && inv_ok, std::string("G1 ") + c.name + ": exact sum + invariants every block");
            ok(neg_ok, std::string("G2 ") + c.name + ": owed never negative, prepaid <= fresh credit");
            ok(credit_tot == paid_tot + owed + pend, std::string("G3 ") + c.name + ": conservation credit = paid + owed + pending");
        }
    }

    // ── H: scale ──
    {
        L::Params P; P.M = 50; P.h_min_dust = 330;
        In in; in.R = 320000000; in.D_min = 1; in.slots = 4000;
        for (u64 i = 0; i < 200000; ++i) in.rows.push_back(row(i + 1, U(0, 3) ? U(1, 50000) : U(1, 5000000), U(0, 100000), U(0, 3000)));
        const auto t0 = std::chrono::steady_clock::now();
        const auto r = L::compute(P, in);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        std::printf("   H: 200k rows, s=4000: %zu outputs, %zu skips, %lld ms\n", r.outputs.size(), r.skipped.size(),
                    (long long)ms);
        ok(invariants(P, in, r), "H1 200k rows / 4000 slots: invariants hold");
        In in2 = in; in2.slots = 16;
        const auto r2 = L::compute(P, in2);
        ok(invariants(P, in2, r2) && r2.outputs.size() <= 16, "H2 200k rows / 16 slots (stock 750-B class)");
    }

    std::printf("v37_payout_rule_l_kat: %d checks, %d failed -> %s\n", g_checks, g_fail, g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
