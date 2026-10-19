// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_drops_jk_keep_share_credit_kat — DROPS-JK: an interval with J < K
// near-misses is NOT ESTIMABLE, so it keeps its share credit (delta 0).
//
// THE DEFECT (DROPS defect 1, confirmed on the XDW regtest verify). With the
// gate ON, an ENROLLED payee's harvested interval that had shares but fewer
// than K near-misses was composed as if the estimator had measured ZERO work:
// Hhat := 0, and the REPLACE composition then took the interval's whole share
// work S*T back out of E_b. On the XDW rig the net sub-threshold credit came
// out NEGATIVE for all three enrolled payees (-10.97e12 / -3.75e12 / -1.06e12
// piconero). With J < K there is no h_(K), so there is no estimate at all — the
// interval is not estimable, and nothing should be replaced.
//
// THE RULING (operator, 09-25). J < K keeps the share credit; the DROPS delta
// for that (payee, interval) is 0. That is also what the reference
// apply_credit() has always returned (`J < K => 0`, no delta).
//
// WHAT THIS KAT PINS, on every lane geometry the flip can build (arity 1, which
// the XMR lane and every decoupled node use, and arity 2 per BTC/LTC/DASH/DOGE):
//   JK-1  an enrolled payee with S > 0 and J = 0 (the synthesised row) and one
//         with S > 0 and J = K - 1 produce NO delta row; RED on the base,
//         where both were composed NEGATIVE (-S*T each);
//   JK-2  the composed credit (compose_credit_replace) for every J < K payee is
//         its E_b row, byte for byte — the share credit is unchanged;
//   JK-3  intervals with J >= K are composed EXACTLY as before: the delta equals
//         the from-spec entitlement(Hhat_comb) - entitlement(S*T) to the unit,
//         covered and drop-only alike;
//   JK-4  a harvest of ONLY J < K rows leaves the settled owed_digest identical
//         to a fold with no harvest at all (non-vacuous: the full harvest moves
//         it); RED on the base;
//   JK-5  the shipped seam and the reference apply_credit() now agree on WHICH
//         (payee, interval) rows carry a delta, including the dedup key a J < K
//         row does not consume;
//   JK-6  gate OFF is master: LaneParams{} composes nothing, base map returned;
//   JK-7  a measured stream: a small enrolled miner over many intervals — the
//         count of NEGATIVE compositions caused by J < K is 0 on the fix (the
//         base count is printed), and the J >= K deltas are unchanged.
//
// HOLLOW-GREEN GUARD: registered with add_test() in
// src/c2pool/v37/test/CMakeLists.txt AND listed on BOTH build.yml
// `cmake --build --target` allowlists.
//
// Exit status 0 = all checks pass; 1 = at least one check failed.
// ===========================================================================
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>   // subthreshold_credit, OwedLedger

namespace n37    = ::c2pool::v37n;
namespace settle = ::c2pool::v37n::settle;
namespace sub    = ::c2pool::v37::subthreshold;
using ::v37::bytes32;
using ::v37::LaneKind;
using ::v37::LaneParams;
using ::v37::u64;

static long g_checks = 0, g_fail = 0;
static void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) ++g_fail;
    std::printf("  %s %s\n", ok ? "ok  " : "FAIL", what);
}
static std::string hex(const bytes32& d) {
    static const char* x = "0123456789abcdef";
    std::string s;
    for (auto b : d) { s += x[b >> 4]; s += x[b & 15]; }
    return s;
}
static bytes32 key(int i) { bytes32 k{}; k[0] = 0x4A; k[1] = 0x4B; k[31] = (std::uint8_t)i; return k; }

// share target h_T = 2^244 - 1  ->  one share is 2^12 = 4096 hashes of work.
static constexpr unsigned H_T_BIT = 244;
static sub::u256 share_target() {
    sub::u256 t;
    for (unsigned b = 0; b < H_T_BIT; ++b) t.w[b >> 6] |= (1ull << (b & 63));
    return t;
}
// a near-miss hash strictly above h_T: m * 2^244, m >= 2.
static sub::u256 near_miss(std::uint64_t m) {
    sub::u256 h;
    h.w[3] = m << (H_T_BIT - 192);
    return h;
}

static constexpr std::uint32_t K = 4;
static constexpr u64 REWARD = 50ull * 100000000ull;
static constexpr u64 IV = 1000;                    // the harvested interval

// The price at the cut: SUM weight = 64 shares of lane work, in Q62 units.
static settle::WorkPrice price() {
    settle::WorkPrice wp;
    wp.reward = REWARD;
    wp.sum_weight = ::v37::U256::from_u128(((::v37::u128)(64ull * 4096ull)) << 62);
    wp.valid = true;
    return wp;
}

static sub::ReceiptCollector collector(std::uint64_t S, const std::vector<std::uint64_t>& ms) {
    sub::ReceiptCollector rc(K, share_target());
    rc.set_shares(S);
    for (auto m : ms) rc.observe(near_miss(m));
    return rc;
}

// The from-spec J >= K composition (Combined): entitlement(Hhat_comb) - entitlement(S*T).
static long long spec_delta(const settle::WorkPrice& wp, const sub::ReceiptCollector& rc) {
    const sub::u320 e = sub::estimate_combined(rc.shares(), K, rc.h_K());
    const sub::u320 w = sub::share_covered_work(rc.shares(), rc.target_hash());
    return settle::entitlement_of_work(wp, e) - settle::entitlement_of_work(wp, w);
}
static long long share_ent(const settle::WorkPrice& wp, std::uint64_t S) {
    return settle::entitlement_of_work(wp, sub::share_covered_work(S, share_target()));
}

static bytes32 fold(const LaneParams& p, const std::map<bytes32, long long>& base,
                    const std::vector<settle::HarvestedReceipt>& hv,
                    const settle::DropsCompose& ctx) {
    settle::OwedLedger led(7);
    led.on_block_found_with_drops("blk", base, {}, p, hv, ctx);
    led.on_block_finalized("blk", IV + 20);
    return led.owed_digest();
}

struct Geo { const char* name; LaneParams p; };

int main() {
    std::printf("v37_drops_jk_keep_share_credit_kat — DROPS-JK: J < K keeps the share credit\n");
    const settle::WorkPrice wp = price();
    const bytes32 P_SYNTH = key(1), P_THIN = key(2), P_DTHIN = key(3), P_COV = key(4),
                  P_DROP = key(5), P_OUT = key(6);

    n37::EnrollmentBook book;
    for (const bytes32& k : {P_SYNTH, P_THIN, P_DTHIN, P_COV, P_DROP})
        check(book.commit(k, 10, 11), "enrol ex ante (effective 11, harvest at 1000)");
    settle::DropsCompose ctx;
    ctx.price = wp;
    ctx.enrollment = &book;

    // The six payee shapes (S shares, J near-misses) at interval IV.
    const auto rc_synth = collector(3, {});                   // S=3, J=0 (synthesised row)
    const auto rc_thin  = collector(2, {2, 3, 5});            // S=2, J=3 = K-1
    const auto rc_dthin = collector(0, {2, 7});               // S=0, J=2 (drop-only, < K)
    const auto rc_cov   = collector(2, {2, 3, 5, 9, 11});     // S=2, J=5 >= K (h_K = 9*2^244)
    const auto rc_drop  = collector(0, {3, 4, 6, 8, 13, 15}); // S=0, J=6 >= K
    const auto rc_out   = collector(2, {});                   // NOT enrolled
    const std::vector<settle::HarvestedReceipt> harvest{
        {P_SYNTH, IV, rc_synth}, {P_THIN, IV, rc_thin}, {P_DTHIN, IV, rc_dthin},
        {P_COV, IV, rc_cov},     {P_DROP, IV, rc_drop}, {P_OUT, IV, rc_out}};
    const std::vector<settle::HarvestedReceipt> jk_only{
        {P_SYNTH, IV, rc_synth}, {P_THIN, IV, rc_thin}, {P_DTHIN, IV, rc_dthin}};

    // E_b as the ordinary share path pays it, plus one lane payee outside DROPS.
    std::map<bytes32, long long> base;
    base[P_SYNTH] = share_ent(wp, 3);
    base[P_THIN]  = share_ent(wp, 2);
    base[P_COV]   = share_ent(wp, 2);
    base[P_OUT]   = share_ent(wp, 2);
    base[key(9)]  = share_ent(wp, 55);
    std::printf("   one share at this cut = %lld units; E_b(S=3) = %lld\n",
                share_ent(wp, 1), base[P_SYNTH]);

    std::vector<Geo> geos;
    geos.push_back({"arity-1 for_version(1) [XMR / decoupled]", LaneParams::for_version(1)});
    geos.push_back({"arity-2 BTC ", LaneParams::for_version(1, LaneKind::BTC)});
    geos.push_back({"arity-2 LTC ", LaneParams::for_version(1, LaneKind::LTC)});
    geos.push_back({"arity-2 DASH", LaneParams::for_version(1, LaneKind::DASH)});
    geos.push_back({"arity-2 DOGE", LaneParams::for_version(1, LaneKind::DOGE)});

    std::string transcript;
    for (const auto& g : geos) {
        std::printf("\n-- geometry %s (gate %s, K=%u, mode=%u) --\n", g.name,
                    g.p.subthreshold.enabled ? "ON" : "OFF", g.p.subthreshold.K,
                    g.p.subthreshold.mode);
        check(g.p.subthreshold.enabled && g.p.subthreshold.K == K &&
                  g.p.subthreshold.mode == 1,
              "the flip geometry is gate ON, K = 4, Combined");
        bool sat = false;
        const auto d = settle::subthreshold_credit(g.p, harvest, ctx, &sat);
        auto at = [&](const bytes32& k) { return d.count(k) ? d.at(k) : 0LL; };
        std::printf("   delta: SYNTH(S=3,J=0)=%lld THIN(S=2,J=3)=%lld DTHIN(S=0,J=2)=%lld "
                    "COV(S=2,J=5)=%lld DROP(S=0,J=6)=%lld OUT(not enrolled)=%lld\n",
                    at(P_SYNTH), at(P_THIN), at(P_DTHIN), at(P_COV), at(P_DROP), at(P_OUT));
        check(!sat, "no i64 saturation");
        // JK-1
        check(d.count(P_SYNTH) == 0,
              "JK-1 ★ enrolled S=3, J=0 (synthesised row): NO delta — not estimable, "
              "the share credit is kept (base: composed -S*T)");
        check(d.count(P_THIN) == 0,
              "JK-1 ★ enrolled S=2, J=K-1: NO delta (base: composed -S*T)");
        check(d.count(P_DTHIN) == 0, "JK-1 enrolled drop-only S=0, J=2 < K: NO delta");
        check(d.count(P_OUT) == 0, "R-SYBIL unchanged: a non-enrolled payee: NO delta");
        // JK-2
        const auto comp = settle::compose_credit_replace(g.p, base, harvest, ctx);
        check(comp.at(P_SYNTH) == base.at(P_SYNTH) && comp.at(P_THIN) == base.at(P_THIN) &&
                  comp.at(P_OUT) == base.at(P_OUT) && comp.at(key(9)) == base.at(key(9)) &&
                  comp.count(P_DTHIN) == 0,
              "JK-2 ★ the composed credit of every J < K payee IS its E_b row, "
              "byte for byte");
        // JK-3
        const long long s_cov = spec_delta(wp, rc_cov), s_drop = spec_delta(wp, rc_drop);
        std::printf("   from-spec J>=K: COV=%lld DROP=%lld\n", s_cov, s_drop);
        check(at(P_COV) == s_cov && s_cov != 0,
              "JK-3 J >= K covered: delta == entitlement(Hhat_comb) - entitlement(S*T), "
              "exactly as before");
        check(at(P_DROP) == s_drop && s_drop > 0,
              "JK-3 J >= K drop-only: delta == entitlement(Hhat_comb) > 0, exactly as before");
        check(comp.at(P_COV) == base.at(P_COV) + s_cov && comp.at(P_DROP) == s_drop,
              "JK-3 the composed J >= K rows are E_b + the from-spec delta");
        // JK-4
        const bytes32 d_none = fold(g.p, base, {}, ctx);
        const bytes32 d_jk   = fold(g.p, base, jk_only, ctx);
        const bytes32 d_full = fold(g.p, base, harvest, ctx);
        std::printf("   owed_digest: no-harvest=%s\n                J<K-only  =%s\n"
                    "                full      =%s\n",
                    hex(d_none).substr(0, 24).c_str(), hex(d_jk).substr(0, 24).c_str(),
                    hex(d_full).substr(0, 24).c_str());
        check(d_jk == d_none,
              "JK-4 ★ a harvest of ONLY J < K rows leaves the settled owed_digest "
              "IDENTICAL to no harvest");
        check(d_full != d_none, "JK-4 non-vacuous: the J >= K rows move it");
        // JK-5: the reference apply_credit() (raw, pre-ruling denomination) and
        // the shipped seam agree on WHICH rows carry a delta.
        const auto raw = settle::subthreshold_credit_raw_PRE_RULING(g.p, harvest);
        std::string rk, sk;
        for (const auto& [k, v] : raw) { (void)v; if (k != P_OUT) rk += hex(k).substr(62) + ","; }
        for (const auto& [k, v] : d) { (void)v; sk += hex(k).substr(62) + ","; }
        std::printf("   rows with a delta: reference=[%s] shipped=[%s]\n", rk.c_str(), sk.c_str());
        check(rk == sk, "JK-5 the shipped seam and the reference apply_credit() agree "
                        "on which (payee, interval) rows are composed");
        // the dedup key: a J < K row does not consume it (as in the reference).
        const std::vector<settle::HarvestedReceipt> twice{
            {P_THIN, IV, rc_thin}, {P_THIN, IV, rc_cov}};
        const auto d2 = settle::subthreshold_credit(g.p, twice, ctx);
        const auto r2 = settle::subthreshold_credit_raw_PRE_RULING(g.p, twice);
        check(d2.size() == 1 && d2.begin()->second == s_cov && r2.size() == 1,
              "JK-5 a J < K row does not consume its (payee, interval) dedup key — "
              "same as the reference");
        for (const auto& [k, v] : d) transcript += hex(k) + "=" + std::to_string(v) + ";";
        transcript += hex(d_full) + "|";
    }

    // JK-6: gate OFF is master.
    std::printf("\n-- JK-6 gate OFF --\n");
    {
        const LaneParams off{};
        check(settle::subthreshold_credit(off, harvest, ctx).empty(),
              "JK-6 gate OFF: subthreshold_credit is EMPTY");
        check(settle::compose_credit_replace(off, base, harvest, ctx) == base,
              "JK-6 gate OFF: the composed credit is the base map");
        check(fold(off, base, harvest, ctx) == fold(off, base, {}, ctx),
              "JK-6 gate OFF: owed_digest unchanged by the harvest");
    }

    // JK-7: a measured stream. One enrolled small miner over 400 intervals,
    // each with S in 0..6 shares and J in 0..6 near-misses drawn from a fixed
    // splitmix64 stream (J < K in about 4 of 7 intervals — the small-miner
    // regime the XDW rig ran in). Count the J < K intervals, the NEGATIVE
    // compositions they produce, and check every J >= K interval against the
    // from-spec composition.
    std::printf("\n-- JK-7 measured stream (400 intervals, S and J in 0..6) --\n");
    {
        const LaneParams p = LaneParams::for_version(1);
        const bytes32 M = key(20);
        n37::EnrollmentBook b2;
        b2.commit(M, 0, 1);
        settle::DropsCompose c2;
        c2.price = wp;
        c2.enrollment = &b2;
        std::uint64_t st = 0x4A4B5EEDull;
        auto next = [&]() {
            st += 0x9E3779B97F4A7C15ull;
            std::uint64_t z = st;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
            return z ^ (z >> 31);
        };
        long long net = 0, net_jk_base = 0, net_ge = 0;
        long jk_rows = 0, jk_neg_fix = 0, jk_neg_base = 0, ge_rows = 0, ge_mismatch = 0;
        for (u64 iv = 1; iv <= 400; ++iv) {
            const std::uint64_t S = next() % 7;
            const unsigned J = (unsigned)(next() % 7);
            std::vector<std::uint64_t> ms;
            for (unsigned j = 0; j < J; ++j) ms.push_back(2 + next() % 14);
            const auto rc = collector(S, ms);
            const std::vector<settle::HarvestedReceipt> one{{M, iv, rc}};
            const auto d = settle::subthreshold_credit(p, one, c2);
            const long long v = d.count(M) ? d.at(M) : 0;
            net += v;
            if (!rc.has_K()) {
                ++jk_rows;
                if (v < 0) ++jk_neg_fix;
                // what the base composed for this row: Hhat := 0, minus S*T
                const long long b = -share_ent(wp, S);
                if (b < 0) ++jk_neg_base;
                net_jk_base += b;
            } else {
                ++ge_rows;
                net_ge += v;
                if (v != spec_delta(wp, rc)) ++ge_mismatch;
            }
        }
        std::printf("   J<K intervals=%ld  negative compositions: fix=%ld base=%ld "
                    "(base net from J<K = %lld)\n",
                    jk_rows, jk_neg_fix, jk_neg_base, net_jk_base);
        std::printf("   J>=K intervals=%ld  net J>=K delta=%lld  mismatches vs from-spec=%ld\n",
                    ge_rows, net_ge, ge_mismatch);
        std::printf("   net sub-threshold delta: fix=%lld base=%lld\n", net, net_ge + net_jk_base);
        check(jk_rows > 0 && jk_neg_base > 0,
              "JK-7 non-vacuous: the stream has J < K intervals WITH shares");
        check(jk_neg_fix == 0, "JK-7 ★ 0 negative compositions from J < K on the fix");
        check(ge_mismatch == 0, "JK-7 every J >= K interval composed exactly as from-spec");
        check(net == net_ge, "JK-7 the whole net delta comes from J >= K intervals");
        transcript += std::to_string(net) + "|";
    }

    // The transcript digest: one value a re-run must reproduce.
    const bytes32 td = ::v37::sha256d(
        std::vector<std::uint8_t>(transcript.begin(), transcript.end()));
    std::printf("\nDROPS-JK transcript digest = %s\n", hex(td).c_str());
    std::printf("\n%ld checks, %ld failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
