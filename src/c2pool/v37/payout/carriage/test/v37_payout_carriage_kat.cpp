// v37_payout_carriage_kat — CarriageGate (capacity-based carriage bonus) +
// FeeFloorGate (h_min_dyn) standalone module: src/c2pool/v37/payout/carriage.hpp
//
//   A  carriage gate OFF identity: beta_ppm == 0 (or pos < activation) =>
//      w' == w bit-for-bit, nothing read, nothing rejected
//   B  formula vectors: cap tables (BTC P2WPKH / DASH P2PKH), n_fee off-by-one,
//      n_b = min(cap, Q_fin, n_fee, n_ref), bonus exactness (u128) + saturation,
//      explicit rejects (class byte > 5, cb_total_out < subsidy, bad params)
//   C  ANTI-DISPLACEMENT: the bonus is independent of the number of outputs the
//      coinbase actually emits; a template that trades fee txs for outputs
//      never earns more (w' non-increasing), equal fees => identical w'
//   D  Q_fin cap (finalized queue length) + class 5 saturation
//   E  zero-sum normalisation over a window: sum pay + residual == R exactly,
//      OFF split == plain split, per-miner loss <= beta/(1+beta), bonus mass
//      <= beta * w (sybil bound)
//   F  fee floor gate OFF identity: output_vb == w5 output_size, h_min_dyn ==
//      w5 h_min(kind, k_floor), REAL OwedLedger::propose_coinbase byte-identical
//   G  h_min_dyn vectors (design K10) + ceil rounding + validate(m)
//   H  displacement bound <= R/m on REAL propose_coinbase proposals; every
//      emitted output >= h_min_dyn, every skipped one < h_min_dyn (carry);
//      template facts == block-recomputed facts => identical proposal
//   I  K9 balance inequality (also static_assert in the header)
//   J  lane-tag fold material: OFF => no fold; every field perturbs the digest
//   K  XMR: carriage permanently OFF; fee floor via explicit vb
#include <map>
#include <set>
#include <string>
#include <vector>

#include <c2pool/v37/payout/carriage.hpp>
#include <c2pool/v37/w5_coinbase.hpp>
#include <c2pool/v37/roundabout/test/rb_kat_harness.hpp>

namespace C = ::c2pool::v37n::payout::carriage;
namespace rb = ::c2pool::v37n::rb;
namespace S = ::c2pool::v37n::settle;
namespace CB = ::c2pool::v37n::coinbase;
using ::v37::ScriptKind;
using ::v37::ScriptRef;
using ::v37::u128;
using ::v37::u64;
using rbkat::ok;

// Pinned lane-tag fold goldens (J5): a change here is a consensus change.
static const char* GOLDEN_CARRIAGE = "9b628c342b93744a856a27bddef7547de99d6b94a0d1109af484925726624b01";
static const char* GOLDEN_FEE_FLOOR = "621af719d2eb620a3f5cebed4adfffa217824c9701e2214ef1cabec7e9faddb6";

static const ScriptKind KINDS[6] = {ScriptKind::P2PKH, ScriptKind::P2SH, ScriptKind::P2WPKH,
                                    ScriptKind::P2WSH, ScriptKind::P2TR, ScriptKind::RAW};

static std::map<::v37::bytes32, ScriptRef> g_pay;
static ScriptRef pay_of(const ::v37::bytes32& k) {
    auto it = g_pay.find(k);
    return it == g_pay.end() ? ScriptRef{} : it->second;
}

// A random finalized ledger with n keys of mixed kinds and amounts spanning
// several orders of magnitude (so any floor splits emit/carry).
static void build_ledger(S::OwedLedger& L, rbkat::SplitMix64& r, int n, int tag) {
    for (int i = 0; i < n; ++i) {
        ::v37::bytes32 k = r.key();
        ScriptRef sr;
        sr.kind = KINDS[r.below(6)];
        sr.payload.assign((sr.kind == ScriptKind::P2TR || sr.kind == ScriptKind::P2WSH ||
                           sr.kind == ScriptKind::RAW) ? 32 : 20, std::uint8_t(i));
        g_pay[k] = sr;
        const u64 mag = u64(1) << r.below(28);
        S::OwedLedger::Amounts credit{{k, static_cast<long long>(1 + r.below(mag) + (mag >> 1))}};
        const std::string bid = "t" + std::to_string(tag) + "b" + std::to_string(i);
        L.on_block_found(bid, credit, {});
        L.on_block_finalized(bid, 100 + r.below(60));
    }
}

static bool same_prop(const S::OwedLedger::Proposal& a, const S::OwedLedger::Proposal& b) {
    if (a.outs.size() != b.outs.size()) return false;
    for (std::size_t i = 0; i < a.outs.size(); ++i)
        if (a.outs[i].key != b.outs[i].key || a.outs[i].amount != b.outs[i].amount ||
            a.outs[i].pay.kind != b.outs[i].pay.kind)
            return false;
    return true;
}

int main() {
    std::printf("v37_payout_carriage_kat\n");
    const u64 BTC_SUBSIDY = 312'500'000;

    // ── A: carriage gate OFF identity ──────────────────────────────────────
    {
        rbkat::SplitMix64 r(0xA0A0);
        const C::CarriageGate off{};
        ok(off.off() && off.beta_ppm == 0 && C::validate(off), "A0 default CarriageGate is OFF and valid");
        bool id = true, noreject = true;
        for (int i = 0; i < 20000; ++i) {
            const u64 w = (i % 7 == 0) ? C::U64_MAX - r.below(3) : r.next() >> r.below(64);
            C::CarriageFacts f;
            f.cb_class_byte = std::uint8_t(r.below(256));     // includes invalid 6..255
            f.subsidy = r.next();
            f.cb_total_out = r.next();                         // may be < subsidy
            f.q_fin = r.next();
            const auto res = C::carriage_apply(off, w, f, r.below(2) ? 0 : r.next() >> 40, r.next());
            if (res.w_prime != w) id = false;
            if (res.verdict != C::CarriageVerdict::OK || res.n_b != 0) noreject = false;
            if (C::carriage_bonus_weight(off, w, r.below(501)) != w) id = false;
        }
        ok(id, "A1 beta_ppm == 0 => w' == w bit-for-bit (20000 random w incl. u64 max)");
        ok(noreject, "A2 OFF gate reads nothing: invalid class byte / cb_total < subsidy never reject");
        C::CarriageGate pend = C::CarriageGate::v1(C::CARRIAGE_VB_REF_BTC, 1000);
        C::CarriageFacts f{3, BTC_SUBSIDY + 10'000'000, BTC_SUBSIDY, 5000};
        ok(C::carriage_apply(pend, 1'000'000, f, 0, 999).w_prime == 1'000'000,
           "A3 ON params before activation_pos => w' == w");
        ok(C::carriage_apply(pend, 1'000'000, f, 0, 1000).w_prime == 1'005'000,
           "A4 at activation_pos the bonus applies (class 3 saturates n_ref: +0.5 %)");
        C::CarriageGate nb0 = C::CarriageGate::v1(31, 0);
        ok(C::carriage_bonus_weight(nb0, 777, 0) == 777, "A5 n_b == 0 => w' == w");
    }

    // ── B: formula vectors ────────────────────────────────────────────────
    {
        const auto btc = C::CarriageGate::v1(C::CARRIAGE_VB_REF_BTC, 0);
        const auto dash = C::CarriageGate::v1(C::CARRIAGE_VB_REF_DASH, 0);
        const u64 want_btc[5] = {16, 64, 201, 520, 2106};
        const u64 want_dash[5] = {14, 59, 184, 474, 1920};
        bool tb = true, td = true;
        for (int c = 0; c < 5; ++c) {
            if (C::carriage_cap(btc, rb::CbClass(c), 0) != want_btc[c]) tb = false;
            if (C::carriage_cap(dash, rb::CbClass(c), 0) != want_dash[c]) td = false;
        }
        ok(tb, "B1 BTC P2WPKH cap table {16, 64, 201, 520, 2106} (design {16,64,201,520,~2100})");
        ok(td, "B2 DASH P2PKH cap table {14, 59, 184, 474, 1920} (design {14,59,184,474,~1900})");
        ok(C::carriage_cap(btc, rb::CbClass::SV2_HEADER_ONLY, 100'000) == (100'000 - 244) / 31,
           "B3 class 5 cap = (lane K_max - overhead) / vb_ref");
        ok(C::carriage_cap(btc, rb::CbClass::SV2_HEADER_ONLY, 0) >= (u64(1) << 50),
           "B4 class 5 under an unbounded lane: effectively infinite cap");
        C::CarriageGate fat = btc; fat.overhead_min = 800;
        ok(C::carriage_cap(fat, rb::CbClass::STOCK_ANTMINER, 0) == 0, "B5 overhead >= class bytes => cap 0");

        ok(C::carriage_n_fee(btc, 0) == 16, "B6 n_fee: F = 0 => n_floor (16): empty block earns floor only");
        ok(C::carriage_n_fee(btc, 150'039) == 499, "B7 n_fee: F = 150,039 => 499");
        ok(C::carriage_n_fee(btc, 150'040) == 500, "B8 n_fee: F = 150,040 => 500 (f_ref*vb_ref = 310 sat step)");
        ok(C::carriage_n_fee(btc, C::U64_MAX) == 16 + C::U64_MAX / 310, "B9 n_fee: huge F, no wrap");
        ok(C::carriage_n_b(btc, rb::CbClass::OPEN_FW_16K, 1'000'000, 1'000'000'000, 0) == 500,
           "B10 n_b saturates at n_ref (class 3 cap 520 > 500)");
        ok(C::carriage_n_b(btc, rb::CbClass::OPEN_FW_16K, 1'000'000, 0, 0) == 16,
           "B11 n_b bound by n_fee when F = 0");

        // Design bonus-per-class numbers (beta 0.5 %, w = 1e6): +0.016/0.064/0.201/0.5 %.
        const u64 w = 1'000'000;
        const u64 want_bonus[6] = {160, 640, 2010, 5000, 5000, 5000};
        bool bv = true;
        for (int c = 0; c <= 5; ++c) {
            C::CarriageFacts f{std::uint8_t(c), BTC_SUBSIDY + 50'000'000, BTC_SUBSIDY, 100'000};
            const auto res = C::carriage_apply(btc, w, f, 0, 0);
            if (res.verdict != C::CarriageVerdict::OK || res.w_prime - w != want_bonus[c]) bv = false;
        }
        ok(bv, "B12 bonus by class at beta 0.5 %: +160/+640/+2010/+5000/+5000/+5000 ppm-of-w");
        C::CarriageGate v2 = btc; v2.beta_ppm = C::CARRIAGE_BETA_PPM_V2;
        ok(C::carriage_bonus_weight(v2, w, 500) == 1'010'000, "B13 V2 beta 1 %: saturated bonus +1 %");

        rbkat::SplitMix64 r(0xB0B0);
        bool exact = true, mono = true;
        for (int i = 0; i < 50000; ++i) {
            C::CarriageGate g = btc;
            g.beta_ppm = std::uint32_t(1 + r.below(C::CARRIAGE_BETA_PPM_MAX));
            g.n_ref = std::uint16_t(1 + r.below(2000));
            const u64 x = r.next() >> r.below(64);
            const u64 nb = r.below(u64(g.n_ref) + 1);
            const u64 wp = C::carriage_bonus_weight(g, x, nb);
            const u128 prod = u128(x) * g.beta_ppm * nb;
            const u128 den = u128(C::PPM) * g.n_ref;
            const u128 exact_w = u128(x) + prod / den;
            if (exact_w <= u128(C::U64_MAX)) {
                const u128 b = u128(wp) - x;   // floor check by inequality, not by the same expression
                if (!(b * den <= prod && prod < (b + 1) * den)) exact = false;
            } else if (wp != C::U64_MAX) exact = false;
            if (nb > 0 && C::carriage_bonus_weight(g, x, nb - 1) > wp) mono = false;
        }
        ok(exact, "B14 bonus == floor(w*beta*n_b/(1e6*n_ref)) exactly (50000 random, u128 + saturation)");
        ok(mono, "B15 w' monotone non-decreasing in n_b");
        ok(C::carriage_bonus_weight(v2, C::U64_MAX, 500) == C::U64_MAX, "B16 u64 max saturates, never wraps");

        bool rj = true;
        for (int b = 6; b < 256; ++b) {
            C::CarriageFacts f{std::uint8_t(b), BTC_SUBSIDY, BTC_SUBSIDY, 10};
            const auto res = C::carriage_apply(btc, w, f, 0, 0);
            if (res.verdict != C::CarriageVerdict::REJECT_CLASS_BYTE || res.w_prime != w) rj = false;
        }
        ok(rj, "B17 committed class byte 6..255 => REJECT_CLASS_BYTE (never guessed)");
        C::CarriageFacts low{2, BTC_SUBSIDY - 1, BTC_SUBSIDY, 10};
        ok(C::carriage_apply(btc, w, low, 0, 0).verdict == C::CarriageVerdict::REJECT_CB_TOTAL_BELOW_SUBSIDY,
           "B18 cb_total_out < subsidy => REJECT (never clamped to F = 0)");
        ok(!C::fees_included(9, 10).has_value() && *C::fees_included(10, 10) == 0, "B19 fees_included boundary");
        C::CarriageGate bad = btc; bad.n_ref = 0;
        ok(!C::validate(bad) && C::carriage_apply(bad, w, C::CarriageFacts{2, BTC_SUBSIDY, BTC_SUBSIDY, 10}, 0, 0)
                                        .verdict == C::CarriageVerdict::REJECT_PARAMS,
           "B20 ON with n_ref = 0 => invalid params, explicit reject");
        C::CarriageGate greedy = btc; greedy.beta_ppm = std::uint32_t(C::CARRIAGE_BETA_PPM_MAX + 1);
        ok(!C::validate(greedy), "B21 beta above the K9 service value (17,123 ppm) is invalid");
        C::CarriageGate edge = btc; edge.beta_ppm = std::uint32_t(C::CARRIAGE_BETA_PPM_MAX);
        ok(C::validate(edge), "B22 beta == 17,123 ppm is valid");
        C::CarriageGate zf = btc; zf.f_ref_sat_vb = 0;
        C::CarriageGate zv = btc; zv.vb_ref = 0;
        ok(!C::validate(zf) && !C::validate(zv), "B23 ON with f_ref = 0 or vb_ref = 0 is invalid");
    }

    // ── C: anti-displacement (the pivot's property test) ──────────────────
    {
        rbkat::SplitMix64 r(0xC0C0);
        bool nonincr = true, equal_f = true, fmono = true;
        for (int t = 0; t < 4000; ++t) {
            C::CarriageGate g = C::CarriageGate::v1(r.below(2) ? 31 : 34, 0);
            if (r.below(2)) g.beta_ppm = C::CARRIAGE_BETA_PPM_V2;
            const std::uint8_t cls = std::uint8_t(r.below(6));
            const u64 q = r.below(3000);
            const u64 w = 1 + (r.next() >> r.below(40));
            const u64 fees0 = r.below(400'000'000);
            const u64 vb = C::output_vb(KINDS[r.below(6)]);
            const u64 feerate = r.below(400);                 // sat/vB of displaced tail txs
            const u64 dn = 1 + r.below(200);                   // extra outputs per step
            u64 prev = C::U64_MAX;
            for (int j = 0; j < 8; ++j) {
                // Template j emits n0 + j*dn outputs by displacing j*dn*vb vB of txs.
                const u64 lost = std::min<u64>(fees0, u64(j) * dn * vb * feerate);
                C::CarriageFacts f{cls, BTC_SUBSIDY + fees0 - lost, BTC_SUBSIDY, q};
                const u64 wp = C::carriage_apply(g, w, f, 0, 0).w_prime;
                if (wp > prev) nonincr = false;
                prev = wp;
            }
            const u64 f1 = r.below(1'000'000), f2 = f1 + r.below(1'000'000);
            if (C::carriage_n_b(g, rb::CbClass(cls), q, f1, 0) > C::carriage_n_b(g, rb::CbClass(cls), q, f2, 0))
                fmono = false;
        }
        ok(nonincr, "C1 displacing fee txs for more outputs never raises w' (4000 x 8 templates)");
        // C2 on REAL coinbases: proposals with different output counts (slot
        // budget C varies) all total subsidy + fees (payouts + donation
        // residual), so the receipt facts and hence w' are identical.
        for (int t = 0; t < 40; ++t) {
            S::OwedLedger L(3);
            build_ledger(L, r, 20 + int(r.below(150)), 500 + t);
            const u64 fees = r.below(200'000'000);
            const u64 R = BTC_SUBSIDY + fees;
            const std::uint8_t cls = std::uint8_t(r.below(6));
            const u64 q = r.below(3000), w = 1 + (r.next() >> 24);
            const auto g = C::CarriageGate::v1(31, 0);
            u64 ref = 0;
            std::set<std::size_t> nouts;
            for (unsigned Cc : {1u, 5u, 17u, 64u, 0u}) {
                const auto p = L.propose_coinbase(R, Cc, pay_of, [](ScriptKind k) { return CB::h_min(k, 1); });
                u64 paid = 0;
                for (const auto& o : p.outs) paid += o.amount;
                const u64 cb_total_out = paid + (R - paid);   // payouts + donation residual
                nouts.insert(p.outs.size());
                const u64 wp = C::carriage_apply(g, w, C::CarriageFacts{cls, cb_total_out, BTC_SUBSIDY, q}, 0, 0).w_prime;
                if (Cc == 1u) ref = wp;
                else if (wp != ref) equal_f = false;
            }
            if (nouts.size() < 2) equal_f = false;   // the sample must really vary n_out
        }
        ok(equal_f, "C2 REAL coinbases with different n_out (C = 1/5/17/64/unbounded) => identical w'");
        ok(fmono, "C3 n_b non-decreasing in F_incl (fee self-harm only)");
        // Structural: CarriageFacts has exactly 4 fields, none of them n_out.
        ok(sizeof(C::CarriageFacts) == 32, "C4 CarriageFacts = {class, cb_total_out, subsidy, q_fin}: no n_out input");
    }

    // ── D: Q_fin cap ──────────────────────────────────────────────────────
    {
        const auto g = C::CarriageGate::v1(31, 0);
        bool capq = true;
        for (int c = 0; c <= 5; ++c)
            for (u64 q : {u64(0), u64(1), u64(30), u64(499), u64(5000)}) {
                const u64 nb = C::carriage_n_b(g, rb::CbClass(c), q, 10'000'000'000ull, 0);
                if (nb > q || nb > C::carriage_cap(g, rb::CbClass(c), 0) || nb > g.n_ref) capq = false;
            }
        ok(capq, "D1 n_b <= min(Q_fin, cap(class), n_ref) for all 6 classes x 5 queue lengths");
        ok(C::carriage_n_b(g, rb::CbClass::SV2_HEADER_ONLY, 30, 10'000'000'000ull, 0) == 30,
           "D2 Q_fin = 30 => class 5 n_b = 30 (no pay for empty capacity)");
        C::CarriageFacts f{5, BTC_SUBSIDY + 10'000'000'000ull, BTC_SUBSIDY, 0};
        ok(C::carriage_apply(g, 123456789, f, 0, 0).w_prime == 123456789, "D3 Q_fin = 0 => w' == w");
        f.q_fin = 30;
        ok(C::carriage_apply(g, 1'000'000, f, 0, 0).w_prime == 1'000'300, "D4 Q_fin = 30 => +0.03 % at beta 0.5 %");
    }

    // ── E: zero-sum normalisation over a window ───────────────────────────
    {
        rbkat::SplitMix64 r(0xE0E0);
        bool sum_ok = true, off_ok = true, loss_ok = true, mass_ok = true;
        for (int t = 0; t < 1500; ++t) {
            C::CarriageGate g = C::CarriageGate::v1(31, 0);
            g.beta_ppm = r.below(2) ? C::CARRIAGE_BETA_PPM_V1 : C::CARRIAGE_BETA_PPM_V2;
            const u64 R = BTC_SUBSIDY + r.below(300'000'000);
            const u64 q = r.below(3000);
            const std::size_t n = 1 + r.below(300);
            std::vector<u64> w(n), wp(n), woff(n);
            for (std::size_t i = 0; i < n; ++i) {
                w[i] = 1 + (r.next() >> (20 + r.below(30)));
                C::CarriageFacts f{std::uint8_t(r.below(6)), R, BTC_SUBSIDY, q};
                wp[i] = C::carriage_apply(g, w[i], f, 0, 0).w_prime;
                woff[i] = C::carriage_apply(C::CarriageGate{}, w[i], f, 0, 0).w_prime;
                if (u128(wp[i] - w[i]) * C::PPM > u128(w[i]) * g.beta_ppm) mass_ok = false;
            }
            const auto s0 = C::window_split(R, w), s1 = C::window_split(R, wp), soff = C::window_split(R, woff);
            u128 t1 = s1.residual, t0 = s0.residual;
            for (std::size_t i = 0; i < n; ++i) { t1 += s1.pay[i]; t0 += s0.pay[i]; }
            if (t1 != R || t0 != R) sum_ok = false;
            if (soff.pay != s0.pay || soff.residual != s0.residual) off_ok = false;
            const u128 k = C::PPM + g.beta_ppm;
            for (std::size_t i = 0; i < n; ++i)
                if (u128(s1.pay[i]) * k + k < u128(s0.pay[i]) * C::PPM) loss_ok = false;
        }
        ok(sum_ok, "E1 sum pay + residual == R exactly, gate ON and OFF (1500 windows)");
        ok(off_ok, "E2 gate OFF window split == plain split of w");
        ok(loss_ok, "E3 every miner's payout >= gate-OFF payout / (1 + beta) - 1 (loss <= beta/(1+beta))");
        ok(mass_ok, "E4 bonus mass per share <= beta * w (sybil identities gain only their own beta)");
    }

    // ── F: fee floor gate OFF identity ────────────────────────────────────
    {
        bool vb = true;
        for (ScriptKind k : KINDS) if (C::output_vb(k) != CB::output_size(k)) vb = false;
        ok(vb, "F1 output_vb(kind) == w5 output_size(kind) for all 6 kinds");
        const C::FeeFloorGate off{};
        ok(off.off() && C::validate(off), "F2 default FeeFloorGate is OFF and valid");
        rbkat::SplitMix64 r(0xF0F0);
        bool hid = true;
        for (int i = 0; i < 20000; ++i) {
            const ScriptKind k = KINDS[r.below(6)];
            const u64 kf = r.below(4) == 0 ? r.next() >> r.below(64) : r.below(50);
            C::FeeFloorFacts f{r.next() >> r.below(64), r.below(4'000'000), r.below(10'000)};
            if (C::h_min_dyn(off, k, kf, f, r.next()) != CB::h_min(k, kf) && kf < (u64(1) << 57)) hid = false;
            C::FeeFloorGate pend = C::FeeFloorGate::on(100, 1'000'000);
            if (C::h_min_dyn(pend, k, kf, f, r.below(1'000'000)) != C::h_min_dyn(off, k, kf, f, 0)) hid = false;
        }
        ok(hid, "F3 OFF / pre-activation h_min_dyn == w5 h_min(kind, k_floor) (20000 random)");

        bool same = true;
        for (int t = 0; t < 60; ++t) {
            S::OwedLedger L(3);
            build_ledger(L, r, 5 + int(r.below(120)), 1000 + t);
            const u64 kf = r.below(3) == 0 ? 0 : (r.below(2) ? 1 : 10);
            const u64 reward = BTC_SUBSIDY + r.below(100'000'000);
            const unsigned Cc = unsigned(r.below(3) == 0 ? 0 : 1 + r.below(80));
            auto w5_lambda = [&](ScriptKind k) { return CB::h_min(k, kf); };
            C::FeeFloorHmin gate_off{off, kf, C::FeeFloorFacts{r.below(1'000'000'000), 1'000'000, 300}, r.next()};
            const auto a = L.propose_coinbase(reward, Cc, pay_of, w5_lambda);
            const auto b = L.propose_coinbase(reward, Cc, pay_of, gate_off);
            if (!same_prop(a, b)) same = false;
            CB::CoinbaseBudget bud; bud.slot_budget_C = Cc; bud.k_floor = kf;
            const auto asm_ = CB::assemble(L, reward, bud, pay_of);
            if (asm_.outputs.size() != a.outs.size()) same = false;
            for (std::size_t i = 0; i < a.outs.size() && i < asm_.outputs.size(); ++i)
                if (asm_.outputs[i].key != a.outs[i].key || asm_.outputs[i].amount != a.outs[i].amount) same = false;
        }
        ok(same, "F4 REAL propose_coinbase with FeeFloorHmin(OFF) == w5 h_min lambda == assemble() (60 ledgers)");
    }

    // ── G: h_min_dyn vectors ──────────────────────────────────────────────
    {
        const auto g = C::FeeFloorGate::on(C::FEE_FLOOR_M_DEFAULT, 0);
        const u64 D = 1'000'000 - 250;
        auto facts = [&](u64 fbar) { return C::FeeFloorFacts{fbar * D, 1'000'000, 250}; };
        ok(C::h_min_dyn(g, ScriptKind::P2WPKH, 10, facts(0), 0) == 310, "G1 fbar = 0 => k_floor * vb (310 at k_floor 10)");
        ok(C::h_min_dyn(g, ScriptKind::P2WPKH, 10, facts(1), 0) == 3'100, "G2 fbar = 1 sat/vB => 3,100 sat");
        ok(C::h_min_dyn(g, ScriptKind::P2WPKH, 10, facts(10), 0) == 31'000, "G3 fbar = 10 => 31,000 sat (P2WPKH)");
        ok(C::h_min_dyn(g, ScriptKind::P2WPKH, 10, facts(100), 0) == 310'000, "G4 fbar = 100 => 310,000 sat");
        ok(C::h_min_dyn(g, ScriptKind::P2WPKH, 10, facts(312), 0) == 967'200, "G5 fbar = 312 => 967,200 sat");
        ok(C::h_min_dyn(g, ScriptKind::P2TR, 10, facts(10), 0) == 43'000, "G6 P2TR at fbar = 10 => 43,000 sat");
        ok(C::h_min_dyn(g, ScriptKind::P2PKH, 10, facts(10), 0) == 34'000, "G7 P2PKH at fbar = 10 => 34,000 sat");
        const C::FeeFloorFacts tiny{1, 1'000'000, 0};
        ok(C::h_min_dyn(g, ScriptKind::P2WPKH, 0, tiny, 0) == 1, "G8 dynamic term rounds UP (ceil(3100/1e6) = 1)");
        const C::FeeFloorFacts exact{1'000'000, 1'000'000, 0};   // fbar = 1 exactly
        ok(C::h_min_dyn(g, ScriptKind::P2WPKH, 0, exact, 0) == 3'100, "G9 exact division: no ceil bump");
        const C::FeeFloorFacts full{1000, 300, 300};              // L == cb_fixed => D floored at 1
        ok(C::fee_floor_denominator(full) == 1 && C::h_min_dyn(g, ScriptKind::P2WPKH, 0, full, 0) == 3'100'000,
           "G10 degenerate D (L <= cb_fixed) floors at 1, never divides by 0");
        const C::FeeFloorFacts huge{C::U64_MAX, 1, 0};   // D = 1
        ok(C::h_min_dyn(g, ScriptKind::RAW, 0, huge, 0) == C::U64_MAX, "G11 saturates at u64 max, never wraps");
        ok(C::h_min_dyn_vb(g, u64(1) << 33, 0, exact, 0) == C::U64_MAX, "G12 nonsense vb (> 2^32) never emits");
        ok(!C::validate(C::FeeFloorGate::on(50, 0)) && C::validate(C::FeeFloorGate::on(100, 0)) &&
               C::validate(C::FeeFloorGate::on(1000, 0)),
           "G13 validate: m in {0} U [100, ..) (fee bound m >= 100)");
        ok(C::fee_floor_emits(31'000, 31'000) && !C::fee_floor_emits(30'999, 31'000), "G14 emit iff amount >= h_min_dyn");
        rb::BlockFacts bf; bf.block_limit_bytes = 1'000'000; bf.coinbase_fixed_overhead = 250; bf.txs_bytes = 900'000;
        const auto ff = C::fee_floor_facts_from_block(bf, BTC_SUBSIDY + 10 * D, BTC_SUBSIDY);
        ok(ff && ff->f_incl == 10 * D && ff->block_limit == 1'000'000 && ff->cb_fixed == 250 &&
               C::h_min_dyn(g, ScriptKind::P2WPKH, 10, *ff, 0) == 31'000,
           "G15 facts recomputed from BlockFacts + coinbase total reproduce G3");
        ok(!C::fee_floor_facts_from_block(bf, BTC_SUBSIDY - 1, BTC_SUBSIDY).has_value(),
           "G16 coinbase total < subsidy => no facts (block invalid)");
    }

    // ── H: displacement bound on REAL proposals ───────────────────────────
    {
        rbkat::SplitMix64 r(0x4848);
        bool bound = true, floor_ok = true, carry_ok = true, rebuild = true, order = true;
        std::size_t emitted = 0, carried = 0;
        for (int t = 0; t < 120; ++t) {
            S::OwedLedger L(3);
            build_ledger(L, r, 10 + int(r.below(200)), 2000 + t);
            const std::uint32_t m = r.below(2) ? 100 : 100 + std::uint32_t(r.below(2000));
            const auto g = C::FeeFloorGate::on(m, 0);
            const u64 limit = 1'000'000, cbfix = 200 + r.below(800);
            const u64 fees = r.below(4) == 0 ? 0 : r.below(400'000'000);
            const u64 R = BTC_SUBSIDY + fees;
            const u64 kf = r.below(2) ? 1 : 10;
            C::FeeFloorFacts facts{fees, limit, cbfix};
            C::FeeFloorHmin hmin{g, kf, facts, 0};
            const auto p = L.propose_coinbase(R, 0, pay_of, hmin);
            u64 sum_vb = 0, sum_a = 0;
            std::set<::v37::bytes32> in;
            for (const auto& o : p.outs) {
                sum_vb += C::output_vb(o.pay.kind);
                sum_a += o.amount;
                in.insert(o.key);
                if (o.amount < hmin(o.pay.kind)) floor_ok = false;
            }
            emitted += p.outs.size();
            if (!C::displacement_within_bound(g, facts, sum_vb, sum_a)) bound = false;
            if (!(u128(m) * fees * sum_vb <= u128(C::fee_floor_denominator(facts)) * R)) bound = false;
            // Every eligible key that was skipped had owed < its floor (a CARRY),
            // unless the reward budget ran out first.
            // Oldest-first: emitted keys appear in the gate-OFF (k_floor 0) visiting order.
            const auto all = L.propose_coinbase(C::U64_MAX / 4, 0, pay_of, [](ScriptKind) { return u64(0); });
            std::size_t pos = 0;
            for (const auto& o : p.outs) {
                while (pos < all.outs.size() && all.outs[pos].key != o.key) ++pos;
                if (pos == all.outs.size()) order = false;
            }
            u64 left = R;
            for (const auto& a : all.outs) {
                if (left == 0) break;
                const u64 take = std::min<u64>(a.amount, left);
                const bool em = in.count(a.key) != 0;
                if (em) left -= take;
                else if (take >= hmin(a.pay.kind)) carry_ok = false;
                else ++carried;
            }
            // Rebuild: validator facts from the block's bytes == template facts.
            rb::BlockFacts bf; bf.block_limit_bytes = limit; bf.coinbase_fixed_overhead = cbfix;
            const auto vf = C::fee_floor_facts_from_block(bf, R, BTC_SUBSIDY);
            if (!vf) { rebuild = false; continue; }
            const auto p2 = L.propose_coinbase(R, 0, pay_of, C::FeeFloorHmin{g, kf, *vf, 0});
            if (!same_prop(p, p2)) rebuild = false;
        }
        std::printf("   H: %zu outputs emitted, %zu sub-floor balances carried over 120 ledgers\n", emitted, carried);
        ok(floor_ok, "H1 every emitted output >= h_min_dyn(kind)");
        ok(carry_ok, "H2 every skipped balance was below its floor (skip-and-CARRY, no other drop)");
        ok(bound, "H3 m * F_incl * sum(vb) <= D * sum(a) <= D * R  (displacement <= R/m)");
        ok(order, "H4 emitted outputs keep the oldest-first K_fair visiting order");
        ok(rebuild, "H5 validator facts recomputed from the block => byte-identical proposal");
        ok(carried > 0 && emitted > 0, "H6 the sample exercises both emit and carry");
        // H7 tightness: an output paid EXACTLY its floor still satisfies the
        // bound (this is what the CEIL buys; a floor-rounded h_min_dyn breaks it
        // whenever m * F * vb is not a multiple of D).
        bool tight = true;
        for (int i = 0; i < 20000; ++i) {
            const auto g = C::FeeFloorGate::on(100 + std::uint32_t(r.below(5000)), 0);
            C::FeeFloorFacts f{r.below(u64(1) << 40), 1 + r.below(4'000'000), 0};
            const u64 vb = C::output_vb(KINDS[r.below(6)]);
            const u64 h = C::h_min_dyn_vb(g, vb, 0, f, 0);
            if (!C::displacement_within_bound(g, f, vb, h)) tight = false;
            if (h > 0 && u128(g.m) * f.f_incl * vb <= u128(C::fee_floor_denominator(f)) * (h - 1)) tight = false;
        }
        ok(tight, "H7 h_min_dyn is the LEAST amount meeting the bound (exact ceil, 20000 random)");
    }

    // ── I: K9 balance inequality ──────────────────────────────────────────
    {
        ok(C::CARRIAGE_BETA_PPM_MAX == 17'123 && C::drain_service_value_ppm(50'000) == 4'280,
           "I1 drain service value: 1.71 % of R at r = 20 %, 0.43 % at r = 5 %");
        ok(C::CARRIAGE_BETA_PPM_V1 <= C::CARRIAGE_BETA_PPM_MAX && C::CARRIAGE_BETA_PPM_V2 <= C::CARRIAGE_BETA_PPM_MAX,
           "I2 V1 (0.5 %) and V2 (1 %) beta within the service value (static_assert in header)");
        ok(C::FEE_FLOOR_M_DEFAULT >= C::FEE_FLOOR_M_MIN, "I3 fee bound m >= 100");
    }

    // ── J: lane-tag fold material ─────────────────────────────────────────
    {
        ok(!C::fold_required(C::CarriageGate{}) && !C::fold_required(C::FeeFloorGate{}),
           "J1 OFF gates are not folded (OFF lane tag byte-identical to master)");
        const auto v1 = C::CarriageGate::v1(31, 777);
        ok(C::fold_required(v1) && C::fold_required(C::FeeFloorGate::on(100, 5)), "J2 ON gates require the fold");
        ok(C::carriage_params_leaf(v1).size() == 29 && C::fee_floor_params_leaf(C::FeeFloorGate{}).size() == 18,
           "J3 leaf sizes: carriage 29 B, fee floor 18 B");
        const auto d0 = C::params_digest(v1);
        bool all = true;
        for (int f = 0; f < 7; ++f) {
            C::CarriageGate p = v1;
            switch (f) {
                case 0: p.beta_ppm++; break;
                case 1: p.n_ref++; break;
                case 2: p.n_floor++; break;
                case 3: p.f_ref_sat_vb++; break;
                case 4: p.vb_ref++; break;
                case 5: p.overhead_min++; break;
                case 6: p.activation_pos++; break;
            }
            if (C::params_digest(p) == d0) all = false;
        }
        const auto e0 = C::params_digest(C::FeeFloorGate::on(100, 5));
        if (C::params_digest(C::FeeFloorGate::on(101, 5)) == e0 || C::params_digest(C::FeeFloorGate::on(100, 6)) == e0)
            all = false;
        ok(all, "J4 every parameter field perturbs its digest (mixed fleet => TAG_MISMATCH)");
        const auto cz = C::params_digest(C::CarriageGate::v1(31, 0));
        const auto fz = C::params_digest(C::FeeFloorGate::on(100, 0));
        std::printf("   J goldens: carriage V1 BTC @0 %s\n              fee floor m=100 @0 %s\n",
                    rbkat::hx(cz).c_str(), rbkat::hx(fz).c_str());
        ok(rbkat::hx(cz) == GOLDEN_CARRIAGE && rbkat::hx(fz) == GOLDEN_FEE_FLOOR, "J5 params digests match pinned goldens");
    }

    // ── K: XMR ────────────────────────────────────────────────────────────
    {
        ok(C::XMR_CARRIAGE_PERMANENTLY_OFF && C::carriage_gate_xmr().off() &&
               C::validate_for_xmr(C::carriage_gate_xmr()) &&
               !C::validate_for_xmr(C::CarriageGate::v1(31, 0)),
           "K1 XMR carriage permanently OFF; any beta != 0 invalid for XMR");
        C::CarriageFacts f{5, 1, 0, 100000};
        ok(C::carriage_apply(C::carriage_gate_xmr(), 42, f, 0, 0).w_prime == 42, "K2 XMR w' == w");
        const auto g = C::FeeFloorGate::on(100, 0);
        const C::FeeFloorFacts xf{300'000 * 20, 300'000, 0};   // 20 pico/B mean fee rate
        ok(C::h_min_dyn_vb(g, 43, 0, xf, 0) == 100 * 20 * 43, "K3 XMR fee floor via explicit vb (43 B output, 20 pico/B)");
    }

    return rbkat::finish("v37_payout_carriage_kat");
}
