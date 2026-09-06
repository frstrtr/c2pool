// ============================================================================
// v37_subthreshold_estimator_test — consolidated KAT for the DROPS half of the
// V37 "raindrops -> bucket" work estimator (src/c2pool/v37/
// v37_subthreshold_estimator.hpp).
//
// Stdlib-only, no gtest / no Boost / no core link — the same self-harness shape
// as src/c2pool/v37/test/v37_w4_settlement_test.cpp: the suite is its own driver
// and returns nonzero on any failure, so it runs anywhere the toolchain exists.
//
// HOLLOW-GREEN GUARD: this target MUST be listed in the build.yml `cmake --build
// --target` allowlist for BOTH legs (Linux x86_64 + ASan/UBSan) and registered
// in src/c2pool/v37/test/CMakeLists.txt, else CTest reports it NOT_BUILT and the
// run silently passes (the DGB #137 / #769 / PR #1467 unregistered-KAT class).
//
// Cases (each reported PASS/FAIL with detail):
//   1  estimator-core exact integer vector           (golden ESTIMATE)
//   2  combined sybil-neutral estimator exact vector  (golden COMBINED)
//   3  censoring-corrected receipts-only exact vector (golden CENSORING)
//   4  unbiasedness Monte-Carlo  E[Hhat]/H -> 1       (reproduces mc_estimator/sim E1)
//   5  sybil-neutrality: broken clamp 1.9x REJECTED; comb <= ~1.02x active
//   6  no-double-count: share-covered worker not re-credited
//   7  interval-straddle dedup per (payee, sequence)  (golden STRADDLE ratio)
//   8  K>=3 guard (K=2 -> no estimate / no credit)
//   9  ★ PRIME: gate-off owed_digest BYTE-IDENTICAL; gate-on differs
//  10  golden stamp check + NEGATIVE CONTROL (corrupt one byte -> KAT red)
//  11  ★ PRIME: gate-off receipt/share-digest BYTE-IDENTICAL (add-only carrier
//      is 0 bytes when OFF); gate-on appends the "V37D" trailer and differs
// ============================================================================
#include <c2pool/v37/v37_subthreshold_estimator.hpp>
#include "subthreshold_golden_v1.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace c2pool::v37::subthreshold;
namespace gv = c2pool::v37::subthreshold::golden;

// ------------------------------------------------------------- tiny harness
static int g_pass = 0, g_fail = 0;
static void check(bool ok, const char* name, const std::string& detail) {
    std::printf("  [%s] %-46s %s\n", ok ? "PASS" : "FAIL", name, detail.c_str());
    if (ok) ++g_pass; else ++g_fail;
}

// ------------------------------------------------------------- helpers
static u256 u256_from_hex(const char* hex) {  // 64 hex chars, big-endian
    std::array<std::uint8_t, 32> b{};
    for (int i = 0; i < 32; ++i) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        b[static_cast<std::size_t>(i)] =
            (std::uint8_t)((nib(hex[i * 2]) << 4) | nib(hex[i * 2 + 1]));
    }
    return u256::from_be_bytes(b);
}

static std::string hex_of(const std::array<std::uint8_t, 32>& d) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (auto c : d) { s.push_back(H[c >> 4]); s.push_back(H[c & 15]); }
    return s;
}

// deterministic, portable PRNG (splitmix64) — no platform rand, no <random>
// engine dependency, so the MC bands are stable across toolchains/legs.
struct SplitMix64 {
    std::uint64_t s;
    explicit SplitMix64(std::uint64_t seed) : s(seed) {}
    std::uint64_t next() {
        std::uint64_t z = (s += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }
    u256 hash() {
        u256 r;
        for (int i = 0; i < 4; ++i) r.w[static_cast<std::size_t>(i)] = next();
        return r;
    }
};

// raw magnitude of a u320 as a double (the estimate is a hash COUNT ~ H, not a
// fraction of 2^256), for MC ratios (diagnostic maths only).
static double u320_to_double(const u320& x) {
    double v = 0.0;
    for (int i = 4; i >= 0; --i)
        v = v * 18446744073709551616.0 + (double)x.w[static_cast<std::size_t>(i)];
    return v;
}

// K-th smallest of `hs` (ascending), 1-indexed K.
static u256 kth_smallest(std::vector<u256>& hs, std::uint32_t K) {
    std::sort(hs.begin(), hs.end());
    return hs[K - 1];
}

// =====================================================================
int main(int argc, char** argv) {
    bool neg = (argc > 1 && std::strcmp(argv[1], "--neg") == 0);
    std::printf("v37_subthreshold_estimator_test  (golden stamp %s)\n", gv::STAMP);

    // -- Case 1: estimator-core exact integer vector -------------------
    {
        bool all = true; std::string d;
        for (const auto& r : gv::ESTIMATE) {
            u256 hK = u256_from_hex(r.h_K_hex);
            std::string got = estimate_hashes(r.K, hK).to_dec();
            if (got != r.Hhat_dec) { all = false; d += " K=" + std::to_string(r.K) +
                " got=" + got + " want=" + r.Hhat_dec; }
        }
        if (all) d = "5 rows (K=3,4,8,16,32) floor((K-1)*2^256/(h_K+1)) exact";
        check(all, "1 estimator-core exact vector", d);
    }

    // -- Case 2: combined sybil-neutral estimator ----------------------
    {
        bool all = true; std::string d;
        for (const auto& r : gv::COMBINED) {
            u256 hK = u256_from_hex(r.h_K_hex);
            std::string got = estimate_combined(r.S, r.K, hK).to_dec();
            if (got != r.Hcomb_dec) { all = false; d += " (S=" + std::to_string(r.S) +
                ",K=" + std::to_string(r.K) + ") got=" + got + " want=" + r.Hcomb_dec; }
        }
        if (all) d = "8 rows (S+K-1)*2^256/(h_K+1); S=0 row == estimate";
        check(all, "2 combined (S+K-1)*D'_K exact vector", d);
    }

    // -- Case 3: censoring-corrected receipts-only ---------------------
    {
        bool all = true; std::string d;
        for (const auto& r : gv::CENSORING) {
            u256 hK = u256_from_hex(r.h_K_hex);
            u256 hT = u256_from_hex(r.h_T_hex);
            auto got = estimate_censoring_corrected(r.K, hK, hT);
            std::string gs = got ? got->to_dec() : std::string("<none>");
            if (gs != r.corrected_dec) { all = false; d += " K=" + std::to_string(r.K) +
                " got=" + gs + " want=" + r.corrected_dec; }
        }
        if (all) d = "5 rows (K-1)*2^256/(h_K+1-h_T), receipts-only truncation fix";
        check(all, "3 censoring-corrected exact vector", d);
    }

    // -- Case 4: unbiasedness Monte-Carlo ------------------------------
    // Reproduces the ANALYTIC prediction the proto goldens confirm (mc_estimator
    // exp_A / sim E1): E[Hhat]/H -> 1 within Monte-Carlo SE for every K>=3.
    {
        const std::uint32_t H = 4096;
        const int trials = 2000;
        const std::uint32_t Ks[] = {3u, 4u, 8u, 16u};
        std::string d; bool all = true;
        std::vector<std::vector<double>> ratios(4);
        SplitMix64 rng(0xA5A5A500u + H);
        std::vector<u256> hs; hs.reserve(H);
        for (int t = 0; t < trials; ++t) {
            hs.clear();
            for (std::uint32_t i = 0; i < H; ++i) hs.push_back(rng.hash());
            std::sort(hs.begin(), hs.end());  // one sort feeds every K
            for (int ki = 0; ki < 4; ++ki) {
                std::uint32_t K = Ks[ki];
                double r = u320_to_double(estimate_hashes(K, hs[K - 1])) / (double)H;
                ratios[static_cast<std::size_t>(ki)].push_back(r);
            }
        }
        for (int ki = 0; ki < 4; ++ki) {
            const auto& rs = ratios[static_cast<std::size_t>(ki)];
            double mean = 0.0; for (double r : rs) mean += r; mean /= rs.size();
            double var = 0.0; for (double r : rs) var += (r - mean) * (r - mean);
            var /= (rs.size() - 1);
            double se = std::sqrt(var / rs.size());
            // K>=3 unbiased: |mean-1| must be within 4 SE (very loose, robust).
            bool ok = std::fabs(mean - 1.0) <= 4.0 * se + 0.01;
            all = all && ok;
            char buf[128];
            std::snprintf(buf, sizeof buf, " K=%u mean/H=%.4f(se %.4f)", Ks[ki], mean, se);
            d += buf;
        }
        check(all, "4 unbiasedness MC  E[Hhat]/H->1", d);
    }

    // -- Case 5: sybil-neutrality (broken clamp REJECTED) --------------
    // Reproduces sim E5b: one miner H=20*T split into n identities. The broken
    // clamp max(S*T,est) inflates toward ~1.98x; the sybil-neutral COMBINED and
    // the consensus EST_ONLY path stay <= ~1.02x. clamp is NOT the active rule.
    {
        const std::uint64_t Tdiff = 4096;              // work per share, in hashes
        const u256 hT = [&]{ u256 t; t.w[3] = 0; // h_T = 2^256 / Tdiff  (approx)
            // 2^256 / 4096 = 2^244  -> bit 244 set (limb3 bit52)
            t.w[3] = (1ULL << (244 - 192)); return t; }();
        const std::uint64_t Hbig = 20 * Tdiff;         // 81920
        const std::uint32_t K = 4;
        std::string d; bool ok = true; double clamp_2000 = 0, comb_2000 = 0;
        for (std::uint64_t n : {1ull, 20ull, 2000ull}) {
            std::uint64_t h = Hbig / n;
            int tr = (int)std::min<std::uint64_t>(200, std::max<std::uint64_t>(30, 3000 / n));
            double clamp = 0, comb = 0, est_only = 0;
            for (int t = 0; t < tr; ++t) {
                double c = 0, cm = 0, eo = 0;
                for (std::uint64_t id = 0; id < n; ++id) {
                    SplitMix64 rng(0xC0FFEEull + n * 1315423911ull + (std::uint64_t)t * 2654435761ull + id);
                    std::vector<u256> band; std::uint64_t S = 0;
                    for (std::uint64_t i = 0; i < h; ++i) {
                        u256 hv = rng.hash();
                        if (!(hT < hv)) ++S; else band.push_back(hv);
                    }
                    if (band.size() < K) continue;
                    u256 hK = kth_smallest(band, K);
                    double est = u320_to_double(estimate_hashes(K, hK));
                    double clv = u320_to_double(broken_clamp_NEVER_CONSENSUS(S, K, hK, hT));
                    double cov = u320_to_double(estimate_combined(S, K, hK));
                    c += clv; cm += cov; eo += est;
                }
                clamp += c; comb += cm; est_only += eo;
            }
            double denom = (double)tr * (double)Hbig;
            double cr = clamp / denom, cor = comb / denom;
            char buf[160];
            std::snprintf(buf, sizeof buf, " n=%llu clamp=%.3f comb=%.3f",
                          (unsigned long long)n, cr, cor);
            d += buf;
            if (n == 2000) { clamp_2000 = cr; comb_2000 = cor; }
        }
        // The broken clamp must be visibly inflated (>1.3x) at the 2000-split and
        // strictly worse than COMBINED; COMBINED must stay near-neutral (<=1.05).
        ok = (clamp_2000 > 1.3) && (comb_2000 <= 1.05) && (clamp_2000 > comb_2000);
        d += ok ? "  => clamp REJECTED, comb neutral" : "  => UNEXPECTED";
        check(ok, "5 sybil-neutrality (clamp rejected)", d);
    }

    // -- Case 6: no-double-count ---------------------------------------
    // EstimateOnly: a worker whose shares account for its work (S>0) gets NO
    // estimator credit; a worker that never meets the target (S=0) is credited.
    {
        SubthresholdParams p; p.enabled = true; p.K = 8; p.mode = CreditMode::EstimateOnly;
        u256 hT; hT.w[0] = 2;  // share iff hash <= 2
        // build a collector with S>0 (has shares) and K near-misses
        auto make = [&](std::uint64_t nshares) {
            ReceiptCollector rc(p.K, hT);
            for (std::uint64_t i = 0; i < nshares; ++i) { u256 s; s.w[0] = 1; rc.observe(s); }
            u256 base = u256_from_hex(gv::ESTIMATE[2].h_K_hex);  // hk_of(8)
            for (std::uint32_t j = 0; j < p.K; ++j) {
                u256 v = base; v.w[0] -= (p.K - 1 - j);  // ascending, K-th == base
                rc.observe(v);
            }
            return rc;
        };
        std::map<DedupKey, bool> seen1, seen2;
        DedupKey ka{}; ka.payee.fill(0xA0); ka.seq = 1;
        DedupKey kb{}; kb.payee.fill(0xB0); kb.seq = 1;
        auto rcA = make(5);   // S=5 shares -> accounted by shares
        auto rcB = make(0);   // S=0 -> credited estimate
        auto dA = apply_credit(p, ka, rcA, seen1);
        auto dB = apply_credit(p, kb, rcB, seen2);
        bool ok = dA.empty() && !dB.empty();
        std::string d = "S>0 delta_keys=" + std::to_string(dA.size()) +
                        " ; S=0 delta_keys=" + std::to_string(dB.size());
        if (!dB.empty()) d += " credit=" + std::to_string(dB.begin()->second);
        check(ok, "6 no-double-count (shares vs estimate)", d);
    }

    // -- Case 7: interval-straddle dedup -------------------------------
    // (a) exact straddle ratio 1+(K-1)/(2K-1) matches golden; (b) dedup per
    // (payee, seq): a replayed stream yields the estimate at most ONCE.
    {
        bool ratio_ok = true; std::string d;
        for (const auto& r : gv::STRADDLE) {
            std::uint64_t num = (2ull * r.K - 1) + (r.K - 1), den = 2ull * r.K - 1;
            if (num != r.num || den != r.den) ratio_ok = false;
        }
        SubthresholdParams p; p.enabled = true; p.K = 4; p.mode = CreditMode::EstimateOnly;
        u256 hT; hT.w[0] = 2;
        ReceiptCollector rc(p.K, hT);
        u256 base = u256_from_hex(gv::ESTIMATE[1].h_K_hex);  // hk_of(4)
        for (std::uint32_t j = 0; j < p.K; ++j) { u256 v = base; v.w[0] -= (p.K - 1 - j); rc.observe(v); }
        std::map<DedupKey, bool> seen;
        DedupKey k{}; k.payee.fill(0xCC); k.seq = 42;
        auto first = apply_credit(p, k, rc, seen);    // credited
        auto second = apply_credit(p, k, rc, seen);   // SAME (payee,seq) -> deduped
        bool dedup_ok = !first.empty() && second.empty();
        d = "ratio 1+(K-1)/(2K-1) golden ok=" + std::string(ratio_ok ? "y" : "n") +
            " ; replay(payee,seq) first=" + std::to_string(first.size()) +
            " second=" + std::to_string(second.size());
        check(ratio_ok && dedup_ok, "7 interval-straddle dedup", d);
    }

    // -- Case 8: K>=3 guard --------------------------------------------
    {
        u256 hK = u256_from_hex(gv::ESTIMATE[0].h_K_hex);
        bool guard_ok = !k_guard_ok(2) && k_guard_ok(3) &&
                        estimate_hashes(2, hK).is_zero();
        // apply_credit with K=2 must also emit nothing even when enabled.
        SubthresholdParams p; p.enabled = true; p.K = 2; p.mode = CreditMode::EstimateOnly;
        u256 hT; hT.w[0] = 2; ReceiptCollector rc(2, hT);
        u256 base = hK; for (int j = 0; j < 2; ++j) { u256 v = base; v.w[0] -= (1 - j); rc.observe(v); }
        std::map<DedupKey, bool> seen; DedupKey k{}; k.seq = 1;
        bool credit_empty = apply_credit(p, k, rc, seen).empty();
        check(guard_ok && credit_empty, "8 K>=3 guard (K=2 rejected)",
              "estimate(K=2)=0 ; apply_credit(K=2) empty");
    }

    // -- Case 9: ★ PRIME gate-off byte-identity ------------------------
    {
        std::array<std::uint8_t, 32> A{}, B{}; A.fill(0xA0); B.fill(0xB0);
        std::map<std::array<std::uint8_t, 32>, long long> baseW = {{A, 1000000}, {B, 0}};
        std::map<std::array<std::uint8_t, 32>, std::uint64_t> fe = {{A, 7}, {B, 0}};
        std::string baseline = hex_of(owed_digest(baseW, fe));

        // Build a S=0 collector for payee B, K=8, h_K = hk_of(8).
        SubthresholdParams p; p.K = 8; p.mode = CreditMode::EstimateOnly;
        u256 hT; hT.w[0] = 2; ReceiptCollector rc(8, hT);
        u256 base = u256_from_hex(gv::ESTIMATE[2].h_K_hex);
        for (std::uint32_t j = 0; j < 8; ++j) { u256 v = base; v.w[0] -= (7 - j); rc.observe(v); }
        DedupKey kb{}; kb.payee = B; kb.seq = 1;

        // GATE OFF: apply_credit returns {} -> ledger unchanged -> digest identical.
        p.enabled = false;
        std::map<DedupKey, bool> seenOff;
        auto deltaOff = apply_credit(p, kb, rc, seenOff);
        auto Woff = baseW;
        for (auto& [k, v] : deltaOff) Woff[k] += v;
        std::string offDigest = hex_of(owed_digest(Woff, fe));

        // GATE ON: credit enters -> digest changes.
        p.enabled = true;
        std::map<DedupKey, bool> seenOn;
        auto deltaOn = apply_credit(p, kb, rc, seenOn);
        auto Won = baseW;
        for (auto& [k, v] : deltaOn) Won[k] += v;
        std::string onDigest = hex_of(owed_digest(Won, fe));

        bool off_identical = (offDigest == baseline) &&
                             (offDigest == gv::OWED_DIGEST_GATE_OFF_HEX) &&
                             deltaOff.empty();
        bool on_changes = (onDigest != baseline) &&
                          (onDigest == gv::OWED_DIGEST_GATE_ON_HEX) &&
                          !deltaOn.empty();
        std::string credit = deltaOn.empty() ? "0" : std::to_string(deltaOn.begin()->second);
        std::string d = "off==master==golden(" + std::string(off_identical ? "y" : "n") +
                        ") ; on!=master, credit=" + credit +
                        " (" + std::string(on_changes ? "y" : "n") + ")";
        check(off_identical && on_changes, "9 PRIME gate-off byte-identical digest", d);
    }

    // -- Case 10: golden stamp + NEGATIVE CONTROL ----------------------
    {
        // Read the frozen golden JSON, hash it, compare to the embedded STAMP.
        std::ifstream f(gv::JSON_FILE, std::ios::binary);
        std::string ok_detail;
        bool present = f.good();
        std::vector<std::uint8_t> bytes;
        if (present) {
            std::ostringstream ss; ss << f.rdbuf();
            std::string s = ss.str();
            bytes.assign(s.begin(), s.end());
        }
        if (neg && !bytes.empty()) bytes[bytes.size() / 2] ^= 0x01;  // corrupt 1 byte
        std::array<std::uint8_t, 32> h;
        detail::sha256(bytes, h);
        std::string got = hex_of(h);
        bool stamp_match = present && (got == gv::STAMP);
        if (!neg) {
            check(stamp_match, "10 golden stamp verification",
                  present ? ("sha256==STAMP " + std::string(stamp_match ? "y" : "n"))
                          : "golden JSON not found next to binary");
        } else {
            // NEGATIVE CONTROL: with one byte flipped the stamp MUST NOT match,
            // i.e. the KAT correctly goes red on a corrupted golden.
            bool detected = present && (got != gv::STAMP);
            check(detected, "10 NEGATIVE CONTROL (corrupt byte -> red)",
                  detected ? "flipped 1 byte -> stamp mismatch DETECTED (KAT would fail)"
                           : "corruption NOT detected -- golden check is hollow");
        }
    }

    // -- Case 11: ★ PRIME gate-off receipt/share-digest byte-identity --------
    // The K-best sub-threshold receipts are an ADD-ONLY, gated trailer ("V37D").
    // GATE OFF => the trailer is 0 bytes, so the committed receipt/share body is
    // byte-identical to master and its digest is unchanged. GATE ON => the
    // trailer is appended and the digest differs. This is the receipt-digest
    // analogue of case 9's owed_digest proof; together they cover both consensus
    // commitments the PRIME invariant names.
    {
        std::vector<std::uint8_t> body(64);
        for (std::size_t i = 0; i < body.size(); ++i) body[i] = (std::uint8_t)(i * 7 + 1);
        // one harvested UNCOVERED interval, K=4, K best hashes from ESTIMATE[1].
        HarvestedInterval hi; hi.payee.fill(0xCC); hi.interval = 42;
        u256 base = u256_from_hex(gv::ESTIMATE[1].h_K_hex);
        for (std::uint32_t j = 0; j < 4; ++j) { u256 v = base; v.w[0] -= (3 - j); hi.best.push_back(v); }
        std::vector<HarvestedInterval> rows{hi};

        SubthresholdParams p; p.K = 4;
        std::string masterDig = hex_of(detail::sha256d(body));

        p.enabled = false;
        auto offCarrier = serialize_receipt_carrier(p, rows);
        std::string offDig = hex_of(receipt_body_digest(p, body, rows));

        p.enabled = true;
        auto onCarrier = serialize_receipt_carrier(p, rows);
        std::string onDig = hex_of(receipt_body_digest(p, body, rows));

        bool ok = offCarrier.empty() && (offDig == masterDig) &&
                  !onCarrier.empty() && (onDig != masterDig);
        std::string d = "off carrier_bytes=" + std::to_string(offCarrier.size()) +
                        " off==master(" + std::string(offDig == masterDig ? "y" : "n") +
                        ") ; on carrier_bytes=" + std::to_string(onCarrier.size()) +
                        " on!=master(" + std::string(onDig != masterDig ? "y" : "n") + ")";
        check(ok, "11 PRIME gate-off receipt-digest byte-identical", d);
    }

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
