// ============================================================================
// v37_w4_estimator_wiring_test — RDWR-OQ2 activation KAT.
//
// Proves the sub-threshold estimator (src/c2pool/v37/v37_subthreshold_estimator
// .hpp, merged) wired into the REAL W4 OwedLedger credit/fold path
// (src/c2pool/v37/w4_settlement.hpp) behind the ::v37::LaneParams::subthreshold
// gate. It does NOT re-implement any estimator maths — it calls the seam
// (OwedLedger::on_block_found_with_estimator / subthreshold_credit) which calls
// the module's apply_credit(), the module's ONLY receipts->credit entry point.
//
// Stdlib-only, no gtest / no Boost / no core link — the same self-harness shape
// as the sibling v37 suites; returns nonzero on any failure.
//
// HOLLOW-GREEN GUARD: this target MUST be listed in the build.yml `cmake --build
// --target` allowlist for BOTH legs (Linux x86_64 + ASan/UBSan) and registered
// in src/c2pool/v37/test/CMakeLists.txt, else CTest reports it NOT_BUILT and the
// run silently passes (the DGB #137 / #769 / PR #1467 unregistered-KAT class).
// The frozen golden JSON is copied next to the binary (WORKING_DIRECTORY) so the
// stamp case reads it in-CI regardless of cwd.
//
// Cases:
//   1  ★ PRIME  gate-OFF owed_digest BYTE-IDENTICAL to the master-style plain
//               on_block_found path on the SAME schedule (and == pinned golden)
//   2  ★ PRIME  lane digest is IDENTICAL with the gate OFF vs ON (the LaneParams
//               gate field is not part of the digested geometry) (== golden)
//   3  ★ PRIME  gate-OFF receipt/share carrier is 0 bytes; digest == master body
//   4  gate-ON   the uncovered (S==0, J>=K) worker's corrected estimate is
//               credited; owed_digest changes (== pinned gate-ON golden)
//   5  no-double-count: a share-covered (S>0) worker keeps ONLY its E_b
//   6  sybil-neutral survives the wiring: 2000-identity split routed through the
//               seam stays neutral; the broken clamp is rejected
//   7  unbiasedness survives the wiring: E[credit]/H -> 1 (EstimateOnly, S==0)
//   8  golden stamp verification + NEGATIVE CONTROL (corrupt 1 byte -> red)
// ============================================================================
#include <c2pool/v37/w4_settlement.hpp>
#include <sharechain/v37/v37_lane.hpp>
#include "w4_estimator_wiring_golden_v1.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using ::v37::bytes32;
using ::v37::LaneParams;
using ::v37::Lane;
using ::v37::MinerId;
namespace S = c2pool::v37n::settle;
namespace sub = c2pool::v37::subthreshold;
namespace wg = c2pool::v37n::settle::wiring_golden;

// ------------------------------------------------------------- tiny harness
static int g_pass = 0, g_fail = 0;
static void check(bool ok, const char* name, const std::string& detail) {
    std::printf("  [%s] %-52s %s\n", ok ? "PASS" : "FAIL", name, detail.c_str());
    if (ok) ++g_pass; else ++g_fail;
}

static std::string hex_of(const std::array<std::uint8_t, 32>& d) {  // bytes32 == this
    static const char* H = "0123456789abcdef";
    std::string s;
    for (auto c : d) { s.push_back(H[c >> 4]); s.push_back(H[c & 15]); }
    return s;
}

static sub::u256 u256_from_hex(const char* hex) {  // 64 hex chars, big-endian
    std::array<std::uint8_t, 32> b{};
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    for (int i = 0; i < 32; ++i)
        b[(std::size_t)i] = (std::uint8_t)((nib(hex[i * 2]) << 4) | nib(hex[i * 2 + 1]));
    return sub::u256::from_be_bytes(b);
}

// deterministic, portable PRNG (splitmix64) — matches the module KAT's bands.
struct SplitMix64 {
    std::uint64_t s;
    explicit SplitMix64(std::uint64_t seed) : s(seed) {}
    std::uint64_t next() {
        std::uint64_t z = (s += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }
    sub::u256 hash() {
        sub::u256 r;
        for (int i = 0; i < 4; ++i) r.w[(std::size_t)i] = next();
        return r;
    }
};
static double u320_to_double(const sub::u320& x) {
    double v = 0.0;
    for (int i = 4; i >= 0; --i)
        v = v * 18446744073709551616.0 + (double)x.w[(std::size_t)i];
    return v;
}
static sub::u256 kth_smallest(std::vector<sub::u256>& hs, std::uint32_t K) {
    std::sort(hs.begin(), hs.end());
    return hs[K - 1];
}

static bytes32 keyfill(std::uint8_t v) { bytes32 k; k.fill(v); return k; }

// hk_of(8) from the merged module's canonical golden (Hhat low-63 == 874999).
static const char* HK8_HEX =
    "00008637bd05af6c69b5a63f9a49c2c1b10fd7e45803cd141a6937d1fe64f54d";

// Build the S=0, K-best (K=8) collector for the UNCOVERED worker: near-misses
// whose K-th smallest == hk_of(8), no shares. h_T small so every fed hash is a
// near-miss (hash > h_T).
static sub::ReceiptCollector uncovered_collector(std::uint32_t K) {
    sub::u256 hT; hT.w[0] = 2;                       // share iff hash <= 2
    sub::ReceiptCollector rc(K, hT);
    sub::u256 base = u256_from_hex(HK8_HEX);
    for (std::uint32_t j = 0; j < K; ++j) {
        sub::u256 v = base; v.w[0] -= (K - 1 - j);   // ascending; K-th == base
        rc.observe(v);
    }
    return rc;
}
// Build a covered worker: S shares + K near-misses (EstimateOnly => no credit).
static sub::ReceiptCollector covered_collector(std::uint32_t K, std::uint64_t Sshares) {
    sub::u256 hT; hT.w[0] = 2;
    sub::ReceiptCollector rc(K, hT);
    for (std::uint64_t i = 0; i < Sshares; ++i) { sub::u256 s; s.w[0] = 1; rc.observe(s); }
    sub::u256 base = u256_from_hex(HK8_HEX);
    for (std::uint32_t j = 0; j < K; ++j) { sub::u256 v = base; v.w[0] -= (K - 1 - j); rc.observe(v); }
    return rc;
}

// The fixed schedule (cases 1/4/5). Two payees carry base entitlement E_b; two
// harvested intervals present near-miss receipts (one uncovered, one covered).
// `params` gate decides whether the estimator credit enters. Returns the
// finalized OwedLedger owed_digest.
struct ScheduleOut { bytes32 owed; long long finalW_A, finalW_B, finalW_C; };
static ScheduleOut run_schedule_wired(const LaneParams& params) {
    S::OwedLedger ledger(/*chain=*/7);
    bytes32 A = keyfill(0xA1), B = keyfill(0xB2), C = keyfill(0xC3);
    // E_b: A and B earned by shares; C earned nothing on-chain (uncovered).
    S::OwedLedger::Amounts base_credit = {{A, 1000000}, {B, 500000}};
    S::OwedLedger::Amounts payout = {};  // no coinbase draw in this schedule
    // Harvested (buried, F1 monotone interval bins): C uncovered (S=0), A covered
    // (S=5 shares) — A must NOT be re-credited under EstimateOnly.
    std::vector<S::HarvestedReceipt> harvested;
    harvested.push_back(S::HarvestedReceipt{C, /*interval=*/100, uncovered_collector(params.subthreshold.K)});
    harvested.push_back(S::HarvestedReceipt{A, /*interval=*/100, covered_collector(params.subthreshold.K, 5)});
    ledger.on_block_found_with_estimator("blk1", base_credit, payout, params, harvested);
    ledger.on_block_finalized("blk1", /*bin_height=*/100);
    ScheduleOut o;
    o.owed = ledger.owed_digest();
    o.finalW_A = ledger.effective_owed(A);
    o.finalW_B = ledger.effective_owed(B);
    o.finalW_C = ledger.effective_owed(C);
    return o;
}
// Master-style: identical schedule via the PLAIN on_block_found (no estimator).
static bytes32 run_schedule_master_style() {
    S::OwedLedger ledger(/*chain=*/7);
    bytes32 A = keyfill(0xA1), B = keyfill(0xB2);
    S::OwedLedger::Amounts base_credit = {{A, 1000000}, {B, 500000}};
    S::OwedLedger::Amounts payout = {};
    ledger.on_block_found("blk1", base_credit, payout);
    ledger.on_block_finalized("blk1", 100);
    return ledger.owed_digest();
}

// A fixed lane push schedule; digest computed with the caller's LaneParams.
static bytes32 lane_digest(const LaneParams& p) {
    auto id_key = [](MinerId m) -> bytes32 {
        std::uint8_t b[4] = {(std::uint8_t)m, (std::uint8_t)(m >> 8),
                             (std::uint8_t)(m >> 16), (std::uint8_t)(m >> 24)};
        return ::v37::sha256d(b, 4);
    };
    Lane lane(p);
    SplitMix64 rng(0x5CEDUL);
    for (int i = 0; i < 300; ++i)
        lane.push((MinerId)(rng.next() % 7), 1 + (rng.next() % 1000000), 0);
    return lane.digest(id_key);
}

// =====================================================================
int main(int argc, char** argv) {
    bool neg = (argc > 1 && std::strcmp(argv[1], "--neg") == 0);
    bool emit = (argc > 1 && std::strcmp(argv[1], "--emit") == 0);
    std::printf("v37_w4_estimator_wiring_test  (golden stamp %s)\n", wg::STAMP);

    LaneParams pOff;                       // subthreshold.enabled == false (default)
    LaneParams pOn = pOff;
    pOn.subthreshold.enabled = true;
    pOn.subthreshold.K = 8;                // uncovered_collector uses K-best K=8
    pOn.subthreshold.mode = 0;             // EstimateOnly
    pOn.subthreshold.version = 1;          // V37.1 estimator-on
    LaneParams pOffK8 = pOff; pOffK8.subthreshold.K = 8;  // OFF path also uses K=8 collector

    // --emit mode: print the digests for cross-checkout capture / golden pinning.
    if (emit) {
        ScheduleOut off = run_schedule_wired(pOffK8);
        ScheduleOut on = run_schedule_wired(pOn);
        std::printf("EMIT OWED_OFF=%s\n", hex_of(off.owed).c_str());
        std::printf("EMIT OWED_ON=%s\n", hex_of(on.owed).c_str());
        std::printf("EMIT MASTER_STYLE=%s\n", hex_of(run_schedule_master_style()).c_str());
        std::printf("EMIT LANE_OFF=%s\n", hex_of(lane_digest(pOffK8)).c_str());
        std::printf("EMIT LANE_ON=%s\n", hex_of(lane_digest(pOn)).c_str());
        std::printf("EMIT UNCOVERED_CREDIT=%lld\n", on.finalW_C);
        return 0;
    }

    // -- Case 1: PRIME gate-OFF owed_digest byte-identity ----------------
    {
        ScheduleOut off = run_schedule_wired(pOffK8);
        std::string offh = hex_of(off.owed);
        std::string masterh = hex_of(run_schedule_master_style());
        bool eq_master = (offh == masterh);
        bool eq_golden = (offh == std::string(wg::OWED_DIGEST_GATE_OFF_HEX));
        // gate OFF must credit nothing: A/B keep E_b, C absent.
        bool no_credit = (off.finalW_A == 1000000) && (off.finalW_B == 500000) &&
                         (off.finalW_C == 0);
        bool ok = eq_master && eq_golden && no_credit;
        check(ok, "1 PRIME gate-OFF owed_digest byte-identical",
              "wired-OFF==master-style(" + std::string(eq_master ? "y" : "n") +
              ") ==golden(" + std::string(eq_golden ? "y" : "n") +
              ") no-credit(" + std::string(no_credit ? "y" : "n") + ")");
    }

    // -- Case 2: PRIME lane digest gate-neutrality ----------------------
    {
        std::string dOff = hex_of(lane_digest(pOffK8));
        std::string dOn = hex_of(lane_digest(pOn));
        // Also a wildly different gate config must not move the digest.
        LaneParams pWild = pOff; pWild.subthreshold.enabled = true;
        pWild.subthreshold.K = 32; pWild.subthreshold.mode = 1; pWild.subthreshold.version = 9;
        std::string dWild = hex_of(lane_digest(pWild));
        bool ok = (dOff == dOn) && (dOff == dWild) &&
                  (dOff == std::string(wg::LANE_DIGEST_HEX));
        check(ok, "2 PRIME lane digest gate-neutral (== golden)",
              "off==on(" + std::string(dOff == dOn ? "y" : "n") +
              ") ==wild(" + std::string(dOff == dWild ? "y" : "n") +
              ") ==golden(" + std::string(dOff == std::string(wg::LANE_DIGEST_HEX) ? "y" : "n") + ")");
    }

    // -- Case 3: PRIME gate-OFF receipt/share carrier 0 bytes -----------
    {
        std::vector<std::uint8_t> body(64);
        for (std::size_t i = 0; i < body.size(); ++i) body[i] = (std::uint8_t)(i * 7 + 1);
        sub::HarvestedInterval hi; hi.payee.fill(0xCC); hi.interval = 100;
        sub::u256 base = u256_from_hex(HK8_HEX);
        for (std::uint32_t j = 0; j < 8; ++j) { sub::u256 v = base; v.w[0] -= (7 - j); hi.best.push_back(v); }
        std::vector<sub::HarvestedInterval> rows{hi};
        sub::SubthresholdParams spOff = S::to_subthreshold_params(pOffK8);
        sub::SubthresholdParams spOn = S::to_subthreshold_params(pOn);
        auto offCarrier = sub::serialize_receipt_carrier(spOff, rows);
        auto onCarrier = sub::serialize_receipt_carrier(spOn, rows);
        std::string masterDig = hex_of(sub::detail::sha256d(body));
        std::string offDig = hex_of(sub::receipt_body_digest(spOff, body, rows));
        std::string onDig = hex_of(sub::receipt_body_digest(spOn, body, rows));
        bool ok = offCarrier.empty() && (offDig == masterDig) &&
                  !onCarrier.empty() && (onDig != masterDig);
        check(ok, "3 PRIME gate-OFF receipt carrier 0 bytes",
              "off_bytes=" + std::to_string(offCarrier.size()) +
              " off==master(" + std::string(offDig == masterDig ? "y" : "n") +
              ") on_bytes=" + std::to_string(onCarrier.size()) +
              " on!=master(" + std::string(onDig != masterDig ? "y" : "n") + ")");
    }

    // -- Case 4: gate-ON credits the uncovered worker -------------------
    {
        ScheduleOut on = run_schedule_wired(pOn);
        ScheduleOut off = run_schedule_wired(pOffK8);
        std::string onh = hex_of(on.owed);
        bool changed = (onh != hex_of(off.owed));
        bool eq_golden = (onh == std::string(wg::OWED_DIGEST_GATE_ON_HEX));
        bool credited = (on.finalW_C == std::atoll(wg::UNCOVERED_CREDIT_LOW63_DEC));
        bool ok = changed && eq_golden && credited;
        check(ok, "4 gate-ON credits uncovered (owed_digest changes)",
              "owed changed(" + std::string(changed ? "y" : "n") +
              ") ==golden(" + std::string(eq_golden ? "y" : "n") +
              ") C_credit=" + std::to_string(on.finalW_C));
    }

    // -- Case 5: no-double-count (share-covered worker) -----------------
    {
        ScheduleOut on = run_schedule_wired(pOn);
        // A is covered (S=5 shares) AND appears in a harvested interval; under
        // EstimateOnly it must keep ONLY its E_b (1000000), never the estimate.
        bool a_only_Eb = (on.finalW_A == 1000000);
        // B has no harvested receipt at all -> untouched.
        bool b_untouched = (on.finalW_B == 500000);
        // C (uncovered, S=0) IS credited -> the estimator is actually active.
        bool c_credited = (on.finalW_C > 0);
        bool ok = a_only_Eb && b_untouched && c_credited;
        check(ok, "5 no-double-count (covered worker keeps E_b only)",
              "A=" + std::to_string(on.finalW_A) + "(E_b only " +
              std::string(a_only_Eb ? "y" : "n") + ") B=" + std::to_string(on.finalW_B) +
              " C=" + std::to_string(on.finalW_C) + "(credited " +
              std::string(c_credited ? "y" : "n") + ")");
    }

    // -- Case 6: sybil-neutrality survives the wiring -------------------
    // Reproduces the module KAT's sim E5b but routes EVERY estimate through the
    // W4 seam subthreshold_credit(). One miner H=20*T split into n identities;
    // the broken clamp inflates (>1.3x @ 2000-split) while the sybil-neutral
    // Combined path stays neutral. clamp is NOT reachable through the seam.
    {
        const std::uint64_t Tdiff = 4096;
        sub::u256 hT; hT.w[3] = (1ULL << (244 - 192));  // h_T = 2^244 (approx 2^256/4096)
        const std::uint64_t Hbig = 20 * Tdiff;          // 81920
        const std::uint32_t K = 4;
        std::string d; double clamp_2000 = 0, comb_2000 = 0;
        for (std::uint64_t n : {1ull, 20ull, 2000ull}) {
            std::uint64_t h = Hbig / n;
            int tr = (int)std::min<std::uint64_t>(200, std::max<std::uint64_t>(30, 3000 / n));
            double clamp = 0, comb = 0;
            for (int t = 0; t < tr; ++t) {
                double c = 0, cm = 0;
                for (std::uint64_t id = 0; id < n; ++id) {
                    SplitMix64 rng(0xC0FFEEull + n * 1315423911ull + (std::uint64_t)t * 2654435761ull + id);
                    sub::ReceiptCollector rc(K, hT);
                    std::vector<sub::u256> band; std::uint64_t Sc = 0;
                    for (std::uint64_t i = 0; i < h; ++i) {
                        sub::u256 hv = rng.hash();
                        rc.observe(hv);
                        if (!(hT < hv)) ++Sc; else band.push_back(hv);
                    }
                    if (band.size() < K) continue;
                    sub::u256 hK = kth_smallest(band, K);
                    // clamp: the broken reference (never reachable via the seam).
                    c += u320_to_double(sub::broken_clamp_NEVER_CONSENSUS(Sc, K, hK, hT));
                    // comb: the ACTUAL wiring, Combined mode, via subthreshold_credit.
                    LaneParams pc; pc.subthreshold.enabled = true; pc.subthreshold.K = K;
                    pc.subthreshold.mode = 1;  // Combined (sybil-neutral)
                    bytes32 payee = keyfill((std::uint8_t)(0x10 + id));
                    std::vector<S::HarvestedReceipt> hv1;
                    hv1.push_back(S::HarvestedReceipt{payee, /*interval=*/(std::uint64_t)id, rc});
                    auto credit = S::subthreshold_credit(pc, hv1);
                    for (auto& [k, v] : credit) { (void)k; cm += (double)v; }
                }
                clamp += c; comb += cm;
            }
            double denom = (double)tr * (double)Hbig;
            double cr = clamp / denom, cor = comb / denom;
            char buf[160];
            std::snprintf(buf, sizeof buf, " n=%llu clamp=%.3f comb=%.3f",
                          (unsigned long long)n, cr, cor);
            d += buf;
            if (n == 2000) { clamp_2000 = cr; comb_2000 = cor; }
        }
        bool ok = (clamp_2000 > 1.3) && (comb_2000 <= 1.05) && (clamp_2000 > comb_2000);
        d += ok ? "  => seam sybil-neutral, clamp rejected" : "  => UNEXPECTED";
        check(ok, "6 sybil-neutral via seam (clamp rejected)", d);
    }

    // -- Case 7: unbiasedness survives the wiring -----------------------
    // EstimateOnly, S==0: route the estimate through the seam and confirm
    // E[credit]/H -> 1 within Monte-Carlo SE for every K>=3 (module sim E1 shape).
    {
        const std::uint32_t H = 4096;
        const int trials = 1500;
        const std::uint32_t Ks[] = {3u, 4u, 8u, 16u};
        std::string d; bool all = true;
        sub::u256 hT; hT.w[0] = 0;  // h_T = 0 => every hash is a near-miss (S==0)
        std::vector<std::vector<double>> ratios(4);
        SplitMix64 rng(0xA5A5A500u + H);
        for (int t = 0; t < trials; ++t) {
            std::vector<sub::u256> hs; hs.reserve(H);
            for (std::uint32_t i = 0; i < H; ++i) hs.push_back(rng.hash());
            for (int ki = 0; ki < 4; ++ki) {
                std::uint32_t K = Ks[ki];
                sub::ReceiptCollector rc(K, hT);
                for (const auto& hh : hs) rc.observe(hh);
                LaneParams pk; pk.subthreshold.enabled = true; pk.subthreshold.K = K;
                pk.subthreshold.mode = 0;  // EstimateOnly
                bytes32 payee = keyfill((std::uint8_t)(0x40 + ki));
                std::vector<S::HarvestedReceipt> hv;
                hv.push_back(S::HarvestedReceipt{payee, (std::uint64_t)t, rc});
                auto credit = S::subthreshold_credit(pk, hv);
                double amt = credit.empty() ? 0.0 : (double)credit.begin()->second;
                ratios[(std::size_t)ki].push_back(amt / (double)H);
            }
        }
        for (int ki = 0; ki < 4; ++ki) {
            const auto& rs = ratios[(std::size_t)ki];
            double mean = 0.0; for (double r : rs) mean += r; mean /= rs.size();
            double var = 0.0; for (double r : rs) var += (r - mean) * (r - mean);
            var /= (rs.size() - 1);
            double se = std::sqrt(var / rs.size());
            bool ok = std::fabs(mean - 1.0) <= 4.0 * se + 0.01;
            all = all && ok;
            char buf[128];
            std::snprintf(buf, sizeof buf, " K=%u mean/H=%.4f(se %.4f)", Ks[ki], mean, se);
            d += buf;
        }
        check(all, "7 unbiasedness via seam  E[credit]/H->1", d);
    }

    // -- Case 8: golden stamp + NEGATIVE CONTROL ------------------------
    {
        std::ifstream f(wg::JSON_FILE, std::ios::binary);
        bool present = f.good();
        std::vector<std::uint8_t> bytes;
        if (present) {
            std::ostringstream ss; ss << f.rdbuf();
            std::string s = ss.str();
            bytes.assign(s.begin(), s.end());
        }
        if (neg && !bytes.empty()) bytes[bytes.size() / 2] ^= 0x01;
        std::array<std::uint8_t, 32> h;
        sub::detail::sha256(bytes, h);
        std::string got = hex_of(h);
        if (!neg) {
            bool stamp_match = present && (got == std::string(wg::STAMP));
            check(stamp_match, "8 golden stamp verification",
                  present ? ("sha256==STAMP " + std::string(stamp_match ? "y" : "n"))
                          : "golden JSON not found next to binary");
        } else {
            bool detected = present && (got != std::string(wg::STAMP));
            check(detected, "8 NEGATIVE CONTROL (corrupt byte -> red)",
                  detected ? "flipped 1 byte -> stamp mismatch DETECTED"
                           : "corruption NOT detected -- hollow");
        }
    }

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
