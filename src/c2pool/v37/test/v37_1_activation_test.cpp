// ============================================================================
// v37_1_activation_test — RDWR-OQ2 V37.1 CONSENSUS ACTIVATION KAT.
//
// The wiring landed in #1519 (v37_w4_estimator_wiring_test) proved the seam is
// SAFE with the gate OFF (the default): gate-OFF owed_digest / lane digest /
// receipt carrier are byte-identical to master. THIS KAT proves the ACTIVATION
// — the shipped default is now V37.1, which turns the gate ON under the
// E-2-corrected sybil-neutral COMBINED rule — is correct, deterministic, and
// non-destructive:
//
//   * the version marker is authoritative and add-only: LaneParams::v37_0() is
//     gate OFF and byte-identical to the bare default (the V37.0 base preserved
//     for replay/audit); LaneParams::v37_1() / LaneParams::shipped() is gate ON,
//     Combined, version==1; SHIPPED_CONSENSUS_VERSION == 1.
//   * the ACTIVE credit rule is the sybil-neutral combined estimator
//     Hhat_comb = (S + K - 1) * D'_K  (v37_subthreshold_estimator.hpp
//     estimate_combined), NEVER the broken clamp max(S*T, Hhat) — the clamp is
//     kept ONLY as the module's NEVER_CONSENSUS witness and is unreachable here.
//   * gate-OFF (V37.0) owed_digest == the UNCHANGED V37.0 golden (== master),
//     gate-ON (V37.1) owed_digest == the NEW pinned V37.1 golden, and the two
//     DIFFER (non-vacuous — activation actually moves the ledger).
//   * the lane digest is version-invariant (the gate is not digested geometry).
//   * sybil-neutrality survives the shipped Combined activation (2000-identity
//     split routed through the seam stays <= ~1.0x; the clamp inflates >1.3x and
//     is rejected).
//
// Stdlib-only self-harness (no gtest / Boost / core link) — the same shape as
// the sibling v37 suites; returns nonzero on any failure.
//
// HOLLOW-GREEN GUARD: this target MUST be listed in the build.yml `cmake --build
// --target` allowlist for BOTH legs (Linux x86_64 + ASan/UBSan) and registered
// in src/c2pool/v37/test/CMakeLists.txt, else CTest reports it NOT_BUILT and the
// run silently passes (the DGB #137 / #769 / PR #1467 unregistered-KAT class).
// The frozen golden JSON is copied next to the binary (WORKING_DIRECTORY) so the
// stamp case reads it in-CI regardless of cwd.
// ============================================================================
#include <c2pool/v37/w4_settlement.hpp>
#include <sharechain/v37/v37_lane.hpp>
#include "v371_activation_golden_v1.hpp"

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
using ::v37::SubthresholdGate;
using ::v37::SHIPPED_CONSENSUS_VERSION;
namespace S = c2pool::v37n::settle;
namespace sub = c2pool::v37::subthreshold;
namespace vg = c2pool::v37n::settle::v371_golden;

// ------------------------------------------------------------- tiny harness
static int g_pass = 0, g_fail = 0;
static void check(bool ok, const char* name, const std::string& detail) {
    std::printf("  [%s] %-54s %s\n", ok ? "PASS" : "FAIL", name, detail.c_str());
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

// The module's own low-63-bit fold of a bounded u320 estimate (mirrors
// apply_credit's fold) — used ONLY to independently predict the credit and to
// contrast estimate_combined vs the broken clamp. NOT a re-implementation of the
// crediting path: the ledger credit still flows through the real seam.
static long long low63(const sub::u320& est) {
    long long amt = 0;
    for (int i = 62; i >= 0; --i) amt = (amt << 1) | (est.bit(i) ? 1 : 0);
    return amt;
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

// A single deterministic near-miss K-th-smallest hash, shared by C and D so the
// two Combined credits differ ONLY through S (S+K-1): C has S=0, D has S=2, so
// D's credit is 5/3 of C's — a direct witness of the (S+K-1) coefficient.
static const char* HK_HEX =
    "00008637bd05af6c69b5a63f9a49c2c1b10fd7e45803cd141a6937d1fe64f54d";
static constexpr std::uint32_t V371_K = 4;  // == SubthresholdGate::for_version(1).K

// K=4 collector whose K-th smallest near-miss == HK_HEX, with `Sshares` shares.
// h_T tiny so every fed near-miss is above target; shares are hash w[0]==1 <= h_T.
static sub::ReceiptCollector make_collector(std::uint64_t Sshares) {
    sub::u256 hT; hT.w[0] = 3;                       // share iff hash <= 3 (h_T not
                                                     // a power of two: keeps S*T off
                                                     // a clean 2^n so the clamp folds
                                                     // to a real number in case 2)
    sub::ReceiptCollector rc(V371_K, hT);
    for (std::uint64_t i = 0; i < Sshares; ++i) { sub::u256 s; s.w[0] = 1; rc.observe(s); }
    sub::u256 base = u256_from_hex(HK_HEX);
    for (std::uint32_t j = 0; j < V371_K; ++j) {     // ascending; K-th == base
        sub::u256 v = base; v.w[0] -= (V371_K - 1 - j);
        rc.observe(v);
    }
    return rc;
}

// The fixed activation schedule. base_credit is the on-chain E_b of the MAIN
// window (A, B); the harvested near-miss receipts are BURIED, out-of-interval
// (F1 monotone bin) and belong to workers with NO E_b in this settle (C, D) — so
// the Combined estimate is their TOTAL sub-threshold credit with no E_b overlap
// (no double count). Gate OFF => C/D contribute nothing (byte-identical to
// master's {A,B}); gate ON (V37.1, Combined) => C and D are credited.
struct ScheduleOut { bytes32 owed; long long A, B, C, D; };
static ScheduleOut run_schedule(const LaneParams& params) {
    S::OwedLedger ledger(/*chain=*/7);
    bytes32 A = keyfill(0xA1), B = keyfill(0xB2), C = keyfill(0xC3), D = keyfill(0xD4);
    S::OwedLedger::Amounts base_credit = {{A, 1000000}, {B, 500000}};
    S::OwedLedger::Amounts payout = {};
    std::vector<S::HarvestedReceipt> harvested;
    harvested.push_back(S::HarvestedReceipt{C, /*interval=*/200, make_collector(0)});  // uncovered
    harvested.push_back(S::HarvestedReceipt{D, /*interval=*/201, make_collector(2)});  // S=2 buried
    ledger.on_block_found_with_estimator("blk1", base_credit, payout, params, harvested);
    ledger.on_block_finalized("blk1", /*bin_height=*/100);
    ScheduleOut o;
    o.owed = ledger.owed_digest();
    o.A = ledger.effective_owed(A);
    o.B = ledger.effective_owed(B);
    o.C = ledger.effective_owed(C);
    o.D = ledger.effective_owed(D);
    return o;
}
// Master-style baseline: the SAME {A,B} via the plain on_block_found (no gate).
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
    std::printf("v37_1_activation_test  (golden stamp %s)\n", vg::STAMP);

    const LaneParams v0 = LaneParams::v37_0();       // gate OFF (V37.0 base)
    const LaneParams v1 = LaneParams::v37_1();       // gate ON  (V37.1 activation)

    if (emit) {
        ScheduleOut off = run_schedule(v0);
        ScheduleOut on = run_schedule(v1);
        std::printf("EMIT OWED_OFF=%s\n", hex_of(off.owed).c_str());
        std::printf("EMIT OWED_ON=%s\n", hex_of(on.owed).c_str());
        std::printf("EMIT MASTER_STYLE=%s\n", hex_of(run_schedule_master_style()).c_str());
        std::printf("EMIT LANE_OFF=%s\n", hex_of(lane_digest(v0)).c_str());
        std::printf("EMIT LANE_ON=%s\n", hex_of(lane_digest(v1)).c_str());
        std::printf("EMIT C_CREDIT=%lld\n", on.C);
        std::printf("EMIT D_CREDIT=%lld\n", on.D);
        return 0;
    }

    // -- Case 1: version marker is authoritative + add-only --------------
    {
        SubthresholdGate g0 = SubthresholdGate::for_version(0);
        SubthresholdGate g1 = SubthresholdGate::for_version(1);
        LaneParams bare;                              // bare default constructor
        bool v0_off = (!v0.subthreshold.enabled) && (v0.subthreshold.version == 0);
        // v37_0() gate is byte-identical to the bare default gate (V37.0 base).
        bool bare_eq_v0 = (bare.subthreshold.enabled == v0.subthreshold.enabled) &&
                          (bare.subthreshold.K == v0.subthreshold.K) &&
                          (bare.subthreshold.mode == v0.subthreshold.mode) &&
                          (bare.subthreshold.version == v0.subthreshold.version);
        bool v1_on = v1.subthreshold.enabled && (v1.subthreshold.version == 1) &&
                     (v1.subthreshold.K == V371_K) && (v1.subthreshold.mode == 1);
        bool factory_consistent = (g0.enabled == v0.subthreshold.enabled) &&
                                  (g1.enabled == v1.subthreshold.enabled) &&
                                  (g1.mode == v1.subthreshold.mode);
        // shipped() IS V37.1 (the shipped default is the activation).
        LaneParams sh = LaneParams::shipped();
        bool shipped_is_v1 = (SHIPPED_CONSENSUS_VERSION == 1u) &&
                             (sh.subthreshold.enabled == v1.subthreshold.enabled) &&
                             (sh.subthreshold.K == v1.subthreshold.K) &&
                             (sh.subthreshold.mode == v1.subthreshold.mode) &&
                             (sh.subthreshold.version == v1.subthreshold.version);
        bool ok = v0_off && bare_eq_v0 && v1_on && factory_consistent && shipped_is_v1;
        check(ok, "1 version marker authoritative + add-only",
              "v0 OFF(" + std::string(v0_off ? "y" : "n") + ") bare==v0(" +
              std::string(bare_eq_v0 ? "y" : "n") + ") v1 ON,K=4,Combined(" +
              std::string(v1_on ? "y" : "n") + ") shipped==V37.1(" +
              std::string(shipped_is_v1 ? "y" : "n") + ")");
    }

    // -- Case 2: ACTIVE rule is Combined (S+K-1)*D'_K, NOT the broken clamp
    {
        // Route an S=2 worker through the REAL seam under the shipped V37.1
        // params; the credit MUST equal estimate_combined's low-63 fold and MUST
        // differ from the broken clamp's (non-vacuous: the two rules disagree).
        sub::ReceiptCollector rc = make_collector(2);
        bytes32 payee = keyfill(0xD4);
        std::vector<S::HarvestedReceipt> hv{S::HarvestedReceipt{payee, 201, rc}};
        auto credit = S::subthreshold_credit(v1, hv);
        long long seam = credit.empty() ? -1 : credit.begin()->second;
        sub::u256 hK = u256_from_hex(HK_HEX);
        long long comb = low63(sub::estimate_combined(/*S=*/2, V371_K, hK));
        long long clamp = low63(sub::broken_clamp_NEVER_CONSENSUS(
            /*S=*/2, V371_K, hK, /*h_T=*/[]{ sub::u256 t; t.w[0] = 3; return t; }()));
        // S=0 consistency: Combined(0,K) == EstimateOnly (K-1)*D_K, same denom.
        long long comb0 = low63(sub::estimate_combined(0, V371_K, hK));
        long long est0 = low63(sub::estimate_hashes(V371_K, hK));
        bool is_combined = (seam == comb) && (comb > 0);
        bool not_clamp = (seam != clamp) && (clamp != comb);   // rules disagree
        bool s0_consistent = (comb0 == est0);
        bool ok = is_combined && not_clamp && s0_consistent;
        check(ok, "2 active rule is Combined (S+K-1)*D'_K, not clamp",
              "seam=" + std::to_string(seam) + " comb=" + std::to_string(comb) +
              " clamp=" + std::to_string(clamp) + " (seam==comb!=clamp " +
              std::string(is_combined && not_clamp ? "y" : "n") +
              ") comb(0)==estOnly(" + std::string(s0_consistent ? "y" : "n") + ")");
    }

    // -- Case 3: gate-OFF (V37.0) owed_digest byte-identical -------------
    {
        ScheduleOut off = run_schedule(v0);
        std::string offh = hex_of(off.owed);
        bool eq_master = (offh == hex_of(run_schedule_master_style()));
        bool eq_golden = (offh == std::string(vg::OWED_DIGEST_GATE_OFF_HEX));
        bool no_credit = (off.A == 1000000) && (off.B == 500000) &&
                         (off.C == 0) && (off.D == 0);
        bool ok = eq_master && eq_golden && no_credit;
        check(ok, "3 gate-OFF (V37.0) owed_digest byte-identical",
              "off==master(" + std::string(eq_master ? "y" : "n") + ") ==V37.0-golden(" +
              std::string(eq_golden ? "y" : "n") + ") C/D uncredited(" +
              std::string(no_credit ? "y" : "n") + ")");
    }

    // -- Case 4: gate-ON (V37.1) owed_digest == new golden; differs ------
    {
        ScheduleOut on = run_schedule(v1);
        ScheduleOut off = run_schedule(v0);
        std::string onh = hex_of(on.owed);
        bool eq_golden = (onh == std::string(vg::OWED_DIGEST_GATE_ON_HEX));
        bool differs = (onh != hex_of(off.owed));               // NON-VACUOUS
        bool ok = eq_golden && differs;
        check(ok, "4 gate-ON (V37.1) owed_digest == golden, differs",
              "on==V37.1-golden(" + std::string(eq_golden ? "y" : "n") +
              ") on!=off(" + std::string(differs ? "y" : "n") + ")");
    }

    // -- Case 5: activation credits C & D; D=(5/3)C via (S+K-1) ----------
    {
        ScheduleOut on = run_schedule(v1);
        bool c_ok = (on.C == std::atoll(vg::C_CREDIT_DEC)) && (on.C > 0);
        bool d_ok = (on.D == std::atoll(vg::D_CREDIT_DEC)) && (on.D > 0);
        bool a_b_intact = (on.A == 1000000) && (on.B == 500000);  // E_b untouched
        // D (S=2) credit == (2+K-1)/(0+K-1) * C credit == 5/3 of C (within floor).
        bool s_scaled = (on.D * 3 >= on.C * 5 - 5) && (on.D * 3 <= on.C * 5 + 5);
        bool ok = c_ok && d_ok && a_b_intact && s_scaled;
        check(ok, "5 activation credits C,D; D/C == (S+K-1) ratio",
              "C=" + std::to_string(on.C) + " D=" + std::to_string(on.D) +
              " A,B intact(" + std::string(a_b_intact ? "y" : "n") +
              ") D~=5/3 C(" + std::string(s_scaled ? "y" : "n") + ")");
    }

    // -- Case 6: sybil-neutrality survives the shipped Combined activation
    // 2000-identity split routed through the REAL seam under v37_1() (Combined);
    // the broken clamp inflates (>1.3x @ 2000-split) and is unreachable via the
    // seam, the sybil-neutral Combined path stays neutral (<= ~1.0x).
    {
        const std::uint64_t Tdiff = 4096;
        sub::u256 hT; hT.w[3] = (1ULL << (244 - 192));   // h_T ~ 2^244 (~2^256/4096)
        const std::uint64_t Hbig = 20 * Tdiff;           // 81920
        const std::uint32_t K = V371_K;
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
                    c += u320_to_double(sub::broken_clamp_NEVER_CONSENSUS(Sc, K, hK, hT));
                    // The ACTUAL shipped wiring: v37_1() params through the seam.
                    bytes32 payee = keyfill((std::uint8_t)(0x10 + id));
                    std::vector<S::HarvestedReceipt> hv1{
                        S::HarvestedReceipt{payee, (std::uint64_t)id, rc}};
                    auto credit = S::subthreshold_credit(v1, hv1);
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
        d += ok ? "  => shipped Combined sybil-neutral, clamp rejected" : "  => UNEXPECTED";
        check(ok, "6 sybil-neutral shipped activation (clamp rejected)", d);
    }

    // -- Case 7: lane digest is version-invariant ------------------------
    {
        std::string d0 = hex_of(lane_digest(v0));
        std::string d1 = hex_of(lane_digest(v1));
        bool ok = (d0 == d1) && (d0 == std::string(vg::LANE_DIGEST_HEX));
        check(ok, "7 lane digest version-invariant (== golden)",
              "v0==v1(" + std::string(d0 == d1 ? "y" : "n") + ") ==golden(" +
              std::string(d0 == std::string(vg::LANE_DIGEST_HEX) ? "y" : "n") + ")");
    }

    // -- Case 8: golden stamp + NEGATIVE CONTROL -------------------------
    {
        std::ifstream f(vg::JSON_FILE, std::ios::binary);
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
            bool stamp_match = present && (got == std::string(vg::STAMP));
            check(stamp_match, "8 golden stamp verification",
                  present ? ("sha256==STAMP " + std::string(stamp_match ? "y" : "n"))
                          : "golden JSON not found next to binary");
        } else {
            bool detected = present && (got != std::string(vg::STAMP));
            check(detected, "8 NEGATIVE CONTROL (corrupt byte -> red)",
                  detected ? "flipped 1 byte -> stamp mismatch DETECTED"
                           : "corruption NOT detected -- hollow");
        }
    }

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
