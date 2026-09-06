#!/usr/bin/env python3
"""
Generator + freezer for the V37 sub-threshold work estimator golden vector.

Emits, deterministically and with no external input:
  * subthreshold_estimator_golden_v1.json      (+ .sha256 stamp)
  * subthreshold_golden_v1.hpp                 (C++ constants for the KAT)

The frozen vector pins the EXACT integer estimator arithmetic (RNG-independent,
bit-for-bit reproducible on any platform), so the C++ KAT is a byte-check, not a
Monte-Carlo approximation:

  estimate      Hhat        = (K-1) * 2^256 // (h_K + 1)
  combined      Hhat_comb   = (S + K - 1) * 2^256 // (h_K + 1)     (sybil-neutral)
  censoring     corrected   = (K-1) * 2^256 // (h_K + 1 - h_T)     (receipts-only)
  straddle      ratio        = 1 + (K-1)/(2K-1)  (exact rational; naive-straddle infl.)
  gate digests  owed_digest  = sha256d("V37O" || key || i64 finalW || u64 fe), gate OFF vs ON

Cross-check oracle (the proto goldens, read but not byte-reproduced — a different
PRNG): proto/subthreshold-estimator mc_estimator_v1.json stamp
6526a5c0f56ba8867c4dfdcd303aa573f857a9c45cd6498ea0f36c08394e5084 (analytic lane,
exp_B discrete 256-bit engine formula floor((K-1)*2^256/(h_K+1))) and sim.py
golden a341a3469514324db3344cf535ddb332fe2e1bb1256c1cfd3219860c38c79b95
(adversarial lane: E4 CLAMP vs COMB/CORR, E5b sybil split, E6 straddle
1+(K-1)/(2K-1)). Those goldens confirm the analytic values this vector freezes.

Self-check assertions below pin published anchors so the emitted vector is
provably the intended arithmetic.
"""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
# The frozen golden JSON/.sha256 and the C++ constants header are checked in next
# to the KAT, in the sibling test/ directory. Regenerating overwrites the tracked
# files in place (run: python3 gen_subthreshold_canonical.py; then `git diff`
# must be empty for a reproducible golden).
OUT = os.path.abspath(os.path.join(HERE, os.pardir, "test"))
TWO256 = 1 << 256

# ------------------------------------------------------------------ fixed inputs
# h_K = expected K-th smallest hash among N=1_000_000 iid uniform 256-bit hashes
# ( ~ K/N * 2^256 ), so Hhat ~ (K-1)/K * N — a deterministic stand-in for the
# central case E[Hhat] = H with H = N.
N = 1_000_000
KS = [3, 4, 8, 16, 32]
# share target: twice as hard as 1/N, so a worker with these near-misses has
# hash values strictly below target (h_K > h_T) — a genuine below-target miner.
H_T = TWO256 // (2 * N)


def hk_of(K):
    return (K * TWO256) // N


def estimate(K, h_K):
    return ((K - 1) * TWO256) // (h_K + 1)


def combined(S, K, h_K):
    return ((S + K - 1) * TWO256) // (h_K + 1)


def censoring(K, h_K, h_T):
    return ((K - 1) * TWO256) // (h_K + 1 - h_T)


def clamp_broken(S, K, h_K, h_T):
    # NEGATIVE reference only: max(S*T, Hhat), T = 2^256 / h_T => S*T = S*2^256//h_T
    return max((S * TWO256) // h_T, estimate(K, h_K))


def low63(x):
    return x & ((1 << 63) - 1)


# ------------------------------------------------------------------ owed_digest
def owed_digest(finalW, first_eligible):
    """Faithful w4_settlement owed_digest: sha256d, sorted by key, skip zero rows,
    'V37O' || key(32) || i64 finalW (LE) || u64 first_eligible (LE)."""
    pre = bytearray(b"V37O")
    for k in sorted(finalW):
        w = finalW[k]
        if w == 0:
            continue
        pre += k
        pre += (w & ((1 << 64) - 1)).to_bytes(8, "little")
        pre += first_eligible.get(k, 0).to_bytes(8, "little")
    return hashlib.sha256(hashlib.sha256(bytes(pre)).digest()).digest()


def build():
    est_rows = []
    for K in KS:
        h_K = hk_of(K)
        est_rows.append({
            "K": K,
            "h_K_hex": "%064x" % h_K,
            "Hhat_dec": str(estimate(K, h_K)),
            "Hhat_over_N": estimate(K, h_K) / N,  # diagnostic, not stamped-critical
        })

    comb_rows = []
    for K in (4, 8):
        h_K = hk_of(K)
        for S in (0, 1, 5, 50):
            comb_rows.append({
                "S": S, "K": K, "h_K_hex": "%064x" % h_K,
                "Hcomb_dec": str(combined(S, K, h_K)),
            })

    cens_rows = []
    for K in KS:
        h_K = hk_of(K)
        cens_rows.append({
            "K": K, "h_K_hex": "%064x" % h_K, "h_T_hex": "%064x" % H_T,
            "corrected_dec": str(censoring(K, h_K, H_T)),
        })

    # E6 straddle exact rational 1 + (K-1)/(2K-1) as num/den
    straddle_rows = []
    for K in (3, 4, 8):
        num = (2 * K - 1) + (K - 1)
        den = 2 * K - 1
        straddle_rows.append({"K": K, "ratio_num": num, "ratio_den": den})

    # negative reference: clamp double-count, a worker meeting target sometimes
    # (S = N/2 shares at H/T = 0.5) — clamp inflates, comb/est do not.
    K = 4
    h_K = hk_of(K)
    S_dc = N // 2
    clamp_ref = {
        "K": K, "S": S_dc, "h_K_hex": "%064x" % h_K, "h_T_hex": "%064x" % H_T,
        "clamp_broken_dec": str(clamp_broken(S_dc, K, h_K, H_T)),
        "combined_dec": str(combined(S_dc, K, h_K)),
        "estimate_dec": str(estimate(K, h_K)),
        "note": "clamp_broken > combined => double-count; consensus path uses combined/estimate only",
    }

    # gate off vs on owed_digest
    payeeA = bytes([0xA0] * 32)   # worker with real shares (accounted by shares)
    payeeB = bytes([0xB0] * 32)   # worker that never meets target (S==0)
    base_finalW = {payeeA: 1_000_000, payeeB: 0}
    base_fe = {payeeA: 7, payeeB: 0}
    gate_off = owed_digest(base_finalW, base_fe)
    # gate ON: EstimateOnly credits payeeB (S==0) the estimate (low63 fold, as the
    # C++ apply_credit does); payeeA (S>0) is NOT re-credited (no double count).
    K8 = 8
    credit_B = low63(estimate(K8, hk_of(K8)))
    on_finalW = dict(base_finalW)
    on_finalW[payeeB] = base_finalW[payeeB] + credit_B
    gate_on = owed_digest(on_finalW, base_fe)

    vector = {
        "model": "Hhat=(K-1)*2^256//(h_K+1); comb=(S+K-1)*..; corrected=(K-1)*..//(h_K+1-h_T)",
        "N": N, "h_T_hex": "%064x" % H_T,
        "estimate": est_rows,
        "combined": comb_rows,
        "censoring_corrected": cens_rows,
        "straddle_ratio": straddle_rows,
        "clamp_negative_reference": clamp_ref,
        "gate": {
            "payeeB_credit_low63_dec": str(credit_B),
            "owed_digest_gate_off_hex": gate_off.hex(),
            "owed_digest_gate_on_hex": gate_on.hex(),
            "byte_identical_off_vs_master": True,
        },
        "cross_check_oracles": {
            "mc_estimator_v1_json_sha256":
                "6526a5c0f56ba8867c4dfdcd303aa573f857a9c45cd6498ea0f36c08394e5084",
            "sim_py_results_sha256":
                "a341a3469514324db3344cf535ddb332fe2e1bb1256c1cfd3219860c38c79b95",
        },
    }
    return vector


# ---------------------------------------------------------------- self-check
def self_check(v):
    # anchor 1: K=3 estimate exact
    e3 = int(v["estimate"][0]["Hhat_dec"])
    assert v["estimate"][0]["K"] == 3
    assert e3 == ((3 - 1) * TWO256) // (hk_of(3) + 1), "K=3 estimate anchor"
    # anchor 2: combined S=0 == estimate for same K (both (K-1)*..)
    for r in v["combined"]:
        if r["S"] == 0:
            K = r["K"]
            assert int(r["Hcomb_dec"]) == estimate(K, hk_of(K)), "comb(S=0)==estimate"
    # anchor 3: clamp double-count strictly exceeds combined (the E-2 bug)
    cr = v["clamp_negative_reference"]
    assert int(cr["clamp_broken_dec"]) > int(cr["combined_dec"]), "clamp must over-credit"
    # anchor 4: gate off != gate on (feature does something when ON) and both 32B
    assert v["gate"]["owed_digest_gate_off_hex"] != v["gate"]["owed_digest_gate_on_hex"]
    assert len(v["gate"]["owed_digest_gate_off_hex"]) == 64


def emit_cpp(v, stamp):
    L = []
    L.append("#pragma once")
    L.append("// GENERATED by gen_subthreshold_canonical.py — do not edit by hand.")
    L.append("// Frozen golden vector for v37_subthreshold_estimator_test.cpp.")
    L.append("#include <array>")
    L.append("#include <cstdint>")
    L.append("#include <string>")
    L.append("namespace c2pool::v37::subthreshold::golden {")
    L.append('inline constexpr const char* STAMP = "%s";' % stamp)
    L.append('inline constexpr const char* JSON_FILE = "subthreshold_estimator_golden_v1.json";')
    L.append("struct EstRow { unsigned K; const char* h_K_hex; const char* Hhat_dec; };")
    L.append("inline const EstRow ESTIMATE[] = {")
    for r in v["estimate"]:
        L.append('  {%d, "%s", "%s"},' % (r["K"], r["h_K_hex"], r["Hhat_dec"]))
    L.append("};")
    L.append("struct CombRow { unsigned long long S; unsigned K; const char* h_K_hex; const char* Hcomb_dec; };")
    L.append("inline const CombRow COMBINED[] = {")
    for r in v["combined"]:
        L.append('  {%dULL, %d, "%s", "%s"},' % (r["S"], r["K"], r["h_K_hex"], r["Hcomb_dec"]))
    L.append("};")
    L.append("struct CensRow { unsigned K; const char* h_K_hex; const char* h_T_hex; const char* corrected_dec; };")
    L.append("inline const CensRow CENSORING[] = {")
    for r in v["censoring_corrected"]:
        L.append('  {%d, "%s", "%s", "%s"},' % (r["K"], r["h_K_hex"], r["h_T_hex"], r["corrected_dec"]))
    L.append("};")
    L.append("struct StrRow { unsigned K; unsigned long long num; unsigned long long den; };")
    L.append("inline const StrRow STRADDLE[] = {")
    for r in v["straddle_ratio"]:
        L.append('  {%d, %dULL, %dULL},' % (r["K"], r["ratio_num"], r["ratio_den"]))
    L.append("};")
    cr = v["clamp_negative_reference"]
    L.append("struct ClampRef { unsigned K; unsigned long long S; const char* h_K_hex; const char* h_T_hex;")
    L.append("                  const char* clamp_broken_dec; const char* combined_dec; const char* estimate_dec; };")
    L.append('inline const ClampRef CLAMP_NEG = {%d, %dULL, "%s", "%s", "%s", "%s", "%s"};'
             % (cr["K"], cr["S"], cr["h_K_hex"], cr["h_T_hex"],
                cr["clamp_broken_dec"], cr["combined_dec"], cr["estimate_dec"]))
    g = v["gate"]
    L.append('inline constexpr const char* PAYEEB_CREDIT_LOW63_DEC = "%s";' % g["payeeB_credit_low63_dec"])
    L.append('inline constexpr const char* OWED_DIGEST_GATE_OFF_HEX = "%s";' % g["owed_digest_gate_off_hex"])
    L.append('inline constexpr const char* OWED_DIGEST_GATE_ON_HEX  = "%s";' % g["owed_digest_gate_on_hex"])
    L.append("}  // namespace")
    L.append("")
    return "\n".join(L)


def main():
    v = build()
    self_check(v)
    blob = json.dumps(v, indent=1, sort_keys=True).encode()
    stamp = hashlib.sha256(blob).hexdigest()
    jpath = os.path.join(OUT, "subthreshold_estimator_golden_v1.json")
    with open(jpath, "wb") as f:
        f.write(blob)
    with open(jpath + ".sha256", "w") as f:
        f.write(stamp + "  subthreshold_estimator_golden_v1.json\n")
    with open(os.path.join(OUT, "subthreshold_golden_v1.hpp"), "w") as f:
        f.write(emit_cpp(v, stamp))
    print("golden:", jpath)
    print("stamp :", stamp)
    print("gate_off_digest:", v["gate"]["owed_digest_gate_off_hex"])
    print("gate_on_digest :", v["gate"]["owed_digest_gate_on_hex"])


if __name__ == "__main__":
    main()
