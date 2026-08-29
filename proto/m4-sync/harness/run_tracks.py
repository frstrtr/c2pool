#!/usr/bin/env python3
"""M4 T1/T2/T3 driver over the real Utreexo forest. Produces deterministic numbers.

T1 bootstrap-cost : build the full forest over N synthetic shares; time + node mem.
T2 proof-serving  : bridge node generates membership proofs; proof size vs O(log n).
T3 churn-inflation: adversarial add-cycling; does the proof path stay ~log2(n)?

Deterministic: synthetic shares = sha256(i). No randomness, no wall-clock in logic
(time.perf_counter only for the reported cost columns).
"""
import sys, time, argparse
from utreexo import Forest, leaf_hash


def synth(i: int) -> bytes:
    return i.to_bytes(8, "little")


def t1_bootstrap(n: int):
    f = Forest()
    t0 = time.perf_counter()
    for i in range(n):
        f.add(synth(i))
    dt = time.perf_counter() - t0
    nodes = f.node_count()
    # 32 bytes/hash; bridge node holds the whole forest
    mem_mb = nodes * 32 / (1024 * 1024)
    return f, {
        "n": n, "build_s": round(dt, 3),
        "nodes": nodes, "forest_mem_mb": round(mem_mb, 2),
        "roots": len(f.roots()),
        "us_per_share": round(dt / n * 1e6, 2),
    }


def t2_proofs(f: Forest, n: int, samples: int):
    import math
    rootset = set(f.roots())
    step = max(1, n // samples)
    sizes, ok = [], 0
    t0 = time.perf_counter()
    for i in range(0, n, step):
        lh = leaf_hash(synth(i))
        pr = f.prove(lh)
        assert pr is not None, f"no proof for leaf {i}"
        # fold to implied root, must be one of the forest roots (stateless verify)
        acc, pos = pr["leaf"], pr["pos"]
        from utreexo import parent_hash
        for sib in pr["path"]:
            acc = parent_hash(sib, acc) if pos & 1 else parent_hash(acc, sib)
            pos >>= 1
        if acc in rootset:
            ok += 1
        sizes.append(len(pr["path"]))
    dt = time.perf_counter() - t0
    cnt = len(sizes)
    return {
        "samples": cnt, "verified_ok": ok,
        "proof_hashes_min": min(sizes), "proof_hashes_max": max(sizes),
        "proof_hashes_avg": round(sum(sizes) / cnt, 2),
        "proof_bytes_max": max(sizes) * 32,
        "log2_n": round(math.log2(n), 2),
        "us_per_proof": round(dt / cnt * 1e6, 2),
    }


def t3_churn(n: int, churn_rounds: int):
    """Adversarial churn: keep appending shares (the realistic sharechain growth +
    re-org append pattern) and watch the worst-case proof path for the OLDEST live
    leaf. If the path stays ~log2(n) the proof size is churn-resistant; if it grows
    super-log the bridge/verifier cost blows up."""
    import math
    f = Forest()
    for i in range(n):
        f.add(synth(i))
    watch = leaf_hash(synth(0))  # oldest leaf — worst case for path growth
    series = []
    base = n
    for k in range(churn_rounds):
        for j in range(n // 10):  # +10% growth per round
            f.add(synth(base)); base += 1
        pr = f.prove(watch)
        series.append({"total_n": f.n, "oldest_proof_hashes": len(pr["path"]),
                       "log2_n": round(math.log2(f.n), 2)})
    return {"rounds": churn_rounds, "series": series,
            "inflation_ratio": round(series[-1]["oldest_proof_hashes"] /
                                     max(1, series[0]["oldest_proof_hashes"]), 2)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300_000)
    ap.add_argument("--samples", type=int, default=200)
    ap.add_argument("--churn-rounds", type=int, default=5)
    a = ap.parse_args()

    f, r1 = t1_bootstrap(a.n)
    r2 = t2_proofs(f, a.n, a.samples)
    r3 = t3_churn(min(a.n, 100_000), a.churn_rounds)

    print("=== M4 T1 bootstrap-cost ===")
    for k, v in r1.items(): print(f"  {k}: {v}")
    print("=== M4 T2 proof-serving ===")
    for k, v in r2.items(): print(f"  {k}: {v}")
    print("=== M4 T3 churn-inflation ===")
    print(f"  rounds={r3['rounds']} inflation_ratio={r3['inflation_ratio']}")
    for s in r3["series"]: print(f"    {s}")
    # gate verdict
    blowup = r2["proof_hashes_max"] > 2 * r2["log2_n"] or r3["inflation_ratio"] > 1.5
    print("=== VERDICT ===")
    print(f"  bridge_forest_mem_mb={r1['forest_mem_mb']}  "
          f"worst_proof_bytes={r2['proof_bytes_max']}  "
          f"proof_churn_resistant={not blowup}")
    sys.exit(0)
