#!/usr/bin/env python3
"""M4 T4: adversarial DELETION-churn — the track T1/T3 could not exercise.

T1/T3 use the append-only forest, so they model sharechain GROWTH but never share
EXPIRY. In V37 the live window is bounded (W shares); old shares fall out. Expiry is
deletion, and deletion is where Utreexo churn actually bites: a bridge that does not
re-pack the forest accumulates dangling subtrees, so the peak count and the worst-case
membership-proof path grow without bound even though the LIVE set size is constant.

We measure both bridge strategies over the same FIFO sliding-window churn workload:

  REPACK  — bridge rebuilds the forest from the live set each round. Proof path stays
            <= ceil(log2 W); the cost is an O(W) re-pack per round. (Bounded proofs,
            recurring bridge CPU.)
  LAZY    — bridge appends new leaves and tombstones expired ones, never re-packing.
            Proofs for still-live leaves keep their original (deepening) paths and the
            peak/root count grows with TOTAL-ever-appended. (Cheap updates, inflating
            proofs — the adversarial failure mode.)

Workload: window W, each round expire the oldest d = floor(W * rate) and append d new.
Deterministic: synthetic share i = i.to_bytes(8,'little'); no randomness, no wall-clock
in the measured path (perf_counter only for the cost columns).
"""
import sys, time, math, argparse
from utreexo import Forest, leaf_hash, parent_hash


def synth(i: int) -> bytes:
    return i.to_bytes(8, "little")


def build_forest(indices) -> Forest:
    f = Forest()
    for i in indices:
        f.add(synth(i))
    return f


def proof_stats(f: Forest, sample_indices):
    """Worst/avg membership-proof path length over a sample of live leaves, and the
    forest peak (root) count. Every sampled proof is stateless-verified against a root."""
    rootset = set(f.roots())
    sizes, verified = [], 0
    for i in sample_indices:
        pr = f.prove(leaf_hash(synth(i)))
        if pr is None:
            continue
        sizes.append(len(pr["path"]))
        acc, pos = pr["leaf"], pr["pos"]
        for sib in pr["path"]:
            acc = parent_hash(sib, acc) if pos & 1 else parent_hash(acc, sib)
            pos >>= 1
        if acc in rootset:
            verified += 1
    return {
        "worst_hashes": max(sizes) if sizes else 0,
        "avg_hashes": round(sum(sizes) / len(sizes), 2) if sizes else 0,
        "roots": len(f.roots()),
        "verified": verified,
        "sampled": len(sizes),
        "forest_mb": round(f.node_count() * 32 / (1024 * 1024), 2),
    }


def sample(window_lo, window_hi, k):
    """k evenly-spaced live indices, always including the OLDEST live leaf (worst case)."""
    span = window_hi - window_lo
    if span <= k:
        return list(range(window_lo, window_hi))
    step = span // k
    return [window_lo + j * step for j in range(k)]


def t4_repack(W, rounds, rate, k):
    d = max(1, int(W * rate))
    lo, hi = 0, W            # live window = [lo, hi)
    f = build_forest(range(lo, hi))
    series, rebuild_ms = [], []
    for _ in range(rounds):
        lo += d; hi += d     # FIFO: expire oldest d, append d new
        t0 = time.perf_counter()
        f = build_forest(range(lo, hi))   # re-pack: forest IS the live set
        rebuild_ms.append((time.perf_counter() - t0) * 1e3)
        st = proof_stats(f, sample(lo, hi, k))
        st["total_live"] = hi - lo
        series.append(st)
    return series, rebuild_ms


def t4_lazy(W, rounds, rate, k):
    d = max(1, int(W * rate))
    lo, hi = 0, W
    f = build_forest(range(lo, hi))   # never rebuilt; only appended
    series, append_ms = [], []
    for _ in range(rounds):
        lo += d              # tombstone the oldest d (no structural removal)
        t0 = time.perf_counter()
        for i in range(hi, hi + d):   # append d new leaves
            f.add(synth(i))
        append_ms.append((time.perf_counter() - t0) * 1e3)
        hi += d
        st = proof_stats(f, sample(lo, hi, k))   # sample only still-LIVE leaves
        st["total_live"] = hi - lo
        st["total_ever"] = hi
        series.append(st)
    return series, append_ms


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--w", type=int, default=100_000, help="live window size")
    ap.add_argument("--rounds", type=int, default=12)
    ap.add_argument("--rate", type=float, default=0.10, help="expire+append fraction/round")
    ap.add_argument("--samples", type=int, default=200)
    a = ap.parse_args()

    log2W = round(math.log2(a.w), 2)
    rp, rp_ms = t4_repack(a.w, a.rounds, a.rate, a.samples)
    lz, lz_ms = t4_lazy(a.w, a.rounds, a.rate, a.samples)

    print(f"=== M4 T4 deletion-churn  (W={a.w} live, {a.rate:.0%}/round, {a.rounds} rounds, log2(W)={log2W}) ===")
    print("--- REPACK bridge (rebuild live set each round) ---")
    for r, ms in zip(rp, rp_ms):
        print(f"  live={r['total_live']} worst={r['worst_hashes']} avg={r['avg_hashes']} "
              f"roots={r['roots']} mem={r['forest_mb']}MB verified={r['verified']}/{r['sampled']} rebuild={ms:.0f}ms")
    print("--- LAZY bridge (tombstone + append, never re-pack) ---")
    for r, ms in zip(lz, lz_ms):
        print(f"  live={r['total_live']} ever={r['total_ever']} worst={r['worst_hashes']} "
              f"avg={r['avg_hashes']} roots={r['roots']} mem={r['forest_mb']}MB verified={r['verified']}/{r['sampled']} append={ms:.1f}ms")

    rp_infl = round(rp[-1]["worst_hashes"] / max(1, rp[0]["worst_hashes"]), 2)
    lz_infl = round(lz[-1]["worst_hashes"] / max(1, lz[0]["worst_hashes"]), 2)
    rp_root_infl = round(rp[-1]["roots"] / max(1, rp[0]["roots"]), 2)
    lz_root_infl = round(lz[-1]["roots"] / max(1, lz[0]["roots"]), 2)
    print("=== VERDICT ===")
    print(f"  REPACK: worst-proof inflation={rp_infl}x  root inflation={rp_root_infl}x  "
          f"avg rebuild={sum(rp_ms)/len(rp_ms):.0f}ms/round  -> proofs BOUNDED, recurring O(W) CPU")
    print(f"  LAZY:   worst-proof inflation={lz_infl}x  root inflation={lz_root_infl}x  "
          f"avg append={sum(lz_ms)/len(lz_ms):.1f}ms/round  -> cheap updates, proofs+peaks INFLATE")
    print(f"  worst-proof bound this run: repack<=ceil(log2 W)={math.ceil(log2W)} hashes "
          f"({math.ceil(log2W)*32}B); lazy reached {lz[-1]['worst_hashes']} hashes "
          f"({lz[-1]['worst_hashes']*32}B) at {lz[-1]['total_ever']} ever-appended")
    print(f"  bridge storage: repack steady {rp[-1]['forest_mb']}MB (~O(W)); "
          f"lazy {lz[0]['forest_mb']}->{lz[-1]['forest_mb']}MB "
          f"(O(total-ever), {round(lz[-1]['forest_mb']/max(0.01,lz[0]['forest_mb']),2)}x) "
          f"<- the real lazy cost is STORAGE, not proof depth (both grow only ~log/linear-in-n)")
    sys.exit(0)
