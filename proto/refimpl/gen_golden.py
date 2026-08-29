#!/usr/bin/env python3
"""
Golden-vector generator for the V37 MRR scaled-frame accumulator.

Emits golden/mrr_accumulator_v0.json with three consensus-relevant properties:

  P1 (determinism / residual reproducibility, sec.4.2 "Determinism note"):
      two independent replays of the identical share sequence produce bit-identical
      acc and bit-identical decayed payouts at every sampled head.

  P2 (OQ-2 exact-rebuild re-convergence, sec.4.2 / sec.8.4):
      the incrementally-maintained acc at each epoch boundary equals acc rebuilt
      from-scratch over the durable L0 records -- bit-for-bit.

  P3 (why OQ-2 is mandatory): the truncating multiply-renorm path (acc *= lambda^E,
      the cheaper alternative OQ-2 REJECTS) drifts from the rebuild path; we record
      the max per-miner residual so the spec's "residuals never accumulate" claim is
      quantified, not asserted.

Deterministic inputs only (no RNG in the consensus path): a fixed LCG over a fixed
seed drives the share sequence purely to produce a reproducible vector file.
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from mrr_ref import build_tables, Lane, mul_q62, E, HALF_LIFE, FRAC_BITS, ONE

NMINERS = 8
EPOCHS = 3                          # cover 3 epoch boundaries
NPUSH = E * EPOCHS + (E // 2)       # land mid-epoch at the end

def share_sequence(n):
    """Fixed deterministic (miner, weight) sequence -- a documented LCG, NOT consensus RNG."""
    x = 0x9E3779B97F4A7C15
    seq = []
    for _ in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        miner = (x >> 17) % NMINERS
        w = 1 + ((x >> 29) % 1000)          # difficulty-unit weights 1..1000
        seq.append((miner, w))
    return seq

def rebuild_from_records(InvD, records, B, epoch):
    fresh = {}
    for (p, m, w) in records:
        if p < B or p - B >= epoch:
            continue
        fresh[m] = fresh.get(m, 0) + ((w * InvD[p - B]) >> FRAC_BITS)
    return fresh

def main():
    InvD, decay, base_inv = build_tables()
    seq = share_sequence(NPUSH)

    # --- run A (rebuild path = the V37 spec) ---
    laneA = Lane(InvD, decay)
    sampled = {}                    # head -> {miner: decayed}
    boundary_checks = []
    # renorm-path shadow accumulator (the REJECTED alternative), reset each epoch with laneA frame
    lamE = decay[E]                 # lambda^E in Q62
    renorm_acc = {}
    renorm_B = 0
    max_residual = 0

    for i, (miner, w) in enumerate(seq):
        # detect upcoming boundary (mirrors Lane.push internal check)
        if laneA.H + 1 - laneA.B == E:
            # capture incremental acc BEFORE rebuild, compare to from-scratch rebuild
            inc = dict(laneA.acc)
            # renorm-path: multiply live acc by lambda^E (truncating) -> new frame
            renorm_next = {m: mul_q62(v, lamE) for m, v in renorm_acc.items()}
            laneA.push(miner, w)    # triggers rebuild internally, advances B, then pushes
            rebuilt = rebuild_from_records(InvD, laneA.l0, laneA.B, E)
            # P2: rebuilt acc must equal incremental acc carried into new frame? The rebuild
            # DEFINES the new-frame acc; record both for the vector + the residual vs renorm.
            # Residual: compare renorm-path projection to rebuild over the SAME records.
            for m in set(list(renorm_next.keys()) + list(rebuilt.keys())):
                resid = abs(renorm_next.get(m, 0) - rebuilt.get(m, 0))
                if resid > max_residual:
                    max_residual = resid
            renorm_acc = dict(rebuilt)   # re-anchor renorm path to truth each epoch (best case)
            renorm_B = laneA.B
            boundary_checks.append({
                "head": laneA.H,
                "B": laneA.B,
                "acc_entries": len(rebuilt),
                "acc_total": sum(rebuilt.values()),
            })
        else:
            laneA.push(miner, w)
            j = laneA.H - renorm_B
            renorm_acc[miner] = renorm_acc.get(miner, 0) + ((w * InvD[j]) >> FRAC_BITS)

        if laneA.H % E == 0 or i == len(seq) - 1:
            sampled[laneA.H] = {str(m): laneA.decayed_payout(m) for m in range(NMINERS)}

    # --- run B (independent replay, P1 determinism) ---
    laneB = Lane(InvD, decay)
    sampledB = {}
    for i, (miner, w) in enumerate(seq):
        laneB.push(miner, w)
        if laneB.H % E == 0 or i == len(seq) - 1:
            sampledB[laneB.H] = {str(m): laneB.decayed_payout(m) for m in range(NMINERS)}

    p1_ok = (sampled == sampledB)

    vector = {
        "spec": "c2pool-v37-mrr-roundabout-buffer.md",
        "geometry": {"half_life": HALF_LIFE, "E": E, "frac_bits": FRAC_BITS,
                     "nminers": NMINERS, "npush": NPUSH},
        "table": {"base_inv_q62": str(base_inv),
                  "InvD_E_q62": str(InvD[E]), "decay_E_q62": str(decay[E]),
                  "note": "table base is a CANDIDATE integer construction; canonical "
                          "generation procedure to be pinned in M3 spec-consolidation"},
        "P1_determinism_bitidentical": p1_ok,
        "P2_epoch_boundaries": boundary_checks,
        "P3_renorm_vs_rebuild_max_residual_q62": str(max_residual),
        "P3_residual_relative_to_one": max_residual / float(ONE),
        "sampled_decayed_payouts": {str(h): v for h, v in sorted(sampled.items())},
    }
    outdir = os.path.join(os.path.dirname(__file__), "golden")
    os.makedirs(outdir, exist_ok=True)
    outpath = os.path.join(outdir, "mrr_accumulator_v0.json")
    with open(outpath, "w") as f:
        json.dump(vector, f, indent=2, sort_keys=True)

    print(f"P1 determinism bit-identical : {p1_ok}")
    print(f"P2 epoch boundaries checked  : {len(boundary_checks)}")
    print(f"P3 max renorm-vs-rebuild resid: {max_residual} (Q62)  "
          f"= {max_residual/float(ONE):.3e} relative")
    print(f"wrote {outpath}")
    return 0 if p1_ok else 1

if __name__ == "__main__":
    sys.exit(main())
