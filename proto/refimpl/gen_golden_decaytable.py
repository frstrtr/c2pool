#!/usr/bin/env python3
"""
Golden-vector generator for the V37 MRR CANONICAL decay-table base (M2).

Emits golden/decay_table_canonical_golden_v1.json. Three blocks:

  G-A  CANONICAL ANCHORS & SAMPLED ENTRIES — the consensus-pinned table values that any
       conformant implementation must reproduce bit-for-bit:
         decay[0]=InvD[0]=ONE ; decay[half_life]=2^(frac-1) (exact) ; decay[E], InvD[E] ;
         plus a deterministic sample of interior entries.

  G-B  DRIFT vs the v0 per-step table (mrr_ref.build_tables) — the iterated truncating-multiply
       table accumulates O(j) ULPs of floor bias; we record max abs deviation and where it
       peaks. This is *why* the canonical per-entry construction replaces it: the v0 base was
       position-order dependent; the canonical base is not.

  G-C  ACCUMULATOR EQUIVALENCE ON THE CANONICAL BASE — re-run the scaled-frame accumulator
       (mrr_ref.Lane) using the canonical tables and confirm P1 determinism + P2 OQ-2
       exact-rebuild still hold bit-for-bit, so swapping in the canonical base does not perturb
       the settlement properties M1/M2 already lock.

Deterministic inputs only.
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from decay_table import load_or_build, validate, HALF_LIFE, E, FRAC_BITS, ONE
from mrr_ref import build_tables as build_v0, Lane, FRAC_BITS as MRR_FRAC

assert MRR_FRAC == FRAC_BITS, "frac-bit pin mismatch between mrr_ref and decay_table"

NMINERS = 8
EPOCHS = 3
NPUSH = E * EPOCHS + (E // 2)


def share_sequence(n):
    x = 0x9E3779B97F4A7C15
    seq = []
    for _ in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        miner = (x >> 17) % NMINERS
        w = 1 + ((x >> 29) % 1000)
        seq.append((miner, w))
    return seq


def run_accumulator(InvD, decay):
    """P1 determinism + P2 OQ-2 exact-rebuild, returns (p1_ok, p2_boundaries, sampled)."""
    seq = share_sequence(NPUSH)

    def replay():
        lane = Lane(InvD, decay)
        sampled, boundaries = {}, []
        for i, (miner, w) in enumerate(seq):
            if lane.H + 1 - lane.B == E:
                lane.push(miner, w)  # triggers internal OQ-2 rebuild
                # P2: independently rebuild from durable L0 over the new frame, must match acc
                fresh = {}
                for (p, m, wt) in lane.l0:
                    if p < lane.B or p - lane.B >= E:
                        continue
                    fresh[m] = fresh.get(m, 0) + ((wt * InvD[p - lane.B]) >> FRAC_BITS)
                boundaries.append({"head": lane.H, "B": lane.B,
                                   "rebuild_matches_acc": (fresh == lane.acc),
                                   "acc_total": sum(lane.acc.values())})
            else:
                lane.push(miner, w)
            if lane.H % E == 0 or i == len(seq) - 1:
                sampled[lane.H] = {str(m): lane.decayed_payout(m) for m in range(NMINERS)}
        return sampled, boundaries

    sA, boundaries = replay()
    sB, _ = replay()
    p1_ok = (sA == sB)
    p2_ok = all(b["rebuild_matches_acc"] for b in boundaries)
    return p1_ok, p2_ok, boundaries, sA


def main():
    InvD, decay = load_or_build()
    checks = validate(InvD, decay)

    # G-B: drift vs v0 per-step table
    InvD0, decay0, base_inv0 = build_v0()
    drift_decay = [abs(decay[d] - decay0[d]) for d in range(E + 1)]
    drift_invd = [abs(InvD[d] - InvD0[d]) for d in range(E + 1)]
    max_dd = max(drift_decay); arg_dd = drift_decay.index(max_dd)
    max_di = max(drift_invd); arg_di = drift_invd.index(max_di)

    # G-C: accumulator equivalence on canonical base
    p1_ok, p2_ok, boundaries, sampled = run_accumulator(InvD, decay)

    sample_idx = sorted(set([0, 1, HALF_LIFE - 1, HALF_LIFE, HALF_LIFE + 1, E - 1, E]
                            + list(range(0, E + 1, 512))))
    vector = {
        "spec": "c2pool-v37-mrr-roundabout-buffer.md sec.8.2 (canonical decay-table base)",
        "geometry": {"half_life": HALF_LIFE, "E": E, "frac_bits": FRAC_BITS,
                     "ONE_q62": str(ONE)},
        "construction": "decay[d]=floor((2^(frac*hl - d))^(1/hl)); "
                        "InvD[j]=floor((2^(frac*hl + j))^(1/hl)) -- exact per-entry hl-th root",
        "G_A_canonical_invariants": {k: (v if isinstance(v, bool) else str(v))
                                     for k, v in checks.items()},
        "G_A_anchors": {
            "decay_0": str(decay[0]), "InvD_0": str(InvD[0]),
            "decay_halflife": str(decay[HALF_LIFE]),
            "two_pow_frac_minus_1": str(1 << (FRAC_BITS - 1)),
            "decay_E": str(decay[E]), "InvD_E": str(InvD[E]),
        },
        "G_A_sampled_entries": {str(d): {"decay": str(decay[d]), "InvD": str(InvD[d])}
                                for d in sample_idx},
        "G_B_drift_vs_v0_per_step_table": {
            "decay_max_abs_ulp": str(max_dd), "decay_argmax_index": arg_dd,
            "InvD_max_abs_ulp": str(max_di), "InvD_argmax_index": arg_di,
            "note": "v0 iterated-multiply table biases ~O(index) ULPs; canonical base is "
                    "per-entry exact, so this drift is the error the canonical base removes",
        },
        "G_C_accumulator_on_canonical_base": {
            "P1_determinism_bitidentical": p1_ok,
            "P2_oq2_rebuild_matches_acc": p2_ok,
            "boundaries_checked": len(boundaries),
        },
        "G_C_sampled_decayed_payouts": {str(h): v for h, v in sorted(sampled.items())},
    }

    outdir = os.path.join(os.path.dirname(__file__), "golden")
    os.makedirs(outdir, exist_ok=True)
    outpath = os.path.join(outdir, "decay_table_canonical_golden_v1.json")
    with open(outpath, "w") as f:
        json.dump(vector, f, indent=2, sort_keys=True)

    inv_ok = all(v for v in checks.values() if isinstance(v, bool))
    print("G-A canonical invariants :", "PASS" if inv_ok else "FAIL")
    print(f"G-B drift vs v0 table    : decay max {max_dd} ULP @ d={arg_dd}; "
          f"InvD max {max_di} ULP @ j={arg_di}")
    print(f"G-C accumulator on canon : P1={p1_ok} P2={p2_ok} ({len(boundaries)} boundaries)")
    print(f"wrote {outpath}")
    ok = inv_ok and p1_ok and p2_ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
