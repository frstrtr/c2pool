#!/usr/bin/env python3
"""T8 — periodic-checkpoint cadence model (the superlight lever).

T6/T7 established the trustless cold-start floor is O(W live) via a root-anchored
snapshot, BUT the only *server-trustless* fallback when no honest snapshot server
exists is PATH-A replay from genesis = O(total-ever) = O(W*(1 + f*R)), UNBOUNDED
in history length R. T7's closing note: "a periodic consensus live-set checkpoint
collapses it to O(W) -- that checkpoint is the lever the superlight open problem
turns on." T8 quantifies that lever.

Model
-----
Consensus commits the live-set roots (the 8-root Utreexo commitment, O(1) on-chain)
every C rounds = a CHECKPOINT. A cold/returning validator with NO honest snapshot
server anchors to the most recent checkpoint and:
  (1) fetches the W live leaves of that checkpoint from ANY (untrusted) server,
      rebuilds the forest O(W), and verifies its roots == the committed checkpoint
      roots  -> trustless, server need not be honest;
  (2) replays at most C rounds of deltas on top (each op unforgeable vs the PoW
      chain, as in T7), reaching the current head; verifies head roots == current
      committed roots.

Worst case = arriving one round before the next checkpoint => replay tail = C
rounds. Trustless cold-start cost = O(W) snapshot rebuild + O(f*W*C) delta replay
= O(W*(1 + f*C)). To cap replay at k*O(W):  1 + f*C <= k  =>  C <= (k-1)/f.

This harness measures, for a sweep of cadences C, the ACTUAL worst-case trustless
cold-start (wall-clock + egress) and contrasts it with the no-checkpoint PATH-A
replay, and confirms the rebuilt+replayed head reproduces the committed roots.
"""

import sys, time, argparse
from collections import deque
from utreexo import Forest, leaf_hash

LEAF_BYTES = 32          # a served live leaf hash
DEL_BYTES = 8            # a delta delete id
ROOT_BYTES = 32          # one committed root (<=8 roots / checkpoint)


def synth(i: int) -> bytes:
    return i.to_bytes(8, "little")


def make_schedule(w: int, rounds: int, churn_frac: float):
    """Genesis adds 0..W-1, then each round adds c fresh + deletes the c oldest
    live (FIFO), holding live==W. Returns (ops, round_marks, c, live_at_mark)
    where round_marks[r] = index into ops at END of round r, and live_at_mark[r]
    = the sorted live id-set at the end of round r (the checkpoint leaf set)."""
    ops = [("add", i) for i in range(w)]
    live = deque(range(w))
    round_marks = [len(ops)]
    live_at_mark = [list(live)]
    next_id = w
    c = max(1, int(w * churn_frac))
    for _ in range(rounds):
        for _ in range(c):
            ops.append(("add", next_id)); live.append(next_id); next_id += 1
        for _ in range(c):
            old = live.popleft(); ops.append(("del", old))
        round_marks.append(len(ops))
        live_at_mark.append(list(live))
    return ops, round_marks, c, live_at_mark


def apply_ops(f: Forest, ops):
    for op, i in ops:
        if op == "add":
            f.add(synth(i))
        else:
            f.delete(leaf_hash(synth(i)))


def build_from_live(live_ids):
    """Trustless snapshot rebuild: ingest the W served live leaves -> forest."""
    f = Forest()
    for i in live_ids:
        f.add(synth(i))
    return f


def roots_of(live_ids):
    return tuple(build_from_live(live_ids).roots())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--w", type=int, default=50_000, help="live share-set size")
    ap.add_argument("--rounds", type=int, default=40, help="total churn rounds (history depth R)")
    ap.add_argument("--churn", type=float, default=0.10, help="fraction churned/round (f)")
    ap.add_argument("--cadences", type=str, default="1,2,5,10,20,40",
                    help="checkpoint cadences C to sweep")
    args = ap.parse_args()
    f = args.churn
    R = args.rounds
    cadences = [int(x) for x in args.cadences.split(",")]

    print(f"=== T8 checkpoint cadence: W={args.w} f={f:.0%} R={R}rounds "
          f"cadences={cadences} ===\n")

    ops, marks, c, live_at_mark = make_schedule(args.w, R, f)

    # current head (round R) committed roots -- the target every cold-start must hit
    head_roots = tuple(build_from_live(live_at_mark[R]).roots())

    # --- baseline: no-checkpoint PATH-A replay from genesis = O(total-ever) ----
    t0 = time.perf_counter()
    genesis = Forest()
    apply_ops(genesis, ops)                       # every op since genesis
    t_pathA = time.perf_counter() - t0
    total_ops = len(ops)
    eg_pathA = args.w * LEAF_BYTES + (total_ops - args.w) * DEL_BYTES  # gross replay feed
    assert tuple(genesis.roots()) == head_roots, "PATH-A must reproduce head"
    print(f"[baseline] no-checkpoint PATH-A replay (genesis..head): "
          f"{total_ops:,} ops  {t_pathA:.3f}s  ~{eg_pathA/1e6:.1f}MB feed  "
          f"= O(W*(1+f*R)), grows with R\n")

    # snapshot-only floor (T6): rebuild current live set, no replay
    t0 = time.perf_counter()
    _ = build_from_live(live_at_mark[R])
    t_floor = time.perf_counter() - t0
    eg_floor = args.w * LEAF_BYTES
    print(f"[floor]    T6 snapshot-only rebuild (needs an honest live-set server): "
          f"{t_floor:.3f}s  {eg_floor/1e6:.2f}MB  = O(W)\n")

    # --- CONSTRAINT PROBE: does a naive leaf-set checkpoint + tail-replay even
    # reproduce the head under a history-dependent (swap-delete) forest? --------
    # Anchor 1 round back, rebuild from the served live set, replay the 1-round
    # tail, and compare to head. If this fails, leaf-set checkpoints are NOT
    # self-sufficient and the checkpoint must re-canonicalize (design finding).
    anchor1 = R - 1
    fprobe = build_from_live(live_at_mark[anchor1])
    apply_ops(fprobe, ops[marks[anchor1]:marks[R]])
    naive_ok = tuple(fprobe.roots()) == head_roots
    print(f"[constraint] naive leaf-set rebuild + tail-replay reproduces head: "
          f"{naive_ok}")
    if not naive_ok:
        print("  -> swap-delete forest is HISTORY-DEPENDENT: replaying ops onto a")
        print("     fresh leaf-set rebuild yields a different arrangement than the")
        print("     canonical op-sequence forest. CONSEQUENCE: the checkpoint MUST")
        print("     re-CANONICALISE -- consensus commits roots = canonical rebuild")
        print("     of the sorted live-set, and the validator derives head_live as")
        print("     an ID-SET delta then canonical-rebuilds. Compute is then O(W)")
        print("     flat; the CADENCE bounds the trustless DELTA it must download")
        print("     to derive verified head_live from the nearest committed anchor.\n")

    print(f"{'C':>4} {'delta MB cap':>12} {'delta ids':>11} {'rebuild s':>10} "
          f"{'egress MB':>10} {'ckpts/R':>8} {'head ok':>8}")
    print("-" * 74)
    for C in cadences:
        # worst case: validator arrives one round before the next checkpoint =>
        # nearest committed canonical anchor is `tail` rounds back.
        tail = min(C, R)
        anchor = R - tail
        ckpt_live = set(live_at_mark[anchor])
        ckpt_roots = tuple(build_from_live(sorted(ckpt_live)).roots())  # committed

        t0 = time.perf_counter()
        # (1) download + canonical-rebuild the committed checkpoint live-set,
        #     verify roots vs the on-chain commitment (server need not be honest).
        assert tuple(build_from_live(sorted(ckpt_live)).roots()) == ckpt_roots
        # (2) learn head_live by applying the bounded ID-SET delta [anchor..head].
        head_live = set(ckpt_live)
        delta_ids = 0
        for op, i in ops[marks[anchor]:marks[R]]:
            delta_ids += 1
            if op == "add":
                head_live.add(i)
            else:
                head_live.discard(i)
        # (3) canonical-rebuild head_live -> must equal the committed head roots.
        head_built = tuple(build_from_live(sorted(head_live)).roots())
        t_cold = time.perf_counter() - t0
        ok = head_built == head_roots

        eg = args.w * LEAF_BYTES + delta_ids * DEL_BYTES   # W leaves + delta ids
        delta_cap = delta_ids * DEL_BYTES
        ckpts = R / C
        print(f"{C:>4} {delta_cap/1e6:>12.2f} {delta_ids:>11,} {t_cold:>10.3f} "
              f"{eg/1e6:>10.2f} {ckpts:>8.1f} {str(ok):>8}")

    print()
    print("Checkpoint commit cost on-chain: <=8 roots = "
          f"{8*ROOT_BYTES}B per checkpoint, O(1) -- independent of W and cadence.")
    print("Snapshot-serving storage stays O(W): only the latest committed live-set")
    print("must be materialised; older checkpoints prune once superseded + final.")
    print("=> Under canonical (re-canonicalising) checkpoints, cold-start COMPUTE is")
    print("   O(W) flat; the CADENCE bounds the trustless DELTA download to O(f*C*W)")
    print("   ids. Pick C <= (k-1)/f for the delta to stay <=(k-1)x the W-leaf floor;")
    print("   at f=10%: C=5 -> +0.5x, C=10 -> +1.0x. Without a checkpoint, the nearest")
    print("   trustless anchor is genesis => O(total-ever) delta, UNBOUNDED in R.")
    print("   This is the lever the superlight open problem turns on.")


if __name__ == "__main__":
    main()
