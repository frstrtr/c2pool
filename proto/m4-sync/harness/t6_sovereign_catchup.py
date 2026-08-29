#!/usr/bin/env python3
"""M4 T6 — sovereign first-time-validator cold-start catch-up cost.

The milestone-4 open problem: a stateless VERIFIER is O(log n), but a brand-new
SOVEREIGN validator (no trusted snapshot server, no prior state) must reconstruct
the accumulator itself before it can verify anything. The design flags this as
"a sovereign first-time validator pays O(n)" — this track measures which n.

Two cold-start paths, both anchored ONLY to the PoW-committed root set (the
stateless commitment, O(log W) hashes the validator gets from the chain tip):

  PATH A  full-history replay : download EVERY share ever admitted (total-ever,
          including ones later deleted) + the deletion ops, replay them to rebuild
          the live forest, check roots == committed. Server-trustless: a peer
          cannot forge history that folds to the committed roots. O(total-ever).

  PATH B  root-anchored snapshot : download only the bridge's LIVE row-0 leaf
          vector (W leaf hashes in physical order), fold them, check the rebuilt
          roots == the PoW-committed roots. If they match, the snapshot is
          TRUSTLESS (the roots are consensus-committed; a forged snapshot cannot
          reproduce them). O(W live), NOT O(total-ever history).

PATH B collapses sovereign cost from O(total-ever) to O(W live) while staying
trustless against the committed roots. O(W) is the irreducible floor — the
sovereign must touch every live leaf once. This sharpens the superlight-chain
open problem to "is one-time O(W) bootstrap acceptable", separate from
steady-state O(log W) verification.

Deterministic: synthetic shares = i.to_bytes(8). A single op SCHEDULE drives both
the bridge build and the PATH-A replay, so identical end-state (and roots) holds
by construction. perf_counter only for the reported cost columns.
"""
import sys, time, argparse
from collections import deque
from utreexo import Forest, leaf_hash

LEAF_BYTES = 32          # a leaf hash on the wire
DEL_BYTES = 8            # a deletion op = a leaf position/id pointer
ROOT_BYTES = 32


def synth(i: int) -> bytes:
    return i.to_bytes(8, "little")


def make_schedule(w: int, rounds: int, churn_frac: float):
    """Deterministic op stream that ends with W live leaves but total-ever > W.

    Genesis: add 0..W-1. Then each round: add `c` fresh, delete the `c` oldest
    still-live (FIFO), holding the live set at W. Returns (ops, total_ever,
    deletes) where ops is a list of ('add', id) | ('del', id)."""
    ops = [("add", i) for i in range(w)]
    live = deque(range(w))
    next_id = w
    c = max(1, int(w * churn_frac))
    deletes = 0
    for _ in range(rounds):
        for _ in range(c):
            ops.append(("add", next_id)); live.append(next_id); next_id += 1
        for _ in range(c):
            old = live.popleft(); ops.append(("del", old)); deletes += 1
    return ops, next_id, deletes


def run_schedule(ops):
    """Apply an op schedule to a fresh forest. Returns the forest."""
    f = Forest()
    for op, i in ops:
        if op == "add":
            f.add(synth(i))
        else:
            f.delete(leaf_hash(synth(i)))
    return f


def path_a_replay(ops, total_ever, deletes, committed):
    """Naive sovereign: replay the entire admit/delete history from genesis.
    Same schedule as the bridge -> identical forest -> roots match by construction."""
    t0 = time.perf_counter()
    f = run_schedule(ops)
    dt = time.perf_counter() - t0
    bw = total_ever * LEAF_BYTES + deletes * DEL_BYTES
    return {
        "path": "A full-history replay",
        "build_s": round(dt, 3),
        "ops": len(ops),
        "bandwidth_mb": round(bw / 1024 / 1024, 2),
        "roots_match": f.roots() == committed,
    }


def path_b_snapshot(snapshot_leaves, committed):
    """Root-anchored sovereign: download the bridge's live row-0 leaf-hash vector,
    fold it, verify the rebuilt roots reproduce the PoW-committed roots."""
    t0 = time.perf_counter()
    f = Forest()
    for lh in snapshot_leaves:
        f.add_hash(lh)
    dt = time.perf_counter() - t0
    w = len(snapshot_leaves)
    return {
        "path": "B root-anchored snapshot",
        "build_s": round(dt, 3),
        "ops": w,
        "bandwidth_mb": round(w * LEAF_BYTES / 1024 / 1024, 2),
        "roots_match": f.roots() == committed,
        "us_per_leaf": round(dt / w * 1e6, 2),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--w", type=int, default=300_000, help="live share-set size")
    ap.add_argument("--rounds", type=int, default=20, help="churn rounds")
    ap.add_argument("--churn", type=float, default=0.10, help="fraction churned/round")
    ap.add_argument("--clients", type=int, default=50, help="cold-start clients to serve")
    args = ap.parse_args()

    print(f"=== T6 sovereign cold-start catch-up: W={args.w} "
          f"churn={args.churn:.0%}x{args.rounds}rounds clients={args.clients} ===")

    ops, total_ever, dels = make_schedule(args.w, args.rounds, args.churn)
    tb = time.perf_counter()
    bridge = run_schedule(ops)
    tb = time.perf_counter() - tb
    committed = bridge.roots()
    snapshot_leaves = list(bridge.rows[0])   # the live row-0 leaf-hash vector
    print(f"bridge state: live W={bridge.n} total_ever={total_ever} deletes={dels} "
          f"roots={len(committed)} build={tb*1000:.0f}ms "
          f"(commitment the sovereign anchors to = {len(committed)} root hashes "
          f"= {len(committed)*ROOT_BYTES}B)")

    a = path_a_replay(ops, total_ever, dels, committed)
    b = path_b_snapshot(snapshot_leaves, committed)
    for r in (a, b):
        print(f"  {r['path']:<26} build={r['build_s']:>7.3f}s "
              f"ops={r['ops']:>8} bw={r['bandwidth_mb']:>7.2f}MB "
              f"roots_match={r['roots_match']}")

    snap_bw = bridge.n * LEAF_BYTES
    replay_bw = total_ever * LEAF_BYTES + dels * DEL_BYTES
    print("=== bridge proof-serving topology ===")
    print(f"  bridge forest mem ~ {bridge.node_count()*32/1024/1024:.1f}MB (O(W), "
          f"the cost of being a proof-server / snapshot-server)")
    print(f"  serve 1 sovereign via snapshot : {snap_bw/1024/1024:.2f}MB egress")
    print(f"  serve 1 sovereign via replay   : {replay_bw/1024/1024:.2f}MB egress "
          f"({replay_bw/max(1,snap_bw):.2f}x snapshot)")
    print(f"  serve {args.clients} sovereigns via snapshot: "
          f"{args.clients*snap_bw/1024/1024:.1f}MB total bridge egress")

    inflate = total_ever / bridge.n
    print("=== VERDICT ===")
    print(f"  total-ever / live = {inflate:.2f}x  -> replay pays {inflate:.2f}x the "
          f"bandwidth AND build of the snapshot path for an IDENTICAL end-state.")
    print(f"  PATH B trustless: rebuilt roots == committed roots ({b['roots_match']}); "
          f"a forged snapshot cannot match the PoW-committed {len(committed)}-root "
          f"commitment.")
    print(f"  => sovereign cold-start floor is O(W live) = {b['build_s']:.3f}s / "
          f"{b['bandwidth_mb']:.2f}MB at W={args.w}, NOT O(total-ever). "
          f"Steady-state verification stays O(log W).")
    print(f"  OPEN: is one-time O(W) bootstrap acceptable at production W, and is "
          f"there a sovereign with NO honest snapshot-server? (replay is the "
          f"fallback, {inflate:.2f}x costlier; both paths are server-trustless.)")
    ok = a["roots_match"] and b["roots_match"]
    print(f"  correctness: both paths reproduce the committed roots: "
          f"{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
