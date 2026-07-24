#!/usr/bin/env python3
"""M4 T7 — incremental snapshot deltas + the no-honest-server replay worst case.

T6 established two cold-start floors for a brand-new sovereign:
  PATH A full-history replay  O(total-ever)   (server-trustless, no snapshot needed)
  PATH B root-anchored snapshot O(W live)     (server-trustless vs committed roots)

T7 closes the two remaining local questions the T6 README flagged:

  Q1  A RETURNING validator (already holds a trustless forest at checkpoint c0,
      comes back at c1 after k churn rounds) should NOT pay O(W) again. It should
      pay O(ΔW) = O(adds+deletes since c0). This track measures that the delta
      path reproduces the c1-committed roots and costs O(ΔW), and sweeps ΔW vs gap.

      The delta is just the op stream [c0..c1] in order. Determinism (T6) means a
      validator that applies it to its saved c0 forest lands on the bridge's exact
      c1 forest -> roots match by construction. A delta cannot be forged: the
      rebuilt roots must equal the PoW-committed c1 roots, same trust anchor as B.

  Q2  The no-honest-snapshot-server WORST CASE. PATH B needs SOMEONE serving the
      live row-0 vector. If no honest server exists, the only server-trustless
      fallback is PATH A replay, which pays O(total-ever). Under sustained
      adversarial churn at fraction f for R rounds, total-ever = W*(1 + f*R):
      the replay-only floor grows LINEARLY IN HISTORY LENGTH, unbounded in R, NOT
      bounded by W. This track quantifies that inflation and shows that a single
      honest snapshot server (or a periodic consensus live-set checkpoint)
      collapses it back to O(W) -- the actual lever the open problem turns on.

Deterministic: synthetic shares = i.to_bytes(8); one op SCHEDULE drives bridge,
checkpoint, and delta so identical end-state (and roots) holds by construction.
perf_counter only feeds the reported cost columns.
"""
import sys, time, argparse
from collections import deque
from utreexo import Forest, leaf_hash

LEAF_BYTES = 32          # a leaf hash on the wire
DEL_BYTES = 8            # a deletion op = a leaf id/position pointer (validator holds the leaf)
ROOT_BYTES = 32


def synth(i: int) -> bytes:
    return i.to_bytes(8, "little")


def make_schedule(w: int, rounds: int, churn_frac: float):
    """Deterministic op stream: genesis add 0..W-1, then each round add c fresh and
    delete the c oldest live (FIFO), holding live==W. Returns (ops, round_marks)
    where round_marks[r] = index into ops at the END of round r (round_marks[0] =
    end of genesis)."""
    ops = [("add", i) for i in range(w)]
    round_marks = [len(ops)]            # mark 0 = end of genesis (the c0 baseline)
    live = deque(range(w))
    next_id = w
    c = max(1, int(w * churn_frac))
    for _ in range(rounds):
        for _ in range(c):
            ops.append(("add", next_id)); live.append(next_id); next_id += 1
        for _ in range(c):
            old = live.popleft(); ops.append(("del", old))
        round_marks.append(len(ops))
    return ops, round_marks, c


def apply_ops(f: Forest, ops):
    """Apply an op slice to forest f in place. Returns (adds, deletes) counts."""
    a = d = 0
    for op, i in ops:
        if op == "add":
            f.add(synth(i)); a += 1
        else:
            f.delete(leaf_hash(synth(i))); d += 1
    return a, d


def delta_bandwidth(ops_slice) -> int:
    """Wire cost of a delta op slice: adds ship a 32B leaf hash, deletes a 8B id."""
    bw = 0
    for op, _ in ops_slice:
        bw += LEAF_BYTES if op == "add" else DEL_BYTES
    return bw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--w", type=int, default=300_000, help="live share-set size")
    ap.add_argument("--rounds", type=int, default=20, help="total churn rounds")
    ap.add_argument("--churn", type=float, default=0.10, help="fraction churned/round")
    ap.add_argument("--gap", type=int, default=5, help="rounds a returning validator was away")
    args = ap.parse_args()

    print(f"=== T7 incremental delta + no-server worst case: W={args.w} "
          f"churn={args.churn:.0%}x{args.rounds}rounds gap={args.gap} ===")

    ops, marks, c = make_schedule(args.w, args.rounds, args.churn)

    # --- bridge builds the full current (c1 = final round) state -------------
    tb = time.perf_counter()
    bridge = Forest()
    total_a, total_d = apply_ops(bridge, ops)
    tb = time.perf_counter() - tb
    committed = bridge.roots()                         # PoW-committed c1 roots
    total_ever = total_a                               # every leaf ever admitted
    print(f"bridge: live W={bridge.n} total_ever={total_ever} deletes={total_d} "
          f"roots={len(committed)} build={tb*1000:.0f}ms  "
          f"(anchor = {len(committed)} root hashes = {len(committed)*ROOT_BYTES}B)")

    # checkpoint c0 = end of genesis; returning validator was away `gap` rounds,
    # i.e. it last synced at round (rounds-gap) and returns at round `rounds`.
    c0_round = max(0, args.rounds - args.gap)
    c0_idx = marks[c0_round]

    # --- returning validator: hold the c0 forest, apply ONLY the delta -------
    val = Forest()
    apply_ops(val, ops[:c0_idx])                       # its already-trusted c0 state
    c0_roots = val.roots()
    delta_slice = ops[c0_idx:]
    td = time.perf_counter()
    da, dd = apply_ops(val, delta_slice)
    td = time.perf_counter() - td
    dW = da + dd
    delta_bw = delta_bandwidth(delta_slice)
    delta_ok = val.roots() == committed

    # --- cold sovereign (T6 path B) for the same c1, as the O(W) comparison --
    snap_bw = bridge.n * LEAF_BYTES
    ts = time.perf_counter()
    cold = Forest()
    for lh in bridge.rows[0]:
        cold.add_hash(lh)
    ts = time.perf_counter() - ts
    cold_ok = cold.roots() == committed

    print(f"--- Q1 returning validator (away {args.gap}/{args.rounds} rounds, "
          f"checkpoint=end-of-round-{c0_round}) ---")
    print(f"  c0 baseline roots != c1 roots: {c0_roots != committed} "
          f"(state really moved)")
    print(f"  delta path   : ΔW={dW:>7} ops (adds={da} dels={dd}) "
          f"build={td*1000:7.1f}ms bw={delta_bw/1024/1024:6.3f}MB roots_match={delta_ok}")
    print(f"  cold O(W)    : W ={bridge.n:>7}     "
          f"build={ts*1000:7.1f}ms bw={snap_bw/1024/1024:6.3f}MB roots_match={cold_ok}")
    if dW:
        print(f"  => returning validator pays {dW/bridge.n:.4f}x the cold-snapshot "
              f"work/bandwidth ( O(ΔW) vs O(W), ΔW/W = {dW}/{bridge.n} ).")

    # --- Q2 no-honest-server replay worst case, swept over history length ----
    print("--- Q2 no-honest-snapshot-server fallback = PATH A replay, O(total-ever) ---")
    print(f"  total-ever / live inflation = {total_ever/bridge.n:.2f}x at "
          f"R={args.rounds} rounds (replay rebuilds {total_ever} leaves for a "
          f"W={bridge.n} live set).")
    print(f"  closed form: total_ever = W*(1 + f*R), f={args.churn:.0%}  ->")
    for R in (args.rounds, args.rounds * 5, args.rounds * 25, args.rounds * 100):
        infl = 1 + args.churn * R
        print(f"     R={R:>6} rounds : replay floor = {infl:6.2f}x O(W)  "
              f"(~{infl*bridge.n/1e6:.2f}M leaf-rebuilds)")
    print(f"  => WITHOUT an honest server the replay-only floor is UNBOUNDED in "
          f"history length R, not bounded by W. A SINGLE honest snapshot server "
          f"(or a periodic consensus live-set checkpoint) collapses it to O(W). "
          f"That checkpoint is the lever the superlight open problem turns on.")

    ok = delta_ok and cold_ok and (c0_roots != committed)
    print("=== VERDICT ===")
    print(f"  returning-validator delta reproduces the committed c1 roots in O(ΔW), "
          f"trustless vs the same PoW-committed {len(committed)}-root anchor as the "
          f"snapshot; cold-start floor stays O(W); replay-only fallback is O(W*(1+fR)).")
    print(f"  correctness (delta+cold reproduce committed roots, state moved): "
          f"{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
