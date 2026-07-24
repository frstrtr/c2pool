#!/usr/bin/env python3
"""M4 T5 -- REALISTIC in-place Utreexo swap-delete cost (closes T4 OPEN-a).

T4 could only BRACKET the realistic bridge per-update CPU between two proxies it
actually implemented: REPACK (full O(W) rebuild, ~353ms) and LAZY (tombstone+
append, ~41ms, but O(total-ever) storage). Neither is the true incremental
swap-delete Utreexo specifies. This track exercises Forest.delete (now
implemented) on a FIFO sliding window and measures the genuine per-update cost.

Correctness oracle: this forest representation is fully-packed, so its internal
rows are a PURE FUNCTION of the leaf row. After every incremental delete we
assert rows == a from-scratch pairwise re-fold of the current leaf row. If the
incremental _refold_above logic is wrong, the round fails loudly -- no silent
bad numbers. We additionally stateless-verify 300 sampled proofs/round against
the live forest roots.

Reproduce: python3 t5_inplace_delete.py --w 100000 --rounds 20 --churn 0.10
"""
from __future__ import annotations
import argparse, time, sys
from utreexo import Forest, parent_hash, leaf_hash


def fold_from_leaves(leaf_row: list[bytes]) -> list[list[bytes]]:
    """Obvious, trusted full re-fold: the reference the incremental must match."""
    rows = [list(leaf_row)]
    while len(rows[-1]) >= 2:
        prev = rows[-1]
        rows.append([parent_hash(prev[2 * i], prev[2 * i + 1])
                     for i in range(len(prev) // 2)])
    return rows


def trim(rows: list[list[bytes]]) -> list[list[bytes]]:
    out = list(rows)
    while len(out) > 1 and not out[-1]:
        out.pop()
    return out


def assert_consistent(f: Forest) -> None:
    ref = fold_from_leaves(f.rows[0])
    got = trim(f.rows)
    if got != ref:
        raise AssertionError(
            f"incremental forest diverged from re-fold: "
            f"rows={[len(r) for r in got]} ref={[len(r) for r in ref]}")
    # leaf_index must stay in sync with the leaf row after swaps
    assert len(f.leaf_index) == f.n, f"leaf_index {len(f.leaf_index)} != n {f.n}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--w", type=int, default=100000)      # live window size
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--churn", type=float, default=0.10)  # fraction expired/added per round
    ap.add_argument("--samples", type=int, default=300)
    args = ap.parse_args()

    W, R = args.w, args.rounds
    step = max(1, int(W * args.churn))
    print(f"=== T5 in-place swap-delete: W={W} rounds={R} churn={step}/round "
          f"({args.churn:.0%}) ===")

    f = Forest()
    # FIFO order of live leaf hashes (oldest first) -> what we expire
    fifo: list[bytes] = []
    t0 = time.perf_counter()
    for i in range(W):
        fifo.append(f.add(i.to_bytes(8, "big")))
    build_ms = (time.perf_counter() - t0) * 1e3
    assert_consistent(f)
    print(f"bootstrap: W={W} build={build_ms:.0f}ms nodes={f.node_count()} "
          f"mem~{f.node_count()*32/1e6:.1f}MB roots={len(f.roots())}")

    next_id = W
    del_us_all: list[float] = []
    for rnd in range(1, R + 1):
        # expire oldest `step` via real swap-delete; time only the deletes
        td = time.perf_counter()
        for _ in range(step):
            old = fifo.pop(0)
            if not f.delete(old):
                raise AssertionError("expired leaf missing from forest")
        del_ms = (time.perf_counter() - td) * 1e3
        del_us = del_ms * 1e3 / step
        del_us_all.append(del_us)
        # append `step` fresh leaves
        for _ in range(step):
            fifo.append(f.add(next_id.to_bytes(8, "big")))
            next_id += 1
        # correctness oracle: incremental == full re-fold, every round
        assert_consistent(f)
        # stateless proof check on a spread of live leaves
        roots = set(f.roots())
        idxs = [min(len(fifo) - 1, k * len(fifo) // args.samples)
                for k in range(args.samples)]
        worst = 0
        ok = 0
        for j in idxs:
            pr = f.prove(fifo[j])
            worst = max(worst, len(pr["path"]))
            # find which root this proof reconstructs
            acc = pr["leaf"]; pos = pr["pos"]
            for sib in pr["path"]:
                acc = parent_hash(sib, acc) if pos & 1 else parent_hash(acc, sib)
                pos >>= 1
            ok += acc in roots
        print(f"  rnd {rnd:2d}: live={f.n} ever={next_id} del={del_us:6.1f}us/leaf "
              f"({del_ms:5.1f}ms/{step}) worst={worst}h({worst*32}B) "
              f"roots={len(roots)} mem~{f.node_count()*32/1e6:.1f}MB verify={ok}/{len(idxs)}")
        if ok != len(idxs):
            raise AssertionError("a sampled proof failed to verify against roots")

    avg_us = sum(del_us_all) / len(del_us_all)
    print("=== VERDICT ===")
    print(f"  in-place swap-delete: {avg_us:.1f} us/leaf avg "
          f"({avg_us*step/1e3:.1f}ms per {args.churn:.0%} round)")
    print(f"  T4 bracket was REPACK ~353ms vs LAZY ~41ms per round at this W; "
          f"in-place lands at {avg_us*step/1e3:.1f}ms")
    print(f"  storage: steady {f.node_count()*32/1e6:.1f}MB = O(W) (no LAZY "
          f"O(total-ever) growth -- swap-delete reclaims in place)")
    print("  correctness: incremental forest == full re-fold every round; "
          "all sampled proofs stateless-verified. PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
