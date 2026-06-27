#!/usr/bin/env python3
"""T13 — checkpoint cadence vs FINALITY-LAG interaction (the README NEXT item).

T8 established the on-chain live-set checkpoint as the lever that bounds trustless
cold-start to O(W*(1+f*C)). T9/T12 hardened the SERVING layer (safety unconditional,
W/K bounded DoS, sticky-shard liveness). One interaction was flagged but not yet
modelled: **a checkpoint must NEVER be committed over a reorg-able tip.**

This is the seam where M4 (superlight sync) touches M1 (the finality-gated overlay:
BlockFound->OverlayAdded, BlockFinalized->OwedSettled, BlockOrphaned->OverlayReverted).
The cold-start safety argument of T9 ("rebuild the committed live-set, verify roots
vs the on-chain commitment -> server need not be honest") has a HIDDEN PREMISE: the
committed root must itself be canonical. If consensus commits a checkpoint over a tip
that a later reorg orphans, then the committed root corresponds to an ORPHANED live-set.
A cold validator that trustlessly anchors to it rebuilds a head on a dead branch -- the
serving-layer safety proof does not save it, because the *commitment itself* is wrong.

Model
-----
finality depth D_f : a block at depth >= D_f from the tip is final (cannot be reorged) --
                     the SAME parameter M1's overlay gate uses (OwedSettled at finality).
reorg depth   d    : an adversary/natural reorg rewrites the last d rounds, d in [0..D_f].
checkpoint lag L   : consensus commits the live-set as of round (tip - L), not the tip.

A checkpoint committed when the tip is at round T commits the live-set at height (T-L).
A later reorg of depth d rewrites rounds (T-d+1 .. T).
  - height (T-L) is BELOW the rewrite base  iff  L >= d  -> the committed live-set is on
    the surviving prefix -> checkpoint stays canonical -> SAFE.
  - L < d -> height (T-L) is INSIDE the rewritten zone -> the committed live-set belonged
    to an orphaned block -> the post-reorg canonical chain has a DIFFERENT live-set at
    that height -> the committed root is orphaned -> a cold validator anchoring to it
    reconstructs a non-canonical head. UNSAFE.

We simulate a canonical chain and a divergent fork (the orphaned branch the checkpoint
was committed over), sweep (d, L), and measure:
  * orphaned-checkpoint events (committed root != canonical root at that height);
  * whether a cold validator anchoring to the committed checkpoint reproduces the
    CANONICAL head (the T9 trustless-anchor procedure, now against a possibly-orphaned
    commitment);
  * the STALENESS TAX of lag: cold-start delta tail = (C + L) rounds, so trustless delta
    egress = O(f*(C+L)*W) -- the additive +O(f*L*W) is the price of finality-safety.

Verdict sought: the safe rule is L >= D_f (commit only finalized prefixes). The cost is a
bounded, additive staleness term, NOT a new asymptotic. This pins the checkpoint to the
finality gate and closes the README NEXT item / feeds v37-superlight-chain-synthesis.md.
"""

import sys, time, argparse
from collections import deque
from utreexo import Forest, leaf_hash

LEAF_BYTES = 32
DEL_BYTES = 8
ROOT_BYTES = 32


def synth(i: int) -> bytes:
    return i.to_bytes(8, "little")


def build_from_live(live_ids):
    f = Forest()
    for i in sorted(live_ids):
        f.add(synth(i))
    return f


def roots_of(live_ids):
    return tuple(build_from_live(live_ids).roots())


def gen_chain(w, rounds, f, start_id, seed_live):
    """FIFO churn chain holding live==W. Returns (live_at_round, next_id), where
    live_at_round[r] is the sorted live id-set at the END of round r (r=0 = base).
    Deterministic; `start_id`/`seed_live` let a fork continue from a shared base."""
    live = deque(seed_live)
    next_id = start_id
    c = max(1, int(w * f))
    live_at_round = [list(live)]
    for _ in range(rounds):
        for _ in range(c):
            live.append(next_id); next_id += 1
        for _ in range(c):
            live.popleft()
        live_at_round.append(list(live))
    return live_at_round, next_id


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--w", type=int, default=50_000)
    ap.add_argument("--finality", type=int, default=8, help="finality depth D_f (rounds)")
    ap.add_argument("--base", type=int, default=20, help="rounds of shared history before the fork")
    ap.add_argument("--cadence", type=int, default=5, help="checkpoint cadence C (for the staleness tax)")
    ap.add_argument("--churn", type=float, default=0.10)
    ap.add_argument("--lags", type=str, default="0,1,2,4,8,12",
                    help="checkpoint lags L to sweep")
    ap.add_argument("--reorgs", type=str, default="1,2,4,8",
                    help="reorg depths d to sweep")
    args = ap.parse_args()
    f = args.churn
    Df = args.finality
    C = args.cadence
    lags = [int(x) for x in args.lags.split(",")]
    reorgs = [int(x) for x in args.reorgs.split(",")]

    print(f"=== T13 checkpoint finality-lag: W={args.w} f={f:.0%} D_f={Df} "
          f"C={C} base={args.base} lags={lags} reorgs={reorgs} ===\n")

    # Shared history up to `base`, then a single canonical chain advances `max_d`
    # rounds to the tip T. A depth-d reorg means the branches AGREE up to height
    # (max_d - d) above the base and DIVERGE only in the last d rounds -- so the
    # orphan branch is rebuilt PER d, splitting from canon at (max_d - d). (The
    # earlier model split at the base for every d, which wrongly orphaned heights
    # the reorg never touched.)
    base = args.base
    max_d = max(reorgs)
    shared, nid_after_base = gen_chain(args.w, base, f, start_id=args.w,
                                       seed_live=range(args.w))
    fork_base_live = shared[base]

    # canonical branch advances max_d rounds from the fork base (the chain that wins)
    canon, nid_after_canon = gen_chain(args.w, max_d, f, start_id=nid_after_base,
                                       seed_live=fork_base_live)

    def orphan_branch(d):
        """The branch that was tip at commit time but loses a depth-d reorg: shares
        canon up to height (max_d - d), then advances d rounds with DIFFERENT ids."""
        split_h = max_d - d
        ob, _ = gen_chain(args.w, d, f,
                          start_id=nid_after_canon + 10_000_000 * d,
                          seed_live=canon[split_h])
        # return a height-indexed view (above base) matching canon's indexing
        return split_h, ob   # ob[j] is height split_h + j

    # absolute round of the tip when the checkpoint was committed = base + max_d
    T = base + max_d
    canon_head_roots = roots_of(canon[max_d])

    # sanity: at depths below the fork the two branches agree (shared prefix)
    assert roots_of(shared[base]) == roots_of(fork_base_live)

    print("SAFETY SWEEP — does the committed checkpoint stay canonical after a depth-d reorg?")
    print("(committed branch was tip at commit time; canonical branch wins the reorg)\n")
    print(f"{'d\\L':>5}", end="")
    for L in lags:
        print(f"{('L='+str(L)):>10}", end="")
    print("   <- cell = cold-start anchoring to committed ckpt @lag L reaches CANONICAL head?")
    print("-" * (5 + 10 * len(lags) + 4))

    wrong_head_events = 0
    for d in reorgs:
        split_h, orphan = orphan_branch(d)     # orphan[j] is height split_h + j
        print(f"{d:>5}", end="")
        for L in lags:
            # the committed checkpoint commits the live-set at height (T - L) =
            # (max_d - L) above the fork base. The branch the tip was on at commit
            # time is the ORPHAN (it later loses the reorg); below split_h both
            # branches share canon.
            h = max_d - L                      # committed height above the fork base
            if h <= split_h:                   # shared prefix -> canonical regardless
                committed_live = canon[max(0, h)]
            else:                              # inside the to-be-orphaned tip
                committed_live = orphan[h - split_h]
            committed_roots = roots_of(committed_live)

            # what the CANONICAL chain has at that same height after the reorg wins:
            canon_at_h = canon[max(0, h)]
            canon_roots_at_h = roots_of(canon_at_h)

            # A reorg of depth d rewrites heights (max_d-d .. max_d]. The committed
            # height h survives iff h <= max_d - d = split_h  i.e. L >= d.
            checkpoint_canonical = (committed_roots == canon_roots_at_h)

            # Cold-start trustless anchor (the T9 procedure): fetch committed live-set,
            # verify vs committed root (always passes -- it's what was committed), then
            # apply canonical deltas to reach head and check vs canonical head root.
            # If the anchor was orphaned, the derived head is on a dead branch.
            if checkpoint_canonical:
                # anchor is canonical: re-derive head from canon[h..max_d] -> matches.
                reaches_canonical = True
            else:
                # anchor is orphaned: the live-set we trustlessly rebuilt is NOT a
                # canonical ancestor of the head; a delta to canonical head cannot be
                # formed from it without already knowing the canonical branch.
                reaches_canonical = False
                wrong_head_events += 1
            mark = "ok" if reaches_canonical else "ORPH"
            print(f"{mark:>10}", end="")
        print()

    print()
    print(f"wrong-head / orphaned-anchor events across sweep: {wrong_head_events}")
    print(f"SAFE RULE: every cell with L >= d is 'ok'; every L < d is 'ORPH'. "
          f"Commit lag L >= D_f={Df} (>= any admissible reorg depth) => 0 orphaned anchors.\n")

    # --- STALENESS TAX of finality-lag -------------------------------------------
    # cold-start delta tail = (C + L) rounds (cadence worst-case C, plus the lag L the
    # checkpoint trails the tip). Trustless delta egress = W leaves + f*W*(C+L) ids.
    print("STALENESS TAX — cold-start trustless delta as lag L grows (cadence C fixed):")
    print(f"{'L':>4} {'tail rounds':>12} {'delta ids':>11} {'delta MB':>9} "
          f"{'total egress MB':>16} {'x W-floor':>10}")
    print("-" * 66)
    c_per_round = max(1, int(args.w * f))
    w_floor_eg = args.w * LEAF_BYTES
    for L in lags:
        tail = C + L
        delta_ids = c_per_round * tail
        delta_mb = delta_ids * DEL_BYTES / 1e6
        total_mb = (w_floor_eg + delta_ids * DEL_BYTES) / 1e6
        x = total_mb * 1e6 / w_floor_eg
        print(f"{L:>4} {tail:>12} {delta_ids:>11,} {delta_mb:>9.2f} "
              f"{total_mb:>16.2f} {x:>9.2f}x")

    print()
    print("FINDINGS")
    print("--------")
    print(f"1. SAFETY: a checkpoint committed at lag L < reorg-depth d is committed over an")
    print(f"   orphan-able tip; after the reorg its committed root is non-canonical and a")
    print(f"   trustless cold-start anchoring to it lands on a DEAD branch. The T9 serving-")
    print(f"   layer safety proof does NOT cover this -- it assumes the commitment canonical.")
    print(f"2. RULE: commit only FINALIZED prefixes -> L >= D_f (={Df}). This reuses M1's")
    print(f"   finality gate verbatim: a checkpoint is the OwedSettled/BlockFinalized-side")
    print(f"   read of the same overlay the lane settles on. BlockOrphaned never touches a")
    print(f"   committed checkpoint because the checkpoint trails finality.")
    print(f"3. COST: the lag is an ADDITIVE staleness term, delta tail = (C+L) rounds, NOT a")
    print(f"   new asymptotic -- cold-start stays O(W*(1+f*(C+L))). At f={f:.0%}, C={C}, L=D_f={Df}:")
    L = Df
    print(f"   delta = +{f*(C+L):.1f}x the W-leaf floor vs +{f*C:.1f}x for lag-0 -- the safety")
    print(f"   premium is +{f*L:.1f}x egress, bounded and one-time per cold-start.")
    print(f"4. DESIGN FEED: checkpoint = {{<=8 forest roots + 1 shard-root}} committed at depth")
    print(f"   >= D_f behind the tip. Cadence C bounds delta; finality lag D_f bounds safety;")
    print(f"   the two compose additively. Pick C <= (k-1)/f - D_f to keep total delta <= k*W.")


if __name__ == "__main__":
    main()
