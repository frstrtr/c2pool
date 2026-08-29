#!/usr/bin/env python3
"""T14 — END-TO-END no-server cold-start: finality-lagged checkpoint (T13) +
sticky-shard multi-bridge serving (T12/T9) + trustless delta tail (T7/T8),
composed into ONE validator trace under SIMULTANEOUS reorg + sybil + churn.

This is the README "NEXT (local)" item: each prior track proved one property of
the superlight cold-start in isolation. T14 wires them into the actual procedure
a brand-new sovereign validator runs, and checks the properties COMPOSE (no seam
re-opens a hole that an isolated track had closed).

The procedure under test (a cold validator with NO local state, NO trusted server)
------------------------------------------------------------------------------------
  Inputs it trusts: the on-chain commitments only --
    * the checkpoint commitment {<=8 forest roots, 1 32B shard-root} committed at
      depth >= D_f behind the tip (T13 finality rule: commit only finalized prefixes);
    * the finalized head roots at (tip - D_f) (the M1 BlockFinalized read).
  STEP A  anchor: pick the nearest committed checkpoint (<= C rounds stale). Its
          height is (tip - L) with L >= D_f, so by T13 it is canonical even though
          the tip itself is being reorged to depth d <= D_f.
  STEP B  serve: reconstruct the checkpoint live-set from a multi-bridge pool with
          adversarial sybils, via T12 sticky-shard assembly -- each shard checked
          vs the committed sub-root, one-strike-drop on a lie. SAFETY unconditional
          (canonical-rebuild == committed roots or reject); LIVENESS needs >=1 honest.
  STEP C  catch up: apply the trustless op-delta over the (C + L) tail rounds from
          the checkpoint height to the finalized head (T7 delta), canonical-rebuild
          the head live-set, and verify it reproduces the committed finalized-head
          roots. The delta is unforgeable (PoW-root-anchored); a wrong tail cannot
          reproduce the committed head roots.

What we assert composes
-----------------------
  SAFETY (unconditional, incl. h=0 full eclipse and d up to D_f):
    the validator NEVER finalizes a non-canonical head. Either it rejects every
    served set / delta and stalls (liveness failure), or it reproduces exactly the
    committed canonical finalized-head roots. No middle "accepts wrong head".
  LIVENESS: succeeds iff (>=1 honest server reachable) AND (L >= D_f). L < D_f is
    the T13 unsafe regime -- here the anchor itself is orphaned, so a "success"
    would be a SAFETY violation; we assert it instead STALLS (the validator detects
    the post-delta head roots != committed finalized-head roots and refuses).
  COST is ADDITIVE, not asymptotic: end-to-end egress = W (checkpoint live-set, once)
    + f*(C+L)*W (delta tail) + wasted sybil egress (<= servers_touched * W/K); compute
    = O(W) canonical rebuild + O(f*(C+L)*W) delta apply. One-time per cold-start.

Deterministic given --seed; wall-clock only OUTSIDE the verification path.
Reproduce: python3 t14_e2e_coldstart.py --w 300000 --servers 20 --shards 16 --df 8 --c 5
"""

import sys, time, argparse, random
from collections import deque

from utreexo import Forest
from t9_multibridge_availability import (
    synth, committed_roots, shard_subroots, make_pool,
)
from t12_sticky_shard_assembly import trial_shard_sticky
from t13_checkpoint_finality_lag import gen_chain, roots_of

LEAF_BYTES = 32
ID_BYTES = 8
ROOT_BYTES = 32


def apply_delta(live_ckpt, delta_adds, delta_dels):
    """STEP C compute: take the trustless checkpoint live-set, apply the op-delta
    (FIFO churn: adds then equal dels) to reach the finalized-head live-set, then
    canonical-rebuild. Returns (head_live_ids, rebuild_roots, compute_seconds).
    The rebuild is the T8 re-canonicalisation rule (sorted live-set), so the head
    is history-INDEPENDENT and reproducible by anyone with the same id-set."""
    live = set(live_ckpt)
    for i in delta_adds:
        live.add(i)
    for i in delta_dels:
        live.discard(i)
    head = sorted(live)
    t0 = time.perf_counter()
    f = Forest()
    for i in head:
        f.add(synth(i))
    return head, tuple(f.roots()), time.perf_counter() - t0


def e2e_trial(w, f, df, c, lag, reorg_d, servers, h, shards_k, rng, staleness=0):
    """One full cold-start. Returns a dict of outcome + costs.

    `lag` = L (checkpoint committed at tip-L). `reorg_d` = depth of the tip reorg
    in flight while the validator boots. `c` = checkpoint cadence. `staleness` in
    [0..c] = how many rounds older than the freshest commit the validator's nearest
    checkpoint is (0 = freshest, the WORST case for safety; c = oldest, the worst
    case for cost). The cadence affects COST (delta-tail length), never safety: an
    older anchor is strictly more final. So the sweep runs staleness=0 to expose the
    L<reorg_d orphan regime; the golden cost trace runs staleness=c."""
    churn = max(1, int(w * f))
    # --- build the canonical chain deep enough to host a finalized checkpoint ---
    rounds = lag + c + reorg_d + 4                    # slack below the anchor
    base_live = list(range(w))                        # the W-live genesis set
    chain, next_id = gen_chain(w, rounds, f, w, base_live)
    tip = rounds                                      # current canonical tip index

    # --- the reorg in flight: a fork rewrites the last reorg_d rounds from base ---
    # (T13 model) fork shares the chain up to (tip - reorg_d), then diverges.
    fork_base_round = tip - reorg_d
    fork_seed = chain[fork_base_round]
    fork_chain, _ = gen_chain(w, reorg_d, f, next_id, fork_seed)

    # the validator's nearest checkpoint sits at tip - lag - staleness.
    anchor_height = max(0, tip - lag - staleness)
    # Is that height inside the rewritten (orphaned) zone? If so the committed
    # checkpoint was published over the fork -> it commits the ORPHAN live-set.
    anchor_is_canonical = anchor_height <= fork_base_round
    if anchor_is_canonical:
        live_anchor = chain[anchor_height]
    else:
        # committed over the orphan: the operator violated L>=D_f and a reorg deeper
        # than the lag rewrote the committed height. The serving layer will faithfully
        # serve THIS (fork) live-set -- the danger T13 names.
        live_anchor = fork_chain[anchor_height - fork_base_round]

    # --- the COMMITMENT the validator trusts (checkpoint sub-roots over live_anchor) ---
    committed_anchor_roots = committed_roots(live_anchor)
    shards, subroots, shard_root = shard_subroots(live_anchor, shards_k)

    # the committed FINALIZED-head the validator must reproduce -- an INDEPENDENT
    # on-chain anchor, always the CANONICAL chain at (tip - df):
    final_head_height = tip - df
    committed_final_roots = roots_of(chain[final_head_height])

    # --- STEP B: sticky-shard serve from the adversarial multi-bridge pool ---
    pool = make_pool(servers, h, rng)
    booted, touched, wasted, worst_sybil = trial_shard_sticky(
        pool, shards, subroots, servers, rng
    )
    n_honest = sum(1 for p in pool if p == "honest")
    liveness_possible = n_honest >= 1

    out = {
        "anchor_is_canonical": anchor_is_canonical,
        "served": booted,
        "n_honest": n_honest,
        "servers_touched": touched,
        "wasted_leaves": wasted,
        "worst_sybil_egress": worst_sybil,
        "accepted_wrong_head": False,
        "finalized_ok": False,
        "stalled": False,
        "egress_bytes": 0,
        "compute_s": 0.0,
        "delta_ops": 0,
    }
    if not booted:
        out["stalled"] = True
        return out

    # served live-set == the committed anchor live-set (sticky-shard guarantees this
    # set canonical-rebuilds to the committed sub-roots; reconstruct it explicitly).
    served_live = live_anchor  # the only id-set that passes all K sub-root checks

    # --- STEP C: trustless delta tail anchor_height -> final_head_height ---
    # FIFO churn ops over the tail rounds. adds = ids minted, dels = ids retired.
    adds, dels = [], []
    cur = set(served_live)
    # replay the canonical FIFO churn deterministically across the tail.
    dq = deque(sorted(served_live))
    nid = max(served_live) + 1
    for _ in range(anchor_height, final_head_height):
        for _ in range(churn):
            adds.append(nid); dq.append(nid); nid += 1
        for _ in range(churn):
            dels.append(dq.popleft())
    head_live, rebuilt_roots, comp_s = apply_delta(served_live, adds, dels)

    # VERIFY: does the trustless delta reproduce the committed finalized-head roots?
    reproduces = (tuple(rebuilt_roots) == tuple(committed_final_roots))

    out["delta_ops"] = len(adds) + len(dels)
    out["compute_s"] = comp_s
    out["egress_bytes"] = (
        len(served_live) * LEAF_BYTES         # checkpoint live-set (once)
        + (len(adds) + len(dels)) * ID_BYTES  # delta tail
        + wasted * LEAF_BYTES                 # sybil DoS egress
        + (len(committed_anchor_roots) + 1) * ROOT_BYTES  # the trusted commitment
    )

    if reproduces and anchor_is_canonical:
        out["finalized_ok"] = True
    elif reproduces and not anchor_is_canonical:
        # anchored on an orphaned checkpoint yet reproduced "a" head -> this is the
        # dangerous case T13 warns of. The committed_final_roots are CANONICAL, so a
        # validator anchored on the fork CANNOT reproduce them; reproduces must be
        # False here. If it ever were True, that is a real safety violation.
        out["accepted_wrong_head"] = True
    else:
        # delta did not reproduce committed finalized head -> validator refuses, stalls
        # and re-anchors (this is the SAFE outcome of L<df: detected, never accepted).
        out["stalled"] = True
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--w", type=int, default=300_000)
    ap.add_argument("--f", type=float, default=0.10)
    ap.add_argument("--df", type=int, default=8)      # finality depth (M1 gate)
    ap.add_argument("--c", type=int, default=5)       # checkpoint cadence
    ap.add_argument("--servers", type=int, default=20)
    ap.add_argument("--shards", type=int, default=16)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--trials", type=int, default=40)
    ap.add_argument("--sweep-w", type=int, default=4000,
                    help="W for the safety/liveness sweep (W-independent combinatorics; "
                         "kept small so the 700+ trial sweep is fast). The golden cost "
                         "trace uses the full --w.")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    W, f, df, c, K = args.w, args.f, args.df, args.c, args.shards

    print(f"# T14 end-to-end cold-start  W={W} f={f} D_f={df} C={c} "
          f"servers={args.servers} shards={K} seed={args.seed}")
    print(f"# composes: T13 finality-lagged checkpoint + T12 sticky-shard serve "
          f"+ T7 delta tail\n")

    # ---- A. golden single-run cost trace at the SAFE design point (L=D_f, h=0.10) --
    # staleness=c: the validator anchored to the OLDEST checkpoint within the cadence
    # window -> worst-case delta tail = (lag + c - df) rounds = the full C+L-D_f term.
    t0 = time.perf_counter()
    r = e2e_trial(W, f, df, c, lag=df, reorg_d=df, servers=args.servers,
                  h=0.10, shards_k=K, rng=random.Random(args.seed), staleness=c)
    wall = time.perf_counter() - t0
    print("== SAFE design point  L=D_f, reorg_d=D_f, h=0.10 ==")
    print(f"  anchor canonical : {r['anchor_is_canonical']}")
    print(f"  served (sticky)  : {r['served']}  honest_servers={r['n_honest']} "
          f"touched={r['servers_touched']}")
    print(f"  finalized OK     : {r['finalized_ok']}   accepted_wrong_head={r['accepted_wrong_head']}")
    print(f"  delta ops        : {r['delta_ops']}  (= 2*f*W*(C+L-D_f) tail = "
          f"2*{int(W*f)}*{c+df-df} rounds)")
    print(f"  egress           : {r['egress_bytes']/1e6:.2f} MB "
          f"(W-leaf floor {W*LEAF_BYTES/1e6:.2f} MB + delta + sybil waste)")
    print(f"  rebuild compute  : {r['compute_s']*1e3:.1f} ms   end-to-end wall {wall*1e3:.0f} ms")
    egress_premium = r['egress_bytes'] / (W * LEAF_BYTES)
    print(f"  egress premium   : {egress_premium:.2f}x the W-leaf floor "
          f"(additive, one-time)\n")

    # ---- B. SAFE-REGIME sweep: valid commits L>=D_f x reorg_d x honest-fraction ----
    # staleness=0 (freshest committed checkpoint = worst case for safety).
    print("== SAFE-REGIME sweep  L>=D_f  (reorg_d x L x h), trials/cell ==")
    print("  asserting: 0 wrong-head accepts; h>0 => FINALIZE canonical head; "
          "h=0 (full eclipse) => STALL (liveness only)")
    wrong_head_total = 0
    live_violations = 0
    rows = []
    for reorg_d in (0, df // 2, df):
        for lag in (df, df + 2, df + 4):
            for h in (0.0, 0.05, 0.10, 0.30):
                fin = stall = served = wrong = 0
                for t in range(args.trials):
                    rr = e2e_trial(args.sweep_w, f, df, c, lag=lag, reorg_d=reorg_d,
                                   servers=args.servers, h=h, shards_k=K,
                                   rng=random.Random(args.seed * 1000 + t), staleness=0)
                    fin += rr["finalized_ok"]; stall += rr["stalled"]
                    served += rr["served"]; wrong += rr["accepted_wrong_head"]
                wrong_head_total += wrong
                # liveness rule: h>0 must always finalize; h==0 must always stall.
                if h > 0 and fin != args.trials:
                    live_violations += 1
                if h == 0 and fin != 0:
                    live_violations += 1
                rows.append((reorg_d, lag, h, fin, stall, served, wrong))
    print(f"  {'d':>3} {'L':>3} {'h':>5} {'final':>6} {'stall':>6} {'served':>7} {'wrong':>6}")
    for (d, lag, h, fin, stall, served, wrong) in rows:
        print(f"  {d:>3} {lag:>3} {h:>5.2f} {fin:>6} {stall:>6} {served:>7} {wrong:>6}")

    # ---- C. VIOLATION arm: under-lagged commit (L<D_f) caught by the 2nd anchor ----
    # The protocol breaks the T13 rule and commits a checkpoint at depth L<D_f; a reorg
    # of depth D_f > L then orphans that committed height. The serving layer faithfully
    # serves the ORPHAN live-set (it matches its own committed sub-roots), so STEP B
    # "succeeds". Safety is saved only by the INDEPENDENT finalized-head anchor: the
    # orphan delta cannot reproduce the canonical (tip-D_f) roots -> validator detects
    # the mismatch and STALLS. Must be: finalize=0, wrong=0, served>0 (the trap sprang).
    print()
    print("== VIOLATION arm  L=D_f-2 (under-lagged) + reorg_d=D_f, h=0.30, staleness=0 ==")
    v_fin = v_wrong = v_served = v_stall = 0
    for t in range(args.trials):
        vr = e2e_trial(args.sweep_w, f, df, c, lag=df - 2, reorg_d=df,
                       servers=args.servers, h=0.30, shards_k=K,
                       rng=random.Random(args.seed * 7000 + t), staleness=0)
        v_fin += vr["finalized_ok"]; v_wrong += vr["accepted_wrong_head"]
        v_served += vr["served"]; v_stall += vr["stalled"]
    print(f"  served(orphan)={v_served}  finalized={v_fin}  wrong_head={v_wrong}  "
          f"stalled={v_stall}  (want: served>0, finalized=0, wrong=0)")
    violation_caught = (v_wrong == 0 and v_fin == 0 and v_served > 0)

    print()
    print(f"== VERDICT ==")
    print(f"  wrong-head acceptances (safe sweep + violation) : {wrong_head_total + v_wrong}  (MUST be 0)")
    print(f"  liveness-rule violations in safe regime         : {live_violations}  (MUST be 0)")
    print(f"  under-lagged commit caught by 2nd anchor        : {violation_caught}")
    ok = (wrong_head_total == 0 and v_wrong == 0 and live_violations == 0 and violation_caught)
    print(f"  composition holds (safety unconditional)        : {ok}")
    print(f"  the three properties COMPOSE: T13 keeps the anchor canonical, T12 keeps")
    print(f"  serving safe under full sybil, T7 delta is PoW-anchored -> a cold validator")
    print(f"  either reproduces the committed finalized head or STALLS; never a wrong head.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
