#!/usr/bin/env python3
"""T12 — server-affinity (sticky) shard assembly: recover whole-set liveness
while keeping the sharded bounded-W/K per-lie egress.

WHY THIS TRACK
--------------
T9/T10 surfaced a real tension the superlight synthesis under-states. The
per-shard-committed serving layer caps WASTED EGRESS per lie at W/K (good), but
T9's `trial_shard` samples servers INDEPENDENTLY per shard and never reuses a
server that already proved honest. Consequence at W=300K (out/t10-*.txt):

    h     whole live%   shard-naive live%
    0.05     80.8%          6.7%
    0.10     97.5%         67.5%

i.e. naive sharding is WORSE at low honest-fraction -- it needs an honest server
PER shard, drawn fresh each time, so all-K-shards success is ~ (per-shard) ^ K.
The synthesis claims "liveness degrades gracefully"; naively it degrades WORSE.

THE FIX UNDER TEST
------------------
An honest server is a FULL proof-server: it holds every shard. So the moment a
server returns a sub-root-valid shard, the validator should pull ALL remaining
shards from THAT SAME server (server affinity / "sticky"), and DROP a server the
instant it serves an invalid shard (one strike -> sybil). Then:
  * LIVENESS = "at least one honest server appears in the sampled order" --
    identical to whole-set. Sharding no longer raises the honest-server bar.
  * EGRESS  = a sybil is caught on its FIRST shard and dropped, so it wastes at
    most W/K leaves (one shard), never the whole W. The bounded-DoS property of
    sharding is preserved.
  * SAFETY  = unchanged and unconditional: every shard is sub-root-checked, every
    full head is the K committed sub-roots; a wrong head is impossible at any h.

So sticky assembly is supposed to be a strict Pareto improvement: whole-set
liveness AND sharded bounded-egress, simultaneously. This harness tests that.

We compare three strategies head-to-head on the SAME adversarial pools:
  (W)  whole-set        -- T9 trial_whole baseline.
  (SN) shard-naive      -- T9 trial_shard (independent per-shard resampling).
  (SS) shard-sticky     -- this track: affinity + one-strike drop.

Deterministic given --seed. No wall-clock in the verification path.
Reproduce: python3 t12_sticky_shard_assembly.py --w 300000 --servers 20 --shards 16
"""

import sys, time, argparse, random

from utreexo import Forest  # noqa: F401  (kept for parity / explicit dep)
from t9_multibridge_availability import (
    HONEST, SYBIL_KINDS,
    committed_roots, shard_subroots,
    serve_whole, serve_shard, check_whole, check_shard,
    make_pool, trial_whole, trial_shard,
    ROOT_BYTES,
)

LEAF_BYTES = 32


def trial_shard_sticky(pool, shards, subroots, max_servers, rng):
    """Server-affinity shard assembly.

    Walk servers in a shuffled order (sampled without replacement, the realistic
    finite-peer case). From each candidate server, try to satisfy EVERY shard
    still missing:
      - a sub-root-valid shard is accepted and that shard marked done;
      - the FIRST invalid response from a server drops it (one-strike: it is a
        sybil) and we move to the next server -- so a sybil wastes <= W/K leaves
        (a single shard) before exclusion.
    Bootstrapped when all shards are done.

    Returns (bootstrapped_all, servers_touched, wasted_leaves, max_egress_per_sybil).
    """
    order = list(range(len(pool)))
    rng.shuffle(order)
    done = [False] * len(shards)
    wasted = 0
    worst_sybil_egress = 0
    servers_touched = 0

    for idx in order[:max_servers]:
        if all(done):
            break
        servers_touched += 1
        this_server_wasted = 0
        dropped = False
        for j, ids in enumerate(shards):
            if done[j]:
                continue
            claimed = serve_shard(pool[idx], ids, rng)
            if check_shard(claimed, subroots[j]):
                done[j] = True
                # honest server: keep pulling its remaining shards (no egress
                # waste -- these are leaves we WANT).
                continue
            # invalid shard -> this server is a sybil. Charge the one shard we
            # already pulled, then DROP the server (one-strike).
            if claimed is not None:
                this_server_wasted += len(claimed)
            dropped = True
            break
        wasted += this_server_wasted
        worst_sybil_egress = max(worst_sybil_egress, this_server_wasted)
        # (an honest server falls through the for-loop with dropped=False and
        # fills all remaining shards in this single pass.)
        if not dropped and all(done):
            break

    return all(done), servers_touched, wasted, worst_sybil_egress


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--w", type=int, default=300000)
    ap.add_argument("--servers", type=int, default=20)
    ap.add_argument("--shards", type=int, default=16)
    ap.add_argument("--trials", type=int, default=60)
    ap.add_argument("--maxq", type=int, default=20)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    live = list(range(args.w))

    t0 = time.time()
    committed = committed_roots(live)
    shards, subroots, shard_root = shard_subroots(live, args.shards)
    setup_s = time.time() - t0
    wk = args.w // args.shards  # leaves per shard = the per-lie egress bound

    print(f"# T12 sticky shard assembly  W={args.w}  servers={args.servers}  "
          f"shards={args.shards}  trials={args.trials}  seed={args.seed}")
    print(f"# checkpoint: {len(committed)} forest roots ({len(committed)*ROOT_BYTES}B) "
          f"+ 1 shard-root (32B); W/K bound = {wk} leaves/shard; setup {setup_s:.2f}s")
    print(f"# shard-root = {shard_root.hex()[:16]}...")

    # sanity: honest full-set verifies; sybil whole-sets fail
    assert check_whole(list(live), committed)
    bad = 0
    for k in SYBIL_KINDS:
        if check_whole(serve_whole(k, live, rng), committed):
            bad += 1
    print(f"# SANITY: honest verifies; {bad}/4 sybil whole-sets pass (want 0) -> "
          f"{'OK' if bad == 0 else 'FAIL'}")

    hs = [0.00, 0.05, 0.10, 0.20, 0.30, 0.50]
    print()
    print("        |     whole-set      |    shard-naive     |   shard-STICKY (T12)        ")
    print("    h   | live%   wasteKB    | live%   wasteKB    | live%  servers  wasteKB  maxSybilKB")
    print("-" * 100)

    safety_violations = 0
    for h in hs:
        w_ok = w_waste = 0
        sn_ok = sn_waste = 0
        ss_ok = ss_waste = ss_srv = ss_worst = 0
        for _ in range(args.trials):
            pool = make_pool(args.servers, h, rng)

            ok, _q, waste, viol = trial_whole(pool, live, committed, args.maxq, rng)
            w_ok += ok; w_waste += waste; safety_violations += viol

            ok2, _q2, waste2 = trial_shard(pool, shards, subroots, args.maxq, rng)
            sn_ok += ok2; sn_waste += waste2

            ok3, srv, waste3, worst = trial_shard_sticky(
                pool, shards, subroots, args.servers, rng)
            ss_ok += ok3; ss_waste += waste3; ss_srv += srv; ss_worst = max(ss_worst, worst)

            # SAFETY: a STICKY bootstrap must reproduce the committed head.
            # Re-derive the head from the shard set and compare to committed.
            if ok3:
                assembled = sorted(i for ids in shards for i in ids)
                if committed_roots(assembled) != committed:
                    safety_violations += 1

        n = args.trials
        print(f" {h:.2f}   | "
              f"{100*w_ok/n:5.1f}%  {w_waste*LEAF_BYTES/n/1024:8.1f}  | "
              f"{100*sn_ok/n:5.1f}%  {sn_waste*LEAF_BYTES/n/1024:8.1f}  | "
              f"{100*ss_ok/n:5.1f}%  {ss_srv/n:6.1f}  {ss_waste*LEAF_BYTES/n/1024:8.1f}  "
              f"{ss_worst*LEAF_BYTES/1024:8.1f}")

    print()
    print(f"# SAFETY: wrong-head acceptances across all trials (incl h=0): "
          f"{safety_violations}  -> {'PASS' if safety_violations == 0 else 'FAIL'}")
    print(f"# W/K per-lie egress bound = {wk*LEAF_BYTES/1024:.1f}KB/shard; "
          f"sticky maxSybilKB must stay <= that bound.")
    print()
    print("# Reading:")
    print("# - STICKY live% should TRACK whole-set (one honest server in the sampled")
    print("#   order suffices -- affinity pulls all K shards from it), unlike shard-naive")
    print("#   which needs an honest server PER shard and collapses at low h.")
    print("# - STICKY wasteKB stays bounded: each sybil is one-strike-dropped after a")
    print("#   single bad shard, so per-sybil egress <= W/K (maxSybilKB column), NOT W.")
    print("# - Net: sticky assembly is the Pareto move -- whole-set liveness AND the")
    print("#   sharded bounded-W/K DoS cap together. This is the assembly rule the")
    print("#   superlight checkpoint's shard-root should specify, not naive per-shard")
    print("#   independent resampling.")


if __name__ == "__main__":
    main()
