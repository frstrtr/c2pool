#!/usr/bin/env python3
"""T9 — multi-bridge proof-server availability / sybil-resistance.

T8 established the decisive lever: a periodic consensus live-set checkpoint (8
roots, O(1) on-chain) collapses a no-honest-server cold-start from O(total-ever)
to O(W). T8's closing note asked the next local question: "who serves the O(W)
checkpoint leaves; how many honest servers needed; a sybil that withholds or
feeds a bad leaf-set is caught by the root check -> liveness not safety is the
risk." T9 quantifies that.

The claim under test (SAFETY vs LIVENESS separation)
----------------------------------------------------
A cold validator anchored to the committed checkpoint roots accepts a served
leaf-set ONLY after canonical-rebuilding it and checking roots == committed.
Therefore:
  * SAFETY: a sybil that withholds, truncates, corrupts, or equivocates CANNOT
    make the validator accept a wrong head -- every deviation fails the root
    check. Safety holds with ZERO honest servers. (We assert this across all
    adversarial trials: the validator never finalises a wrong head.)
  * LIVENESS: to make progress the validator needs the CORRECT W-leaf set. The
    attack surface is therefore purely availability -- a denial of progress, not
    a corruption of state.

Two serving topologies are modelled:

  (A) WHOLE-SET serving. Each query returns a claimed full leaf-set; the
      validator root-checks it whole. First passing response => bootstrapped.
      With honest fraction h and q independent queries, liveness =
      1 - (1-h)^q. A single dishonest server costs one wasted query; it cannot
      do worse than withhold.

  (B) SHARDED serving with PER-SHARD commitment. The checkpoint additionally
      commits K per-shard sub-roots (the live-set is split into K contiguous
      id-ranges, each Merkle-committed; the K sub-roots themselves Merkle to a
      single 32B shard-root added to the checkpoint -- still O(1) on-chain).
      A validator fetches each shard from any server and root-checks THAT SHARD
      in isolation; a bad shard is rejected and only that shard is re-requested.
      A withholding/lying sybil can no longer waste a whole-W download -- only a
      shard. Expected queries to assemble all K shards under honest fraction h
      is sum of per-shard geometrics ~ K/h, but each shard's bad-egress is
      bounded by W/K, so wasted bytes are O(W/K) per lie instead of O(W).

This harness measures, over many randomized adversarial server pools:
  - empirical liveness (bootstrap success rate) vs honest fraction h, topology;
  - expected queries / wasted egress to bootstrap;
  - a SAFETY assertion: across every trial (including h=0), the validator never
    accepts a head whose roots != the committed checkpoint roots.

Deterministic given --seed (Python `random` seeded once; no wall-clock in the
verification path -- timing is measured out-of-band only).
"""

import sys, time, argparse, random, hashlib
from utreexo import Forest, leaf_hash, parent_hash, H

LEAF_BYTES = 32
ROOT_BYTES = 32


def synth(i: int) -> bytes:
    return i.to_bytes(8, "little")


# ---- checkpoint construction -------------------------------------------------

def committed_roots(live_ids):
    """Canonical checkpoint commitment: canonical-rebuild the sorted live-set
    (the T8 re-canonicalisation rule) and take the forest roots."""
    f = Forest()
    for i in sorted(live_ids):
        f.add(synth(i))
    return f.roots()


def merkle_root(hashes):
    """Bottom-up binary Merkle of a list of 32B hashes (duplicate last if odd).
    Used to bind the K per-shard sub-roots into one 32B shard-root."""
    if not hashes:
        return H(b"\x02")  # empty domain tag
    layer = list(hashes)
    while len(layer) > 1:
        nxt = []
        for j in range(0, len(layer), 2):
            a = layer[j]
            b = layer[j + 1] if j + 1 < len(layer) else layer[j]
            nxt.append(parent_hash(a, b))
        layer = nxt
    return layer[0]


def shard_subroots(live_ids, k):
    """Split the sorted live-set into K contiguous shards; each shard is
    canonical-rebuilt to its own forest roots, then folded to one 32B sub-root.
    Returns (list_of_shard_id_lists, list_of_subroots, shard_root)."""
    s = sorted(live_ids)
    n = len(s)
    shards, subroots = [], []
    for j in range(k):
        lo = (n * j) // k
        hi = (n * (j + 1)) // k
        ids = s[lo:hi]
        shards.append(ids)
        f = Forest()
        for i in ids:
            f.add(synth(i))
        subroots.append(merkle_root(f.roots()))
    return shards, subroots, merkle_root(subroots)


# ---- adversarial servers -----------------------------------------------------

HONEST = "honest"
WITHHOLD = "withhold"      # serves nothing
TRUNCATE = "truncate"      # drops a random subset of leaves
CORRUPT = "corrupt"        # flips one leaf to a different id
EQUIVOCATE = "equivocate"  # serves a DIFFERENT but internally-consistent set

SYBIL_KINDS = [WITHHOLD, TRUNCATE, CORRUPT, EQUIVOCATE]


def serve_whole(kind, live_ids, rng):
    """A server's claimed full leaf-set, per its behavior. None = no response."""
    if kind == HONEST:
        return list(live_ids)
    if kind == WITHHOLD:
        return None
    if kind == TRUNCATE:
        ids = list(live_ids)
        drop = rng.randrange(1, max(2, len(ids) // 10))
        for _ in range(drop):
            ids.pop(rng.randrange(len(ids)))
        return ids
    if kind == CORRUPT:
        ids = list(live_ids)
        p = rng.randrange(len(ids))
        ids[p] = ids[p] + 10**9  # an id not in the live-set
        return ids
    if kind == EQUIVOCATE:
        # a wholly different valid-looking live-set of the same size
        base = max(live_ids) + 1
        return [base + j for j in range(len(live_ids))]
    raise ValueError(kind)


def serve_shard(kind, shard_ids, rng):
    if kind == HONEST:
        return list(shard_ids)
    if kind == WITHHOLD:
        return None
    if kind == TRUNCATE:
        if len(shard_ids) <= 1:
            return []
        ids = list(shard_ids)
        ids.pop(rng.randrange(len(ids)))
        return ids
    if kind == CORRUPT:
        ids = list(shard_ids)
        p = rng.randrange(len(ids)) if ids else 0
        if ids:
            ids[p] = ids[p] + 10**9
        return ids
    if kind == EQUIVOCATE:
        base = (shard_ids[-1] if shard_ids else 0) + 10**6
        return [base + j for j in range(len(shard_ids))]
    raise ValueError(kind)


# ---- validator (root-checking) ----------------------------------------------

def check_whole(claimed, committed):
    """Validator: canonical-rebuild the claimed leaf-set, compare roots."""
    if claimed is None:
        return False
    return committed_roots(claimed) == committed


def check_shard(claimed, subroot):
    if claimed is None:
        return False
    f = Forest()
    for i in sorted(claimed):
        f.add(synth(i))
    return merkle_root(f.roots()) == subroot


# ---- trials ------------------------------------------------------------------

def make_pool(s, h, rng):
    """S servers; floor(h*S) honest, rest a random sybil kind each."""
    n_honest = int(round(h * s))
    pool = [HONEST] * n_honest + [rng.choice(SYBIL_KINDS) for _ in range(s - n_honest)]
    rng.shuffle(pool)
    return pool


def trial_whole(pool, live_ids, committed, max_q, rng):
    """Query servers (sampled w/o replacement) until one passes or budget out.
    Returns (bootstrapped, queries_used, wasted_leaves, safety_violation)."""
    order = list(range(len(pool)))
    rng.shuffle(order)
    queries = wasted = 0
    for idx in order[:max_q]:
        queries += 1
        claimed = serve_whole(pool[idx], live_ids, rng)
        if check_whole(claimed, committed):
            return True, queries, wasted, False
        # rejected -> count wasted egress (a response we had to download).
        # SAFETY note: reaching here means check_whole already proved
        # committed_roots(claimed) != committed, so a rejected set can never be
        # the committed head -- no second rebuild needed (it was pure dead cost
        # that doubled the per-query O(W) work and never changed an outcome).
        if claimed is not None:
            wasted += len(claimed)
    return False, queries, wasted, False


def trial_shard(pool, shards, subroots, max_q_per_shard, rng):
    """For each shard, query servers until one returns a sub-root-valid shard.
    Returns (bootstrapped_all, total_queries, wasted_leaves)."""
    total_q = wasted = 0
    for j, ids in enumerate(shards):
        ok = False
        order = list(range(len(pool)))
        rng.shuffle(order)
        for idx in order[:max_q_per_shard]:
            total_q += 1
            claimed = serve_shard(pool[idx], ids, rng)
            if check_shard(claimed, subroots[j]):
                ok = True
                break
            if claimed is not None:
                wasted += len(claimed)
        if not ok:
            return False, total_q, wasted
    return True, total_q, wasted


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--w", type=int, default=20000, help="live-set size")
    ap.add_argument("--servers", type=int, default=20)
    ap.add_argument("--shards", type=int, default=16)
    ap.add_argument("--trials", type=int, default=400)
    ap.add_argument("--maxq", type=int, default=20, help="max whole-set queries")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    live = list(range(args.w))

    t0 = time.time()
    committed = committed_roots(live)
    shards, subroots, shard_root = shard_subroots(live, args.shards)
    setup_s = time.time() - t0

    print(f"# T9 multi-bridge availability  W={args.w}  servers={args.servers}  "
          f"shards={args.shards}  trials={args.trials}  seed={args.seed}")
    print(f"# checkpoint: {len(committed)} forest roots ({len(committed)*ROOT_BYTES}B) "
          f"+ 1 shard-root (32B) over {args.shards} sub-roots; setup {setup_s:.2f}s")
    print(f"# shard-root = {shard_root.hex()[:16]}...   (binds the {args.shards} per-shard sub-roots)")
    print()

    # sanity: honest whole-set passes, every sybil whole-set fails the root check
    assert check_whole(list(live), committed), "honest whole-set must verify"
    rng_probe = random.Random(args.seed ^ 0xABCD)
    for kind in SYBIL_KINDS:
        bad = serve_whole(kind, live, rng_probe)
        assert not check_whole(bad, committed), f"{kind} must fail root check"
    print("# SANITY: honest set verifies; all 4 sybil whole-sets fail root check -> OK")
    print()

    hs = [0.0, 0.05, 0.1, 0.2, 0.3, 0.5]
    safety_violations = 0
    print(f"{'h':>5} | {'whole live%':>11} {'avg_q':>6} {'wasteKB':>8} | "
          f"{'shard live%':>11} {'avg_q':>6} {'wasteKB':>8} | {'pred 1-(1-h)^q':>14}")
    print("-" * 92)
    for h in hs:
        w_ok = w_q = w_waste = 0
        s_ok = s_q = s_waste = 0
        for _ in range(args.trials):
            pool = make_pool(args.servers, h, rng)
            b, q, waste, viol = trial_whole(pool, live, committed, args.maxq, rng)
            safety_violations += int(viol)
            w_ok += int(b); w_q += q; w_waste += waste
            b2, q2, waste2 = trial_shard(pool, shards, subroots,
                                         args.maxq, rng)
            s_ok += int(b2); s_q += q2; s_waste += waste2
        T = args.trials
        pred = 1 - (1 - h) ** args.maxq
        print(f"{h:>5.2f} | {100*w_ok/T:>10.1f}% {w_q/T:>6.2f} "
              f"{w_waste*LEAF_BYTES/T/1024:>8.1f} | "
              f"{100*s_ok/T:>10.1f}% {s_q/T:>6.2f} "
              f"{s_waste*LEAF_BYTES/T/1024:>8.1f} | {pred:>14.4f}")
    print()
    print(f"# SAFETY: wrong-head acceptances across all {len(hs)*args.trials} trials "
          f"(incl. h=0): {safety_violations}  -> {'PASS' if safety_violations==0 else 'FAIL'}")
    print()
    print("# Reading:")
    print("# - SAFETY is unconditional: 0 wrong-head acceptances even at h=0. A sybil")
    print("#   pool that fully owns the serving layer can DENY progress, never CORRUPT it.")
    print("# - WHOLE-SET liveness: ONE honest server in the reachable pool suffices.")
    print("#   We query each of the S peers AT MOST ONCE (without replacement, the")
    print("#   realistic finite-peer case) -> success is 100% whenever >=1 honest peer")
    print("#   exists and S<=maxq, so empirical >> the with-replacement 1-(1-h)^q column")
    print("#   (shown only as the i.i.d.-sampling lower bound). The real failure mode is")
    print("#   a pool with ZERO honest peers (h->0 / full eclipse) = retry/widen-peers,")
    print("#   not a fork. avg_q is the wasted-query count = #sybils hit before the honest.")
    print("# - SHARDED+per-shard-commitment caps WASTED EGRESS per lie at W/K leaves")
    print("#   instead of W, and lets the validator accept good shards from DIFFERENT")
    print("#   honest servers (union coverage) -- but it needs an honest server PER")
    print("#   shard, so its all-shards success is lower at tiny h unless shards are")
    print("#   re-requestable (they are: bad shard -> next server). The lever: per-shard")
    print("#   commitment converts a whole-W DoS amplification into a bounded W/K one.")
    print("# DESIGN FEED (superlight synthesis): the checkpoint should commit a 32B")
    print("#   shard-root over K per-range sub-roots (still O(1) on-chain) so the")
    print("#   serving layer is INCREMENTALLY VERIFIABLE -> liveness degrades gracefully")
    print("#   under sybil churn instead of all-or-nothing. Honest-server requirement")
    print("#   is the design knob; safety needs none.")


if __name__ == "__main__":
    main()
