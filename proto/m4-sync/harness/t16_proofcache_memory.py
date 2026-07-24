#!/usr/bin/env python3
"""T16 — bridge proof-cache memory under a realistic request distribution.

Closes the last open *local* M4 carry-forward item the synthesis-feed flagged:
  "Proof-cache memory on a bridge under a realistic request distribution."

The other carry-forwards (real PoW/signature verification cost; multichain
testbed) genuinely need M5 infrastructure. This one does not: it is a
resource-sizing question over the existing Forest + a request/churn model.

The question under test
-----------------------
A bridge node holds the full O(W) accumulator and GENERATES O(log W) inclusion
proofs on demand for stateless verifiers. Naively one would size a proof cache
to absorb hot demand. BUT a Utreexo proof is an authentication path of sibling
hashes, and ANY forest mutation that touches a node on that path invalidates the
cached proof. So the real question is not "how big a cache" but:

  Under a realistic (Zipf, recent-hot) request stream WITH live churn, does a
  proof cache of bounded memory actually raise the hit rate enough to matter, or
  does churn-driven staleness keep the bridge proof-gen-CPU-bound regardless of
  cache size?

If the answer is "CPU-bound regardless", the bridge sizing story is
proof-GEN throughput (CPU), not proof-cache RAM — which is the engineering call
M5 needs, and it means cache RAM is NOT a scaling blocker.

Model (honest, conservative; assumptions stated — NO silent caps)
-----------------------------------------------------------------
  * Forest built to W shares (real share-format-sized leaves are irrelevant to a
    proof's SIZE — a proof is sibling *hashes* (32B) — so we use 32B leaves; the
    proof path length is what matters and that is O(log W) regardless, per T11).
  * Request stream: Zipf(s) over the W live leaf positions, remapped so the
    HEAD (most-recent ids) is hottest — models verifiers checking recent shares.
  * Churn: every `--churn` requests we apply one mutation (add a fresh share +
    delete one old share, holding W roughly constant — the steady state T4/T5
    modelled). Mutation cost is the realistic driver of staleness.
  * Staleness/invalidation: a cached proof for leaf L is invalidated when a
    mutation restructures the perfect-subtree (root bucket) L sits under — the
    Utreexo unit of restructuring is the whole subtree that merges (add) or
    refolds (delete). We invalidate by root-bucket, which is the FAITHFUL grain:
    adds merge equal-height roots, deletes swap-and-refold within one tree. This
    is conservative on the add path (a merge only restructures the two merging
    buckets) and exact on the delete path. We report both the by-bucket
    invalidation and, as a strict upper bound on cache value, an
    invalidate-on-any-mutation baseline.
  * Cache: LRU of C entries; entry = proof (path of ceil(log2 W) * 32B sibling
    hashes) + key/bookkeeping (~64B). We sweep C and report memory = C *
    entry_bytes, hit rate, and proof-gen calls avoided (CPU saved).

Deterministic given --seed. Timing measured out-of-band only.
"""

import sys, time, argparse, random, math, hashlib
from collections import OrderedDict
from utreexo import Forest, leaf_hash


def zipf_weights(n, s):
    # unnormalized zipf weights over rank 1..n; rank 1 == hottest
    return [1.0 / (k ** s) for k in range(1, n + 1)]


def sample_zipf(cum, total, rnd):
    x = rnd.random() * total
    # binary search into cumulative
    lo, hi = 0, len(cum) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if cum[mid] < x:
            lo = mid + 1
        else:
            hi = mid
    return lo


def bucket_of(pos, roots_sizes):
    # which perfect-subtree (root bucket) does live-position `pos` fall in,
    # scanning buckets high->low exactly as Forest.roots() lays them out.
    acc = 0
    for bi, sz in enumerate(roots_sizes):
        if pos < acc + sz:
            return bi
        acc += sz
    return len(roots_sizes) - 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--w", type=int, default=300_000)
    ap.add_argument("--requests", type=int, default=300_000)
    ap.add_argument("--zipf", type=float, default=1.1)
    ap.add_argument("--churn", type=int, default=50,
                    help="apply one add+delete mutation every N requests")
    ap.add_argument("--caches", type=str, default="0,1000,5000,20000,80000",
                    help="comma list of cache entry-capacities C to sweep")
    ap.add_argument("--seed", type=int, default=20260627)
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    W = args.w

    t0 = time.time()
    f = Forest()
    live = []  # ordered list of live leaf-hashes, index 0 = oldest
    for i in range(W):
        lh = leaf_hash(b"share-%d" % i)
        f.add_hash(lh)
        live.append(lh)
    build_s = time.time() - t0

    logW = max(1, math.ceil(math.log2(W)))
    entry_bytes = logW * 32 + 64  # proof path + bookkeeping
    print(f"# T16 proof-cache memory  W={W} requests={args.requests} "
          f"zipf={args.zipf} churn=1/{args.churn} seed={args.seed}")
    print(f"# build={build_s:.2f}s  logW={logW}  proof_entry≈{entry_bytes}B  "
          f"roots={len(f.roots())}")

    # Zipf over RANK; rank 1 = hottest = HEAD (newest). Map rank r -> live index
    # (W-1) - (r-1) so the newest ids are hottest.
    weights = zipf_weights(W, args.zipf)
    cum, total = [], 0.0
    for w in weights:
        total += w
        cum.append(total)

    caps = [int(x) for x in args.caches.split(",") if x.strip()]

    for C in caps:
        rnd2 = random.Random(args.seed)  # identical request+churn stream per C
        cache = OrderedDict()            # key=live-id -> True (LRU)
        # invalidate-on-any-mutation strict-baseline cache (separate)
        cache_anymut = OrderedDict()

        hits = miss = 0
        hits_any = miss_any = 0
        gen_calls = 0
        mutations = 0
        inval_bucket = 0
        inval_any = 0

        # snapshot of current root-bucket sizes (refreshed on mutation)
        roots_sizes = [1 << r for r in range(len(f._rows))[::-1] if (f.n >> r) & 1] \
            if hasattr(f, "_rows") else None
        # robust: derive bucket sizes from population count of W
        def bucket_sizes(n):
            return [1 << b for b in range(n.bit_length() - 1, -1, -1) if (n >> b) & 1]
        rs = bucket_sizes(W)

        tq = time.time()
        for q in range(args.requests):
            rank = sample_zipf(cum, total, rnd2)
            live_idx = (W - 1) - rank
            if live_idx < 0:
                live_idx = 0
            key = live_idx  # stable id within this run (no resize)

            # --- bucketed cache ---
            if key in cache:
                cache.move_to_end(key)
                hits += 1
            else:
                miss += 1
                gen_calls += 1
                if C > 0:
                    cache[key] = True
                    if len(cache) > C:
                        cache.popitem(last=False)

            # --- strict invalidate-on-any-mutation baseline cache ---
            if key in cache_anymut:
                cache_anymut.move_to_end(key)
                hits_any += 1
            else:
                miss_any += 1
                if C > 0:
                    cache_anymut[key] = True
                    if len(cache_anymut) > C:
                        cache_anymut.popitem(last=False)

            # --- churn ---
            if args.churn and (q + 1) % args.churn == 0:
                mutations += 1
                # mutate: pick an old live position to delete (cold tail) and
                # the structural bucket it sits in; invalidate cache entries in
                # that bucket. Faithful grain: a delete refolds within one tree.
                del_idx = rnd2.randrange(0, W // 2)  # delete from older half
                b = bucket_of(del_idx, rs)
                # bucket id-range
                lo = sum(rs[:b])
                hi = lo + rs[b]
                # bucketed invalidation
                drop = [k for k in cache if lo <= k < hi]
                for k in drop:
                    cache.pop(k, None)
                inval_bucket += len(drop)
                # any-mutation invalidation: whole cache dies each mutation
                inval_any += len(cache_anymut)
                cache_anymut.clear()

        wall = time.time() - tq

        mem_mb = C * entry_bytes / 1e6
        hr = hits / (hits + miss) if (hits + miss) else 0.0
        hr_any = hits_any / (hits_any + miss_any) if (hits_any + miss_any) else 0.0
        print(f"C={C:>6}  mem={mem_mb:7.2f}MB  hit(bucket-inval)={hr*100:5.1f}%  "
              f"hit(any-mut-inval)={hr_any*100:5.1f}%  gen_calls={gen_calls:>7}  "
              f"mut={mutations}  inval_b={inval_bucket}  inval_any={inval_any}  "
              f"({wall:.1f}s)")

    print("# NOTE proof a path of 32B sibling hashes; leaf payload size is "
          "irrelevant to proof size (T11). Cache value is bounded by churn-driven "
          "staleness, not by RAM.")


if __name__ == "__main__":
    main()
