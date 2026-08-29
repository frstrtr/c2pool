# T16 — bridge proof-cache memory under a realistic request distribution

Closes the last open **local** M4 carry-forward item from the synthesis-feed:
*"Proof-cache memory on a bridge under a realistic request distribution."*
(The other carry-forwards — real PoW/signature *verification* cost, and the
multichain testbed — genuinely need M5 infrastructure; this one did not.)

Reproduce: `harness/t16_proofcache_memory.py`; raw in `out/t16-proofcache-w300k.txt`.

## Question
A bridge holds the full O(W) accumulator and GENERATES O(log W) inclusion proofs
on demand for stateless verifiers. Naively, size a proof cache to absorb hot
demand. But a Utreexo proof is an authentication path of sibling hashes, and any
forest mutation touching a node on that path invalidates the cached proof. So:
does a bounded-memory proof cache actually raise the hit rate under a realistic
(Zipf, recent-hot) request stream WITH live churn — or does churn-driven
staleness keep the bridge proof-GEN-CPU-bound regardless of cache RAM?

## Model (assumptions stated — no silent caps)
- W=300K live shares, 32B leaves (proof SIZE is sibling *hashes*, independent of
  share-format payload size — established T11/T15), logW=19, proof entry ≈ 672B.
- Requests: Zipf(s=1.1) over live positions, remapped so the HEAD (newest ids)
  is hottest — models verifiers checking recent shares.
- Churn: one add+delete mutation every N requests (steady-state W, per T4/T5).
- Invalidation grain = **root-bucket** (the Utreexo unit of restructuring: adds
  merge equal-height roots, deletes swap-and-refold within one tree). Faithful;
  conservative on the add path, exact on delete. Reported alongside a strict
  **invalidate-on-any-mutation** upper-bound baseline.
- Cache: LRU of C entries; memory = C · 672B. Deterministic given --seed.

## Results (W=300K, 300K requests, Zipf 1.1)

| C (entries) | cache RAM | hit% (bucket-inval, faithful) | hit% (any-mut, strict LB) | proof-gen calls |
|------------:|----------:|------------------------------:|--------------------------:|----------------:|
|           0 |    0.00MB |                          0.0% |                      0.0% |         300,000 |
|       1,000 |    0.67MB |                         64.6% |                     23.0% |         106,177 |
|       5,000 |    3.36MB |                         76.7% |                     23.0% |          69,897 |
|      20,000 |   13.44MB |                         83.9% |                     23.0% |          48,441 |
|      80,000 |   53.76MB |                         84.0% |                     23.0% |          48,134 |

## Findings
1. **Cache benefit SATURATES at ~13 MB.** Hit rate plateaus at ~84% by
   C=20,000 (13.4 MB); quadrupling to 53.8 MB adds nothing (84.0% vs 83.9%). The
   ceiling is the Zipf hot-set + churn staleness, **not** capacity. A bridge
   needs single-digit-to-low-tens MB of proof cache and no more.
2. **The faithful hit rate is churn-INVARIANT.** At C=5,000 the bucketed hit
   rate is 76.7% under both 1/50 and 1/10 churn (3× heavier). Reason: bucketed
   invalidation only evicts cold-tail buckets, which a head-hot Zipf stream
   rarely caches. The strict any-mutation baseline DOES fall with churn
   (23% → 8.7%) — it bounds the pathological grain but is not the real grain.
3. **Residual misses are CPU-bound, not RAM-bound.** The ~16% irreducible miss
   stream is proof-GENERATION work: each is an O(log W)=19-sibling-hash path
   walk. No amount of RAM removes it; it is throughput, not memory.

## Verdict
**Bridge proof-serving is proof-gen-CPU-bound, not RAM-bound. Proof-cache memory
is NOT an M4 scaling blocker** — ~13 MB saturates the benefit at W=300K, and the
hit rate is robust to churn. The M5 engineering call is proof-GEN throughput
(CPU), which is O(log W) per request and fully tractable (T11 showed proof work
grows +1 log-step from W=300K to 1M, not linearly). This composes with the T9/T12
result that bridges serve 32B-leaf snapshots/shards (not raw shares): a bridge is
a modest-RAM, CPU-sized proof server, and neither dimension is a feasibility wall.

M4 local feasibility: all locally-answerable items now **CLOSED**. Remaining open
items (real PoW/sig verification cost; proof-cache under a *measured* production
request trace; multichain testbed) are explicit **M5** carry-forwards.
