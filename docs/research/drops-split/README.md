# Splitting identities under the sub-threshold estimator (DROPS)

Research note, 2026-09-30. External review, "a note on the paper's own
arguments": N independent unbiased estimates carry about 1/N the variance of
one, so a miner that splits across identities draws steadier income; neutral
on the mean, better on variance. Portable: `split.cpp` is self-contained, and
`module_check.cpp` builds against `src/`.

## Short answer

- **The review understates it.** On the XMR geometry the shipped COMBINED
  K-min estimator is **not neutral on the mean**. It is biased between −8% and
  +19% for the small miners DROPS exists for, and the bias moves with the
  split. A miner at about one share per interval gets 0.935 of its work on one
  identity and 1.187 split over 16 identities, i.e. +27% for splitting. This is
  measured on the shipped module (`ReceiptCollector` + `estimate_combined`,
  K = 4, DROPS-JK, REPLACE).
- **The root cause is the base design, not a bug.** The estimator spends a
  fixed budget per identity: K order statistics per (payee, interval).
  - Anything with a per-identity budget rewards splitting, because splitting
    buys budget.
  - The J < K rule and the XMR drops floor add a branch on data the miner
    produces, so the mean is not preserved either (the same flaw as EST_ONLY's
    branch on S, one level down).
- **Two split-neutral replacements keep the base ideas**: work measured by
  proof-of-work order statistics, the payee bound before the hash, a committed
  constant, and no trust.
  - **E2, count at the floor.** Every raindrop is one floor unit of work.
    Unbiased and exactly split-neutral in mean and variance. It costs nothing
    extra on XMR, where every raindrop is already relayed and RandomX-verified
    by every node; today's estimator throws all but 4 of them away.
  - **E3, pool-wide bottom-k.** The k smallest hashes of the **whole pool**
    per interval, each worth 1/τ, where τ is the (k+1)-th smallest (priority
    sampling). Unbiased, exactly split-neutral in mean and variance, and it
    bounds verification to about `(k+1)(1 + ln(J/(k+1)))` per interval
    pool-wide, instead of every raindrop.

## The geometry

On XMR (`xmr_drops_wiring.hpp`):

- A raindrop is a RandomX hash meeting `share_diff / 64` (kDropsFloorDiv).
- It is minted for every such hash, flooded on the receipt relay, and
  RandomX-verified by every receiver, like a share.
- The harvester keeps, per (payee, interval), the K = 4 smallest raindrops
  and the share count S.
- Credit is `(S + K − 1) / u_(S+K)` when J ≥ K. Otherwise it is the shares
  only (DROPS-JK). The REPLACE composition swaps that for the share credit.

Model:

- Hashes are a Poisson process on the floor-normalised value `u ∈ [0, 1)`.
  `u < 1` is a raindrop and `u < 1/64` is a share.
- A miner of rate λ has λ hashes below the floor per interval, so λ = 64 is
  one share per interval.
- The rest of the pool is 6400 raindrops per interval (100 shares).
- Each row below is 200 000 intervals; `module_check.cpp` runs 100 000.

## Results

Mean credit / true work, and CV per interval:

| λ | N ids | E1 shipped K-min | E2 count | E3 k=64 | E3 k=512 |
|---|---|---|---|---|---|
| 1 | 1 | 1.037 / 7.60 | 0.996 / 1.00 | 0.984 / 10.2 | 0.998 / 3.56 |
| 1 | 16 | 1.011 / 7.96 | 1.001 / 1.00 | 1.017 / 9.99 | 1.005 / 3.53 |
| 4 | 1 | **1.166** / 2.28 | 1.000 / 0.50 | 0.969 / 5.10 | 0.994 / 1.78 |
| 4 | 16 | 1.000 / 4.01 | 1.001 / 0.50 | 0.997 / 5.06 | 1.001 / 1.77 |
| 16 | 1 | 0.971 / 0.60 | 1.001 / 0.25 | 1.006 / 2.52 | 1.002 / 0.88 |
| 16 | 4 | **1.182** / 1.15 | 1.001 / 0.25 | 0.996 / 2.52 | 1.002 / 0.89 |
| 64 | 1 | **0.935** / 0.50 | 0.999 / 0.13 | 1.004 / 1.27 | 0.999 / 0.44 |
| 64 | 16 | **1.187** / 0.57 | 1.000 / 0.13 | 0.999 / 1.27 | 1.001 / 0.44 |
| 256 | 1 | **0.927** / 0.38 | 1.000 / 0.06 | 1.001 / 0.64 | 1.000 / 0.23 |
| 256 | 16 | 0.971 / 0.15 | 1.000 / 0.06 | 1.003 / 0.64 | 1.000 / 0.23 |

The same E1 bias on the shipped module (`module_check.cpp`), mean credit /
true work:

| λ | N = 1 | N = 4 | N = 16 |
|---|---|---|---|
| 4 | 1.186 | 1.064 | 1.002 |
| 16 | 0.972 | 1.181 | 1.042 |
| 64 | 0.935 | 0.970 | 1.187 |
| 256 | 0.924 | 0.936 | 0.971 |

Reading:

- The bias peaks where a shard carries a few raindrops above K.
- Splitting walks the shards down that curve, so a miner can pick N to land
  on the peak.
- The module's own sybil KAT (case 5) does not see this, for two reasons:
  - it models an uncensored stream (every hash above the target is a
    near-miss, no drops floor) with H = 20 shares per identity-set;
  - it skips identities with fewer than K near-misses instead of applying
    DROPS-JK.

### Why E1 is biased

`(n − 1)/u_(n)` is unbiased only for a fixed n on an uncensored process. Here
two things break that:

- n = S + K, and S is counted from the same stream, so it is random and tied
  to the data.
- The J < K fallback switches estimators on an observed quantity: a branch on
  data, exactly as EST_ONLY's branch on S was.

A fixed budget per identity also means N identities get N budgets, which is
where the review's variance point comes from.

### E2: count

- Credit = `S + J` floor units, i.e. `(S + J) / 64` shares.
  - REPLACE delta = `(J − 63·S) / 64` shares, which is linear.
  - A sum over shards is the unsplit sum, so mean **and** variance are
    identical for any split.
- There is no K, no J < K rule, no order statistic and no coupling to S.
- Cost on XMR: none beyond today. Every raindrop is already flooded and
  verified; E1 discards all but 4 per row.
- CV for a miner is `1/√λ` per interval, the Poisson floor. That is the best
  any unbiased rule can do with the raindrops it verifies.

### E3: pool-wide bottom-k

- τ = the (k+1)-th smallest raindrop of the whole pool in the interval. A hash
  below τ is worth `1/τ` floor units. With k+1 or fewer raindrops it reduces
  to E2.
- This is the rank-conditioned Horvitz–Thompson (priority sampling)
  estimator. It is unbiased for **any** subset, and its item covariances are
  zero, so a payee's variance depends only on its own hashes. Splitting
  changes neither the mean nor the variance.
- Withholding is a pure loss:
  - an included hash withheld loses its own 1/τ and raises τ for everyone;
  - an excluded one changes nothing.
- The payee is bound before the hash, as today. k is a committed constant, as
  K is today.
- Verification:
  - a node relays and verifies a raindrop only if it beats its current
    (k+1)-th smallest for that interval;
  - hash values arrive in random order, so the expected count is
    `Σ min(1, (k+1)/i) ≈ (k+1)(1 + ln(J/(k+1)))`;
  - at J = 6400 that is about 363 for k = 64 and about 1810 for k = 512,
    versus 6400 now: 18× and 3.5× fewer;
  - it stays bounded as the pool grows: logarithmic in J.
- The price is small-miner variance. E3 is E2 with an adaptive floor τ, so a
  miner's CV is `1/√(λ·τ)`. With k = 512 a miner at 1/64 of a share per
  interval has CV 3.5 per interval, and about 0.13 over a 720-interval window.

E2 and E3 are the same rule at different k: E2 is `k = ∞`. One committed
constant decides the trade between verification and small-miner variance, and
neither setting has a sybil gradient.

## Recommendation

1. **Do not enable DROPS on XMR with the K-min estimator.** It is biased for
   exactly the miners it targets and pays for splitting. It is gated off
   today, and this is the reason to keep it off.
2. **Replace the estimator before any flip:**
   - E2 if the raindrop flood (64× the share traffic) is acceptable. It
     already is in the current design, and E2 is the simplest rule with the
     lowest variance.
   - E3 if verification must stay bounded as the pool grows. Same properties,
     one extra constant.
3. **Fix the module's sybil KAT.** It must drive the censored stream with the
   DROPS-JK fallback and small λ, and assert the mean and the variance under
   a split, not only an upper bound on the mean.
4. **Paper §5 and §8:** "a bounded number of its best" should become "the
   pool's k best" (E3), or the count (E2), once ruled.

## Files

| file | what |
|---|---|
| `split.cpp` | E1 / E2 / E3 on one Poisson hash stream, split 1 / 4 / 16 |
| `module_check.cpp` | the E1 bias reproduced on the shipped module (`ReceiptCollector`, `estimate_combined`, DROPS-JK) |
