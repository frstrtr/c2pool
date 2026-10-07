# XMR lane: per-block cost

Measured 2026-09-29 on one core of the CI build VM (`-O3`). Every node does
this work for every lane block, so it has to stay well inside the 120 s
Monero block time at the pool's largest expected size.

## Primitives

| operation | cost |
|---|---|
| `derive_output` (one output key + view tag) | 161 µs |
| of which `8·r·A` (key derivation) | 120 µs |
| of which the one-time key `H(D‖i)·G + B` | 46 µs |
| of which the view tag (one Keccak) | 0.5 µs |

Monero's output keys are Ed25519 scalar multiplications. `r` is new in
every block, so no derivation can be precomputed across blocks.

## The ledger

| keys in the ledger | 1 000 | 10 000 | 100 000 |
|---|---|---|---|
| `owed_digest` | 0.4 ms | 4.3 ms | 45 ms |
| booking a block that credits 3 000 keys | 1.2 ms | 7.8 ms | 79 ms |
| K_fair proposal, 2 700 outputs | 0.1 ms | 0.5 ms | 0.9 ms |
| salted K_fair proposal, one cohort of every key | 1.8 ms | 18 ms | 185 ms |

The ledger scales. The salted tie-break hashes every key of the cohort the
walk reaches (the salt is unknown before the parent block). 100 000 keys
armed at one height is an extreme case, and it costs 0.2 s per build.

## Mapping outputs to payees (fixed)

The booking decode tried every known ref against every output, with a full
`derive_output` per pair: O(outputs × refs) scalar multiplications.

| outputs × refs | before | after |
|---|---|---|
| 100 × 200 | 1.6 s | 0.03 s |
| 300 × 500 | 12.3 s | 0.12 s |
| 2 700 × 3 000 | ≈ 650 s (estimated) | 3.5 s |

Now `8·r·A` is computed once per ref, and each pair first checks the view
tag, which is one hash. A match needs both the tag and the key, so the result
and the first-match order are unchanged (`xmr_coinbase_authority.hpp`).

## Repeated derivations (fixed)

Per lane block a node derives the same `(r, payee, index)` outputs several
times:

* the builder's template;
* the recompute's builds: at the total, at the V37N base, and per candidate
  output cap (up to 5 builds);
* the booking decode;
* the minority re-derivation.

At 2 700 outputs that was about 2.2 s per block for the recompute alone. A
process-wide cache of the two pure functions now computes each pair once per
block (`xmr_coinbase.cpp`, `cached_key_derivation` and `derive_output`). It
is bounded (cleared at 65 536 entries) and locked, because stratum threads
build coinbases too.

## Next

* **Canonical fast path.** Every node already knows the canonical output
  list: it is what the recompute builds. For a canonical block, mapping is a
  check of one expected ref per output, O(outputs), not a search. The search
  is only needed for a non-canonical block. Its ref set is the booking map
  (booked refs plus the refs of the block's own cut).
* **Bounding the booking map.** Booked refs are never forgotten, so the ref
  set a non-canonical block is searched against grows with the pool's
  lifetime. Only keys with a positive balance and the cut's payees can
  appear in a canonical coinbase. Restricting the search to them bounds it by
  current activity.
* **Pre-existing, not from this work.**
  * A ring-evicted cut is rebuilt by replaying every receipt since genesis
    (`replay_view`): O(lane lifetime).
  * `replay_cache` is unbounded.
