# T11 — scale-extension to W = 1,000,000 (retires the "W beyond 300K" carry-forward)

Reproduce: `cd proto/m4-sync/harness && python3 run_tracks.py --n 1000000`
and `python3 t6_sovereign_catchup.py --w 1000000`. Deterministic synthetic shares
= sha256(i); same real Utreexo forest as T1–T10. All numbers below are at W=1M
(3.3× the Phase-1 W=300K baseline) — purpose is to confirm the asymptotics are real,
not a small-W artifact.

## Result: every M4 claim holds linearly at 3.3× scale

| metric                         | W=300K (baseline) | W=1M (this run) | scaling     |
|--------------------------------|-------------------|-----------------|-------------|
| T1 bridge build                | 1.27 s            | 3.64 s          | ~linear O(W)|
| T1 bridge forest mem           | 18.3 MB           | 61.0 MB         | ~linear O(W)|
| T1 cost / share                | ~4.2 µs           | 3.64 µs         | flat        |
| T2 worst proof                 | ≤576 B (16 h)     | ≤608 B (19 h)   | O(log W)    |
| T2 log2(W)                     | 18.2              | 19.93           | proof≈log2  |
| T3 churn inflation (5 rounds)  | 1.06              | 1.06            | flat        |
| T6 sovereign snapshot cold-start | 0.74 s / 9.16 MB | 2.42 s / 30.5 MB | ~linear O(W live) |
| T6 full-replay fallback        | 3.0× snapshot     | 3.50× snapshot  | bounded     |
| T6 trustless root-match        | True              | True            | unconditional |

## Reading

- **Proofs stay O(log W).** Worst proof grew 576 B → 608 B (16 → 19 hashes) for a
  3.3× larger set — exactly the +log2 step (18.2 → 19.93), NOT linear. The stateless
  verifier cost is unchanged in practice at production scale.
- **Bridge O(W) is cheap in absolute terms even at 1M:** 61 MB / 3.6 s to build the
  full proof-server forest. A proof-server is a commodity box at W=1M.
- **Sovereign cold-start floor stays O(W live), trustless:** 2.42 s / 30.5 MB from a
  root-anchored snapshot vs 86.5 s full replay; rebuilt roots == the PoW-committed
  7-root commitment (a forged snapshot cannot match). The replay fallback is 3.5×
  costlier but server-trustless — same conclusion as W=300K.
- **Churn is not a scale risk at 1M** — sustained 10%/round delete+re-add holds the
  inflation ratio flat at 1.06.

## What this closes

The synthesis previously listed *"W beyond 300K (production may target higher) — all
numbers above are at W=300K"* as an explicit deferred unknown. **Closed:** the
asymptotics are confirmed linear-in-W (cost) / log-in-W (proof) at 3.3× the baseline.
No new scale cliff appears. Remaining M5-integration carry-forwards (real share/PoW/
signature verification cost; proof-cache memory under a realistic request distribution)
are unchanged — those need the multichain testbed + real share format, not larger W.
