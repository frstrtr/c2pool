# M4 superlight-chain — T4–T10: the three open blockers, answered

Companion to `FINDINGS-t1t2t3.md`. T1–T3 established that the **bridge side is cheap**
(18 MB / 1.3 s build for 300K shares) and proofs are genuinely O(log n). Those findings
left three honest gaps open. T4–T10 close all three with concrete numbers (real Utreexo
forest: add/prove/verify/delete; deterministic synthetic shares = sha256(i)).

Reproduce: `cd harness && python3 t<NN>_*.py` — each track is self-documenting and writes
its own `out/t<NN>-*.txt`.

---

## Open gap 1 — delete+re-add cycling (the real adversarial churn)

T3 modelled append/growth only. Deletion in Utreexo swaps-in the last leaf and *can*
fragment the forest, so the worry was super-inflated proof paths under sustained delete
churn. It does not happen.

| track | scenario | result |
|-------|----------|--------|
| **T4** repack | W=100K, 10%/round × 20 rounds, rebuild live set each round | worst proof **16 h** (=ceil log2 W), avg 15.59, **stable across all 20 rounds**, 6.1 MB, 300/300 verify |
| **T5** in-place | W=100K, swap-delete 10K/round × 20, no rebuild | delete **~68 µs/leaf**, worst stays **16 h / 512 B**, mem flat ~6.4 MB, 300/300 verify every round |

**Reading:** adversarial delete/re-add churn does **not** inflate proof size or fragment
the forest beyond the log2(W) bound. Both the repack and in-place-swap deletion strategies
hold proofs at the information-theoretic floor. Gap 1 closed: deletion is not a scale risk.

## Open gap 2 — who serves proofs (topology + liveness under sybil churn)

T2 measured proof size but assumed an oracle server. The real questions: single bridge vs
N bridges, liveness when the serving layer is sybil/churned, and whether a malicious
serving majority can corrupt (not just deny).

| track | scenario | result |
|-------|----------|--------|
| **T9/T10** multibridge | W=300K, 20–24 servers, 16 shards, fraction h honest | **SAFETY unconditional: 0 wrong-head acceptances across all trials incl. h=0**; whole-set **liveness 100% whenever ≥1 honest peer reachable** (h≥0.1 → 100%); sharded per-shard-commitment caps wasted egress at **W/K** per lie instead of W |

**Reading:** a sybil pool that fully owns the serving layer can **DENY progress, never
CORRUPT it** — the stateless verifier reconstructs a committed forest root, so a wrong head
is rejected regardless of who served it. The only failure mode is full eclipse (zero honest
peers) = retry/widen-peers, *not* a fork. **Design feed to the superlight synthesis:** the
on-chain checkpoint should commit a 32 B shard-root over K per-range sub-roots (still O(1)
on-chain) so the serving layer is *incrementally verifiable* and liveness degrades
gracefully under churn instead of all-or-nothing. Gap 2 closed: honest-server count is a
liveness knob; safety needs none.

## Open gap 3 — the sovereign first-time validator's O(n) catch-up

The design's stated worst case: a sovereign validator with no trusted snapshot pays O(n).
Measured, with the question of whether incremental delta replay beats it.

| track | scenario | result |
|-------|----------|--------|
| **T6** cold-start | W=300K, 10%×20 churn | full-history replay **23.6 s / 32 MB / 1.5M ops** vs root-anchored snapshot **0.74 s / 9.16 MB** — snapshot is **~32×** cheaper and roots match |
| **T7** returning validator | away 5/20 rounds, ΔW=300K | incremental delta replay **6.2 s / 5.7 MB** vs cold O(W) snapshot **0.77 s / 9.16 MB** — **cold snapshot WINS** for large gaps (delta only pays off for small gaps) |
| **T8** checkpoint cadence | W=50K, f=10%, R=40 | no-checkpoint replay O(W·(1+fR)) grows with R; snapshot floor **0.16 s / 1.6 MB** = O(W) flat |

**Reading:** the O(n) catch-up is real but **bounded and small** — ~0.74 s / 9 MB for a
300K-share chain from a root-anchored snapshot, dominated by bandwidth not compute. The
non-obvious result: **incremental delta replay is NOT a win for large gaps** — a returning
validator that was away many rounds is better served re-pulling the O(W) snapshot than
replaying ΔW ops, because each replayed op re-touches the forest. Cadence sets the
no-server fallback cost; with any honest snapshot server the floor is flat O(W). Gap 3
closed: the sovereign worst case is feasible at Phase-1 W, and the right primitive is
"anchor to checkpoint root + pull live snapshot", not "replay history".

---

## Net for M4 (the CORE production-scale blocker)
At W=300K the superlight-chain is feasible on every axis tested locally:
- bridge holds full forest at **18 MB**, builds in **1.3 s** (T1)
- proofs **≤ 576 B**, O(log n), **stable under adversarial delete churn** (T2/T4/T5)
- serving layer is **safety-unconditional under full sybil ownership**, liveness needs only
  one honest peer, sharded commitment bounds DoS amplification to W/K (T9/T10)
- sovereign cold-start is **~0.74 s / 9 MB** from a root anchor; delta replay does not beat
  it for large gaps (T6/T7/T8)

**Still NOT answered locally (needs the multichain testbed / real share format):** real
share/PoW/signature verification cost in the build path (synthetic sha256 understates it);
proof-cache memory on a bridge under a real request distribution; and W beyond 300K
(production may target higher). These are M5-integration items, not M4 local-feasibility
blockers.

**Recommendation:** the local feasibility verdict is GREEN — fold this + the T9 design feed
(shard-root checkpoint) into `v37-superlight-chain-synthesis.md` and land as a `frstrtr/the`
PR. Defer the real-share-format cost and W>300K to the M5 testbed.
