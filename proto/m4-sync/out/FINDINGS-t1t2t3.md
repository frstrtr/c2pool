# M4 superlight-chain — first feasibility numbers (local, no shared-inference slot)

Harness: `harness/utreexo.py` (real Utreexo forest: add/prove/verify/delete) +
`harness/run_tracks.py`. Deterministic synthetic shares = sha256(i). Reproduce:
`cd harness && python3 run_tracks.py --n 300000 --samples 300 --churn-rounds 5`.

## Results @ n=300,000

| track | metric | value |
|-------|--------|-------|
| T1 bootstrap | full bridge forest build | **1.27 s**, 600K nodes, **18.3 MB**, 8 roots, 4.2 µs/share |
| T2 proof-serving | membership proof size | **12–18 hashes (≤ log2 n=18.19)**, worst **576 B**; 300/300 verify vs 8-root commitment; 37 µs/proof |
| T3 churn (growth) | oldest-leaf proof vs n | tracks log2(n) exactly (16→17 over 110K→150K); **inflation 1.06** over 5×(+10%) rounds |

## What this establishes
- The **bridge-node side is cheap**: holding the full O(n) forest for 300K shares
  is ~18 MB and ~1.3 s to build from scratch — not a scale blocker at this W.
- Proofs are genuinely **O(log n)** (≤ 576 B worst-case) and a stateless verifier
  reconstructs one of the 8 forest roots — the superlight verify path works.
- **Append/growth churn does NOT super-inflate** proofs; they ride log2(n).

## Honest limitations (next iterations — NOT yet answered)
1. T3 models **append/growth churn only**. The real adversarial question is
   **delete+re-add cycling** (Utreexo deletion swaps-in the last leaf and can
   fragment the forest). `Forest.delete` is not yet exercised by the driver —
   add a deletion-churn track to probe worst-case path growth + proof-cache bloat.
2. **Who serves proofs** (T2 topology) is unmodeled — a single bridge vs N bridges,
   liveness if bridges churn, and the cost a *sovereign first-time validator* pays
   (O(n) catch-up) are still open.
3. Synthetic shares ≠ real share format; no signature/PoW verification in the build
   path (build time is hash-bound only).
4. Deep analysis of `v37-superlight-chain-synthesis.md` remains **gated behind the
   single shared-inference slot** (M1 lanes → payment-hardening). These numbers are the local
   empirical floor that pass will reason against.

Verdict (preliminary, Phase-1 scope): at W≈300K the **bridge-forest + O(log n)
proof model is feasible**; the surviving risk is concentrated in (1) deletion-churn
and (2) proof-serving topology/liveness — both locally testable next.

---

## T4 — adversarial DELETION/expiry churn (added 2026-06-26)

T1/T3 were append-only (sharechain growth); they could not exercise share EXPIRY,
which is where Utreexo churn was hypothesised to inflate proofs. T4 runs a FIFO
sliding-window workload (W=100K live, expire-oldest-10% + append-10% per round, 20
rounds → 300K ever-appended) against two bridge strategies. Every sampled proof
stateless-verifies against a forest root (300/300 each round). Driver:
`harness/t4_deletion_churn.py`; raw: `out/t4-deletion-churn-w100k.txt`.

| strategy | worst proof | root count | bridge storage | per-round cost |
|---|---|---|---|---|
| REPACK (rebuild live set) | 16 hashes (512B), flat | 6, flat | 6.1MB steady (O(W)) | ~353ms rebuild |
| LAZY (tombstone+append)   | 16→18 hashes (576B)    | 5–11, bounded | 6.7→18.3MB (O(total-ever), 2.73×) | ~41ms append |

**Finding F-M4-1 — the churn threat is STORAGE, not proof size.** Over 3× ever-appended
growth the worst-case membership proof rose only 16→18 hashes (≤ ⌈log2(total)⌉, +12%)
and the peak/root count stayed ≤ log2(n) (popcount-bounded). So "adversarial churn
inflates the proofs a verifier must carry" is true only *logarithmically* — not a
blow-up. The dominant cost axis is the BRIDGE's own forest: a non-repacking (lazy)
bridge grows O(total-ever-appended) without bound even though the live set is constant,
while a repacking bridge holds steady at O(W) but pays a recurring O(W) re-pack (~350ms
at W=100K here).

**Implication for the superlight-chain open problem.** The unresolved question is not
"do proofs explode under churn" (they don't, materially) but "what is the bridge's
re-pack / prune policy" — a repack-cadence knob trading bridge CPU (O(W)/cycle) against
bridge RAM (O(total-ever) if deferred). Both endpoints are cheap in absolute terms at
W=100–300K (single-digit→tens of MB, sub-second CPU), so a stateless verifier remains
viable; the live design choice is bridge pruning cadence, not proof-size churn-resistance.

OPEN next-local: (a) model true Utreexo *in-place* swap-delete (the docstring's claimed
algorithm is not yet implemented; current LAZY tombstones, REPACK rebuilds — neither is
the incremental swap-delete, so per-update CPU of the realistic bridge is still
un-measured, bracketed between 41ms and 353ms here); (b) sovereign first-time-validator
O(n) catch-up cost + proof-serving topology (T2 follow-up). Defer the deep
churn-adversary modelling to the deep superlight-chain pass when the slot frees.

---

## T5 — REALISTIC in-place Utreexo swap-delete (added 2026-06-27, closes T4 OPEN-a)

T4 only BRACKETED the realistic bridge per-update CPU (REPACK ~353ms vs LAZY ~41ms
per 10% round) because neither proxy was the true incremental swap-delete. `Forest.delete`
is now implemented (move last leaf into the hole, pop tail, refold only the hole's
ancestor spine — O(log n) hashes/delete). Correctness is hard-checked: the forest's
internal rows are a pure function of the leaf row, so every round asserts
incremental-rows == a from-scratch pairwise re-fold, plus 300/300 stateless proof
verifies. Also stress-passed 4000 random add/delete ops. Driver: `harness/t5_inplace_delete.py`;
raw: `out/t5-inplace-delete-w100k.txt`.

| strategy | worst proof | bridge storage | per 10% round (W=100K) |
|---|---|---|---|
| in-place swap-delete (T5) | 16h / 512B, **flat** | **6.4MB steady = O(W)** | **683ms** |
| REPACK rebuild (T4)       | 16h / 512B, flat     | 6.1MB steady = O(W)    | 353ms |
| LAZY tombstone (T4)       | 16→18h / 576B        | 6.7→18.3MB = O(total)  | 41ms |

**Finding F-M4-2 — incremental swap-delete is CORRECT and O(W)-storage, but NOT the
CPU win you'd assume; there is a churn-rate crossover.** At 10%/round churn, 10,000
individual O(log n) swap-deletes (~68 µs each, ~16 hashes + dict/list ops) sum to 683ms
— ~2× a single cache-friendly O(W) batch REPACK (353ms). Incremental updates only pay
off when deletes-per-round is SMALL relative to W (each amortizes cheaply and you skip
the full rebuild); under heavy churn a batched repack wins. So the bridge's optimal
maintenance is **churn-adaptive**: incremental swap-delete in the light-churn regime,
periodic batch repack in the heavy-churn regime — LAZY only if RAM is free and you never
want to pay CPU.

**The superlight verify path is robust across all three bridge strategies.** Every one
keeps the membership proof bounded at ≤⌈log2 W⌉ (16h/512B here) and the verifier fully
stateless (reconstructs a forest root); they differ ONLY in the bridge's internal
CPU/RAM trade. So "adversarial delete-churn breaks the accumulator" is refuted at the
verifier: churn touches bridge maintenance cost, never proof size or verify cost. At
W=100–300K all strategies are cheap in absolute terms (single-digit MB, sub-second/round).

OPEN next-local (unchanged): (b) sovereign first-time-validator O(n) catch-up cost +
proof-serving topology/liveness (single vs N bridges) — the T2 follow-up. Then the deep
churn-adversary + synthesis-doc reasoning is the deep superlight-chain pass (gated behind
the single slot: M1 lanes → payment-hardening cross-check → superlight).

---

## T6 — sovereign first-time-validator cold-start catch-up (the milestone-4 core)

Question the design flagged: a stateless verifier is O(log n), but a brand-new
*sovereign* validator (no prior state) must rebuild the accumulator before it can
verify anything — "a sovereign first-time validator pays O(n)". **Which n?**

Harness: `harness/t6_sovereign_catchup.py` over the real Utreexo forest. A single
deterministic op schedule drives both the bridge build and the replay, so identical
end-state (hence identical committed roots) holds *by construction*. W=300K live,
20 rounds of 10% FIFO churn → total-ever=900K admits, 600K deletes, 8-root
commitment (256B).

| cold-start path | build | wire bandwidth | trust anchor | roots match |
|---|---|---|---|---|
| A full-history replay | 23.6s | 32.0MB (900K leaves + 600K del ops) | folds to committed roots | ✅ |
| B root-anchored snapshot | **0.74s** | **9.16MB** (300K live leaf hashes) | rebuilt roots == committed roots | ✅ |

**Findings @ W=300K:**
- **Sovereign cold-start floor is O(W live), not O(total-ever).** Path B downloads
  only the bridge's live row-0 leaf-hash vector, folds it, and checks the rebuilt
  8 roots == the PoW-committed 8 roots. Match ⇒ the snapshot is *trustless*: a
  forged snapshot cannot reproduce the consensus-committed roots. 0.74s / 9.16MB.
- **Replay is the server-trustless fallback**, 3.0x costlier (23.6s / 32MB) and
  scaling with total-ever (= churn-history depth), not live set. Both paths are
  server-trustless; B just needs an *available* (not honest) snapshot server.
- **Bridge / proof-server topology cost:** holding the full forest is 18.3MB O(W)
  mem. Per cold-start client egress = 9.16MB (snapshot) vs 32MB (replay). Serving
  50 simultaneous cold sovereigns via snapshot = 458MB total egress — cheap; the
  bridge role is bandwidth-bound, not compute-bound.

**This sharpens the open problem.** The superlight-chain blocker is NOT "sovereign
pays O(total history)" — a committed-root-anchored snapshot makes it one-time
O(W live), separable from steady-state O(log W) verification. Residual OPEN items
for the deep-analysis pass (gated behind the single slot): (1) is one-time O(W) bootstrap
acceptable at the *production* W (extrapolate 9.16MB·W/300K, 0.74s·W/300K); (2) the
no-honest-server adversarial case (replay fallback bounds it at 3x here, but
total-ever inflation grows with churn depth — measure the worst-case multiplier);
(3) incremental snapshot deltas so a returning validator pays O(ΔW) not O(W).
