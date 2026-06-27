# M4 — large-W node sync / state-availability (local feasibility harness)

Goal (locally testable, NO shared-inference slot, NO consensus merge): can a node bootstrap
300K+ shares feasibly? who serves proofs? churn-resistance of proof sizes?

Tracks:
- T1 bootstrap-cost: ingest N synthetic shares -> O(n) accumulator build time/mem.
- T2 proof-serving: bridge-node holds full accumulator, generates Utreexo-style
  O(log n) proofs; measure proof-gen cost + who-serves topology.
- T3 churn-inflation: adversarial add/spend churn -> measure proof-size growth
  vs amortized O(log n) baseline.

STATUS: real Utreexo forest implemented (harness/utreexo.py: add/prove/verify/delete)
+ T1/T2/T3 driver (harness/run_tracks.py). First numbers @300K in out/FINDINGS-t1t2t3.md:
bridge forest 18.3MB / 1.27s build, proofs <=576B (O(log n)), append-churn inflation 1.06,
300/300 proofs verify vs the 8-root commitment.
T4/T5 deletion-churn DONE (out/t4-*, out/t5-*: repack vs lazy vs in-place swap-delete,
steady O(W) storage). T6 sovereign cold-start DONE (out/t6-sovereign-catchup-w300k.txt):
sovereign floor is O(W live) = 0.74s / 9.16MB via root-anchored snapshot (trustless vs
the 8-root commitment), NOT O(total-ever); full replay = 3.0x fallback; bridge proof-
server = 18.3MB O(W) mem, 9.16MB egress/client.
T7 incremental-delta + no-server worst case DONE (harness/t7_incremental_delta.py,
out/t7-incremental-delta-w300k.txt): a RETURNING validator applies only the op delta
[c0..c1] to its saved trustless forest -> reproduces the committed c1 roots in O(dW),
same PoW-root anchor as the snapshot (delta unforgeable). BUT honest caveat: dW = 2*f*gap*W,
so the break-even gap is ~1/(2f) rounds (5 rounds at f=10%); beyond it a fresh O(W)
snapshot is cheaper, AND delete ops cost more per-op than snapshot leaf-folding so even at
dW=W the delta is wall-clock costlier (6.2s vs 0.77s @300k). Use delta only for short gaps.
Q2 no-honest-server: the only server-trustless fallback is PATH-A replay = O(total-ever)
= O(W*(1+f*R)) -> UNBOUNDED in history length R, NOT bounded by W (3x@R=20, 201x@R=2000).
A SINGLE honest snapshot server OR a periodic consensus live-set checkpoint collapses it
to O(W) -- that checkpoint is the lever the superlight open problem turns on.
T8 periodic-checkpoint cadence model DONE (harness/t8_checkpoint_cadence.py,
out/t8-checkpoint-cadence-w50k.txt): consensus commits the live-set roots (8 roots,
256B, O(1) on-chain) every C rounds = a CHECKPOINT; a no-server cold validator anchors
to the nearest committed checkpoint and derives verified head_live as a bounded ID-set
delta. KEY CONSTRAINT SURFACED: the swap-delete forest is HISTORY-DEPENDENT -- naive
leaf-set rebuild + tail-op replay does NOT reproduce the head (proved: head ok=False),
so the checkpoint MUST RE-CANONICALISE (committed roots = canonical rebuild of the
sorted live-set; validator canonical-rebuilds head_live). Under that rule: cold-start
COMPUTE is O(W) FLAT (~0.33-0.39s @W=50k across C=1..40), and the CADENCE bounds only
the trustless DELTA download = O(f*C*W) ids (C=5 -> +0.5x the W-leaf floor, C=10 ->
+1.0x). Pick C <= (k-1)/f for a k-floor cap. Without a checkpoint the nearest trustless
anchor is genesis => O(total-ever), UNBOUNDED in R (baseline 450k-op PATH-A replay).
Net: checkpointing is ~free (8 roots) and is the decisive lever; the real design cost
is the RE-CANONICALISATION rule, not on-chain bytes -- feeds the superlight synthesis.
T9 multi-bridge proof-server availability / sybil-resistance DONE
(harness/t9_multibridge_availability.py, out/t9-multibridge-w8k.txt). Models S serving
bridges with adversarial sybils (withhold / truncate / corrupt / equivocate) against the
T8 committed-checkpoint root-check, separating SAFETY from LIVENESS:
  - SAFETY is UNCONDITIONAL: 0 wrong-head acceptances across 720 trials INCLUDING h=0.
    Every served leaf-set is canonical-rebuilt and checked vs the committed roots, so a
    sybil pool that fully owns the serving layer can DENY progress, never CORRUPT state.
    Confirms the README hypothesis: "liveness not safety is the risk."
  - WHOLE-SET liveness: one honest peer in the reachable pool suffices; querying each peer
    once (without replacement = realistic finite-peer case) => 100% live whenever >=1
    honest exists. The only failure is a ZERO-honest pool (full eclipse) = retry/widen-
    peers, not a fork. avg_q = wasted queries before hitting an honest server.
  - The DoS surface is EGRESS amplification: a sybil whole-set forces a full-W download
    before the root check rejects it. At h=0 this is 3.64MB wasted/cold-start @W=8k.
  - LEVER: commit a 32B SHARD-ROOT over K per-range sub-roots (still O(1) on-chain) so the
    serving layer is INCREMENTALLY VERIFIABLE -- each shard root-checks in isolation, a lie
    costs only W/K wasted egress (measured: 231KB = exactly 3642/16 @K=16, a clean 16x
    cap), and good shards can be UNIONED across different honest servers. Cost: needs an
    honest server per shard, so all-shards completion takes more queries (re-request bad
    shards) -- graceful degradation under churn instead of all-or-nothing whole-W retry.
  Net design feed for the superlight synthesis: checkpoint = {<=8 forest roots + 1 shard-
  root}; safety needs ZERO honest servers, honest-server count is purely a liveness knob,
  and per-shard commitment converts whole-W DoS amplification into a bounded W/K one.
T13 checkpoint cadence-vs-FINALITY-LAG DONE (harness/t13_checkpoint_finality_lag.py,
out/t13-finality-lag-w50k.txt, out/FINDINGS-t13-finality-lag.md). Closes the seam where M4
touches M1's finality gate: the T9/T12 serving-layer safety proof assumes the COMMITTED root
is canonical; a checkpoint committed over a reorg-able tip commits an orphaned live-set and a
trustless cold-start anchoring to it lands on a dead branch. Sweeping reorg-depth d x lag L
against the real forest gives a clean safety diagonal -- canonical iff L >= d (10 orphan
events = the exact lower triangle, no grey zone). RULE: commit only finalized prefixes,
L >= D_f -- the SAME depth M1's overlay settles on; a checkpoint is the BlockFinalized/
OwedSettled-side read of the settlement overlay, so BlockOrphaned never touches a committed
checkpoint. Cost is ADDITIVE not asymptotic: delta tail = (C+L) rounds, cold-start stays
O(W*(1+f*(C+L))); +0.8x W-floor egress premium at f=10%/C=5/L=D_f=8, one-time per cold-start.
Pick C <= (k-1)/f - D_f for total delta <= k*W. Net checkpoint = {<=8 forest roots +
1 shard-root} committed at depth >= D_f behind the tip.
T14 END-TO-END combined cold-start DONE (harness/t14_e2e_coldstart.py,
out/t14-e2e-coldstart-w300k.txt, out/FINDINGS-t14-e2e-coldstart.md). Wires the three
load-bearing tracks into the single procedure a new sovereign validator runs: T13 finality-
lagged checkpoint (L>=D_f) -> T12 sticky-shard serve from an adversarial bridge pool -> T7
PoW-anchored delta tail to the finalized head, accept iff rebuilt head reproduces the
committed finalized-head roots. They COMPOSE: end-to-end @300K = 14.4MB egress (1.5x the
9.6MB W-leaf floor) / 1.04s rebuild, cost O(W*(1+f*(C+L-D_f))) ADDITIVE not asymptotic;
0 wrong-head accepts across the full sweep (incl h=0 eclipse), h>0 finalizes canonical at
every reorg depth<=D_f, h=0 stalls (liveness only). KEY RESULT: the spec is TWO independent
on-chain anchors {checkpoint at depth>=D_f} + {finalized-head roots} -- the VIOLATION arm
proves an under-lagged commit (L<D_f) orphaned by a deep reorg is SERVED faithfully yet
CAUGHT by the second anchor (finalized=0, wrong=0), so a bad checkpoint costs liveness not
safety. Sync-model open problem now CLOSED in prototype.
NEXT (local): real-share-format build cost is the only residual M4 item, an M5 testbed item
(synthetic 32B leaves here). Deep write-up into v37-superlight-chain-synthesis.md still gated
behind the single shared-inference slot (M1 lanes -> payment-hardening). No production code;
proto repo only.
