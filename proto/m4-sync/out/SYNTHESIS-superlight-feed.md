# M4 superlight-chain — local-feasibility synthesis (PR feed for `v37-superlight-chain-synthesis.md`)

Status: **local feasibility GREEN.** Folds T1–T10 (real Utreexo forest; deterministic
synthetic shares = sha256(i)) into the open-problem doc. Each claim is reproducible:
`cd proto/m4-sync/harness && python3 t<NN>_*.py`. Raw per-track results in `out/t<NN>-*.txt`,
narrative in `FINDINGS-t1t2t3.md` + `FINDINGS-t4t10.md`.

## What the open problem asked vs what the harness now answers

The synthesis doc framed three unresolved blockers. All three are closed at Phase-1 W=300K:

1. **Bridge cost / proof asymptotics (T1–T3).** Bridge holds the full forest at **18 MB**,
   builds in **1.3 s** for 300K shares; proofs are **≤ 576 B** and genuinely O(log n).
   The "stateless for verifiers, O(n) for the network" framing holds — the O(n) lives on
   the bridge, and it is cheap in absolute terms.

2. **Adversarial churn does NOT inflate proofs (T4/T5).** Sustained delete+re-add churn
   (10%/round × 20 rounds, both repack and in-place swap-delete) holds proofs at the
   information-theoretic floor (ceil log2 W = 16 hashes / 512 B), forest memory flat
   ~6.4 MB, 300/300 verify every round. Churn is not a scale risk.

3. **Serving layer is safety-unconditional (T9/T10).** Across 720 trials incl. h=0:
   **0 wrong-head acceptances.** A sybil pool that fully owns the serving layer can DENY
   progress, never CORRUPT it — the stateless verifier reconstructs a committed forest root,
   so a wrong head is rejected regardless of server. Whole-set liveness is 100% whenever
   ≥1 honest peer is reachable; full eclipse (h=0) = retry/widen-peers, not a fork.

4. **Sovereign cold-start is bounded (T6/T7/T8).** First-time validator with no trusted
   snapshot: **~0.74 s / 9.16 MB** from a root-anchored snapshot vs 23.6 s / 32 MB full
   replay (~32×). Non-obvious result: **incremental delta replay does NOT beat a cold
   snapshot for large gaps** — each replayed op re-touches the forest, so a long-absent
   returning validator should re-pull the O(W) snapshot, not replay ΔW. Right primitive is
   "anchor to checkpoint root + pull live snapshot", not "replay history".

## DESIGN CHANGE to fold into the synthesis (T9/T10/T12 feed)

The on-chain checkpoint should commit a **32 B shard-root over K per-range sub-roots**
(still O(1) on-chain). This makes the serving layer **incrementally verifiable**: liveness
degrades gracefully under sybil churn instead of all-or-nothing, wasted DoS egress per lie
is bounded to **W/K** leaves instead of W, and a validator can accept good shards from
*different* honest servers (union coverage, bad shard → next server). Honest-server count
becomes a pure liveness knob; **safety needs none.**

**The checkpoint must also specify the ASSEMBLY RULE, not just the commitment (T12).**
T9/T10 surfaced a tension this section first glossed: *naive* sharded assembly (sample a
server independently per shard) is actually WORSE for liveness at low honest-fraction —
6.7% vs whole-set's 80.8% live @h=0.05/W=300K — because it needs an honest server *per
shard*. T12 closes it: the validator does **server-affinity ("sticky") assembly** — once
a server returns a sub-root-valid shard, pull all remaining shards from that same full
server, and **one-strike-drop** any server that serves an invalid shard. That recovers
whole-set liveness (one honest peer suffices, not one-per-shard) while keeping per-lie
egress pinned to the W/K bound (measured: maxSybilKB == W/K exactly at every h) and total
wasted egress ~15× below whole-set. Net: with the sticky rule the per-shard commitment is
a strict Pareto improvement — whole-set liveness AND bounded-W/K DoS AND unconditional
safety, together. Reproduce: `t12_sticky_shard_assembly.py`; numbers in
`out/FINDINGS-t12-sticky-shard.md`.

## CHECKPOINT MUST LAG FINALITY (T13 feed) — the M4 ⟂ M1 seam

The T9/T12 serving-layer safety proof ("stateless verifier canonical-rebuilds the served
live-set and checks it vs the committed root → server need not be honest") has a hidden
premise: **the committed root must itself be canonical.** T13 closes it. If consensus commits
a checkpoint over a reorg-able tip, the committed root describes an orphaned live-set, and a
trustless cold-start anchoring to it lands on a dead branch — the serving-layer proof does not
cover this, because the *commitment* is wrong, not the server.

T13 sweeps reorg depth `d` × checkpoint lag `L` against the real forest and finds a clean
safety diagonal: the committed height stays canonical **iff `L ≥ d`** (10 orphan events = the
exact lower triangle, no grey zone). **Rule: commit only finalized prefixes, `L ≥ D_f`** — the
SAME finality depth M1's overlay settles on (`BlockFinalized→OwedSettled`,
`BlockOrphaned→OverlayReverted`). A checkpoint is just the finalized-side read of the
settlement overlay, so an orphan never touches a committed checkpoint. The cost is **additive,
not asymptotic**: delta tail = `(C+L)` rounds, cold-start stays `O(W·(1+f·(C+L)))`; at f=10%,
C=5, L=D_f=8 the safety premium is +0.8× the W-leaf-floor egress, one-time per cold-start.
Pick `C ≤ (k−1)/f − D_f` to keep total delta ≤ k·W. Net: checkpoint =
`{≤8 forest roots + 1 shard-root} committed at depth ≥ D_f behind the tip`. Reproduce:
`t13_checkpoint_finality_lag.py`; numbers in `out/FINDINGS-t13-finality-lag.md`.

## Still NOT answered locally — explicit M5-integration carry-forward (no silent caps)

- Real share/PoW/signature verification cost in the build path — synthetic sha256
  understates it.
- Proof-cache memory on a bridge under a realistic request distribution.
- ~~W beyond 300K — all numbers above are at W=300K.~~ **CLOSED (T11, out/FINDINGS-t11-scale-w1m.md):**
  re-ran T1/T2/T3 + T6 at W=1,000,000 (3.3×). Asymptotics confirmed: build/mem linear
  O(W) (61 MB / 3.6 s), worst proof O(log W) (576 B → 608 B = +1 log2 step, not linear),
  churn inflation flat 1.06, sovereign cold-start O(W live) 2.42 s / 30.5 MB still
  trustless vs the PoW-committed roots. No new scale cliff.

The remaining items need the multichain testbed + real share format; they are M5 items, **not** M4
local-feasibility blockers. Verdict for M4: **GREEN, land this feed + the shard-root
checkpoint change into `v37-superlight-chain-synthesis.md` via a `frstrtr/the` branch PR.**
