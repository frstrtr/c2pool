# M4 superlight-chain — local-feasibility synthesis (PR feed for `v37-superlight-chain-synthesis.md`)

Status: **local feasibility GREEN — closed end-to-end (T1–T15).** Folds the real Utreexo
forest tracks (deterministic synthetic shares = sha256(i); real V37 share-format preimages
at T15) into the open-problem doc, capped by the **T14 e2e composition** below. Each claim is
reproducible: `cd proto/m4-sync/harness && python3 t<NN>_*.py`. Raw per-track results in
`out/t<NN>-*.txt`, narrative in `FINDINGS-t1t2t3.md`, `FINDINGS-t4t10.md`, `FINDINGS-t12-*`,
`FINDINGS-t13-*`, `FINDINGS-t14-*`, `FINDINGS-t15-*`, scale at `FINDINGS-t11-scale-w1m.md`.

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

## THE CAPSTONE — three load-bearing tracks COMPOSE into one cold-start (T14)

T1–T13 each closed ONE property in isolation; T14 wires the three load-bearing ones into the
single procedure a brand-new sovereign validator actually runs and checks no seam re-opens a
closed hole. The validator trusts only **two** on-chain commitments: (1) the checkpoint
`{≤8 forest roots + 1 32 B shard-root}` committed at depth `≥ D_f`; (2) the finalized-head
roots at `tip−D_f` (the M1 `BlockFinalized` read). It anchors to the nearest checkpoint,
sticky-shard-serves the live-set from an adversarial bridge pool (T12/T9), applies the
PoW-anchored delta tail to the finalized head (T7/T8), and **accepts iff** the rebuilt head
reproduces the committed finalized-head roots — else STALLS and re-anchors.

Result @W=300K, f=0.10, D_f=8, C=5, 20 servers, 16 shards, worst-case staleness with a reorg
in flight: **~14.4 MB egress / ~1.0 s rebuild = 1.5× the bare W-leaf floor.** Cold-start stays
`O(W·(1 + f·(C+L−D_f)))` — the finality lag and cadence are a **bounded additive** staleness
tax, never a new asymptotic. Across the full sweep (`reorg_d × L × h`, incl. h=0 eclipse):
**0 wrong-head acceptances**; `h>0` always finalizes the canonical head; `h=0` STALLS (liveness
loss only, never a fork).

**Decisive composition result — TWO independent anchors fail safe.** Force a protocol bug:
commit an under-lagged checkpoint (`L = D_f−2`) and let a depth-`D_f` reorg orphan it. The
serving layer faithfully serves the **orphan** live-set (it matches its own committed sub-roots,
so serving "succeeds", 20/20). Safety is saved **only** by the second anchor: the orphan delta
cannot reproduce the canonical `tip−D_f` roots, so the validator detects the mismatch and stalls
(`finalized=0, wrong=0`). A bad checkpoint commitment can cause **only liveness loss, never a
safety violation**, because the finalized-head roots are an independent canonical check. The
cold-start spec is therefore `{checkpoint at depth ≥ D_f} + {finalized-head roots}` — two
on-chain anchors, and the redundancy is what makes serving-layer and checkpoint bugs fail safe.
`L ≥ D_f` ties the checkpoint lag to the **same** finality depth M1's overlay settles on, so a
checkpoint is literally the `BlockFinalized/OwedSettled`-side read of the settlement overlay and
`BlockOrphaned` never touches a committed checkpoint. Reproduce: `t14_e2e_coldstart.py`;
numbers in `out/FINDINGS-t14-e2e-coldstart.md`.

## Still NOT answered locally — explicit M5-integration carry-forward (no silent caps)

- ~~Real share-format preimage cost in the build path — synthetic sha256 understates it.~~
  **PARTLY CLOSED (T15, out/FINDINGS-t15-real-share-format.md):** building over real V37
  share-format preimages (receipt 244B / full carrier share 1364B) keeps O(W) — preimage
  size is a bounded constant factor on the cold raw-ingest hashing leg only (full_share
  ~15–16s @300K, ~21× the snapshot floor), and the snapshot/checkpoint cold-start (32B leaf
  hashes) pays zero preimage cost. STILL M5: real PoW/signature *verification* cost (T15
  hashes preimages, it does not verify PoW or signatures).
- ~~Proof-cache memory on a bridge under a realistic request distribution.~~
  **CLOSED (T16, out/FINDINGS-t16-proofcache.md):** under a Zipf(1.1) head-hot
  request stream + steady-state churn, proof-cache benefit SATURATES at ~13 MB
  (84% hit @ C=20K; 54 MB adds nothing), and the faithful (root-bucket) hit rate
  is churn-INVARIANT (76.7% @ C=5K under both 1/50 and 1/10 churn). Residual
  ~16% misses are CPU-bound O(log W)=19-hash proof-gen, not RAM. A bridge is a
  modest-RAM, CPU-sized proof server; proof-cache memory is NOT an M4 scaling
  blocker. STILL M5: proof-cache under a *measured* production request trace.
- ~~W beyond 300K — all numbers above are at W=300K.~~ **CLOSED (T11, out/FINDINGS-t11-scale-w1m.md):**
  re-ran T1/T2/T3 + T6 at W=1,000,000 (3.3×). Asymptotics confirmed: build/mem linear
  O(W) (61 MB / 3.6 s), worst proof O(log W) (576 B → 608 B = +1 log2 step, not linear),
  churn inflation flat 1.06, sovereign cold-start O(W live) 2.42 s / 30.5 MB still
  trustless vs the PoW-committed roots. No new scale cliff.

The remaining items need the multichain testbed + real share format; they are M5 items, **not** M4
local-feasibility blockers. Verdict for M4: **GREEN, land this feed + the shard-root
checkpoint change into `v37-superlight-chain-synthesis.md` via a `frstrtr/the` branch PR.**
