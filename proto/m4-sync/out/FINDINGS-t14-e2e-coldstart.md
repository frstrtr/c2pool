# T14 — END-TO-END cold-start composition (finality-lagged checkpoint + sticky-shard serving + delta tail)

Harness: `harness/t14_e2e_coldstart.py`  •  raw: `out/t14-e2e-coldstart-w300k.txt`
Reproduce: `python3 harness/t14_e2e_coldstart.py --w 300000 --sweep-w 800 --servers 20 --shards 16 --df 8 --c 5`

## What this closes
T1–T13 each proved ONE property of the superlight cold-start in isolation. T14 wires the three
load-bearing ones into the single procedure a brand-new sovereign validator actually runs, and checks
they **compose** — no seam re-opens a hole an isolated track had closed:

- **T13** finality-lagged checkpoint: commit only finalized prefixes (`L >= D_f`) so the committed
  live-set root is canonical even while the tip is being reorged.
- **T12/T9** sticky-shard multi-bridge serving: reconstruct the committed live-set from an adversarial
  bridge pool; every shard root-checked vs its committed sub-root, one-strike-drop on a lie.
- **T7/T8** trustless delta tail: apply the PoW-anchored op-delta from the checkpoint height up to the
  finalized head and canonical-rebuild it.

## Procedure under test (NO local state, NO trusted server)
The validator trusts only two on-chain commitments: (1) the checkpoint `{<=8 forest roots, 1 32B
shard-root}` committed at depth `>= D_f`; (2) the finalized-head roots at `tip - D_f` (the M1
`BlockFinalized` read). It anchors to the nearest checkpoint, sticky-shard-serves the live-set from the
bridge pool, applies the delta tail to the finalized head, and **accepts iff** the rebuilt head
reproduces the committed finalized-head roots — else it STALLS and re-anchors.

## Results (W=300K, f=0.10, D_f=8, C=5, 20 servers, 16 shards)

**Cost — additive, one-time, at the safe design point `L=D_f`, worst-case staleness, reorg in flight:**
| metric | value | note |
|---|---|---|
| egress | **14.40 MB** | 9.60 MB W-leaf floor + delta tail + sybil waste = **1.50× the floor** |
| delta ops | 300K | `2·f·W·(C+L−D_f)` = the additive staleness tax, NOT a new asymptotic |
| rebuild compute | **1.04 s** | O(W) canonical rebuild |

Cold-start stays `O(W·(1 + f·(C+L−D_f)))` — the finality lag and cadence add a **bounded additive**
term over the O(W) live-set floor, never an asymptotic.

**Safety / liveness — sweep `reorg_d ∈ {0, D_f/2, D_f}` × `L ∈ {D_f, D_f+2, D_f+4}` × `h ∈ {0, .05, .10, .30}`:**
- **0 wrong-head acceptances** across the entire safe-regime sweep AND the violation arm. Safety is
  **unconditional** — independent of honest-server fraction, including `h=0` (full eclipse).
- `h>0` ⇒ **always FINALIZES the canonical head**, at every reorg depth up to `D_f`. One honest server
  in the reachable pool suffices (sticky assembly = whole-set liveness).
- `h=0` (full eclipse) ⇒ **STALLS** (liveness loss only) — retry/widen-peers, never a fork.

**The decisive composition result — TWO independent anchors (VIOLATION arm):**
Force a protocol bug: commit an **under-lagged** checkpoint (`L = D_f−2`) and let a reorg of depth `D_f`
orphan it. The serving layer faithfully serves the **orphan** live-set (it matches its own committed
sub-roots, so STEP B "succeeds" — `served=20/20`). Safety is saved **only** by the second, independent
anchor: the orphan delta cannot reproduce the canonical `tip−D_f` roots, so the validator detects the
mismatch and stalls — **finalized=0, wrong=0**. A bad checkpoint commitment cannot cause a safety
violation, only liveness loss, because the finalized-head roots are an independent canonical check.

## Net design feed for `v37-superlight-chain-synthesis.md`
1. The cold-start spec is `{checkpoint at depth >= D_f} + {finalized-head roots}` — **two** on-chain
   anchors, not one. The redundancy is what makes serving-layer + checkpoint bugs fail safe.
2. `L >= D_f` ties the checkpoint lag to the **same** finality depth M1's settlement overlay uses — a
   checkpoint is literally the `BlockFinalized/OwedSettled`-side read of the overlay, so `BlockOrphaned`
   never touches a committed checkpoint.
3. End-to-end cost at 300K shares is **~14 MB / ~1 s**, 1.5× the bare live-set floor — feasible for a
   sovereign first-time validator. The `f·(C+L−D_f)` staleness tax is the only premium over the O(W) floor.
4. Cadence `C` is a pure **cost** knob (delta-tail length); it never affects safety. Pick
   `C <= (k-1)/f - D_f` to cap total delta egress at `k·W`.

Remaining M4 item is the **real-share-format build cost** (vs the synthetic 32B leaves here) — an M5
testbed item, not locally modellable. The sync-model open problem is now **closed in prototype**: a
node CAN bootstrap 300K+ shares feasibly; the serving layer is safe under full sybil and live with one
honest peer; proof/egress sizes are churn- and reorg-resistant under the checkpoint+shard commitment.
