# V37 P3 — multichain sharechain integration testbed (build)

Status: BUILD, slice-1 landed GREEN. Design source: `../c2pool-v37-p3-multichain-testbed-design.md`
(operator-greenlit 2026-07-02). N>1 red-team deltas: `../FINDINGS-redteam-p3-multichain-Ngt1.md`.

This is prototype code. It composes the already-verified pieces (M2 `refimpl/` K_fair selection,
the P3-12 KEYED_CRDT overlay from `p3-overlay/`) and adds ONLY orchestration — no new consensus
logic, no c2pool-master touch. Lands on the `v37-dev` prototype line (feature-branch → PR into
v37-dev), never master.

## Layout
- `harness/engine.py`    — core: KEYED_CRDT finality-gated overlay (order-invariant), K_fair
  coinbase assembly, N-chain mock `ChainOracle`, F6 legal-interleaving enumerator.
- `harness/scenarios.py` — matrix rows; each PASS emits a bit-stable golden vector.
- `golden/P3-*.json`     — committed golden vectors (one per row).

## Run
```
python3 harness/scenarios.py      # runs all rows, writes golden/, prints per-row + suite stamp
```
Deterministic: no wall-clock, no unseeded RNG (M4 `sha256(i)` convention). The suite stamp is
reproducible across runs; a changed stamp is a regression signal.

## Rows landed (slice-1)
| ID    | What it proves | Class |
|-------|----------------|-------|
| P3-1  | single happy path FOUND→FINALIZED, all miners paid, bounded coinbase, value conserved | base |
| P3-2  | orphan-then-revert at d ≤ D_f restores pre-FOUND owed; no double-pay | base |
| P3-3  | N=3 independent chains, distinct D_f/cadence/f_consensus; settlement isolation, per-chain fee denom | multichain |
| P3-4  | two-anchor share (same work, two chains): paid once, second finalize does not re-credit | **A-2ANCHOR** |
| P3-12 | event-order-permutation invariance over all legal interleavings — owed + coinbase order-invariant | **F1 / consensus** |
| P3-13 | two-anchor × revert: paid exactly once on the surviving chain, revert-aware dedup, over all orders | **F2 / consensus** |

P3-12 and P3-13 are the two consensus-bearing N>1 paths the red-team flagged (F1 order-sensitivity →
split; F2 revert-then-reanchor breaks paid-once). Both close green: the KEYED_CRDT overlay makes the
owed-ledger a pure function of the event multiset, and the dedup key is joined to the FINALIZED set.

## Rows landed (slice-2)
| ID    | What it proves | Class |
|-------|----------------|-------|
| P3-5  | sustained low-h inflow: self-carry keeps coinbase bounded (≤C), small miner eventually paid, no dust lost to pot | compaction |
| P3-6  | reorg-STORM (multi-orphan) convergence over all 90 legal interleavings — owed order-invariant | consensus |
| P3-7  | eventual-payment liveness: M>C miners all paid within ceil(M/C) rounds; owed-ledger bounded | liveness |
| P3-7b | **A-CHAINLIVE**: a silent chain does not starve the shared ledger; its owed pends (not lost), other chains settle | liveness |
| P3-8  | negative — out-of-floor reorg (depth>D_f) HALTS-and-surfaces, does not silently revert | negative |
| P3-9  | negative — un-PoW'd share rejected before settlement (A-F1) | negative |
| P3-10 | cold-validator bootstrap from a FINALIZED checkpoint + tail == full genesis replay (M4 state-availability) | sync |
| P3-11 | per-chain f_consensus divergence: owed stored canonical, denomination applied per finalizing chain, no cross-chain corruption | multichain |
| F4    | cross-denomination remainder → pot; value conserved (the ONLY sanctioned pot use) | remainder |
| F5    | per-chain affinity isolation: chain-c finalize touches only c-affiliated owed, no cross-chain leak | multichain |

Self-carry note: slice-2 self-carry rows run the `Overlay` with `tau=0` so sub-floor owed CARRIES
(retains miner identity per M2 `mrr_ref`), not swept. The remainder pot is reserved for its canonical
role — genuinely unattributable cross-denomination remainder (F4). Slice-1 stamps are untouched: no
slice-1 row ever finalizes a sub-TAU credit, so `_pot` stays 0 and those goldens are byte-identical.

## Rows landed (slice-3) — explicit coinbase-artifact lifecycle (FOUND→ASSEMBLED→ACCEPTED)
| ID    | What it proves | Class |
|-------|----------------|-------|
| P3-14 | full artifact lifecycle FOUND→ASSEMBLED→ACCEPTED: template-binding is deterministic (assemble≡accept coinbase), bounded ≤C, and ORPHAN-before-accept leaves owed intact so a fresh re-assembly reproduces the same template and pays the set exactly once | lifecycle |
| P3-15 | merged-mining paid-once across aux chains: a STALE over-paying template != the canonical coinbase re-derived over current owed → REJECTED-and-surfaced; every miner paid exactly once across chains, no cross-chain double-pay, value conserved | **consensus / merged-mining** |

Slice-3 composes only existing primitives (`assemble_coinbase` = ASSEMBLED, `_settle_round` = ACCEPT/drain,
M2 K_fair selection) — no new consensus logic. It closes the end-to-end merged-mining payout item at
coinbase-artifact granularity (P3-1/P3-7 collapse ASSEMBLED into a single finalize). Slice-1/slice-2 per-row
goldens are byte-identical (the 16-row set's stamps are unchanged; only the aggregate suite stamp shifts with
the row count). The prior 16-row aggregate was `39f96135066256d2ce6c44615d1fca8a06f3994668c142bc89520bc7d8c02964`.
Full 18-row suite is deterministic; suite stamp `bc2b5c84390a6c07630f1a6aee1f9ee40d513caec133e746c7f2b8490d87d6db`.

## Consensus-bearing carry-ins (SURFACED — canonical-doc fold is an operator call, not a harness call)
A-F1 (share-PoW), A-2ANCHOR (two-anchor overclaim, refined by F2 revert-aware dedup), F1 order-invariance
requirement, and the slice-3 **canonical-coinbase re-derivation at ACCEPT** rule (a block whose coinbase !=
the canonical assembly over current owed is rejected — the cross-chain paid-once guard, P3-15). The harness
encodes these as hard asserts; their fold into the canonical spec is gated on the operator, same class as
the M1–M4 held surfaces.
