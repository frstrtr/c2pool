# V37 P5 — integration scaffolding (interface-level, HELD)

Status: **SCAFFOLD, slice-1 GREEN, HELD no-push.** Authorized as parallel work while the M4/P2-CORE
closing-gate GLM red-team runs to completion (integrator 2026-07-02T14:52 +04). P5 *proper* is gated
on the batched M1–M4/P3/P4 merge-cp; this scaffolding is not — it is structural only.

## What this is
The composition layer that wires the already-verified V37 slices into ONE end-to-end node lifecycle
and asserts the **cross-layer invariants** no single slice can assert alone (the seams between slices):

- `bootstrap` (sync) → `settle` (multichain) → `message` (perishable receipt) → `market` (spot
  hashrate) → `venue` (atomic cross).

Cross-layer invariants exercised (see `harness/integration.py`):
- **X1** sync-gated admission — a share enters settlement only if its inclusion proof verifies
  against the externally-committed root (honours the M4 cold-start anchor-trust fence at the seam).
- **X2** end-to-end value conservation — coinbase pays exactly the block value across ALL finalized
  chains; nothing created/destroyed between settlement and payout.
- **X3** paid-once across the venue seam — settlement owed and venue payout are disjoint ledgers.
- **X4** receipt-liveness gating — a market delivery is creditable only while the seller's standing
  receipt is live (TTL), coupling P4-messaging to P4-market.
- **X5** atomic-cross isolation — a non-atomic (failed) venue cross pays neither leg and leaves owed
  untouched.

## Why it does NOT hard-couple to the unmerged slices (integrator bound #2)
Each slice is reached through a narrow **port** (`harness/ports.py`). P5 ships a **reference stub
adapter** per port (`harness/stubs.py`) that mirrors only the slice's public surface. The scenarios
and invariant checks depend on the ports, never on a slice module or its golden SHA — so the batched
merge-cp is a **drop-in**, not a rebase storm.

### Merge-cp swap plan (one binding at a time, scenarios unchanged)
| Port          | Stub (now)        | Real adapter at merge-cp forwards to        |
|---------------|-------------------|---------------------------------------------|
| `sync`        | `SyncStub`        | `proto/m4-sync` utreexo bootstrap + proof   |
| `settlement`  | `SettlementStub`  | `proto/p3-testbed/harness/engine.py`        |
| `messaging`   | `MessagingStub`   | `proto/p4-messaging` perishable receipt     |
| `market`      | `MarketStub`      | `proto/p4-market` spot delivery contract    |
| `venue`       | `VenueStub`       | `proto/p4-dex` atomic two-sided cross       |

Swap = `registry.register("<port>", RealAdapter(...))` before building `V37Node`. Any stub whose
behaviour diverges from its real slice is a P5 bug — caught the moment the real adapter is swapped in
and the same E2E golden must still reproduce.

## Run
```
python3 harness/scenarios.py      # 5 E2E rows, writes golden/, prints per-row + suite stamp
```
Deterministic (M4 `sha256(i)` convention, no wall-clock, no unseeded RNG). A changed suite stamp is
a regression signal.

## Rows landed (slice-1)
| ID     | What it proves                                                        | Invariants |
|--------|-----------------------------------------------------------------------|------------|
| E2E-1  | full happy-path lifecycle across all five seams                       | X1 X2 X4   |
| E2E-2  | N=2 chains settle independently; value conserved across both          | X2 (multichain) |
| E2E-3  | orphaned chain reverted before payout; only survivor pays             | X2         |
| E2E-4  | delivery under an expired receipt is not creditable                   | X4 (negative) |
| E2E-5  | failed (non-atomic) venue cross is a no-op on owed                    | X5         |

Suite stamp (slice-1, stubs): `328a292b0162b31b64dea4ffc5a8decfe7e56e2780d850611a7593348ff2098e`

## Fence
Design/proto only. Prose/specs → `frstrtr/the`; runnable code → `v37-dev` branch on `frstrtr/c2pool`
(feature-branch → PR into `v37-dev`, NEVER master). No v37 code to c2pool master until the operator
reopens the build phase. HELD no-push; the merge-tap is the integrator's.
