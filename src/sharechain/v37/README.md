# c2pool V37 — prototype (`v37-dev`)

**Status: prototype / research dev line.** This is the long-lived development branch for c2pool V37. It
does **not** ship to `master`. The code here is a working prototype, published at a **principles level** —
the full design blueprint, formal specifications, and research record are maintained separately and are
not reproduced in this repository.

## What V37 is
A **multichain** evolution of c2pool: one decentralized, operatorless sharechain accounting engine that
serves many chains at once, and — built on the same primitive, a **work-receipt** — a small family of
products:

- **Multichain pool** — merged, decentralized PPLNS accounting across chains; every miner's real earnings
  preserved (no redistribution away from small miners) with a bounded coinbase.
- **Messaging** — perishable receipts bound to a fresh context, for pool/miner messaging.
- **Hashrate marketplace + DEX** — spot matching and a settlement venue for hashrate, bound to block
  templates so a delivery is self-proving.

## Core principles (the *what*, not the *how*)
- **Operatorless & deterministic.** All payout-affecting state is consensus-committed in the sharechain and
  bit-reproducible — no central server, no off-chain database.
- **Real-work weighting.** Accounting is by real proof-of-work (vardiff-safe), never share count.
- **Earnings preserved, not redistributed.** Cross-epoch compaction carries each miner's owed value forward
  until it is economically payable; spare coinbase space drains the backlog.
- **Identity is a payout descriptor.** Miners are identified by canonical payout-script bytes, with per-chain
  merged addresses as attributes.
- **Reorg-safe by finality.** Ledger transitions fire only on finalized events, on both the sharechain and
  the parent chain.

## The parts (high level)
| File | Part | Provides |
|---|---|---|
| `v37_roundabout.hpp` | Roundabout buffer | Top-level multi-lane structure: independent per-chain lanes + a global miner directory. |
| `v37_lane.hpp` | Lane | One sharechain lane — a multi-resolution real-work accumulator with incremental decay and a reorg journal. |
| `v37_descriptor.hpp` | Payout descriptor | The identity canon — canonical payout-script bytes; merged-address attributes. |
| `v37_fixed.hpp` | Fixed-point | Deterministic fixed-point arithmetic and decay tables (the consensus arithmetic). |
| `v37_hash.hpp` | Hash | Self-contained SHA-256 / SHA-256d so the module builds standalone. |
| `test/` | Tests | Prototype test suite. |

## Where the rest lives
The detailed design, formal specification, adversarial-review record, and economic analysis are maintained
in a separate research repository and are **not** reproduced here. This branch shows the core features and a
runnable prototype — it is intentionally not the full blueprint.
