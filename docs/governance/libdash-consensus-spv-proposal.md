# Governance Proposal — `libdash-consensus-spv`: a pluggable, daemonless DASH consensus library

> **Status:** DRAFT / living document. This branch (`governance/daemonless-consensus-library`)
> is intentionally long-lived: it is refreshed and re-submitted across successive DASH
> governance cycles until funded, then converted into the funded milestone tracker.
>
> **Relationship to proposal #1** (`c2pool-daemonless-finalize`, gobject `fa758340…`):
> proposal #1 funds *cutting dashd out of pool block production*. This proposal #2 funds
> *productizing the consensus engine that made the cut possible* as a reusable library for
> the whole DASH ecosystem, maintained in lock-step with dashd's upgrade cadence.

---

## 1. One-paragraph summary

c2pool has built, and proven on mainnet, a **daemonless DASH consensus engine**: it
self-derives the deterministic masternode list, rotated LLMQ quorums, PoSe ban state, and
block-reward payee **byte-for-byte** from the P2P network alone — no `dashd`, no ~40 GB
chainstate, no `-txindex`. This proposal extracts that engine from c2pool into a standalone,
Apache-2.0-licensed library, **`libdash-consensus-spv`** — the DASH analog of Bitcoin's
`libbitcoinconsensus` — so any project (light wallets, explorers, L2 bridges, other pools,
monitoring, research) can obtain verified DASH consensus state from headers + proofs without
running a full node. The ask funds the extraction, a stable C ABI, portability hardening, and
a **maintenance commitment keyed to dashd's release/DIP cadence** so the library never drifts
from consensus.

## 2. Problem

Everything that needs authoritative DASH masternode / quorum / reward state today must run a
full `dashd`. That is heavy (tens of GB, hours of IBD), operationally awkward to embed, and
overkill for consumers that only need *verified answers*, not a validating archive. Bitcoin
solved the analogous problem for script verification with `libbitcoinconsensus`; DASH has no
equivalent for its distinctive consensus surface (DIP-3 deterministic MN list, DIP-4 coinbase
commitments, DIP-6/DIP-24 LLMQ and rotated quorums, PoSe, ChainLocks, credit-pool /
asset-lock accounting).

## 3. What we already have (this is not vapor)

The engine exists and is soak-proven inside c2pool:

- **Deterministic MN list** self-derived and checkpointed byte-exact vs `dashd protx`.
- **Rotated LLMQ quorums** (type-5) derived and served daemonless.
- **PoSe ban / revival**, on-demand payee re-derivation, fail-closed gates.
- **DIP-4 coinbase** (`merkleRootMNList`, `merkleRootQuorums`) — real mainnet blocks accepted.
- **Mempool ingest** at byte-for-byte parity with `dashd`'s mempool (fee-priced from our own
  UTXO view), and reward-safe template tx-selection (subset-of-dashd invariant).
- A **replay/fold architecture** that walks the chain applying the same consensus transitions
  `dashd` does, keyed to activation heights (DIP-3/4, V19, V20, DIP-24 …).

The remaining engine work to reach *full* self-derivation across every historical activation
is tracked as the dashd-cut blocker; **this proposal rides that close — it does not precede
it.** A consensus core that cannot self-derive past every activation is not shippable as a
library, and we will not present it as one.

## 4. Deliverables

1. **Extraction** of the consensus core out of c2pool into `c2pool-core-engine`
   (Apache-2.0, already the licensing/packaging vehicle) as an independently buildable unit
   with no pool-specific dependencies.
2. **Stable C ABI** (`libdash-consensus-spv`) + headers: feed headers/proofs, query MN list,
   quorum membership, payee, PoSe state, coinbase commitment roots, at a given height/tip.
3. **Language bindings** starter set (C/C++ first; a Rust/Python FFI shim as reach).
4. **Coin-abstraction seam** so the engine is not DASH-welded — reusing c2pool's existing
   coin-registry pattern — making the same library shape portable to related chains.
5. **Conformance test vectors (KATs)** captured from live `dashd` at each activation boundary,
   so any consumer can verify the library against ground truth.
6. **Cadence-maintenance commitment** (see §5) with a public compatibility matrix.
7. **Documentation**: integration guide, ABI reference, "run a light DASH consensus client in
   N lines" quickstart.

## 5. The maintenance model — "aligned to dashd upgrade cadence"

The single most valuable thing this proposal funds is a **standing commitment to track
dashd's consensus cadence**. Concretely:

- Each DASH hard-fork / DIP activation (and each `dashd` minor that changes consensus-relevant
  serialization or LLMQ parameters) triggers a **versioned engine release keyed to the
  activation height**, with refreshed KATs proving parity across the boundary.
- A published **compatibility matrix**: `libdash-consensus-spv` version ↔ `dashd` version range
  ↔ activation heights covered.
- This is already how the engine is developed — every derive "wall" we cross *is* an activation
  boundary (e.g. the rotated-quarter fill boundary, V19 basic-BLS). The proposal **formalizes
  and funds** that discipline as an ongoing service to the ecosystem rather than a c2pool
  internal.

## 6. Why fund it (value to DASH)

- **Lowers the barrier** to building DASH-aware software: wallets, explorers, dashboards,
  bridges, and research tooling get verified consensus state without operating full nodes.
- **Strengthens decentralization**: more independent software can check masternode/quorum/
  reward truth cheaply, rather than trusting a remote full node's RPC.
- **A public good with a maintainer**: the funded cadence commitment means the library stays
  correct across upgrades — the usual failure mode of ecosystem libraries (bit-rot after the
  grant) is exactly what §5 pays to prevent.
- **Builds on delivered work**: this is the second step of a proven program, not a greenfield
  promise. Proposal #1 demonstrated the daemonless pool; this generalizes the engine.

## 7. Scope / milestones (to be priced per cycle)

| # | Milestone | Gate |
|---|-----------|------|
| M0 | Engine reaches full historical self-derivation (dashd-cut blocker closed) | **hard prerequisite** — library ships from here, not before |
| M1 | Core extracted, builds standalone under Apache-2.0 | green CI, no pool deps |
| M2 | Stable C ABI + headers + quickstart | third-party integrates in <1 day |
| M3 | KAT conformance suite from live dashd at every activation | parity proven per boundary |
| M4 | Cadence-maintenance live (compat matrix + release process) | first tracked dashd upgrade handled |
| M5 | Bindings + portability seam | second consumer beyond c2pool |

## 8. Honest risks & non-goals

- **Not a validating full node.** SPV-style: it verifies consensus *state* from proofs, it does
  not relay/validate the entire UTXO set. Consumers needing full validation still run `dashd`.
- **Depends on M0.** If historical self-derivation stalls, the library ships later — we will
  not present a partial engine as complete.
- **No UTXO oracle.** DASH has no daemonless UTXO anchor; fee/amount-exact use-cases that need
  full UTXO state remain full-node territory (documented, bounded).

## 9. The ask

To be finalized per governance cycle (extraction + ABI + KAT + first year of cadence
maintenance). This document is refreshed each cycle with the current amount, DashCentral link,
and gobject hash once submitted.

---

*Maintained on branch `governance/daemonless-consensus-library`. Prepared for operator review
and submission; this repository branch is the canonical living draft across governance cycles.*
