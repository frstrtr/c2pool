# v37 XMR / RandomX lane — design notes (Family B, Track X)

Design and provenance notes for the Monero/RandomX settlement lane
(`src/impl/xmr/`). This is a **fenced Phase-2 design track**: GO as a track,
NO-GO for inserting Track-X code into the A2 W0–W6 cascade until W2–W5 run on a
Bitcoin-family lane and Monero pins FCMP++/CARROT timing. See the scoping note
(design of record) `v37-monero-randomx-lane-scoping.md`.

## Licensing & provenance (read first)

- [`LICENSING.md`](LICENSING.md) — the AGPLv3 §13 / GPLv3 §13 combined-work
  rationale (AGPL-3.0 whole; BSD-3 islands; GPL-3.0-only p2pool-plumbing islands).
- [`PROVENANCE.md`](PROVENANCE.md) — the authoritative per-file port plan: what
  is vendored/adapted from which upstream at which pinned commit, and what is
  **not** taken from p2pool (the whole pool model). Machine-readable table:
  `src/impl/xmr/xmr_provenance.hpp`. Aggregated attribution: repo-root `NOTICE`;
  full upstream texts: `third_party/licenses/`.
- [`header-templates/`](header-templates/) — the three headers a porter pastes
  (bsd-ported / gpl-ported / agpl-fresh).

## Per-track design notes

| WBS | Note | Surface |
|---|---|---|
| X1 | [`x1-monero-primitives.md`](x1-monero-primitives.md) | varint/blob, Keccak midstate, ed25519 derivation, tree_hash, check_hash, seed-height, PoW select |
| — | [`x-randomx-vendor.md`](x-randomx-vendor.md) | RandomX light-mode verifier, two-cache epoch handling, KAT vectors, consensus pin |
| X2 | [`x2-monerod-adapter.md`](x2-monerod-adapter.md) | monerod RPC + ZMQ → mainchain index, backlog, reorg/orphan events |
| X3 | [`x3-descriptor-kinds.md`](x3-descriptor-kinds.md) | `XMR_STD`/`XMR_SUB` PayoutDescriptor kinds + torsion rule (canon tap) |
| X4 | [`family-b-receipt-envelope-addendum.md`](family-b-receipt-envelope-addendum.md) | Family-B receipt envelope + inverted `keyed_heavy` admission order |
| — | [`x-template-builder.md`](x-template-builder.md) | whole-block template builder (p2pool plumbing, pool model excised) |
| X5 | [`x5-stratum.md`](x5-stratum.md) | CryptoNote / XMRig stratum dialect |
| X6 | [`w5-xmr-coinbase-rule.md`](w5-xmr-coinbase-rule.md) | W5-XMR coinbase: deterministic `r`, exact-sum residual sink, MM-tree commitment, CARROT fence |
| X7 | [`x7-w3-wire.md`](x7-w3-wire.md) | W3 carrier/receipt wire type + RandomX DoS budget |
| X0 | `src/impl/xmr/test/X0-PROVENANCE.md` | feasibility KATs (hashing-blob / block-id / tx-hash triple, Keccak-midstate opening) on real mainnet blocks |

## Open questions carried (route to operator / integrator)

The consolidated OQ-X1..X10 list is in the scoping note §7. Each design note
carries its own subset (descriptor width OQ-X7; residual-sink identity OQ-X8;
`k_live` OQ-X9; commitment placement OQ-X4; byte budget/seed-ref OQ-X2;
consensus-vs-relay split OQ-X3; licensing/host-sizing OQ-X6; CARROT timing
OQ-X10). None is resolved by this FOUNDATION PR; it reserves the surface.
