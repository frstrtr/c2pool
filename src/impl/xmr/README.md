# Family B — Monero / RandomX settlement lane (`src/impl/xmr/`)

**Status: FOUNDATION (scaffold + vendored + X0). This is NOT a finished lane.**

A new, isolated per-coin tree for a Monero/RandomX settlement lane on the v37
Work-Receipts substrate. It is a *second chain family* (not a Bitcoin-clone
coin): ~0 % reuse below the sharechain seam, ~100 % above it. It does **not**
touch `src/sharechain/v37` consensus-digest code. Design of record:
`v37-monero-randomx-lane-scoping.md` (GO as a fenced Phase-2 track; all Track-X
code deferred until A2 W2–W5 run on a Bitcoin-family lane and Monero pins
FCMP++/CARROT timing).

## Layout

| Path | What | Build state |
|---|---|---|
| `coin/` | Monero primitives: CryptoNote varint/blob, Keccak-256 + resumable midstate, ed25519 derivation, `tree_hash`/`tree_branch`, 128-bit `check_hash`, seed-height, PoW-algorithm select. `coin/vendor/` = BSD-3 Monero C verbatim; `coin/compat/` = boost-free epee shim. | selfcheck GREEN (libsodium paths syntax-only) |
| `pow/` | `randomx_verify.hpp` — c2pool's own two-cache **light-mode** (256 MiB, never the 2 GiB dataset) RandomX verifier over the vendored `third_party/randomx/` C API. `randomx_verify_kat.cpp` needs `librandomx.a`. | header compiles; KAT needs the lib |
| `third_party/randomx/` | tevador/RandomX public headers + LICENSE (BSD-3, verbatim). The library is a pinned submodule at package time. | vendored |
| `node/` | monerod adapter (X2): JSON-RPC + ZMQ → bounded mainchain index (≥ 2112-block seed reach), fee-sorted backlog, reorg/orphan events. Parsers are skeleton stubs. | index check GREEN; RPC/ZMQ skeleton |
| `template/` | Whole-block template builder (p2pool plumbing, GPL-3.0-only): penalty-aware knapsack, `create_miner_tx`, per-worker extra-nonce jobs, Keccak-midstate opening. Pool model excised. | not built in CI (needs coin+primitives) |
| `stratum/` | CryptoNote / XMRig `login`/`job`/`submit` dialect. Separate from the v36 Bitcoin stratum. | selftest GREEN (53 KATs) |
| `receipt/` | Family-B receipt envelope (`MoneroReceipt`) + the **inverted** `keyed_heavy` admission order (RandomX LAST). | check GREEN |
| `wire/` | W3 carrier/receipt message codec (byte-exact, one-canon) + the RandomX-evaluation DoS budget. | check GREEN |
| `settle/` | W5-XMR coinbase rule: deterministic `r`, exact-sum residual sink, K_fair order, weight-aware cap, 0x03 MM-tree commitment, ACCEPT re-derivation. **Pre-CARROT fenced.** | needs coin crypto (libsodium) |
| `xmr_provenance.hpp` | Machine-readable 14-row porting table + 3 compile-time provenance `static_assert`s. | gate GREEN |
| `test/` | Self-contained self-checks (CI-wired) + the X0 KAT harness (`x0_harness.py`, mainnet vectors) + the RandomX light-mode probe (`rx_probe.cpp`, needs the lib). | see below |

## What is real vs scaffold

- **Real & self-verifying (CI):** the Monero primitives (Keccak midstate, v2
  coinbase tx-hash, `tree_hash`/branch, `check_hash`, seed-height, PoW/CARROT
  fences); the mainchain-index math; the receipt envelope + inverted admission
  order; the W3 wire codec + DoS budget; the stratum dialect; the descriptor
  `XMR_STD`/`XMR_SUB` kinds vs the real v37 canon; the provenance gate.
- **Scaffold (real signatures + provenance, bodies deferred):** the monerod
  RPC/ZMQ parsers, the template builder, the W5 coinbase executor (all need the
  vendored crypto / RandomX lib / a daemon, landed in later Track-X PRs).
- **Vendored:** RandomX headers (BSD-3); Monero crypto-ops/keccak/tree-hash/
  hash/int-util/varint (BSD-3); full upstream licence texts under
  `third_party/licenses/`.

## FCMP++ / CARROT fence

All coinbase-output derivation is **pre-CARROT**, pinned per Monero hard-fork
`major_version ≤ 16` (`XMR_PRECARROT_MAX_MAJOR_VERSION` / `xmr_precarrot_ok()`;
`xmr_pow_select.hpp`). A block past the pin is **refused**, never silently built
with the old rule. When Monero pins CARROT, add a new derivation path keyed on
the new major version — do not edit the pre-CARROT path in place.

## Licensing

c2pool is AGPL-3.0. RandomX + Monero-core crypto are BSD-3 (combine freely);
p2pool-derived plumbing is GPL-3.0-only, combined under AGPLv3 §13 / GPLv3 §13
and kept under its GPLv3 header. Fresh c2pool files are AGPL-3.0 and
attribution-clean. See `docs/xmr-lane/{LICENSING,PROVENANCE}.md`, the repo-root
`NOTICE`, and `xmr_provenance.hpp`.

## Remaining WBS (deferred)

X1 primitives + RandomX wrapper KATs · X2 adapter RPC/ZMQ bodies · X3 descriptor
tap + `ChainLimits` sibling · X4 receipt envelope implementation · X5 stratum +
extra-nonce jobs · X6 W5 coinbase executor + ACCEPT cache · X7 W3 relay wiring ·
X8 stagenet + p2pool-vector goldens + Python peer · X9 stagenet soak + FCMP++
dry run. See `docs/xmr-lane/` for the per-track design notes.
