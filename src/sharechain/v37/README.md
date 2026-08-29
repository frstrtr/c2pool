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


> **Purple paper.** A strict, Satoshi-style technical paper stating the architecture and properties of the system is in [`PURPLE-PAPER.md`](PURPLE-PAPER.md). The full formal specification is maintained separately and is not reproduced here.

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

---

## How V37 compares

A principles-level comparison against prior decentralized peer-to-peer pool designs. Implementations are
not named: **`p2pool-canonical (forrest)`** is the original; **`p2pool_1..3`** are later lineages;
**`V37`** is this branch. V37 status marks: ✅ implemented · 📐 designed · 🅿️ planned (V37.0) · ⏳ V37.x ·
🔮 vision/roadmap. This shows *what* each design does, not *how* V37 implements it — the detailed design
lives in a separate research repository.

### Foundations
| Property | p2pool-canonical (forrest) | p2pool_1 | p2pool_2 | p2pool_3 | **V37** |
|---|---|---|---|---|---|
| Sharechain structure | linear (1 share/height) | linear, size-split chains | linear + uncle shares | linear (merged) | ✅ multi-lane roundabout (multi-resolution roll-up) |
| Multichain / merged | ❌ one coin per daemon | ❌ single-coin | ❌ single-coin | ⚠️ aux-merged | ✅ native multichain lanes (first-class `chain_id` axis) |
| Cross-algorithm work | ❌ | ❌ | ❌ | ❌ | ✅ work normalized across Scrypt/SHA-256/X11; 🔮 one hash → many chains |
| Payout math cost | O(log n)–O(window) | O(window) | O(n)–O(log n) | O(window) recompute | ✅ **O(1) amortized push, O(active miners) payout** |
| Numeric basis | float/int | native int | native types | fixed-point | ✅ unsigned **62-bit fixed-point**, bit-reproducible cross-toolchain |

### Work accounting & retention
| Property | canonical | p2pool_1 | p2pool_2 | p2pool_3 | **V37** |
|---|---|---|---|---|---|
| Ledger model | ledger of **shares** | ledger of shares | ledger of shares + uncles | ledger of shares | 📐 **ledger of balances** — per-miner accumulator + moving `paid` high-water-mark |
| Old work outside window | **evaporates** | evaporates | settled via side-trades | evaporates | ✅ **never expires** — folded into compact immutable buckets, raw work kept forever |
| History storage | flat, memory-heavy | flat per sub-chain | flat DB (RocksDB-class) | dense ring | ✅ multi-resolution pyramid (whole history in ~MB) |
| Weight basis | work(target), no decay | work(target) | work(target) | work(target)+decay | ✅ work(target) + origin-bin age-decay (luck-neutral, vardiff-safe) |
| Light-client verification | ❌ full node | ❌ full daemon | ❌ full node | ❌ | 📐 **log-size Merkle proofs** (phone-class) |

### Coinbase & small-miner payout — *the core problem*
| Property | canonical | p2pool_1 | p2pool_2 | p2pool_3 | **V37** |
|---|---|---|---|---|---|
| Coinbase strategy | 1 output/miner until full | relies on **dynamic block size** | top direct + tail via **atomic swaps/market-makers** | bounded, redistribute | 📐 **moving queue to a derived weight/value budget** (no magic cap) |
| Sub-threshold miners | **confiscated → donation** | routed to Mini/Nano chain | sold to external market-makers | swept to donation | 📐 **owed balance grows** until it crosses a fee-pegged spendability threshold |
| Block-size dependence | hard cliff | sidesteps (elastic blocks) | bypassed off-chain | hard cap | 📐 decoupled — reach is unbounded, only *instant* payout is block-bounded |
| Long-tail settlement | ❌ lost | separate chain | external swaps | ❌ | ⏳ **single Merkle-root commitment** → O(1) coinbase outputs for the whole tail |
| Fairness floor | ❌ | per-chain | market-priced | ⚠️ | 📐 long-wait priority (K_fair) + anti-hop vesting |
| Reorg / double-pay safety | sharechain-reorg only | sharechain | uncle fork-choice | sharechain | 📐 **dual-finality gate** (parent + sharechain) + pending overlay |

### Stale/late work & pool-hopping
| Property | canonical | p2pool_1 | p2pool_2 | p2pool_3 | **V37** |
|---|---|---|---|---|---|
| Stale/late share | **discarded** | discarded (fast prop. helps) | **uncle = partial credit** | discarded | 📐 **full credit via work-receipts (RDWR)**, no timestamp trust |
| Pool-hopping resistance | ❌ weak | ⚠️ | ⚠️ | ✅ hardened | ✅✅ structural (decay + vesting kill persistence value) |
| Small-miner variance | high | low (Mini chain) | low (uncles+market) | medium | ✅ low (work persists + off-coinbase settlement) |

### Sync, scale & verification
| Property | canonical | p2pool_1 | p2pool_2 | p2pool_3 | **V37** |
|---|---|---|---|---|---|
| Initial sync | full O(n) (stalls) | full daemon | full node | O(n) | 📐 lanes + lite proofs; ⏳ **stateless root-sync** |
| Whole-chain-as-history | ❌ | ❌ | ❌ | ❌ | ✅ archive pyramid (no-evict lanes) |
| Formal verification (TLA+) | ❌ | ❌ | ❌ | ❌ | ⏳ **in progress** (settlement + lane-invariant specs) |
| Adversarial red-team | ad-hoc | community | active | v36 audits | ✅ 5 formal rounds → convergence |
| Determinism gate | — | — | consensus tests | KAT | ✅ bit-exact reference gate, 100K+/1.6M-check suites |

### Products built on the work-receipt engine — *none exist in prior pools*
| Product | canonical … p2pool_3 | **V37** |
|---|---|---|
| Permissionless miner messaging | ❌ | 📐 work-priced, work-TTL, derived-key, cross-sharechain |
| Anti-spam / rate-limit service | ❌ | 📐 perishable-receipt "hashcash with memory" |
| Hashrate marketplace | ❌ | 📐 template-bound delivery; the sharechain *is* the delivery log; trustless proof-of-delivery |
| Settlement / DEX venue | ❌ | 📐 consensus-measured settlement *(difficulty-derivatives dropped — no edge over on-chain difficulty)* |
| PoW-as-a-Service / wallet oracles / DHT discovery | ❌ | 🔮 roadmap |

---

> **Honest boundaries.** No design fits unlimited simultaneous outputs into a finite block — that is physics.
> What V37 removes is the *coupling* that made coinbase space limit who can ever be credited: reach is
> unbounded, instant payout is block-bounded by a *derived* budget, and the unpaid remainder is preserved and
> provable rather than discarded. The superlight-verification primitives it uses (succinct chain proofs,
> committed-state accumulators) are re-combined prior art, not unique; the genuinely-novel core is the
> **work-receipt + two-ledger finality-gated distribution** and the **archive-pyramid / origin-bin temporal
> model**. Roadmap rows (⏳ V37.x, 🔮 vision) are not committed V37.0 scope.

## Where the rest lives
The detailed design, formal specification, adversarial-review record, and economic analysis are maintained
in a separate research repository and are **not** reproduced here. This branch shows the core features and a
runnable prototype — it is intentionally not the full blueprint.
