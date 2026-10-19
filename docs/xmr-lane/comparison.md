# How the Monero lane compares

Every decentralized pool has to answer the same five questions:

1. What happens to work that loses the propagation race?
2. Does work below the share difficulty count at all?
3. How do payouts fit in the coinbase, and who holds the money?
4. How does the accounting state stay small enough to sync?
5. How much consensus surface has to be free of bugs?

This page compares the answers of classical p2pool, Monero P2Pool, p2poolv2,
Braidpool and c2pool v37. The v37 column describes the Monero lane as it runs
on stagenet on 2026-10-03. Cells marked *(design)* describe parts that are
written down but not yet running on the lane.

The P2Pool and p2poolv2 columns come from reading their sources (Monero
P2Pool `side_chain.cpp`; p2poolv2 `ShareChain.tla` and its store).

## The comparison, compressed

| Axis | classical p2pool | Monero P2Pool | p2poolv2 | Braidpool | **v37 (Monero lane)** |
|------|------------------|---------------|----------|-----------|-----------------------|
| **Stale work** | lost | uncles: about 80%, depth up to 3, only if a later share references them | lost (classical model) | kept, by DAG topology | **kept at full weight: a receipt carries its own work and is ordered by the bin it was done in; nothing is orphaned. Late work counts while it is inside the late tail (30 bins, about an hour)** |
| **Work below the share difficulty** | not counted | sidechain tiers (main, mini, nano), which split the hashrate | not counted | not counted | **counted: each raindrop (1/64 of the share difficulty) counts as 1/64 of a share; on by default on the Monero lane** |
| **Payout custody** | coinbase, non-custodial | coinbase, non-custodial | coinbase commitments, non-custodial | one output to a t-of-n threshold key | **coinbase, non-custodial; what does not fit waits in an owed ledger that every node keeps** |
| **Coinbase space** | pays everyone, dust outputs | cheap (Monero's dynamic block size) | classical | one output (by custody) | **pay the window in the block; old balances drain from a capped slice; one ledger, every node recomputes the coinbase (no custody)** |
| **Window** | share count | share weight, credited at arrival | share based | DAG cohorts | **bins of performed time, work summed per bin, decay by the age of the bin the work was done in** |
| **Several chains** | merged mining per instance | one chain (Tari merge mining recently) | one chain | one chain | **one lane per chain; only the Monero lane runs today; one account across chains is *(design)*** |
| **State and sync** | full window | window | RocksDB window | DAG | **window of bins; log-size roll-up of older bins *(design)*** |
| **Formal checks and determinism** | none | fixed-point payout math | TLA+ specs | research | **integer-only consensus; TLA+ models of the ledger rules, checked with TLC at small bounds (the C++ is not proven against them)** |
| **Pool-majority attack** (over half of the pool's own hashrate) | reorg the sharechain, orphan honest shares and take their PPLNS place; censor; withhold | the same per sidechain (main, mini and nano are each attackable alone); uncles soften orphaning | sharechain reorg (classical model) | no orphaning in the DAG; payouts depend on the custody signer threshold | **no reorg or orphan path: receipts stand alone, their order is a fixed rule, every node recomputes the coinbase, finality is Monero's (60 blocks); a majority can only leave fresh work out of the blocks it finds, until an honest block includes it, and withhold** |
| **Maturity** | a decade live (now dead on BTC) | production, proven | early | early | **multi-node runs on stagenet; the mainnet run is the Monero CCS milestone** |

## The systems in short

**Classical p2pool** (2011, later maintained in a fork) started the
category: a linear sharechain, a PPLNS window, payouts straight from the
coinbase with no custody. Stale shares are thrown away, the share difficulty
is a hard floor for small miners, and every block pays the whole window, which
fills blocks with dust outputs.

**Monero P2Pool** is the strongest shipped system. Uncle blocks recover late
work at a penalty, three sidechains give small miners a lower difficulty, the
window is capped by Monero's difficulty, and payouts use fixed-point math.
Much of its simplicity comes from Monero itself: RandomX keeps mining on CPUs,
and the dynamic block size lets the coinbase pay every miner in the window in
every block. Uncles only recover work within a small depth and only when a
later share references them; the sidechains split the hashrate instead of
counting small work.

**p2poolv2** is a careful re-engineering of the classical model for Bitcoin:
TLA+ specifications, a RocksDB store, separate candidate and confirmed chains,
and the miner's address bound into each share. Its economics keep the
classical share race, so stale work and the difficulty floor stay as they are.

**Braidpool** removes stale work by topology: shares form a DAG in which
every share is merged. It solves coinbase space with one output to a FROST
threshold key held by the miners, which is a trust assumption p2pool never
needed.

**Ocean/DATUM and Stratum V2 job declaration** are a different class:
miners build their own templates, and Ocean pays in the coinbase, but the
accounting belongs to an operator.

## Where v37 is weaker

1. **Maturity.** Monero P2Pool runs in production. The v37 Monero lane runs
   on stagenet; the mainnet run is still ahead.
2. **Complexity.** v37 has the largest consensus surface in this table:
   receipts, bins, the count rule for raindrops, the owed ledger and the
   drain rule. Our own soak runs and an external review of the payout ledger
   found real bugs before launch, and each moving part is attack surface.
3. **Monero needs it least.** With dynamic blocks and CPU mining, most of
   the payment machinery solves a problem Monero has already solved. It
   matters most on chains with fixed block space and fee competition.
4. **The late tail.** Work older than about an hour can be dropped if a pool
   majority finds every block in that hour and leaves it out. This is being
   worked on.
5. **Stall, not split.** When nodes cannot agree on a booking, a node stops
   and waits rather than split the ledger. A stall is the chosen failure
   mode, and it is a liveness cost.

## What v37 borrowed

The non-custodial coinbase and merged mining from classical p2pool; fixed-point
payout math, a window capped by the chain's difficulty, and the statement of
the small-miner problem from Monero P2Pool; TLA+ discipline and the coinbase
commitment direction from p2poolv2.
