# XMR lane against the Purple Paper

Audit of 2026-09-30. The paper is `src/sharechain/v37/PURPLE-PAPER.md`, with
§6, §8 and §9 as corrected on the audit date. The code is the XMR lane on
branch `claude/nifty-allen-ktyg1s`. Each item was confirmed by reading the
code.

## Fixed at audit time

| # | finding | fix |
|---|---|---|
| A1 | **Live bug.** The relay share verdict got coinbase height + 1: `ctx->height + 1`, where the ChainView already maps `prev_id` to the new block's height. Every honest relayed share was rebuilt one block high, refused as non-canonical, and its sender took a strike. | Now passes `ctx->height`. Pinned by `v37_xmr_relay_multinode_kat` M2: the verdict sees height 100 for all 7 receipts. It was red on the old code. |
| A6 | Replaying the winner's served order checked only the spine. A winner could count one of its own receipts twice to steer the next anchor, and its own spine would include the duplicate. | A served order that repeats a receipt id is refused, and the serving peer is set aside. **Still open:** a duplicate that spans the served `[a0, P)` and this node's own `[0, a0)`. Also open: a canonical-order rule, `(bin, id)` with a bounded late tail. |

## Open, consensus-affecting (need a ruling)

| # | finding | direction |
|---|---|---|
| A2 | **Fee model:** a receipt with give-author d > 0 is two lane pushes, `(payee, 65535-d)` and `(donation, d)`. At the default d = 66, one receipt takes two window positions. The window is then no longer a fixed count of equal units: a d > 0 receipt ages and evicts others' work twice as fast per unit of work. | One position per receipt: split by d at fold/project time, or push the donation part without advancing the cover and the decay index. |
| A3 | **DROPS enrolment needs a full lane share** (`lane_enrollment` reads only `base_first` and `shares`). A miner that never meets `share_diff` is never enrolled and earns nothing, which is exactly the miner DROPS exists for. | Under Count there is no selection gradient, so enrol at the first raindrop as well: it is PoW-bound to its payee, and enrolment stays ex-ante from bin + 1. |
| A4 | **DROPS work is priced once**, at one lane block's slice, for the interval that block harvests. A share earns a slice at every lane block over its window life. At equal work a raindrop earns about 1/R of a share-hash, where R ≈ the effective window / shares per lane block. | Credit raindrops through the window. For example a lane push of weight att(floor) per counted hash, with share weight scaled to att(share) and the window made work-denominated, so raindrops do not deflate it. Or state and derive the one-shot price. Needs a KAT: long-run income per hash, share-only miner against DROPS-only miner. |
| A5 | **The DROPS delta is added after pay-now's net booking.** It becomes an owed balance, never paid in the block. Below the spend floor the owed pass never pays it, and it can decay. A negative REPLACE delta can make a paid share miner's balance negative. | Compose DROPS into E_b before `allocate_exact_sum`, so it is paid in the block like everyone else. Bound a negative delta by that interval's share credit. |
| A7 | **Pay-now and E_b come from the anchor:** the cut of the latest finalized lane block, at least D_conf = 60 blocks old. A new pool has no anchor, and the finder takes the block. | Paper §9 should state it. |
| A8 | **The owed pass never pays a balance below the spend floor c**, whatever room the block has (`arm_floor`). Paper §9 says such amounts only wait "when the block is full". | Paper: state that balances below c are not paid by the queue. Or code: pay them after the others while slots are free. |
| A9 | **Dust decay writes off owed balances.** Its horizon and half-life borrow the lane window, 8640 and 2160 positions, but apply them as Monero heights. The abstract, §14 and §16 say "without loss of owed funds". | Paper: add the write-off rule. Code: define the horizon in heights explicitly. |

## Paper-only (not consensus)

1. **§2, §3, §4, §15 describe the time window:** bins gated on burial, decay by bin age, late work "decays as if on time", "value matures with age". XMR ships the positional lane: bins are not burial-gated, decay goes by arrival position, a late receipt is the youngest, and fresh weight counts most. §6 already says the shipped window is positional. Mark §2–§4 as the planned form, or rewrite them.
2. **Estimator wording is stale:** the last sentence of §5, the abstract, §15 ("cannot inflate its estimate") and §16 ("achieved difficulty … can estimate work") no longer match Count.
3. **§13's Merkle root and logarithmic light-client proofs are not implemented.** `owed_digest` is a flat hash with a depth-0 0x03 root. The real verification is that every node recomputes the coinbase, with debit-only booking, V37R and the anchor rule, and the paper does not describe it.
4. **§9 fee paragraph:**
   - fee model v1 is mandatory on mainnet, and the donation output (0-amount marker) is always present;
   - give-author defaults to 0.1%;
   - give-author is a per-receipt weight split, not "a share of jobs";
   - it is "reported to the miner" only in the log and on the dashboard. The stratum login reply carries neither the fee nor `c`, although `payout-threshold.md` §4 claims it carries `c`. #1880 adds the disclosure.
5. **§7 (one identity across lanes, work comparable by att(T)):** XMR runs a single lane with weight 1 or 65535, which is not att(T). That is fine for one lane with a pinned `share_diff`; it must become att(T) before XMR joins a record shared across lanes.
6. **§10 and §11 are not implemented; §12's MRR summaries are off.**
7. **DROPS give-author** splits each payee's delta by its mean d over the prefix, not per hash (low).

## Doc drift

- `docs/xmr-lane/README.md`, PT row: says "not yet implemented, cash is advanced". It is implemented and never an advance.
- `coinbase-recompute.md` §2: `n`/`n+1` cap latitude. With the spend floor on, only the wire cap is accepted.
- `review-criticals.md`, window row: "every receipt is the same work" does not hold under the fee model (A2).
