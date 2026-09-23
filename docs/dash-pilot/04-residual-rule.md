# Dash pilot, design note 4: the residual rule

Status: DESIGN NOTE. No code. Needs an operator ruling.
Scope: the v37 btc-dash arm (`c2pool-v37-btc-dash`), DASH testnet pilot T1.
Written against master `018a66b6` + branch `v37/dash-t1-prep`.

## 1. The problem

A v37 DASH block has a miner-spendable value `R_b`: the coinbase total minus
the masternode, platform-burn and superblock payments. The owed ledger credits
`E_b` over the lane cut when block `b` is found (S-1), and W5 turns the oldest
owed balances into coinbase outputs once they are buried (K_fair,
`assemble_if_buried`). The payout for block `b` is almost never exactly `R_b`:

* at the start (the first `D_conf = 100` blocks after activation) nothing is
  buried yet, so there is no eligible owed balance and the W5 payout is empty;
* later, the eligible balances can add up to less than `R_b` (a quiet pool, or
  balances still under `h_min`), or more (a backlog). W4 already caps the
  payout at `R_b` (value-bounded K_fair), but nothing says where the remainder
  `R_b - sum(payout)` goes.

That remainder is the **residual**. Today it is implicit: the arm mines the v36
coinbase (the finder takes all of `R_b`, minus a 1-duff donation output), W5
emission is withheld (`--settlement off`), and the ledger keeps accruing. So
100% of every block is residual, and the owed ledger has never paid anyone.

A residual rule must be **consensus-fixed**. Every node rebuilds the winner's
coinbase from the same inputs (design note 5), so a node-local choice about
where the remainder goes changes the coinbase. The block would then be
rejected, or credited differently on different nodes. This is the same class
of problem as the XMR owner-fee rule.

## 2. The accounting identity

For every block `b`, and so summed over any range of blocks:

    sum(credited E_b)  =  sum(paid in coinbase outputs)
                        + sum(residual carried as owed)
                        + sum(residual routed to the sink)
                        + sum(sub-h_min dust carried)

Per key, the ledger already enforces `finalW += credit; finalW -= payout`
(Settlement.tla G, `btc_node.hpp` FINALIZE). The residual rule only decides
what happens to `R_b - sum(payout_b)`. There are two cases, and they must not
be mixed up:

* **Owed residual.** Balances that were eligible but did not fit (C / K_max /
  h_min) stay in `finalW` and are paid later. No value leaves the ledger.
* **Unallocated residual.** Block value that no owed balance claims, for
  example the whole block in the first 100 blocks. This value is not in the
  ledger. The rule has to send it to a fixed output, or the coinbase is not
  fully specified.

A KAT for the rule must check the identity above per block and cumulatively.
It must also check that the unallocated residual is always
`R_b - sum(payout_b) >= 0` and goes to exactly one output.

## 3. Options

### (a) A residual-sink wallet (the XMR pattern)

One extra coinbase output pays `R_b - sum(payout_b)` to a sink address fixed
by consensus. XMR does this (`xmr_node_config.hpp` residual sink,
`main_v37_xmr.cpp` exact-sum assembly, `xmr_credit_cut.hpp`).

* Pro: the coinbase is fully determined, the output sum is exact, and it is
  already proven on XMR.
* Con: on DASH, "who is the sink" is a policy question. If the sink is a pool
  wallet, the pool operator holds the residual in custody, which v37 exists to
  avoid. If the sink is **the finder's own identity**, (a) is the v36 rule
  ("finder takes the remainder") under another name. That version needs no
  custody and is deterministic, because the finder's identity is on the wire
  (the block-winner descriptor).

### (b) The donation script, as in v36

The residual goes to `COMBINED_DONATION_SCRIPT` (`core/donation.hpp`), the
output p2pool has always had (history: the donation output was a mandatory
anti-forgery marker from day 1, and dust was a residual sink).

* Pro: the simplest option, with p2pool precedent, and no new identity.
* Con: in the first `D_conf = 100` blocks the **whole block** goes to the
  donation, because nothing is buried yet, so all of `R_b` is unallocated.
  Later, in any quiet period, the same happens to the unfilled part. That is
  not acceptable on its own economics. It only works together with a
  bootstrap rule, and then it is really option (a)-finder with a donation
  floor.

### (c) A PPLNS-style fallback

The unallocated residual is split by the current lane weights at the cut
(`fold_eb` at `P`), and not by owed balances.

* Pro: miners are paid from the first block, with no custody and no donation
  windfall.
* Con: it brings back the node-local-`K_fair` fork class that RECON fixed
  (c2pool#1697, K_fair reconstruct-at-cut). The fallback set is computed from
  a view that is not buried. It is only safe if the fallback payout set, or
  the inputs to reproduce it, are carried on the wire and checked against the
  mined coinbase (design note 5, v0x03). The cost is a larger wire format and
  a verification path on every block.

## 4. The first D_conf = 100 blocks

| option | blocks 1..100 | steady state |
|---|---|---|
| (a) sink = finder | finder gets all of `R_b` (the v36 behaviour, unchanged) | finder gets the remainder after K_fair |
| (a) sink = pool wallet | pool wallet gets all of `R_b` (custody) | pool wallet gets the remainder |
| (b) donation | donation gets all of `R_b` (not acceptable) | donation gets the remainder |
| (c) PPLNS fallback | lane-weighted payout from block 1 | K_fair first, then a lane-weighted remainder |

In every option the ledger keeps crediting `E_b` from block 1. The residual
rule only decides who is paid now for value the ledger does not yet owe. With
(a)-finder, activation cannot surprise a miner: before anything is buried, the
coinbase is byte-for-byte the v36 coinbase.

## 5. Recommendation

**(a) with sink = the finder's identity, plus the 1-duff donation kept as a
fixed consensus output. This is a hybrid of (a) and (c), without the unsafe
part of (c).**

* The coinbase is `[masternode/burn/superblock] ++ K_fair(owed, C, K_max,
  h_min) ++ [finder: R_b - sum(K_fair) - 1] ++ [donation: 1 duff]
  ++ [OP_RETURN]`.
* It is deterministic from the winner descriptor (the finder identity is on
  the wire) and the owed state at the cut. The receiver rebuilds it and
  RECON-checks it against the mined coinbase (step-3 machinery, see design
  note 5).
* The first 100 blocks behave exactly like v36. Owed payouts then phase in as
  blocks are buried, with no switchover discontinuity.
* No custody, and no donation windfall.
* Pool-level PPLNS smoothing (c) can be added later as a v37.0x subversion,
  once v0x03 carries a verifiable payout set. It should not be in T1.

**Pilot parameters** (see note 5 for C/K_max): keep `k_floor = 1`
(`h_min(P2PKH) = 34` duffs) **only if** outputs below the DASH dust threshold
are acceptable in a coinbase. dashd accepts them (the 1-duff donation output
proves it), but wallets treat them as dust. The recommendation is `k_floor =
17`, which gives `h_min(P2PKH) = 578 >= 546` duffs (DASH dust at the default
relay fee). Balances below the floor carry forward and are never dropped.

**Ruling needed:** (1) the sink identity, finder (recommended) or a pool
wallet; (2) `k_floor` 17 (recommended) or 1; (3) whether the 1-duff donation
stays mandatory in v37 DASH coinbases (recommended yes, for v36 parity and as
the anti-forgery marker).
