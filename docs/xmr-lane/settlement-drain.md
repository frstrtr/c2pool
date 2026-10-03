# XMR lane: the drain rule (pay the old balances, never create a new one)

Status: **implemented** behind lane rules 23-25 (`drain_rule_version = 1`,
`drain_q = 16`, `drain_h_cap = 64` on every network: the test networks from the
rule's flag day, mainnet from its genesis -- RULES RATCHET R1 made the drain
floor constitutional, R-MIN (c) in [lane-rules.md](lane-rules.md) sec. 4, and
`16 / 64` IS the floor; `0 / 0 / 0` is no longer a mainnet state).
Operator rulings R1-R5 of 2026-10-02, on the settlement study of the same
week. Payout scheme: Work Receipt Settlement (WRS), pay-per-receipt. This page
summarises the study (method, data, numbers) and states the rule as the code
implements it. The study's raw data and run outputs are not in the
repository; their place is named in section 6.

## 1. The problem: the float is a fixed point

A lane block pays two kinds of money: old balances (the owed queue, oldest
first) and its own window (pay-now, each miner's E_b). Before this rule the
owed pass ran first over the whole reward R, so every piconero it paid to an
old balance was a piconero the window was credited but not paid: the window
received the same amount as a new balance. The ledger total
`T = SUM finalW` was invariant under every shipped rule: a float of old
balances (a restart, a migration, seeds, payees that did not fit) only
rotated from one set of keys to the next and never shrank. The study's
four-year replay carried a 1.2 XMR float unchanged from 2022 to 2026 and
re-issued about 0.107 XMR of IOUs in every block (study MODEL F1,
RECOMMENDATION 0).

## 2. The rulings of 2026-10-02

* **R1 Pay-now first.** Old balances are paid only out of a bounded slice
  Delta of the block that the window is not credited. The window's E_b is
  split at `P = R - debt_paid` and paid in full when everyone fits, so no
  canonical block creates a balance. DEBT FIRST (master's step that paid an
  admitted payee's old balance out of a waiting payee's cash) is removed. In
  a contested block the owed pass keeps `K_o = max(1, cap_owed * owed_paid_1
  / R)` slots: debt's slot share is its cash share, which makes "nobody
  admitted" unreachable. `F = 0` is master's coinbase, byte for byte.
* **R2 Drain speed.** 1/16 of block value (fees included) at P2Pool-main
  cadence, normalised per Monero height so that every lane drains at the same
  speed in time (amendment A5).
* **R3 Pool id first.** Before the rule may activate, every consensus-relevant
  lane parameter is committed, so a node with other values refuses the peer
  or does not recognise its lane blocks; never a silent owed_digest fork
  (amendment A2). Implemented by the lane-rules list
  ([`lane-rules.md`](lane-rules.md)); the drain rule's three numbers are its
  fields 23-25.
* **R4 Overflow** (more payees than slots): P2Pool's rule for the waiters
  (their E_b is redistributed to the admitted payees) is accepted; to revisit
  before FCMP++.
* **R5 Same flag day:** the F4 band fix (a balance in `[c(tail), c(R))` the
  owed pass would skip is paid by the dust pass) and the dust-decay clock
  started from the block's gross credited set.
* **O-2 Refused lane blocks count for dh** (ruled 2026-10-02, same flag day).
  A lane block refused on the lane-root path (a stale or unknown 0x03 root)
  is FOUND as an EMPTY booking (credit {}, payout {}) carrying its Monero
  height, so dh is a pure chain function. Its payouts stay node-local
  liability exactly as before. owed_digest may change (V37Z commits it).
* **F4-partial** (ruled 2026-10-02). Only a key whose BALANCE is below
  `c(R)` (the F4 band, and sub-floor dust) goes to the dust pass. A
  budget-stopped owed take below `c(R)` for a creditor whose balance is
  `>= c(R)` is not paid: it carries one block, its age untouched. The unspent
  part of Delta stays in `P = R - debt_paid`, i.e. goes to the current window
  (credited), never to the donation.

Amendments of the adversarial review honoured: A1 (F over the whole ledger,
never filtered by payee-ref resolvability), A3 (the preconditions of "0 new
owed" stated and tested), B5 (K_o from the FIRST owed pass's cash), B6
(`E_b(R) > 0` for every payee with `E_b(P) > 0`, else the build fails closed).

## 3. The rule, exact and integer

Units piconero; every quantity u64, every product u128, every division floor.
Per lane block b at Monero height h, built on (and recomputed from) the
booking-point ledger L:

    F      = SUM over every key of max(0, EffectiveOwed(k))          (A1: the whole ledger)
    dh     = h - prev_lane_height(L)        (0 = no earlier lane block of this pool: the cap)
    Delta  = min(F, R * min(dh, H_cap) / (Q * 16))                   Q = 16, H_cap = 64
           = R / 256 per Monero height, at most R / 4 per lane block, never more than F

* **D0, D2** (`XmrOwedSettlementSource::build`). The owed proposal runs at
  budget Delta (salted K_fair, unchanged). A proposed take below `c(R)` is not
  handed to the owed pass. Its key goes to the dust list only when its
  balance (EffectiveOwed) is below `c(R)` (R5, the F4 band); a budget-stopped
  take below `c(R)` of a balance `>= c(R)` is not paid at all: the creditor
  carries one block with its age untouched (F4-partial), never a sub-c
  output. The dust list is every positive balance below `c(R)` the owed pass
  does not pay (the routed takes and the untaken balances), in the salted
  order; a balance `>= c(R)` is paid by the owed pass alone.
* **D3, D4** (`allocate_exact_sum`). The owed pass pays the proposal. When the
  owed outputs and the pay-now payees that need a slot do not all fit, the
  pass is re-run with `K_o = max(1, cap_owed * owed_paid_1 / R)` slots,
  `owed_paid_1` the first pass's cash. With `owed_paid_1 <= Delta <= R / 4`,
  `K_o <= 674` of 2699.
* **D5.** The dust pass (free slots, salted order) draws on `Delta -
  owed_paid` only, so `debt_paid = owed_paid + dust_paid <= Delta`. It may be
  less than Delta (a carried partial, or no dust to pay): the unspent part is
  in `P = R - debt_paid`, the window's cash.
* **D6.** Admission is decided on `E_b(R)` as before (payouts worth spending
  first, then age, then the salted tie). The amounts are `E_b(P)`,
  `P = R - debt_paid`; with the fee model's 0-amount marker the pay-now pool
  is exactly P, so every admitted payee is paid in full when everyone fits.
  DEBT FIRST is gone. The waiting payees' `E_b(P)` is redistributed to the
  admitted payees (R4); if the admitted payees' `E_b(P)` sums to 0, to the
  payees the owed pass paid, pro rata to what it paid them, never to the
  donation. A payee with `E_b(P) > 0` and `E_b(R) = 0` fails the build closed
  (`BuildError::PayNowSplit`, B6).
* **D7** (the booking). The recompute returns `split_at = P`; the receiver
  refolds the window's E_b at P, applies the redistribution and books net of
  the pay-now. Every window row nets to 0 and the block books
  `dT = -debt_paid`. An empty-cut finder is credited P, what it was paid.
* **dh is ledger state.** A lane block's FOUND carries its Monero height
  (settle-store event schema 6); `prev_lane_height()` is the greatest height
  of a FOUND, non-orphaned lane block, finalized (committed in `owed_digest`
  as "V37Z") or pending. Every node books lane blocks in chain order at the
  same booking point (R6), so every node derives the same dh. Seeds carry no
  height. A lane block refused on the lane-root path (stale or unknown 0x03
  root) is FOUND as an EMPTY booking carrying its height (ruling O-2;
  `XmrNode::on_lane_block_refused`, `FinalizeConnect::found_refused_empty`,
  sidecar kind `e`); its on-chain payout stays node-local liability. The
  minority-converge refold books it the same way: a decoded lane-root
  refusal, and a forced block whose root is not in the scratch ring, is
  FOUND empty; an empty FOUND of the old log is never reused as a booking of
  money. With the rule off nothing is FOUND (master).
* **The decay clock (R5).** The FOUND also carries `G_b = {k : E'_b(k) > 0}`
  (the fold at the cut after the DROPS-due clamp, before redistribution,
  finder and netting). A FINALIZE with a non-empty `G_b` passes by every
  sub-floor key outside it; a key in it resets its clock; an empty cut passes
  nobody by; a debit-only block carries an empty `G_b`.
* **The recompute** derives F, dh and Delta from its own ledger (no claim
  field). The V37N base must state exactly the Delta pass's takes: more is an
  over-take, less an under-take, both a Mismatch (booked debit-only). So is a
  window credited at R, DEBT FIRST kept, more than K_o owed slots, a skipped
  sub-c take, another predecessor's dh, and a version-0 builder. The builder
  cuts its snapshot at the template's final reward (a bounded fixpoint in the
  provider), because Delta is a function of the final total.

With `F = 0`: Delta = 0, no owed or dust output, `P = R`, no re-run: the
coinbase is master's byte for byte (`v37_xmr_drain_kat` B: a golden over
10,000 random X6 inputs captured from master, and the rule on at F = 0
against the rule off on 10,000 more).

**The stated preconditions of "0 new owed"** (amendment A3). A canonical
block creates no balance. Owed is still created by (i) seeds (lane
configuration), (ii) a DROPS due claimed with the window rule off (the claim
adds avail to E_b, so the pool is short) and (iii) a non-canonical block
(debit-only). The drain pays each back: rehearsal M7c drains the 1.04 XMR
seed float in 5 blocks at dh 64 and a DROPS-off due back to 0 once the
deposits stop. The empty-cut finder of a fresh pool is credited exactly its
pay (recompute KAT R19).

## 4. Why R / 256 per height, and why a cap of 64 heights

The operator's number is 1/16 of block value at P2Pool-main cadence (R2).
P2Pool main found a lane block every 16.8 Monero heights over 2022-2026 and
every 18.0 in the 2025 window (median 12, 90th percentile 42, longest gap
182), so "1/16 per lane block" is R / 256 per height. The cap decides both
the worst share one block's window can give up (`H_cap / 256`) and how far
the per-height normalisation reaches before a slow lane is capped:

| H_cap | 16 | 32 | **64** | 128 | 256 |
|---|---|---|---|---|---|
| mean share of a main block while F > 0 (cadence alone) | 4.07 % | 5.67 % | **6.73 %** | 7.02 % | 7.03 % |
| worst share of one block | 6.25 % | 12.5 % | **25 %** | 50 % | 100 % |
| main blocks fully normalised (dh <= H_cap) | 62.8 % | 83.6 % | **96.5 %** | ~100 % | 100 % |

`H_cap = 16` under-drains the main lane itself (it would drain at about 2/3
of the ruled speed). 64 is the smallest cap that keeps main at the ruled
speed, and it bounds any block's give-up to a quarter: the window always
keeps at least 75 % of its block, and in a contested block the owed pass
keeps at most 674 of 2699 slots. 128 and 256 buy slow lanes more speed with
half or all of a block; the cap is committed (field 24), so a different
choice is a new pool, not a fork.

## 5. How the study was done

* **Harness.** A purpose-built simulator (`settle_opt`, C++) that books every
  lane block with the REAL `OwedLedger` (the XMR lane rules: arm floor,
  rotation, dust decay, salted ties) and rebuilds the settlement source as
  the node does. Policies were re-implemented as variants and gated against
  the REAL `allocate_exact_sum` before any result was used: 53,000 random
  inputs byte-identical (every output, role, owed_part, BuildError and
  credit_delta), a negative control that must diverge and does, 394,992 live
  master blocks with 0 mismatches, and every F = 0 block of every rule run
  (224,094) byte-identical to master.
* **Block values and cadence.** Every tail-era Monero block (heights
  2,641,623 to 3,774,700: base + fees, weight, penalty zone), lane blocks at
  the real P2Pool main-chain heights (71,400 tail-era blocks), mini and nano
  cadences from the same census. Windows: 2022-08, the 2024-03 spam wave, 2025
  and 2026, plus a four-year replay (71,392 main-lane blocks).
* **Populations.** Synthetic miners (lognormal hashrate, a persistent
  8640-share window, 0.5 % churn per lane block, leavers keep their balances)
  calibrated to P2Pool's payee counts (main median 41, mini 571), plus two
  hypothetical overflow populations (about 3,300 and 5,000 payees; no P2Pool
  block ever carried more than 875 outputs).
* **Floats.** Presets: 1.04 XMR (rehearsal M7's seeds), 1.2 XMR spread by
  hashrate (a migration), 6 XMR on one key, gone and DROPS debt, a 2,700 x 2c
  debt flood, 10,000 gone dust keys, 1,000 balances inside the F4 band.
* **Review.** An adversarial pass (rated the first text NO-SHIP for two lines
  that would split consensus, A1 and A2, and the missing commitment; with the
  amendments, ship-able) and an independent reproduction (SHIP: a separate
  Python integer model of master and the rule, the flood to the piconero,
  894 run summaries re-aggregated).
* **This implementation's runs.** The per-height mode (`drain=hshare`, 37
  runs on main / mini / nano cadences, two floats, H_cap 16 to 256 and the
  fixed R/16 rule) and the TLA+ model of the rule (`SettlementCanon`, with
  NoNewOwed, DrainBound, SlotShare, SomeoneAdmitted, MasterWhenNoFloat;
  3,051,279 states, every mutation caught) were run before the code.

## 6. Data provenance

Headers and coinbases were fetched read-only from public Monero nodes; the
reproduction lane re-fetched a random sample from a third node the data lane
never used: 50 of 50 headers identical (hash, reward, weights, difficulty,
timestamp, miner tx hash) and 20 of 20 P2Pool coinbases with identical output
multisets and merge-mining tags. The census, the run outputs and the reports
(MODEL, RESULTS, RECOMMENDATION, VERIFY-ADVERSARY, VERIFY-REPRO) are kept
with the study's working files, outside the repository; none of the raw data
is copied here.

## 7. Headline numbers

Master never drains: the float is carried unchanged (section 1). The fixed
rule the study recommended first (`Delta = min(F, R/16)` per lane block)
drained 1.2 XMR in 0.84 days on average over the four windows (6 XMR in 4.3
days) at a give-up of exactly 1/16 of each block while F > 0, and nothing
after; 0 new owed in every pay-now-first block of every run. The per-height
rule of R2 (2025 window, M = 40 payees; days to F = 0 / mean give-up while
F > 0 / worst block):

| lane (mean dh) | float | fixed R/16 | per height, H_cap 64 |
|---|---|---|---|
| main (19.1) | 1.2 XMR | 0.64 d / 6.16 % / 6.25 % | 0.68 d / 5.97 % / 25 % |
| main | 6 XMR | 3.76 d / 6.22 % / 6.25 % | 3.58 d / 6.26 % / 25 % |
| mini (246.6) | 1.2 XMR | 6.09 d / 6.14 % / 6.25 % | 1.38 d / 24.8 % / 25 % |
| mini | 6 XMR | 48.4 d / 6.24 % / 6.25 % | 10.4 d / 20.5 % / 25 % |
| nano (1687.9) | 1.2 XMR | 113.7 d / 6.15 % / 6.25 % | 15.8 d / 24.7 % / 25 % |
| nano | 6 XMR | 382.9 d / 6.24 % / 6.25 % | 128.4 d / 24.6 % / 25 % |

On main the per-height rule is the ruled drain (the two differ only in which
blocks pay: late blocks more, early ones less). Mini drains 4.4x (1.2 XMR)
and 4.7x (6 XMR) faster, nano 7.2x and 3.0x. In all 37 runs: 0 new owed, F
ends at 0, `debt_paid <= Delta` and `Delta <= F` in every block, exact sum,
no advance, and the F = 0 blocks byte-identical to master.

Other findings carried into the rule: K_o bounds a 2,700 x 2c debt flood to
its cash share of the slots (the flood costs speed only in overflow, 0.03 to
1.55 days); the F4 band is paid in about 0.03 days instead of days or never;
fees enter only through R (a fee spike drains more, the give-up share stays
the same); in a hypothetical overflow pool the sub-c waiters lose their share
of those blocks to the admitted payees exactly as on master at F = 0 (R4).

## 8. Code and tests

| piece | code | tests |
|---|---|---|
| Delta, the triple's validity | `x6::drain_delta`, `drain_rule_refusal` (`src/impl/xmr/settle/xmr_drain_rule.hpp`) | `v37_xmr_drain_kat` A, C, F; rehearsal K6 |
| the activation chain: the network triple, the node's ledger rules, the settlement rule, the template context | `apply_network_drain` (`xmr_node_config.hpp`), `XmrNode::ledger_rules`, `drain_rule_of` (`xmr_o2_settlement_source.hpp`), `make_xmr_coinbase_context` | `v37_xmr_drain_wiring_kat` W1, W2 |
| D0, D2 (and F4-partial) | `XmrOwedSettlementSource::build` (`xmr_o2_settlement_source.hpp`, `DrainRule`) | drain A, C, E, I; `v37_xmr_spend_floor_kat` F4b |
| D3-D6 | `allocate_exact_sum` under `CoinbaseInputs::paynow_first`, `AllocStats` | drain B, C, D, D2, D3, G |
| dh, V37Z, the gross clock | `OwedLedgerRules::lane_height`, `decay_from_gross`, `LaneFound` (`w4_settlement.hpp`); FOUND event schema 6 (`xmr_settle_store.hpp`) | recompute R16; spend floor F10b; drain H |
| O-2: the empty FOUND of a lane-root-refused block | `XmrNode::on_lane_block_refused`, `FinalizeConnect::found_refused_empty` (sidecar kind `e`), the refold (`xmr_minority_converge.hpp`) | wiring W5 (dh, V37Z, restart, rule off); `v37_xmr_minority_converge_selfcheck` MC8 |
| the converge refold under the rule | `minority::refold` (lane height and G_b on every FOUND) | `v37_xmr_minority_converge_selfcheck` MC7 |
| the recompute | `canonical_source` (over/under-take at Delta), `Result::split_at` (`xmr_coinbase_recompute.hpp`) | recompute R17, R18 a-h, R19 |
| the booking at P, G_b, the finder at P | `paynow::drain_refold_credit`, `drain_gross_set`, `drain_finder_credit` (`xmr_paynow.hpp`), called by `drain_refold` / `paynow_net` in `main_v37_xmr.cpp` | wiring W4 runs the three functions; main's own fold (`fold_credit`) and the status line are not linked by any KAT: rehearsal M7c and recompute R17/R19 mirror that arithmetic, they do not run it |
| the builder's final-reward fixpoint | `x6::drain_reward_fixpoint` (`xmr_drain_rule.hpp`), called by `xmr_o2_settlement_provider.hpp` | wiring W3 (converges within 4 rebuilds, fails closed beyond); recompute R18 c (an un-fixed reward is a Mismatch) |
| the lane rules and the refusal | fields 23-25 (`xmr_lane_rules_build.hpp`), `lane_knob_refusal` | `v37_xmr_lane_rules_kat` E, `v37_xmr_relay_pool_id_kat` P8c, `v37_xmr_cli_strict_kat` |

## 9. Open points

* `H_cap` 64 against 128 is the operator's fairness call (section 4).
* Ruled (O-2, 2026-10-02): a block refused by the "lane-root-refused" path is
  FOUND as an empty booking carrying its height (section 3). Other refusals
  (a credit-cut mismatch, an unmapped output, a booking stall) are not FOUND,
  as before; a recompute Mismatch is booked debit-only and counts.
* The daemon's own booking path (`fold_credit` at P inside `drain_refold`)
  is proven by reading and by mirrored arithmetic, not by a run of the
  binary: a multi-node stagenet run with a seeded float before the flag day
  (`drain-book:` on every node, `dT = -debt_paid`, one owed_digest per height).
* The first lane block of a pool takes the cap (`dh = 0` maps to `H_cap`);
  with F = 0 at a pool's genesis this is master either way.
* The arm floor is still `spend_floor(kTailSubsidy)` and moves with the input
  weight at the FCMP++ fork; the F4 routing makes the band harmless until
  then. The overflow rule (R4) is to be revisited before FCMP++.
* The study harness and its per-height mode are not in the repository.
