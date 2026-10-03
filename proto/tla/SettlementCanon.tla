--------------------------- MODULE SettlementCanon ---------------------------
\* c2pool v37 XMR lane: the finality-gated settlement of Settlement.tla under the
\* every-node coinbase recompute (docs/xmr-lane/coinbase-recompute.md).
\*
\* Every node rebuilds a lane block's coinbase from inputs it holds at the block's
\* booking point and compares it with the coinbase on chain
\* (xmr_coinbase_recompute.hpp, verify_lane_coinbase). The verdict decides the booking
\* (main_v37_xmr.cpp, canon_check / book_from_chain_ex):
\*
\*   canonical    the on-chain payouts are the recompute's: the block is booked with its
\*                credit (E_b at the split point P plus the redistribution delta) and its
\*                payouts.
\*   mismatch     anything else: booked DEBIT-ONLY. Its on-chain payouts are debited
\*                (forward repair, never a clawback) and its credit is dropped.
\*   undecidable  the view at the block's cut is not readable on this node yet: the block
\*                is HELD (cut-pending). It is not booked, nothing after it is booked, and
\*                the finalize cursor does not pass its booking point until it is decided.
\*                It is never booked debit-only for being undecidable.
\*
\* The booking point of the block at height h: every lower block booked, the finalize
\* cursor at h - 1 - D_conf (R6). The honest builder assembles a template only there
\* (the booking-point gate), so its coinbase is the one every node recomputes.
\*
\* PAY-IN-BLOCK, in abstract form (x6::allocate_exact_sum under the spend floor, its
\* credit_delta; payout-threshold.md section 3), with the DRAIN RULE of the operator
\* rulings of 2026-10-02 (R1 pay-now first, R2 drain per Monero height). A block carries
\* dh, the Monero heights since the previous lane block (a chain fact, the same for the
\* builder and every receiver). `Alloc(E, ord, dh)` at the booking point:
\*   0. the drain budget: F = SUM of every positive EffectiveOwed (the whole ledger, never
\*      filtered by payee reference: amendment A1), and
\*         Delta(dh) = min(F, (Reward * min(dh, HCap)) div DrainQ)
\*      (in the lane DrainQ = Q * 16 = 256 and HCap = 64: R/256 per Monero height, at
\*      most R/4 per block; HCap < DrainQ keeps Delta < R);
\*   1. owed pass: keys with EffectiveOwed > 0 in the block's order, each paid
\*      min(EffectiveOwed, budget left) out of Delta, never more, one slot each, at most
\*      min(OwedCap, Cap) keys. Contested slots (the window payees that need a slot plus
\*      the owed keys exceed Cap): the pass is re-run with
\*         K_o = max(1, (Cap * owed_paid_1) div Reward)
\*      slots, owed_paid_1 the FIRST pass's cash (amendment B5): debt's slot share is its
\*      cash share. debt_paid = what the pass pays; P = Reward - debt_paid;
\*   2. admission, on E_b at the whole Reward as before: payees with E_b > 0 in the same
\*      order; a payee with an owed output needs no slot, any other takes a free slot or
\*      waits;
\*   3. pay-now first: the window's credit is E_b(P), the same weights split at P (exact
\*      sum, largest remainder); the admitted payees are paid their E_b(P) in full
\*      (SUM E_b(P) <= P = the cash left), so no canonical block leaves a window payee a
\*      new balance;
\*   4. the master step DEBT FIRST (the cash the split leaves pays the admitted payees'
\*      balances the owed pass left) is REMOVED: old balances are paid only out of Delta;
\*   5. redistribution: what is left, up to the waiting payees' E_b(P), comes off the
\*      waiting payees' credit (credit_delta) and goes, with the same amount of credit,
\*      to the admitted payees pro rata to their E_b(P). When the admitted payees' E_b(P)
\*      sums to 0 (nobody admitted, or a one-unit E_b floored to 0 at P < R) it goes to
\*      the payees the owed pass paid in this block, pro rata to what it paid them,
\*      merged into their outputs (operator ruling 2026-10-02). Cash and credit move
\*      together, so the delta sums to zero. Only a block with no payee output at all (no
\*      slot for anyone, Cap = 0 here) moves no cash: the waiting payees' credit still
\*      comes off and the cash stays in the residual, because crediting work whose cash
\*      went to the donation output would be a claim nothing backs;
\*   6. the rest stays in the residual (the donation output).
\* No advance: no step pays a key more than its positive balance plus its credit. With
\* F = 0 the rule is master's allocation exactly (MasterWhenNoFloat).
\*
\* MASTER (DrainQ = 0; lane rules drain_q = drain_h_cap = drain_rule_version = 0): the
\* allocation before the rule. The owed pass draws on the whole Reward with no K_o, the
\* window is credited at the whole Reward (a short pool leaves the window payees a
\* balance) and DEBT FIRST pays the admitted payees' balances out of the cash the split
\* leaves. SettlementCanon_master.cfg checks it; NoNewOwed fails there (wit-master-new-owed).
\*
\* Abstractions. `ord` stands for oldest first with the salted tie
\* sha256d("V37T" || prev_id || key): it is an input of the block, the same for the
\* builder and every receiver, and the model checks every order. The spend floor c is 0
\* (no dust class, no A8 dust pass, so debt_paid is the owed takes and the R5 fixes, the
\* F4 band and the dust-decay clock, have nothing to act on here). The V37N base is not
\* modelled. `dh` ranges over 1..HCap (min(dh, HCap) is all the rule reads; a block that
\* is not the honest builder's carries dh = 1). The float has one source, the genesis
\* balances `seed`: the paths that the operator rulings list as still creating a balance
\* (the empty-cut finder credit, DROPS due with the window rule off; amendment A3) are
\* not modelled, so NoNewOwed here is the claim for a canonical block, under the
\* recompute, with those paths absent. Reorgs below FINALIZE are Settlement.tla's subject
\* and are not repeated here. The share rule (V37R: a share's coinbase must be canonical)
\* is the same recompute applied to a share; here a block's window credit E is taken as
\* already built from canonical shares.

EXTENDS Naturals, Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Miners,          \* payee keys
    Reward,          \* cash a lane block distributes (the exact-sum total less the fixed outputs)
    SeedMax,         \* each key's genesis balance (the seeded float) is in 0..SeedMax
    Cap,             \* payee output slots in one coinbase, owed and pay-now outputs together
                     \* (0: no slot for any payee, the degenerate case)
    OwedCap,         \* the most keys the owed pass takes in one block
    FINALITY_DEPTH,  \* D_conf: a block finalizes once FINALITY_DEPTH later blocks are booked
    MaxChainLen,     \* model bound: lane blocks on the chain
    DrainQ,          \* R2: the drain divisor, Q * the reference cadence (16 * 16 = 256 in
                     \* the lane); 0 = master (the allocation before the rule)
    HCap,            \* R2: the cap on the Monero heights one block counts (64 in the lane)
    Mutation         \* "none", or one negative control (check-settlement-canon.sh)

\* HCap < DrainQ (Delta < Reward) is the lane-rules validity condition; it is not assumed
\* here so that a config can show it is needed (mut-hcap-full in check-settlement-canon.sh).
ASSUME /\ Reward \in Nat \ {0}
       /\ SeedMax \in Nat
       /\ Cap \in Nat
       /\ OwedCap \in Nat
       /\ FINALITY_DEPTH \in Nat \ {0}
       /\ MaxChainLen \in Nat
       /\ DrainQ \in Nat
       /\ HCap \in Nat \ {0}
       /\ Mutation \in {"none", "foreign_credit", "authority", "advance", "debt_unbounded",
                       "redistribute_to_nobody", "keep_credit_unbacked",
                       "degenerate_keep_credit", "held_debit", "nogate",
                       "debt_first_on", "delta_unbounded", "no_ko", "credit_at_reward",
                       "split_at_delta"}

VARIABLES
    chain,   \* Seq of lane blocks on the chain, oldest first (index = lane height)
    book,    \* Seq of bookings: book[i] is the FOUND booking of chain[i]
    fin,     \* the finalize cursor: chain[1..fin] are FINALIZED into owed
    owed,    \* [Miners -> Int] finalized balances (finalW); negative = a debt
    seed     \* the genesis balances (ghost, fixed at Init)

vars == << chain, book, fin, owed, seed >>

-------------------------------------------------------------------------------
\* Helpers

Zero == [ m \in Miners |-> 0 ]
Max(a, b) == IF a >= b THEN a ELSE b
Min(a, b) == IF a <= b THEN a ELSE b
Pos(x) == Max(x, 0)

RECURSIVE SumOver(_, _)
SumOver(f, S) == IF S = {} THEN 0
                 ELSE LET x == CHOOSE y \in S : TRUE IN f[x] + SumOver(f, S \ {x})
Sum(f) == SumOver(f, Miners)

\* Every order of the keys (stands for oldest first with the salted tie).
Perms == { s \in [ 1..Cardinality(Miners) -> Miners ] :
             \A k \in Miners : \E j \in DOMAIN s : s[j] = k }
FirstOrd == CHOOSE s \in Perms : TRUE
\* A block's window credit E_b at its cut, and any payout vector its cash covers.
Windows   == { e \in [ Miners -> 0..Reward ] : Sum(e) <= Reward }
Coinbases == { p \in [ Miners -> 0..Reward ] : Sum(p) <= Reward }
\* dh: the Monero heights since the previous lane block, as far as the rule reads it.
Steps     == 1..HCap

Height == Len(chain)
Booked == Len(book)

\* Pay-now net booking (paynow::net_booking): a booked block's PENDING payout to m is net
\* of what it also credits m, min(credit, paid). A debit-only block credits nothing, so its
\* whole payout is pending.
NetPay(i, m) == Pos(chain[i].pay[m] - book[i].credit[m])

RECURSIVE PendPay(_, _)
PendPay(j, m) == IF j <= fin THEN 0 ELSE NetPay(j, m) + PendPay(j - 1, m)

\* EffectiveOwed = finalW - SUM(pending payouts) (w4_settlement.hpp effective_owed).
EO(m) == owed[m] - PendPay(Booked, m)

\* R2/A1: the float the drain pays down is EVERY positive EffectiveOwed.
Float == Sum([ m \in Miners |-> Pos(EO(m)) ])
\* R2: the slice of a block that comes dh heights after the previous lane block, before
\* the clamp by the float, and the drain budget Delta. DrainQ = 0: no slice (master).
Slice(dh) == IF DrainQ = 0 THEN 0 ELSE (Reward * Min(dh, HCap)) \div DrainQ
Delta(dh) == Min(Float, Slice(dh))

-------------------------------------------------------------------------------
\* The allocation, a pure function of the booking-point state and the block's inputs.

\* Exact-sum pro-rata split of `amount` over the weights `w`: floor shares, then one unit
\* each by largest remainder, ties by the order (x6 paynow_split / prorata).
LR(amount, w, ord) ==
    LET S    == Sum(w)
        fl   == [ k \in Miners |-> (amount * w[k]) \div S ]
        rm   == [ k \in Miners |-> (amount * w[k]) % S ]
        left == amount - Sum(fl)
        pos(k)  == CHOOSE j \in DOMAIN ord : ord[j] = k
        rank(k) == Cardinality({ x \in Miners : rm[x] > rm[k] \/ (rm[x] = rm[k] /\ pos(x) < pos(k)) })
    IN  [ k \in Miners |-> fl[k] + (IF rm[k] > 0 /\ rank(k) < left THEN 1 ELSE 0) ]
\* paynow_split: each <= its weight; a pool that covers every weight pays each in full.
PaySplit(amount, w, ord) ==
    IF amount = 0 \/ Sum(w) = 0 THEN Zero ELSE IF amount >= Sum(w) THEN w ELSE LR(amount, w, ord)
\* prorata: uncapped.
Prorata(amount, w, ord) == IF amount = 0 \/ Sum(w) = 0 THEN Zero ELSE LR(amount, w, ord)

\* R1: the window's credit at the split point P (x6 paynow_at(P), split_reward(P, view)):
\* the same weights, the window's share of P, exact-sum by largest remainder. P = Reward
\* gives E itself. Each key gets at most its E (B6: E_b(P) > 0 only where E_b(R) > 0).
CreditAt(E, P, ord) ==
    IF Sum(E) = 0 \/ P = Reward THEN E ELSE LR((Sum(E) * P) \div Reward, E, ord)

\* 1. The owed pass: at most `cap` slot-taking keys, out of the budget `left`.
RECURSIVE OwedWalk(_, _, _, _, _, _)
OwedWalk(ord, j, left, n, cap, take) ==
    IF j > Len(ord) THEN take
    ELSE LET k == ord[j]
             t == IF EO(k) > 0 /\ n < cap THEN Min(EO(k), left) ELSE 0
         IN  OwedWalk(ord, j + 1, left - t, IF t > 0 THEN n + 1 ELSE n, cap, [ take EXCEPT ![k] = t ])

\* 2. Admission.
RECURSIVE AdmitWalk(_, _, _, _, _, _)
AdmitWalk(ord, j, free, E, take, adm) ==
    IF j > Len(ord) THEN adm
    ELSE LET k == ord[j]
         IN  IF E[k] = 0 THEN AdmitWalk(ord, j + 1, free, E, take, adm)
             ELSE IF take[k] > 0 THEN AdmitWalk(ord, j + 1, free, E, take, [ adm EXCEPT ![k] = TRUE ])
             ELSE IF free > 0 THEN AdmitWalk(ord, j + 1, free - 1, E, take, [ adm EXCEPT ![k] = TRUE ])
             ELSE AdmitWalk(ord, j + 1, free, E, take, adm)

\* 4. Debt first (master only; the rule removes it).
RECURSIVE DebtWalk(_, _, _, _, _)
DebtWalk(ord, j, spare, need, add) ==
    IF j > Len(ord) \/ spare = 0 THEN add
    ELSE LET k == ord[j]
             d == Min(spare, need[k])
         IN  DebtWalk(ord, j + 1, spare - d, need, [ add EXCEPT ![k] = d ])

\* The rule's four changes against master. A rule-change set `rc` selects which are in
\* force: {} is master, RuleChanges is the rule. A negative control switches one off.
RuleChanges == {"drain_budget", "slot_share", "credit_at_p", "no_debt_first"}
\* MUTATION "delta_unbounded": the owed pass draws on the whole Reward, not on Delta.
\* MUTATION "no_ko": contested slots, the owed pass keeps every slot it filled.
\* MUTATION "credit_at_reward": the window is credited at the whole Reward while Delta
\*   pays old balances (master's split, the short pool leaves the window a balance).
\* MUTATION "debt_first_on": DEBT FIRST is kept.
SwitchedOff ==
    CASE Mutation = "delta_unbounded"  -> {"drain_budget"}
      [] Mutation = "no_ko"            -> {"slot_share"}
      [] Mutation = "credit_at_reward" -> {"credit_at_p"}
      [] Mutation = "debt_first_on"    -> {"no_debt_first"}
      [] OTHER                         -> {}
InForce == IF DrainQ = 0 THEN {} ELSE RuleChanges \ SwitchedOff

AllocBy(E, ord, dh, rc) ==
    LET cap0   == Min(OwedCap, Cap)
        budget == IF "drain_budget" \in rc THEN Delta(dh) ELSE Reward
        take1  == OwedWalk(ord, 1, budget, 0, cap0, Zero)
        paid1  == Sum(take1)
        nOwed1 == Cardinality({ k \in Miners : take1[k] > 0 })
        \* the window payees that need a slot (E_b > 0, no owed output)
        wd     == Cardinality({ k \in Miners : E[k] > 0 /\ take1[k] = 0 })
        contested == wd + nOwed1 > Cap
        \* B5: K_o from the FIRST pass's cash; the pass is re-run with that slot cap.
        ko     == IF "slot_share" \in rc /\ contested /\ nOwed1 > 0
                  THEN Max(1, (Cap * paid1) \div Reward) ELSE cap0
        take   == IF nOwed1 > ko THEN OwedWalk(ord, 1, budget, 0, ko, Zero) ELSE take1
        nOwed  == Cardinality({ k \in Miners : take[k] > 0 })
        debtPaid == Sum(take)
        pool   == Reward - debtPaid
        \* R1: P = Reward - debt_paid. MUTATION "split_at_delta": P = Reward - the slice
        \* before the clamp by F (the window gives up the whole slice, also with no float).
        P      == IF "credit_at_p" \in rc /\ Mutation = "split_at_delta"
                  THEN Reward - Slice(dh) ELSE pool
        EP     == IF "credit_at_p" \in rc THEN CreditAt(E, P, ord) ELSE E
        adm    == AdmitWalk(ord, 1, Cap - nOwed, E, take, [ k \in Miners |-> FALSE ])
        tk     == [ k \in Miners |-> IF adm[k] THEN EP[k] ELSE 0 ]
        split  == PaySplit(pool, tk, ord)
        \* MUTATION "debt_unbounded" (master): the debt pass ignores what the owed pass left.
        need   == [ k \in Miners |-> IF ~adm[k] THEN 0
                                    ELSE IF Mutation = "debt_unbounded" THEN Reward
                                    ELSE Pos(EO(k) - take[k]) ]
        debt   == IF "no_debt_first" \in rc THEN Zero
                  ELSE DebtWalk(ord, 1, pool - Sum(split), need, Zero)
        spare  == pool - Sum(split) - Sum(debt)
        wait   == [ k \in Miners |-> IF adm[k] THEN 0 ELSE EP[k] ]
        nobody == ~\E k \in Miners : adm[k]
        \* Who takes the moved cash: the admitted payees by E_b(P); when that sums to 0
        \* (nobody admitted, or a one-unit E_b floored to 0 at P < R), the payees the owed
        \* pass paid, by what it paid them; else nobody (no payee output). Under master
        \* E_b(P) = E_b, so "sums to 0" is "nobody admitted", the ruling as before.
        \* MUTATION "redistribute_to_nobody": the rule before the ruling: with nobody
        \* admitted the cash goes to nobody, the waiting credit still comes off.
        recv   == IF Sum(tk) > 0 THEN tk
                  ELSE IF Mutation = "redistribute_to_nobody" THEN Zero
                  ELSE take
        \* MUTATION "keep_credit_unbacked": with nobody admitted nothing moves, the
        \* waiting payees keep their credit and the cash goes to the residual.
        \* MUTATION "degenerate_keep_credit": the same, only with no payee output at all.
        stuck  == nobody /\ (Mutation = "keep_credit_unbacked"
                            \/ (Mutation = "degenerate_keep_credit" /\ Sum(take) = 0))
        moved  == IF stuck THEN 0 ELSE Min(spare, Sum(wait))
        plus   == Prorata(moved, recv, ord)
        minus  == PaySplit(moved, wait, ord)
    IN  [ debt      |-> debt,
          nobody    |-> nobody,
          plus      |-> plus,
          contested |-> contested,
          paid1     |-> paid1,
          nOwed     |-> nOwed,
          capped    |-> nOwed1 > ko,
          debtPaid  |-> debtPaid,
          ep        |-> EP,
          tk        |-> tk,
          pay       |-> [ k \in Miners |-> take[k] + split[k] + debt[k] + plus[k] ],
          \* MUTATION "advance": the redistributed cash is paid but not booked as credit
          \* (the cash of a payee without a slot paid as an advance).
          credit    |-> IF Mutation = "advance" THEN EP
                        ELSE [ k \in Miners |-> EP[k] + plus[k] - minus[k] ] ]

\* The allocation in force, and master's, for the same block.
Alloc(E, ord, dh)       == AllocBy(E, ord, dh, InForce)
MasterAlloc(E, ord, dh) == AllocBy(E, ord, dh, {})

-------------------------------------------------------------------------------
Init ==
    /\ chain = << >>
    /\ book = << >>
    /\ fin = 0
    /\ seed \in [ Miners -> 0..SeedMax ]
    /\ owed = seed

AtBookingPoint(h) == Booked = h - 1 /\ fin = Max(0, h - 1 - FINALITY_DEPTH)

\* An honest builder on the tip, behind the booking-point gate: its coinbase is the
\* allocation every receiver recomputes. `v`: whether THIS node can read the view at
\* the block's cut when the block arrives. `dh`: the Monero heights since the previous
\* lane block, a chain fact every node reads alike (B-SPEC section 3).
\* MUTATION "nogate": the builder assembles on whatever its ledger shows (issue #1861).
MineCanon(E, ord, dh, v) ==
    /\ Height < MaxChainLen
    /\ Mutation = "nogate" \/ AtBookingPoint(Height + 1)
    /\ chain' = Append(chain, [ E |-> E, ord |-> ord, dh |-> dh, pay |-> Alloc(E, ord, dh).pay,
                                honest |-> TRUE, view |-> v ])
    /\ UNCHANGED << book, fin, owed, seed >>

\* Any other coinbase: a lagged builder or a hostile one. Any payout vector the block's
\* cash covers, on top of the block's window credit E (dh = 1: the verdict only asks
\* whether `pay` is the recompute's, and the honest builder covers every dh).
MineAny(E, pay) ==
    /\ Height < MaxChainLen
    /\ chain' = Append(chain, [ E |-> E, ord |-> FirstOrd, dh |-> 1, pay |-> pay,
                                honest |-> FALSE, view |-> TRUE ])
    /\ UNCHANGED << book, fin, owed, seed >>

\* The view at a held block's cut becomes readable here (replay or relay repair).
ViewArrives(i) ==
    /\ ~chain[i].view
    /\ chain' = [ chain EXCEPT ![i].view = TRUE ]
    /\ UNCHANGED << book, fin, owed, seed >>

\* The verdict, decided at the booking point: the on-chain payouts are the recompute's.
AllocOf(i) == Alloc(chain[i].E, chain[i].ord, chain[i].dh)
Canonical(i) == chain[i].pay = AllocOf(i).pay

\* FOUND: book the next block, in order, at its booking point, once decided.
\* MUTATION "held_debit": an undecidable block is booked debit-only instead of held.
\* MUTATION "foreign_credit": a debit-only block keeps its window credit.
\* MUTATION "authority": no verdict (coinbase authority): a block that is not canonical
\* is booked like a canonical one, with its window credit and whatever it paid.
\* A booking records `ep`, the window's credit at P as the booking point computed it
\* (Zero for a debit-only block): a later state has the block pending, so EO, F, Delta
\* and P differ there, and an invariant must not re-evaluate Alloc for a booked block.
Book ==
    LET i == Booked + 1 IN
    /\ i <= Height
    /\ AtBookingPoint(i)
    /\ chain[i].view \/ Mutation = "held_debit"
    /\ book' = Append(book,
         IF ~chain[i].view
         THEN [ verdict |-> "debit", credit |-> Zero, ep |-> Zero ]
         ELSE IF Canonical(i)
         THEN [ verdict |-> "canon", credit |-> AllocOf(i).credit, ep |-> AllocOf(i).ep ]
         ELSE IF Mutation = "authority"
         THEN [ verdict |-> "canon", credit |-> chain[i].E, ep |-> chain[i].E ]
         ELSE [ verdict |-> "debit", ep |-> Zero,
                credit  |-> IF Mutation = "foreign_credit" THEN chain[i].E ELSE Zero ])
    /\ UNCHANGED << chain, fin, owed, seed >>

\* FINALIZE: the oldest booked block once FINALITY_DEPTH later blocks are booked. A held
\* block therefore stops the cursor at its booking point.
Finalize ==
    LET i == fin + 1 IN
    /\ Booked >= i + FINALITY_DEPTH
    /\ fin' = i
    /\ owed' = [ m \in Miners |-> owed[m] + book[i].credit[m] - chain[i].pay[m] ]
    /\ UNCHANGED << chain, book, seed >>

Next ==
    \/ \E E \in Windows, ord \in Perms, dh \in Steps, v \in BOOLEAN : MineCanon(E, ord, dh, v)
    \/ \E E \in Windows, p \in Coinbases : MineAny(E, p)
    \/ \E i \in 1..Height : ViewArrives(i)
    \/ Book
    \/ Finalize

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------------
\* INVARIANTS

TypeOK ==
    /\ chain \in Seq([ E : Windows, ord : Perms, dh : Steps, pay : Coinbases,
                      honest : BOOLEAN, view : BOOLEAN ])
    /\ book \in Seq([ verdict : {"canon", "debit"}, credit : [ Miners -> Int ],
                     ep : [ Miners -> Int ] ])
    /\ Booked <= Height
    /\ fin \in 0..Booked
    /\ owed \in [ Miners -> Int ]
    /\ seed \in [ Miners -> 0..SeedMax ]

\* The finalized ledger is exactly the genesis balances plus the credit minus the
\* on-chain payouts of the finalized blocks, per key.
RECURSIVE NetFin(_, _)
NetFin(n, m) == IF n = 0 THEN 0 ELSE book[n].credit[m] - chain[n].pay[m] + NetFin(n - 1, m)
Conservation == \A m \in Miners : owed[m] = seed[m] + NetFin(fin, m)

\* A non-canonical block never credits anybody: it is booked debit-only.
NonCanonicalEarnsNothing ==
    \A i \in 1..Booked : book[i].verdict = "debit" => book[i].credit = Zero

\* What "negative" means now. A debit-only block MAY drive the key it paid negative: that
\* key carries the payment as a debt (forward repair), accepted by design (WitNoNegative
\* shows it is reachable). A canonical block never does (CanonicalNeverNegative below).
\* So a key that no booked debit-only block pays has a finalized balance >= 0 and an
\* EffectiveOwed >= 0.
PaidByDebitOnly(m) == \E i \in 1..Booked : book[i].verdict = "debit" /\ chain[i].pay[m] > 0
UnpaidKeyNeverNegative ==
    \A m \in Miners : ~PaidByDebitOnly(m) => (owed[m] >= 0 /\ EO(m) >= 0)

\* The redistribution only moves credit with cash: a canonical block that has a payee
\* output books exactly its window credit in total (credit_delta sums to zero). A block
\* with no payee output can move no cash and books less (only reachable with Cap = 0).
\* R1: the window credit is the one AT P (`ep`, E_b(P)); the drain is the part of E_b the
\* window gives up, never a credit. Under master `ep` is E_b itself.
RedistributionNeutral ==
    \A i \in 1..Booked :
        (book[i].verdict = "canon" /\ Sum(chain[i].pay) > 0) => Sum(book[i].credit) = Sum(book[i].ep)

\* Solvency: no claim without cash. Every coinbase pays all its cash out, to keys or to
\* the residual, so a balance is backed only if some block paid its cash to a key. No
\* booked block credits more in total than it pays to keys, so the outstanding total
\* (finalized balances plus the pending net of booked blocks) never exceeds the genesis
\* float. A debit-only block only lowers it.
RECURSIVE PendNet(_)
PendNet(j) == IF j <= fin THEN 0 ELSE Sum(book[j].credit) - Sum(chain[j].pay) + PendNet(j - 1)
LedgerTotal == Sum(owed) + PendNet(Booked)
LedgerWithinFloat == LedgerTotal <= Sum(seed)
NoClaimWithoutCash == \A i \in 1..Booked : Sum(book[i].credit) <= Sum(chain[i].pay)

\* One function, two callers: an honest builder's block at the booking point is booked
\* canonical on this node, also after it was held.
HonestIsCanonical == \A i \in 1..Booked : chain[i].honest => book[i].verdict = "canon"

\* Undecidable is held: not booked, and the finalize cursor stays at or below its
\* booking point until it is decided.
UndecidableHeld ==
    \A i \in 1..Height : ~chain[i].view =>
        /\ Booked < i
        /\ fin <= Max(0, i - 1 - FINALITY_DEPTH)

\* R1: a canonical block never raises a balance. Per key it books at most what it pays
\* (an admitted payee is paid its E_b(P) and its redistribution share in full, a waiting
\* payee's E_b(P) all comes off), so its pending net is >= 0 per key and its FINALIZE
\* moves every balance down or leaves it. Caught: debt_first_on (DEBT FIRST spends a
\* waiting payee's share on an admitted payee's old balance; the waiting payee keeps the
\* credit as a balance), credit_at_reward (the window is credited at the whole Reward
\* while Delta pays old balances: the short pool's shortfall becomes a balance). Master
\* fails it (wit-master-new-owed).
NoNewOwed ==
    \A i \in 1..Booked : book[i].verdict = "canon" =>
        \A m \in Miners : book[i].credit[m] <= chain[i].pay[m]

\* B6: the window's credit at P is per key at most its credit at the whole Reward, so
\* E_b(P) > 0 only where E_b(R) > 0 (the allocator's fail-closed check never fires).
PayNowWithinWindow ==
    \A i \in 1..Booked : book[i].verdict = "canon" =>
        \A m \in Miners : book[i].ep[m] <= chain[i].E[m]

\* ACTION PROPERTIES

BookStep == Len(book') = Len(book) + 1 /\ book'[Len(book')].verdict = "canon"

\* No advance: a canonical block pays a key at most its positive EffectiveOwed at the
\* booking point plus the credit the block books for it; the credit is never negative and
\* never exceeds the block's window credit in total; the payouts fit the block's cash.
NoAdvance ==
    [][ BookStep =>
          LET i == Len(book') IN
          /\ \A m \in Miners : /\ chain[i].pay[m] <= Pos(EO(m)) + book'[i].credit[m]
                               /\ book'[i].credit[m] >= 0
          /\ Sum(book'[i].credit) <= Sum(chain[i].E)
          /\ Sum(chain[i].pay) <= Reward ]_vars

\* Finalizing a canonical block never makes a balance negative and never deepens a debt.
CanonicalNeverNegative ==
    [][ (fin' = fin + 1 /\ book[fin'].verdict = "canon") =>
          \A m \in Miners : owed'[m] >= Min(owed[m], 0) ]_vars

\* R1: no step raises any key's EffectiveOwed, so the float never grows: its one source
\* is the genesis balances, and every block drains it or leaves it (a canonical FINALIZE
\* changes no EffectiveOwed, the booking took its net; a debit-only block lowers the
\* keys it paid). Caught: debt_first_on (the IOU appears at FINALIZE).
FloatNonIncreasing ==
    [][ /\ \A m \in Miners : EO(m)' <= EO(m)
        /\ Float' <= Float ]_vars

\* R2: what a canonical block pays beyond the credit it books (the old balances it pays
\* down, debt_paid) is at most Delta(dh), and Delta(dh) <= F; both at the booking point.
\* Caught: delta_unbounded.
DrainBound ==
    [][ BookStep =>
          LET i == Len(book') IN
          /\ Sum(chain[i].pay) - Sum(book'[i].credit) <= Delta(chain[i].dh)
          /\ Delta(chain[i].dh) <= Float ]_vars

\* R1/B5: in a contested canonical block the owed pass keeps at most
\* K_o = max(1, (Cap * owed_paid_1) div Reward) slots, owed_paid_1 the FIRST pass's cash:
\* debt's slot share is its cash share. Caught: no_ko.
SlotShare ==
    [][ BookStep =>
          LET a == AllocOf(Len(book')) IN
          a.contested => a.nOwed <= Max(1, (Cap * a.paid1) \div Reward) ]_vars

\* With two or more slots and a window, a canonical block admits a window payee:
\* "nobody admitted" is unreachable, since owed_paid_1 <= Delta < Reward leaves
\* K_o <= Cap - 1. Needs HCap < DrainQ (Delta < Reward, the lane-rules validity
\* condition; mut-hcap-full shows it is needed). Caught: no_ko.
SomeoneAdmitted ==
    [][ BookStep =>
          LET i == Len(book') IN
          (Cap >= 2 /\ Sum(chain[i].E) > 0) => ~AllocOf(i).nobody ]_vars

\* F = 0 => master: with no positive balance the rule's coinbase and booking are
\* master's, payout for payout and credit for credit (Delta = 0, no owed take, P = Reward,
\* no K_o re-run, DEBT FIRST a no-op). Caught: split_at_delta.
MasterWhenNoFloat ==
    [][ BookStep =>
          LET i  == Len(book')
              a  == AllocOf(i)
              ma == MasterAlloc(chain[i].E, chain[i].ord, chain[i].dh)
          IN  Float = 0 => (a.pay = ma.pay /\ a.credit = ma.credit) ]_vars

-------------------------------------------------------------------------------
\* REACHABILITY WITNESSES (each expected VIOLATED; check-settlement-canon.sh)

\* A debit-only block can drive a key negative.
WitNoNegative == \A m \in Miners : owed[m] >= 0
\* The redistribution (credit_delta) is exercised: a canonical block books a credit other
\* than the window's credit at P.
WitNoRedistribution == \A i \in 1..Booked : book[i].verdict = "canon" => book[i].credit = book[i].ep
\* A held block is reachable.
WitNoHeld == \A i \in 1..Height : chain[i].view
\* Master's debt-first step pays a balance (SettlementCanon_master.cfg; an action property).
WitNoDebtFirst ==
    [][ BookStep => Sum(AllocOf(Len(book')).debt) = 0 ]_vars
\* Nobody is admitted and the moved cash goes to the payees the owed pass paid (an action
\* property; with Cap = 1, where K_o = 1 = Cap).
WitNoLeftoverToOwed ==
    [][ BookStep => LET a == AllocOf(Len(book')) IN ~(a.nobody /\ Sum(a.plus) > 0) ]_vars
\* The drain pays an old balance: a canonical block pays beyond the credit it books.
WitNoDrain ==
    [][ BookStep => LET i == Len(book') IN Sum(chain[i].pay) = Sum(book'[i].credit) ]_vars
\* The window is credited at P < R: a canonical block's credit at P differs from E_b.
WitNoSplitAtP == \A i \in 1..Booked : book[i].verdict = "canon" => book[i].ep = chain[i].E
\* The K_o cap cuts an owed pass (SettlementCanon_ko.cfg).
WitNoKoCut == [][ BookStep => ~AllocOf(Len(book')).capped ]_vars
\* The recv fallback with a payee admitted: the admitted payees' E_b(P) sums to 0 (a
\* one-unit E_b floored at P < R) and the moved cash goes to the payees the owed pass paid.
WitNoFloorFallback ==
    [][ BookStep => LET a == AllocOf(Len(book')) IN
                    ~(~a.nobody /\ Sum(a.tk) = 0 /\ Sum(a.plus) > 0) ]_vars

=============================================================================
