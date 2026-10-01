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
\*                credit (E_b plus the redistribution delta) and its payouts.
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
\* credit_delta; payout-threshold.md section 3). `Alloc(E, ord)` at the booking point:
\*   1. owed pass: keys with EffectiveOwed > 0 in the block's order, each paid
\*      min(EffectiveOwed, cash left), at most OwedCap keys, one slot each;
\*   2. admission: payees with E_b > 0 in the same order; a payee with an owed output
\*      needs no slot, any other takes a free slot or waits;
\*   3. short pool: the admitted payees share the cash left with the same fraction of
\*      their E_b (exact-sum, largest remainder, each <= its E_b);
\*   4. debt first: the cash the split leaves (a waiting payee's share, or cash nobody is
\*      credited) pays the admitted payees' positive balances the owed pass left
\*      (owed_left), in order;
\*   5. redistribution: what is still left, up to the waiting payees' E_b, comes off the
\*      waiting payees' credit (credit_delta) and goes, with the same amount of credit,
\*      to the admitted payees pro rata to their E_b. When nobody is admitted (the owed
\*      pass took every slot) it goes to the payees the owed pass paid in this block,
\*      pro rata to what it paid them, merged into their outputs (operator ruling
\*      2026-10-02). Cash and credit move together, so the delta sums to zero. Only a
\*      block with no payee output at all (no slot for anyone, Cap = 0 here) moves no
\*      cash: the waiting payees' credit still comes off and the cash stays in the
\*      residual, because crediting work whose cash went to the donation output would be
\*      a claim nothing backs;
\*   6. the rest stays in the residual (the donation output).
\* No advance: no step pays a key more than its positive balance plus its credit.
\*
\* Abstractions. `ord` stands for oldest first with the salted tie
\* sha256d("V37T" || prev_id || key): it is an input of the block, the same for the
\* builder and every receiver, and the model checks every order. The spend floor c is 0
\* (no dust class, no A8 dust pass). The owed budget is the block's whole cash (the V37N
\* base is not modelled). Reorgs below FINALIZE are Settlement.tla's subject and are not
\* repeated here. The share rule (V37R: a share's coinbase must be canonical) is the same
\* recompute applied to a share; here a block's window credit E is taken as already
\* built from canonical shares.

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
    Mutation         \* "none", or one negative control (check-settlement-canon.sh)

ASSUME /\ Reward \in Nat \ {0}
       /\ SeedMax \in Nat
       /\ Cap \in Nat
       /\ OwedCap \in Nat
       /\ FINALITY_DEPTH \in Nat \ {0}
       /\ MaxChainLen \in Nat
       /\ Mutation \in {"none", "foreign_credit", "authority", "advance", "debt_unbounded",
                       "redistribute_to_nobody", "keep_credit_unbacked",
                       "degenerate_keep_credit", "held_debit", "nogate"}

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

\* 1. The owed pass.
RECURSIVE OwedWalk(_, _, _, _, _)
OwedWalk(ord, j, left, n, take) ==
    IF j > Len(ord) THEN take
    ELSE LET k == ord[j]
             t == IF EO(k) > 0 /\ n < OwedCap /\ n < Cap THEN Min(EO(k), left) ELSE 0
         IN  OwedWalk(ord, j + 1, left - t, IF t > 0 THEN n + 1 ELSE n, [ take EXCEPT ![k] = t ])

\* 2. Admission.
RECURSIVE AdmitWalk(_, _, _, _, _, _)
AdmitWalk(ord, j, free, E, take, adm) ==
    IF j > Len(ord) THEN adm
    ELSE LET k == ord[j]
         IN  IF E[k] = 0 THEN AdmitWalk(ord, j + 1, free, E, take, adm)
             ELSE IF take[k] > 0 THEN AdmitWalk(ord, j + 1, free, E, take, [ adm EXCEPT ![k] = TRUE ])
             ELSE IF free > 0 THEN AdmitWalk(ord, j + 1, free - 1, E, take, [ adm EXCEPT ![k] = TRUE ])
             ELSE AdmitWalk(ord, j + 1, free, E, take, adm)

\* 4. Debt first.
RECURSIVE DebtWalk(_, _, _, _, _)
DebtWalk(ord, j, spare, need, add) ==
    IF j > Len(ord) \/ spare = 0 THEN add
    ELSE LET k == ord[j]
             d == Min(spare, need[k])
         IN  DebtWalk(ord, j + 1, spare - d, need, [ add EXCEPT ![k] = d ])

Alloc(E, ord) ==
    LET take   == OwedWalk(ord, 1, Reward, 0, Zero)
        nOwed  == Cardinality({ k \in Miners : take[k] > 0 })
        pool   == Reward - Sum(take)
        adm    == AdmitWalk(ord, 1, Cap - nOwed, E, take, [ k \in Miners |-> FALSE ])
        tk     == [ k \in Miners |-> IF adm[k] THEN E[k] ELSE 0 ]
        split  == PaySplit(pool, tk, ord)
        \* MUTATION "debt_unbounded": the debt pass ignores what the owed pass left.
        need   == [ k \in Miners |-> IF ~adm[k] THEN 0
                                    ELSE IF Mutation = "debt_unbounded" THEN Reward
                                    ELSE Pos(EO(k) - take[k]) ]
        debt   == DebtWalk(ord, 1, pool - Sum(split), need, Zero)
        spare  == pool - Sum(split) - Sum(debt)
        wait   == [ k \in Miners |-> IF adm[k] THEN 0 ELSE E[k] ]
        nobody == Sum(tk) = 0
        \* Who takes the moved cash: the admitted payees by E_b, else the payees the owed
        \* pass paid by what it paid them, else nobody (no payee output).
        \* MUTATION "redistribute_to_nobody": the rule before the ruling: with nobody
        \* admitted the cash goes to nobody, the waiting credit still comes off.
        recv   == IF ~nobody THEN tk
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
    IN  [ debt   |-> debt,
          nobody |-> nobody,
          plus   |-> plus,
          pay    |-> [ k \in Miners |-> take[k] + split[k] + debt[k] + plus[k] ],
          \* MUTATION "advance": the redistributed cash is paid but not booked as credit
          \* (the cash of a payee without a slot paid as an advance).
          credit |-> IF Mutation = "advance" THEN E
                     ELSE [ k \in Miners |-> E[k] + plus[k] - minus[k] ] ]

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
\* the block's cut when the block arrives.
\* MUTATION "nogate": the builder assembles on whatever its ledger shows (issue #1861).
MineCanon(E, ord, v) ==
    /\ Height < MaxChainLen
    /\ Mutation = "nogate" \/ AtBookingPoint(Height + 1)
    /\ chain' = Append(chain, [ E |-> E, ord |-> ord, pay |-> Alloc(E, ord).pay,
                                honest |-> TRUE, view |-> v ])
    /\ UNCHANGED << book, fin, owed, seed >>

\* Any other coinbase: a lagged builder or a hostile one. Any payout vector the block's
\* cash covers, on top of the block's window credit E.
MineAny(E, pay) ==
    /\ Height < MaxChainLen
    /\ chain' = Append(chain, [ E |-> E, ord |-> FirstOrd, pay |-> pay,
                                honest |-> FALSE, view |-> TRUE ])
    /\ UNCHANGED << book, fin, owed, seed >>

\* The view at a held block's cut becomes readable here (replay or relay repair).
ViewArrives(i) ==
    /\ ~chain[i].view
    /\ chain' = [ chain EXCEPT ![i].view = TRUE ]
    /\ UNCHANGED << book, fin, owed, seed >>

\* The verdict, decided at the booking point: the on-chain payouts are the recompute's.
Canonical(i) == chain[i].pay = Alloc(chain[i].E, chain[i].ord).pay

\* FOUND: book the next block, in order, at its booking point, once decided.
\* MUTATION "held_debit": an undecidable block is booked debit-only instead of held.
\* MUTATION "foreign_credit": a debit-only block keeps its window credit.
\* MUTATION "authority": no verdict (coinbase authority): a block that is not canonical
\* is booked like a canonical one, with its window credit and whatever it paid.
Book ==
    LET i == Booked + 1 IN
    /\ i <= Height
    /\ AtBookingPoint(i)
    /\ chain[i].view \/ Mutation = "held_debit"
    /\ book' = Append(book,
         IF ~chain[i].view
         THEN [ verdict |-> "debit", credit |-> Zero ]
         ELSE IF Canonical(i)
         THEN [ verdict |-> "canon", credit |-> Alloc(chain[i].E, chain[i].ord).credit ]
         ELSE IF Mutation = "authority"
         THEN [ verdict |-> "canon", credit |-> chain[i].E ]
         ELSE [ verdict |-> "debit",
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
    \/ \E E \in Windows, ord \in Perms, v \in BOOLEAN : MineCanon(E, ord, v)
    \/ \E E \in Windows, p \in Coinbases : MineAny(E, p)
    \/ \E i \in 1..Height : ViewArrives(i)
    \/ Book
    \/ Finalize

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------------
\* INVARIANTS

TypeOK ==
    /\ chain \in Seq([ E : Windows, ord : Perms, pay : Coinbases, honest : BOOLEAN, view : BOOLEAN ])
    /\ book \in Seq([ verdict : {"canon", "debit"}, credit : [ Miners -> Int ] ])
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
RedistributionNeutral ==
    \A i \in 1..Booked :
        (book[i].verdict = "canon" /\ Sum(chain[i].pay) > 0) => Sum(book[i].credit) = Sum(chain[i].E)

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

-------------------------------------------------------------------------------
\* REACHABILITY WITNESSES (each expected VIOLATED; check-settlement-canon.sh)

\* A debit-only block can drive a key negative.
WitNoNegative == \A m \in Miners : owed[m] >= 0
\* The redistribution (credit_delta) is exercised.
WitNoRedistribution == \A i \in 1..Booked : book[i].verdict = "canon" => book[i].credit = chain[i].E
\* A held block is reachable.
WitNoHeld == \A i \in 1..Height : chain[i].view
\* The debt-first step pays a balance (SettlementCanon_debt.cfg; an action property).
WitNoDebtFirst ==
    [][ BookStep => LET i == Len(book') IN Sum(Alloc(chain[i].E, chain[i].ord).debt) = 0 ]_vars
\* Nobody is admitted and the moved cash goes to the payees the owed pass paid (an action
\* property).
WitNoLeftoverToOwed ==
    [][ BookStep => LET i == Len(book')
                        a == Alloc(chain[i].E, chain[i].ord)
                    IN  ~(a.nobody /\ Sum(a.plus) > 0) ]_vars

=============================================================================
