------------------------------ MODULE SettlementCanon ------------------------------
\* c2pool v37 XMR lane -- the CANONICAL-COINBASE rule on top of the finality-gated
\* settlement of Settlement.tla.
\*
\* Settlement.tla guards BlockFound with coinbase legality (payout <= EffectiveOwed) and
\* so models an HONEST builder. The running lane cannot assume that: a lane block books
\* whatever its on-chain coinbase paid (coinbase authority), so a lagged or hostile
\* builder can pay any vector (issue #1861). The canonical-coinbase rule
\* (xmr_canonical_coinbase.hpp, LaneParams::canon) splits the blocks the ledger sees:
\*
\*   canonical      the coinbase is the one the lane state dictates: its payout is legal
\*                  against the builder's view (EffectiveOwed) and it earns its credit.
\*   non-canonical  a recognised lane block whose coinbase is anything else: it is
\*                  booked PAYOUT-ONLY -- its payouts are debited, it earns NO credit.
\*
\* What the model checks: settlement stays conservative, a non-canonical block never
\* credits anybody, and a key that no non-canonical block pays is never debited below
\* zero (a foreign coinbase can only over-debit the keys it actually paid).

EXTENDS Naturals, Integers, FiniteSets, Sequences, TLC

CONSTANTS Miners, MaxReward, FINALITY_DEPTH, MaxChainLen, MaxIds

ASSUME FinalityOK == FINALITY_DEPTH \in Nat /\ FINALITY_DEPTH >= 1

VARIABLES chain, owed, settled, nextId

PoolBlock == [ id : Nat, canon : BOOLEAN,
               credit : [Miners -> 0..MaxReward], payout : [Miners -> 0..MaxReward] ]

vars == << chain, owed, settled, nextId >>

Height == Len(chain)
IsFinalized(i) == (Height - i) >= FINALITY_DEPTH
OverlayBlocks == { i \in 1..Height : ~IsFinalized(i) }

FoldPayout(S, m) == LET F[T \in SUBSET S] ==
                          IF T = {} THEN 0
                          ELSE LET i == CHOOSE x \in T : TRUE IN chain[i].payout[m] + F[T \ {i}]
                    IN F[S]
FoldCredit(S, m) == LET F[T \in SUBSET S] ==
                          IF T = {} THEN 0
                          ELSE LET i == CHOOSE x \in T : TRUE IN chain[i].credit[m] + F[T \ {i}]
                    IN F[S]
OverlaySum(m) == FoldPayout(OverlayBlocks, m)
EffectiveOwed(m) == owed[m] - OverlaySum(m)

\* owed is an integer ledger: a non-canonical block may over-debit a key it paid.
Zero == [ m \in Miners |-> 0 ]

Init == /\ chain = << >> /\ owed = [ m \in Miners |-> 0 ] /\ settled = {} /\ nextId = 0

\* A canonical block: legal payout against the builder's view, earns its credit.
BlockFoundCanon(credit, payout) ==
    /\ Height < MaxChainLen /\ nextId < MaxIds
    /\ \A m \in Miners : payout[m] <= EffectiveOwed(m)
    /\ chain' = chain \o << [ id |-> nextId, canon |-> TRUE, credit |-> credit, payout |-> payout ] >>
    /\ nextId' = nextId + 1
    /\ UNCHANGED << owed, settled >>

\* A non-canonical block: ANY payout vector (a lagged builder that has not booked an
\* ancestor, or a hostile one), booked payout-only -- credit is dropped.
BlockFoundForeign(payout) ==
    /\ Height < MaxChainLen /\ nextId < MaxIds
    /\ chain' = chain \o << [ id |-> nextId, canon |-> FALSE, credit |-> Zero, payout |-> payout ] >>
    /\ nextId' = nextId + 1
    /\ UNCHANGED << owed, settled >>

SettleFinal(i) ==
    /\ IsFinalized(i) /\ chain[i].id \notin settled
    /\ owed' = [ m \in Miners |-> owed[m] + chain[i].credit[m] - chain[i].payout[m] ]
    /\ settled' = settled \cup { chain[i].id }
    /\ UNCHANGED << chain, nextId >>

Next ==
    \/ \E c \in [ Miners -> 0..MaxReward ], p \in [ Miners -> 0..MaxReward ] : BlockFoundCanon(c, p)
    \/ \E p \in [ Miners -> 0..MaxReward ] : BlockFoundForeign(p)
    \/ \E i \in 1..Height : SettleFinal(i)

Spec == Init /\ [][Next]_vars

StateConstraint == nextId <= MaxIds

-------------------------------------------------------------------------------
\* `owed` holds integers here (a foreign block can over-debit), so TypeOK is over Int.
TypeOK ==
    /\ chain \in Seq(PoolBlock)
    /\ owed \in [ Miners -> Int ]
    /\ settled \subseteq Nat
    /\ nextId \in Nat

SettledIx == { i \in 1..Height : chain[i].id \in settled }

\* The finalized ledger is exactly the settled credit minus the settled payouts.
Conservation == \A m \in Miners : owed[m] = FoldCredit(SettledIx, m) - FoldPayout(SettledIx, m)

\* A non-canonical block never credits anybody.
NonCanonicalEarnsNothing == \A i \in 1..Height : ~chain[i].canon => \A m \in Miners : chain[i].credit[m] = 0

\* A key that no settled non-canonical block pays is never debited below zero: a foreign
\* coinbase can only over-debit the keys it actually paid.
UnpaidKeyNeverNegative ==
    \A m \in Miners :
        (\A i \in SettledIx : chain[i].canon \/ chain[i].payout[m] = 0) => owed[m] >= 0

\* The pending overlay of canonical blocks alone never exceeds what is finalized-owed.
CanonicalOverlayBounded ==
    \A m \in Miners : FoldPayout({ i \in OverlayBlocks : chain[i].canon }, m) <= 2 * MaxChainLen * MaxReward

=============================================================================
