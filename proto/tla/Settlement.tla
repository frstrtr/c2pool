------------------------------ MODULE Settlement ------------------------------
\* c2pool V37.0 Phase-1 -- finality-gated owed/overlay settlement state machine.
\* Adversarial-review-hardened spec. Models the round-5 converged transitions:
\*   BlockFound      -> OverlayAdded      (now with a signed, DROPS-composed credit row)
\*   BlockFinalized  -> OwedSettled + OverlayCleared
\*   BlockOrphaned   -> OverlayReverted   (shallow, pre-SETTLED tip swap)
\*   DeepOrphan      -> priced residual   (orphan AFTER SETTLED; SETTLED is terminal)
\* Source of truth: c2pool-v37-work-receipts.md section 7.1, REDTEAM-RESPONSE-v37-round{4,5}.md.
\* ERRATA: revision 2 (owed-sign semantics) -- signed owed, forward repair, NoClawback;
\*   NoNegativeOwed / OverlayNeverExceedsOwed withdrawn. See ERRATA.md in this directory.
\*
\* Scope (Phase-1, Phase-2 OFF): the TWO-LEDGER settlement only. Ledger #1 (in-window
\* decayed weight) is abstracted to an opaque per-block entitlement vector `base[b]` (E_b);
\* its determinism is a SEPARATE invariant set (I1-I4, modeled in Lanes.tla). Here we prove
\* the SETTLEMENT around finality is safe: no double-pay, no rob, no clawback, monotone
\* finalized ledger, and a bounded, never-re-owed residual for a beyond-finality orphan.
\*
\* Sign domain (revision 2): per-key finalized owed is a SIGNED integer. Over-credit is
\* netted forward against the same key's later credit (forward repair), never clawed back.
\* A carried DROPS replace delta may be negative (netting, legal); it may take a key no
\* lower than -(its carrier block's own E_b). There is no receiver guard on a coinbase's
\* payout map (coinbase authority): the model constrains payouts only by what an honest
\* builder can produce (its possibly-lagged EffectiveOwed view, pay-now within its own
\* E_b, the block's reward budget), not by a check every receiver runs.

EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Miners,           \* set of miner identities (payee keys)
    MaxReward,        \* per-key per-block entitlement / payout magnitude bound
    MaxDelta,         \* per-key magnitude bound of a carried DROPS replace delta
    FINALITY_DEPTH,   \* confirmations required to finalize (reuses M2 clock)
    MaxChainLen,      \* model bound on mainchain height
    MaxIds,           \* model bound on minted block ids (state-space finiteness)
    MaxDeepOrphans,   \* model bound on beyond-finality orphan events
    C4Bound,          \* TRUE = the per-block carried-delta floor is enforced (spec)
    DeltaMassRule,    \* TRUE = a carried delta never removes mass from its block
    AllowClawback     \* FALSE in the spec; TRUE only in the negative-control config

ASSUME FinalityOK == FINALITY_DEPTH \in Nat /\ FINALITY_DEPTH >= 1
ASSUME FlagsOK == {C4Bound, DeltaMassRule, AllowClawback} \subseteq BOOLEAN

VARIABLES
    chain,      \* Seq of blocks on the canonical mainchain tip; index = height
    owed,       \* [Miners -> Int] : FINALIZED ledger finalW (signed; never rolls back)
    paid,       \* [Miners -> Nat] : settled on-chain payout to date per key
    book,       \* set of SETTLED block records (kept even if later orphaned)
    settled,    \* set of block ids whose credit/payout has been applied to `owed`
    orphaned,   \* set of SETTLED block ids a beyond-finality reorg later orphaned
    residual,   \* priced residual: payout mass of orphaned SETTLED blocks (MD-2)
    deep,       \* count of beyond-finality orphan events (model bound only)
    nextId      \* monotonic block-id source (determinism: ids stand in for hashes)

\* A pool block carries an id, its per-key entitlement E_b (`base`, the in-window split of
\* the block reward), a carried DROPS replace delta (`delta`, may be negative), and the
\* payout map its coinbase pays. The ledger credit row is base + delta (signed).
\* NOTE: credit MUST be per-key, not a scalar block reward (round-1 finding of this spec).
Zero == [ m \in Miners |-> 0 ]
PoolBlock == [ id : Nat, base : [Miners -> 0..MaxReward],
               delta : [Miners -> -MaxDelta..MaxDelta],
               payout : [Miners -> 0..MaxReward] ]

vars == << chain, owed, paid, book, settled, orphaned, residual, deep, nextId >>

-------------------------------------------------------------------------------
\* Helpers

Height == Len(chain)

\* depth of the block at index i (index 1 = OLDEST/deepest, index Height = NEWEST/tip).
\* depth = Height - i confs; finalized iff buried at least FINALITY_DEPTH deep.
IsFinalized(i) == (Height - i) >= FINALITY_DEPTH

Max0(x) == IF x > 0 THEN x ELSE 0

\* Sum of a per-key vector over all keys.
SumM(v) ==
    LET RECURSIVE S(_)
        S(T) == IF T = {} THEN 0
                ELSE LET k == CHOOSE x \in T : TRUE IN v[k] + S(T \ {k})
    IN  S(Miners)

\* The signed ledger credit row of a block: E_b composed with its carried delta.
Credit(b) == [ m \in Miners |-> b.base[m] + b.delta[m] ]

\* The block's own E_b mass (its reward split); the C-4 floor and the payout budget.
Eb(b) == SumM(b.base)

\* Pending (unsettled) blocks on the canonical chain: the overlay. This matches the
\* ledger's pending rows (FOUND, not yet FINALIZED), not merely "not yet buried".
PendingIx == { i \in 1..Height : chain[i].id \notin settled }

\* Folds over a set of block INDICES (a multiset discipline: equal rows from distinct
\* blocks must each count; a value-set would silently dedup them).
FoldPayout(S, m) ==
    LET RECURSIVE F(_)
        F(T) == IF T = {} THEN 0
                ELSE LET i == CHOOSE k \in T : TRUE
                     IN  chain[i].payout[m] + F(T \ {i})
    IN  F(S)

FoldNet(S, m) ==
    LET RECURSIVE F(_)
        F(T) == IF T = {} THEN 0
                ELSE LET i == CHOOSE k \in T : TRUE
                     IN  Credit(chain[i])[m] - chain[i].payout[m] + F(T \ {i})
    IN  F(S)

\* Folds over a set of block RECORDS (ids are unique, so the set is a multiset).
BookNet(B, m) ==
    LET RECURSIVE F(_)
        F(T) == IF T = {} THEN 0
                ELSE LET b == CHOOSE x \in T : TRUE
                     IN  Credit(b)[m] - b.payout[m] + F(T \ {b})
    IN  F(B)

BookPayout(B, m) ==
    LET RECURSIVE F(_)
        F(T) == IF T = {} THEN 0
                ELSE LET b == CHOOSE x \in T : TRUE IN b.payout[m] + F(T \ {b})
    IN  F(B)

PayoutMass(B) ==
    LET RECURSIVE F(_)
        F(T) == IF T = {} THEN 0
                ELSE LET b == CHOOSE x \in T : TRUE IN SumM(b.payout) + F(T \ {b})
    IN  F(B)

\* EffectiveOwed seen by a coinbase built on the current tip = finalized owed minus the
\* pending overlay. Signed: a negative value is over-credit netted forward.
EffectiveOwed(m) == owed[m] - FoldPayout(PendingIx, m)

\* A builder's node-local view may lag by the newest pending FOUND (it has not yet seen
\* it). Over an ancestry `anc`, the lagged view excludes anc's tip-most member.
LastIx(anc) == IF anc = {} THEN 0 ELSE CHOOSE i \in anc : \A j \in anc : j <= i
ViewEO(anc, m) == owed[m] - FoldPayout(anc \ {LastIx(anc)}, m)

\* Carried DROPS replace deltas the model draws from. Zero = gate off / no delta. A
\* Transfer lowers one key by a and raises another by a (the replace delta moves credit
\* between keys; the key lowered may be driven negative -- netting, C-6). A Shortfall
\* only lowers a key (the block's credit mass drops below its E_b); it is drawn only
\* when DeltaMassRule = FALSE (negative control: see AggregateNonNeg).
Transfers == UNION { { [ m \in Miners |-> IF m = k THEN -a ELSE IF m = j THEN a ELSE 0 ] :
                          j \in Miners \ {k}, a \in 1..MaxDelta } : k \in Miners }
Shortfalls == { [ m \in Miners |-> IF m = k THEN -a ELSE 0 ] :
                  k \in Miners, a \in 1..MaxDelta }
DeltaVecs == {Zero} \cup Transfers \cup (IF DeltaMassRule THEN {} ELSE Shortfalls)

\* A block that is not the pool's (a competing miner's block): no credit, no payout.
Foreign(i) == [ id |-> i, base |-> Zero, delta |-> Zero, payout |-> Zero ]

\* Per-key floor the ledger may reach (C-3 + C-4): one block's E_b mass, plus the
\* over-payment one lagged builder view can add (at most one pending block per key).
MaxBlockEb == Cardinality(Miners) * MaxReward
KeyBound == MaxBlockEb + MaxReward

\* Honest-builder legality of block b built on pending ancestry `anc` (NOT a receiver
\* guard: receivers book whatever map the coinbase carries -- coinbase authority, C-5).
\*  - owed pass: a key is paid at most its (possibly lagged) positive EffectiveOwed view;
\*    a key whose view is <= 0 gets no owed output (FR-004);
\*  - pay-now (Rule L): the only over-owed payment is <= the key's own E_b of THIS block;
\*  - budget: the coinbase pays out of this block's reward (its E_b mass);
\*  - C-4 (c): a carried negative delta may take a key no lower than -(this block's E_b),
\*    judged on the replicated finalized partition plus the canonical pending ancestry.
LegalBlock(anc, b) ==
    /\ \A m \in Miners : b.payout[m] <= Max0(ViewEO(anc, m)) + b.base[m]
    /\ SumM(b.payout) <= Eb(b)
    /\ C4Bound =>
         \A m \in Miners :
            b.delta[m] < 0 =>
               owed[m] + FoldNet(anc, m) + Credit(b)[m] - b.payout[m] >= -Eb(b)

-------------------------------------------------------------------------------
Init ==
    /\ chain = << >>
    /\ owed = Zero
    /\ paid = Zero
    /\ book = {}
    /\ settled = {}
    /\ orphaned = {}
    /\ residual = 0
    /\ deep = 0
    /\ nextId = 0

-------------------------------------------------------------------------------
\* BlockFound -> OverlayAdded. A pool block is appended to the tip. Its credit row is
\* base + delta (a negative DROPS row is netting, C-6). No `owed` mutation here (deferred
\* to finality) -> this IS the overlay-add step. No receiver guard against EffectiveOwed.
BlockFound(base, delta, payout) ==
    /\ Height < MaxChainLen
    /\ LET b == [ id |-> nextId, base |-> base, delta |-> delta, payout |-> payout ]
       IN  /\ LegalBlock(PendingIx, b)
           /\ chain' = chain \o << b >>
    /\ nextId' = nextId + 1
    /\ UNCHANGED << owed, paid, book, settled, orphaned, residual, deep >>

\* BlockFinalized -> OwedSettled + OverlayCleared. When a block crosses FINALITY_DEPTH its
\* row leaves the overlay AND lands in the finalized ledger: += credit[m], -= payout[m].
\* One-shot per block id; applied in chain order (FINALIZE follows burial order).
SettleFinal(i) ==
    /\ IsFinalized(i)
    /\ chain[i].id \notin settled
    /\ \A j \in 1..(i - 1) : chain[j].id \in settled
    /\ owed' = [ m \in Miners |-> owed[m] + Credit(chain[i])[m] - chain[i].payout[m] ]
    /\ paid' = [ m \in Miners |-> paid[m] + chain[i].payout[m] ]
    /\ book' = book \cup { chain[i] }
    /\ settled' = settled \cup { chain[i].id }
    /\ UNCHANGED << chain, orphaned, residual, deep, nextId >>

\* BlockOrphaned -> OverlayReverted. A depth-1 reorg: the unfinalized, unsettled tip is
\* REPLACED by a competing pool block at the SAME height (height never decreases, MD-3).
\* The old tip's pending row is removed whole; the new tip is built on the ancestry
\* without it. Modeling this as a swap, not a truncation, keeps finalized depths buried.
BlockOrphaned(base, delta, payout) ==
    /\ Height > 0
    /\ ~IsFinalized(Height)
    /\ chain[Height].id \notin settled
    /\ LET b == [ id |-> nextId, base |-> base, delta |-> delta, payout |-> payout ]
       IN  /\ LegalBlock(PendingIx \ {Height}, b)
           /\ chain' = [ chain EXCEPT ![Height] = b ]
    /\ nextId' = nextId + 1
    /\ UNCHANGED << owed, paid, book, settled, orphaned, residual, deep >>

\* DeepOrphan -> priced residual (MD-2 ruling (a)). A competing branch of EQUAL height
\* (MD-3) replaces the suffix i..Height, reaching a SETTLED block at i: the finality
\* assumption failed with its priced probability. SETTLED is terminal: `owed`, `paid` and
\* `book` are untouched; the orphaned SETTLED payout mass is surfaced as residual and is
\* never re-owed. Unsettled blocks in the suffix are pre-SETTLED orphans: their pending
\* rows simply leave the chain. The replacement blocks are a competing miner's.
DeepOrphan(i) ==
    /\ deep < MaxDeepOrphans
    /\ i \in 1..Height
    /\ chain[i].id \in settled
    /\ LET gone == { chain[j].id : j \in { k \in i..Height : chain[k].id \in settled } }
           lost == { r \in book : r.id \in gone }
       IN  /\ residual' = residual + PayoutMass(lost)
           /\ orphaned' = orphaned \cup gone
    /\ chain' = [ j \in 1..Height |->
                    IF j < i THEN chain[j] ELSE Foreign(nextId + (j - i)) ]
    /\ nextId' = nextId + (Height - i + 1)
    /\ deep' = deep + 1
    /\ UNCHANGED << owed, paid, book, settled >>

\* NEGATIVE CONTROL ONLY (AllowClawback = FALSE in the spec config): reclaim part of a
\* settled payout from a negative key. This is exactly what forward repair forbids.
ClawbackMut(m) ==
    /\ AllowClawback
    /\ owed[m] < 0
    /\ paid[m] > 0
    /\ paid' = [ paid EXCEPT ![m] = @ - 1 ]
    /\ owed' = [ owed EXCEPT ![m] = @ + 1 ]
    /\ UNCHANGED << chain, book, settled, orphaned, residual, deep, nextId >>

Blocks == [ Miners -> 0..MaxReward ]

Next ==
    \/ \E c \in Blocks, d \in DeltaVecs, p \in Blocks : BlockFound(c, d, p)
    \/ \E i \in 1..Height : SettleFinal(i)
    \/ \E c \in Blocks, d \in DeltaVecs, p \in Blocks : BlockOrphaned(c, d, p)
    \/ \E i \in 1..Height : DeepOrphan(i)
    \/ \E m \in Miners : ClawbackMut(m)

Spec == Init /\ [][Next]_vars

\* STATE CONSTRAINT (TLC finiteness): bound the explored id-space to MaxIds. This bounds
\* the model, NOT the protocol; MaxIds must exceed MaxChainLen so reorg churn is exercised.
StateConstraint == nextId <= MaxIds

-------------------------------------------------------------------------------
\* SAFETY INVARIANTS (revision 2: owed-sign semantics)

TypeOK ==
    /\ owed \in [ Miners -> Int ]
    /\ paid \in [ Miners -> Nat ]
    /\ book \subseteq PoolBlock
    /\ settled \subseteq (0..nextId)
    /\ orphaned \subseteq settled
    /\ residual \in Nat
    /\ Height <= MaxChainLen

\* INV-KEYFLOOR (C-3 + C-4): a per-key balance may be negative (forward repair) but never
\* below -KeyBound. Replaces the withdrawn NoNegativeOwed (owed[m] >= 0).
KeyFloor == \A m \in Miners : owed[m] >= -KeyBound

\* INV-AGGREGATE (C-3): the pool as a whole never owes less than zero.
AggregateNonNeg == SumM(owed) >= 0

\* INV-FINALITY: a SETTLED block still on the chain stays finalized. A shallow reorg never
\* un-buries it; a deep orphan removes it from the chain (it is then residual, not owed).
SettledImpliesFinalized == \A i \in 1..Height : (chain[i].id \in settled) => IsFinalized(i)

\* INV-CONSERV (revised): each key's owed is EXACTLY the net of ITS OWN settled credit rows
\* (signed, including negative DROPS rows) and settled payouts, and paid-to-date is exactly
\* its settled payouts. No cross-key coupling, no leftover-reward fan-out, no clamp, and a
\* deep orphan changes neither (the residual is never re-owed).
Conservation ==
    \A m \in Miners : /\ owed[m] = BookNet(book, m)
                      /\ paid[m] = BookPayout(book, m)

\* INV-NODOUBLEPAY: each block settles at most once; the book is keyed by id.
SettleOnce ==
    /\ { r.id : r \in book } = settled
    /\ Cardinality(book) = Cardinality(settled)
    /\ \A i, j \in 1..Height : i # j => chain[i].id # chain[j].id

\* INV-RESIDUAL (MD-2 (a), C-7): the priced residual is exactly the payout mass of the
\* orphaned SETTLED blocks, is bounded by what was actually settled, and every orphaned
\* SETTLED block stays in the book (never re-owed, never reverted).
ResidualBound ==
    /\ residual = PayoutMass({ r \in book : r.id \in orphaned })
    /\ residual <= PayoutMass(book)
    /\ \A i \in 1..Height : chain[i].id \notin orphaned

\* ACTION PROPERTIES
\* MONOTONE: a settled block never becomes unsettled (finality is terminal).
MonoOnFinal ==
    [][ /\ settled \subseteq settled'
        /\ \A i \in 1..Height : (chain[i].id \in settled) => (chain[i].id \in settled') ]_vars

\* NO CLAWBACK (FR-002): what a key has been paid on-chain never decreases.
NoClawback == [][ \A m \in Miners : paid'[m] >= paid[m] ]_vars

THEOREM Safety == Spec => [](TypeOK /\ KeyFloor /\ AggregateNonNeg /\ Conservation
                            /\ ResidualBound)
=============================================================================
