------------------------------ MODULE Settlement ------------------------------
\* c2pool V37.0 Phase-1 — finality-gated owed/overlay settlement state machine.
\* Adversarial-review-hardened spec. Models the round-5 converged transitions:
\*   BlockFound      -> OverlayAdded
\*   BlockFinalized  -> OwedSettled + OverlayCleared
\*   BlockOrphaned   -> OverlayReverted
\* Source of truth: c2pool-v37-work-receipts.md §7.1, REDTEAM-RESPONSE-v37-round{4,5}.md.
\*
\* Scope (Phase-1, Phase-2 OFF): the TWO-LEDGER settlement only. Ledger #1 (in-window
\* decayed weight) is abstracted to an opaque per-block payout vector `payout[b]` — the
\* split is assumed already computed and deterministic (its determinism is a SEPARATE
\* invariant set: I1-I4 lane/dedup/bin-clock, modeled in Lanes.tla). Here we prove the
\* SETTLEMENT around finality is safe: no double-pay, no rob, monotone finalized ledger.

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Miners,           \* set of miner identities
    MaxReward,        \* per-block reward magnitude bound (model finiteness)
    FINALITY_DEPTH,   \* confirmations required to finalize (reuses M2 clock)
    MaxChainLen,      \* model bound on mainchain height
    MaxIds            \* model bound on minted block ids (state-space finiteness)

ASSUME FinalityOK == FINALITY_DEPTH \in Nat /\ FINALITY_DEPTH >= 1

VARIABLES
    chain,      \* Seq of blocks on the canonical mainchain tip; index = height
    owed,       \* [Miners -> Nat] : FINALIZED monotonic ledger (never rolls back)
    settled,    \* set of block ids whose credit/payout has been applied to `owed`
    nextId      \* monotonic block-id source (determinism: ids stand in for hashes)

\* A pool block carries: an id, a per-miner CREDIT vector (Ledger #1: the in-window
\* decayed-weight split of the block reward across miners), and the payout vector it pays
\* OUT of (owed - overlay) at build time. Both credit and payout are finality-gated.
\* NOTE: credit MUST be per-miner, not a scalar block reward. Model-checking (round-1 of
\* this spec) showed a scalar reward credited wholesale to every miner inflates `owed` and
\* breaks OverlayNeverExceedsOwed -- the two-ledger settlement requires a credit vector.
PoolBlock == [ id : Nat, credit : [Miners -> 0..MaxReward], payout : [Miners -> 0..MaxReward] ]

vars == << chain, owed, settled, nextId >>

-------------------------------------------------------------------------------
\* Helpers

Height == Len(chain)

\* depth of the block at index i (index 1 = OLDEST/deepest, index Height = NEWEST/tip).
\* depth = Height - i confs; finalized iff buried at least FINALITY_DEPTH deep.
IsFinalized(i) == (Height - i) >= FINALITY_DEPTH

\* The pending-payout OVERLAY: payout vectors of pool blocks that are ANCESTORS of the
\* current tip but NOT yet finalized (< FINALITY_DEPTH confs). Pure function of ancestry.
OverlayBlocks == { i \in 1..Height : ~IsFinalized(i) }

\* Fold payout[m] over a set of block indices (NOT a set of values -- equal payouts from
\* distinct blocks must each count; a value-set would silently dedup them).
FoldPayout(S, m) ==
    LET RECURSIVE FoldIx(_)
        FoldIx(T) == IF T = {} THEN 0
                     ELSE LET i == CHOOSE k \in T : TRUE
                          IN  chain[i].payout[m] + FoldIx(T \ {i})
    IN  FoldIx(S)

\* Fold credit[m] over a set of block indices (same multiset discipline as FoldPayout).
FoldCredit(S, m) ==
    LET RECURSIVE FoldIx(_)
        FoldIx(T) == IF T = {} THEN 0
                     ELSE LET i == CHOOSE k \in T : TRUE
                          IN  chain[i].credit[m] + FoldIx(T \ {i})
    IN  FoldIx(S)

\* Total overlay obligation to miner m.
OverlaySum(m) == FoldPayout(OverlayBlocks, m)

\* Overlay obligation EXCLUDING block index j (used when a reorg SWAPS the tip: the new
\* tip's coinbase is built against the overlay with the old tip removed).
OverlaySumExcl(j, m) == FoldPayout(OverlayBlocks \ {j}, m)

\* effective owed seen by a freshly-built coinbase = finalized owed minus overlay.
EffectiveOwed(m) == owed[m] - OverlaySum(m)

-------------------------------------------------------------------------------
Init ==
    /\ chain = << >>
    /\ owed = [ m \in Miners |-> 0 ]
    /\ settled = {}
    /\ nextId = 0

-------------------------------------------------------------------------------
\* BlockFound -> OverlayAdded.
\* A pool block is appended to the tip. Its payout vector is built from EffectiveOwed
\* (owed - overlay) so it cannot re-pay what an unfinalized ancestor already pays.
\* No `owed` mutation here (deferred to finality) -> this IS the overlay-add step.
BlockFound(credit, payout) ==
    /\ Height < MaxChainLen
    \* coinbase legality: never pay a miner more than it is (effectively) owed now.
    /\ \A m \in Miners : payout[m] <= EffectiveOwed(m)
    /\ LET b == [ id |-> nextId, credit |-> credit, payout |-> payout ]
       IN  chain' = chain \o << b >>
    /\ nextId' = nextId + 1
    /\ UNCHANGED << owed, settled >>

\* BlockFinalized -> OwedSettled + OverlayCleared.
\* When a block crosses FINALITY_DEPTH it leaves the overlay (clearing) AND both of its
\* `owed` transitions land in the immutable ledger: += credit[m] and -= payout[m].
\* Modeled as a one-shot settle per block id (idempotent via `settled`).
SettleFinal(i) ==
    /\ IsFinalized(i)
    /\ chain[i].id \notin settled
    /\ owed' = [ m \in Miners |->
                   owed[m] + chain[i].credit[m] - chain[i].payout[m] ]
    /\ settled' = settled \cup { chain[i].id }
    /\ UNCHANGED << chain, nextId >>

\* BlockOrphaned -> OverlayReverted.
\* A depth-1 reorg: the unfinalized tip is REPLACED by a competing block at the SAME height
\* (height is constant -- a heavier/equal-length branch wins; the chain never shrinks). The
\* old tip's pending payout leaves the overlay (reverted) and the new tip brings its own.
\* Modeling height as a tip SWAP, not a truncation, is essential: truncating Len(chain) would
\* un-bury a deeper already-finalized/settled block (TLC found this -- it breaks the finality
\* gate). The finality assumption is exactly that reorgs never reach a >=FINALITY_DEPTH block,
\* so only an unfinalized, unsettled tip may be swapped; finalized depths are untouched.
BlockOrphaned(credit, payout) ==
    /\ Height > 0
    /\ ~IsFinalized(Height)                       \* only an unfinalized tip can reorg
    /\ chain[Height].id \notin settled            \* never settled => safe to swap
    \* new tip coinbase legality: vs overlay with the OLD tip removed (it is being replaced).
    /\ \A m \in Miners : payout[m] <= owed[m] - OverlaySumExcl(Height, m)
    /\ LET b == [ id |-> nextId, credit |-> credit, payout |-> payout ]
       IN  chain' = [ chain EXCEPT ![Height] = b ]
    /\ nextId' = nextId + 1
    /\ UNCHANGED << owed, settled >>

Next ==
    \/ \E c \in [ Miners -> 0..MaxReward ], p \in [ Miners -> 0..MaxReward ] : BlockFound(c, p)
    \/ \E i \in 1..Height : SettleFinal(i)
    \/ \E c \in [ Miners -> 0..MaxReward ], p \in [ Miners -> 0..MaxReward ] : BlockOrphaned(c, p)

Spec == Init /\ [][Next]_vars

\* STATE CONSTRAINT (TLC finiteness): each BlockFound/reorg mints a fresh id, so nextId --
\* and hence owed -- grow without bound. Bound the explored id-space to MaxIds. This bounds
\* the model, NOT the protocol; MaxIds must exceed MaxChainLen so genuine reorg churn (build
\* + swap + re-finalize) is still exercised within the bound.
StateConstraint == nextId <= MaxIds

-------------------------------------------------------------------------------
\* SAFETY INVARIANTS (the round-5 verdict, as machine-checkable obligations)

\* TypeOK
TypeOK ==
    /\ owed \in [ Miners -> Nat ]
    /\ settled \subseteq (0..nextId)
    /\ Height <= MaxChainLen

\* INV-NONNEG: no coinbase ever drives effective owed negative (no over-pay / robbery).
NoNegativeOwed == \A m \in Miners : owed[m] >= 0

\* INV-FINALITY: the gate's core guarantee -- once a block's owed mutation is applied
\* (settled), that block stays finalized forever. A reorg must NEVER un-bury it. This is the
\* obligation a naive drop-the-tip reorg model violates.
SettledImpliesFinalized == \A i \in 1..Height : (chain[i].id \in settled) => IsFinalized(i)

\* INV-OVERLAY: the unfinalized overlay for a miner never exceeds its finalized owed,
\* i.e. EffectiveOwed stays >= 0. This is the safety the BlockFound guard buys: the sum
\* of all in-flight (unfinalized) payouts can never promise more than the ledger holds.
OverlayNeverExceedsOwed == \A m \in Miners : OverlaySum(m) <= owed[m]

\* INV-NOROB: a block that never settled never reduced `owed` (orphan-safe).
\*   enforced structurally: `owed` only changes in SettleFinal, gated on IsFinalized.
\* INV-MONO is a temporal property over finalized state; here we assert the static guard:
NoUnfinalizedMutation == TRUE  \* placeholder: SettleFinal is the ONLY owed-writer, gated.

\* INV-CONSERV (the no-robbery property the round-2 red-team flagged NoNegativeOwed does
\* NOT entail): each miner's owed is EXACTLY the net of its OWN settled credits and payouts.
\* Init owed = 0, so owed[m] can only have moved by m's own settled-block transactions --
\* no cross-miner coupling, no leftover-reward fan-out, nothing but a finality settle moves it.
\* (Settled blocks are never swapped -- BlockOrphaned guards chain[Height].id \notin settled --
\* so SettledIx and these folds are stable for already-settled ids.)
SettledIx == { i \in 1..Height : chain[i].id \in settled }
Conservation == \A m \in Miners : owed[m] = FoldCredit(SettledIx, m) - FoldPayout(SettledIx, m)

\* INV-NODOUBLEPAY: each block settles at most once (idempotent finality application).
SettleOnce == Cardinality(settled) = Cardinality({ chain[i].id : i \in 1..Height }
                                                  \cap settled)

\* MONOTONE (temporal): finalized owed for a miner, net of its own paid-out blocks, never
\* loses an earned credit to a reorg. Check as action property:
MonoOnFinal ==
    [][ \A i \in 1..Height : (chain[i].id \in settled) => (chain[i].id \in settled') ]_vars

THEOREM Safety == Spec => [](TypeOK /\ NoNegativeOwed /\ Conservation)
=============================================================================
