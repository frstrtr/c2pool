---------------------------- MODULE Lanes ----------------------------
\* c2pool V37.0 Phase-1 — Ledger #1: the in-window decayed-weight roundabout
\* (the "MRR roundabout buffer"). Companion to Settlement.tla, which abstracted
\* this split to an OPAQUE deterministic per-miner vector. Lanes.tla discharges
\* that assumption: it formalizes the lane accumulator and proves the four lane
\* invariants I1-I4 the Settlement spec relied on.
\*
\* ============================ DETERMINISM BUG ============================
\* M1 finding (2026-06-26, Lanes Part-B co-design + integrator directive):
\* the lane maintains an INCREMENTAL scaled-frame accumulator. At an epoch/bin
\* boundary TWO transitions become enabled:
\*   EpochRenormalize  scaledW := floor(scaledW * NUM/DEN)     (the x-lambda)
\*   EvictTail         scaledW := scaledW - <expiring contrib> (window exit)
\* Under TRUNCATING fixed-point these DO NOT COMMUTE:
\*   floor((A-B)*lambda) /= floor(A*lambda) - floor(B*lambda)   in general.
\* Counterexample A=2, B=1, lambda=2/3:
\*   evict-then-renorm = floor((2-1)*2/3) = floor(2/3)             = 0
\*   renorm-then-evict = floor(2*2/3) - floor(1*2/3) = 1 - 0        = 1.
\* If both actions are independently enabled, two honest nodes can fire them in
\* different orders and derive DIFFERENT scaledW from the SAME committed chain
\* state -> different owed/credit vector -> different coinbase -> CONSENSUS SPLIT.
\* This is invisible to Settlement.tla, which trusts credit as a deterministic fn.
\*
\* THE FIX (modeled here): pin a CANONICAL ORDER. EpochRenormalize fires BEFORE
\* EvictTail at every boundary (CONSTANT CanonicalOrder = TRUE guards EvictTail
\* to require the renorm already discharged). Under the canonical order the
\* incremental scaledW is a deterministic function of committed state, captured
\* exactly by the ghost `canon`; I3_Determinism asserts scaledW = canon at every
\* settled state. With CanonicalOrder = FALSE (free interleaving) TLC exhibits
\* the counterexample as an I3_Determinism violation (see Lanes_free.cfg).
\*
\* PROTOTYPE PARITY: src/sharechain/v37/v37_lane.hpp::push() already applies the
\* canonical order -- epoch_rebuild() at step (1), evict_oldest_bucket() at step
\* (5) -- and its rebuild recomputes each bucket w_scaled = w_raw*decay[depth]
\* exact-per-share, so the aggregate never performs floor((A-B)*lambda). The C++
\* matches the pinned spec order; no latent ordering bug in the prototype.
\* ========================================================================
\*
\* Determinism is the whole point: every honest node must derive the SAME
\* accumulator from the SAME committed chain state, or the opaque vector that
\* Settlement.tla trusts is not actually a function of committed state.

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    MaxWeight,     \* shares carry integer PoW weight 1..MaxWeight
    W,             \* window length, in bins (shares older than W evict at the tail)
    NUM, DEN,      \* per-bin decay lambda = NUM/DEN, truncating (0 < NUM < DEN)
    MaxClock,      \* bound the bin clock (finiteness)
    MaxShares,     \* bound total pushes (finiteness)
    CanonicalOrder \* TRUE: pin EpochRenormalize-before-EvictTail; FALSE: free order

ASSUME DecayFrac == NUM > 0 /\ NUM < DEN /\ DEN > 0
ASSUME Bounds     == W > 0 /\ MaxClock > 0 /\ MaxShares > 0 /\ MaxWeight > 0
ASSUME OrderFlag  == CanonicalOrder \in BOOLEAN

\* ---------------------------------------------------------------------------
\* Deterministic truncating decay:  floor( w * (NUM/DEN)^age ).
\* Integer, total, and a pure function of (w, age) -> reproducible on every node.
RECURSIVE Decay(_, _)
Decay(w, age) == IF age = 0 THEN w ELSE (Decay(w, age - 1) * NUM) \div DEN

\* ---------------------------------------------------------------------------
VARIABLES
    clock,    \* current bin index = height(hashPrevBlock); monotone non-decreasing
    shares,   \* Seq of [pos |-> Nat, w |-> 1..MaxWeight, bin |-> Nat]  (append-only)
    nextPos,  \* strictly-increasing position counter (circular-buffer logical pos)
    scaledW,  \* the implementation's incrementally-maintained scaled-frame sum
    frame,    \* the bin index scaledW is currently normalized to (= baseBin)
    canon,    \* GHOST: the canonical-order deterministic value scaledW must equal
    pendR,    \* boundary obligation: an EpochRenormalize is owed
    pendE,    \* boundary obligation: one or more EvictTail subtractions are owed
    expQ      \* Seq of expiring share records [w, bin] still to evict this boundary

vars == << clock, shares, nextPos, scaledW, frame, canon, pendR, pendE, expQ >>

Settled == pendR = FALSE /\ pendE = FALSE

\* Age of share i at the current clock (>= 0 since a share commits to clock-or-past).
Age(i) == clock - shares[i].bin

\* The set of share indices currently inside the window W.
Live == { i \in 1..Len(shares) : Age(i) >= 0 /\ Age(i) <= W }

\* Per-index decayed contribution at the current clock (per-share floor).
Contrib == [ i \in 1..Len(shares) |-> Decay(shares[i].w, Age(i)) ]

\* Sum of Contrib over a set of indices (ground-truth windowed sum helper).
RECURSIVE SumOver(_)
SumOver(S) == IF S = {} THEN 0
              ELSE LET i == CHOOSE x \in S : TRUE
                   IN Contrib[i] + SumOver(S \ {i})

\* GROUND TRUTH: the O(window) per-share recompute (sum-of-floors).
CanonicalCredit == SumOver(Live)

\* Sum of decayed expiring-record contributions evaluated at frame `fr`.
RECURSIVE SumExp(_, _)
SumExp(seq, fr) == IF seq = << >> THEN 0
                   ELSE Decay(Head(seq).w, fr - Head(seq).bin) + SumExp(Tail(seq), fr)

\* ---------------------------------------------------------------------------
Init ==
    /\ clock   = 0
    /\ shares  = << >>
    /\ nextPos = 0
    /\ scaledW = 0
    /\ frame   = 0
    /\ canon   = 0
    /\ pendR   = FALSE
    /\ pendE   = FALSE
    /\ expQ    = << >>

\* PUSH a fresh share committing to the current bin (age 0 -> full weight w).
\* Only between boundaries (Settled) so frame = clock and the add is in-frame.
Push ==
    /\ Settled
    /\ frame = clock
    /\ Len(shares) < MaxShares
    /\ \E w \in 1..MaxWeight :
        /\ shares'  = Append(shares, [ pos |-> nextPos, w |-> w, bin |-> clock ])
        /\ nextPos' = nextPos + 1
        /\ scaledW' = scaledW + w
        /\ canon'   = canon + w
    /\ UNCHANGED << clock, frame, pendR, pendE, expQ >>

\* TICK opens a boundary: advance the bin clock, raise the renorm obligation,
\* and snapshot the shares leaving the window (new age = W+1, i.e. bin = clock-W).
\* The ghost `canon` is advanced to the CANONICAL (renorm-then-evict-in-new-frame)
\* value the discharged scaledW must equal.
Expiring == IF clock - W >= 0
            THEN SelectSeq(shares, LAMBDA s : s.bin = clock - W)
            ELSE << >>
Tick ==
    /\ Settled
    /\ clock < MaxClock
    /\ clock' = clock + 1
    /\ pendR' = TRUE
    /\ expQ'  = SelectSeq(shares, LAMBDA s : s.bin = (clock + 1) - W)
    /\ pendE' = (Len(expQ') > 0)
    /\ canon' = ((canon * NUM) \div DEN) - SumExp(expQ', clock + 1)
    /\ UNCHANGED << shares, nextPos, scaledW, frame >>

\* EpochRenormalize: discharge the renorm obligation -- multiply the whole scaled
\* aggregate by lambda (truncating) and advance the normalization frame by one bin.
EpochRenormalize ==
    /\ pendR
    /\ scaledW' = (scaledW * NUM) \div DEN
    /\ frame'   = frame + 1
    /\ pendR'   = FALSE
    /\ UNCHANGED << clock, shares, nextPos, canon, pendE, expQ >>

\* EvictTail: discharge one expiring share -- subtract its decayed contribution
\* EVALUATED IN THE CURRENT FRAME. Under CanonicalOrder it is guarded to require
\* the renorm already discharged (pendR = FALSE), so every eviction sees the
\* post-renorm frame and scaledW lands on `canon`. Under free order an eviction
\* may fire pre-renorm (current frame still old) -> floor((A-B)*lambda) path.
EvictTail ==
    /\ pendE
    /\ (CanonicalOrder => pendR = FALSE)
    /\ LET e == Head(expQ)
       IN  scaledW' = scaledW - Decay(e.w, frame - e.bin)
    /\ expQ'  = Tail(expQ)
    /\ pendE' = (Len(expQ) > 1)
    /\ UNCHANGED << clock, shares, nextPos, frame, canon, pendR >>

\* Terminal stutter: once the bounded model saturates (buffer full, clock at
\* MaxClock, boundary settled) no action is enabled. The self-loop keeps the
\* behaviour total so safety checks run clean without the -deadlock flag.
Done ==
    /\ Settled
    /\ Len(shares) = MaxShares
    /\ clock = MaxClock
    /\ UNCHANGED vars

Next == Push \/ Tick \/ EpochRenormalize \/ EvictTail \/ Done

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

\* ---------------------------------------------------------------------------
\* TYPE / STRUCTURE
TypeOK ==
    /\ clock   \in 0..MaxClock
    /\ nextPos \in 0..MaxShares
    /\ scaledW \in Int
    /\ canon   \in Int
    /\ frame   \in 0..MaxClock
    /\ pendR   \in BOOLEAN
    /\ pendE   \in BOOLEAN
    /\ shares  \in Seq([ pos : 0..MaxShares, w : 1..MaxWeight, bin : 0..MaxClock ])

\* ---- I1  dedup / uniqueness -------------------------------------------------
I1_Dedup ==
    \A i, j \in 1..Len(shares) : (i # j) => shares[i].pos # shares[j].pos

\* ---- I2  monotonicity (append-only positional buffer) -----------------------
I2_Mono ==
    /\ \A i \in 1..Len(shares) : shares[i].pos = i - 1
    /\ nextPos = Len(shares)

\* ---- I3  decay / expiry — the faithfulness prize ---------------------------
\* I3_Determinism is THE consensus invariant: at every settled state the
\* incrementally-maintained scaledW equals the canonical-order deterministic
\* value `canon`. Holds under CanonicalOrder = TRUE; VIOLATED under free order
\* (the EvictTail/EpochRenormalize non-commutativity counterexample).
I3_Determinism == Settled => scaledW = canon

\* The settled incremental aggregate never drops below the per-share recompute
\* (floor-of-sum >= sum-of-floors), bounding the truncation relationship.
I3_CanonGE == Settled => scaledW >= CanonicalCredit

\* Expired shares contribute nothing: nothing older than W is in the live sum.
I3_NoStale == \A i \in 1..Len(shares) : (Age(i) > W) => (i \notin Live)

\* ---- I4  bin-clock convergence ---------------------------------------------
\* No share commits to a future bin -> the bin index is a deterministic function
\* of committed chain state -> two honest nodes derive identical ages.
I4_BinClock == \A i \in 1..Len(shares) : shares[i].bin <= clock

\* ---- frame invariant: scaledW is normalized to clock when settled -----------
I_FrameSettled == Settled => frame = clock

\* ---------------------------------------------------------------------------
\* State-space constraint for exhaustive TLC.
StateConstraint == clock <= MaxClock /\ Len(shares) <= MaxShares
=============================================================================
