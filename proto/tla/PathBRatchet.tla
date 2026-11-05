---------------------------- MODULE PathBRatchet ----------------------------
(***************************************************************************)
(* TLA+ model of the Path B rules ratchet (the c2pool v37 rules-upgrade     *)
(* mechanism).                                                              *)
(*                                                                          *)
(* What is modelled.                                                        *)
(*  - One honest chain of positions 0 .. pos - 1.  Each position holds one  *)
(*    carrier (credited work 1) and at most CMAX further placements (work 1, *)
(*    or 0 for a legally dead receipt), each with a ballot in 0..EPOCH_MAX.  *)
(*  - The committed ratchet state S (epoch_cur, rules_cur, all, y1, y2, J)  *)
(*    and rs_step.  rs_root is S itself (an injective commitment).          *)
(*  - Nodes on different releases, i.e. different compiled tables T         *)
(*    (see Tab): a release lacking epoch 1 (R0), a release whose attempt of *)
(*    1 can fail (R1, or R1b which also compiles epoch 2 with a late start), *)
(*    a release that re-proposes 1 after R1's attempt failed (R2, with a    *)
(*    different or the same digest), and a joiner of any of them.           *)
(*  - Every node-local quantity is a function of (S_{y-1}, y, T): base,     *)
(*    open, locked, E_impl (prefix maximum), lvl_need, H_hold, the derived  *)
(*    attempt states (incl. WAITING), act and the honest ballot.  Sem =     *)
(*    "r5" selects an alternate event-driven form for comparison runs.      *)
(*  - The carrier verdict: a node with y < H_hold checks rules_epoch, the   *)
(*    rules it would run and the fold (rs_root of S_{y-1}); a mismatch is a *)
(*    strike of an honest carrier, i.e. a fork.  A node with y >= H_hold    *)
(*    defers.                                                               *)
(*  - The adversary: any ballot on carriers it mines or on extra            *)
(*    placements, at most AdvMax work units per grid window, and it may     *)
(*    withhold.  Dead receipts with any ballot when Ghost is on.            *)
(*  - Reorgs: a suffix of at most RD positions is replaced (RD <= JR < L);  *)
(*    every node rewinds S from its journal of the last JR snapshots.       *)
(*  - Lockstep: every node that builds verifies each new position when it   *)
(*    is appended; a holding node stays at H_hold - 1 and defers.           *)
(*  - The joiner adopts S_{p0-1} from a live peer at any p0 >= 1 and then   *)
(*    behaves as a follower (its first fold check is against the adopted S).*)
(*  - R2 is released only once R1's attempt has failed and the failed       *)
(*    boundary is below the reorg horizon; before that the R2 node replays  *)
(*    the chain dormant.  Layout "P" (premature) drops that discipline.     *)
(*                                                                          *)
(*  Constants Ctl / Sem select negative controls and an alternate semantics *)
(*  used by the model-check configs; the shipped rule is Ctl = "none",      *)
(*  Sem = "r6".                                                             *)
(***************************************************************************)
EXTENDS Naturals, Integers, FiniteSets, Sequences, TLC

CONSTANTS
  L, GRACE, TIMEOUT, EPOCH_MAX,  \* ratchet constants (model values 4, 6, 9, 3)
  MaxPos,       \* positions 0 .. MaxPos - 1 may be built
  JR,           \* journal: snapshots kept per node for rewinds
  RD,           \* deepest reorg (0 = none); RD <= JR < L
  CMAX,         \* extra placements per position (0 or 1)
  AdvMax,       \* adversary work units per grid window
  Layout,       \* release mix: "A" "S" "B" "BS" "T" "U" "N" "P" "M" "MS" "MT"
  Joiners,      \* releases a joiner may run ({} = no joiner)
  Sem,          \* "r6" (shipped rules) or "r5" (alternate rules, for comparison)
  Ctl,          \* "none" or the name of a negative control / probe
  LockedIncl,   \* TRUE: locked while y <= H_act; FALSE: locked while y < H_act
  Ghost         \* TRUE: keep the chain content as a ghost (scenarios, RsRootIsFunctionOfChain)

NW  == TIMEOUT \div L                  \* N_W windows per attempt
WR  == (GRACE - 1) \div L + 1          \* W_R kept windows
INF == 100000
CeilL(a) == ((a + L - 1) \div L) * L

ASSUME /\ L >= 2 /\ GRACE >= 1 /\ NW >= 1 /\ WR <= 4
       /\ RD <= JR /\ JR < L /\ CMAX \in {0, 1} /\ AdvMax >= 0
       /\ Sem \in {"r6", "r5"} /\ LockedIncl \in BOOLEAN /\ Ghost \in BOOLEAN

Max(a, b) == IF a >= b THEN a ELSE b
MinS(X)   == CHOOSE v \in X : \A w \in X : v <= w
Max0(X)   == IF X = {} THEN 0 ELSE CHOOSE v \in X : \A w \in X : w <= v

---------------------------------------------------------------------------
(* Releases and compiled tables.                                           *)
Dsc(e, s, r) == [ep |-> e, s |-> s, to |-> s + NW * L, rd |-> r]

R1To == 8                               \* FAILED boundary of R1's attempt (start 0)
SameDig == Layout \in {"S", "BS", "MS", "MT"}  \* the re-proposal carries the failed attempt's own digest
R2Tab == CASE Layout = "N" -> {Dsc(1, 0, "r1"), Dsc(2, 16, "r2")} \* layout N: no re-proposal of a failed epoch number
           [] SameDig -> {Dsc(1, 8, "r1")}                         \* re-proposal, same digest as R1's
           [] OTHER -> {Dsc(1, 8, "r2")}                            \* re-proposal, new digest
\* R3: a later release with R2's attempt of 1 and an attempt of 2 (a second activation on top of the re-proposal).
\* R3's attempt of 2 starts at R1b's timeout of 2 (R1bTo2); under layout MT at the first grid position at or
\* after R1bTo2 + GRACE.
R1bTo2 == 28                             \* timeout of R1b's attempt of 2 (start 20)
R3Tab == {Dsc(1, 8, IF SameDig THEN "r1" ELSE "r2"),
          Dsc(2, IF Layout = "MT" THEN CeilL(R1bTo2 + GRACE) ELSE R1bTo2, "q3")}
Tab(r) == CASE r = "R0"  -> {}                                    \* lacks epoch 1
            [] r = "R1"  -> {Dsc(1, 0, "r1")}
            [] r = "R1b" -> {Dsc(1, 0, "r1"), Dsc(2, 20, "q2")}   \* two-epoch table, start(2) late
            [] r = "R1u" -> {Dsc(1, 8, "r1")}                     \* layout U
            [] r = "R2"  -> R2Tab
            [] r = "R3"  -> R3Tab
            [] OTHER     -> {}

FolNodes == CASE Layout \in {"T", "U"} -> {"n0", "n1"}
              [] Layout \in {"M", "MS", "MT"} -> {"n0", "n1", "n2", "n3", "n4"}
              [] OTHER -> {"n0", "n1", "n2"}
JN == "j"
AN == FolNodes \cup (IF Joiners = {} THEN {} ELSE {JN})
RelOf(n) == CASE n = "n0" -> "R0"
              [] n = "n1" -> (CASE Layout \in {"B", "BS"} -> "R1b" [] Layout = "U" -> "R1u" [] OTHER -> "R1")
              [] n = "n2" -> "R2"
              [] n = "n3" -> "R1b"
              [] n = "n4" -> "R3"
              [] OTHER -> "none"
Later(r) == r \in {"R2", "R3"}            \* released only after R1's attempt FAILED
FolOf(r) == IF \E n \in FolNodes : RelOf(n) = r THEN CHOOSE n \in FolNodes : RelOf(n) = r ELSE "none"
Digests == {"G", "r1", "r2", "q2", "q3", "fx", "NULL"}

\* start-up validity: epoch numbers ascending from 1, starts on the grid, spaced by timeout + GRACE
ValidTab(T) == /\ \A d \in T : d.s % L = 0 /\ d.to = d.s + NW * L /\ d.ep >= 1 /\ d.ep <= EPOCH_MAX
               /\ \A d1, d2 \in T : d1.ep = d2.ep => d1 = d2
               /\ \A d \in T : d.ep > 1 => \E c \in T : c.ep = d.ep - 1 /\ d.s >= c.to + GRACE
\* checked for the releases the configuration runs (followers and joiners)
UsedRels == {RelOf(n) : n \in FolNodes} \cup Joiners
ASSUME \A r \in UsedRels : ValidTab(Tab(r))

\* re-proposal spacing across releases (layout MT): an attempt of e starts at or after timeout + GRACE of every
\* earlier attempt of e in the releases the configuration runs.  An earlier attempt that ends at R1To is gated
\* by Release instead (Release fires only with no lock-in in windows 0 and 1).
SpacedAcross(rs) == \A r1, r2 \in rs : \A a \in Tab(r1), b \in Tab(r2) :
                      (a.ep = b.ep /\ a.s < b.s /\ a.to # R1To) => b.s >= a.to + GRACE
ASSUME Layout = "MT" => SpacedAcross(UsedRels)

---------------------------------------------------------------------------
(* The committed ratchet state S and rs_step.                              *)
SInit == [ec |-> 0, rc |-> "G", all |-> 0, y1 |-> 0, y2 |-> 0, J |-> [i \in 1..WR |-> 0]]

Step1(s, act, rd) ==
  IF ~act THEN s
  ELSE [s EXCEPT !.ec = s.ec + 1,
                 !.rc = IF Ctl = "NoRulesCur" THEN s.rc ELSE rd,
                 !.y1 = s.y2, !.y2 = 0,
                 !.J  = [i \in 1..WR |-> Max(s.J[i] - 1, 0)]]
AddP(s, w, b) == [s EXCEPT !.all = s.all + w,
                           !.y1  = s.y1 + (IF b >= s.ec + 1 THEN w ELSE 0),
                           !.y2  = s.y2 + (IF b >= s.ec + 2 THEN w ELSE 0)]
Step2(s, P) == LET s1 == AddP(s, P[1].w, P[1].b) IN IF Len(P) = 2 THEN AddP(s1, P[2].w, P[2].b) ELSE s1
Lvl(s) == IF s.all > 0 /\ 4 * s.y2 >= 3 * s.all THEN 2
          ELSE IF s.all > 0 /\ 4 * s.y1 >= 3 * s.all THEN 1 ELSE 0
Step3(s, y) == IF (y + 1) % L = 0
               THEN [s EXCEPT !.J = [i \in 1..WR |-> IF i < WR THEN s.J[i + 1] ELSE Lvl(s)],
                              !.all = 0, !.y1 = 0, !.y2 = 0]
               ELSE s

\* in S_{y-1}, J[i] is the level of grid window KK(y, i)
KK(y, i) == y \div L - WR + (i - 1)
HactW(k) == (k + 1) * L - 1 + GRACE
InR(d, k) == d.s <= k * L /\ (k + 1) * L <= d.to

---------------------------------------------------------------------------
VARIABLES
  pos,   \* positions 0 .. pos - 1 exist on the honest chain
  S,     \* S[n]: the node's committed state after position h[n] - 1
  h,     \* h[n]: the next position node n judges or builds (y)
  div,   \* "no" | "strike" (struck an honest chain carrier: fork) | "sah" (struck at y >= H_hold)
  jnl,   \* jnl[n]: the last JR snapshots [s, d, x] taken before each verified position
  D,     \* Sem "r5" (and control R5Joiner): stored per-attempt states [st, hl]
  advW,  \* adversary work placed in the current grid window
  advJ,  \* journal of advW
  rel2,  \* R2 is released (R1's attempt FAILED below the reorg horizon)
  jr,    \* the joiner's release ("none" before it joins)
  jp0,   \* the joiner's span start p0
  acts,  \* ghost: activations performed [ep, rd, at]
  aux,   \* control scratch per node
  lrn,   \* HELLO controls: descriptors learned from peers
  gc,    \* ghost chain (Ghost): per position [P, act, rd, by]
  gab    \* ghost: the abandoned branch of the last reorg across a window end

vars == <<pos, S, h, div, jnl, D, advW, advJ, rel2, jr, jp0, acts, aux, lrn, gc, gab>>

UsesR5(n) == Sem = "r5" \/ (Ctl = "R5Joiner" /\ n = JN)
RelN(n) == IF n = JN THEN jr ELSE RelOf(n)
TN(n) == Tab(RelN(n))

---------------------------------------------------------------------------
(* Node-local quantities (Sem r6): functions of (s, y, T).                  *)
RT(T, e) == IF e = 0 THEN "G"
            ELSE IF \E d \in T : d.ep = e THEN (CHOOSE d \in T : d.ep = e).rd ELSE "NULL"
HasD(T, e) == \E d \in T : d.ep = e
DOf(T, e)  == CHOOSE d \in T : d.ep = e

\* base: the rules in force are the node's own.  Control NoRulesCur: S has no rules_cur,
\* so a node can only compare epoch numbers.
Base(s, T) == IF Ctl = "NoRulesCur" THEN s.ec = 0 \/ HasD(T, s.ec) ELSE RT(T, s.ec) = s.rc
\* the predecessor of the open epoch is in force with the node's digest;
\* control PredNumber checks its number only
PredOK(s, T) == IF Ctl = "PredNumber" THEN TRUE ELSE Base(s, T)

\* XC(y): x = y, the position judged or built.
\* Probe TipConv: x = y - 1, the tip, with the strict "x < H_act".
XC(y) == IF Ctl = "TipConv" THEN y - 1 ELSE y
OpenR6(s, y, T) == /\ PredOK(s, T) /\ HasD(T, s.ec + 1)
                   /\ DOf(T, s.ec + 1).s <= XC(y) /\ XC(y) < DOf(T, s.ec + 1).to
LockWin(s, y, T, n) ==
  IF ~HasD(T, s.ec + 1) THEN {}
  ELSE {KK(y, i) : i \in {i \in 1..WR : s.J[i] >= 1 /\ InR(DOf(T, s.ec + 1), KK(y, i))}}
       \cup (IF Ctl = "PartialWindow" /\ aux[n] >= 0 /\ InR(DOf(T, s.ec + 1), aux[n]) THEN {aux[n]} ELSE {})
LockedR6(s, y, T, n) ==
  /\ PredOK(s, T) /\ HasD(T, s.ec + 1)
  /\ LockWin(s, y, T, n) # {}
  /\ IF LockedIncl /\ Ctl # "TipConv" THEN y <= HactW(MinS(LockWin(s, y, T, n)))
     ELSE XC(y) < HactW(MinS(LockWin(s, y, T, n)))
EImplR6(s, y, T, n) == IF ~Base(s, T) THEN s.ec - 1
                       ELSE IF OpenR6(s, y, T) \/ LockedR6(s, y, T, n) THEN s.ec + 1 ELSE s.ec

\* derived attempt states
StateR6(s, y, T, d, n) ==
  LET bs == Base(s, T) IN
  IF s.ec >= d.ep /\ bs THEN "ACT"
  ELSE IF d.ep = s.ec + 1 /\ LockedR6(s, y, T, n) THEN "LOCK"
  ELSE IF d.ep = s.ec + 1 /\ OpenR6(s, y, T) THEN "STA"
  ELSE IF d.ep = s.ec + 1 /\ ~bs /\ d.s <= y /\ y < d.to THEN "WAIT"
  ELSE IF y < d.s THEN "DEF"
  ELSE "FAIL"

---------------------------------------------------------------------------
(* Alternate rules (Sem "r5", control R5Joiner): stored event-driven states. *)
D5Init(T) == [d \in T |-> [st |-> "DEF", hl |-> -1]]
\* alternate transitions after rs_step at y (sp = S_{y-1}, sn = S_y)
TransR5(dn, sp, sn, y) ==
  [d \in DOMAIN dn |->
     LET r == dn[d] IN
     CASE r.st = "DEF" /\ y = d.s ->
            IF sp.ec = d.ep - 1 THEN [st |-> "STA", hl |-> -1] ELSE [st |-> "FAIL", hl |-> -1]
       [] r.st = "STA" /\ (y + 1) % L = 0 /\ d.s <= y + 1 - L /\ y < d.to /\ sn.J[WR] >= 1 ->
            [st |-> "LOCK", hl |-> y]
       [] r.st = "STA" /\ y >= d.to -> [st |-> "FAIL", hl |-> -1]
       [] r.st = "LOCK" /\ y = r.hl + GRACE -> [st |-> "ACT", hl |-> r.hl]
       [] OTHER -> r]
\* the alternate joiner derivation (Sem r5), at p = p0 - 1
Der5(T, s, p) ==
  [d \in T |->
     IF s.ec >= d.ep /\ (d.ep < s.ec \/ s.rc = d.rd \/ Ctl = "NoRulesCur") THEN [st |-> "ACT", hl |-> -1]
     ELSE LET lw == {KK(p + 1, i) : i \in {i \in 1..WR : d.ep - s.ec >= 1 /\ s.J[i] >= d.ep - s.ec
                                                          /\ InR(d, KK(p + 1, i))}}
          IN IF lw # {} THEN [st |-> "LOCK", hl |-> (MinS(lw) + 1) * L - 1]
             ELSE IF d.s <= p /\ p < d.to /\ s.ec = d.ep - 1 THEN [st |-> "STA", hl |-> -1]
             ELSE IF p >= d.to /\ s.ec < d.ep THEN [st |-> "FAIL", hl |-> -1]
             ELSE IF p < d.s THEN [st |-> "DEF", hl |-> -1]
             ELSE [st |-> "FAIL", hl |-> -1]]     \* a case the alternate table did not cover

---------------------------------------------------------------------------
(* Node decisions under the configured semantics.                         *)
BaseN(n) == IF UsesR5(n) THEN (Ctl = "NoRulesCur" \/ RT(TN(n), S[n].ec) = S[n].rc) ELSE Base(S[n], TN(n))

EImplN(n) ==
  IF UsesR5(n) THEN Max0({d.ep : d \in {d \in DOMAIN D[n] : D[n][d].st # "FAIL"}})
  ELSE IF Ctl = "R5EImpl"      \* control R5EImpl: E_impl = highest compiled epoch not FAILED
       THEN Max0({d.ep : d \in {d \in TN(n) : StateR6(S[n], h[n], TN(n), d, n) # "FAIL"}})
  ELSE EImplR6(S[n], h[n], TN(n), n)

\* adopted descriptors for the HELLO controls
Adopted(n, e) == LET cand == {d \in lrn[n] : d.ep = e} IN
                 {d \in TN(n) : d.ep = e} \cup (IF Ctl = "HelloNeither" /\ Cardinality(cand) > 1 THEN {} ELSE cand)
HelloOK(n, i, need) == \/ Ctl \notin {"HelloDesc", "HelloNeither"} \/ need # 1
                       \/ \E d \in Adopted(n, S[n].ec + 1) : InR(d, KK(h[n], i))

HHoldN(n) ==
  LET s == S[n]  y == h[n]  e == EImplN(n)  need == e - s.ec + 1 IN
  IF ~BaseN(n) \/ e < s.ec THEN y
  ELSE IF need \notin {1, 2} THEN INF                 \* alternate form: larger values not tracked
  ELSE LET ks == {i \in 1..WR : s.J[i] >= need /\ HelloOK(n, i, need)} IN
       IF ks = {} THEN INF ELSE MinS({HactW(KK(y, i)) : i \in ks})

Builds(n) == IF Ctl = "PastHact" THEN h[n] <= HHoldN(n) ELSE h[n] < HHoldN(n)
Held(n)   == ~Builds(n) \/ (Ctl = "FrameHold" /\ aux[n] = 1)

ActNow(n) ==
  IF UsesR5(n) THEN \E d \in DOMAIN D[n] : D[n][d].st = "LOCK" /\ D[n][d].hl + GRACE = h[n]
  ELSE LockedR6(S[n], h[n], TN(n), n) /\ HactW(MinS(LockWin(S[n], h[n], TN(n), n))) = h[n]
ActRd(n) ==
  IF ~ActNow(n) THEN "NULL"
  ELSE IF UsesR5(n) THEN (CHOOSE d \in DOMAIN D[n] : D[n][d].st = "LOCK" /\ D[n][d].hl + GRACE = h[n]).rd
  ELSE DOf(TN(n), S[n].ec + 1).rd

\* honest ballot writer
StaAtR5(n, d) == LET r == D[n][d] IN
                 IF r.st = "DEF" THEN h[n] = d.s /\ S[n].ec = d.ep - 1 ELSE r.st = "STA" /\ h[n] < d.to
OpenBal(n) ==
  LET s == S[n]  y == h[n]  T == TN(n) IN
  IF Ctl = "TailYes"     \* control TailYes: yes ballots until the window boundary at or after S + TIMEOUT
  THEN Base(s, T) /\ HasD(T, s.ec + 1) /\ DOf(T, s.ec + 1).s <= y /\ y < DOf(T, s.ec + 1).s + CeilL(TIMEOUT)
  ELSE OpenR6(s, y, T)
Ballot(n) ==
  IF UsesR5(n)
  THEN IF \E d \in DOMAIN D[n] : StaAtR5(n, d) THEN (CHOOSE d \in DOMAIN D[n] : StaAtR5(n, d)).ep ELSE S[n].ec
  ELSE IF OpenBal(n) THEN S[n].ec + 1 ELSE S[n].ec

LabelSt(n, d) == IF UsesR5(n) THEN D[n][d].st ELSE StateR6(S[n], h[n], TN(n), d, n)
LockHl(n, d)  == IF UsesR5(n) THEN D[n][d].hl ELSE HactW(MinS(LockWin(S[n], h[n], TN(n), n))) - GRACE
Labels(n) == [d \in TN(n) |-> IF LabelSt(n, d) = "LOCK" THEN <<"LOCK", LockHl(n, d)>> ELSE <<LabelSt(n, d), -1>>]

\* pending activations of node m: [ep, rd, at]
PendAct(m) ==
  IF UsesR5(m)
  THEN {[ep |-> d.ep, rd |-> d.rd, at |-> D[m][d].hl + GRACE] : d \in {d \in DOMAIN D[m] : D[m][d].st = "LOCK"}}
  ELSE IF LockedR6(S[m], h[m], TN(m), m)
       THEN {[ep |-> S[m].ec + 1, rd |-> DOf(TN(m), S[m].ec + 1).rd,
              at |-> HactW(MinS(LockWin(S[m], h[m], TN(m), m)))]}
       ELSE {}

Dec(n)  == [ei |-> EImplN(n), hh |-> HHoldN(n), b |-> Ballot(n), st |-> Labels(n)]
DecB(n) == [ei |-> EImplN(n), hh |-> HHoldN(n), b |-> Ballot(n)]

---------------------------------------------------------------------------
Tracked(n) == n \in AN /\ div[n] = "no" /\ (n = JN => jr # "none")
Active(n)  == Tracked(n) /\ (Later(RelN(n)) => rel2)
Live(n)    == Active(n) /\ h[n] = pos /\ ~Held(n)
LiveSet    == {n \in AN : Live(n)}
ActiveSet  == {n \in AN : Active(n)}

Push(q, e) == IF JR = 0 THEN << >> ELSE IF Len(q) < JR THEN Append(q, e) ELSE Append(Tail(q), e)

Init ==
  /\ pos = 0
  /\ S = [n \in AN |-> SInit]
  /\ h = [n \in AN |-> 0]
  /\ div = [n \in AN |-> "no"]
  /\ jnl = [n \in AN |-> << >>]
  /\ D = [n \in AN |-> IF UsesR5(n) /\ n # JN THEN D5Init(Tab(RelOf(n))) ELSE D5Init({})]
  /\ advW = 0 /\ advJ = << >>
  /\ rel2 = (Layout = "P")
  /\ jr = "none" /\ jp0 = -1
  /\ acts = {}
  /\ aux = [n \in AN |-> -1]
  /\ lrn = [n \in AN |-> IF Ctl = "HelloNeither" THEN Tab("R1") \ Tab(RelOf(n)) ELSE {}]  \* honest descriptor already learned
  /\ gc = << >>
  /\ gab = [at |-> -1, s |-> SInit]

---------------------------------------------------------------------------
(* Building one position.                                                  *)
Lags(v) == IF Ctl = "FoldAllCarried" /\ Len(jnl[v]) >= 1 THEN {0, 1} ELSE {0}
NoneX == [k |-> "none", w |-> 0, b |-> 0, lag |-> 0, a |-> 0]
PlcOpts(v) ==
  IF CMAX = 0 THEN {NoneX}
  ELSE {NoneX}
       \cup {[k |-> "hon", w |-> 1, b |-> Ballot(m), lag |-> g, a |-> 0] : m \in LiveSet, g \in Lags(v)}
       \cup {[k |-> "adv", w |-> 1, b |-> b, lag |-> g, a |-> 1] : b \in 0..EPOCH_MAX, g \in Lags(v)}
       \cup (IF Ghost THEN {[k |-> "dead", w |-> 0, b |-> b, lag |-> 0, a |-> 0] : b \in 0..EPOCH_MAX} ELSE {})
CarOpts(v) == {[b |-> Ballot(v), a |-> 0]} \cup {[b |-> b, a |-> 1] : b \in 0..EPOCH_MAX}

NewAux(n, a, s2) ==
  CASE Ctl = "PartialWindow" ->
         IF a THEN -1
         ELSE IF /\ aux[n] = -1 /\ (pos + 1) % L # 0 /\ s2.all > 0 /\ 4 * s2.y1 >= 3 * s2.all
                 /\ OpenR6(S[n], pos, TN(n)) /\ InR(DOf(TN(n), S[n].ec + 1), pos \div L)
              THEN pos \div L ELSE aux[n]
    [] Ctl = "PendingTally" -> -1
    [] OTHER -> aux[n]

\* the outcome for node n of the carrier car with placements P at y = pos
Res(n, car, P, lag) ==
  LET same == [s |-> S[n], h |-> h[n], dv |-> div[n], j |-> jnl[n], d |-> D[n], x |-> aux[n], act |-> FALSE, rd |-> "NULL"] IN
  IF ~Tracked(n) THEN same
  ELSE IF h[n] # pos \/ Held(n)
       THEN \* DEFER (header-level checks only); STRIKE only for rules_epoch outside [epoch_cur, EPOCH_MAX]
            [same EXCEPT !.dv = IF car.re >= S[n].ec /\ car.re <= EPOCH_MAX THEN "no" ELSE "sah"]
  ELSE LET a   == ActNow(n)
           ard == ActRd(n)
           s1  == Step1(S[n], a, ard)
           okE == car.re = s1.ec                          \* rules_epoch = epoch_cur after step 1
           okR == car.rr = RT(TN(n), s1.ec)               \* the carrier runs the rules this node runs
           okF == car.fold = S[n] \/ (n = JN /\ Ctl = "JoinerIgnoresS")   \* receipts_root fold
           okC == \/ Ctl # "FoldAllCarried"
                  \/ IF lag THEN Len(jnl[n]) >= 1 /\ jnl[n][Len(jnl[n])].s = car.xfold
                     ELSE car.xfold = S[n]
           s2  == Step3(Step2(s1, P), pos)
       IN IF ~(okE /\ okR /\ okF /\ okC) THEN [same EXCEPT !.dv = "strike"]
          ELSE [s |-> s2, h |-> pos + 1, dv |-> "no",
                j |-> Push(jnl[n], [s |-> S[n], d |-> D[n], x |-> aux[n]]),
                d |-> IF UsesR5(n) THEN TransR5(D[n], S[n], s2, pos) ELSE D[n],
                x |-> NewAux(n, a, s2),
                act |-> a, rd |-> ard]

Extend ==
  /\ pos < MaxPos
  /\ \E v \in LiveSet : \E cb \in CarOpts(v) : \E ex \in PlcOpts(v) :
       /\ advW + cb.a + ex.a <= AdvMax
       /\ LET sv  == S[v]
              av  == ActNow(v)
              s1v == Step1(sv, av, ActRd(v))
              lag == ex.k # "none" /\ ex.lag = 1
              car == [re |-> s1v.ec, rr |-> RT(TN(v), s1v.ec), fold |-> sv,
                      xfold |-> IF lag THEN jnl[v][Len(jnl[v])].s ELSE sv]
              P   == IF ex.k = "none" THEN << [w |-> 1, b |-> cb.b] >>
                     ELSE << [w |-> 1, b |-> cb.b], [w |-> ex.w, b |-> ex.b] >>
              R   == [n \in AN |-> Res(n, car, P, lag)]
              wend == (pos + 1) % L = 0
          IN /\ pos' = pos + 1
             /\ S'   = [n \in AN |-> R[n].s]
             /\ h'   = [n \in AN |-> R[n].h]
             /\ div' = [n \in AN |-> R[n].dv]
             /\ jnl' = [n \in AN |-> R[n].j]
             /\ D'   = [n \in AN |-> R[n].d]
             /\ aux' = [n \in AN |-> R[n].x]
             /\ acts' = acts \cup {[ep |-> R[n].s.ec, rd |-> R[n].rd, at |-> pos] :
                                    n \in {m \in AN : Active(m) /\ R[m].act /\ R[m].dv = "no"}}
             /\ advJ' = Push(advJ, advW)
             /\ advW' = IF wend THEN 0 ELSE advW + cb.a + ex.a
             /\ gc' = IF Ghost THEN Append(gc, [P |-> P, act |-> av, rd |-> ActRd(v),
                                                by |-> IF cb.a = 1 THEN "ADV" ELSE RelN(v)])
                      ELSE gc
             /\ UNCHANGED <<rel2, jr, jp0, lrn, gab>>

(* A joiner adopts S_{p0-1} from a live peer at p0 = pos.                  *)
Join ==
  /\ Joiners # {} /\ jr = "none" /\ pos >= 1 /\ pos < MaxPos
  /\ \E r \in Joiners, p \in LiveSet \ {JN} :
       /\ (Later(r) => rel2)
       /\ LET sAd == IF Ctl = "JoinerIgnoresS"
                     THEN [S[p] EXCEPT !.all = 0, !.y1 = 0, !.y2 = 0, !.J = [i \in 1..WR |-> 0]]
                     ELSE S[p]
          IN /\ jr' = r /\ jp0' = pos
             /\ S' = [S EXCEPT ![JN] = sAd]
             /\ h' = [h EXCEPT ![JN] = pos]
             /\ jnl' = [jnl EXCEPT ![JN] = << >>]
             /\ D' = [D EXCEPT ![JN] = IF Sem = "r5" \/ Ctl = "R5Joiner" THEN Der5(Tab(r), sAd, pos - 1) ELSE D5Init({})]
             /\ UNCHANGED <<pos, div, advW, advJ, rel2, acts, aux, lrn, gc, gab>>

(* A reorg replaces the last k <= RD positions; nodes rewind from their journals. *)
Reorg ==
  /\ RD >= 1
  /\ \E k \in 1..RD :
       LET f == pos - k
           need(n) == IF Tracked(n) /\ h[n] > f THEN h[n] - f ELSE 0
           snap(n) == jnl[n][Len(jnl[n]) - need(n) + 1]
           crossed == \E x \in f..(pos - 1) : (x + 1) % L = 0
       IN /\ f >= 0
          /\ Len(advJ) >= k
          /\ \A n \in AN : need(n) <= Len(jnl[n])
          /\ pos' = f
          /\ S' = [n \in AN |-> IF need(n) > 0 /\ Ctl # "StaleS" THEN snap(n).s ELSE S[n]]
          /\ D' = [n \in AN |-> IF need(n) > 0 /\ Ctl # "StaleState" THEN snap(n).d ELSE D[n]]
          /\ aux' = [n \in AN |-> IF need(n) > 0 THEN snap(n).x ELSE aux[n]]
          /\ h' = [n \in AN |-> IF need(n) > 0 THEN f ELSE h[n]]
          /\ jnl' = [n \in AN |-> IF need(n) > 0 THEN SubSeq(jnl[n], 1, Len(jnl[n]) - need(n)) ELSE jnl[n]]
          /\ advW' = advJ[Len(advJ) - k + 1]
          /\ advJ' = SubSeq(advJ, 1, Len(advJ) - k)
          /\ gc' = IF Ghost THEN SubSeq(gc, 1, f) ELSE gc
          /\ gab' = IF Ghost /\ crossed /\ \E n \in LiveSet : TRUE
                    THEN [at |-> pos, s |-> S[CHOOSE n \in LiveSet : TRUE]] ELSE gab
          /\ UNCHANGED <<div, rel2, jr, jp0, acts, lrn>>

(* R2 is released once R1's attempt FAILED (no lock-in in windows 0 and 1) *)
(* and the FAILED boundary 8 lies below the reorg horizon (JR).            *)
Release ==
  /\ ~rel2 /\ Layout \in {"A", "S", "B", "BS", "N", "M", "MS", "MT"} /\ pos = R1To + JR
  /\ \E n \in LiveSet : \A i \in 1..WR : KK(pos, i) \in {0, 1} => S[n].J[i] = 0
  /\ \A n \in AN : Later(RelN(n)) => div[n] = "no"
  /\ rel2' = TRUE
  /\ UNCHANGED <<pos, S, h, div, jnl, D, advW, advJ, jr, jp0, acts, aux, lrn, gc, gab>>

(* Negative controls that need their own actions.                         *)
\* control FrameHold: a forged frame with rules_epoch 65535 makes the node HOLD
Forge ==
  /\ Ctl = "FrameHold"
  /\ \E n \in LiveSet : aux[n] # 1 /\ aux' = [aux EXCEPT ![n] = 1]
  /\ UNCHANGED <<pos, S, h, div, jnl, D, advW, advJ, rel2, jr, jp0, acts, lrn, gc, gab>>
\* controls HelloDesc / HelloNeither: HOLD needs a descriptor (compiled or learned from a peer's HELLO)
Learn ==
  /\ Ctl \in {"HelloDesc", "HelloNeither"}
  /\ \E n \in ActiveSet, m \in LiveSet : \E d \in TN(m) :
       /\ n # m /\ d \notin lrn[n] /\ ~(d \in TN(n))
       /\ lrn' = [lrn EXCEPT ![n] = @ \cup {d}]
  /\ UNCHANGED <<pos, S, h, div, jnl, D, advW, advJ, rel2, jr, jp0, acts, aux, gc, gab>>
AdvHello ==
  /\ Ctl = "HelloNeither"
  /\ \E n \in ActiveSet : Dsc(1, 0, "fx") \notin lrn[n] /\ lrn' = [lrn EXCEPT ![n] = @ \cup {Dsc(1, 0, "fx")}]
  /\ UNCHANGED <<pos, S, h, div, jnl, D, advW, advJ, rel2, jr, jp0, acts, aux, gc, gab>>
\* a tally over pending (not placed) receipts: the node adds a receipt from its own pool
PendingAdd ==
  /\ Ctl = "PendingTally"
  /\ \E n \in LiveSet, b \in 0..EPOCH_MAX :
       /\ aux[n] = -1
       /\ S' = [S EXCEPT ![n] = AddP(S[n], 1, b)]
       /\ aux' = [aux EXCEPT ![n] = 1]
  /\ UNCHANGED <<pos, h, div, jnl, D, advW, advJ, rel2, jr, jp0, acts, lrn, gc, gab>>

Next == Extend \/ Join \/ Reorg \/ Release \/ Forge \/ Learn \/ AdvHello \/ PendingAdd
Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Invariants.                                                             *)
AllMax == (1 + CMAX) * L + (IF Ctl = "PendingTally" THEN L ELSE 0)
SRec == [ec : 0..EPOCH_MAX, rc : Digests, all : 0..AllMax, y1 : 0..AllMax, y2 : 0..AllMax, J : [1..WR -> 0..2]]
\* BoundedState: S keeps one fixed shape and bounded fields whatever ballots appear
TypeOK == /\ pos \in 0..MaxPos
          /\ \A n \in AN : S[n] \in SRec /\ h[n] \in 0..MaxPos /\ div[n] \in {"no", "strike", "sah"}
          /\ advW \in 0..AdvMax
BoundedState == \A n \in AN : S[n] \in SRec

\* any two nodes that judge the same position agree on S (hence epoch_cur and rules_cur)
SameActivation == \A n, m \in ActiveSet : h[n] = h[m] => S[n] = S[m]

PrefixEImpl == \A n \in ActiveSet : EImplN(n) <= S[n].ec + 1

\* no honest node strikes a carrier of the honest chain (a fork), dormant R2 aside
NoFork == \A n \in AN : div[n] = "strike" => (Later(RelN(n)) /\ ~rel2)
NoStrikeOfHonestAfterHold == \A n \in AN : div[n] # "sah"
FollowerNeverDiverges == NoFork /\ NoStrikeOfHonestAfterHold

HoldOnlyOnConfirmedLockIn ==
  \A n \in ActiveSet : Held(n) =>
     \/ ~BaseN(n) \/ EImplN(n) < S[n].ec
     \/ \E i \in 1..WR : S[n].J[i] >= EImplN(n) - S[n].ec + 1 /\ HactW(KK(h[n], i)) <= h[n]

\* a HOLD sits at the activation of an attempt the node does not run (configs with AdvMax < 3/4 of a window)
NoSpuriousHold ==
  \A n \in ActiveSet : Held(n) =>
     \/ ~BaseN(n) \/ EImplN(n) < S[n].ec
     \/ \E a \in acts : a.at = HHoldN(n)
     \/ \E m \in ActiveSet \ {n} : \E p \in PendAct(m) : p.at = HHoldN(n)

\* an upgraded node's activation is the HOLD trigger of every node that does not run that attempt
ActiveEqualsHoldTrigger ==
  \A m \in ActiveSet : \A p \in PendAct(m) : \A n \in ActiveSet \ {m} :
     (h[n] <= p.at /\ p \notin PendAct(n)) =>
        /\ HHoldN(n) <= p.at
        /\ (EImplN(n) = p.ep - 1 /\ S[n].ec = p.ep - 1) => HHoldN(n) = p.at

FolJ == FolOf(jr)
JoinerAgreesWithFollower ==
  (jr # "none" /\ FolJ \in AN /\ Active(FolJ)) =>
     /\ div[JN] = "no"
     /\ h[JN] = h[FolJ] => (S[JN] = S[FolJ] /\ Dec(JN) = Dec(FolJ))
     /\ (Held(FolJ) /\ jp0 <= h[FolJ]) => h[JN] = h[FolJ]
     /\ Held(JN) => h[FolJ] <= h[JN]
JoinerAgreesBehaviour ==
  (jr # "none" /\ FolJ \in AN /\ Active(FolJ)) =>
     /\ div[JN] = "no"
     /\ h[JN] = h[FolJ] => DecB(JN) = DecB(FolJ)
     /\ (Held(FolJ) /\ jp0 <= h[FolJ]) => h[JN] = h[FolJ]
     /\ Held(JN) => h[FolJ] <= h[JN]

Proj5(dn) == [d \in DOMAIN dn |-> IF dn[d].st = "LOCK" THEN <<"LOCK", dn[d].hl>> ELSE <<dn[d].st, -1>>]
\* the same with only what other nodes can observe: no fork, the HOLD position and the ballot written
JoinerAgreesHB ==
  (jr # "none" /\ FolJ \in AN /\ Active(FolJ)) =>
     /\ div[JN] = "no"
     /\ h[JN] = h[FolJ] => (HHoldN(JN) = HHoldN(FolJ) /\ Ballot(JN) = Ballot(FolJ))
     /\ (Held(FolJ) /\ jp0 <= h[FolJ]) => h[JN] = h[FolJ]
     /\ Held(JN) => h[FolJ] <= h[JN]

\* fork and HOLD position only (the r5 and r6 ballot writers differ while LOCKED_IN, by design)
JoinerAgreesH ==
  (jr # "none" /\ FolJ \in AN /\ Active(FolJ)) =>
     /\ div[JN] = "no"
     /\ h[JN] = h[FolJ] => HHoldN(JN) = HHoldN(FolJ)
     /\ (Held(FolJ) /\ jp0 <= h[FolJ]) => h[JN] = h[FolJ]
     /\ Held(JN) => h[FolJ] <= h[JN]

\* the alternate wording of JoinerAgreesWithFollower: a joiner starting at ANY p0 reaches the same hold as a
\* follower of the same release from genesis (the shipped rule relaxes this for a joiner that starts after
\* H_act of a same-digest re-proposal)
JoinerAgreesR5 ==
  (jr # "none" /\ FolJ \in AN /\ Active(FolJ)) =>
     /\ div[JN] = "no"
     /\ h[JN] = h[FolJ] => (HHoldN(JN) = HHoldN(FolJ) /\ Ballot(JN) = Ballot(FolJ))
     /\ Held(FolJ) => Held(JN)
     /\ Held(JN) => h[FolJ] <= h[JN]

\* NoStrikeOfHonestAfterHold read against the Sem r6 H_hold (where the node should stop): a node that struck
\* an honest carrier at y did so below the H_hold the Sem r6 rule gives on (S_{y-1}, y, T)
NoStrikeAtOrAfterR6Hold ==
  \A n \in AN : div[n] = "strike" =>
     LET s == S[n]  y == h[n]  T == TN(n)  e == EImplR6(s, y, T, n)
         ks == {i \in 1..WR : s.J[i] >= e - s.ec + 1}
         hh == IF ~Base(s, T) THEN y ELSE IF ks = {} THEN INF ELSE MinS({HactW(KK(y, i)) : i \in ks})
     IN y < hh

RECURSIVE FoldC(_, _)
FoldC(sq, k) == IF k = 0 THEN SInit
                ELSE Step3(Step2(Step1(FoldC(sq, k - 1), sq[k].act, sq[k].rd), sq[k].P), k - 1)
\* S is a function of the chain prefix: with Ghost, every node's S equals the fold of the chain content;
\* alternate (Sem r5) stored states equal their derivation from S (a rewind restores both)
RsRootIsFunctionOfChain ==
  /\ SameActivation
  /\ Ghost => \A n \in ActiveSet : S[n] = FoldC(gc, h[n])
  /\ \A n \in ActiveSet \ {JN} : (UsesR5(n) /\ h[n] >= 1) => Proj5(D[n]) = Proj5(Der5(TN(n), S[n], h[n] - 1))

GraceFromLockIn ==
  /\ \A a \in acts : (a.at - GRACE + 1) % L = 0 /\ a.at - GRACE >= L - 1
  /\ \A m \in ActiveSet : \A p \in PendAct(m) : (p.at - GRACE + 1) % L = 0

OneOpenDeployment ==
  \A n \in ActiveSet : Cardinality({d \in TN(n) : LabelSt(n, d) \in {"STA", "LOCK", "WAIT"}}) <= 1

\* no two releases that are out hold open attempts of one epoch at once (release discipline)
OneOpenAcrossReleases ==
  \A n, m \in ActiveSet : \A d \in TN(n), c \in TN(m) :
     (d.ep = c.ep /\ d # c /\ LabelSt(n, d) \in {"STA", "LOCK"}) => LabelSt(m, c) \notin {"STA", "LOCK"}

---------------------------------------------------------------------------
(* Liveness as bounded reachability, and the scenarios.                     *)
(* Each "Witness" predicate is checked as an invariant: TLC reporting it    *)
(* VIOLATED is the witness trace (the scenario is reachable).               *)
\* ReProposalLive: after R1's attempt FAILED, a re-proposal of epoch 1 activates
RPWitness == ~(rel2 /\ \E a \in acts : a.ep = 1)
\* no dead end (structural form): once R2 is out and epoch 1 is not in force, R2's attempt of 1 is open
\* (STARTED or LOCKED_IN) at every position of its range; under "never reused" no attempt of 1 can ever open
ReProposalOpen ==
  \A n \in ActiveSet : (Later(RelN(n)) /\ S[n].ec = 0
                        /\ h[n] >= (IF UsesR5(n) THEN 9 ELSE 8) /\ h[n] < (IF UsesR5(n) THEN 17 ELSE 16)) =>
     \E d \in TN(n) : d.ep = 1 /\ LabelSt(n, d) \in {"STA", "LOCK"}

Sc1 == ~( \E a \in acts : a.ep = 1 /\ a.rd = "r1" /\ a.at = 3 + GRACE
          /\ Held("n0") /\ HHoldN("n0") = 3 + GRACE /\ h["n0"] = 3 + GRACE /\ pos > 3 + GRACE /\ NoFork )
\* contested: R1 built carriers in both STARTED windows, R1 FAILED, then R1 built the whole would-be window [8,12)
Sc2 == ~( Ghost /\ pos = 12 /\ (\A x \in 9..12 : gc[x].by = "R1")
          /\ (\E x \in 1..4 : gc[x].by = "R1") /\ (\E x \in 5..8 : gc[x].by = "R1")
          /\ LabelSt("n1", Dsc(1, 0, "r1")) = "FAIL"
          /\ \A n \in ActiveSet : ~Held(n) /\ NoFork )
Sc3 == ~( rel2 /\ \E a \in acts : a.ep = 1 /\ a.rd = "r2"
          /\ Held("n0") /\ Held("n1") /\ HHoldN("n0") = a.at /\ HHoldN("n1") = a.at
          /\ jr = "R1" /\ jp0 > a.at /\ Held(JN) /\ NoFork )
Sc4a == ~( jr = "R0" /\ \E a \in acts : a.ep = 1 /\ a.rd = "r1" /\ jp0 - 1 >= a.at - GRACE /\ jp0 <= a.at
           /\ Held(JN) /\ HHoldN(JN) = a.at /\ Held("n0") /\ HHoldN("n0") = a.at /\ NoFork )
Sc4b == ~( jr = "R1" /\ \E a \in acts : a.ep = 1 /\ a.rd = "r1" /\ jp0 - 1 >= a.at - GRACE /\ jp0 <= a.at
           /\ pos > a.at /\ h[JN] = pos /\ S[JN] = S["n1"] /\ S[JN].ec = 1 /\ NoFork )
\* supermajority for an unpublished epoch: window 0 (outside every range) at level 2, i.e. at least 3/4 of its
\* work votes above every published epoch (ballots 2 and 3); every node holds at h_L + GRACE - 1, nothing activates
Sc5 == ~( acts = {} /\ pos = 3 + GRACE /\ NoFork
          /\ \A n \in ActiveSet : S[n].J[1] = 2 /\ Held(n) /\ HHoldN(n) = 3 + GRACE )
\* junk: dead receipts with every ballot value in one window; no HOLD, S in its fixed shape
Sc6 == ~( Ghost /\ pos = L
          /\ {gc[x].P[2].b : x \in {x \in 1..Len(gc) : Len(gc[x].P) = 2 /\ gc[x].P[2].w = 0}} = 0..EPOCH_MAX
          /\ \A n \in ActiveSet : ~Held(n) /\ S[n].J[WR] = 0 /\ BoundedState /\ NoFork )
\* a reorg across a window end: the two branches' S differ, every node holds the winner's S
Sc7 == ~( Ghost /\ gab.at >= 0 /\ pos = gab.at /\ \E n \in LiveSet : S[n].J # gab.s.J
          /\ SameActivation /\ NoFork )
\* two-epoch table: R1b's 1 FAILS, R2's re-proposal activates while R1b's 2 is DEFINED; R1b holds
Sc8 == ~( rel2 /\ \E a \in acts : a.ep = 1 /\ a.rd = "r2" /\ a.at < 20
          /\ Held("n1") /\ HHoldN("n1") = a.at /\ EImplN("n1") = 0 /\ NoFork )
\* same-digest re-proposal: the R1 follower holds at H_act - 1, an R1 joiner after H_act runs
Sc9 == ~( rel2 /\ \E a \in acts : a.ep = 1 /\ a.rd = "r1"
          /\ Held("n1") /\ HHoldN("n1") = a.at /\ jr \in {"R1", "R1b"} /\ jp0 > a.at
          /\ ~Held(JN) /\ h[JN] = pos /\ pos > jp0 /\ NoFork )
\* predecessor digest: R2's attempt with another digest activates before R1b's start(2);
\* an R1b joiner after that sees WAITING for 2, writes no yes ballot and holds at once
Sc10 == ~( rel2 /\ \E a \in acts : a.ep = 1 /\ a.rd = "r2" /\ a.at < 20
           /\ jr = "R1b" /\ h[JN] >= 20 /\ Held(JN) /\ LabelSt(JN, Dsc(2, 20, "q2")) = "WAIT"
           /\ Ballot(JN) = 1 /\ NoFork )
\* a second activation: R3 activates epoch 2 on top of the re-proposed epoch 1; every other release holds
WEp2 == ~( \E a \in acts : a.ep = 2 /\ a.rd = "q3"
           /\ \A n \in ActiveSet \ {"n4"} : Held(n) /\ NoFork )
=============================================================================
