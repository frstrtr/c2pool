------------------------------ MODULE PathBSealRNP ------------------------------
(* TLA+ model of the Path B settlement / seal state machine (the c2pool v37 receipt-carrier ledger).

   Carriers form a chain through tip pointers; each carrier carries a canonically-ordered list of receipt ids.
   The checks of record:
     order     a carrier's carried list is strictly increasing by the canonical key (key here = (bin, id), the
               model's stand-in for (origin bin, sha256d(id || parent))).  Omission is relay policy, never a refusal.
     record    the height record H(x) = the max Monero height over the carriers at positions <= x (placed receipts
               never enter it); a receipt is live iff h(r) >= H(min(q - 1, own position)).  The hot path keeps
               HeightAt(ch, x) = rec[ch[x]].bin; RecordIsCarrierMax checks on every reachable chain that it equals
               the max over carriers 1..x.
     open      a carried receipt's bin is open iff H(pos(c) - 1) < h(r) + F on the carrier's own chain (= the record
               at the carrier's parent); the fold carrier may still carry its bin.

   Verdict.  Verdict(n, c) in {"defer", "accept", "refuse"}: defer while node n lacks c or an ancestor of c; else
   accept iff every carrier on c's lineage passes the node's validity rule.  Rule selects the rule a node computes:
     "ruled"      the checks above: a function of c's body, its lineage and the carried bodies only.
     "openlocal"  negative control: open judged on the verifier's best chain H(L) < h(r) + F.
     "omitlocal"  negative control: a carrier with room that omits an admissible pending receipt the verifier holds
                  (pool[n]) is refused.
     "prevlocal" / "unique" / "prevalt" / "joiner"  kept so earlier configs parse; in this model they compute the
                  ruled verdict.
   Fork choice and seals always use the ruled validity (Lineage), so a negative control changes only the verdict the
   invariant compares, never the explored chains (no circularity: Verdict may read ChainOf, ChainOf never reads Verdict).

   Adv = TRUE: Find may also mint invalid carriers (carried list out of order, a carried bin closed at the parent);
   they exist, are delivered and judged; no node's chain contains them.
   MaxCarry: at most this many carried ids per receipt (1; 2 lets the order rule bind).

   Delta is fixed at 1.  (This is the variant without the prev_own_share field.) *)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS Nodes, Rids, Payees, F, Dfin, MaxH, Reward, Variant, Fresh, CatchUp, MaxCarry, Adv, Rule, JoinWin, Joiner

ASSUME F >= 1 /\ Dfin >= 1 /\ Fresh >= 0 /\ CatchUp \in BOOLEAN /\ Adv \in BOOLEAN /\ MaxCarry \in {1, 2}
       /\ Variant \in {"own", "carriage", "nodead", "sharechain"}
       /\ Rule \in {"ruled", "openlocal", "prevlocal", "omitlocal", "unique", "joiner", "prevalt"}
       /\ JoinWin >= 1

VARIABLES mon, rec, nextId, known, sealed, pool

NONE == [kind |-> "none"]
UNSEALED == [done |-> FALSE, s |-> {}, pre |-> << >>]
vars == <<mon, rec, nextId, known, sealed, pool>>

IsCarrier(r) == rec[r].kind = "carrier"
InSeq(s, x) == \E i \in 1..Len(s) : s[i] = x
Range(s) == { s[i] : i \in 1..Len(s) }
MaxOf(S) == CHOOSE m \in S : \A y \in S : y <= m

(* Global lineage of a carrier through its tip pointers (genesis first).  Tip ids are older, so this terminates. *)
RECURSIVE GLin(_)
GLin(r) == IF r = 0 THEN << >> ELSE Append(GLin(rec[r].tip), r)

(* The record = max carrier height over positions 1..x of a chain (0 before genesis). *)
RecMax(ch, x) == IF x < 1 THEN 0 ELSE MaxOf({ rec[ch[p]].bin : p \in 1..x })
HeightAt(chain, p) == rec[chain[p]].bin           \* hot path; = RecMax (RecordIsCarrierMax)

(* Canonical key and order. *)
Less(x, y) == rec[x].bin < rec[y].bin \/ (rec[x].bin = rec[y].bin /\ x < y)
InOrder(s) == \A i \in 1..(Len(s) - 1) : Less(s[i], s[i + 1])

(* Placements of a chain in order: per position, the carried list (first placements only) then the carrier. *)
RECURSIVE PlSeq(_)
PlSeq(ch) == IF ch = << >> THEN << >>
             ELSE LET pre == PlSeq(SubSeq(ch, 1, Len(ch) - 1))
                      c == ch[Len(ch)]
                      new == SelectSeq(rec[c].carries, LAMBDA x : ~InSeq(pre, x))
                  IN pre \o new \o << c >>
(* Probe "prevalt": the other intra-position order (the carrier first, then its carried list). *)
RECURSIVE PlSeqAlt(_)
PlSeqAlt(ch) == IF ch = << >> THEN << >>
                ELSE LET pre == PlSeqAlt(SubSeq(ch, 1, Len(ch) - 1))
                         c == ch[Len(ch)]
                         new == SelectSeq(rec[c].carries, LAMBDA x : ~InSeq(pre, x))
                     IN pre \o << c >> \o new

(* Record at the carrier's parent = max carrier height on the tip's lineage. *)
ParentRec(c) == IF rec[c].tip = 0 THEN 0 ELSE RecMax(GLin(rec[c].tip), Len(GLin(rec[c].tip)))
OpenAt(c, x) == ParentRec(c) < rec[x].bin + F

(* The RULED validity of one carrier (its own body + carried bodies + its lineage only). *)
ValidRuled(c) == /\ InOrder(rec[c].carries)
                 /\ \A i \in 1..Len(rec[c].carries) : OpenAt(c, rec[c].carries[i])
ValidChainG(c) == \A a \in Range(GLin(c)) : ValidRuled(a)

VCarriers(n) == IF Adv THEN { r \in known[n] : IsCarrier(r) /\ ValidChainG(r) } ELSE { r \in known[n] : IsCarrier(r) }

RECURSIVE Lineage(_, _)
Lineage(n, r) == IF r = 0 THEN << >>
                 ELSE IF r \in VCarriers(n) /\ (rec[r].tip = 0 \/ rec[r].tip \in VCarriers(n))
                      THEN LET pre == Lineage(n, rec[r].tip)
                           IN IF rec[r].tip # 0 /\ pre = << >> THEN << >> ELSE Append(pre, r)
                      ELSE << >>

Tips(n) == { r \in VCarriers(n) : ~\E c \in VCarriers(n) : rec[c].tip = r }
ChainLen(n, t) == Len(Lineage(n, t))
ChainOf(n) == IF Tips(n) = {} THEN << >>
              ELSE LET best == CHOOSE t \in Tips(n) :
                                 \A u \in Tips(n) : ChainLen(n, u) < ChainLen(n, t)
                                                    \/ (ChainLen(n, u) = ChainLen(n, t) /\ t <= u)
                   IN Lineage(n, best)

OnChain(chain, r) == \E p \in 1..Len(chain) : chain[p] = r
PosOf(chain, r) == CHOOSE p \in 1..Len(chain) : chain[p] = r

RECURSIVE OwnPos(_, _, _)
OwnPos(chain, r, fuel) == IF r = 0 \/ fuel = 0 THEN 0
                          ELSE IF OnChain(chain, r) THEN PosOf(chain, r)
                          ELSE OwnPos(chain, rec[r].tip, fuel - 1) + 1

(* Liveness (Delta = 1): live iff h(r) >= H(min(q - 1, own position)); "carriage": H(q - 1). *)
JudgedPos(chain, r, cp) == LET o == OwnPos(chain, r, Cardinality(Rids)) IN IF cp - 1 < o THEN cp - 1 ELSE o
Live(chain, r, cp) ==
  CASE Variant = "nodead" -> "live"
    [] Variant = "carriage" -> IF cp - 1 < 1 \/ rec[r].bin >= HeightAt(chain, cp - 1) THEN "live" ELSE "dead"
    [] OTHER -> LET x == JudgedPos(chain, r, cp) IN IF x < 1 \/ rec[r].bin >= HeightAt(chain, x) THEN "live" ELSE "dead"

Placed(chain, r, p) == chain[p] = r \/ (Variant # "sharechain" /\ InSeq(rec[chain[p]].carries, r))

BinSet(chain, b, upto) ==
  { r \in Rids : rec[r].kind # "none" /\ rec[r].bin = b
       /\ \E p \in 1..upto : Placed(chain, r, p) /\ Live(chain, r, p) = "live" }

FoldPos(chain, b) == IF \E p \in 1..Len(chain) : HeightAt(chain, p) >= b + F
                     THEN CHOOSE p \in 1..Len(chain) : HeightAt(chain, p) >= b + F
                                 /\ \A q \in 1..(p - 1) : HeightAt(chain, q) < b + F
                     ELSE 0
SealPos(chain, b) == FoldPos(chain, b) + Dfin - 1
Sealable(chain, b) == FoldPos(chain, b) # 0 /\ Len(chain) >= SealPos(chain, b)

------------------------------------------------------------------------------------------------
(* Verdicts. *)
Avail(n, c) == IsCarrier(c) /\ Range(GLin(c)) \subseteq known[n]
TopRec(n) == LET ch == ChainOf(n) IN RecMax(ch, Len(ch))
(* The node's placement sequence (the only place the verdict still reads one): *)
PlSeqBy(n, ch) == IF Rule = "prevalt" /\ n = Joiner THEN PlSeqAlt(ch) ELSE PlSeq(ch)
OpenBy(n, c, x) == IF Rule = "openlocal" THEN TopRec(n) < rec[x].bin + F ELSE OpenAt(c, x)
OmitsKnown(n, c) == Len(rec[c].carries) < MaxCarry
                    /\ \E y \in pool[n] : /\ y < c /\ y # rec[c].tip /\ ~InSeq(rec[c].carries, y)   \* y older than c: its builder could hold it
                                          /\ ~InSeq(PlSeqBy(n, GLin(rec[c].tip)), y)
                                          /\ OpenAt(c, y)
LocalValid(n, c) == /\ InOrder(rec[c].carries)
                    /\ \A i \in 1..Len(rec[c].carries) : OpenBy(n, c, rec[c].carries[i])
                    /\ (Rule = "omitlocal" => ~OmitsKnown(n, c))
Accepts(n, c) == \A a \in Range(GLin(c)) : LocalValid(n, a)
Verdict(n, c) == IF ~Avail(n, c) THEN "defer" ELSE IF Accepts(n, c) THEN "accept" ELSE "refuse"

------------------------------------------------------------------------------------------------
Init == /\ mon = 1
        /\ rec = [r \in Rids |-> NONE]
        /\ nextId = 1
        /\ known = [n \in Nodes |-> {}]
        /\ sealed = [n \in Nodes |-> [b \in 1..MaxH |-> UNSEALED]]
        /\ pool = [n \in Nodes |-> {}]

Tick == /\ mon < MaxH
        /\ mon' = mon + 1
        /\ UNCHANGED <<rec, nextId, known, sealed, pool>>

CarrySeqs == {<< >>} \cup { << x >> : x \in Rids }
             \cup (IF MaxCarry >= 2 THEN { q \in Rids \X Rids : q[1] # q[2] } ELSE {})


(* A hash at carrier difficulty with a carried sequence.  Honest (Adv = FALSE): list in canonical order, every
   carried bin open at the parent record.  Adv = TRUE: also any order, closed bins. *)
Find(pay, h, tip, cs) ==
  /\ nextId \in Rids
  /\ h \in 1..mon
  /\ \/ h + 1 >= mon
     \/ CatchUp /\ tip # 0 /\ IsCarrier(tip) /\ mon - rec[tip].bin > Fresh /\ h = rec[tip].bin + Fresh
  /\ (tip = 0 /\ \A r \in Rids : ~IsCarrier(r)) \/ (tip # 0 /\ IsCarrier(tip) /\ rec[tip].bin <= h)
  /\ IF tip = 0 THEN TRUE ELSE h - rec[tip].bin <= Fresh
  /\ \A i \in 1..Len(cs) : rec[cs[i]].kind # "none" /\ cs[i] # tip
  /\ IF Adv THEN TRUE
     ELSE /\ InOrder(cs)
          /\ \A i \in 1..Len(cs) : tip = 0 \/ rec[cs[i]].bin + F > rec[tip].bin
  /\ LET isCar == \/ tip = 0
                  \/ \E n \in Nodes : tip \in Tips(n)
     IN rec' = [rec EXCEPT ![nextId] = [payee |-> pay, bin |-> h, tip |-> tip, carries |-> cs,
                                          kind |-> IF isCar THEN "carrier" ELSE "orphan"]]
  /\ nextId' = nextId + 1
  /\ UNCHANGED <<mon, known, sealed, pool>>

Deliver(n, r) == /\ IsCarrier(r) /\ r \notin known[n]
                 /\ known' = [known EXCEPT ![n] = @ \cup {r}]
                 /\ UNCHANGED <<mon, rec, nextId, sealed, pool>>

(* Pending-receipt relay: only the omitlocal control reads it, so it is enabled only there (other spaces unchanged). *)
DeliverPending(n, r) == /\ Rule = "omitlocal"
                        /\ rec[r].kind = "orphan" /\ r \notin pool[n]
                        /\ pool' = [pool EXCEPT ![n] = @ \cup {r}]
                        /\ UNCHANGED <<mon, rec, nextId, known, sealed>>

Prefix(ch, b) == SubSeq(ch, 1, SealPos(ch, b))

Seal(n, b) == /\ LET ch == ChainOf(n) IN
                 /\ Sealable(ch, b)
                 /\ (~sealed[n][b].done \/ sealed[n][b].pre # Prefix(ch, b))
                 /\ sealed' = [sealed EXCEPT ![n][b] = [done |-> TRUE, s |-> BinSet(ch, b, SealPos(ch, b)),
                                                           pre |-> Prefix(ch, b)]]
              /\ UNCHANGED <<mon, rec, nextId, known, pool>>

Next == \/ Tick
        \/ \E p \in Payees, h \in 1..MaxH, t \in {0} \cup Rids, cs \in CarrySeqs : Find(p, h, t, cs)
        \/ \E n \in Nodes, r \in Rids : Deliver(n, r)
        \/ \E n \in Nodes, r \in Rids : DeliverPending(n, r)
        \/ \E n \in Nodes, b \in 1..MaxH : Seal(n, b)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------------------------
TypeOK == /\ mon \in 1..MaxH
          /\ nextId \in 1..(Cardinality(Rids) + 1)
          /\ \A n \in Nodes : known[n] \subseteq Rids /\ pool[n] \subseteq Rids

Current(n, b) == LET ch == ChainOf(n) IN
                 sealed[n][b].done /\ Sealable(ch, b) /\ sealed[n][b].pre = Prefix(ch, b)

SealAgreement ==
  \A n1, n2 \in Nodes, b \in 1..MaxH :
    (Current(n1, b) /\ Current(n2, b) /\ sealed[n1][b].pre = sealed[n2][b].pre)
    => sealed[n1][b].s = sealed[n2][b].s

NoLostReceipt ==
  \A n \in Nodes, b \in 1..MaxH :
    Current(n, b) =>
      LET ch == ChainOf(n) IN
      \A r \in Rids : (rec[r].kind # "none" /\ rec[r].bin = b
                       /\ \E p \in 1..SealPos(ch, b) : Placed(ch, r, p) /\ Live(ch, r, p) = "live")
                      => r \in sealed[n][b].s

OrphanRecovered ==
  \A n \in Nodes, b \in 1..MaxH :
    Current(n, b) =>
      LET ch == ChainOf(n) IN
      \A r \in Rids : (rec[r].kind = "orphan" /\ rec[r].bin = b
                       /\ \E p \in 1..SealPos(ch, b) : InSeq(rec[ch[p]].carries, r) /\ rec[r].bin >= HeightAt(ch, p))
                      => r \in sealed[n][b].s

(* LegallyDead: every sealed receipt has a placement p with h(r) >= H(min(p - 1, own position)). *)
LegallyDead ==
  \A n \in Nodes, b \in 1..MaxH :
    Current(n, b) =>
      LET ch == ChainOf(n) IN
      \A r \in sealed[n][b].s :
        \E p \in 1..SealPos(ch, b) : Placed(ch, r, p)
          /\ LET x == JudgedPos(ch, r, p) IN x < 1 \/ rec[r].bin >= RecMax(ch, x)

LateUsefulLive ==
  \A n \in Nodes, b \in 1..MaxH :
    Current(n, b) =>
      LET ch == ChainOf(n) IN
      \A r \in Rids : (rec[r].kind = "orphan" /\ rec[r].bin = b
                       /\ (\E p \in 1..SealPos(ch, b) : InSeq(rec[ch[p]].carries, r))
                       /\ LET o == OwnPos(ch, r, Cardinality(Rids))
                          IN o < 1 \/ (o <= Len(ch) /\ rec[r].bin >= HeightAt(ch, o)))
                      => r \in sealed[n][b].s

FreshSealed == \A n \in Nodes, b \in 1..MaxH :
  sealed[n][b].done => \A r \in sealed[n][b].s :
     rec[r].tip = 0 \/ (rec[rec[r].tip].bin <= rec[r].bin /\ rec[r].bin - rec[rec[r].tip].bin <= Fresh)

Split(S) == LET k == Cardinality(S) IN k * (Reward \div k) + (Reward % k)
ExactSum == \A n \in Nodes, b \in 1..MaxH :
              (sealed[n][b].done /\ sealed[n][b].s # {}) => Split(sealed[n][b].s) = Reward

------------------------------------------------------------------------------------------------

(* AGREEMENT: two nodes that both hold a carrier's data never judge it differently. *)
Agreement == \A n1, n2 \in Nodes, c \in Rids :
               (Avail(n1, c) /\ Avail(n2, c)) => (Accepts(n1, c) = Accepts(n2, c))

(* No honest refusal: with Adv = FALSE every carrier is honest, so every node holding its data accepts it. *)
HonestAccepted == ~Adv => \A n \in Nodes, c \in Rids : Avail(n, c) => Accepts(n, c)

(* Ruled verdict vs the chain: a node's best chain holds only carriers the ruled verdict accepts. *)
ChainRuledValid == \A n \in Nodes : LET ch == ChainOf(n) IN
  /\ \A p \in 1..Len(ch) : ValidRuled(ch[p])

(* On every reachable chain the hot-path record (the carrier at x) equals the max over carriers 1..x. *)
RecordIsCarrierMax == \A n \in Nodes : LET ch == ChainOf(n) IN \A x \in 1..Len(ch) : HeightAt(ch, x) = RecMax(ch, x)


(* PROBES (expected VIOLATED = a witness exists). *)
(* A carrier on a best chain carries a receipt of a higher height than its own record (witness). *)
NoCarriedAboveRecord == \A n \in Nodes : LET ch == ChainOf(n) IN
  \A p \in 1..Len(ch) : \A i \in 1..Len(rec[ch[p]].carries) : rec[rec[ch[p]].carries[i]].bin <= HeightAt(ch, p)
(* A fold carrier carries a receipt of the bin it folds and that receipt is sealed (witness). *)
NoFoldCarrySealed == \A n \in Nodes, b \in 1..MaxH :
  Current(n, b) => LET ch == ChainOf(n) f == FoldPos(ch, b) IN
     \A i \in 1..Len(rec[ch[f]].carries) : LET x == rec[ch[f]].carries[i] IN ~(rec[x].bin = b /\ x \in sealed[n][b].s)
(* Single-check witnesses under Adv: a carrier whose ONLY failing ruled check is X exists and is refused. *)
OrderOK(c) == InOrder(rec[c].carries)
OpenOK(c) == \A i \in 1..Len(rec[c].carries) : OpenAt(c, rec[c].carries[i])
AncOK(c) == rec[c].tip = 0 \/ ValidChainG(rec[c].tip)
NoOrderRefusal == \A n \in Nodes, c \in Rids :
  (Avail(n, c) /\ ~OrderOK(c) /\ OpenOK(c) /\ AncOK(c)) => Accepts(n, c)      \* the order check binds
NoClosedRefusal == \A n \in Nodes, c \in Rids :
  (Avail(n, c) /\ OrderOK(c) /\ ~OpenOK(c) /\ AncOK(c)) => Accepts(n, c)      \* the open check binds

NodeSym == Permutations(Nodes)

(* One invariant = SealAgreement /\ NoLostReceipt /\ OrphanRecovered /\ LegallyDead /\ LateUsefulLive /\ ExactSum /\
   FreshSealed /\ Agreement /\ HonestAccepted /\ ChainRuledValid /\ RecordIsCarrierMax, each chain computed once per state
   (for the long n2r5 runs only; the separate invariants are checked on the n2r4 configs). *)
AllR ==
  LET chs == [n \in Nodes |-> ChainOf(n)]
      Cur(n, b) == sealed[n][b].done /\ Sealable(chs[n], b) /\ sealed[n][b].pre = Prefix(chs[n], b)
      acc == [n \in Nodes |-> [c \in Rids |-> IF Avail(n, c) THEN IF Accepts(n, c) THEN 1 ELSE 0 ELSE 2]]
  IN
  /\ \A n1, n2 \in Nodes, b \in 1..MaxH :
       (Cur(n1, b) /\ Cur(n2, b) /\ sealed[n1][b].pre = sealed[n2][b].pre) => sealed[n1][b].s = sealed[n2][b].s
  /\ \A n \in Nodes, b \in 1..MaxH :
       Cur(n, b) =>
         LET ch == chs[n]  sp == SealPos(ch, b)  S == sealed[n][b].s IN
         /\ \A r \in Rids : (rec[r].kind # "none" /\ rec[r].bin = b
                             /\ \E p \in 1..sp : Placed(ch, r, p) /\ Live(ch, r, p) = "live") => r \in S
         /\ \A r \in Rids : (rec[r].kind = "orphan" /\ rec[r].bin = b
                             /\ \E p \in 1..sp : InSeq(rec[ch[p]].carries, r) /\ rec[r].bin >= HeightAt(ch, p)) => r \in S
         /\ \A r \in S :
              \E p \in 1..sp : Placed(ch, r, p)
                 /\ LET x == JudgedPos(ch, r, p) IN x < 1 \/ rec[r].bin >= RecMax(ch, x)
         /\ \A r \in Rids : (rec[r].kind = "orphan" /\ rec[r].bin = b
                             /\ (\E p \in 1..sp : InSeq(rec[ch[p]].carries, r))
                             /\ LET o == OwnPos(ch, r, Cardinality(Rids))
                                IN o < 1 \/ (o <= Len(ch) /\ rec[r].bin >= HeightAt(ch, o)))
                            => r \in S
  /\ \A n \in Nodes, b \in 1..MaxH :
       (sealed[n][b].done /\ sealed[n][b].s # {}) => Split(sealed[n][b].s) = Reward
  /\ FreshSealed
  /\ \A n1, n2 \in Nodes, c \in Rids : (acc[n1][c] # 2 /\ acc[n2][c] # 2) => acc[n1][c] = acc[n2][c]
  /\ ~Adv => \A n \in Nodes, c \in Rids : acc[n][c] # 0
  /\ \A n \in Nodes : /\ \A p \in 1..Len(chs[n]) : ValidRuled(chs[n][p])
                      /\ \A x \in 1..Len(chs[n]) : HeightAt(chs[n], x) = RecMax(chs[n], x)

(* AllR without the LateUsefulLive conjunct: the carriage variant's combined invariant (LateUsefulLive is the
   carriage negative control, excluded from every carriage config).  Same statements otherwise. *)
AllRC ==
  LET chs == [n \in Nodes |-> ChainOf(n)]
      Cur(n, b) == sealed[n][b].done /\ Sealable(chs[n], b) /\ sealed[n][b].pre = Prefix(chs[n], b)
      acc == [n \in Nodes |-> [c \in Rids |-> IF Avail(n, c) THEN IF Accepts(n, c) THEN 1 ELSE 0 ELSE 2]]
  IN
  /\ \A n1, n2 \in Nodes, b \in 1..MaxH :
       (Cur(n1, b) /\ Cur(n2, b) /\ sealed[n1][b].pre = sealed[n2][b].pre) => sealed[n1][b].s = sealed[n2][b].s
  /\ \A n \in Nodes, b \in 1..MaxH :
       Cur(n, b) =>
         LET ch == chs[n]  sp == SealPos(ch, b)  S == sealed[n][b].s IN
         /\ \A r \in Rids : (rec[r].kind # "none" /\ rec[r].bin = b
                             /\ \E p \in 1..sp : Placed(ch, r, p) /\ Live(ch, r, p) = "live") => r \in S
         /\ \A r \in Rids : (rec[r].kind = "orphan" /\ rec[r].bin = b
                             /\ \E p \in 1..sp : InSeq(rec[ch[p]].carries, r) /\ rec[r].bin >= HeightAt(ch, p)) => r \in S
         /\ \A r \in S :
              \E p \in 1..sp : Placed(ch, r, p)
                 /\ LET x == JudgedPos(ch, r, p) IN x < 1 \/ rec[r].bin >= RecMax(ch, x)
  /\ \A n \in Nodes, b \in 1..MaxH :
       (sealed[n][b].done /\ sealed[n][b].s # {}) => Split(sealed[n][b].s) = Reward
  /\ FreshSealed
  /\ \A n1, n2 \in Nodes, c \in Rids : (acc[n1][c] # 2 /\ acc[n2][c] # 2) => acc[n1][c] = acc[n2][c]
  /\ ~Adv => \A n \in Nodes, c \in Rids : acc[n][c] # 0
  /\ \A n \in Nodes : /\ \A p \in 1..Len(chs[n]) : ValidRuled(chs[n][p])
                      /\ \A x \in 1..Len(chs[n]) : HeightAt(chs[n], x) = RecMax(chs[n], x)

(* AllR without the verdict terms (Agreement, HonestAccepted): seal invariants + ChainRuledValid + RecordIsCarrierMax,
   for the n2r5 runs that must finish inside the budget; the verdict terms are checked complete at n2r4. *)
AllRS ==
  LET chs == [n \in Nodes |-> ChainOf(n)]
      Cur(n, b) == sealed[n][b].done /\ Sealable(chs[n], b) /\ sealed[n][b].pre = Prefix(chs[n], b)
  IN
  /\ \A n1, n2 \in Nodes, b \in 1..MaxH :
       (Cur(n1, b) /\ Cur(n2, b) /\ sealed[n1][b].pre = sealed[n2][b].pre) => sealed[n1][b].s = sealed[n2][b].s
  /\ \A n \in Nodes, b \in 1..MaxH :
       Cur(n, b) =>
         LET ch == chs[n]  sp == SealPos(ch, b)  S == sealed[n][b].s IN
         /\ \A r \in Rids : (rec[r].kind # "none" /\ rec[r].bin = b
                             /\ \E p \in 1..sp : Placed(ch, r, p) /\ Live(ch, r, p) = "live") => r \in S
         /\ \A r \in Rids : (rec[r].kind = "orphan" /\ rec[r].bin = b
                             /\ \E p \in 1..sp : InSeq(rec[ch[p]].carries, r) /\ rec[r].bin >= HeightAt(ch, p)) => r \in S
         /\ \A r \in S :
              \E p \in 1..sp : Placed(ch, r, p)
                 /\ LET x == JudgedPos(ch, r, p) IN x < 1 \/ rec[r].bin >= RecMax(ch, x)
         /\ \A r \in Rids : (rec[r].kind = "orphan" /\ rec[r].bin = b
                             /\ (\E p \in 1..sp : InSeq(rec[ch[p]].carries, r))
                             /\ LET o == OwnPos(ch, r, Cardinality(Rids))
                                IN o < 1 \/ (o <= Len(ch) /\ rec[r].bin >= HeightAt(ch, o)))
                            => r \in S
  /\ \A n \in Nodes, b \in 1..MaxH :
       (sealed[n][b].done /\ sealed[n][b].s # {}) => Split(sealed[n][b].s) = Reward
  /\ FreshSealed
  /\ \A n \in Nodes : /\ \A p \in 1..Len(chs[n]) : ValidRuled(chs[n][p])
                      /\ \A x \in 1..Len(chs[n]) : HeightAt(chs[n], x) = RecMax(chs[n], x)

(* AllRS for the carriage variant (no LateUsefulLive, the carriage control). *)
AllRSC ==
  LET chs == [n \in Nodes |-> ChainOf(n)]
      Cur(n, b) == sealed[n][b].done /\ Sealable(chs[n], b) /\ sealed[n][b].pre = Prefix(chs[n], b)
  IN
  /\ \A n1, n2 \in Nodes, b \in 1..MaxH :
       (Cur(n1, b) /\ Cur(n2, b) /\ sealed[n1][b].pre = sealed[n2][b].pre) => sealed[n1][b].s = sealed[n2][b].s
  /\ \A n \in Nodes, b \in 1..MaxH :
       Cur(n, b) =>
         LET ch == chs[n]  sp == SealPos(ch, b)  S == sealed[n][b].s IN
         /\ \A r \in Rids : (rec[r].kind # "none" /\ rec[r].bin = b
                             /\ \E p \in 1..sp : Placed(ch, r, p) /\ Live(ch, r, p) = "live") => r \in S
         /\ \A r \in Rids : (rec[r].kind = "orphan" /\ rec[r].bin = b
                             /\ \E p \in 1..sp : InSeq(rec[ch[p]].carries, r) /\ rec[r].bin >= HeightAt(ch, p)) => r \in S
         /\ \A r \in S :
              \E p \in 1..sp : Placed(ch, r, p)
                 /\ LET x == JudgedPos(ch, r, p) IN x < 1 \/ rec[r].bin >= RecMax(ch, x)
  /\ \A n \in Nodes, b \in 1..MaxH :
       (sealed[n][b].done /\ sealed[n][b].s # {}) => Split(sealed[n][b].s) = Reward
  /\ FreshSealed
  /\ \A n \in Nodes : /\ \A p \in 1..Len(chs[n]) : ValidRuled(chs[n][p])
                      /\ \A x \in 1..Len(chs[n]) : HeightAt(chs[n], x) = RecMax(chs[n], x)

================================================================================================
