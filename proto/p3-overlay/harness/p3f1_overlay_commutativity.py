#!/usr/bin/env python3
"""
P3-F1 overlay-commutativity harness (the P3-12 invariant).

Question (consensus-bearing): at N>1 aux-chains feeding ONE owed-ledger through ONE
finality-gated overlay, is the final owed-ledger a function ONLY of the event multiset
and NOT of the cross-chain interleaving order? If not, two honest nodes that observe the
N streams in different orders compute different owed-ledgers -> different assemble()
coinbase -> different sharechain-block validity -> CHAIN SPLIT.

We test three revert semantics over ALL legal interleavings of one fixed event multiset:

  (B1) SNAPSHOT_WHOLE   - ORPHAN restores a whole-ledger snapshot taken at FOUND
                          ("restore pre-FOUND owed", literal reading). Expected: NON-commutative
                          even without compaction (it wipes other chains' interleaved events).
  (B2) SNAPSHOT_DELTA   - ORPHAN subtracts the FOUND-time delta from the current working ledger.
                          Commutes under pure adds AND under value-recoverable compaction - but
                          small-miner-equity compaction sweeps sub-threshold owed into the
                          REMAINDER POT, an IRREVERSIBLE rebase that loses per-(chain,block)
                          attribution. If that sweep folds a still-pending contribution, the stale
                          absolute delta misfires on revert. Expected: NON-commutative.
  (FIX) KEYED_CRDT      - contributions live as a per-(chain,block)-keyed pending multiset;
                          FINALIZE moves a key into a monotonic finalized partition (and ONLY the
                          finalized partition is ever compacted); ORPHAN deletes its key. Rendered
                          L = finalized-equity + sum of pending contributions. Expected: COMMUTATIVE
                          - final L is a pure function of the event multiset.

Deterministic: no RNG, no clock. Prints a golden sha256 over the FIX invariant result.
"""
import copy, hashlib, json
from itertools import permutations

MINERS = ["m1", "m2", "m3"]
H_MIN = 1  # byte-denominated anti-sybil floor (M2); outputs below are not emitted
TAU = 3    # small-miner-equity dust threshold: owed < TAU is swept to the remainder pot

# Fixed event multiset: c0 found-then-orphaned, c1 found-then-finalized.
# Final TRUTH: c0 reorged out (gone), c1 final -> owed == c1's contribution only.
# Note m2's c0-share (2) is BELOW the dust threshold TAU=3: if compaction runs while c0 is
# still pending, m2:2 gets swept irreversibly into the remainder pot -> the B2 hazard.
CONTRIB = {
    ("c0", "b0"): {"m1": 6, "m2": 2},   # delta0  (m2:2 < TAU -> dust-sweepable while pending)
    ("c1", "b0"): {"m3": 10},           # delta1
}
EXPECTED = {"m1": 0, "m2": 0, "m3": 10, "R_pot": 0}  # order-independent ground truth (c0 gone, c1 final)

# Per-chain causal order: FOUND must precede ORPHAN/FINALIZED of the same (chain,block).
EVENTS = [
    ("FOUND",     "c0", "b0"),
    ("ORPHAN",    "c0", "b0"),
    ("FOUND",     "c1", "b0"),
    ("FINALIZED", "c1", "b0"),
]

def legal(seq):
    """Causal legality: for each (chain,block), FOUND index < its ORPHAN/FINALIZED index."""
    pos = {}
    for i, (k, c, b) in enumerate(seq):
        pos.setdefault((c, b), {})[k] = i
    for (c, b), p in pos.items():
        if "FOUND" not in p:
            return False
        for term in ("ORPHAN", "FINALIZED"):
            if term in p and p["FOUND"] > p[term]:
                return False
    return True

def legal_interleavings():
    seen, out = set(), []
    for perm in permutations(EVENTS):
        if perm in seen:
            continue
        seen.add(perm)
        if legal(perm):
            out.append(perm)
    return out

def zero():
    return {m: 0 for m in MINERS}

def add(a, b, sign=1):
    return {m: a.get(m, 0) + sign * b.get(m, 0) for m in MINERS}

# ---------------------------------------------------------------- B1: SNAPSHOT_WHOLE
def run_snapshot_whole(seq):
    W = zero()
    snap = {}
    for (k, c, b) in seq:
        if k == "FOUND":
            snap[(c, b)] = copy.deepcopy(W)          # snapshot the WHOLE ledger
            W = add(W, CONTRIB[(c, b)])
        elif k == "FINALIZED":
            pass                                      # contribution stays owed/credited
        elif k == "ORPHAN":
            W = copy.deepcopy(snap[(c, b)])           # "restore pre-FOUND owed" (whole ledger)
    out = {m: W[m] for m in MINERS}
    out["R_pot"] = 0
    return out

# ---------------------------------------------------------------- B2: SNAPSHOT_DELTA + dust-sweep
def dust_sweep(W, pot):
    """Small-miner-equity compaction: owed below TAU is swept into the remainder pot, an
    IRREVERSIBLE rebase that DROPS per-(chain,block) attribution. Value-preserving in total,
    but a swept miner's per-miner owed is gone from W -> a later absolute-delta revert misfires."""
    for m in MINERS:
        if 0 < W[m] < TAU:
            pot[0] += W[m]
            W[m] = 0
    return W

def run_snapshot_delta(seq):
    W = zero()
    pot = [0]                                             # remainder pot (unattributed)
    sd = {}
    for (k, c, b) in seq:
        if k == "FOUND":
            sd[(c, b)] = copy.deepcopy(CONTRIB[(c, b)])   # store the ABSOLUTE found-time delta
            W = add(W, CONTRIB[(c, b)])
        elif k == "FINALIZED":
            W = dust_sweep(W, pot)                        # BUG: sweeps WHATEVER is in W, incl. pending
        elif k == "ORPHAN":
            W = add(W, sd[(c, b)], sign=-1)               # subtract the STALE absolute delta
    out = {m: W[m] for m in MINERS}
    out["R_pot"] = pot[0]
    return out

# ---------------------------------------------------------------- FIX: KEYED_CRDT
def run_keyed_crdt(seq):
    pending = {}          # (chain,block) -> contribution map        [reversible]
    finalW = zero()       # monotonic finalized partition            [compaction acts ONLY here]
    pot = [0]             # remainder pot
    for (k, c, b) in seq:
        if k == "FOUND":
            pending[(c, b)] = copy.deepcopy(CONTRIB[(c, b)])
        elif k == "FINALIZED":
            contrib = pending.pop((c, b))                 # move key into the finalized partition
            for m in MINERS:
                finalW[m] += contrib.get(m, 0)
            finalW = dust_sweep(finalW, pot)              # compaction restricted to FINALIZED only:
            # the necessary+sufficient invariant. A pending contribution is NEVER swept, so its
            # revert (key removal) stays well-defined and order-independent.
        elif k == "ORPHAN":
            pending.pop((c, b))                           # pure keyed multiset removal
    L = copy.deepcopy(finalW)
    for contrib in pending.values():
        L = add(L, contrib)
    L["R_pot"] = pot[0]
    return L

# ---------------------------------------------------------------- assemble() coinbase
def assemble(L):
    """Deterministic coinbase: outputs sorted by miner, amounts >= H_MIN only. Identical L
    -> identical coinbase. Returned as a sha256 over the canonical output list."""
    outs = sorted([(m, v) for m, v in L.items() if v >= H_MIN])
    blob = json.dumps(outs, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()

def distinct(results):
    return {json.dumps(r, sort_keys=True) for r in results}

def report(name, runner, interleavings):
    Ls = [runner(s) for s in interleavings]
    cbs = [assemble(L) for L in Ls]
    uniqL = distinct(Ls)
    uniqCB = set(cbs)
    commutative = len(uniqL) == 1
    matches_truth = commutative and Ls[0] == EXPECTED
    print(f"\n=== {name} : {len(interleavings)} legal interleavings ===")
    print(f"  distinct final owed-ledgers : {len(uniqL)}")
    print(f"  distinct assembled coinbases: {len(uniqCB)}")
    print(f"  COMMUTATIVE (order-independent): {commutative}")
    if commutative:
        print(f"  final L = {json.dumps(Ls[0], sort_keys=True)}  (== ground truth: {matches_truth})")
        print(f"  golden coinbase sha256: {cbs[0]}")
    else:
        print(f"  !! NON-COMMUTATIVE -> chain-split surface. Divergent ledgers:")
        for s, L in zip(interleavings, Ls):
            order = " ".join(f"{k[:3]}.{c}" for (k, c, b) in s)
            print(f"     [{order}] -> {json.dumps(L, sort_keys=True)}  cb={assemble(L)[:12]}")
    return {"name": name, "interleavings": len(interleavings),
            "distinct_L": len(uniqL), "commutative": commutative,
            "matches_truth": matches_truth,
            "golden_L": Ls[0] if commutative else None,
            "golden_cb": cbs[0] if commutative else None}

def main():
    inter = legal_interleavings()
    print(f"P3-F1 overlay-commutativity / P3-12 invariant")
    print(f"event multiset = {[ (k,c) for (k,c,b) in EVENTS ]}")
    print(f"legal interleavings (per-chain causal order enforced): {len(inter)}")
    r1 = report("B1 SNAPSHOT_WHOLE  (restore pre-FOUND whole ledger)", run_snapshot_whole, inter)
    r2 = report("B2 SNAPSHOT_DELTA  (subtract stale absolute delta; FINALIZE compacts)", run_snapshot_delta, inter)
    r3 = report("FIX KEYED_CRDT     (keyed pending multiset; compact finalized-only)", run_keyed_crdt, inter)

    print("\n=== VERDICT ===")
    assert not r1["commutative"], "B1 expected NON-commutative"
    assert not r2["commutative"], "B2 expected NON-commutative under compaction"
    assert r3["commutative"], "FIX expected COMMUTATIVE"
    assert r3["matches_truth"], "FIX must equal the order-independent ground truth"
    print("  B1 snapshot-whole : NON-commutative (wipes interleaved cross-chain events)  [as predicted]")
    print("  B2 snapshot-delta : NON-commutative (compaction rebases; stale delta misfires) [as predicted]")
    print("  FIX keyed-CRDT    : COMMUTATIVE over all legal interleavings, == ground truth  [P3-12 GREEN]")
    golden = {"P3-12": "event-order-permutation invariance",
              "fix": "KEYED_CRDT (per-(chain,block) pending multiset + finalized-only compaction)",
              "interleavings_tested": r3["interleavings"],
              "final_owed_ledger": r3["golden_L"],
              "assembled_coinbase_sha256": r3["golden_cb"]}
    stamp = hashlib.sha256(json.dumps(golden, sort_keys=True).encode()).hexdigest()
    print(f"\n  GOLDEN VECTOR sha256: {stamp}")
    print(f"  golden: {json.dumps(golden, sort_keys=True)}")

if __name__ == "__main__":
    main()
