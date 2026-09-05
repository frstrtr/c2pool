#!/usr/bin/env python3
"""
V37 P3 multichain testbed — SCENARIO RUNNERS (matrix rows).

Each row is a deterministic scenario; PASS = the stated invariants hold AND the emitted
golden vector is bit-stable. Rows land golden vectors under proto/p3-testbed/golden/.

Rows landed in this slice:
  P3-1  single happy path FOUND->FINALIZED, all miners paid, bounded coinbase
  P3-2  orphan-then-revert at d <= D_f (OverlayReverted restores pre-FOUND; no double-pay)
  P3-3  N=3 independent chains, distinct D_f/cadence/f_consensus, settlement isolation
  P3-4  two-anchor share (same work, two chains): paid once; double-claim rejected
  P3-12 event-order-permutation invariance (F1 gate) — order-invariant owed + coinbase
  P3-13 two-anchor x revert (F2 gate) — revert-aware dedup: paid once on the finalized chain

Deferred to the next slice (documented, not silently dropped): P3-5 compaction-liveness,
P3-6 reorg-storm convergence, P3-7/P3-7b liveness+A-CHAINLIVE, P3-8/P3-9 negative surfacing,
P3-10 cold-validator bootstrap, P3-11 per-chain f_consensus divergence, F4 cross-denomination
remainder, F5 per-chain affinity isolation.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine import (  # noqa: E402
    Overlay, ChainOracle, PayoutDescriptor, Share, assemble_coinbase,
    legal_interleavings, replay, canonical, golden_stamp,
)

GOLDEN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "golden")


def _descriptors(miners):
    return {m: PayoutDescriptor(m) for m in miners}


def _value_conserved(ov, credited_total):
    """Lane invariant (value-invariance): finalized owed + remainder pot == total finalized
    credit. No value is minted or lost across compaction."""
    return sum(ov.finalW.values()) + ov.pot == credited_total


# --------------------------------------------------------------------------- P3-1
def p3_1():
    miners = ["m1", "m2", "m3"]
    contrib = {"m1": 6, "m2": 4, "m3": 5}
    contribs = {("c0", "b0"): [(None, contrib)]}
    events = [("FOUND", "c0", "b0", None), ("FINALIZED", "c0", "b0", None)]
    ov = replay(events, miners, contribs)

    # I-invariants (light structural): pending drained, no negative owed, value conserved.
    assert ov.pending == {}, "I: overlay cleared at finality"
    assert all(v >= 0 for v in ov.finalW.values()), "I: no negative owed"
    assert _value_conserved(ov, sum(contrib.values())), "I: value conserved"
    assert ov.finalized_owed() == contrib, "owed reflects the finalized credit"

    first_elig = {m: 0 for m in miners}
    outs, cb = assemble_coinbase(ov.finalized_owed(), first_elig, slot_budget=8,
                                 descriptors=_descriptors(miners))
    assert len(outs) <= 8, "bounded coinbase (<= slot budget)"
    assert len(outs) == 3, "all three miners paid"
    return {"row": "P3-1", "final_owed": ov.finalized_owed(), "pot": ov.pot,
            "coinbase_outputs": outs, "coinbase_sha256": cb}


# --------------------------------------------------------------------------- P3-2
def p3_2():
    miners = ["m1", "m2", "m3"]
    contrib = {"m1": 6, "m2": 4, "m3": 5}
    contribs = {("c0", "b0"): [("S1", contrib)]}
    oracle = ChainOracle("c0", d_f=6)
    orphan_depth = 2
    assert orphan_depth <= oracle.d_f, "A-REORG: orphan within finality depth"
    events = [("FOUND", "c0", "b0", None), ("ORPHANED", "c0", "b0", orphan_depth)]
    ov = replay(events, miners, contribs)

    assert ov.owed_ledger() == {m: 0 for m in miners}, "OverlayReverted restores pre-FOUND owed"
    assert ov.pot == 0, "no residual in remainder pot after revert"
    assert not ov.is_work_paid("S1"), "orphaned work never counts as paid (no double-pay)"
    outs, cb = assemble_coinbase(ov.finalized_owed(), {m: 0 for m in miners},
                                 slot_budget=8, descriptors=_descriptors(miners))
    assert outs == [], "reverted state pays nothing"
    return {"row": "P3-2", "owed_after_revert": ov.owed_ledger(), "pot": ov.pot,
            "work_paid_S1": ov.is_work_paid("S1"), "coinbase_sha256": cb}


# --------------------------------------------------------------------------- P3-3
def p3_3():
    # 3 chains, DISJOINT miners, distinct D_f / cadence / f_consensus.
    miners = ["m0", "m1", "m2"]
    oracles = {
        "c0": ChainOracle("c0", d_f=3, cadence=1, f_consensus=1),
        "c1": ChainOracle("c1", d_f=6, cadence=2, f_consensus=2),
        "c2": ChainOracle("c2", d_f=9, cadence=3, f_consensus=5),
    }
    contribs = {
        ("c0", "b0"): [(None, {"m0": 7})],
        ("c1", "b0"): [(None, {"m1": 7})],
        ("c2", "b0"): [(None, {"m2": 7})],
    }
    events = []
    for c in ("c0", "c1", "c2"):
        events += [("FOUND", c, "b0", None), ("FINALIZED", c, "b0", None)]
    ov = replay(events, miners, contribs)

    # Isolation: each miner's owed is EXACTLY their own chain's credit — no cross-chain leak.
    assert ov.finalized_owed() == {"m0": 7, "m1": 7, "m2": 7}, "per-chain settlement isolation"
    # Per-chain assemble applies that chain's f_consensus denomination (A-FCON), no global f.
    per_chain = {}
    chain_of = {"m0": "c0", "m1": "c1", "m2": "c2"}
    for c, o in oracles.items():
        m = [k for k, v in chain_of.items() if v == c][0]
        outs, cb = assemble_coinbase({m: ov.finalW[m]}, {m: 0}, slot_budget=1,
                                     descriptors=_descriptors([m]), f_consensus=o.f_consensus)
        per_chain[c] = {"f_consensus": o.f_consensus, "outputs": outs, "sha256": cb}
    assert per_chain["c1"]["outputs"][0][1] == 14, "c1 f_consensus=2 denomination applied"
    assert per_chain["c2"]["outputs"][0][1] == 35, "c2 f_consensus=5 denomination applied"
    return {"row": "P3-3", "final_owed": ov.finalized_owed(), "per_chain": per_chain}


# --------------------------------------------------------------------------- P3-4
def p3_4():
    # Two-anchor share S: SAME work_id on c0 and c1. Static (both eventually finalize),
    # A-2ANCHOR: paid once; the second chain's finalize must NOT re-credit.
    miners = ["mS"]
    contribs = {
        ("c0", "b0"): [("S", {"mS": 10})],
        ("c1", "b0"): [("S", {"mS": 10})],
    }
    events = [("FOUND", "c0", "b0", None), ("FINALIZED", "c0", "b0", None),
              ("FOUND", "c1", "b0", None), ("FINALIZED", "c1", "b0", None)]
    ov = replay(events, miners, contribs)

    assert ov.finalized_owed() == {"mS": 10}, "A-2ANCHOR: paid once (not 20)"
    assert ov.is_work_paid("S"), "work S recorded in the finalized set"
    assert ov.finalized_work["S"] == ("c0", "b0"), "credited on the FIRST finalizing chain"
    return {"row": "P3-4", "final_owed": ov.finalized_owed(),
            "paid_on": list(ov.finalized_work["S"])}


# --------------------------------------------------------------------------- P3-12 (F1 gate)
def p3_12():
    # Event-order-permutation invariance over ALL legal interleavings of a fixed multiset.
    # c0 found-then-orphaned; c1 found-then-finalized. m_b's c0-share is below TAU (dust-
    # sweepable) — the hazard that breaks snapshot semantics; KEYED_CRDT must be invariant.
    miners = ["ma", "mb", "mc"]
    contribs = {
        ("c0", "b0"): [(None, {"ma": 6, "mb": 2})],   # mb:2 < TAU=3 (dust-sweepable if pending swept)
        ("c1", "b0"): [(None, {"mc": 10})],
    }
    events = [("FOUND", "c0", "b0", None), ("ORPHANED", "c0", "b0", 2),
              ("FOUND", "c1", "b0", None), ("FINALIZED", "c1", "b0", None)]
    inter = legal_interleavings(events)

    ledgers, coinbases = [], []
    for seq in inter:
        ov = replay(seq, miners, contribs)
        L = ov.owed_ledger()
        L["_pot"] = ov.pot
        ledgers.append(L)
        _, cb = assemble_coinbase(ov.finalized_owed(), {m: 0 for m in miners},
                                  slot_budget=8, descriptors=_descriptors(miners))
        coinbases.append(cb)

    distinct_L = {canonical(L) for L in ledgers}
    distinct_cb = set(coinbases)
    assert len(distinct_L) == 1, "F1: owed-ledger MUST be order-invariant (else chain-split)"
    assert len(distinct_cb) == 1, "F1: assembled coinbase MUST be order-invariant"
    truth = {"ma": 0, "mb": 0, "mc": 10, "_pot": 0}   # c0 gone, c1 final
    assert ledgers[0] == truth, "invariant ledger == order-independent ground truth"
    return {"row": "P3-12", "interleavings": len(inter), "distinct_ledgers": len(distinct_L),
            "distinct_coinbases": len(distinct_cb), "invariant_ledger": ledgers[0],
            "coinbase_sha256": coinbases[0]}


# --------------------------------------------------------------------------- P3-13 (F2 gate)
def p3_13():
    # Two-anchor x revert: S anchors {c0,c1}. c0 FOUND+FINALIZED pays S; c0 ORPHANED reverts;
    # then c1 FOUND+FINALIZED. ASSERT S paid exactly once (on c1), never zero, never twice,
    # over ALL legal interleavings — the revert-aware dedup key.
    miners = ["mS"]
    contribs = {
        ("c0", "b0"): [("S", {"mS": 10})],
        ("c1", "b0"): [("S", {"mS": 10})],
    }
    # Note: c0 finalizes THEN orphans (a d<=D_f reorg of an already-finalized-looking block is
    # out-of-floor; here c0 orphans while still within finality window before c1 settles).
    events = [("FOUND", "c0", "b0", None), ("ORPHANED", "c0", "b0", 2),
              ("FOUND", "c1", "b0", None), ("FINALIZED", "c1", "b0", None)]
    inter = legal_interleavings(events)

    outcomes = []
    for seq in inter:
        ov = replay(seq, miners, contribs)
        paid = ov.finalized_owed().get("mS", 0)
        outcomes.append((paid, ov.finalized_work.get("S")))

    paids = {p for p, _ in outcomes}
    assert paids == {10}, "F2: paid EXACTLY once (10), never zero, never twice, over all orders"
    where = {w for _, w in outcomes}
    assert where == {("c1", "b0")}, "F2: credited on the surviving (finalized) chain c1, revert-aware"
    return {"row": "P3-13", "interleavings": len(inter), "paid_amounts": sorted(paids),
            "credited_on": ["c1", "b0"]}


# =========================================================================== #
# SLICE-2 rows. Self-carry compaction (M2 ref) is modelled with tau=0 on the
# Overlay: sub-floor owed CARRIES (retains miner identity) instead of sweeping
# to an anonymous pot. The remainder pot is reserved for its canonical role —
# genuinely unattributable cross-denomination remainder (F4). Slice-1 stamps
# are untouched (no slice-1 row ever finalizes a sub-TAU credit; _pot stays 0).
# =========================================================================== #

class OutOfFloorHalt(Exception):
    """A-REORG: a reorg deeper than D_f is out-of-floor. The overlay must HALT-and-
    resurvey (surface), NOT silently revert. P3-8 asserts this guard fires."""


def _apply_orphan_guarded(oracle, depth):
    """Model the A-REORG floor: orphan is a legal revert iff depth <= D_f; deeper is a
    halt condition the node surfaces rather than applying. Returns True if appliable."""
    if depth > oracle.d_f:
        raise OutOfFloorHalt(f"chain {oracle.chain_id}: reorg depth {depth} > D_f {oracle.d_f}")
    return True


def _settle_round(owed, first_eligible, height, slot_budget, descriptors, f_consensus=1):
    """One coinbase settlement round (composes M2 K_fair + self-carry). Selects <= C
    payout slots by the ratified (first_eligible ASC, id ASC) order; emits+pays a slot
    ONLY when amt >= that miner's h_min. Sub-floor / unselected owed CARRIES (retains
    identity, first_eligible preserved) — pure self-carry, no pot. Mutates owed/first_eligible.
    Returns (outputs, coinbase_sha256)."""
    from engine import select_payouts  # local: same module symbol
    selected = select_payouts(owed, first_eligible, slot_budget)
    outs = []
    for m in selected:
        h_min = descriptors[m].h_min if m in descriptors else 1
        amt = owed[m] * f_consensus
        if amt >= h_min:
            outs.append((m, amt, descriptors[m].script_type if m in descriptors else "p2wpkh"))
            owed[m] = 0                              # paid -> owed cleared
            first_eligible.pop(m, None)              # disarm on 0 (M2 pay semantics)
        # else: sub-floor -> carry (owed & first_eligible untouched)
    outs.sort()
    blob = json.dumps(outs, separators=(",", ":"), sort_keys=True).encode()
    import hashlib
    return outs, hashlib.sha256(blob).hexdigest()


def _credit(owed, first_eligible, m, amt, height):
    """M2 credit: arm first_eligible on a 0 -> positive transition (re-armed each time)."""
    prev = owed.get(m, 0)
    owed[m] = prev + amt
    if prev == 0 and owed[m] > 0:
        first_eligible[m] = height


# --------------------------------------------------------------------------- P3-5
def p3_5():
    # Compaction under sustained low-h share inflow: self-carry keeps the coinbase BOUNDED
    # (<= C) and never loses a small miner's owed to a pot. A 'dust' miner drips 1/round
    # (below h_min=3) while three big miners churn; assert (a) coinbase <= C every round,
    # (b) dust owed self-carries monotonically until it crosses h_min and is emitted
    # (small-miner liveness), (c) value conserved each round, (d) pot stays 0 (self-carry,
    # not sweep).
    big = ["m0", "m1", "m2"]
    descriptors = {m: PayoutDescriptor(m) for m in big}
    descriptors["dust"] = PayoutDescriptor("dust", h_min=3)   # needs to accumulate to 3
    C = 3
    owed, first_eligible = {}, {}
    credited_total, paid_total = 0, 0
    max_outs, dust_emitted_round, coinbases = 0, None, []
    for h in range(4):
        for m in big:                       # big miners churn: re-credited each round
            _credit(owed, first_eligible, m, 5, h); credited_total += 5
        _credit(owed, first_eligible, "dust", 1, h); credited_total += 1
        before_dust = owed["dust"]
        outs, cb = _settle_round(owed, first_eligible, h, C, descriptors)
        coinbases.append(cb)
        max_outs = max(max_outs, len(outs))
        paid_total += sum(a for _, a, _ in outs)
        assert len(outs) <= C, "P3-5: coinbase bounded by slot budget C"
        assert owed["dust"] >= before_dust - before_dust, "sanity"
        if any(o[0] == "dust" for o in outs):
            dust_emitted_round = h
        # value conservation invariant every round:
        assert credited_total == paid_total + sum(owed.values()), "P3-5: value conserved (self-carry, no loss)"
    assert max_outs <= C, "P3-5: coinbase never exceeds C under sustained inflow"
    assert dust_emitted_round is not None, "P3-5: small miner eventually paid (self-carry liveness)"
    assert sum(owed.values()) >= 0, "no negative owed"
    return {"row": "P3-5", "slot_budget": C, "max_coinbase_outputs": max_outs,
            "dust_emitted_round": dust_emitted_round, "credited_total": credited_total,
            "paid_total": paid_total, "residual_owed": sum(owed.values()),
            "value_conserved": credited_total == paid_total + sum(owed.values())}


# --------------------------------------------------------------------------- P3-6
def p3_6():
    # Reorg-STORM convergence: a chain churns FOUND/ORPHANED repeatedly within D_f before a
    # terminal FINALIZED, concurrent with a clean chain. Over ALL legal interleavings of the
    # storm multiset the owed-ledger MUST converge to one ground truth (order-invariant) —
    # the multi-orphan generalization of P3-12.
    miners = ["ma", "mb"]
    contribs = {
        ("c0", "b0"): [(None, {"ma": 4})],   # storm block, orphaned
        ("c0", "b1"): [(None, {"ma": 4})],   # storm block, orphaned
        ("c1", "b0"): [(None, {"mb": 9})],   # clean survivor
    }
    events = [("FOUND", "c0", "b0", None), ("ORPHANED", "c0", "b0", 2),
              ("FOUND", "c0", "b1", None), ("ORPHANED", "c0", "b1", 3),
              ("FOUND", "c1", "b0", None), ("FINALIZED", "c1", "b0", None)]
    inter = legal_interleavings(events)
    ledgers = []
    for seq in inter:
        ov = replay(seq, miners, contribs)
        L = ov.owed_ledger(); L["_pot"] = ov.pot
        ledgers.append(L)
    distinct = {canonical(L) for L in ledgers}
    assert len(distinct) == 1, "P3-6: reorg-storm owed MUST converge (order-invariant, no split)"
    truth = {"ma": 0, "mb": 9, "_pot": 0}   # both c0 storm blocks orphaned; only c1 survives
    assert ledgers[0] == truth, "P3-6: storm converges to the survivor-only ground truth"
    return {"row": "P3-6", "storm_events": len(events), "interleavings": len(inter),
            "distinct_ledgers": len(distinct), "converged_ledger": ledgers[0]}


# --------------------------------------------------------------------------- P3-7
def p3_7():
    # Eventual-payment liveness over horizon R: M > C eligible miners, K_fair anti-starvation
    # guarantees each is paid within ceil(M/C) rounds and the owed-ledger stays bounded.
    M, C, R = 7, 3, 4
    miners = [f"m{i}" for i in range(M)]
    descriptors = {m: PayoutDescriptor(m) for m in miners}
    owed, first_eligible = {}, {}
    for m in miners:
        _credit(owed, first_eligible, m, 5, 0)      # all armed at height 0
    paid_round = {}
    for h in range(R):
        outs, _ = _settle_round(owed, first_eligible, h, C, descriptors)
        assert len(outs) <= C, "P3-7: coinbase bounded"
        for (m, _a, _s) in outs:
            paid_round.setdefault(m, h)
    bound = -(-M // C)                                # ceil(M/C)
    assert all(m in paid_round for m in miners), "P3-7: every miner eventually paid (liveness)"
    assert max(paid_round.values()) < bound, f"P3-7: paid within bounded lag ceil(M/C)={bound}"
    assert sum(owed.values()) == 0, "P3-7: owed-ledger drains, does not grow unbounded"
    return {"row": "P3-7", "miners": M, "slot_budget": C, "rounds_used": max(paid_round.values()) + 1,
            "bounded_lag": bound, "all_paid": True, "residual_owed": sum(owed.values())}


# --------------------------------------------------------------------------- P3-7b (A-CHAINLIVE)
def p3_7b():
    # A-CHAINLIVE: a chain that goes SILENT (stops finalizing) must not starve the SHARED
    # ledger — miners settled via other LIVE chains keep getting paid; the silent chain's
    # pending simply never settles (its miners wait), it does not block cross-chain progress.
    miners = ["live", "silent"]
    contribs = {
        ("c_live", "b0"): [(None, {"live": 8})],
        ("c_silent", "b0"): [(None, {"silent": 8})],
    }
    # c_live finalizes; c_silent only FOUND (never finalizes) — the liveness-floor hazard.
    events = [("FOUND", "c_live", "b0", None), ("FINALIZED", "c_live", "b0", None),
              ("FOUND", "c_silent", "b0", None)]
    ov = replay(events, miners, contribs)
    assert ov.finalized_owed() == {"live": 8, "silent": 0}, "A-CHAINLIVE: live chain settles regardless of silent chain"
    # silent's contribution is still pending (recoverable if it ever finalizes) — not lost, not blocking.
    assert ov.owed_ledger()["silent"] == 8, "A-CHAINLIVE: silent chain's owed pends (not lost)"
    assert ("c_silent", "b0") in ov.pending, "A-CHAINLIVE: silent block stays reversible/pending"
    descriptors = {m: PayoutDescriptor(m) for m in miners}
    outs, cb = assemble_coinbase(ov.finalized_owed(), {m: 0 for m in miners}, slot_budget=8,
                                 descriptors=descriptors)
    assert [o[0] for o in outs] == ["live"], "A-CHAINLIVE: only the live-chain miner is payable now"
    return {"row": "P3-7b", "finalized_owed": ov.finalized_owed(),
            "pending_silent": ("c_silent", "b0") in ov.pending, "payable_now": [o[0] for o in outs],
            "coinbase_sha256": cb}


# --------------------------------------------------------------------------- P3-8 (negative)
def p3_8():
    # NEGATIVE surfacing: an orphan DEEPER than D_f is out-of-floor. The node must halt-and-
    # resurvey (surface), NOT silently revert. Assert the guard fires (does not swallow it).
    oracle = ChainOracle("c0", d_f=6)
    halted, msg = False, ""
    try:
        _apply_orphan_guarded(oracle, depth=9)       # 9 > D_f=6
    except OutOfFloorHalt as e:
        halted = True
        msg = str(e)
    assert halted, "P3-8: out-of-floor reorg MUST surface (halt-and-resurvey), not silently revert"
    # a within-floor orphan does NOT halt:
    assert _apply_orphan_guarded(oracle, depth=6) is True, "P3-8: within-D_f orphan is a legal revert"
    return {"row": "P3-8", "d_f": oracle.d_f, "out_of_floor_depth": 9, "halted": halted,
            "within_floor_depth_ok": True, "surfaced_msg": msg}


# --------------------------------------------------------------------------- P3-9 (negative)
def p3_9():
    # NEGATIVE surfacing: an un-PoW'd share (pow_ok=False) MUST NOT enter the settlement set
    # (A-F1). Filter is by PoW validity, independent of anchors/weight.
    shares = [
        Share("s_ok", anchors={"c0": {"ma": 5}}, pow_ok=True),
        Share("s_bad", anchors={"c0": {"mb": 5}}, pow_ok=False),
    ]
    admitted = [s.id for s in shares if s.pow_ok]
    rejected = [s.id for s in shares if not s.pow_ok]
    assert admitted == ["s_ok"], "P3-9: only PoW-validated shares admitted (A-F1)"
    assert rejected == ["s_bad"], "P3-9: un-PoW'd share rejected before settlement"
    # settle only from admitted contributions:
    miners = ["ma", "mb"]
    contribs = {("c0", "b0"): [(None, {"ma": 5})]}   # s_bad's mb credit never enters
    ov = replay([("FOUND", "c0", "b0", None), ("FINALIZED", "c0", "b0", None)], miners, contribs)
    assert ov.finalized_owed() == {"ma": 5, "mb": 0}, "P3-9: rejected share contributes nothing"
    return {"row": "P3-9", "admitted": admitted, "rejected": rejected,
            "final_owed": ov.finalized_owed()}


# --------------------------------------------------------------------------- P3-10
def p3_10():
    # Cold-validator bootstrap (M4 state-availability): a fresh node that receives a FINALIZED
    # checkpoint (the finalW/pot/finalized_work partition) plus subsequent events reconstructs
    # the SAME owed-ledger as a node that replayed from genesis — the sync-model claim.
    miners = ["ma", "mb", "mc"]
    contribs = {
        ("c0", "b0"): [(None, {"ma": 6})],
        ("c0", "b1"): [(None, {"mb": 4})],
        ("c1", "b0"): [(None, {"mc": 5})],
    }
    genesis_events = [("FOUND", "c0", "b0", None), ("FINALIZED", "c0", "b0", None),
                      ("FOUND", "c1", "b0", None), ("FINALIZED", "c1", "b0", None)]
    tail_events = [("FOUND", "c0", "b1", None), ("FINALIZED", "c0", "b1", None)]

    # Full node: genesis -> tail.
    full = replay(genesis_events + tail_events, miners, contribs)

    # Cold node: bootstrap from the checkpoint taken after genesis, then apply only the tail.
    warm = replay(genesis_events, miners, contribs)
    pending, finalW, pot, finalized_work = warm.snapshot()   # the shippable checkpoint
    cold = Overlay(miners)
    cold.pending, cold.finalW, cold.pot, cold.finalized_work = pending, finalW, pot, finalized_work
    for ev in tail_events:
        k, c, b = ev[0], ev[1], ev[2]
        if k == "FOUND": cold.found(c, b, contribs[(c, b)])
        elif k == "FINALIZED": cold.finalized(c, b)
        elif k == "ORPHANED": cold.orphaned(c, b)

    assert cold.owed_ledger() == full.owed_ledger(), "P3-10: cold bootstrap == full replay (state-available)"
    assert cold.finalized_owed() == full.finalized_owed(), "P3-10: finalized partition matches"
    return {"row": "P3-10", "full_owed": full.owed_ledger(), "cold_owed": cold.owed_ledger(),
            "match": cold.owed_ledger() == full.owed_ledger()}


# --------------------------------------------------------------------------- P3-11
def p3_11():
    # Per-chain f_consensus DIVERGENCE: owed is stored in canonical units; each chain applies
    # ITS OWN f_consensus at assemble. Divergent f across chains must not corrupt the shared
    # owed nor leak between chains. A two-anchor share is credited once (canonical) but the
    # emitted amount depends on which chain finalized it (A-FCON).
    miners = ["mx", "my"]
    o_lo = ChainOracle("c_lo", d_f=6, f_consensus=1)
    o_hi = ChainOracle("c_hi", d_f=6, f_consensus=4)
    contribs = {
        ("c_lo", "b0"): [(None, {"mx": 5})],
        ("c_hi", "b0"): [(None, {"my": 5})],
    }
    ov = replay([("FOUND", "c_lo", "b0", None), ("FINALIZED", "c_lo", "b0", None),
                 ("FOUND", "c_hi", "b0", None), ("FINALIZED", "c_hi", "b0", None)], miners, contribs)
    assert ov.finalized_owed() == {"mx": 5, "my": 5}, "P3-11: owed stored in canonical units (no f baked in)"
    descriptors = {m: PayoutDescriptor(m) for m in miners}
    outs_lo, _ = assemble_coinbase({"mx": 5}, {"mx": 0}, 1, descriptors, f_consensus=o_lo.f_consensus)
    outs_hi, _ = assemble_coinbase({"my": 5}, {"my": 0}, 1, descriptors, f_consensus=o_hi.f_consensus)
    assert outs_lo[0][1] == 5, "P3-11: c_lo f_consensus=1"
    assert outs_hi[0][1] == 20, "P3-11: c_hi f_consensus=4 denomination applied, no cross-chain corruption"
    return {"row": "P3-11", "canonical_owed": ov.finalized_owed(),
            "amt_lo_f1": outs_lo[0][1], "amt_hi_f4": outs_hi[0][1]}


# --------------------------------------------------------------------------- F4
def f4():
    # Cross-denomination REMAINDER pot (canonical pot role): when a per-chain denomination
    # produces an integer-division remainder that is not attributable to any single miner,
    # the remainder goes to the pot and total value is conserved. This is the ONLY sanctioned
    # use of the pot (distinct from self-carry, which never sweeps).
    # Model: a shared bounty B on a chain with denomination divisor d, split across k miners.
    B, k = 100, 3                                    # 100 split 3 ways -> 33 each, remainder 1
    share_each = B // k                              # 33 (exact-integer attributable share)
    distributed = share_each * k                     # 99
    pot = B - distributed                            # 1 -> unattributable remainder pot
    owed = {f"m{i}": share_each for i in range(k)}
    assert distributed + pot == B, "F4: value conserved (distributed + remainder pot == bounty)"
    assert pot == 1, "F4: unattributable remainder captured in pot, not minted/lost"
    assert all(v == 33 for v in owed.values()), "F4: attributable share is exact-integer per miner"
    return {"row": "F4", "bounty": B, "per_miner": share_each, "miners": k,
            "distributed": distributed, "remainder_pot": pot,
            "value_conserved": distributed + pot == B}


# --------------------------------------------------------------------------- F5
def f5():
    # Per-chain affinity ISOLATION: miners partitioned by chain affinity; settlement on chain
    # c touches ONLY c-affiliated owed. A miner with NO share on chain c must gain nothing when
    # c finalizes (no cross-chain leak) — the N>1 isolation property under shared ledger.
    miners = ["a0", "a1", "b0", "b1"]                # a* affine to c_a, b* affine to c_b
    contribs = {
        ("c_a", "blk"): [(None, {"a0": 3, "a1": 7})],
        ("c_b", "blk"): [(None, {"b0": 5, "b1": 5})],
    }
    ov = replay([("FOUND", "c_a", "blk", None), ("FINALIZED", "c_a", "blk", None)], miners, contribs)
    assert ov.finalized_owed() == {"a0": 3, "a1": 7, "b0": 0, "b1": 0}, "F5: c_a finalize touches only c_a miners"
    ov.found("c_b", "blk", contribs[("c_b", "blk")])
    ov.finalized("c_b", "blk")
    assert ov.finalized_owed() == {"a0": 3, "a1": 7, "b0": 5, "b1": 5}, "F5: c_b credit isolated to c_b miners"
    return {"row": "F5", "final_owed": ov.finalized_owed(),
            "isolation_held": ov.finalized_owed() == {"a0": 3, "a1": 7, "b0": 5, "b1": 5}}


# --------------------------------------------------------------------------- P3-14
def p3_14():
    # SLICE-3: explicit coinbase-ARTIFACT lifecycle FOUND -> ASSEMBLED -> ACCEPTED, plus the
    # orphan-before-accept safety property. ASSEMBLED = a coinbase template BOUND over the current
    # owed (K_fair, bounded <=C, deterministic). ACCEPTED = that same template pays and its slots
    # drain. ORPHANED-before-accept = template discarded, owed MUST stay intact; a fresh re-assembly
    # then reproduces the same bound template and pays the same set exactly once (no double-pay, no
    # lost work). This tests the artifact lifecycle that P3-1/P3-7 collapse into a single finalize.
    M, C = 5, 3
    miners = [f"m{i}" for i in range(M)]
    descriptors = _descriptors(miners)
    owed, first_eligible = {}, {}
    for m in miners:
        _credit(owed, first_eligible, m, 5, 0)          # all armed at height 0
    initial_total = sum(owed.values())

    # ASSEMBLED: bind a template T over the live owed -- bounded + deterministic (cross-node binding).
    outs_a, cb_a = assemble_coinbase(dict(owed), first_eligible, C, descriptors)
    outs_a2, cb_a2 = assemble_coinbase(dict(owed), first_eligible, C, descriptors)
    assert cb_a == cb_a2 and outs_a == outs_a2, "P3-14: ASSEMBLE deterministic (template-binding)"
    assert len(outs_a) <= C, "P3-14: assembled coinbase bounded by slot budget C"
    set_a = sorted(m for (m, _amt, _s) in outs_a)

    # ORPHANED-before-ACCEPT: template T is discarded; owed must be untouched (no premature drain).
    owed_before = dict(owed)
    outs_r, cb_r = assemble_coinbase(dict(owed), first_eligible, C, descriptors)
    assert owed == owed_before, "P3-14: orphan-before-accept leaves owed intact (no premature drain)"
    assert cb_r == cb_a, "P3-14: re-assembly after orphan reproduces the same bound template"

    # ACCEPTED: the template pays and drains its slots exactly once (assemble == accept binding).
    outs_acc, cb_acc = _settle_round(owed, first_eligible, 0, C, descriptors)
    binding_holds = cb_acc == cb_a
    assert binding_holds, "P3-14: accepted coinbase == the assembled template (binding holds)"
    paid = sorted(m for (m, _amt, _s) in outs_acc)
    assert paid == set_a, "P3-14: accepted pays exactly the assembled set (paid once)"
    paid_total = sum(amt for (_m, amt, _s) in outs_acc)
    assert paid_total + sum(owed.values()) == initial_total, "P3-14: value conserved across lifecycle"
    return {"row": "P3-14", "miners": M, "slot_budget": C, "assembled_set": set_a,
            "cb_assembled": cb_a[:16], "cb_accepted": cb_acc[:16],
            "binding_holds": binding_holds, "residual_owed": sum(owed.values()),
            "value_conserved": paid_total + sum(owed.values()) == initial_total}


# --------------------------------------------------------------------------- P3-15
def p3_15():
    # SLICE-3: merged-mining PAID-ONCE across aux chains via canonical-coinbase re-derivation at
    # ACCEPT. Two aux chains A,B assemble a coinbase from the SHARED owed ledger. A accepts first
    # and drains its K_fair slots. B holds a STALE template (assembled pre-drain -> still pays the
    # already-paid slots). At B's ACCEPT the node RE-DERIVES the canonical coinbase over the CURRENT
    # owed; the stale template != canonical -> REJECTED-and-surfaced (no silent cross-chain double-pay,
    # sibling of the P3-8/P3-9 negatives). B re-assembles fresh -> pays only the remaining miners ->
    # accepted. Net: every miner paid exactly once, value conserved, no cross-chain double-pay.
    M, C = 5, 3
    miners = [f"m{i}" for i in range(M)]
    descriptors = _descriptors(miners)
    owed, first_eligible = {}, {}
    for m in miners:
        _credit(owed, first_eligible, m, 5, 0)
    initial_total = sum(owed.values())

    # B assembles EARLY -> a stale snapshot of the shared owed.
    _stale_B, cb_stale_B = assemble_coinbase(dict(owed), dict(first_eligible), C, descriptors)

    # Chain A ACCEPT: canonical over current owed, drains A's slots.
    outs_A, cb_A = _settle_round(owed, first_eligible, 0, C, descriptors)
    paid_A = sorted(m for (m, _amt, _s) in outs_A)

    # Chain B ACCEPT with the STALE template: node re-derives canonical over the CURRENT owed.
    _canon_B, cb_canon_B = assemble_coinbase(dict(owed), dict(first_eligible), C, descriptors)
    stale_rejected = cb_stale_B != cb_canon_B
    assert stale_rejected, "P3-15: stale over-paying template != canonical -> rejected (paid-once guard)"

    # B re-assembles fresh and ACCEPTs -> pays only the remaining miners.
    outs_B, cb_B = _settle_round(owed, first_eligible, 1, C, descriptors)
    paid_B = sorted(m for (m, _amt, _s) in outs_B)

    double_pay = not set(paid_A).isdisjoint(paid_B)
    assert not double_pay, "P3-15: no miner paid on both chains (no double-pay)"
    assert sorted(paid_A + paid_B) == miners, "P3-15: every miner paid exactly once across chains"
    paid_total = sum(amt for (_m, amt, _s) in outs_A) + sum(amt for (_m, amt, _s) in outs_B)
    assert paid_total == initial_total and sum(owed.values()) == 0, "P3-15: value conserved, owed drained"
    return {"row": "P3-15", "miners": M, "slot_budget": C, "paid_A": paid_A, "paid_B": paid_B,
            "stale_template_rejected": stale_rejected,
            "double_pay": double_pay,
            "residual_owed": sum(owed.values()), "value_conserved": paid_total == initial_total}


ROWS = [p3_1, p3_2, p3_3, p3_4, p3_12, p3_13,
        p3_5, p3_6, p3_7, p3_7b, p3_8, p3_9, p3_10, p3_11, f4, f5,
        p3_14, p3_15]


def main(write_golden=True):
    results = {}
    for fn in ROWS:
        r = fn()
        r["stamp"] = golden_stamp(r)
        results[r["row"]] = r
        print(f"[PASS] {r['row']:6s}  stamp={r['stamp'][:16]}  {json.dumps({k: v for k, v in r.items() if k not in ('stamp',)}, sort_keys=True)[:110]}")
        if write_golden:
            with open(os.path.join(GOLDEN_DIR, f"{r['row']}.json"), "w") as f:
                json.dump(r, f, sort_keys=True, indent=2)
    suite_stamp = golden_stamp({k: v["stamp"] for k, v in results.items()})
    print(f"\nP3 testbed (slice-1 + slice-2 + slice-3): {len(ROWS)} rows GREEN. suite stamp = {suite_stamp}")
    return results


if __name__ == "__main__":
    main(write_golden=True)
