#!/usr/bin/env python3
"""
V37 P3 multichain testbed — CORE ENGINE.

This is the thin orchestration substrate the P3 test matrix runs against. It adds NO new
consensus logic; it composes the already-verified pieces:

  - KEYED_CRDT finality-gated overlay  ... from proto/p3-overlay (P3-12 GREEN): the
    per-(chain,block)-keyed pending multiset + finalized-only compaction that makes the
    owed-ledger a pure function of the aux-chain event MULTISET (order-invariant).
  - K_fair payout selection            ... from proto/refimpl/settlement_kfair_ref.py:
    the ratified (first_eligible_height ASC, miner_id ASC) coinbase-slot selection.
  - N-chain mock oracle                ... deterministic FOUND/FINALIZED/ORPHANED emitter
    per aux chain (the M1 overlay-machine event source), each chain with independent
    D_f, cadence, f_consensus, MANDATED_OUTPUTS.
  - Adversarial-ordering enumerator    ... F6: enumerate the legal interleavings of the N
    oracle streams (per-(chain,block) causal order enforced) so scenarios can assert
    order-INVARIANCE, not just reproduce one schedule.

Design source: c2pool-v37-p3-multichain-testbed-design.md + FINDINGS-redteam-p3-multichain-Ngt1.md
Determinism: no wall-clock, no unseeded RNG. Every share id/seed derives from sha256(i).
"""
import copy
import hashlib
import json
from itertools import permutations

# --------------------------------------------------------------------------- #
# Carried-forward floor constants (Section 1 of the design; do not silently vary).
# --------------------------------------------------------------------------- #
H_MIN_DEFAULT = 1        # byte-denominated anti-sybil floor (M2); outputs below not emitted
TAU_DEFAULT = 3          # small-miner-equity dust threshold: finalized owed < TAU -> remainder pot


# --------------------------------------------------------------------------- #
# Share / anchors (Section 3.1).
# --------------------------------------------------------------------------- #
class PayoutDescriptor:
    """Encodes script type so the byte-denominated h_min floor + full-output-set constraint
    are testable (consensus-relevant per the deferred-fold note)."""
    __slots__ = ("miner", "script_type", "h_min")

    def __init__(self, miner, script_type="p2wpkh", h_min=H_MIN_DEFAULT):
        self.miner = miner
        self.script_type = script_type
        self.h_min = h_min


class Share:
    """A PoW-validated share (A-F1: only PoW-validated shares enter the settlement set).
    anchors maps aux-chain id -> {miner: weight} contribution for that chain's block."""
    __slots__ = ("id", "pow_ok", "anchors", "weight")

    def __init__(self, id, anchors, weight=1, pow_ok=True):
        self.id = id
        self.pow_ok = pow_ok
        self.anchors = anchors          # {chain_id: {miner: amount}}
        self.weight = weight


def share_seed(i):
    """M4 convention: deterministic per-index seed so golden vectors reproduce."""
    return hashlib.sha256(str(i).encode()).hexdigest()


# --------------------------------------------------------------------------- #
# ChainOracle (Section 3.2) — deterministic mock L1 emitting M1 overlay events.
# --------------------------------------------------------------------------- #
class ChainOracle:
    """A mock aux-chain (deterministic block oracle). Emits the three events the M1 overlay
    machine consumes. Independent D_f, cadence, f_consensus, MANDATED_OUTPUTS per chain."""

    def __init__(self, chain_id, d_f=6, cadence=1, f_consensus=1, mandated_outputs=None):
        self.chain_id = chain_id
        self.d_f = d_f                          # finality depth D_f^(c)
        self.cadence = cadence
        self.f_consensus = f_consensus          # aux-fee denomination (per-chain, A-FCON)
        self.mandated_outputs = tuple(mandated_outputs or ())

    def event(self, kind, block, depth=None):
        """Build one overlay event. A reorg injector asserts depth <= d_f (A-REORG);
        depth > d_f is an out-of-floor halt-and-resurvey, surfaced by the scenario, not here."""
        return (kind, self.chain_id, block, depth)


# --------------------------------------------------------------------------- #
# KEYED_CRDT finality-gated overlay (P3-12 fix) — the order-invariant settlement core.
# --------------------------------------------------------------------------- #
class Overlay:
    """One shared owed-ledger + finality-gated overlay fed by N aux chains.

    Representation (the P3-12 fix, verbatim semantics from proto/p3-overlay):
      - pending[(chain,block)] : reversible per-key contribution multiset (FOUND adds it)
      - finalW[miner]          : monotonic finalized partition (FINALIZE moves a key here)
      - pot                    : remainder pot; compaction sweeps ONLY the finalized partition
    Rendered owed-ledger L = finalW + sum(pending contributions). Because a pending
    contribution is NEVER compacted and ORPHAN is a pure key removal, L is a pure function
    of the event multiset -> order-invariant -> no cross-node owed divergence (F1 closed).

    Also tracks the revert-aware two-anchor dedup needed by A-2ANCHOR under A-REORG (F2):
    a share's work is 'paid' only against the FINALIZED partition, so an orphaned FOUND
    never counts as a payment.
    """

    def __init__(self, miners, tau=TAU_DEFAULT):
        self.miners = list(miners)
        self.tau = tau
        self.pending = {}                       # (chain,block) -> {miner: amount}
        self.finalW = {m: 0 for m in miners}    # finalized owed
        self.pot = 0                            # remainder pot (unattributed)
        # F2 dedup: which (share_id) work has already been FINALIZED-credited, and via which
        # (chain,block). Revert-aware because it is only written on FINALIZE and cleared on the
        # orphan of a still-pending key (a FOUND that never finalized is never in here).
        self.finalized_work = {}                # share_id -> (chain, block)

    # -- overlay transitions (M1 state machine) --------------------------------
    def found(self, chain, block, items):
        """BlockFound -> OverlayAdded. Register the reversible pending contribution.

        items : list of (work_id, {miner: amount}). work_id=None is a plain block credit
        (always settled on finalize). A non-None work_id is two-anchor dedup-tracked:
        A-2ANCHOR pays it once across the FINALIZED set (F2). Same share anchored to two
        chains supplies the SAME work_id on both, so exactly one finalize can credit it.
        """
        self.pending[(chain, block)] = {"items": [(wid, {m: c.get(m, 0) for m in self.miners})
                                                   for (wid, c) in items]}

    def finalized(self, chain, block):
        """BlockFinalized -> OwedSettled + OverlayCleared. Move key into finalized partition,
        then compact ONLY the finalized partition. Revert-aware two-anchor dedup: a work_id
        already in the finalized set is NOT credited again (A-2ANCHOR paid-once)."""
        entry = self.pending.pop((chain, block))
        for wid, contrib in entry["items"]:
            if wid is not None and wid in self.finalized_work:
                continue                        # already paid on the finalized set -> skip (F2)
            for m in self.miners:
                self.finalW[m] += contrib.get(m, 0)
            if wid is not None:
                self.finalized_work[wid] = (chain, block)
        self._compact_finalized_only()

    def orphaned(self, chain, block):
        """BlockOrphaned -> OverlayReverted. Pure keyed multiset removal (d <= D_f).
        A never-finalized FOUND leaves NO trace: no finalW mutation, no dedup entry."""
        self.pending.pop((chain, block), None)

    def _compact_finalized_only(self):
        """Small-miner-equity compaction restricted to the FINALIZED partition — the
        necessary+sufficient invariant. Pending contributions are never swept, so their
        revert stays well-defined and order-independent."""
        for m in self.miners:
            if 0 < self.finalW[m] < self.tau:
                self.pot += self.finalW[m]
                self.finalW[m] = 0

    # -- rendered views --------------------------------------------------------
    def owed_ledger(self):
        """L = finalized + pending (the value assemble() and cold-validators derive).

        Pending two-anchor work already settled on the finalized set is not double-counted:
        such a work_id is rendered once (via finalW), matching what a finalize would credit."""
        L = dict(self.finalW)
        for entry in self.pending.values():
            for wid, contrib in entry["items"]:
                if wid is not None and wid in self.finalized_work:
                    continue
                for m in self.miners:
                    L[m] = L.get(m, 0) + contrib.get(m, 0)
        return L

    def finalized_owed(self):
        """Only the finalized, settle-eligible partition (what a coinbase may actually pay)."""
        return dict(self.finalW)

    def is_work_paid(self, work_id):
        """F2 revert-aware 'paid once': paid iff its work sits in the FINALIZED set."""
        return work_id in self.finalized_work

    def snapshot(self):
        return copy.deepcopy((self.pending, self.finalW, self.pot, self.finalized_work))


# --------------------------------------------------------------------------- #
# K_fair coinbase assembly (Section 3.3) — composes the M2 ratified selection.
# --------------------------------------------------------------------------- #
def kfair_key(miner_id, first_eligible_height):
    return (first_eligible_height, miner_id)


def select_payouts(owed, first_eligible, slot_budget):
    """M2 ratified K_fair: (first_eligible_height ASC, miner_id ASC), prefix of length C."""
    eligible = [m for m in owed if owed[m] > 0]
    eligible.sort(key=lambda m: kfair_key(m, first_eligible[m]))
    return eligible[:slot_budget]


def assemble_coinbase(owed, first_eligible, slot_budget, descriptors,
                      mandated_outputs=(), f_consensus=1):
    """Deterministic coinbase over the FINALIZED owed-ledger.

    - selects payout slots by K_fair
    - emits an output only if amount >= that payout's h_min (byte-denominated floor)
    - honours MANDATED_OUTPUTS (A-2ANCHOR full-output-set constraint anchor)
    - applies per-chain f_consensus denomination (A-FCON)
    Returns (outputs, sha256). Identical inputs -> identical coinbase (cross-node agreement)."""
    selected = select_payouts(owed, first_eligible, slot_budget)
    outs = []
    for m in selected:
        h_min = descriptors[m].h_min if m in descriptors else H_MIN_DEFAULT
        amt = owed[m] * f_consensus
        if amt >= h_min:
            outs.append((m, amt, descriptors[m].script_type if m in descriptors else "p2wpkh"))
    for mo in mandated_outputs:
        outs.append(("MANDATED:" + str(mo[0]), mo[1], "mandated"))
    outs.sort()
    blob = json.dumps(outs, separators=(",", ":"), sort_keys=True).encode()
    return outs, hashlib.sha256(blob).hexdigest()


# --------------------------------------------------------------------------- #
# Adversarial-ordering enumerator (F6) — the engine behind P3-12/P3-13/P3-6.
# --------------------------------------------------------------------------- #
def legal_interleaving(seq):
    """Per-(chain,block) causal order: FOUND index precedes its FINALIZED/ORPHANED index."""
    pos = {}
    for i, ev in enumerate(seq):
        kind, chain, block = ev[0], ev[1], ev[2]
        pos.setdefault((chain, block), {})[kind] = i
    for (c, b), p in pos.items():
        if "FOUND" not in p:
            return False
        for term in ("ORPHANED", "FINALIZED"):
            if term in p and p["FOUND"] > p[term]:
                return False
    return True


def legal_interleavings(events):
    """All distinct legal permutations of an event list (small multisets only — this is a
    proof-of-invariance engine, not a runtime path)."""
    seen, out = set(), []
    for perm in permutations(events):
        if perm in seen:
            continue
        seen.add(perm)
        if legal_interleaving(perm):
            out.append(perm)
    return out


def replay(events, miners, contribs, tau=TAU_DEFAULT):
    """Drive one Overlay through an event sequence.

    events   : list of (KIND, chain, block[, depth])
    contribs : {(chain,block): [(work_id, {miner: amt}), ...]}
    Returns the finished Overlay.
    """
    ov = Overlay(miners, tau=tau)
    for ev in events:
        kind, chain, block = ev[0], ev[1], ev[2]
        if kind == "FOUND":
            ov.found(chain, block, contribs[(chain, block)])
        elif kind == "FINALIZED":
            ov.finalized(chain, block)
        elif kind == "ORPHANED":
            ov.orphaned(chain, block)
        else:
            raise ValueError("unknown event kind: %r" % (kind,))
    return ov


def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


def golden_stamp(obj):
    return hashlib.sha256(canonical(obj).encode()).hexdigest()
