#!/usr/bin/env python3
"""
V37 P5 integration — REFERENCE STUB ADAPTERS.

Each stub mirrors the *public contract* of its held-GREEN slice — no more. They are the
"contract mirror": enough real behaviour to exercise the P5 cross-layer invariants
(value conservation end-to-end, paid-once across anchors, sync-proof gating, receipt TTL,
atomic cross), but NOT a reimplementation of the slice internals.

At merge-cp, replace a stub with a thin real adapter forwarding to the merged slice module,
e.g. SettlementAdapter -> proto/p3-testbed/harness/engine.py. The scenarios/invariants stay put.
Any stub whose behaviour DIVERGES from its real slice is a P5 bug, caught when the real adapter
is swapped in and the same golden must still reproduce.
"""
from ports import (SyncPort, SettlementPort, MessagingPort, MarketPort, VenuePort, h)


# --------------------------------------------------------------------------- #
# SyncPort stub — mirrors m4-sync utreexo bootstrap + proof gen/verify (T1/T2).
# Committed root = accumulator over the share set; proof binds a share to that root.
# The cold-start fence is modelled: verify() trusts the committed_root as given (external
# anchor). A wrong root is out of P5 scope — that is the weak-subjectivity assumption.
# --------------------------------------------------------------------------- #
class SyncStub(SyncPort):
    def __init__(self):
        self._members = {}   # committed_root -> set(share_id)

    def bootstrap(self, n_shares):
        ids = [h("share", i) for i in range(n_shares)]
        root = h("root", *ids)
        self._members[root] = set(ids)
        return root

    def prove(self, share_id):
        # opaque inclusion proof; stub binds proof to the id it proves
        return h("proof", share_id)

    def verify(self, committed_root, share_id, proof):
        return (proof == h("proof", share_id)
                and committed_root in self._members
                and share_id in self._members[committed_root])


# --------------------------------------------------------------------------- #
# SettlementPort stub — mirrors p3-testbed KEYED_CRDT overlay + M2 K_fair coinbase.
# Owed is a pure function of the FINALIZED event multiset (order-invariant), paid-once
# per (chain,block,miner) even across two-anchor + revert, and coinbase is bounded and
# value-conserving. This is the consensus-bearing contract; the stub preserves its shape.
# --------------------------------------------------------------------------- #
class SettlementStub(SettlementPort):
    def __init__(self, k_slots=8):
        self._k = k_slots
        self._pending = {}     # (chain, block) -> {miner: credit}
        self._finalized = {}   # (chain, block) -> {miner: credit}
        self._reverted = set() # (chain, block)

    def apply_events(self, events):
        for ev in events:
            key = (ev["chain"], ev["block"])
            if ev["type"] == "FOUND":
                self._pending.setdefault(key, {})
                for miner, credit in ev["credits"].items():
                    self._pending[key][miner] = self._pending[key].get(miner, 0) + credit
            elif ev["type"] == "FINALIZED":
                if key in self._pending and key not in self._reverted:
                    self._finalized[key] = dict(self._pending[key])   # dedup: FINALIZED set is the key
            elif ev["type"] == "ORPHANED":
                self._reverted.add(key)
                self._pending.pop(key, None)
                self._finalized.pop(key, None)

    def owed(self):
        agg = {}
        for credits in self._finalized.values():
            for miner, c in credits.items():
                agg[miner] = agg.get(miner, 0) + c
        return agg

    def coinbase(self, block_value):
        owed = self.owed()
        if not owed:
            return []
        # K_fair: (first_eligible ASC == miner_id ASC here) top-K slots; remainder pot folds
        # sub-threshold tail back so the payout set is value-conserving and bounded by K.
        ranked = sorted(owed.items(), key=lambda kv: (kv[0],))
        total = sum(owed.values())
        out = []
        for miner, c in ranked[: self._k]:
            out.append((miner, c * block_value // total))
        # remainder pot -> first slot so sum == block_value exactly (bounded, conserved)
        paid = sum(a for _, a in out)
        if out and paid < block_value:
            out[0] = (out[0][0], out[0][1] + (block_value - paid))
        return out


# --------------------------------------------------------------------------- #
# MessagingPort stub — mirrors p4-messaging perishable receipt (TTL-gated).
# --------------------------------------------------------------------------- #
class MessagingStub(MessagingPort):
    def mint(self, miner, epoch, ttl):
        return {"miner": miner, "epoch": epoch, "ttl": ttl,
                "sig": h("receipt", miner, epoch, ttl)}

    def valid(self, receipt, now_epoch):
        if receipt["sig"] != h("receipt", receipt["miner"], receipt["epoch"], receipt["ttl"]):
            return False
        return receipt["epoch"] <= now_epoch < receipt["epoch"] + receipt["ttl"]


# --------------------------------------------------------------------------- #
# MarketPort stub — mirrors p4-market spot delivery contract (SPOT ONLY).
# --------------------------------------------------------------------------- #
class _Settlement:
    __slots__ = ("filled", "paid")

    def __init__(self, filled, paid):
        self.filled = filled
        self.paid = paid


class MarketStub(MarketPort):
    def __init__(self):
        self._c = {}   # id -> dict

    def open_contract(self, buyer, seller, shares):
        cid = h("contract", buyer, seller, shares)
        self._c[cid] = {"buyer": buyer, "seller": seller, "want": shares, "got": 0}
        return cid

    def deliver(self, cid, shares):
        self._c[cid]["got"] += shares

    def settle(self, cid):
        c = self._c[cid]
        filled = c["got"] >= c["want"]
        return _Settlement(filled=filled, paid=(c["want"] if filled else 0))


# --------------------------------------------------------------------------- #
# VenuePort stub — mirrors p4-dex atomic two-sided cross (both settle or neither).
# --------------------------------------------------------------------------- #
class _MatchSettlement:
    __slots__ = ("atomic", "a_paid", "b_paid")

    def __init__(self, atomic, a_paid, b_paid):
        self.atomic = atomic
        self.a_paid = a_paid
        self.b_paid = b_paid


class VenueStub(VenuePort):
    def cross(self, leg_a, leg_b, head):
        # both legs final at/below head -> atomic settle; else neither leg pays.
        both_final = leg_a["final_at"] <= head and leg_b["final_at"] <= head
        if both_final:
            return _MatchSettlement(atomic=True, a_paid=leg_a["amount"], b_paid=leg_b["amount"])
        return _MatchSettlement(atomic=False, a_paid=0, b_paid=0)


def default_registry():
    """Bind all five ports to their reference stubs. Merge-cp swaps individual bindings."""
    from ports import SliceRegistry
    return (SliceRegistry()
            .register("sync", SyncStub())
            .register("settlement", SettlementStub())
            .register("messaging", MessagingStub())
            .register("market", MarketStub())
            .register("venue", VenueStub()))
