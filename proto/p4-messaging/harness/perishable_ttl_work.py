#!/usr/bin/env python3
"""
V37 P4 slice-2 — TTL-as-decayed-work reference core.

Binds a perishable-receipt's TTL/standing to the ROUNDABOUT LANE decayed-weight
accumulator (the same MRR lane the payout side uses), rather than to a free-standing
counter. A message's carriage right is a function of the sender's decayed work:

    ttl_shares(dw) = clamp( floor(dw / TTL_WORK_UNIT), 0, TTL_SHARES_MAX )

Normative anchors (design docs, not on this bridge — modelled from README + the
canonical lane primitives that ARE local):
  - c2pool-v37-miner-messages.md sec.3.3  "TTL-as-decayed-work"
  - c2pool-v37-work-receipts.md            receipt primitive
  - decayed-weight source = c2pool-v37-mrr-roundabout-buffer.md Lane.decayed_payout

REQUIRES-NOT-BURNS (the defining slice-2 property): admitting a message GATES on the
sender having >= 1 ttl_share of live decayed work, but consumes NOTHING from the lane
accumulator. The lane keeps decaying on its own binary-exponential clock; carriage
right therefore PERISHES with the work, without an explicit spend/burn op (which would
need a separate double-spend ledger). Perishability is emergent from decay, not booked.

The lane table is the PINNED canonical decay-table base (M2/M3 consensus object,
golden/decay_table_canonical_v1.json), so slice-2's vectors sit on the same base as
the settlement golden — not a slice-local table.
"""
import json
import os
import sys

_REF = os.path.join(os.path.dirname(__file__), "..", "..", "refimpl")
sys.path.insert(0, _REF)
import mrr_ref  # noqa: E402  (Lane + mul_q62, consensus-precision accumulator)

# ---- slice-2 carriage parameters (prototype; fold to miner-messages sec.3.3 on doc land) ----
TTL_WORK_UNIT = 1 << 8          # decayed-weight per 1 ttl_share (integer, w-units)
TTL_SHARES_MAX = 3              # matches the ENVELOPE_MINER 3msg/window cap (slice-3 §7)


def load_canonical_tables():
    """Load the PINNED canonical InvD/decay (no rebuild — reads the golden cache)."""
    cache = os.path.join(_REF, "golden", "decay_table_canonical_v1.json")
    with open(cache) as fh:
        c = json.load(fh)
    # big ints are JSON-encoded as strings to survive round-trip; restore to int
    InvD = [int(x) for x in c["InvD"]]
    decay = [int(x) for x in c["decay"]]
    return InvD, decay


def ttl_shares(decayed_weight):
    """Carriage right derived from decayed work — floored, clamped to the window cap."""
    if decayed_weight < 0:
        raise ValueError("decayed_weight must be non-negative")
    s = decayed_weight // TTL_WORK_UNIT
    if s < 0:
        return 0
    if s > TTL_SHARES_MAX:
        return TTL_SHARES_MAX
    return s


class MessageLane:
    """
    A roundabout lane whose decayed weight also authorizes perishable messages.
    Wraps the canonical-based mrr_ref.Lane; adds the requires-not-burns admission gate.
    """

    def __init__(self):
        InvD, decay = load_canonical_tables()
        self.lane = mrr_ref.Lane(InvD, decay, epoch=mrr_ref.E)

    # -- work side (unchanged MRR semantics) --
    def do_work(self, miner, w):
        self.lane.push(miner, w)

    def decayed_weight(self, miner):
        return self.lane.decayed_payout(miner)

    def ttl_shares(self, miner):
        return ttl_shares(self.decayed_weight(miner))

    # -- message side (slice-2) --
    def admit(self, miner):
        """
        Try to carry one perishable message from `miner`.
        REQUIRES ttl_shares >= 1 of live decayed work; BURNS nothing.
        Returns (ok, reason, dw_before, dw_after). dw_before == dw_after always.
        """
        dw_before = self.decayed_weight(miner)
        if ttl_shares(dw_before) < 1:
            return (False, "insufficient-decayed-work", dw_before, dw_before)
        dw_after = self.decayed_weight(miner)  # gate did not mutate the accumulator
        return (True, "ok", dw_before, dw_after)
