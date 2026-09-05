#!/usr/bin/env python3
"""
V37 P5 integration — the V37Node composition + CROSS-LAYER invariants.

V37Node wires the five ports into one lifecycle: bootstrap (sync) -> settle (multichain) ->
message (perishable receipt) -> market (spot hashrate) -> venue (atomic cross). The value of
P5 is the CROSS-LAYER invariants — properties that no single slice can assert alone because
they span the seams between slices:

  X1  sync-gated settlement: a share only enters settlement if its inclusion proof verifies
      against the externally-committed root (M4 fence honoured at the seam).
  X2  end-to-end value conservation: coinbase pays out exactly the block value across ALL
      finalized chains; no value created or destroyed between the settlement and payout seams.
  X3  paid-once across the venue seam: a miner's owed credit that is also crossed on the venue
      is not double-counted — settlement owed and venue payout are disjoint ledgers.
  X4  receipt liveness gating: a market delivery is only creditable while the seller's standing
      receipt is live (TTL), coupling P4-messaging to P4-market at the seam.
  X5  atomic-cross isolation: a failed (non-atomic) venue cross leaves settlement owed untouched.
"""


class InvariantError(AssertionError):
    pass


class V37Node:
    def __init__(self, registry):
        self.r = registry
        self.sync = registry.get("sync")
        self.settlement = registry.get("settlement")
        self.messaging = registry.get("messaging")
        self.market = registry.get("market")
        self.venue = registry.get("venue")
        self.committed_root = None

    # ---- lifecycle ------------------------------------------------------- #
    def bootstrap(self, n_shares):
        self.committed_root = self.sync.bootstrap(n_shares)
        return self.committed_root

    def admit_share(self, share_id):
        """X1: gate settlement admission on a verifying inclusion proof."""
        proof = self.sync.prove(share_id)
        ok = self.sync.verify(self.committed_root, share_id, proof)
        if not ok:
            raise InvariantError(f"X1 violated: share {share_id[:8]} admitted without valid proof")
        return True

    def settle(self, events):
        self.settlement.apply_events(events)
        return self.settlement.owed()

    def pay(self, block_value):
        out = self.settlement.coinbase(block_value)
        # X2: value conservation across the settlement->payout seam.
        paid = sum(a for _, a in out)
        if out and paid != block_value:
            raise InvariantError(f"X2 violated: coinbase paid {paid} != block_value {block_value}")
        return out

    # ---- cross-layer checks ---------------------------------------------- #
    def market_credit(self, cid, delivered, seller_receipt, now_epoch):
        """X4: only credit a delivery while the seller's standing receipt is live."""
        if not self.messaging.valid(seller_receipt, now_epoch):
            return False   # receipt expired -> delivery not creditable this epoch
        self.market.deliver(cid, delivered)
        return self.market.settle(cid).filled

    def venue_cross(self, leg_a, leg_b, head, owed_before):
        """X3 + X5: atomic cross does not perturb settlement owed; a failed cross is a no-op."""
        ms = self.venue.cross(leg_a, leg_b, head)
        owed_after = self.settlement.owed()
        if owed_after != owed_before:
            raise InvariantError("X3/X5 violated: venue cross mutated settlement owed ledger")
        return ms
