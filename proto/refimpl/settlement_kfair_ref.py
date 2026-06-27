#!/usr/bin/env python3
"""
V37 Phase-1 owed-ledger + finality-gated overlay + K_fair payout selection — SLOW
REFERENCE (golden-vector source).

Scope (M2, F1 slice): the deterministic coinbase payout SELECTION when the per-block
output budget C (compaction slot bound, small-miner-equity.md) is smaller than the set of
eligible owed miners. F1 (RATIFIED 2026-06-27) pins the K_fair sort-key to:

    K_fair = (first_eligible_height ASC, miner_id ASC)      [owed-height-first]

"first_eligible_height[m]" is the mainchain height at which miner m's owed balance LAST
transitioned 0 -> positive (re-armed each time owed returns to 0 and becomes positive
again). It is a function of PoW-committed finalized state only — no node-local estimate —
so it is determinism-safe (the integrator's ratification rationale).

This sits ON TOP of the Settlement.tla finality-gated owed/overlay state machine:
  - credit lands in `owed` only when its block finalizes (>= FINALITY_DEPTH confs)
  - a payout reduces `owed` only when ITS block finalizes
  - until finalized, a chosen payout lives in the pending-payout overlay and the next
    coinbase is built against EffectiveOwed(m) = owed[m] - overlay_owed(m)
The selection here decides WHICH eligible miners fill the C payout slots each block; the
finality gate (modeled + model-checked in Settlement.tla) decides WHEN those mutations
become irreversible. The two are orthogonal and composed in the generator.
"""

# --------------------------------------------------------------------------- #
# Eligibility / selection — the F1 owed-height-first K_fair order.
# --------------------------------------------------------------------------- #

def kfair_key(miner_id, first_eligible_height):
    """The ratified K_fair sort-key: ascending owed-height, then ascending miner id.
    Returned as a tuple so Python's stable sort realizes the total order directly."""
    return (first_eligible_height, miner_id)


def select_payouts(owed, first_eligible, slot_budget):
    """Deterministically pick which owed miners fill this block's payout slots.

    owed            : dict miner_id -> owed amount (> 0 means eligible)
    first_eligible  : dict miner_id -> height owed last went 0 -> positive
    slot_budget     : C, max payout outputs this coinbase may carry

    Returns the selected miner ids in PAYOUT ORDER (the same K_fair order — the order is
    itself consensus-relevant: it fixes output ordering for the F2 full-output-set /
    soft-fork-offset commitment location). Anti-starvation by construction: the oldest
    owed entries are paid first; a younger entry can never jump an older unpaid one.
    """
    eligible = [m for m in owed if owed[m] > 0]
    eligible.sort(key=lambda m: kfair_key(m, first_eligible[m]))
    return eligible[:slot_budget]


class OwedLedger:
    """Finalized owed ledger with first_eligible_height tracking (no overlay here — the
    overlay/finality gate is driven by the generator per Settlement.tla)."""

    def __init__(self):
        self.owed = {}              # miner -> finalized owed amount
        self.first_eligible = {}    # miner -> height owed last became positive

    def credit(self, miner, amount, height):
        """Apply a finalized credit; arm first_eligible on a 0 -> positive transition."""
        prev = self.owed.get(miner, 0)
        self.owed[miner] = prev + amount
        if prev == 0 and self.owed[miner] > 0:
            self.first_eligible[miner] = height

    def pay(self, miner, amount):
        """Apply a finalized payout; disarm first_eligible when owed returns to 0."""
        assert amount <= self.owed.get(miner, 0), "K_fair never over-pays an owed entry"
        self.owed[miner] -= amount
        if self.owed[miner] == 0:
            self.first_eligible.pop(miner, None)

    def eligible_count(self):
        return sum(1 for m in self.owed if self.owed[m] > 0)


# --------------------------------------------------------------------------- #
# Property checkers used by the golden generator.
# --------------------------------------------------------------------------- #

def check_owed_height_first(owed, first_eligible, selected, slot_budget):
    """F1 anti-starvation invariant: no eligible miner with an EARLIER (first_eligible,
    id) key is left unselected while a younger one is selected OR a slot went unused.

    Returns True iff `selected` is exactly the prefix of the K_fair total order, i.e. the
    selection admits no fairness inversion. This is the property F1 makes machine-checkable.
    """
    eligible = sorted((m for m in owed if owed[m] > 0),
                      key=lambda m: kfair_key(m, first_eligible[m]))
    expected = eligible[:slot_budget]
    if selected != expected:
        return False
    # explicit inversion scan: every selected key precedes every UNSELECTED eligible key.
    sel_set = set(selected)
    unsel = [m for m in eligible if m not in sel_set]
    if unsel and len(selected) < slot_budget:
        return False                                   # slot free but an eligible left out
    for s in selected:
        for u in unsel:
            if kfair_key(u, first_eligible[u]) < kfair_key(s, first_eligible[s]):
                return False                           # older-owed jumped by a younger pick
    return True
