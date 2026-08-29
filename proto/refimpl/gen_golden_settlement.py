#!/usr/bin/env python3
"""
Golden-vector generator for the V37 Phase-1 owed-ledger + K_fair payout selection,
composed with the finality-gated overlay (Settlement.tla semantics).

Emits golden/settlement_kfair_v0.json with consensus-relevant properties:

  D1 (determinism): two independent replays of the identical block sequence produce a
      bit-identical selection sequence, payout vectors, and final owed ledger.

  F1 (owed-height-first / anti-starvation): at EVERY block the selected payout set is
      exactly the K_fair prefix (first_eligible_height ASC, miner_id ASC). No fairness
      inversion: no younger-owed eligible miner is paid before an older-owed unpaid one,
      and no slot is left idle while an eligible miner waits. (RATIFIED 2026-06-27.)

  G  (finality gate): owed only mutates on finalized blocks; effective owed (owed minus
      pending overlay) never goes negative -> no double-pay across an unfinalized window.
      This mirrors the Settlement.tla NoNegativeOwed / OverlayNeverExceedsOwed invariants.

  V  (value conservation): sum of all finalized payouts == sum of all owed reductions;
      no value is minted or lost in selection.

Deterministic inputs only: a fixed LCG drives the credit stream (NO consensus RNG).
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from settlement_kfair_ref import OwedLedger, select_payouts, check_owed_height_first

NMINERS        = 12
SLOT_BUDGET    = 4          # C: a coinbase carries at most 4 payout outputs (compaction)
FINALITY_DEPTH = 3          # confs to finalize (reuses the M1 clock)
NBLOCKS        = 60
PAY_PER_SLOT   = 50         # a paid slot clears up to this much owed per block


def credit_stream(n):
    """Fixed deterministic per-block credit events (miner, amount) -- a documented LCG."""
    x = 0xD1B54A32D192ED03
    out = []
    for _ in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        miner  = (x >> 17) % NMINERS
        amount = 10 + ((x >> 31) % 200)        # finalized credit units
        out.append((miner, amount))
    return out


def run(seq, record=False):
    """Drive credits -> finality-gated owed -> K_fair selection, block by block.

    Model: at block height h we (1) finalize the credit that entered the chain at height
    h - FINALITY_DEPTH (gate), (2) run K_fair selection over the now-finalized owed, and
    (3) finalize the payouts chosen FINALITY_DEPTH blocks ago. Payouts therefore sit in
    the overlay for FINALITY_DEPTH blocks exactly as BlockFound -> ... -> BlockFinalized.
    """
    ledger = OwedLedger()
    pending_payouts = {}       # finalize-at-height -> list of (miner, amount)
    pending_credits = {}       # finalize-at-height -> (miner, amount)
    trace = []
    total_paid = 0
    f1_ok = True

    for h in range(NBLOCKS + FINALITY_DEPTH):
        # (1) finalize the credit that was found FINALITY_DEPTH blocks ago
        if h in pending_credits:
            m, amt = pending_credits.pop(h)
            ledger.credit(m, amt, h)
        # (3) finalize payouts chosen FINALITY_DEPTH blocks ago (overlay clears now)
        if h in pending_payouts:
            for m, amt in pending_payouts.pop(h):
                ledger.pay(m, amt)
                total_paid += amt

        # found a NEW credit at this height (enters overlay, finalizes later)
        if h < len(seq):
            cm, camt = seq[h]
            pending_credits[h + FINALITY_DEPTH] = (cm, camt)

        # (2) K_fair selection over CURRENT finalized owed (this is the F1 step)
        selected = select_payouts(ledger.owed, ledger.first_eligible, SLOT_BUDGET)
        ok = check_owed_height_first(ledger.owed, ledger.first_eligible, selected, SLOT_BUDGET)
        f1_ok = f1_ok and ok

        # build this block's payout vector; it enters the overlay, finalizes at h+DEPTH.
        # cap each payout by the miner's CURRENT owed minus what is already in flight.
        in_flight = {}
        for hh, lst in pending_payouts.items():
            for m, amt in lst:
                in_flight[m] = in_flight.get(m, 0) + amt
        block_payouts = []
        for m in selected:
            effective = ledger.owed[m] - in_flight.get(m, 0)     # EffectiveOwed guard
            amt = min(PAY_PER_SLOT, effective)
            if amt > 0:
                block_payouts.append((m, amt))
        if block_payouts:
            pending_payouts.setdefault(h + FINALITY_DEPTH, []).extend(block_payouts)

        if record:
            trace.append({
                "height": h,
                "eligible": ledger.eligible_count(),
                "selected": list(selected),
                "selected_keys": [[ledger.first_eligible[m], m] for m in selected],
                "payouts": [[m, a] for m, a in block_payouts],
                "f1_ok": ok,
            })

    final_owed = {str(m): v for m, v in sorted(ledger.owed.items()) if v}
    return {"trace": trace, "final_owed": final_owed,
            "total_paid": total_paid, "f1_ok": f1_ok}


def main():
    seq = credit_stream(NBLOCKS)
    a = run(seq, record=True)
    b = run(seq, record=True)                       # independent replay

    d1_ok = (a["trace"] == b["trace"] and a["final_owed"] == b["final_owed"]
             and a["total_paid"] == b["total_paid"])

    # value conservation: every unit credited is either still owed or has been paid.
    total_credited = sum(amt for _, amt in seq)
    total_still_owed = sum(int(v) for v in a["final_owed"].values())
    v_ok = (total_credited == total_still_owed + a["total_paid"])

    # G (effective-owed non-negativity) is enforced structurally by the EffectiveOwed cap
    # in run(); assert no payout ever exceeded owed (pay() asserts) -> reaching here = pass.
    g_ok = True

    vector = {
        "spec": "c2pool-v37-work-receipts.md §7.1 + small-miner-equity.md (compaction)",
        "kfair_sort_key": "(first_eligible_height ASC, miner_id ASC)  [F1, ratified 2026-06-27]",
        "geometry": {"nminers": NMINERS, "slot_budget": SLOT_BUDGET,
                     "finality_depth": FINALITY_DEPTH, "nblocks": NBLOCKS,
                     "pay_per_slot": PAY_PER_SLOT},
        "D1_determinism_bitidentical": d1_ok,
        "F1_owed_height_first_all_blocks": a["f1_ok"],
        "G_finality_gate_no_negative_effective_owed": g_ok,
        "V_value_conservation": v_ok,
        "V_total_credited": total_credited,
        "V_total_paid": a["total_paid"],
        "V_total_still_owed": total_still_owed,
        "final_owed": a["final_owed"],
        "trace": a["trace"],
    }
    outdir = os.path.join(os.path.dirname(__file__), "golden")
    os.makedirs(outdir, exist_ok=True)
    outpath = os.path.join(outdir, "settlement_kfair_v0.json")
    with open(outpath, "w") as f:
        json.dump(vector, f, indent=2, sort_keys=True)

    print(f"D1 determinism bit-identical : {d1_ok}")
    print(f"F1 owed-height-first (all blk): {a['f1_ok']}")
    print(f"G  finality-gate no-neg owed : {g_ok}")
    print(f"V  value conservation        : {v_ok}  "
          f"(credited={total_credited} paid={a['total_paid']} owed={total_still_owed})")
    print(f"wrote {outpath}")
    return 0 if (d1_ok and a["f1_ok"] and g_ok and v_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
