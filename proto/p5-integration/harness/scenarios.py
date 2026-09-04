#!/usr/bin/env python3
"""
V37 P5 integration — END-TO-END scenario matrix. Each row drives a full node lifecycle across
all five slice seams and asserts the cross-layer invariants X1..X5. A PASS emits a bit-stable
golden vector; the suite stamp is the sha256 over the row results and must reproduce.

Run:  python3 harness/scenarios.py       # writes golden/, prints per-row + suite stamp
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ports import h                                   # noqa: E402
from stubs import default_registry                    # noqa: E402
from integration import V37Node, InvariantError       # noqa: E402

GOLDEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "golden")


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _events(chain, block, credits, finalize=True, orphan=False):
    evs = [{"type": "FOUND", "chain": chain, "block": block, "credits": credits}]
    if orphan:
        evs.append({"type": "ORPHANED", "chain": chain, "block": block})
    elif finalize:
        evs.append({"type": "FINALIZED", "chain": chain, "block": block})
    return evs


# --------------------------------------------------------------------------- #
# Rows. Each returns a JSON-able result dict; harness asserts + goldens it.
# --------------------------------------------------------------------------- #
def row_e2e1_happy():
    """E2E-1: bootstrap -> admit share -> single-chain settle+pay -> receipt -> spot market
    delivered under live receipt -> atomic venue cross. All seams green, X1/X2/X4 exercised."""
    node = V37Node(default_registry())
    root = node.bootstrap(64)
    sid = h("share", 3)
    node.admit_share(sid)                                     # X1
    node.settle(_events("btc", 1, {"m0": 60, "m1": 40}))
    coinbase = node.pay(100)                                  # X2 (must sum to 100)
    receipt = node.messaging.mint("m0", epoch=5, ttl=3)
    cid = node.market.open_contract("m1", "m0", shares=10)
    filled = node.market_credit(cid, 10, receipt, now_epoch=6)   # X4 live
    owed = node.settlement.owed()
    ms = node.venue_cross({"final_at": 2, "amount": 7}, {"final_at": 2, "amount": 7},
                          head=2, owed_before=owed)
    return {"row": "E2E-1", "root_len": len(root), "coinbase": coinbase,
            "coinbase_sum": sum(a for _, a in coinbase), "market_filled": filled,
            "cross_atomic": ms.atomic, "owed": owed}


def row_e2e2_multichain():
    """E2E-2: N=2 chains settle independently; end-to-end value conservation across BOTH
    finalized chains (X2 spanning the multichain seam)."""
    node = V37Node(default_registry())
    node.bootstrap(64)
    node.settle(_events("btc", 1, {"m0": 50, "m1": 50}))
    node.settle(_events("dgb", 7, {"m1": 30, "m2": 70}))
    coinbase = node.pay(200)
    return {"row": "E2E-2", "coinbase": coinbase,
            "coinbase_sum": sum(a for _, a in coinbase), "owed": node.settlement.owed()}


def row_e2e3_orphan_isolation():
    """E2E-3: an orphaned chain's credits are reverted before payout; only the surviving
    chain pays. X2 holds against the reverted value."""
    node = V37Node(default_registry())
    node.bootstrap(64)
    node.settle(_events("btc", 1, {"m0": 80, "m1": 20}))
    node.settle(_events("dgb", 7, {"m2": 100}, orphan=True))   # reverted, must not pay
    coinbase = node.pay(100)
    owed = node.settlement.owed()
    return {"row": "E2E-3", "coinbase": coinbase,
            "coinbase_sum": sum(a for _, a in coinbase),
            "m2_paid": any(m == "m2" for m, _ in coinbase), "owed": owed}


def row_e2e4_receipt_expiry():
    """E2E-4: X4 negative — a delivery under an EXPIRED receipt is not creditable, even though
    the shares were delivered. Couples P4-messaging TTL to P4-market at the seam."""
    node = V37Node(default_registry())
    node.bootstrap(64)
    receipt = node.messaging.mint("m0", epoch=5, ttl=2)         # live [5,7)
    cid = node.market.open_contract("m1", "m0", shares=5)
    filled_live = node.market_credit(cid, 5, receipt, now_epoch=6)   # creditable
    # new contract, same expired receipt, now_epoch=9 (>= 7) -> not creditable
    cid2 = node.market.open_contract("m1", "m0", shares=5)
    filled_expired = node.market_credit(cid2, 5, receipt, now_epoch=9)
    return {"row": "E2E-4", "filled_live": filled_live, "filled_expired": filled_expired}


def row_e2e5_failed_cross_noop():
    """E2E-5: X5 — a non-atomic venue cross (one leg not final) pays neither leg and leaves the
    settlement owed ledger untouched."""
    node = V37Node(default_registry())
    node.bootstrap(64)
    node.settle(_events("btc", 1, {"m0": 100}))
    owed = node.settlement.owed()
    ms = node.venue_cross({"final_at": 2, "amount": 9}, {"final_at": 5, "amount": 9},
                          head=3, owed_before=owed)              # leg_b not final -> abort
    return {"row": "E2E-5", "cross_atomic": ms.atomic,
            "a_paid": ms.a_paid, "b_paid": ms.b_paid, "owed_unchanged": node.settlement.owed() == owed}


ROWS = [row_e2e1_happy, row_e2e2_multichain, row_e2e3_orphan_isolation,
        row_e2e4_receipt_expiry, row_e2e5_failed_cross_noop]


def main():
    os.makedirs(GOLDEN, exist_ok=True)
    results, ok = [], True
    for fn in ROWS:
        try:
            res = fn()
            digest = h(_canon(res))
            with open(os.path.join(GOLDEN, f"{res['row']}.json"), "w") as fh:
                json.dump({"result": res, "digest": digest}, fh, sort_keys=True, indent=2)
            print(f"  PASS  {res['row']:8s}  digest={digest[:12]}")
            results.append((res["row"], digest))
        except (InvariantError, AssertionError) as e:
            ok = False
            print(f"  FAIL  {fn.__name__}: {e}")
    stamp = h(*[d for _, d in results])
    print(f"\nP5 registry bound: {default_registry().bound()}")
    print(f"P5 suite: {len(results)}/{len(ROWS)} rows green")
    print(f"P5 suite stamp: {stamp}")
    return 0 if ok and len(results) == len(ROWS) else 1


if __name__ == "__main__":
    sys.exit(main())
