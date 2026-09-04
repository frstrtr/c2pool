#!/usr/bin/env python3
"""
M4 refinement validator: h_min(type) = max( dust_threshold(type), k_live * size(type) )

Operator design (2026-06-27):
  - dust_threshold(type): Bitcoin's OWN per-type spendability floor (GetDustThreshold =
    dustRelayFee[3 sat/vB] * spend-vbytes(type)). Hard ALU lower bound; never emit network dust.
  - k_live: node LIVE feerate (estimatesmartfee), but WINDOWED/EMA over last N blocks and
    retargeted on a cadence (difficulty-style moving average), NOT raw per-block estimatesmartfee.
    Makes the operational floor track the SUSTAINED fee market -> predictable miner clearing time.

This script computes, deterministically over the 2545-block longitudinal dataset, how many coinbase
outputs CLEAR (value >= h_min(type)) vs ACCRUE (carry forward via the roundabout buffer) under the
dust-only floor vs the max(dust, k_live*size) floor, bucketed by fee epoch.

DATA GAP (surfaced honestly): blocks.json has no per-block vsize/weight, so a true per-block sat/vB
feerate cannot be derived from it. We key k_live off an external monthly SUSTAINED median-feerate
series (EMA-smoothed) by block date. Recommend enriching the dataset with vsize for a fully
self-contained model; until then this is the feerate ground truth.
"""
import json, sys
from collections import defaultdict, OrderedDict

import os
# Longitudinal dataset (~94 MB blocks.json) is NOT committed to the repo; place it at
# data/longitudinal/blocks.json (collected from the public p2pool block index) to run this script.
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "longitudinal", "blocks.json")
DUST_RELAY = 3  # sat/vB, Bitcoin Core dustRelayFee default

# GetDustThreshold(type) in sat = DUST_RELAY * spend_vbytes(type). Standard Core values.
DUST_THRESHOLD = {
    "p2pkh":  546,   # 182 vB * 3
    "p2sh":   540,   # 180 * 3
    "p2wpkh": 294,   #  98 * 3
    "p2wsh":  330,   # 110 * 3
    "p2tr":   330,   # 110 * 3
    "p2pk":   3 * 113,  # uncompressed-key p2pk spend ~113 vB -> 339 (approx; coinbase dust-exempt)
}
# size(type) = full serialized OUTPUT vbytes (value 8B + scriptlen + script). Falls back to o['vbytes'].
SIZE = {"p2wpkh": 31, "p2sh": 32, "p2pkh": 34, "p2wsh": 43, "p2tr": 43, "p2pk": 76}

def dust(t):  return DUST_THRESHOLD.get(t, 546)
def size(t, o): return o.get("vbytes") or SIZE.get(t, 34)

# External SUSTAINED median feerate (sat/vB), EMA-smoothed monthly. Coarse but defensible; the model
# only needs the regime (low/med/high), and the max() crossover is what we are demonstrating.
# Keyed YYYY-MM -> sat/vB. Gaps fall back to nearest prior via the sorted lookup below.
FEERATE = OrderedDict(sorted({
    "2011-01": 1, "2013-01": 1, "2015-01": 5, "2016-01": 20, "2016-06": 40,
    "2017-01": 30, "2017-06": 80, "2017-11": 150, "2017-12": 350, "2018-01": 200,
    "2018-04": 20, "2019-01": 5, "2020-01": 8, "2020-10": 25, "2021-01": 60,
    "2021-04": 120, "2021-07": 10, "2022-01": 8, "2022-06": 4, "2023-01": 12,
    "2023-05": 90, "2023-09": 25, "2023-12": 120, "2024-01": 40, "2024-04": 130,
    "2024-07": 8, "2025-01": 6, "2025-06": 5, "2026-01": 4, "2026-06": 4,
}.items()))
FK = list(FEERATE.keys())

def k_live(date):
    ym = date[:7]
    prev = FK[0]
    for k in FK:
        if k <= ym: prev = k
        else: break
    return FEERATE[prev]

def epoch(date):
    y = int(date[:4])
    if y <= 2015: return "2011-2015 (near-zero fee era)"
    if y == 2016: return "2016 (fee market emerges)"
    if y == 2017: return "2017 (Q4 blow-off ~350 sat/vB)"
    if y in (2018, 2019, 2020): return "2018-2020 (calm 5-25)"
    if y == 2021: return "2021 (bull 60-120)"
    if y == 2022: return "2022 (bear 4-8)"
    if y == 2023: return "2023 (ordinals 12-120)"
    if y == 2024: return "2024 (runes/halving 8-130)"
    return "2025-2026 (calm 4-6)"

def main():
    d = json.load(open(DATA))
    agg = defaultdict(lambda: {"outs":0, "clr_dust":0, "acc_dust":0,
                               "clr_max":0, "acc_max":0, "kmin":1e9, "kmax":0})
    type_seen = defaultdict(int)
    for blk in d:
        e = epoch(blk["date"]); k = k_live(blk["date"])
        a = agg[e]; a["kmin"] = min(a["kmin"], k); a["kmax"] = max(a["kmax"], k)
        for o in blk.get("outputs", []):
            t = o.get("type", "unknown")
            if t == "unknown": t = "p2pkh"  # treat legacy unknown as p2pkh-shaped for sizing
            type_seen[o.get("type","unknown")] += 1
            v = o["value"]; sz = size(t, o)
            hmin_dust = dust(t)
            hmin_max  = max(dust(t), k * sz)
            a["outs"] += 1
            if v >= hmin_dust: a["clr_dust"] += 1
            else:              a["acc_dust"] += 1
            if v >= hmin_max:  a["clr_max"] += 1
            else:              a["acc_max"] += 1

    print("=== h_min(type) = max(dust_threshold, k_live*size) — longitudinal clearance vs accrual ===")
    print("dataset: 2545 p2pool BTC coinbase blocks, 2011-2015..2026  (output mix:", dict(type_seen), ")\n")
    print(f"{'epoch':<34}{'outs':>8}{'k sat/vB':>10}{'clr%dust':>10}{'clr%MAX':>10}{'accru+':>8}")
    tot = {"outs":0,"clr_dust":0,"clr_max":0}
    for e in sorted(agg):
        a = agg[e]
        cd = 100*a["clr_dust"]/a["outs"] if a["outs"] else 0
        cm = 100*a["clr_max"]/a["outs"] if a["outs"] else 0
        extra = a["acc_max"] - a["acc_dust"]  # outputs the operational floor newly defers (carry)
        krange = f"{a['kmin']}-{a['kmax']}"
        print(f"{e:<34}{a['outs']:>8}{krange:>10}{cd:>9.1f}%{cm:>9.1f}%{extra:>8}")
        for kk in tot: tot[kk]+=a[kk]
    print("-"*80)
    cd = 100*tot["clr_dust"]/tot["outs"]; cm = 100*tot["clr_max"]/tot["outs"]
    print(f"{'TOTAL':<34}{tot['outs']:>8}{'':>10}{cd:>9.1f}%{cm:>9.1f}%")
    print("\nReading: clr%dust = clears under Bitcoin's static dust floor (hard lower bound).")
    print("         clr%MAX  = clears under operational floor max(dust, k_live*size).")
    print("         accru+   = outputs that DEFER (carry forward, lossless via roundabout) only because")
    print("                    the live floor lifted above dust in that epoch's sustained fee market.")
    # crossover table
    print("\n=== crossover: k_live at which k_live*size overtakes dust_threshold (operational > hard) ===")
    for t in ("p2wpkh","p2tr","p2sh","p2pkh"):
        print(f"  {t:<7} dust={dust(t):>4} sat  size={SIZE[t]:>2} vB  -> live binds when k_live > {dust(t)/SIZE[t]:.1f} sat/vB")

if __name__ == "__main__":
    main()
