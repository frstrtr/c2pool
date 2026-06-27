#!/usr/bin/env python3
"""M4 T1: synthetic bootstrap-cost probe (accumulator build over N shares).
Stub — measures build time/mem for an O(n) accumulator over N synthetic shares.
Run: python3 bootstrap_feasibility.py --n 300000
"""
import argparse, time, hashlib

def synth_share(i: int) -> bytes:
    return hashlib.sha256(i.to_bytes(8, "little")).digest()

def build_accumulator(n: int):
    t0 = time.time()
    acc = []  # naive O(n) leaf set; T2 will swap in a Utreexo forest
    for i in range(n):
        acc.append(synth_share(i))
    return acc, time.time() - t0

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300_000)
    a = ap.parse_args()
    acc, dt = build_accumulator(a.n)
    print(f"n={a.n} build_s={dt:.3f} leaves={len(acc)}")
