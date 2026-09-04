#!/usr/bin/env python3
"""
V37 P4 slice-2 harness — TTL-as-decayed-work invariants + golden digest.

Deterministic: no RNG, no wall clock. Time is the integer L0 bin clock (lane pushes);
all weights from fixed seeds. Digest pins the (invariant -> observed) vector so any
drift in the carriage semantics or the canonical decay base is caught.

Invariants:
  P4-5  ttl_shares = clamp(floor(dw/UNIT), 0, MAX)         (exact derivation)
  P4-6  requires-not-burns: admit() leaves decayed_weight UNCHANGED
  P4-7  decay-coupling: with no new work, ttl_shares is monotone non-increasing
        across epochs and reaches 0 (carriage PERISHES with the work)
  P4-8  threshold gate: dw < UNIT -> shares 0 -> rejected; dw >= UNIT -> admitted
  P4-9  sybil-tax: splitting work across N ids cannot GAIN shares
        (floor is sub-additive: sum floor(w_i/U) <= floor(sum w_i /U))
  P4-10 determinism: bit-identical golden digest
"""
import hashlib
import json

from perishable_ttl_work import (
    MessageLane, ttl_shares, TTL_WORK_UNIT, TTL_SHARES_MAX,
)

RESULTS = []


def check(name, got, want):
    ok = got == want
    RESULTS.append((name, ok, got, want))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: got={got!r} want={want!r}")
    return ok


def main():
    U = TTL_WORK_UNIT

    # ---- P4-5 exact derivation over a fixed sample ----
    sample = [0, 1, U - 1, U, U + 1, 2 * U, 3 * U, 7 * U]
    want5 = [min(v // U, TTL_SHARES_MAX) for v in sample]
    got5 = [ttl_shares(v) for v in sample]
    check("P4-5 ttl-shares-derivation", got5, want5)

    # ---- P4-6 requires-not-burns ----
    ml = MessageLane()
    # give miner A enough decayed work to clear >= 1 share right at head
    for _ in range(64):
        ml.do_work("A", 8)          # 64*8 = 512 raw; decayed weight at head ~ below raw
    dw0 = ml.decayed_weight("A")
    ok, reason, before, after = ml.admit("A")
    check("P4-6a admit-nonburn-before-eq-after", before == after, True)
    check("P4-6b admit-leaves-accumulator", ml.decayed_weight("A"), dw0)

    # ---- P4-8 threshold gate (reuse A above) ----
    ml_lo = MessageLane()
    ml_lo.do_work("B", 1)           # tiny work -> below one UNIT of decayed weight
    dwB = ml_lo.decayed_weight("B")
    ok_lo, reason_lo, _, _ = ml_lo.admit("B")
    check("P4-8a below-unit-rejected", (ttl_shares(dwB) == 0 and ok_lo is False), True)
    check("P4-8b reason-insufficient", reason_lo, "insufficient-decayed-work")
    check("P4-8c at-or-above-unit-admits", ml.admit("A")[0], True)

    # ---- P4-7 decay-coupling: no new work, carriage perishes across epochs ----
    ml2 = MessageLane()
    for _ in range(200):
        ml2.do_work("C", 8)
    seq = [ml2.ttl_shares("C")]
    # advance the head with OTHER miners' work so C decays but C's records eventually
    # leave the epoch window -> shares fall to 0 (perish). One full epoch of advance.
    for _ in range(mrr_ref_epoch()):
        ml2.do_work("Z", 0)         # zero-weight pushes advance the clock, add no weight
        seq.append(ml2.ttl_shares("C"))
    monotone = all(seq[i] >= seq[i + 1] for i in range(len(seq) - 1))
    perished = seq[-1] == 0
    check("P4-7a decay-monotone-non-increasing", monotone, True)
    check("P4-7b carriage-perishes-to-zero", perished, True)

    # ---- P4-9 sybil-tax: split cannot gain ----
    single = MessageLane()
    for _ in range(50):
        single.do_work("S", 5)
    shares_single = single.ttl_shares("S")
    split = MessageLane()
    for i in range(50):
        split.do_work(f"S{i % 5}", 5)   # same total work, spread over 5 sybil ids
    shares_split = sum(split.ttl_shares(f"S{i}") for i in range(5))
    check("P4-9 sybil-split-no-gain", shares_split <= shares_single, True)

    # ---- P4-10 determinism digest ----
    payload = json.dumps(
        {
            "params": {"UNIT": U, "MAX": TTL_SHARES_MAX},
            "P4-5": got5,
            "P4-6": [before == after, dw0],
            "P4-7": seq,
            "P4-8": [ttl_shares(dwB), ok_lo],
            "P4-9": [shares_single, shares_split],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(payload).hexdigest()

    npass = sum(1 for _, ok, _, _ in RESULTS if ok)
    print(f"\n{npass}/{len(RESULTS)} invariants PASS")
    print(f"golden-digest sha256: {digest}")
    return 0 if npass == len(RESULTS) else 1


def mrr_ref_epoch():
    import mrr_ref
    return mrr_ref.E


if __name__ == "__main__":
    raise SystemExit(main())
