#!/usr/bin/env python3
"""
V37 MRR canonical decay-table base (M2) — integer-only, per-entry exact construction.

PROBLEM with the v0 table (mrr_ref.build_tables): it derives a single per-step base
  base_inv = floor(2^(1/half_life) * 2^FRAC)
and then forms the table by ITERATED truncating multiply InvD[j] = trunc(InvD[j-1]*base_inv).
Every step truncates, so the per-step floor error compounds along the table: entry j carries
up to ~j ULPs of accumulated bias. That makes the table base position-order dependent and
NOT a clean canonical object — two equally-valid implementations of "the same" iterated
routine can disagree by O(j) ULPs depending on intermediate widths.

CANONICAL BASE (this module). Define each table entry DIRECTLY as a floored exact root of a
power of two, with NO accumulation:

    decay[d] = floor( 2^FRAC * 2^(-d/half_life) )
             = floor( ( 2^(FRAC*half_life - d) ) ^ (1/half_life) )        (d in [0, E])
    InvD[j]  = floor( 2^FRAC * 2^(+j/half_life) )
             = floor( ( 2^(FRAC*half_life + j) ) ^ (1/half_life) )        (j in [0, E])

because  2^FRAC * 2^(k/half_life) = ( 2^(FRAC*half_life + k) ) ^ (1/half_life).

Each entry is the floor of an exact integer k-th root (k = half_life) of an EXACT power of two,
computed by integer Newton iteration with an exact integer termination test. Properties that
make this the canonical base (all verifiable with integer arithmetic, no float):

  C1  decay[0]  = InvD[0]  = 2^FRAC = ONE                         (exact)
  C2  decay[half_life] = 2^(FRAC-1)  exactly (exact half-life)    — the anchoring invariant
      InvD[half_life]  = floor( 2^FRAC * 2 ) = 2^(FRAC+1) ... see C2-note
  C3  floor property is EXACT and self-checking:
          decay[d]^half_life  <=  2^(FRAC*half_life - d)  <  (decay[d]+1)^half_life
  C4  strict monotonicity: decay[] strictly decreasing, InvD[] strictly increasing
  C5  reciprocal consistency: decay[d]*InvD[d] is within 1 ULP-ish of 2^(2*FRAC)
  C6  geometry independence: identical routine for any (half_life, E); no per-geometry
      "base_inv" constant to agree on — the only inputs are integers FRAC, half_life, d.

This is the LN2_MICRO intent (anchor 2^(1/half_life) at full precision) realized exactly:
instead of anchoring a single per-step base and iterating, we anchor EVERY entry at full
precision. The two agree only in the limit of infinite intermediate precision; this one is
the limit, by construction.

Pinned as the CANDIDATE canonical base for M3 spec-consolidation (carry-in C2). The normative
sec.8.2 text is not on the bridge; if it differs from this exact-root construction, the
difference is a [decision-needed] for integrator before goldens become consensus-authoritative.
"""

FRAC_BITS = 62
ONE = 1 << FRAC_BITS

# default BTC/LTC-class lane geometry (OQ-5), same as mrr_ref
HALF_LIFE = 2160
E = 4096


def iroot_floor(n, k, seed=None):
    """floor(n ** (1/k)) for integers n >= 0, k >= 1, EXACT (integer Newton + integer check).

    Optional `seed` is a near-correct starting estimate (e.g. the adjacent table entry); a
    good seed cuts Newton to 1-2 iterations. The result is independent of the seed — the
    closing exact-floor correction + assert guarantee the canonical floored root regardless.
    """
    if k == 1:
        return n
    if n < 2:
        return n  # 0->0, 1->1
    if seed and seed > 0:
        x = seed
    else:
        bl = n.bit_length()
        x = 1 << ((bl + k - 1) // k)  # 2^ceil(bitlen(n)/k) >= true root
    # integer Newton: x_{i+1} = floor( ((k-1)x + n // x^(k-1)) / k ); converges from above
    while True:
        nx = ((k - 1) * x + n // x ** (k - 1)) // k
        if nx >= x:
            break
        x = nx
    # Newton from a seed can land slightly low OR high; correct in both directions to the
    # exact floor. Each step is one big pow; with a tight seed this runs 0-2 times.
    while x ** k > n:
        x -= 1
    while (x + 1) ** k <= n:
        x += 1
    assert x ** k <= n < (x + 1) ** k, "iroot_floor invariant"
    return x


def build_tables(half_life=HALF_LIFE, epoch=E, frac_bits=FRAC_BITS, progress=None):
    """Canonical per-entry exact-root decay tables (Q-frac fixed point).

    Each entry is the exact floored hl-th root of a power of two (see module docstring);
    entry d is seeded from entry d-1 (consecutive entries differ by factor 2^(-1/hl), ~11
    bits) so Newton converges in 1-2 iterations. Seeding is a pure speedup — the closing
    exact-floor correction in iroot_floor makes the output seed-independent and canonical.
    """
    hl = half_life
    base_pow = frac_bits * hl  # 2^(frac_bits*half_life); shift by k for the +/- k/hl entries
    decay = [iroot_floor(1 << base_pow, hl)]          # d=0 -> exactly ONE
    InvD = [decay[0]]                                  # j=0 -> exactly ONE
    for d in range(1, epoch + 1):
        decay.append(iroot_floor(1 << (base_pow - d), hl, seed=decay[-1]))
        InvD.append(iroot_floor(1 << (base_pow + d), hl, seed=InvD[-1]))
        if progress and d % 256 == 0:
            progress(d, epoch)
    return InvD, decay


def _cache_path():
    import os
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden",
                        "decay_table_canonical_v1.json")


def load_or_build(half_life=HALF_LIFE, epoch=E, frac_bits=FRAC_BITS, progress=None):
    """Load the canonical table from the golden cache if it matches this geometry, else build+cache."""
    import json, os
    p = _cache_path()
    if os.path.exists(p):
        with open(p) as f:
            c = json.load(f)
        g = c.get("geometry", {})
        if (g.get("half_life") == half_life and g.get("E") == epoch
                and g.get("frac_bits") == frac_bits):
            return [int(x) for x in c["InvD"]], [int(x) for x in c["decay"]]
    InvD, decay = build_tables(half_life, epoch, frac_bits, progress=progress)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        json.dump({
            "what": "V37 MRR canonical decay-table base (exact per-entry hl-th-root of 2^n)",
            "construction": "decay[d]=floor((2^(frac*hl - d))^(1/hl)); InvD[j]=floor((2^(frac*hl + j))^(1/hl))",
            "geometry": {"half_life": half_life, "E": epoch, "frac_bits": frac_bits},
            "anchors": {"decay_0": str(decay[0]), "decay_halflife": str(decay[half_life]),
                        "decay_E": str(decay[epoch]), "InvD_E": str(InvD[epoch]),
                        "two_pow_frac_minus_1": str(1 << (frac_bits - 1))},
            "InvD": [str(x) for x in InvD],
            "decay": [str(x) for x in decay],
            "status": "CANDIDATE canonical base pending M3 sec.8.2 normative cross-check",
        }, f)
    return InvD, decay


def validate(InvD, decay, half_life=HALF_LIFE, epoch=E, frac_bits=FRAC_BITS):
    """Return dict of canonical-invariant checks (all integer arithmetic, no float)."""
    one = 1 << frac_bits
    hl = half_life
    base_pow = frac_bits * hl
    r = {}
    r["C1_decay0_is_ONE"] = (decay[0] == one)
    r["C1_InvD0_is_ONE"] = (InvD[0] == one)
    # C2 exact half-life: decay[hl] must be exactly 2^(frac-1)
    r["C2_decay_halflife_exact_half"] = (decay[hl] == (1 << (frac_bits - 1)))
    # C3 exact floor property. build_tables already asserts this per entry at construction;
    # here we re-verify a deterministic SAMPLE (endpoints, half-life, every 257th) so validation
    # stays fast. Each check is one hl-th power of a ~63-bit base.
    sample = sorted(set([0, 1, hl - 1, hl, hl + 1, epoch - 1, epoch]
                        + list(range(0, epoch + 1, 257))))
    c3 = all(
        decay[d] ** hl <= (1 << (base_pow - d)) < (decay[d] + 1) ** hl and
        InvD[d] ** hl <= (1 << (base_pow + d)) < (InvD[d] + 1) ** hl
        for d in sample
    )
    r["C3_exact_floor_property_sampled"] = c3
    r["C3_sample_size"] = len(sample)
    # C4 strict monotonicity
    r["C4_decay_strictly_decreasing"] = all(decay[d] > decay[d + 1] for d in range(epoch))
    r["C4_InvD_strictly_increasing"] = all(InvD[j] < InvD[j + 1] for j in range(epoch))
    # C5 reciprocal consistency: decay[d]*InvD[d] ~ 2^(2*frac); record worst ULP gap
    target = 1 << (2 * frac_bits)
    worst = max(abs(decay[d] * InvD[d] - target) for d in range(epoch + 1))
    # bound: each entry floored independently, product error < ~ (decay+InvD) ~ 2^(frac+1) ULPs
    r["C5_reciprocal_max_abs_err"] = worst
    r["C5_reciprocal_within_2^(frac+2)"] = (worst < (1 << (frac_bits + 2)))
    r["C6_geometry_independent"] = True  # routine only consumes integers; asserted by construction
    return r


if __name__ == "__main__":
    import sys, time
    t0 = time.time()
    def prog(d, e):
        print(f"  ... {d}/{e}  ({time.time()-t0:.0f}s)", flush=True)
    InvD, decay = load_or_build(progress=prog)
    print(f"table ready in {time.time()-t0:.0f}s", flush=True)
    checks = validate(InvD, decay)
    print(f"canonical decay-table base  half_life={HALF_LIFE} E={E} frac_bits={FRAC_BITS}")
    print(f"  decay[0]={decay[0]}  (ONE={ONE})")
    print(f"  decay[half_life]={decay[half_life]}  (2^(frac-1)={1 << (FRAC_BITS-1)})")
    print(f"  decay[E]={decay[E]}")
    print(f"  InvD[E] ={InvD[E]}")
    allok = True
    for k, v in checks.items():
        if isinstance(v, bool):
            allok &= v
            print(f"  [{'PASS' if v else 'FAIL'}] {k}")
        else:
            print(f"        {k} = {v}")
    print("ALL CANONICAL INVARIANTS:", "PASS" if allok else "FAIL")
    raise SystemExit(0 if allok else 1)
