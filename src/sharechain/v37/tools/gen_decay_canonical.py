#!/usr/bin/env python3
"""
Generator for src/sharechain/v37/v37_decay_canonical.hpp.

Emits the V37 MRR CANONICAL decay-table base for the ratified default lane
geometry (half_life = 2160, epoch_len E = 4096, frac_bits = 62), built by the
EXACT per-entry hl-th-root construction that the ratified golden pins:

    decay[d] = floor( (2^(FRAC*HL - d)) ^ (1/HL) )   for d in [0, MAXD]
    InvD[j]  = floor( (2^(FRAC*HL + j)) ^ (1/HL) )    for j in [0, E-1]

Each entry is the floor of an EXACT integer HL-th root of an exact power of two
(integer Newton + closing exact-floor correction; no floating point). This is
the LN2_MICRO intent (anchor 2^(1/HL) at full precision) realised exactly at
every entry rather than by iterating a single per-step base.

The [0, E] slice of this table is bit-identical to the ratified golden vector
    proto/refimpl/golden/decay_table_canonical_golden_v1.json
    sha256 = d659c801a2544672e383c2a6ae6c68047c574d0cb212d3140794ca1f3b5b1349
Self-check below asserts the published golden anchors, so the emitted C++ array
is provably the golden's values.

Self-contained (no external inputs); reproducible bit-for-bit on any platform.
"""

FRAC_BITS = 62
HL        = 2160          # ratified default half_life (OQ-5: W/4)
E         = 4096          # ratified default epoch_len
MAXD      = 2 * E         # Lane allocates decay[] over [0, epoch_len + c0] = [0, 2E]
ONE       = 1 << FRAC_BITS

# Published anchors of golden d659c801 (for provenance self-check).
GOLDEN = {
    "decay_0":    4611686018427387904,   # = 2^62
    "decay_1":    4610206359018591605,
    "decay_2160": 2305843009213693952,   # = 2^61 (exact half-life)
    "decay_4096": 1238846976710486712,
    "InvD_0":     4611686018427387904,   # = 2^62
    "InvD_1":     4613166152737261408,
    "InvD_4095":  17161783987563169425,
}


def iroot_floor(n, k, seed=None):
    """floor(n ** (1/k)), exact integer Newton + closing floor correction."""
    if k == 1:
        return n
    if n < 2:
        return n
    if seed and seed > 0:
        x = seed
        while x ** k < n:
            x += x // k + 1
    else:
        bl = n.bit_length()
        x = 1 << ((bl + k - 1) // k)
    while True:
        nx = ((k - 1) * x + n // x ** (k - 1)) // k
        if nx >= x:
            break
        x = nx
    while x ** k > n:
        x -= 1
    while (x + 1) ** k <= n:
        x += 1
    assert x ** k <= n < (x + 1) ** k, "iroot_floor invariant"
    return x


def build():
    base_pow = FRAC_BITS * HL
    decay = [iroot_floor(1 << base_pow, HL, seed=ONE)]   # d=0 -> exactly ONE
    InvD  = [decay[0]]                                    # j=0 -> exactly ONE
    for d in range(1, MAXD + 1):
        decay.append(iroot_floor(1 << (base_pow - d), HL, seed=decay[-1]))
    for j in range(1, E):                                # InvD only needed on [0, E)
        InvD.append(iroot_floor(1 << (base_pow + j), HL, seed=InvD[-1]))
    return decay, InvD


def main():
    import os
    decay, InvD = build()

    # ---- provenance + canonical-invariant self-check (integer only) ----
    assert decay[0] == ONE == (1 << FRAC_BITS), "C1 decay[0]"
    assert InvD[0]  == ONE, "C1 InvD[0]"
    assert decay[HL] == (1 << (FRAC_BITS - 1)), "C2 exact half-life"
    assert decay[0]    == GOLDEN["decay_0"]
    assert decay[1]    == GOLDEN["decay_1"]
    assert decay[HL]   == GOLDEN["decay_2160"]
    assert decay[E]    == GOLDEN["decay_4096"]
    assert InvD[0]     == GOLDEN["InvD_0"]
    assert InvD[1]     == GOLDEN["InvD_1"]
    assert InvD[E - 1] == GOLDEN["InvD_4095"]
    assert all(decay[d] > decay[d + 1] for d in range(MAXD)), "C4 decay monotone"
    assert all(InvD[j] < InvD[j + 1] for j in range(E - 1)), "C4 InvD monotone"
    assert InvD[E - 1] < (1 << 64), "InvD headroom < 4.0 (Q62 u64)"
    assert len(decay) == MAXD + 1 and len(InvD) == E

    out = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "src", "sharechain", "v37",
        "v37_decay_canonical.hpp"))
    # allow override for the c2pool clone
    if "OUT" in os.environ:
        out = os.environ["OUT"]

    def emit_array(name, vals):
        lines = [f"inline constexpr u64 {name}[] = {{"]
        row = "   "
        for i, v in enumerate(vals):
            tok = f" {v}ULL,"
            if len(row) + len(tok) > 96:
                lines.append(row)
                row = "   "
            row += tok
        if row.strip():
            lines.append(row)
        lines.append("};")
        return "\n".join(lines)

    hdr = f"""#pragma once
// ─────────────────────────────────────────────────────────────────────────
//  V37 MRR canonical decay-table base — GENERATED, DO NOT EDIT BY HAND.
//
//  Ratified default lane geometry: half_life = {HL}, epoch_len E = {E},
//  FRAC_BITS = {FRAC_BITS} (Q62).  Exact per-entry HL-th-root construction:
//
//      decay[d] = floor( (2^(FRAC*HL - d)) ^ (1/HL) )   d in [0, {MAXD}]
//      InvD[j]  = floor( (2^(FRAC*HL + j)) ^ (1/HL) )   j in [0, {E - 1}]
//
//  The [0, {E}] slice is BIT-IDENTICAL to the ratified golden vector
//      proto/refimpl/golden/decay_table_canonical_golden_v1.json
//      sha256 d659c801a2544672e383c2a6ae6c68047c574d0cb212d3140794ca1f3b5b1349
//
//  Regenerate with src/sharechain/v37/tools/gen_decay_canonical.py
//  (self-contained; reproducible bit-for-bit, no floating point).
//
//  Anchors (self-checked by the generator against the published golden):
//      decay[0]    = {decay[0]}ULL  (= 2^62 = Q_ONE)
//      decay[1]    = {decay[1]}ULL
//      decay[{HL}] = {decay[HL]}ULL  (= 2^61, exact half-life)
//      decay[{E}] = {decay[E]}ULL
//      InvD[0]     = {InvD[0]}ULL  (= 2^62 = Q_ONE)
//      InvD[1]     = {InvD[1]}ULL
//      InvD[{E - 1}]  = {InvD[E - 1]}ULL
// ─────────────────────────────────────────────────────────────────────────
#include <cstdint>

namespace v37 {{
namespace decay_canonical {{

using u64 = std::uint64_t;

inline constexpr u64 CANON_HALF_LIFE = {HL};
inline constexpr u64 CANON_EPOCH_LEN = {E};       // E (InvD covers [0, E))
inline constexpr unsigned CANON_FRAC_BITS = {FRAC_BITS};
inline constexpr u64 CANON_MAX_DEPTH = {MAXD};    // decay covers [0, MAX_DEPTH]

// decay[d] = lambda^d in Q62, d in [0, CANON_MAX_DEPTH]  (exact HL-th root)
{emit_array("DECAY", decay)}

// InvD[j]  = lambda^-j in Q62, j in [0, CANON_EPOCH_LEN)  (exact HL-th root)
{emit_array("INV_DECAY", InvD)}

}}  // namespace decay_canonical
}}  // namespace v37
"""
    with open(out, "w") as f:
        f.write(hdr)
    print("decay len   :", len(decay), "(indices 0..%d)" % MAXD)
    print("inv_decay len:", len(InvD), "(indices 0..%d)" % (E - 1))
    print("decay[0]    =", decay[0])
    print("decay[1]    =", decay[1])
    print("decay[%d]  =" % HL, decay[HL])
    print("decay[%d]  =" % E, decay[E])
    print("InvD[1]     =", InvD[1])
    print("InvD[%d]   =" % (E - 1), InvD[E - 1])
    print("ALL SELF-CHECKS PASSED; wrote", out)
    print("bytes:", os.path.getsize(out))


if __name__ == "__main__":
    main()
