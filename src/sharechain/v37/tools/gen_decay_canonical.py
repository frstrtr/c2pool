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

What pins these values, stated precisely. The ratified golden vector
    proto/refimpl/golden/decay_table_canonical_golden_v1.json
    sha256 = d659c801a2544672e383c2a6ae6c68047c574d0cb212d3140794ca1f3b5b1349
publishes ANCHORS and a deterministic sample of entries, not all 12289 of them, so
"the emitted table is bit-identical to the golden" claims a comparison nobody has
run. Three things pin it instead:

  1. the DEFINING floor-root invariant, which is self-verifying per entry and needs
     no external file: x = decay[d] is the unique integer with x**HL <= 2**k <
     (x+1)**HL. iroot_floor asserts exactly that on every entry it returns, so a
     wrong value cannot leave the builder;
  2. the golden's published anchors, asserted in main() below before anything is
     written, and re-checked as CHECKs in src/sharechain/v37/test/v37_test.cpp;
  3. a SHA-256 over the FULL emitted arrays, pinned in that same suite. The anchors
     cover 7 of 12289 entries and would not notice an edit to the interior; the
     digest reds on one flipped bit anywhere.

Regenerating and finding the digest changed is therefore a REVIEW event, not a
"update the constant" chore.

Reproducible bit-for-bit on any platform (integers only, no external data). The
root itself comes from proto/refimpl/decay_table.iroot_floor rather than a private
copy: the reference implementation and the shipped consensus table must be the same
root, and two textually identical functions in two trees are exactly how they stop
being.
"""

import os
import sys

# Same import pattern as proto/refimpl/gen_golden_decaytable.py.
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "..", "..", "proto", "refimpl")))
from decay_table import iroot_floor  # noqa: E402  (path set up above)

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


def build():
    base_pow = FRAC_BITS * HL
    decay = [iroot_floor(1 << base_pow, HL, seed=ONE)]   # d=0 -> exactly ONE
    InvD  = [decay[0]]                                    # j=0 -> exactly ONE
    for d in range(1, MAXD + 1):
        decay.append(iroot_floor(1 << (base_pow - d), HL, seed=decay[-1]))
    for j in range(1, E):                                # InvD only needed on [0, E)
        InvD.append(iroot_floor(1 << (base_pow + j), HL, seed=InvD[-1]))
    return decay, InvD


# The generated header, resolved from THIS file's location. It sits one level
# up: src/sharechain/v37/tools/gen_decay_canonical.py -> src/sharechain/v37/.
DEFAULT_OUT = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "v37_decay_canonical.hpp"))


def resolve_out(argv=None):
    """Where to write, in precedence order: --out, $OUT, DEFAULT_OUT.

    The default used to be dirname(__file__)/../src/sharechain/v37/..., i.e. the
    repo-root-relative path with only one level stripped — from inside
    src/sharechain/v37/tools that resolves to src/sharechain/v37/src/sharechain/
    v37/, which does not exist, so a plain `python3 gen_decay_canonical.py` died
    on FileNotFoundError after computing the whole table. The $OUT override
    ("allow override for the c2pool clone") was the only way anyone ran it,
    which is why the default's rot went unnoticed. The header's location is
    fixed relative to this script, so derive it from __file__ and stop guessing.
    """
    import argparse
    ap = argparse.ArgumentParser(
        description="Generate src/sharechain/v37/v37_decay_canonical.hpp.")
    ap.add_argument("--out", default=None, metavar="PATH",
                    help="output header path (default: the in-tree "
                         "v37_decay_canonical.hpp next to this script's parent; "
                         "the OUT environment variable overrides that default "
                         "and is itself overridden by this flag)")
    args = ap.parse_args(argv)
    return os.path.abspath(args.out or os.environ.get("OUT") or DEFAULT_OUT)


def main(argv=None):
    out = resolve_out(argv)          # resolve BEFORE the ~4-minute build
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
//  Ratified golden vector:
//      proto/refimpl/golden/decay_table_canonical_golden_v1.json
//      sha256 d659c801a2544672e383c2a6ae6c68047c574d0cb212d3140794ca1f3b5b1349
//  It publishes ANCHORS and a sampled subset, not all {MAXD + 1 + E} entries, so
//  no artefact compares this table against it byte for byte. What DOES pin the
//  values here:
//    1. the defining floor-root construction above — self-verifying per entry
//       (x^HL <= 2^k < (x+1)^HL), asserted by the generator on every entry;
//    2. the golden's published anchors, listed below, asserted by the generator
//       before it writes and re-checked in test/v37_test.cpp;
//    3. a SHA-256 over the FULL arrays, pinned in test/v37_test.cpp — the
//       anchors cover 7 of {MAXD + 1 + E} entries and would not notice an edit
//       to the interior; the digest reds on one flipped bit anywhere.
//
//  Regenerate with src/sharechain/v37/tools/gen_decay_canonical.py
//  (integers only; reproducible bit-for-bit, no floating point). A changed
//  full-array digest is a review event, not a constant to be updated.
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
#include <iterator>   // std::size, for the array-extent asserts below

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

// Extents are compiler-checked, not hand-trusted. Both arrays are declared
// UNSIZED, so their true lengths come from the initialiser lists above and from
// nothing else — while DecayTables::init indexes them against CANON_MAX_DEPTH
// and CANON_EPOCH_LEN, which are separate literals a few lines up. Nothing but
// these asserts ties the two together. A regeneration cut short, a bad merge
// resolution, a hand-trimmed row: any of them shortens an array while leaving
// the constants saying otherwise, and the result is an out-of-bounds read in
// the consensus path, silently, with whatever happened to follow in memory
// serving as a decay factor. Fail the BUILD instead.
static_assert(std::size(DECAY) == CANON_MAX_DEPTH + 1,
              "v37: DECAY[] must cover [0, CANON_MAX_DEPTH] exactly; "
              "regenerate with tools/gen_decay_canonical.py");
static_assert(std::size(INV_DECAY) == CANON_EPOCH_LEN,
              "v37: INV_DECAY[] must cover [0, CANON_EPOCH_LEN) exactly; "
              "regenerate with tools/gen_decay_canonical.py");

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
