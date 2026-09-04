#!/usr/bin/env python3
# Truth-in-CI driver for the proto/ harness corpus (the six conformance
# harnesses + the decay golden that landed via PR #1465). Until this lane
# existed no workflow referenced proto/, so the pinned goldens were inert: a
# PR that broke a harness rendered green. This driver runs every harness entry
# point and FAILS on
#   (a) a non-zero exit from any harness,
#   (b) a printed stamp / digest that differs from its pin or its committed
#       .sha256 file,
#   (c) a regenerated golden file whose sha256 differs from its pin, and
#   (d) -- authoritatively -- any change to a committed file under proto/
#       after the harnesses have run (`git diff --exit-code -- proto/`).
# (d) matters because most harnesses REWRITE their golden/*.json on the green
# path and two of them (p3-testbed, p3-overlay) do not fail their own exit
# code on a golden change, so "trust the exit code" is insufficient.
#
# The A2 C++ bring-up diffs the engine against these goldens; an unguarded
# oracle is no oracle. Python twin of libmrr-go.yml (issue #1076).
#
# stdlib-only; no pip deps. The harnesses are deterministic (fixed seeds, no
# wall-clock). The proto/payment-hardening longitudinal script needs the
# ~94 MB uncommitted data/longitudinal/blocks.json and is deliberately NOT
# part of this lane (see proto/payment-hardening/README.md).
#
# Run locally:  python3 tools/ci/run_proto_harnesses.py

import os
import re
import subprocess
import sys
import hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROTO = os.path.join(ROOT, "proto")

HEX64 = r"([0-9a-f]{64})"

# Each entry: (slice dir under proto/, argv relative to that dir, checks).
# checks keys:
#   stamp_re   -- regex with one HEX64 group; the LAST match in stdout is the stamp
#   pin        -- expected stamp (full sha256 hex)
#   digest_file-- committed <slice>/<file>; first field is the expected stamp
#   file_sha256-- (relative path, expected sha256) of a golden the harness
#                 regenerates; checked after the run
HARNESSES = [
    # rev3 AT-REPAIR/SPINE/BROADCAST acceptance harness: 75/75 checks.
    ("rev3-falsifiers", ["harness/run_all.py"], {
        "stamp_re": r"golden sha256 " + HEX64,
        "pin": "3692d922af75b61bc3d40b431e0c048ee5ed0412b093c05911294b3ec5af4efe",
    }),
    # P3 multichain settlement testbed: 18 rows, main() does not fail its own
    # exit on golden drift, so the pin + git diff carry the gate.
    ("p3-testbed", ["harness/scenarios.py"], {
        "stamp_re": r"suite stamp = " + HEX64,
        "pin": "bc2b5c84390a6c07630f1a6aee1f9ee40d513caec133e746c7f2b8490d87d6db",
    }),
    # P5 port/adapter composition scaffold: 5 E2E rows.
    ("p5-integration", ["harness/scenarios.py"], {
        "stamp_re": r"P5 suite stamp: " + HEX64,
        "pin": "328a292b0162b31b64dea4ffc5a8decfe7e56e2780d850611a7593348ff2098e",
    }),
    # refimpl MRR accumulator + K_fair settlement goldens: self-checking
    # (P/D/F/G/V properties), rewrite golden/*.json; drift caught by git diff.
    ("refimpl", ["gen_golden.py"], {}),
    ("refimpl", ["gen_golden_settlement.py"], {}),
    # refimpl canonical decay-table golden. F-1 / OI-7 is UNADJUDICATED (the
    # decay-table construction contradiction between v37_fixed.hpp
    # DecayTables::init and the exact-root golden): this entry is a
    # SELF-CONSISTENCY drift gate only -- does the refimpl still reproduce its
    # own committed table -- and is NOT a consensus-authority assertion that
    # d659c801 is canonical. When the integrator rules OI-7, re-pin here and
    # the committed file together.
    ("refimpl", ["gen_golden_decaytable.py"], {
        "file_sha256": ("golden/decay_table_canonical_golden_v1.json",
                        "d659c801a2544672e383c2a6ae6c68047c574d0cb212d3140794ca1f3b5b1349"),
    }),
    # P4 perishable-receipt admission core (slice 1) and TTL-as-decayed-work
    # (slice 2): print a digest, never rewrite the committed .sha256, and do
    # not fail on digest drift while invariants pass -- so compare here.
    ("p4-messaging", ["harness/run_p4.py"], {
        "stamp_re": r"golden-digest sha256: " + HEX64,
        "digest_file": "golden/p4-slice1.sha256",
    }),
    ("p4-messaging", ["harness/run_p4_slice2.py"], {
        "stamp_re": r"golden-digest sha256: " + HEX64,
        "digest_file": "golden/p4-slice2.sha256",
    }),
    # P3-F1 KEYED_CRDT overlay commutativity (P3-12): prints a stamp only, no
    # committed golden file, so the pin is the whole gate.
    ("p3-overlay", ["harness/p3f1_overlay_commutativity.py"], {
        "stamp_re": r"GOLDEN VECTOR sha256: " + HEX64,
        "pin": "d0d495569a4ddd11604d8cdd119b590e17e527d8499b26bfaf8b1176a0c32ac8",
    }),
    # Real-block 955609 h_min replay over committed data/coinbase.json:
    # in-script assertions, exit code is the gate.
    ("payment-hardening", ["realblock-955609-replay.py"], {}),
]


def run(slice_dir, argv):
    cwd = os.path.join(PROTO, slice_dir)
    p = subprocess.run([sys.executable] + argv, cwd=cwd,
                       capture_output=True, text=True)
    sys.stdout.write(p.stdout)
    sys.stderr.write(p.stderr)
    return p.returncode, p.stdout


def last_match(pattern, out):
    hits = re.findall(pattern, out)
    return hits[-1] if hits else None


def sha256_of(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    fails = []
    ran = 0
    for slice_dir, argv, checks in HARNESSES:
        label = "proto/%s/%s" % (slice_dir, argv[0])
        print("\n===== %s" % label, flush=True)
        rc, out = run(slice_dir, argv)
        ran += 1
        if rc != 0:
            fails.append("%s: non-zero exit %d" % (label, rc))
            continue
        if "stamp_re" in checks:
            got = last_match(checks["stamp_re"], out)
            if got is None:
                fails.append("%s: no stamp line matched /%s/"
                             % (label, checks["stamp_re"]))
            elif "pin" in checks and got != checks["pin"]:
                fails.append("%s: stamp %s != pinned %s" % (label, got, checks["pin"]))
            elif "digest_file" in checks:
                dpath = os.path.join(PROTO, slice_dir, checks["digest_file"])
                with open(dpath) as f:
                    want = f.read().split()[0]
                if got != want:
                    fails.append("%s: digest %s != committed %s (%s)"
                                 % (label, got, want, checks["digest_file"]))
        if "file_sha256" in checks:
            rel, want = checks["file_sha256"]
            got = sha256_of(os.path.join(PROTO, slice_dir, rel))
            if got != want:
                fails.append("%s: regenerated %s sha256 %s != pinned %s"
                             % (label, rel, got, want))

    # AUTHORITATIVE drift gate: the writers rewrote their golden/*.json in
    # place; if any committed byte under proto/ moved, that is a regression or
    # an unpinned golden change. Untracked files are reported too, so a
    # harness that starts emitting a new artifact is caught.
    diff = subprocess.run(["git", "diff", "--exit-code", "--stat", "--", "proto/"],
                          cwd=ROOT, capture_output=True, text=True)
    if diff.returncode != 0:
        sys.stdout.write(diff.stdout)
        fails.append("committed proto/ golden(s) changed after running the "
                     "harnesses (regression or unpinned golden); see diff above")
    untracked = subprocess.run(["git", "ls-files", "--others", "--exclude-standard", "--", "proto/"],
                               cwd=ROOT, capture_output=True, text=True).stdout.split()
    if untracked:
        fails.append("harness run left untracked file(s) under proto/: %s"
                     % ", ".join(untracked))

    print()
    if fails:
        print("PROTO-HARNESS LANE FAILED (%d harness(es) ran):" % ran)
        for f in fails:
            print("  - " + f)
        return 1
    print("PROTO-HARNESS LANE OK: %d harness entry points green, all pinned "
          "stamps matched, committed proto/ goldens unchanged." % ran)
    return 0


if __name__ == "__main__":
    sys.exit(main())
