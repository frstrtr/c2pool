#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Golden-reference oracle for the DASH gobject collateral hash — the stdlib-only
# core of frstrtr/dash-proposal-collateral proto_hash.py (MIT, relicensed AGPL
# on inclusion), which is itself proven byte-exact vs mainnet Dash Core
# governance/common.cpp GetHash(). This script recomputes the hashes for the
# fixed mainnet vectors and asserts the C++ port (the M3-A-DASH test binary run
# with --emit-gov-hashes) emits byte-identical values — i.e. it drives the
# proven Python as the oracle for the C++ KAT (design §4.1.1 port note).
#
#   python3 proto_hash_oracle.py --cpp-bin /path/to/c2wallet-dash-test
#
# Exit 0 iff the C++ output matches the Python oracle for every vector.

import argparse
import hashlib
import struct
import subprocess
import sys


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def gov_object_hash(parent_hash_hex, revision, time_, data_hex):
    ss = b""
    ss += bytes.fromhex(parent_hash_hex)[::-1].rjust(32, b"\x00")[:32]
    ss += struct.pack("<i", revision)
    ss += struct.pack("<q", time_)
    s = data_hex.lower().encode("ascii")
    ss += compact_size(len(s)) + s
    ss += b"\x00" * 32 + b"\xff\xff\xff\xff"
    ss += b"\x00" + b"\xff\xff\xff\xff"
    ss += b"\x00"
    return sha256d(ss)[::-1].hex()


# (expected displayed hash, time, data hex) — identical set/order to the C++
# tests/gov_vectors.hpp so the two compare the very same inputs.
VECS = [
    (
        "5966468c7703afe59d176277e289daa5836cd4131c1c488969852c2ff13e1129",
        1778694938,
        "7b22656e645f65706f6368223a313739333632353136302c226e616d65223a22323032362d30"
        "352d4d616b6544617368415361666553746f72654f6656616c7565222c227061796d656e745f"
        "61646472657373223a2258744b41534a62313378724e45796933356244503472576744346d4a"
        "6236734d3264222c227061796d656e745f616d6f756e74223a312c2273746172745f65706f63"
        "68223a313739313034393638302c2274797065223a312c2275726c223a2268747470733a2f2f"
        "7777772e6461736863656e7472616c2e6f72672f702f323032362d30352d4d616b6544617368"
        "415361666553746f72654f6656616c7565227d",
    ),
    (
        "8576a3dbc52f93b8c333ed7398b592d569dbaa2d7647ea3e143f07c949034939",
        1779840000,
        "7b22656e645f65706f6368223a313739353532353230302c226e616d65223a22425443426163"
        "6b706f72747356696a61795f3033222c227061796d656e745f61646472657373223a22587078"
        "65386e7a3359386646655265676d57444168515a383435445574334d595467222c227061796d"
        "656e745f616d6f756e74223a36302c2273746172745f65706f6368223a313737393834303030"
        "302c2274797065223a312c2275726c223a2268747470733a2f2f7777772e6461736863656e74"
        "72616c2e6f72672f702f4254434261636b706f72747356696a61795f3033227d",
    ),
    (
        "5f4cf00613a36bb9683830204cdb4228c6ab665c5b12eb7451881d9315cc815e",
        1786624552,
        "7b226e616d65223a22707368656e6d69632d6465762d646173682d6465736b746f702d736570"
        "74656d6265722d32303236222c227061796d656e745f61646472657373223a22586a646e5a42"
        "55656446347138457a6757574147735a72487465456745557962626f222c227061796d656e74"
        "5f616d6f756e74223a3235302e30302c2275726c223a2268747470733a2f2f7777772e646173"
        "6863656e7472616c2e6f72672f702f707368656e6d69632d6465762d646173682d6465736b74"
        "6f702d73657074656d6265722d32303236222c2273746172745f65706f6368223a3137383533"
        "37383333382c22656e645f65706f6368223a313738373837303733382c2274797065223a317d",
    ),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cpp-bin", required=True, help="path to the c2wallet-dash-test binary")
    args = ap.parse_args()

    oracle = [gov_object_hash("00" * 32, 1, t, d) for (_e, t, d) in VECS]
    # Self-check the oracle against the captured mainnet expectations first.
    for (expected, _t, _d), got in zip(VECS, oracle):
        if got != expected:
            print("ORACLE SELF-CHECK FAILED: %s != %s" % (got, expected), file=sys.stderr)
            return 2

    out = subprocess.check_output([args.cpp_bin, "--emit-gov-hashes"], text=True)
    cpp = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if len(cpp) != len(oracle):
        print("C++ emitted %d hashes, oracle has %d" % (len(cpp), len(oracle)), file=sys.stderr)
        return 1
    ok = True
    for i, (o, c) in enumerate(zip(oracle, cpp)):
        match = o == c
        ok = ok and match
        print("vector %d: python=%s cpp=%s  %s" % (i, o[:16], c[:16], "OK" if match else "MISMATCH"))
    if not ok:
        return 1
    print("gov_hash_python_oracle: C++ port matches the proven Python oracle byte-for-byte")
    return 0


if __name__ == "__main__":
    sys.exit(main())
