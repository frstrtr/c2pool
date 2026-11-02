#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""ctest companion_scan_export_parity: the companion scan's <name>.utxos.json is
byte-identical to what tools/export_utxos.py writes for the same chain view.

The python exporter runs against tests/mock_dash_cli.py (the public fixture at
tip 2563986, its first row spent in the mempool, outputIndex-1 rows
non-coinbase); c2wallet-companion-scan-test --write-mock-export scans a scripted
dashd serving that same view through SourceDashd and writes the export."""
import argparse, os, subprocess, sys, tempfile

ap = argparse.ArgumentParser()
ap.add_argument("--cpp-bin", required=True)
ap.add_argument("--exporter", required=True)
ap.add_argument("--mock", required=True)
ap.add_argument("--fixture", required=True)
a = ap.parse_args()
with tempfile.TemporaryDirectory() as tmp:
    py_out = os.path.join(tmp, "python.utxos.json")
    cpp_out = os.path.join(tmp, "companion.utxos.json")
    env = dict(os.environ, MOCK_FIXTURE=a.fixture, DASH_CLI=f"{sys.executable} -I {a.mock}")
    print(subprocess.run([sys.executable, "-I", a.exporter, "XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u", py_out],
                         env=env, check=True, capture_output=True, text=True).stdout.strip())
    r = subprocess.run([a.cpp_bin, "--write-mock-export", cpp_out], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"FAIL: the companion writer refused: {r.stdout}{r.stderr}")
    py = open(py_out, "rb").read()
    cpp = open(cpp_out, "rb").read()
if py != cpp:
    n = next((i for i in range(min(len(py), len(cpp))) if py[i] != cpp[i]), min(len(py), len(cpp)))
    sys.exit(f"FAIL: {len(py)} B (python) vs {len(cpp)} B (companion), first difference at byte {n}:\n"
             f"  python:    {py[max(0, n - 40):n + 40]!r}\n  companion: {cpp[max(0, n - 40):n + 40]!r}")
print(f"PASS: {len(cpp)} bytes, identical to tools/export_utxos.py")
