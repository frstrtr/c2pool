#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""ctest export_utxos_roundtrip: run tools/export_utxos.py against the mock
dash-cli (the public fixture), then import its output through DashInjectModel
(c2wallet-dash-test --import-file) and check what the model saw."""
import argparse, os, subprocess, sys, tempfile

ap = argparse.ArgumentParser()
ap.add_argument("--cpp-bin", required=True)
ap.add_argument("--exporter", required=True)
ap.add_argument("--fixture", required=True)
a = ap.parse_args()
here = os.path.dirname(os.path.abspath(__file__))
with tempfile.TemporaryDirectory() as tmp:
    out = os.path.join(tmp, "xdgf.export.json")
    env = dict(os.environ, MOCK_FIXTURE=a.fixture,
               DASH_CLI=f"{sys.executable} -I {os.path.join(here, 'mock_dash_cli.py')}")
    print(subprocess.run([sys.executable, "-I", a.exporter, "XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u", out],
                         env=env, check=True, capture_output=True, text=True).stdout.strip())
    r = subprocess.run([a.cpp_bin, "--import-file", out], capture_output=True, text=True)
print(r.stdout + r.stderr)
want = ["c2wallet export v1", "UTXOs:           169, 0.60927215 DASH", "coinbase flags:  present",
        "tip height:      2563986", "spendable: 127 UTXOs", "dust:      42 UTXOs"]
missing = [w for w in want if w not in r.stdout]
if r.returncode != 0 or missing:
    sys.exit(f"FAIL rc={r.returncode} missing={missing}")
print("PASS export_utxos.py -> DashInjectModel round trip")
