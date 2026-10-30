#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A stand-in dash-cli for the export_utxos.py round-trip ctest. Serves the
public getaddressutxos fixture ($MOCK_FIXTURE) at tip 2563986: every outputIndex-1
row is non-coinbase, the first row (by height) is reported spent in the mempool
(gettxout prints nothing), every other row is coinbase."""
import json, os, sys

TIP = 2563986
cmd, args = sys.argv[1], sys.argv[2:]
rows = json.load(open(os.environ["MOCK_FIXTURE"]))
first = min(rows, key=lambda u: (u["height"], u["txid"], u["outputIndex"]))
if cmd == "getblockchaininfo":
    print(json.dumps({"chain": "main", "blocks": TIP}))
elif cmd == "getblockcount":
    print(TIP)
elif cmd == "getblockhash":
    print("0000000000000012" + "ab" * 24)
elif cmd == "getaddressutxos":
    assert json.loads(args[0])["addresses"] == [rows[0]["address"]]
    print(json.dumps(rows))
elif cmd == "gettxout":
    txid, n = args[0], int(args[1])
    if (txid, n) != (first["txid"], first["outputIndex"]):
        print(json.dumps({"confirmations": 1, "coinbase": n != 1}))
else:
    sys.exit("mock dash-cli: unsupported " + cmd)
