#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""export_utxos.py ADDRESS OUT.json -- run on the ONLINE host next to dashd
(addressindex=1). Writes the c2wallet-utxo-export/1 file PageDashInject imports:
every UTXO of ADDRESS with its height, coinbase flag (gettxout) and the tip it was
counted at. Public data only. DASH_CLI overrides the command, e.g.
DASH_CLI="dash-cli -conf=/home/fanfan/.dashcore/dash.conf"."""
import json, os, shlex, subprocess, sys

CLI = shlex.split(os.environ.get("DASH_CLI", "dash-cli"))
def raw(*a): return subprocess.check_output(CLI + [str(x) for x in a]).decode().strip()
def cli(*a): return json.loads(raw(*a) or "null")

addr, out = sys.argv[1], sys.argv[2]
for _ in range(5):  # the tip must not move while the list is read
    info = cli("getblockchaininfo"); tip = info["blocks"]
    utxos = cli("getaddressutxos", json.dumps({"addresses": [addr]}))
    if cli("getblockcount") == tip: break
else: sys.exit("the tip kept moving; try again")
rows, spent = [], 0
for u in sorted(utxos, key=lambda u: (u["height"], u["txid"], u["outputIndex"])):
    t = cli("gettxout", u["txid"], u["outputIndex"], "true")
    if t is None: spent += 1; continue                       # spent in the mempool: leave it out
    rows.append({"txid": u["txid"], "vout": u["outputIndex"], "satoshis": int(u["satoshis"]),
                 "height": u["height"], "confirmations": tip - u["height"] + 1,
                 "coinbase": bool(t.get("coinbase", True)), "scriptPubKey": u["script"]})
doc = {"schema": "c2wallet-utxo-export/1", "coin": "dash",
       "network": "mainnet" if info["chain"] == "main" else "testnet",  # regtest/devnet use testnet addresses
       "address": addr, "tip_height": tip, "tip_hash": raw("getblockhash", tip), "utxos": rows}
with open(out, "w") as f: json.dump(doc, f, indent=1)
print(f"{len(rows)} utxos, {sum(r['satoshis'] for r in rows) / 1e8:.8f} DASH at tip {tip} ({info['chain']}); "
      f"{sum(r['coinbase'] for r in rows)} coinbase; {spent} spent in the mempool left out")
