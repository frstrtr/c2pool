#!/usr/bin/env python3
# Every block above GEN on monerod 1's chain: height, block id, miner_tx blob (hex), outputs sum, reward.
import sys, json, urllib.request
port, gen = int(sys.argv[1]), int(sys.argv[2])
def rpc(m, p):
    r = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/json_rpc", data=json.dumps({"jsonrpc":"2.0","id":"0","method":m,"params":p}).encode(), headers={"Content-Type":"application/json"}), timeout=30)
    return json.loads(r.read())["result"]
tip = rpc("get_block_count", {})["count"] - 1
for h in range(gen, tip + 1):
    b = rpc("get_block", {"height": h})
    j = json.loads(b["json"]); mt = j["miner_tx"]
    outs = sum(o["amount"] for o in mt["vout"])
    blob = b["blob"]
    print(h, b["block_header"]["hash"], b["block_header"]["reward"], outs, len(mt["vout"]), mt.get("extra") and bytes(mt["extra"]).hex(), blob)
