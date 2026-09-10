import json, subprocess
def cli(*a): return subprocess.check_output(["dash-cli",*a], text=True)
LO,HI=2535178,2536177; DUFF=100000000
tot=old=ntx=nold=0
for h in range(LO,HI+1):
    b=json.loads(cli("getblock",cli("getblockhash",str(h)).strip(),"3")); thr=h-288
    for t in b["tx"]:
        vin=t.get("vin",[])
        if not vin or any(("coinbase" in v or "prevout" not in v) for v in vin): continue
        insum=sum(v["prevout"]["value"] for v in vin); outsum=sum(o["value"] for o in t["vout"])
        fee=round((insum-outsum)*DUFF)
        if fee<0: continue
        tot+=fee; ntx+=1
        if any(v["prevout"]["height"]<thr for v in vin): old+=fee; nold+=1
    if h%250==0: print(f"...h={h} tot={tot} old={old}", flush=True)
print(f"RESULT blocks={HI-LO+1} txs={ntx} total_fee_duffs={tot} oldcoin_fee_duffs={old} oldcoin_frac={(old/tot if tot else 0):.4f} oldcoin_txs={nold} oldcoin_tx_frac={(nold/ntx if ntx else 0):.4f}")
