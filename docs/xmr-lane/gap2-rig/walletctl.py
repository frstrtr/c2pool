#!/usr/bin/env python3
# addresses (3 miner wallets + a tx-gen wallet) + premine + good-citizen tx generator; wallet-rpc 44950, daemon1 44901.
import sys, json, time, urllib.request
W = "http://127.0.0.1:44950/json_rpc"; D = "http://127.0.0.1:44901/json_rpc"
def rpc(url, method, params=None, tries=1):
    body = json.dumps({"jsonrpc":"2.0","id":"0","method":method,"params":params or {}}).encode(); last=None
    for _ in range(tries):
        try:
            r = json.load(urllib.request.urlopen(urllib.request.Request(url, body, {"Content-Type":"application/json"}), timeout=30))
            if "error" in r: last=r["error"]; time.sleep(1); continue
            return r.get("result", {})
        except Exception as e: last=str(e); time.sleep(1)
    raise RuntimeError(f"{method}: {last}")
def wallet_addr(name):
    try: rpc(W,"close_wallet")
    except Exception: pass
    try: rpc(W,"open_wallet",{"filename":name})
    except Exception: rpc(W,"create_wallet",{"filename":name,"language":"English"})
    return rpc(W,"get_address")["address"]
def setup():
    for n in "ABC":
        a = wallet_addr("miner"+n); open(f"/home/ubuntu/gap2-rig/addr{n}","w").write(a); print("miner", n, a[:16])
    a = wallet_addr("soakw")
    need = int(__import__("os").environ.get("PREMINE","0")) - rpc(D,"get_info")["height"]
    if need > 0: print("premine ->", rpc(D,"generateblocks",{"amount_of_blocks":need,"wallet_address":a},tries=5).get("height"))
def gen():
    a = wallet_addr("soakw"); ok=0; fail=0
    while True:
        try:
            rpc(W,"refresh")
            rpc(W,"transfer",{"destinations":[{"amount":1000000000000,"address":a}],"ring_size":16,"priority":0}); ok+=1
            if ok%5==0: print("[txgen] sent=%d"%ok, flush=True)
        except Exception as e:
            fail+=1
            if fail%10==1: print(f"[txgen] fail#{fail}: {e}", flush=True)
        time.sleep(15)
if __name__=="__main__": {"setup":setup,"gen":gen}[sys.argv[1]]()
