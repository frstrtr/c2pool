import json
import os

data = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "coinbase.json")))

# full serialized output size = 8 (value) + 1 (varint scriptlen, all <253) + len(script_bytes)
def script_len(spk_hex):
    return len(spk_hex)//2
def out_size(o):
    return 8 + 1 + script_len(o["spk"])

pays = [o for o in data["vout"] if o["type"] not in ("op_return",)]
print(f"paying outputs: {len(pays)}  (n_paying field={data['n_paying']})")

# size by type (observed)
from collections import Counter, defaultdict
bytype = defaultdict(list)
for o in pays:
    bytype[o["type"]].append(out_size(o))
print("observed full-output sizes by type:")
for t,szs in bytype.items():
    print(f"  {t:12s} count={len(szs):2d} size={sorted(set(szs))} bytes")

total_out_bytes = sum(out_size(o) for o in pays) + sum(8+1+script_len(o['spk']) for o in data['vout'] if o['type']=='op_return')
total_pay_bytes = sum(out_size(o) for o in pays)
print(f"\ntotal paying-output bytes: {total_pay_bytes}")
print(f"approx coinbase vsize incl op_returns + ~50B overhead: ~{total_out_bytes+50} B")

# the 27-sat
m = min(pays, key=lambda o:o["value"])
print(f"\nsmallest paying output: {m['value']} sat type={m['type']} size={out_size(m)}B eff={m['value']/out_size(m):.3f} sat/B")
# next smallest
nxt = sorted(pays, key=lambda o:o["value"])[1]
print(f"next-smallest: {nxt['value']} sat type={nxt['type']} size={out_size(nxt)}B eff={nxt['value']/out_size(nxt):.2f} sat/B")

# --- Rule 0 replay at k in {1,10,50} sat/B (k = opportunity-cost per byte ~ fee_rate) ---
print("\n=== Rule 0 (T_floor(m)=k*size) replay: who DEFERS vs PAYS ===")
for k in [1,10,50,338,339]:
    deferred = [o for o in pays if o["value"] < k*out_size(o)]
    print(f"  k={k:4d} sat/B : deferred={len(deferred):2d}/{len(pays)}  " +
          (f"smallest-deferred={[ (o['value'],o['type']) for o in sorted(deferred,key=lambda x:x['value'])[:3] ]}" if deferred else "none"))

# k window pinned by THIS block: defer 27-sat (k>27/size_p2pk) but keep 11508 (k<=11508/34)
p2pk_size = out_size(m)
print(f"\nk lower bound (defer 27-sat P2PK, {p2pk_size}B): k > {27/p2pk_size:.4f} sat/B")
print(f"k upper bound (keep 11508 P2PKH 34B): k <= {11508/34:.2f} sat/B")

# Rule 2 efficiency ordering preview (top/bottom eff)
ranked = sorted(pays, key=lambda o:-(o["value"]/out_size(o)))
print(f"\nhighest eff: {ranked[0]['value']} sat {ranked[0]['type']} eff={ranked[0]['value']/out_size(ranked[0]):.1f}")
print(f"lowest  eff (paying): {ranked[-1]['value']} sat {ranked[-1]['type']} eff={ranked[-1]['value']/out_size(ranked[-1]):.3f}")

# P2PK compressed vs uncompressed note
print(f"\nP2PK actual spk first byte: 0x{m['spk'][:2]} (0x41=push65=UNCOMPRESSED) -> output {p2pk_size}B")
print(f"  compressed P2PK would be 8+1+35 = 44B (integrator's '~44B' assumed compressed)")
print(f"  eff uncompressed = {27/p2pk_size:.3f} sat/B ; eff if compressed-44B = {27/44:.3f} sat/B")
