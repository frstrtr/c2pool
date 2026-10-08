#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
#
# Generator for xmr_input_consensus_golden.hpp: a COMMITTED, third-party
# reproducible corpus of real Monero mainnet RCT transactions together with the
# resolved (public key, commitment) of every ring member of every input, so the
# CLSAG ring-signature verifier can be checked against real signatures offline.
#
# What the node cannot obtain daemonlessly below its anchor -- the ring members
# behind an input's key offsets -- is exactly what this generator fetches from a
# monerod (get_outs) at capture time and freezes into the golden. The C++ KAT
# then decodes the transaction blob ITSELF (our decoder), computes the CLSAG
# message ITSELF, and only takes the ring members from the golden; the verdict
# is our code's, reproducible by anyone who reruns this generator against any
# monerod and diffs the result.
#
# Usage:
#   gen_input_consensus_golden.py <daemon-url> <out.hpp> [--blocks N] [--height H]
#
# The daemon may be a restricted public node: get_block, get_transactions and
# get_outs are all served by restricted RPC. No wallet, no secret keys.
import json
import sys
import urllib.request

def _post(url, path, body_obj):
    # Read the WHOLE body ourselves and json.loads it, with retries: a public
    # node can return an IncompleteRead on a large /get_transactions response,
    # and a keep-alive socket can be dropped mid-stream. Never let one flaky
    # read abort a capture.
    body = json.dumps(body_obj).encode()
    last = None
    for attempt in range(5):
        try:
            req = urllib.request.Request(url + path, data=body,
                                         headers={"Content-Type": "application/json",
                                                  "Connection": "close"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except Exception as e:            # noqa: BLE001 -- retry any transport error
            last = e
    # Always raise a concrete Exception instance: `last` is Optional and CodeQL
    # (py/illegal-raise) cannot prove the loop assigned it, so re-wrap rather
    # than `raise last` (which would raise None on the unreachable empty-loop
    # path). RuntimeError chains the last transport error for the operator.
    raise RuntimeError(
        "POST %s%s failed after 5 attempts: %r" % (url, path, last)) from last

def rpc_json(url, method, params):
    return _post(url, "/json_rpc",
                 {"jsonrpc": "2.0", "id": "0", "method": method, "params": params})["result"]

def get_height(url):
    return rpc_json(url, "get_info", {})["height"]

def get_block(url, h):
    return rpc_json(url, "get_block", {"height": h})

def get_transactions(url, hashes):
    # Chunk the request: a whole block of ~50 non-pruned txs is a big response
    # that some public nodes truncate. Fetch in small batches and concatenate.
    txs = []
    for i in range(0, len(hashes), 8):
        chunk = hashes[i:i + 8]
        got = _post(url, "/get_transactions",
                    {"txs_hashes": chunk, "decode_as_json": True, "prune": False})
        txs.extend(got.get("txs", []))
    return {"txs": txs}

def get_outs(url, amount_index_pairs):
    outs = [{"amount": 0, "index": idx} for idx in amount_index_pairs]
    return _post(url, "/get_outs", {"outputs": outs, "get_txid": True})["outs"]

def rel_to_abs(offsets):
    abs_off = []
    acc = 0
    for o in offsets:
        acc += o
        abs_off.append(acc)
    return abs_off

def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: gen_input_consensus_golden.py <daemon-url> <out.hpp>"
                         " [--blocks N] [--height H]\n")
        return 2
    url = sys.argv[1].rstrip("/")
    out_path = sys.argv[2]
    n_blocks = 2
    top = None
    max_txs = 24            # size discipline: cap the committed corpus
    a = sys.argv[3:]
    while a:
        if a[0] == "--blocks":
            n_blocks = int(a[1]); a = a[2:]
        elif a[0] == "--height":
            top = int(a[1]); a = a[2:]
        elif a[0] == "--max-txs":
            max_txs = int(a[1]); a = a[2:]
        else:
            a = a[1:]

    if top is None:
        # step back from the tip so every ring member is well below the tip and
        # safely spendable-age; the members themselves are older still.
        top = get_height(url) - 60
    tip_at_capture = get_height(url)

    txs_out = []
    for h in range(top - n_blocks + 1, top + 1):
        blk = get_block(url, h)
        tx_hashes = json.loads(blk["json"]).get("tx_hashes", [])
        if not tx_hashes:
            continue
        got = get_transactions(url, tx_hashes)
        for t in got.get("txs", []):
            js = json.loads(t["as_json"])
            # RCT type 6 == BulletproofPlus. Skip anything else (older types are
            # out of the native validator's accepted set anyway).
            rv = js.get("rct_signatures", {})
            if rv.get("type") != 6:
                continue
            vin = js["vin"]
            # collect all absolute offsets across inputs, resolve in one call
            per_input = []
            all_pairs = []
            for vi in vin:
                k = vi["key"]
                if int(k.get("amount", 0)) != 0:
                    per_input = None
                    break
                abso = rel_to_abs(k["key_offsets"])
                per_input.append({"k_image": k["k_image"], "offsets": abso})
                all_pairs.extend(abso)
            if per_input is None or not per_input:
                continue
            resolved = get_outs(url, all_pairs)
            # slice resolved back per input, in order
            idx = 0
            inputs_json = []
            ok = True
            for pi in per_input:
                members = []
                for _ in pi["offsets"]:
                    o = resolved[idx]; idx += 1
                    if not o.get("key") or not o.get("mask"):
                        ok = False; break
                    members.append({"dest": o["key"], "mask": o["mask"],
                                    "height": o.get("height", 0),
                                    "unlocked": bool(o.get("unlocked", True))})
                if not ok:
                    break
                inputs_json.append({"k_image": pi["k_image"],
                                    "offsets": pi["offsets"],
                                    "members": members})
            if not ok:
                continue
            txs_out.append({"id": t["tx_hash"], "full_hex": t["as_hex"],
                            "height": h, "inputs": inputs_json})
            if len(txs_out) >= max_txs:
                break
        if len(txs_out) >= max_txs:
            break

    emit(out_path, url, tip_at_capture, txs_out)
    sys.stderr.write("wrote %d txs (%d inputs) to %s\n" %
                     (len(txs_out), sum(len(x["inputs"]) for x in txs_out), out_path))
    return 0

def emit(path, url, tip, txs):
    L = []
    w = L.append
    w("// SPDX-License-Identifier: AGPL-3.0-or-later")
    w("// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)")
    w("//")
    w("// GENERATED by src/impl/xmr/native/test/gen_input_consensus_golden.py.")
    w("// Real Monero MAINNET RCT (BulletproofPlus) transactions plus the resolved")
    w("// (public key, commitment) of every ring member, captured from a monerod.")
    w("// The transaction blobs are public chain data; the file carries no key.")
    w("// Reproduce: rerun the generator against any monerod and diff.")
    w("//   source daemon reported tip at capture: %d" % tip)
    w("#pragma once")
    w("#include <cstdint>")
    w("#include <vector>")
    w("#include <string>")
    w("namespace c2pool::xmr::native::test {")
    w("struct GoldenMember { const char* dest; const char* mask; };")
    w("struct GoldenInput  { const char* k_image; std::vector<GoldenMember> members; };")
    w("struct GoldenTx     { const char* id; const char* full_hex; std::uint64_t height;"
      " std::vector<GoldenInput> inputs; };")
    w("inline const std::vector<GoldenTx>& input_consensus_golden() {")
    w("    static const std::vector<GoldenTx> g = {")
    for t in txs:
        w('        { "%s", "%s", %dULL, {' % (t["id"], t["full_hex"], t["height"]))
        for vi in t["inputs"]:
            w('            { "%s", {' % vi["k_image"])
            for m in vi["members"]:
                w('                { "%s", "%s" },' % (m["dest"], m["mask"]))
            w("            } },")
        w("        } },")
    w("    };")
    w("    return g;")
    w("}")
    w("} // namespace c2pool::xmr::native::test")
    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")

if __name__ == "__main__":
    sys.exit(main())
