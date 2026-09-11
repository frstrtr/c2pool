#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
#
# C4 template-parity capture. READ-ONLY, paced, and the only thing in this
# component that ever touches a daemon.
#
# Usage:
#   python3 capture_miner_data.py [rpc_url] [first_height] > capture.json
#
#   rpc_url       default http://127.0.0.1:38081/json_rpc (a stagenet daemon)
#   first_height  the lowest header to fetch. Default 2203288, which is the
#                 xmr_c2a_golden.hpp TEST_FIRST: the C4 golden's chain rows
#                 start there so the 100 000-entry long-term weight window can
#                 be seeded from that golden and rolled forward, instead of
#                 re-captured (500 more paged calls against someone's daemon).
#
# The output feeds src/impl/xmr/native/test/gen_c4_parity_golden.py, which turns
# it into the checked-in golden header. What is captured:
#
#   get_miner_data           the whole response, verbatim -- the seven fields the
#                            native arm must reproduce, in the daemon's own
#                            encoding (note `difficulty` arrives as a HEX STRING).
#   get_block_headers_range  the rows below the tip, in 200-header pages with a
#                            0.4 s pause between them. Each row carries the
#                            daemon's own difficulty, cumulative difficulty,
#                            block weight, long-term weight, reward and block id.
#   get_info                 the daemon version and network, so the golden can
#                            say which monerod it was judged against.
#
# The capture is ordered miner_data FIRST, then headers up to (height - 1), and
# the generator asserts the last header is exactly that height - a tip that
# moved mid-capture is rejected rather than silently stitched.

import json, urllib.request, time, sys

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:38081/json_rpc"
FIRST_DEFAULT = int(sys.argv[2]) if len(sys.argv) > 2 else 2203288

def rpc(method, params=None):
    body = {"jsonrpc":"2.0","id":"0","method":method}
    if params is not None: body["params"] = params
    req = urllib.request.Request(URL, data=json.dumps(body).encode(),
                                 headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())

out = {}
md = rpc("get_miner_data")
out["miner_data_raw"] = md
h = md["result"]["height"]          # tip + 1
print("miner_data height", h, file=sys.stderr)
FIRST = FIRST_DEFAULT
hdrs = []
lo = FIRST
while lo <= h - 1:
    hi = min(lo + 199, h - 1)
    r = rpc("get_block_headers_range", {"start_height": lo, "end_height": hi})
    for b in r["result"]["headers"]:
        hdrs.append({
            "height": b["height"], "major_version": b["major_version"],
            "minor_version": b["minor_version"], "timestamp": b["timestamp"],
            "difficulty": b["difficulty"], "difficulty_top64": b.get("difficulty_top64",0),
            "cumulative_difficulty": b["cumulative_difficulty"],
            "cumulative_difficulty_top64": b.get("cumulative_difficulty_top64",0),
            "block_weight": b["block_weight"], "long_term_weight": b["long_term_weight"],
            "reward": b["reward"], "num_txes": b["num_txes"],
            "hash": b["hash"], "prev_hash": b["prev_hash"],
        })
    lo = hi + 1
    time.sleep(0.4)
out["headers"] = hdrs
print("headers", len(hdrs), hdrs[0]["height"], hdrs[-1]["height"], file=sys.stderr)
out["info"] = rpc("get_info")["result"]
try:
    out["txpool_backlog"] = rpc("get_txpool_backlog")["result"]
except Exception as e:
    out["txpool_backlog"] = {"error": str(e)}
print(json.dumps(out))
