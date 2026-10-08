#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
#
# Regenerates xmr_tx_weight_golden.hpp from a live monerod.
#
#   ./gen_tx_weight_golden.py http://127.0.0.1:38081 xmr_tx_weight_golden.hpp
#
# It scans several height bands backwards from the tip, collecting every block
# that carries at least one transaction until it has enough, then fetches each
# transaction twice: once unpruned (for the true blob size) and once pruned (for
# the prefix + rct base bytes the native node actually receives when it syncs
# with prune=true).
#
# The only number in the emitted header that this repository does not compute is
# GoldenBlock::block_weight, taken from the daemon's own block header. That is
# deliberate: it is the independent pin the KAT checks the computed per-tx
# weights against.
#
# This script is documentation and a regeneration path. It is NOT run by the
# build; the generated header is checked in, because CI has no daemon.

import json
import sys
import urllib.request

TARGET_TXS = 240
BANDS_BACK = [0, 100000, 300000, 500000, 800000, 1100000, 1300000]

HEADER = """// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_tx_weight_golden.hpp   -- GENERATED, DO NOT EDIT
//
// Real Monero transactions captured from a live stagenet daemon, with the
// numbers monerod itself reports, for the consensus tx-weight KAT.
//
//   source daemon   : monerod %s (%s)
//   captured at tip : %d
//   regenerate with : src/impl/xmr/native/test/gen_tx_weight_golden.py
//
// The independent, monerod-authoritative number in this file is
// GoldenBlock::block_weight: it comes from the daemon's own block header and is
// NOT computed by anything in this repository. Because a block's weight is the
// coinbase weight plus the weight of every transaction in it, that one number
// pins the per-transaction weights below -- exactly, for the %d blocks that
// carry a single transaction, and as a sum for the rest.
//
// pruned_hex is the blob monerod returns for get_transactions with prune=true:
// the transaction prefix plus the rct base, which is all a node syncing with
// prune=true (pinned decision D-4) ever receives. full_size and prunable_size
// come from the unpruned fetch, so the KAT can check that the prunable length
// RECONSTRUCTED from structure matches the bytes that actually exist.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>

namespace c2pool::xmr::native::golden {

inline constexpr const char* MONEROD_VERSION = "%s";
inline constexpr const char* NETWORK         = "%s";
inline constexpr std::uint64_t CAPTURE_TIP   = %d;

struct GoldenTx {
    const char*   id_hex;
    const char*   pruned_hex;    // prefix + rct base, exactly as monerod prunes it
    std::uint32_t full_size;     // bytes of the complete blob
    std::uint32_t prunable_size; // full_size - pruned bytes
    std::uint32_t weight;        // consensus weight = full_size + clawback
    std::uint8_t  rct_type;
    std::uint16_t n_inputs;
    std::uint16_t n_outputs;
    std::uint16_t ring_size;     // 0 for a coinbase
};

struct GoldenBlock {
    std::uint64_t height;
    std::uint32_t block_weight;   // from monerod, the independent pin
    std::uint8_t  major_version;
    std::uint32_t tx_begin;       // first non-coinbase tx index in TXS
    std::uint32_t tx_count;       // number of non-coinbase transactions
    std::uint32_t miner_index;    // index of this block's coinbase in TXS
};

struct GoldenFullTx {
    const char*   id_hex;
    const char*   full_hex;
    std::uint32_t weight;
};

"""


def make_rpc(base):
    def rpc(method, params=None):
        body = json.dumps({"jsonrpc": "2.0", "id": "0",
                           "method": method, "params": params or {}}).encode()
        req = urllib.request.Request(base + "/json_rpc", body,
                                     {"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=30))["result"]

    def raw(path, params):
        body = json.dumps(params).encode()
        req = urllib.request.Request(base + path, body,
                                     {"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=60))

    return rpc, raw


def next_pow2(n):
    m = 1
    while m < n:
        m <<= 1
    return m


def clawback(rct_type, n_out):
    """monerod get_transaction_weight_clawback, reimplemented for the golden."""
    if rct_type not in (3, 4, 5, 6):
        return 0
    m = next_pow2(max(n_out, 1))
    if m <= 2:
        return 0
    fields = 6 if rct_type == 6 else 9
    bp_base = (32 * (fields + 14)) // 2
    nlr = 0
    while (1 << nlr) < m:
        nlr += 1
    nlr += 6
    bp_size = 32 * (fields + 2 * nlr)
    return (bp_base * m - bp_size) * 4 // 5


def capture(base):
    rpc, raw = make_rpc(base)
    info = rpc("get_info")
    tip = info["height"] - 1
    blocks, total = [], 0
    for back in BANDS_BACK:
        h, got, scanned = tip - back, 0, 0
        while got < 40 and scanned < 900 and total < TARGET_TXS and h > 10:
            hdr = rpc("get_block", {"height": h})
            bh = hdr["block_header"]
            if bh["num_txes"]:
                blocks.append({"height": h, "block_weight": bh["block_weight"],
                               "major_version": bh["major_version"],
                               "miner_tx_hash": bh["miner_tx_hash"],
                               "tx_hashes": hdr.get("tx_hashes", [])})
                got += bh["num_txes"]
                total += bh["num_txes"]
            h -= 1
            scanned += 1
        if total >= TARGET_TXS:
            break

    ids = []
    for b in blocks:
        ids += b["tx_hashes"] + [b["miner_tx_hash"]]

    txs = {}
    for i in range(0, len(ids), 40):
        chunk = ids[i:i + 40]
        full = raw("/get_transactions",
                   {"txs_hashes": chunk, "decode_as_json": True, "prune": False})
        pruned = raw("/get_transactions", {"txs_hashes": chunk, "prune": True})
        pmap = {t["tx_hash"]: t.get("pruned_as_hex", "") for t in pruned.get("txs", [])}
        for t in full.get("txs", []):
            j = json.loads(t["as_json"])
            ring = [len(v.get("key", {}).get("key_offsets", [])) for v in j["vin"]]
            txs[t["tx_hash"]] = {
                "pruned_hex": pmap.get(t["tx_hash"], ""),
                "full_hex": t.get("as_hex", ""),
                "full_len": len(t.get("as_hex", "")) // 2,
                "rct_type": (j.get("rct_signatures") or {}).get("type", 0),
                "n_vin": len(j["vin"]),
                "n_vout": len(j["vout"]),
                "ring": ring,
            }
    return info, tip, sorted(blocks, key=lambda b: b["height"]), txs


def main():
    if len(sys.argv) != 3:
        print(__doc__ or "usage: gen_tx_weight_golden.py <daemon-url> <out.hpp>")
        return 1
    base, out_path = sys.argv[1], sys.argv[2]
    info, tip, blocks, txs = capture(base)

    rows, gblocks = [], []
    for b in blocks:
        begin = len(rows)
        for h in b["tx_hashes"]:
            t = txs[h]
            pruned_len = len(t["pruned_hex"]) // 2
            rows.append((h, t["pruned_hex"], t["full_len"],
                         t["full_len"] - pruned_len,
                         t["full_len"] + clawback(t["rct_type"], t["n_vout"]),
                         t["rct_type"], t["n_vin"], t["n_vout"],
                         t["ring"][0] if t["ring"] else 0))
        mh = b["miner_tx_hash"]
        mt = txs[mh]
        mlen = len(mt["pruned_hex"]) // 2      # a coinbase has no prunable part
        miner_index = len(rows)
        rows.append((mh, mt["pruned_hex"], mlen, 0, mlen,
                     mt["rct_type"], mt["n_vin"], mt["n_vout"], 0))
        gblocks.append((b["height"], b["block_weight"], b["major_version"],
                        begin, len(b["tx_hashes"]), miner_index))

    # a few complete blobs for the full-blob parse path
    pool = sorted(((h, t) for h, t in txs.items()
                   if t["rct_type"] in (5, 6) and t["full_hex"]),
                  key=lambda kv: (kv[1]["rct_type"], kv[1]["n_vout"], kv[1]["n_vin"]))
    picked, seen = [], set()
    for h, t in pool:
        key = (t["rct_type"], t["n_vout"], min(t["n_vin"], 3))
        if key not in seen:
            seen.add(key)
            picked.append((h, t))
    for h, t in pool:
        if t["n_vin"] >= 9 and all(h != p[0] for p in picked):
            picked.append((h, t))
    picked = picked[:12]

    single = sum(1 for g in gblocks if g[4] == 1)
    with open(out_path, "w") as f:
        f.write(HEADER % (info["version"], info["nettype"], tip, single,
                          info["version"], info["nettype"], tip))
        f.write("inline constexpr GoldenTx TXS[] = {\n")
        for r in rows:
            f.write('    { "%s", "%s", %d, %d, %d, %d, %d, %d, %d },\n' % r)
        f.write("};\n\ninline constexpr GoldenBlock BLOCKS[] = {\n")
        for g in gblocks:
            f.write("    { %d, %d, %d, %d, %d, %d },\n" % g)
        f.write("};\n\n// Complete blobs, for the full-blob parse path (the pruned"
                " path above\n// never sees these bytes).\n")
        f.write("inline constexpr GoldenFullTx FULL_TXS[] = {\n")
        for h, t in picked:
            f.write('    { "%s", "%s", %d },\n'
                    % (h, t["full_hex"],
                       t["full_len"] + clawback(t["rct_type"], t["n_vout"])))
        f.write("};\n\n")
        f.write("inline constexpr std::size_t TX_COUNT       = sizeof(TXS) / sizeof(TXS[0]);\n")
        f.write("inline constexpr std::size_t BLOCK_COUNT    = sizeof(BLOCKS) / sizeof(BLOCKS[0]);\n")
        f.write("inline constexpr std::size_t FULL_TX_COUNT  = sizeof(FULL_TXS) / sizeof(FULL_TXS[0]);\n\n")
        f.write("} // namespace c2pool::xmr::native::golden\n")

    print("captured %d blocks, %d transactions (%d non-coinbase) -> %s"
          % (len(gblocks), len(rows), sum(g[4] for g in gblocks), out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
