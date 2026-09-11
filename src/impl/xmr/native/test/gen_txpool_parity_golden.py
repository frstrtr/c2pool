#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
#
# Capture a real monerod /get_transaction_pool answer, plus the tip it was taken
# at, and emit it as xmr_txpool_parity_golden.hpp.
#
# WHY THE RAW RESPONSE AND NOT A PARSED TABLE. The KAT that consumes this file
# is the OFFLINE REPLAY of the M1 run: it parses this body with the same
# MonerodTxpoolRpc::parse the live probe uses, feeds the tx_blob of every entry
# into a real RelayedTxPool through IRelayedTxSink, and compares the two sides
# with the same compare_txpools. A pre-parsed table would test none of that --
# it would test that two arrays the generator wrote are equal.
#
# The one edit made to the daemon's bytes is that every entry's "tx_json" is
# removed: it is a rendering of tx_blob, nothing in the tree reads it, and it is
# roughly three times the size of everything the KAT does read. Nothing else is
# touched -- field order, spacing and every value are the daemon's own.
#
#   usage: gen_txpool_parity_golden.py <host:port> > xmr_txpool_parity_golden.hpp
import json
import subprocess
import sys


def rpc(host, path, body):
    out = subprocess.run(
        ["curl", "-s", "http://%s%s" % (host, path),
         "-H", "Content-Type: application/json", "-d", body],
        capture_output=True, check=True).stdout.decode()
    return out


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: %s <host:port>\n" % sys.argv[0])
        return 2
    host = sys.argv[1]

    info = json.loads(rpc(host, "/json_rpc",
                          '{"jsonrpc":"2.0","id":"0","method":"get_info"}'))["result"]
    hdr = json.loads(rpc(host, "/json_rpc",
                         '{"jsonrpc":"2.0","id":"0","method":"get_last_block_header"}')
                     )["result"]["block_header"]
    raw = rpc(host, "/get_transaction_pool", "{}")
    doc = json.loads(raw)
    txs = doc.get("transactions", [])
    if not txs:
        sys.stderr.write("the daemon's pool is empty; nothing to capture\n")
        return 1
    for t in txs:
        t.pop("tx_json", None)
    body = json.dumps(doc, indent=1, sort_keys=True)
    if ')JSON"' in body:
        sys.stderr.write("the response would break the raw string literal\n")
        return 1

    print("// SPDX-License-Identifier: AGPL-3.0-or-later")
    print("// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)")
    print("//")
    print("// ---------------------------------------------------------------------------")
    print("// src/impl/xmr/native/test/xmr_txpool_parity_golden.hpp  -- GENERATED, DO NOT EDIT")
    print("//")
    print("// A real monerod /get_transaction_pool response, with the tip it was taken at.")
    print("// Every number in it is the daemon's own; nothing here was computed by this")
    print("// repository. The KAT replays it: it parses this body, feeds each entry's")
    print("// tx_blob into a RelayedTxPool through the relay sink, and asks the P-POOL")
    print("// comparator whether the two sides agree on {weight, fee, blob_size} per id.")
    print("//")
    print("// The only edit to the daemon's bytes is that each entry's \"tx_json\" was")
    print("// dropped: it is a rendering of tx_blob that nothing reads and that would")
    print("// treble the size of this file. See gen_txpool_parity_golden.py.")
    print("//")
    print("//   source daemon : monerod %s (%s)" % (info["version"], info["nettype"]))
    print("//   captured at   : height %d, top %s" % (hdr["height"], hdr["hash"]))
    print("//   transactions  : %d" % len(txs))
    print("// ---------------------------------------------------------------------------")
    print("#pragma once")
    print()
    print("#include <cstdint>")
    print()
    print("namespace c2pool::xmr::native::golden {")
    print()
    print('inline constexpr const char* TXPOOL_MONEROD_VERSION = "%s";' % info["version"])
    print('inline constexpr const char* TXPOOL_NETWORK         = "%s";' % info["nettype"])
    print("inline constexpr std::uint64_t TXPOOL_TIP_HEIGHT    = %d;" % hdr["height"])
    print('inline constexpr const char* TXPOOL_TIP_ID          = "%s";' % hdr["hash"])
    print('inline constexpr const char* TXPOOL_TIP_PREV_ID     = "%s";' % hdr["prev_hash"])
    print("inline constexpr std::size_t TXPOOL_TX_COUNT        = %d;" % len(txs))
    print()
    print("// The daemon's own numbers, lifted out so the KAT can assert that the parse")
    print("// recovered them rather than merely that it did not crash.")
    print("struct GoldenPoolTx {")
    print("    const char*   id_hex;")
    print("    std::uint64_t weight;")
    print("    std::uint64_t fee;")
    print("    std::uint64_t blob_size;")
    print("};")
    print()
    print("inline constexpr GoldenPoolTx TXPOOL_TXS[] = {")
    for t in sorted(txs, key=lambda x: x["id_hash"]):
        print('    { "%s", %d, %d, %d },'
              % (t["id_hash"], t["weight"], t["fee"], t["blob_size"]))
    print("};")
    print()
    print("inline constexpr const char* TXPOOL_POOL_JSON = R\"JSON(")
    print(body)
    print(")JSON\";")
    print()
    print("} // namespace c2pool::xmr::native::golden")
    return 0


if __name__ == "__main__":
    sys.exit(main())
