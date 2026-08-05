#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate the W1 DASH replay-fold KAT fixtures (test/data/dash_replay_*.inc)
from dashd RPC captures.

The fold engine (src/impl/dash/coin/replay_fold_engine.hpp) is KAT'd against
REAL mainnet chain bytes: a full-state pre-list at an anchor height, raw block
bodies folded over it, and the committed cbTx merkleRootMNList of every folded
block as the answer key. This tool converts the RPC captures into the .inc
string-literal fixtures the test TU (test/test_dash_replay_fold.cpp) embeds.

Capture recipe (dashd v23, any synced mainnet node):

    dash-cli protx list registered true <H>      > list_<H>.json
    dash-cli protx diff 1 <H>                    > diff_<H>.json
    dash-cli getblock $(dash-cli getblockhash <H+1>) 0 > block_<H+1>.hex
    dash-cli quorum info <llmqType> <quorumHash> > quorum_<...>.json   # per
        non-null qfcommit inside a folded block (member order = bitset order)

Then:

    python3 tools/dash/gen_replay_kat.py prestate \
        --list list_<H>.json --diff diff_<H>.json --height <H> \
        --symbol kDashReplayPrestate<H> --out test/data/dash_replay_prestate_<H>.inc
    python3 tools/dash/gen_replay_kat.py block \
        --hex block_<H+1>.hex --symbol kDashReplayBlock<H+1> \
        --out test/data/dash_replay_block_<H+1>.inc
    python3 tools/dash/gen_replay_kat.py quorum \
        --info quorum_<...>.json --symbol kDashReplayQuorumMembers<...> \
        --out test/data/dash_replay_quorum_<...>.inc

Field conventions in the prestate fixture (format `c2pool-dash-replay-prestate/1`):

  * EVERY hash/hex field on `mn` lines is RAW WIRE BYTES (uint256/uint160
    fields are therefore the REVERSE of the RPC display hex). The C++ parser
    is a dumb hex->memcpy; no byte-order decisions live in the test.
  * Heights use dashd's SIGNED int semantics verbatim: -1 = never/not banned.
  * `-` = absent/empty field.
  * The header's `blockhash`/`mnroot` stay in RPC DISPLAY hex — they are
    compared against uint256::GetHex() (which is display order) in the test.
  * internalId is assigned in (registeredHeight, proTxHash) order and
    total_registered_count = count. NEITHER affects the SML root or any W1
    fold output; the exact chain values are only derivable by the Phase-2
    genesis replay (design doc §4.5), which will supersede this assignment.

The pre-list root parity (fixture entries -> DIP-4 root == `mnroot` ==
committed cbTx root at <H>) is asserted BOTH here at generation time and
again in the C++ KAT, so a conversion bug in this tool cannot ship a fixture
that silently tests nothing.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_mn_checkpoint import (  # noqa: E402
    address_to_keyid_hex,
    address_to_script,
    is_hex_n,
)

# Dash MAINNET base58 version bytes (chainparams.cpp): P2PKH 76 ('X'), P2SH 16.
MAINNET_PUBKEY_VER = 76
MAINNET_P2SH_VER = 16

EVO_STRINGS = ("Evo", "HighPerformance")


def die(msg):
    sys.stderr.write("gen_replay_kat: %s\n" % msg)
    sys.exit(1)


def rev_hex(display_hex):
    """RPC display hex (byte-reversed) -> raw wire-byte hex."""
    return bytes.fromhex(display_hex)[::-1].hex()


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def service_to_ip_port(svc):
    """dashd service string -> (16-byte ip, port). IPv4 maps to ::ffff:a.b.c.d,
    exactly the CService wire encoding the SML entry hashes."""
    if not svc:
        return b"\x00" * 16, 0
    if svc.startswith("["):
        host, port = svc[1:].split("]:")
        return ipaddress.IPv6Address(host).packed, int(port)
    host, port = svc.rsplit(":", 1)
    try:
        return (b"\x00" * 10 + b"\xff\xff"
                + ipaddress.IPv4Address(host).packed), int(port)
    except ipaddress.AddressValueError:
        return ipaddress.IPv6Address(host).packed, int(port)


def operator_reward_bp(v):
    if not isinstance(v, (int, float)):
        return 0
    x = float(v) * 100.0
    return int(x + 0.5) if x >= 0 else -int(-x + 0.5)


def entry_sml_hash(rec):
    """CSimplifiedMNListEntry::CalcHash over a merged record (wire-byte
    fields), mirroring vendor/simplifiedmns.hpp bit for bit."""
    b = b""
    b += bytes.fromhex(rec["proTxHash_wire"])
    b += bytes.fromhex(rec["confirmedHash_wire"])
    b += bytes.fromhex(rec["ip_hex"])
    b += struct.pack(">H", rec["port"])
    b += bytes.fromhex(rec["pubKeyOperator"])
    b += bytes.fromhex(rec["keyIDVoting"])
    b += b"\x01" if rec["isValid"] else b"\x00"
    if rec["nVersion"] >= 2:
        b += struct.pack("<H", rec["nType"])
        if rec["nType"] == 1:
            if rec["nVersion"] < 3:
                b += struct.pack("<H", rec["platformHTTPPort"])
            b += bytes.fromhex(rec["platformNodeID_wire"])
    return sha256d(b)


def merkle_root(leaves):
    if not leaves:
        return b"\x00" * 32
    h = list(leaves)
    while len(h) > 1:
        if len(h) & 1:
            h.append(h[-1])
        h = [sha256d(h[i] + h[i + 1]) for i in range(0, len(h), 2)]
    return h[0]


def c_literal(line):
    out = []
    for ch in line:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        else:
            o = ord(ch)
            if o < 0x20 or o > 0x7E:
                die("non-printable character %r in fixture line" % ch)
            out.append(ch)
    return '"%s\\n"' % "".join(out)


def write_inc(path, symbol, lines, preamble):
    with open(path, "w") as f:
        f.write("// SPDX-License-Identifier: AGPL-3.0-or-later\n")
        f.write("//\n")
        f.write("// GENERATED FILE -- DO NOT EDIT BY HAND.\n")
        f.write("// Produced by tools/dash/gen_replay_kat.py from dashd RPC"
                " captures.\n")
        for p in preamble:
            f.write("// %s\n" % p)
        f.write("\n")
        f.write("static const char %s[] =\n" % symbol)
        for ln in lines:
            f.write("    %s\n" % c_literal(ln))
        f.write("    ;\n")


def _platform_p2p_port(state):
    eps = (state.get("addresses") or {}).get("platform_p2p") or []
    if not eps:
        return 0
    return int(eps[0].rsplit(":", 1)[1])


def cmd_prestate(args):
    with open(args.list) as f:
        plist = json.load(f)
    with open(args.diff) as f:
        pdiff = json.load(f)
    if not isinstance(plist, list) or not plist:
        die("--list is not a non-empty protx list")
    diff_by_protx = {e["proRegTxHash"]: e for e in pdiff.get("mnList", [])}
    if len(diff_by_protx) != len(plist):
        die("protx list carries %d MNs but protx diff carries %d — the two "
            "captures are not the same height" % (len(plist), len(diff_by_protx)))

    height = args.height
    blockhash = pdiff.get("blockHash", "")
    mnroot = pdiff.get("merkleRootMNList", "")
    if not is_hex_n(blockhash, 64) or not is_hex_n(mnroot, 64):
        die("protx diff lacks blockHash/merkleRootMNList")

    records = []
    for e in plist:
        protx = e["proTxHash"].lower()
        d = diff_by_protx.get(protx)
        if d is None:
            die("proTx %s is in the list but not the diff" % protx)
        s = e["state"]
        nversion = d.get("nVersion")
        if s.get("version") != nversion:
            die("proTx %s: state version %r != diff nVersion %r"
                % (protx, s.get("version"), nversion))
        ntype = 1 if e.get("type", "Regular") in EVO_STRINGS else 0
        if d.get("nType", 0) != ntype:
            die("proTx %s: list type %d != diff nType %r"
                % (protx, ntype, d.get("nType", 0)))
        ip, port = service_to_ip_port(s.get("service", ""))
        pubkey = (s.get("pubKeyOperator") or "").lower()
        if not is_hex_n(pubkey, 96):
            die("proTx %s: bad pubKeyOperator" % protx)
        if pubkey != (d.get("pubKeyOperator") or "").lower():
            die("proTx %s: list/diff pubKeyOperator disagree" % protx)
        voting = address_to_keyid_hex(s["votingAddress"])
        owner = address_to_keyid_hex(s["ownerAddress"])
        payout = address_to_script(s["payoutAddress"], MAINNET_PUBKEY_VER,
                                   MAINNET_P2SH_VER).hex()
        op_addr = s.get("operatorPayoutAddress", "")
        script_op = (address_to_script(op_addr, MAINNET_PUBKEY_VER,
                                       MAINNET_P2SH_VER).hex()
                     if op_addr else "-")
        node_id = d.get("platformNodeID", "")
        rec = {
            "proTxHash_wire": rev_hex(protx),
            "confirmedHash_wire": rev_hex(d["confirmedHash"]),
            "ip_hex": ip.hex(),
            "port": port,
            "pubKeyOperator": pubkey,
            "keyIDVoting": voting,
            "keyIDOwner": owner,
            "isValid": bool(d["isValid"]),
            "nVersion": nversion,
            "nType": ntype,
            "platformNodeID_wire": rev_hex(node_id) if node_id else "",
            # v23 protx JSON has no scalar platformP2PPort; it lives in the
            # addresses.platform_p2p endpoint. Not under the SML root — only
            # carried so ProUpServTx folds have a faithful baseline.
            "platformP2PPort": _platform_p2p_port(s),
            "platformHTTPPort": (d.get("platformHTTPPort",
                                       s.get("platformHTTPPort", 0)) or 0),
            "operatorRewardBps": operator_reward_bp(e.get("operatorReward")),
            "scriptPayout": payout,
            "scriptOperatorPayout": script_op,
            "registeredHeight": s.get("registeredHeight", -1),
            "lastPaidHeight": s.get("lastPaidHeight", 0),
            "consecutivePayments": s.get("consecutivePayments", 0),
            "poSePenalty": s.get("PoSePenalty", 0),
            "poSeBanHeight": s.get("PoSeBanHeight", -1),
            "poSeRevivedHeight": s.get("PoSeRevivedHeight", -1),
            "revocationReason": s.get("revocationReason", 0),
            "collateralHash_wire": rev_hex(e["collateralHash"]),
            "collateralIndex": e.get("collateralIndex", 0),
        }
        # dashd RPC and the SML agree on ban semantics: isValid XOR banned.
        if rec["isValid"] != (rec["poSeBanHeight"] == -1):
            die("proTx %s: diff isValid=%r but list PoSeBanHeight=%d"
                % (protx, rec["isValid"], rec["poSeBanHeight"]))
        records.append(rec)

    # Generation-time parity: the merged records MUST reproduce the committed
    # merkleRootMNList before they are allowed to become a fixture.
    leaves = [entry_sml_hash(r) for r in
              sorted(records, key=lambda r: bytes.fromhex(r["proTxHash_wire"]))]
    got = merkle_root(leaves)[::-1].hex()
    if got != mnroot.lower():
        die("fixture would NOT reproduce the committed root at h=%d:\n"
            "  computed  %s\n  committed %s" % (height, got, mnroot))

    # internalId: (registeredHeight, wire proTxHash) order — see module doc.
    order = sorted(range(len(records)),
                   key=lambda i: (records[i]["registeredHeight"],
                                  records[i]["proTxHash_wire"]))
    for internal_id, i in enumerate(order):
        records[i]["internalId"] = internal_id

    lines = [
        "c2pool-dash-replay-prestate/1",
        "network mainnet",
        "height %d" % height,
        "blockhash %s" % blockhash.lower(),
        "mnroot %s" % mnroot.lower(),
        "count %d" % len(records),
    ]
    for r in sorted(records, key=lambda r: r["proTxHash_wire"]):
        lines.append(" ".join(str(x) for x in [
            "mn",
            r["proTxHash_wire"],
            r["confirmedHash_wire"] if int(r["confirmedHash_wire"], 16) else "-",
            r["ip_hex"],
            r["port"],
            r["pubKeyOperator"] if int(r["pubKeyOperator"], 16) else "-",
            r["keyIDVoting"],
            r["keyIDOwner"],
            r["nVersion"],
            r["nType"],
            r["platformNodeID_wire"] or "-",
            r["platformP2PPort"],
            r["platformHTTPPort"],
            r["operatorRewardBps"],
            r["scriptPayout"],
            r["scriptOperatorPayout"],
            r["registeredHeight"],
            r["lastPaidHeight"],
            r["consecutivePayments"],
            r["poSePenalty"],
            r["poSeBanHeight"],
            r["poSeRevivedHeight"],
            r["revocationReason"],
            r["collateralHash_wire"],
            r["collateralIndex"],
            r["internalId"],
        ]))
    write_inc(args.out, args.symbol, lines, [
        "Full-state DML pre-list at mainnet h=%d." % height,
        "Root parity vs the committed cbTx merkleRootMNList was verified at",
        "generation time; the KAT re-verifies it before every fold.",
    ])
    print("wrote %s (%d MNs, root %s ✓)" % (args.out, len(records), got[:16]))


def cmd_block(args):
    with open(args.hex) as f:
        block_hex = f.read().strip()
    if not block_hex or any(c not in "0123456789abcdefABCDEF" for c in block_hex):
        die("--hex is not a raw block hex dump")
    block_hex = block_hex.lower()
    # Chunk into fixed-width lines; the C++ side strips newlines.
    width = 512
    lines = [block_hex[i:i + width] for i in range(0, len(block_hex), width)]
    write_inc(args.out, args.symbol, lines, [
        "Raw mainnet block body (dash-cli getblock <hash> 0), %d bytes."
        % (len(block_hex) // 2),
    ])
    print("wrote %s (%d bytes)" % (args.out, len(block_hex) // 2))


def cmd_quorum(args):
    with open(args.info) as f:
        q = json.load(f)
    members = q.get("members")
    if not isinstance(members, list) or not members:
        die("--info carries no members[]")
    lines = [
        "c2pool-dash-replay-quorum/1",
        "llmqType %d" % args.llmq_type,
        "quorumHash %s" % q["quorumHash"].lower(),
        "count %d" % len(members),
    ]
    # Member order in `quorum info` IS the deterministic DKG order the
    # commitment's validMembers bitset indexes.
    for m in members:
        lines.append("member %s %d" % (rev_hex(m["proTxHash"]),
                                       1 if m.get("valid") else 0))
    write_inc(args.out, args.symbol, lines, [
        "Ordered quorum member set (dash-cli quorum info), index-aligned",
        "with the mined commitment's validMembers bitset.",
    ])
    print("wrote %s (%d members)" % (args.out, len(members)))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("prestate")
    p.add_argument("--list", required=True)
    p.add_argument("--diff", required=True)
    p.add_argument("--height", type=int, required=True)
    p.add_argument("--symbol", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_prestate)

    p = sub.add_parser("block")
    p.add_argument("--hex", required=True)
    p.add_argument("--symbol", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_block)

    p = sub.add_parser("quorum")
    p.add_argument("--info", required=True)
    p.add_argument("--llmq-type", type=int, required=True)
    p.add_argument("--symbol", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_quorum)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
