#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate the W1 DASH replay-fold KAT fixtures (test/data/dash_replay_*.inc)
from dashd RPC captures.

The fold engine (src/impl/dash/coin/replay_fold_engine.hpp) is KAT'd against
REAL chain bytes (mainnet; testnet for Dash Core v24): a full-state pre-list
at an anchor height, raw block bodies folded over it, and the committed cbTx
merkleRootMNList of every folded block as the answer key. This tool converts
the RPC captures into the .inc string-literal fixtures the test TU
(test/test_dash_replay_fold.cpp) embeds.

Capture recipe (dashd v23 or v24, any synced node; a testnet capture takes
--network testnet on both commands below):

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

Format `c2pool-dash-replay-prestate/2` (Dash Core v24; the format
src/impl/dash/coin/replay_prestate.hpp reads) is emitted only when the list
holds a version-3 state; a list without one is still written as /1, byte for
byte as before. /2 appends a 27th field to every `mn` line:

  * `-` for a v1/v2 state;
  * for a v3 state, the hex of its MnStateV24Ext as the state codec writes
    it (v24_state.hpp): ExtNetInfo | payout list | share table |
    u32 nEarlyPeriodBlocks | i64 nEarlyPenalty. The row's scriptPayout field
    is `-`, and its legacy netInfo (ip/port) and scalar platform ports are 0:
    a v3 state carries its addresses in the ExtNetInfo only.

  The ExtNetInfo is rebuilt from the RPC `addresses` object (purposes in
  ascending order, one NetInfoEntry per printed endpoint: IPv4, IPv6 or a
  domain); it is under the v3 SML leaf, so the root self-check below proves
  the reconstruction. The RPC prints a share's reward script as
  RewardScript() (the refund script when none is set), so a reward script
  equal to the refund script is written as "not set" (empty): every reader
  goes through RewardScript(), which gives the same script either way.

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
# Dash Core testnet base58 prefixes (chainparams.cpp CTestNetParams).
TESTNET_PUBKEY_VER = 140
TESTNET_P2SH_VER = 19
ADDRESS_VERSIONS = {"mainnet": (MAINNET_PUBKEY_VER, MAINNET_P2SH_VER),
                    "testnet": (TESTNET_PUBKEY_VER, TESTNET_P2SH_VER)}

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
    if rec["nVersion"] >= 3:
        # v3 leaf: the ExtNetInfo replaces the legacy 18-byte CService.
        b += rec["extNetInfo"]
    else:
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


def _first_endpoint(state, purpose):
    eps = (state.get("addresses") or {}).get(purpose) or []
    return eps[0] if eps else ""


def _legacy_service(state):
    """The 18-byte CService of a v1/v2 state: dashd v23 prints `service`,
    v24 prints only `addresses` (core_p2p; {} for an empty netInfo)."""
    return state.get("service") or _first_endpoint(state, "core_p2p")


def _platform_http_port(diff_entry, state):
    """platformHTTPPort (under the v2 SML leaf): v23 prints it; v24 prints
    the addresses.platform_https endpoint instead."""
    v = diff_entry.get("platformHTTPPort", state.get("platformHTTPPort"))
    if v is None:
        ep = _first_endpoint(diff_entry, "platform_https") or _first_endpoint(state, "platform_https")
        v = int(ep.rsplit(":", 1)[1]) if ep else 0
    return v or 0


def _platform_p2p_port(state):
    eps = (state.get("addresses") or {}).get("platform_p2p") or []
    if not eps:
        return 0
    return int(eps[0].rsplit(":", 1)[1])


# ── Dash Core v24 state codec (v24_state.hpp MnStateV24Ext, vendor/netinfo.hpp,
# vendor/providertx.hpp): Bitcoin-style CompactSize-prefixed vectors and
# scripts, little-endian integers, big-endian ports.

# NetInfoPurpose (netinfo.h): the ascending order ExtNetInfo serializes in.
NETINFO_PURPOSES = {"core_p2p": 0, "platform_p2p": 1, "platform_https": 2}
NETINFO_ENTRY_SERVICE = 0x01
NETINFO_ENTRY_DOMAIN = 0x02
BIP155_IPV4 = 1
BIP155_IPV6 = 2
EXT_NETINFO_VERSION = 1


def compact_size(n):
    if n < 0xfd:
        return struct.pack("<B", n)
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def ser_script(b):
    return compact_size(len(b)) + b


def netinfo_entry_bytes(endpoint, protx):
    """One `addresses` endpoint string -> NetInfoEntry wire bytes: a service
    (ADDRv2 CService: BIP155 net id, CompactSize length, address, BE port)
    or a domain (CompactSize length, name, BE port)."""
    if endpoint.startswith("["):
        host, sep, port = endpoint[1:].partition("]:")
        if not sep:
            die("proTx %s: malformed endpoint %r" % (protx, endpoint))
        addr = ipaddress.IPv6Address(host)
        # Core prints IPv4 as a.b.c.d and keeps the internal/TORv2 ranges out
        # of valid entries; CJDNS (fc00::/8) prints exactly like IPv6, so its
        # BIP155 network cannot be told from the JSON.
        if (addr.ipv4_mapped is not None or addr.packed[0] == 0xfc
                or addr.packed[:6] in (bytes.fromhex("fd87d87eeb43"),
                                       bytes.fromhex("fd6b88c08724"))):
            die("proTx %s: endpoint %r is not a plain IPv6 address; its "
                "ADDRv2 network is ambiguous in the RPC output" % (protx, endpoint))
        svc = (struct.pack("<B", BIP155_IPV6) + compact_size(16) + addr.packed)
        return (struct.pack("<B", NETINFO_ENTRY_SERVICE) + svc
                + struct.pack(">H", int(port)))
    host, _, port = endpoint.rpartition(":")
    if not host:
        die("proTx %s: malformed endpoint %r" % (protx, endpoint))
    try:
        addr = ipaddress.IPv4Address(host)
        svc = struct.pack("<B", BIP155_IPV4) + compact_size(4) + addr.packed
        return (struct.pack("<B", NETINFO_ENTRY_SERVICE) + svc
                + struct.pack(">H", int(port)))
    except ipaddress.AddressValueError:
        pass
    if host.endswith(".onion") or host.endswith(".i2p") or ":" in host:
        die("proTx %s: endpoint %r (Tor/I2P/unbracketed) is not supported by "
            "this encoder" % (protx, endpoint))
    name = host.encode("ascii")
    return (struct.pack("<B", NETINFO_ENTRY_DOMAIN) + compact_size(len(name))
            + name + struct.pack(">H", int(port)))


def ext_netinfo_bytes(addresses, protx):
    """The RPC `addresses` object of a version-3 state -> ExtNetInfo wire
    bytes: u8 version | CompactSize n | {u8 purpose | entries}* in ascending
    purpose order (ExtNetInfo::ToJson prints every purpose it holds)."""
    items = []
    for key, endpoints in (addresses or {}).items():
        if key not in NETINFO_PURPOSES:
            die("proTx %s: unknown netInfo purpose %r" % (protx, key))
        items.append((NETINFO_PURPOSES[key], endpoints))
    items.sort()
    out = struct.pack("<B", EXT_NETINFO_VERSION) + compact_size(len(items))
    for purpose, endpoints in items:
        out += struct.pack("<B", purpose) + compact_size(len(endpoints))
        for ep in endpoints:
            out += netinfo_entry_bytes(ep, protx)
    return out


def _script_matches_address(script, address, pubkey_ver, p2sh_ver, protx, what):
    if address_to_script(address, pubkey_ver, p2sh_ver) != script:
        die("proTx %s: %s script %s does not encode address %s"
            % (protx, what, script.hex(), address))


def v24_ext_bytes(state, protx, pubkey_ver, p2sh_ver, extnet):
    """MnStateV24Ext (v24_state.hpp) of a version-3 state, as its codec
    writes it: ExtNetInfo | payouts | shares | nEarlyPeriodBlocks u32 |
    nEarlyPenalty i64."""
    payouts = state.get("payouts") or []
    shares = state.get("shares") or []
    out = extnet
    out += compact_size(len(payouts))
    for p in payouts:
        script = bytes.fromhex(p["script"])
        _script_matches_address(script, p["address"], pubkey_ver, p2sh_ver,
                                protx, "payout")
        reward = int(p["reward"])
        if not 0 < reward <= 10000:
            die("proTx %s: payout reward %r bps is out of range" % (protx, reward))
        out += ser_script(script) + struct.pack("<H", reward)
    out += compact_size(len(shares))
    for sh in shares:
        refund = bytes.fromhex(sh["refundScript"])
        reward = bytes.fromhex(sh["rewardScript"])
        _script_matches_address(refund, sh["refundAddress"], pubkey_ver, p2sh_ver,
                                protx, "share refund")
        _script_matches_address(reward, sh["rewardAddress"], pubkey_ver, p2sh_ver,
                                protx, "share reward")
        # The RPC prints RewardScript(): an unset reward script reads as the
        # refund script (module doc).
        stored_reward = b"" if reward == refund else reward
        out += struct.pack("<q", int(sh["amount"]))
        out += ser_script(refund) + ser_script(stored_reward)
        out += bytes.fromhex(address_to_keyid_hex(sh["ownerAddress"]))
    out += struct.pack("<I", int(state.get("earlyPeriodBlocks", 0)))
    out += struct.pack("<q", int(state.get("earlyPenalty", 0)))
    return out


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
        v3 = nversion >= 3
        shared = "shares" in s
        pubkey = (s.get("pubKeyOperator") or "").lower()
        if not is_hex_n(pubkey, 96):
            die("proTx %s: bad pubKeyOperator" % protx)
        if pubkey != (d.get("pubKeyOperator") or "").lower():
            die("proTx %s: list/diff pubKeyOperator disagree" % protx)
        voting = address_to_keyid_hex(s["votingAddress"])
        # A shared masternode has no owner key (its share owners sign).
        if "ownerAddress" in s:
            owner = address_to_keyid_hex(s["ownerAddress"])
        elif shared:
            owner = "00" * 20
        else:
            die("proTx %s: state has no ownerAddress" % protx)
        pubkey_ver, p2sh_ver = ADDRESS_VERSIONS[args.network]
        extnet = b""
        v24_hex = "-"
        if v3:
            # The SML entry's addresses are the leaf's ExtNetInfo; the full
            # state prints the same object.
            if (d.get("addresses") or {}) != (s.get("addresses") or {}):
                die("proTx %s: list/diff addresses disagree for a v3 state" % protx)
            extnet = ext_netinfo_bytes(d.get("addresses"), protx)
            if not s.get("payouts") and not s.get("shares"):
                die("proTx %s: v3 state with neither payouts nor shares" % protx)
            v24_hex = v24_ext_bytes(s, protx, pubkey_ver, p2sh_ver, extnet).hex()
            ip, port = b"\x00" * 16, 0
            payout = "-"
        else:
            if shared or "payouts" in s:
                die("proTx %s: a version-%d state with a payout list or share "
                    "table cannot be written to the prestate" % (protx, nversion))
            ip, port = service_to_ip_port(_legacy_service(s))
            payout = address_to_script(s["payoutAddress"], pubkey_ver, p2sh_ver).hex()
        op_addr = s.get("operatorPayoutAddress", "")
        script_op = (address_to_script(op_addr, pubkey_ver, p2sh_ver).hex()
                     if op_addr else "-")
        node_id = d.get("platformNodeID", "")
        rec = {
            "proTxHash_wire": rev_hex(protx),
            "confirmedHash_wire": rev_hex(d["confirmedHash"]),
            "ip_hex": ip.hex(),
            "port": port,
            "extNetInfo": extnet,
            "v24": v24_hex,
            "pubKeyOperator": pubkey,
            "keyIDVoting": voting,
            "keyIDOwner": owner,
            "isValid": bool(d["isValid"]),
            "nVersion": nversion,
            "nType": ntype,
            "platformNodeID_wire": rev_hex(node_id) if node_id else "",
            # v23 protx JSON has no scalar platformP2PPort; it lives in the
            # addresses.platform_p2p endpoint. Not under the SML root — only
            # carried so ProUpServTx folds have a faithful baseline. A v3
            # state has no scalar ports (SetStateVersion zeroes them; a v3
            # ProRegTx carries none): its Platform endpoints are ExtNetInfo
            # entries.
            "platformP2PPort": 0 if v3 else _platform_p2p_port(s),
            "platformHTTPPort": 0 if v3 else _platform_http_port(d, s),
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

    # /1 unless a version-3 state needs the v24 field (module doc).
    format2 = any(r["nVersion"] >= 3 for r in records)
    lines = [
        "c2pool-dash-replay-prestate/2" if format2 else "c2pool-dash-replay-prestate/1",
        "network %s" % args.network,
        "height %d" % height,
        "blockhash %s" % blockhash.lower(),
        "mnroot %s" % mnroot.lower(),
        "count %d" % len(records),
    ]
    for r in sorted(records, key=lambda r: r["proTxHash_wire"]):
        fields = [
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
        ]
        if format2:
            fields.append(r["v24"])
        lines.append(" ".join(str(x) for x in fields))
    if args.text:   # the plain prestate file test_dash_replay_run.cpp reads
        with open(args.out, "w") as f:
            f.write("\n".join(lines) + "\n")
        print("wrote %s (%d MNs, root %s ✓)" % (args.out, len(records), got[:16]))
        return
    write_inc(args.out, args.symbol, lines, [
        "Full-state DML pre-list at %s h=%d." % (args.network, height),
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
        "Raw %s block body (dash-cli getblock <hash> 0), %d bytes."
        % (args.network, len(block_hex) // 2),
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


def cmd_seamwork(args):
    """Emit the WORK-BLOCK masternode lists a rotated-cycle derivation consumes.

    DIP-0024 membership at cycle base B is computed over the masternode list at
    each contributing cycle's WORK block (base - 8), scored under that cycle's
    hash modifier. This packs the four work blocks of one cycle (B, B-C, B-2C,
    B-3C) into a single fixture so the KAT can DERIVE the member sets instead
    of being handed them.

    Per work block the capture is `protx diff 1 <workHeight>` (whose mnList is
    the full SML at that height) plus the block's own hash and cbTx
    bestCLSignature (the post-V20 hash-modifier input, chain data).

    An SML-fed list carries no collateral outpoint, so the upstream score
    TIEBREAK is undecidable and the derivation fails closed on a tie -- the
    same posture as the W4 KATs. A replay-fed list (the live path) carries it.

        for h in <B-8> <B-C-8> <B-2C-8> <B-3C-8>; do
            dash-cli protx diff 1 $h > diff_$h.json
            dash-cli getblock $(dash-cli getblockhash $h) 2 > blk_$h.json
        done
        python3 tools/dash/gen_replay_kat.py seamwork --llmq-type 5 \
            --cycle-base 2513088 --interval 288 \
            --work <B-8>:diff_<B-8>.json:blk_<B-8>.json ... --out work.txt
    """
    lines = ["c2pool-dash-replay-seam-workblocks/1",
             "network %s" % args.network,
             "llmqType %d" % args.llmq_type,
             "cycleBase %d" % args.cycle_base,
             "interval %d" % args.interval]
    for spec in args.work:
        parts = spec.split(":")
        if len(parts) != 3:
            die("--work wants <workHeight>:<protx-diff.json>:<getblock2.json>")
        work_h = int(parts[0])
        with open(parts[1]) as f:
            diff = json.load(f)
        with open(parts[2]) as f:
            blk = json.load(f)
        if blk.get("height") != work_h:
            die("--work %d: getblock capture is at height %r"
                % (work_h, blk.get("height")))
        cycle_base = work_h + 8
        cb = blk["tx"][0].get("cbTx", {})
        clsig = (cb.get("bestCLSignature") or "-")
        mns = diff.get("mnList", [])
        if not mns:
            die("--work %d: protx diff carries no mnList" % work_h)
        lines.append("work %d %d %s %s %d"
                     % (cycle_base, work_h, blk["hash"].lower(),
                        clsig.lower(), len(mns)))
        for e in mns:
            lines.append("mn %s %s %d %d"
                         % (rev_hex(e["proRegTxHash"]),
                            rev_hex(e["confirmedHash"]),
                            1 if e.get("isValid") else 0,
                            int(e.get("nType", 0))))
        print("work h=%d (cycle base %d): %d MNs, cl=%s"
              % (work_h, cycle_base, len(mns), clsig[:16]))
    with open(args.out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote %s" % args.out)


def cmd_qsnapshot(args):
    """Emit the PRE-ANCHOR rotated-cycle snapshot seed a Phase-1 replay needs.

    Rotated (DIP-0024) membership at cycle base B is built from the new
    quarter at B plus the three PREVIOUS cycles' CQuorumSnapshots. A replay
    produces those itself from its anchor forward, but the first three cycles
    after an anchor have no produced predecessor — this seeds exactly those,
    and nothing else (the C++ loader REFUSES any cycle base at or after the
    fold anchor, so a seed cannot mask a derivation that stopped working).

    A CQuorumSnapshot is a skip-list mode + an active-member bitset. It is NOT
    a member set: the member lists are computed by the replay.

        dash-cli quorum rotationinfo $(dash-cli getblockhash <cycleBase>) \
            > rot_<cycleBase>.json
        python3 tools/dash/gen_replay_kat.py qsnapshot \
            --rotationinfo rot_<cycleBase>.json --llmq-type 5 \
            --cycle-base <cycleBase> --interval 288 --out qsnap.txt
    """
    with open(args.rotationinfo) as f:
        rot = json.load(f)
    keys = [("quorumSnapshotAtHMinusC", 1),
            ("quorumSnapshotAtHMinus2C", 2),
            ("quorumSnapshotAtHMinus3C", 3)]
    lines = ["c2pool-dash-replay-qsnapshot/1", "network %s" % args.network]
    for key, mult in keys:
        snap = rot.get(key)
        if not isinstance(snap, dict):
            die("--rotationinfo carries no %s" % key)
        base = args.cycle_base - mult * args.interval
        if base <= 0:
            die("cycle base %d - %d*%d is not a positive height"
                % (args.cycle_base, mult, args.interval))
        mode = snap.get("mnSkipListMode")
        active = snap.get("activeQuorumMembers")
        skips = snap.get("mnSkipList", [])
        if not isinstance(mode, int) or not isinstance(active, list) \
                or not isinstance(skips, list):
            die("%s is not a CQuorumSnapshot (mode/bitset/skiplist)" % key)
        bits = "".join("1" if bool(b) else "0" for b in active) or "-"
        lines.append("snapshot %d %d %d %s %d%s"
                     % (args.llmq_type, base, mode, bits, len(skips),
                        ("".join(" %d" % int(x) for x in skips))))
        print("%s -> cycle base %d: mode=%d active=%d skips=%d"
              % (key, base, mode, len(active), len(skips)))
    with open(args.out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote %s (%d snapshots)" % (args.out, len(keys)))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("prestate")
    p.add_argument("--list", required=True)
    p.add_argument("--diff", required=True)
    p.add_argument("--height", type=int, required=True)
    p.add_argument("--symbol", default="kDashReplayPrestate")
    p.add_argument("--out", required=True)
    p.add_argument("--network", choices=sorted(ADDRESS_VERSIONS), default="mainnet")
    p.add_argument("--text", action="store_true",
                   help="write the plain prestate file (C2POOL_REPLAY_PRESTATE), not an .inc")
    p.set_defaults(fn=cmd_prestate)

    p = sub.add_parser("block")
    p.add_argument("--hex", required=True)
    p.add_argument("--symbol", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--network", choices=sorted(ADDRESS_VERSIONS), default="mainnet",
                   help="only names the chain in the fixture preamble")
    p.set_defaults(fn=cmd_block)

    p = sub.add_parser("seamwork")
    p.add_argument("--llmq-type", type=int, required=True)
    p.add_argument("--cycle-base", type=int, required=True)
    p.add_argument("--interval", type=int, required=True)
    p.add_argument("--work", action="append", required=True,
                   help="<workHeight>:<protx-diff.json>:<getblock-verbosity2.json>")
    p.add_argument("--network", default="mainnet")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_seamwork)

    p = sub.add_parser("qsnapshot")
    p.add_argument("--rotationinfo", required=True,
                   help="dash-cli quorum rotationinfo <cycleBase blockhash>")
    p.add_argument("--llmq-type", type=int, required=True)
    p.add_argument("--cycle-base", type=int, required=True,
                   help="the cycle base the rotationinfo was requested at")
    p.add_argument("--interval", type=int, required=True,
                   help="the type's dkgInterval (mainnet llmq_60_75: 288)")
    p.add_argument("--network", default="mainnet")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_qsnapshot)

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
