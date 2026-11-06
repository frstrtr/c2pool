#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate the Dash Core v24 provider-payload vectors used by
test/test_dash_v24_protx_codecs.cpp (written to dash_v24_s2_vectors.inc).

Usage:  python3 -I gen_s2_vectors.py <dir with the Insight tx_*.json captures> <out.inc>

Two kinds of vectors:

1. Testnet captures (v24 has been active on testnet since height 1,578,000).
   Each tx is rebuilt byte by byte from its Insight JSON (version|type, vin,
   vout, locktime, extra payload) and kept only if SHA256d(raw) equals the
   txid Insight reports. The payload is then decoded by the independent
   decoder below and every decoded field is cross-checked against the
   Insight JSON before it is emitted as an expected value.

2. Synthetic payloads for the shapes testnet does not carry yet (shared
   masternodes, multi-entry payout lists, types 10-12, every ADDRv2 network,
   domain entries, v3 SML entries and an mnlistdiff carrying them). They are
   encoded field by field following the SERIALIZE_METHODS of Dash Core
   v24.0.0 (src/evo/providertx.h, netinfo.h, simplifiedmns.h, smldiff.h,
   src/netaddress.h). The regtest harness (slice S9) replaces them with
   bytes produced by dashd itself.

Nothing here talks to the network.
"""
import hashlib
import json
import os
import struct
import sys
from decimal import Decimal

COIN = 100_000_000


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def cs(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def u8(v): return struct.pack("<B", v)
def u16(v): return struct.pack("<H", v)
def u32(v): return struct.pack("<I", v)
def i32(v): return struct.pack("<i", v)
def i64(v): return struct.pack("<q", v)
def be16(v): return struct.pack(">H", v)
def vec(b): return cs(len(b)) + b


def pat(n, seed):
    """Deterministic filler bytes."""
    return bytes(((seed * 31 + i * 7) & 0xFF) for i in range(n))


def h2b_rev(h):
    return bytes.fromhex(h)[::-1]


# ── base58 (for Insight owner/voting addresses) ─────────────────────────────
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_hash160(addr):
    n = 0
    for c in addr:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes(25, "big")
    assert dsha(raw[:21])[:4] == raw[21:], addr
    return raw[1:21]


# ── ADDRv2 / NetInfo encoders (netaddress.h SerializeV2Stream, netinfo.h) ───
BIP155 = {"ipv4": 1, "ipv6": 2, "torv3": 4, "i2p": 5, "cjdns": 6}


def addrv2(net, addr, port):
    return u8(BIP155[net]) + vec(addr) + be16(port)


def entry_service(net, addr, port):
    return b"\x01" + addrv2(net, addr, port)


def entry_domain(name, port):
    return b"\x02" + vec(name.encode()) + be16(port)


def extnetinfo(purposes):
    out = u8(1) + cs(len(purposes))
    for purpose, entries in purposes:
        out += u8(purpose) + cs(len(entries)) + b"".join(entries)
    return out


def ipv4(s):
    return bytes(int(x) for x in s.split("."))


def p2pkh(h20): return b"\x76\xa9\x14" + h20 + b"\x88\xac"
def p2sh(h20): return b"\xa9\x14" + h20 + b"\x87"


# ── independent decoder for the captured payloads ───────────────────────────
class R:
    def __init__(self, b):
        self.b, self.p = b, 0

    def take(self, n):
        v = self.b[self.p:self.p + n]
        if len(v) != n:
            raise ValueError("short")
        self.p += n
        return v

    def u8(self): return self.take(1)[0]
    def u16(self): return struct.unpack("<H", self.take(2))[0]
    def u32(self): return struct.unpack("<I", self.take(4))[0]
    def i64(self): return struct.unpack("<q", self.take(8))[0]

    def cs(self):
        n = self.u8()
        if n < 253:
            return n
        if n == 253:
            return self.u16()
        if n == 254:
            return self.u32()
        return struct.unpack("<Q", self.take(8))[0]

    def vec(self): return self.take(self.cs())
    def done(self): return self.p == len(self.b)


PURPOSE_NAME = {0: "core_p2p", 1: "platform_p2p", 2: "platform_https"}


def dec_extnetinfo(r):
    assert r.u8() == 1
    out = {}
    last = -1
    for _ in range(r.cs()):
        p = r.u8()
        assert p in PURPOSE_NAME and p > last
        last = p
        items = []
        for _ in range(r.cs()):
            t = r.u8()
            if t == 1:
                net = r.u8()
                a = r.vec()
                port = struct.unpack(">H", r.take(2))[0]
                assert net == 1 and len(a) == 4, "captures only carry IPv4"
                items.append("%d.%d.%d.%d:%d" % (a[0], a[1], a[2], a[3], port))
            elif t == 2:
                name = r.vec().decode()
                port = struct.unpack(">H", r.take(2))[0]
                items.append("%s:%d" % (name, port))
            else:
                raise ValueError("entry type")
        out[PURPOSE_NAME[p]] = items
    return out


def dec_payouts(r):
    return [(r.vec().hex(), r.u16()) for _ in range(r.u8())]


def dec_proreg(b):
    r = R(b)
    d = {"version": r.u16(), "type": r.u16(), "mode": r.u16()}
    assert d["version"] == 3
    d["collateralHash"] = r.take(32)[::-1].hex()
    d["collateralIndex"] = r.u32()
    d["addresses"] = dec_extnetinfo(r)
    d["owner"] = r.take(20).hex()
    d["pubKeyOperator"] = r.take(48).hex()
    d["voting"] = r.take(20).hex()
    d["operatorReward"] = r.u16()
    d["payouts"] = dec_payouts(r)
    assert r.u8() == 0, "captures carry no shares"
    d["early"] = (r.u32(), r.i64())
    d["inputsHash"] = r.take(32)[::-1].hex()
    if d["type"] == 1:
        d["platformNodeID"] = r.take(20)[::-1].hex()
    d["vchSig"] = r.vec().hex()
    assert r.done()
    return d


def dec_proupserv(b):
    r = R(b)
    d = {"version": r.u16()}
    assert d["version"] == 3
    d["type"] = r.u16()
    d["proTxHash"] = r.take(32)[::-1].hex()
    d["addresses"] = dec_extnetinfo(r)
    d["operatorPayout"] = r.vec().hex()
    d["inputsHash"] = r.take(32)[::-1].hex()
    if d["type"] == 1:
        d["platformNodeID"] = r.take(20)[::-1].hex()
    d["sig"] = r.take(96).hex()
    assert r.done()
    return d


def dec_prouprev(b):
    r = R(b)
    d = {"version": r.u16(), "proTxHash": r.take(32)[::-1].hex(),
         "reason": r.u16(), "inputsHash": r.take(32)[::-1].hex(),
         "sig": r.take(96).hex()}
    assert r.done()
    return d


def rebuild_raw(j):
    ver = j["version"] | (j["type"] << 16)
    out = u32(ver) + cs(len(j["vin"]))
    for vin in j["vin"]:
        out += h2b_rev(vin["txid"]) + u32(vin["vout"])
        out += vec(bytes.fromhex(vin["scriptSig"]["hex"])) + u32(vin["sequence"])
    out += cs(len(j["vout"]))
    for vo in j["vout"]:
        sat = int(Decimal(vo["value"]) * COIN)
        out += i64(sat) + vec(bytes.fromhex(vo["scriptPubKey"]["hex"]))
    out += u32(j["locktime"])
    if j["version"] >= 3 and j["type"] != 0:
        out += vec(bytes.fromhex(j["extraPayload"]))
    return out


def fmt_addresses(a):
    return ";".join("%s=%s" % (k, ",".join(a[k])) for k in ("core_p2p", "platform_p2p", "platform_https") if k in a)


def testnet_fixtures(txdir):
    rows = []
    for name in sorted(os.listdir(txdir)):
        if not name.startswith("tx_") or not name.endswith(".json"):
            continue
        j = json.load(open(os.path.join(txdir, name)))
        if j["type"] not in (1, 2, 4):
            continue
        raw = rebuild_raw(j)
        assert dsha(raw)[::-1].hex() == j["txid"], name
        payload = bytes.fromhex(j["extraPayload"])
        assert len(payload) == j["extraPayloadSize"]
        row = {"txid": j["txid"], "height": j["blockheight"], "txtype": j["type"],
               "raw": raw.hex(), "payload": payload.hex()}
        if j["type"] == 1:
            ins, d = j["proRegTx"], dec_proreg(payload)
            assert d["type"] == ins["type"] and d["collateralHash"] == ins["collateralHash"]
            assert d["collateralIndex"] == ins["collateralIndex"]
            assert d["addresses"] == ins["addresses"]
            assert d["owner"] == b58check_hash160(ins["ownerAddress"]).hex()
            assert d["voting"] == b58check_hash160(ins["votingAddress"]).hex()
            assert d["pubKeyOperator"] == ins["pubKeyOperator"]
            assert d["operatorReward"] == ins["operatorReward"]
            assert d["payouts"] == [(p["script"], p["reward"]) for p in ins["payouts"]]
            assert d["inputsHash"] == ins["inputsHash"]
            if d["type"] == 1:
                assert d["platformNodeID"] == ins["platformNodeID"]
            row.update(mntype=d["type"], ref=d["collateralHash"], index=d["collateralIndex"],
                       addresses=fmt_addresses(d["addresses"]), owner=d["owner"], voting=d["voting"],
                       opkey=d["pubKeyOperator"], payouts=",".join("%s:%d" % p for p in d["payouts"]),
                       inputs=d["inputsHash"], nodeid=d.get("platformNodeID", ""))
        elif j["type"] == 2:
            ins, d = j["proUpServTx"], dec_proupserv(payload)
            assert d["type"] == ins["type"] and d["proTxHash"] == ins["proTxHash"]
            assert d["addresses"] == ins["addresses"] and d["inputsHash"] == ins["inputsHash"]
            if d["type"] == 1:
                assert d["platformNodeID"] == ins["platformNodeID"]
            row.update(mntype=d["type"], ref=d["proTxHash"], index=0,
                       addresses=fmt_addresses(d["addresses"]), owner="", voting="", opkey="",
                       payouts="", inputs=d["inputsHash"], nodeid=d.get("platformNodeID", ""))
        else:
            ins, d = j["proUpRevTx"], dec_prouprev(payload)
            assert d["proTxHash"] == ins["proTxHash"] and d["reason"] == ins["reason"]
            assert d["inputsHash"] == ins["inputsHash"]
            row.update(mntype=0, ref=d["proTxHash"], index=d["reason"], addresses="", owner="",
                       voting="", opkey="", payouts="", inputs=d["inputsHash"], nodeid="")
        rows.append(row)
    return rows


# ── synthetic payloads (Core v24.0.0 SERIALIZE_METHODS, field by field) ─────
def proreg_v3(mntype, coll_hash, coll_n, netinfo, owner, opkey, voting, op_reward,
              payouts, shares, join_sigs, early_blocks, early_penalty, inputs, nodeid, sig):
    out = u16(3) + u16(mntype) + u16(0) + coll_hash + u32(coll_n) + netinfo
    out += owner + opkey + voting + u16(op_reward)
    out += u8(len(payouts)) + b"".join(vec(s) + u16(r) for s, r in payouts)
    out += u8(len(shares))
    out += b"".join(i64(a) + vec(rf) + vec(rw) + k for a, rf, rw, k in shares)
    assert len(join_sigs) == len(shares)
    out += b"".join(join_sigs)
    out += u32(early_blocks) + i64(early_penalty) + inputs
    if mntype == 1:
        out += nodeid
    return out + vec(sig)


def syn_vectors():
    v = {}
    zero32 = bytes(32)
    # (a) shared regular registration: 3 shares, internal collateral, early-exit terms
    shares = [
        (400 * COIN, p2pkh(pat(20, 0x11)), b"", pat(20, 0x21)),
        (350 * COIN, p2pkh(pat(20, 0x12)), p2sh(pat(20, 0x32)), pat(20, 0x22)),
        (250 * COIN, p2sh(pat(20, 0x13)), p2pkh(pat(20, 0x33)), pat(20, 0x23)),
    ]
    sigs = [pat(65, 0x41 + i) for i in range(3)]
    v["proreg_shared"] = proreg_v3(
        0, zero32, 0, extnetinfo([(0, [entry_service("ipv4", ipv4("1.2.3.4"), 9999)])]),
        bytes(20), pat(48, 0x05), pat(20, 0x06), 500, [], shares, sigs, 210240, 10 * COIN,
        pat(32, 0x07), b"", b"")
    # (b) multi-payout regular registration, external collateral, IPv4 + IPv6 core entries
    payouts3 = [(p2pkh(pat(20, 0x51)), 5000), (p2sh(pat(20, 0x52)), 3000), (p2pkh(pat(20, 0x53)), 2000)]
    v6 = bytes.fromhex("2a0104f8000000000000000000000001")
    v["proreg_multipayout"] = proreg_v3(
        0, pat(32, 0x61), 1,
        extnetinfo([(0, [entry_service("ipv4", ipv4("5.6.7.8"), 9999),
                         entry_service("ipv6", v6, 9999)])]),
        pat(20, 0x62), pat(48, 0x63), pat(20, 0x64), 0, payouts3, [], [], 0, 0,
        pat(32, 0x65), b"", pat(65, 0x66))
    # (c) EvoNode registration: TORv3 core entry, a domain HTTPS entry
    v["proreg_evo"] = proreg_v3(
        1, pat(32, 0x71), 0,
        extnetinfo([(0, [entry_service("ipv4", ipv4("9.9.9.9"), 9999),
                         entry_service("torv3", pat(32, 0x7a), 9999)]),
                    (1, [entry_service("ipv4", ipv4("9.9.9.9"), 26656)]),
                    (2, [entry_service("ipv4", ipv4("9.9.9.9"), 443),
                         entry_domain("evo.dash.org", 443)])]),
        pat(20, 0x72), pat(48, 0x73), pat(20, 0x74), 1000, [(p2pkh(pat(20, 0x75)), 10000)],
        [], [], 0, 0, pat(32, 0x76), pat(20, 0x77), pat(65, 0x78))
    # (d) ProUpRegTx v3 with two payouts
    v["proupreg"] = (u16(3) + pat(32, 0x81) + u16(0) + pat(48, 0x82) + pat(20, 0x83)
                     + u8(2) + vec(p2pkh(pat(20, 0x84))) + u16(6000)
                     + vec(p2sh(pat(20, 0x85))) + u16(4000)
                     + pat(32, 0x86) + vec(pat(65, 0x87)))
    # (e) ProUpServTx v3 regular: IPv4 + CJDNS + I2P core entries
    cjdns = bytes([0xfc]) + pat(15, 0x91)
    v["proupserv"] = (u16(3) + u16(0) + pat(32, 0x92)
                      + extnetinfo([(0, [entry_service("ipv4", ipv4("8.8.4.4"), 9999),
                                         entry_service("cjdns", cjdns, 9999),
                                         entry_service("i2p", pat(32, 0x93), 0)])])
                      + vec(p2pkh(pat(20, 0x94))) + pat(32, 0x95) + pat(96, 0x96))
    # (f) type 10 ProDisTx: unilateral (one sig) and unanimous (three sigs)
    v["prodis_uni"] = u16(1) + pat(32, 0xa1) + u16(1) + u8(1) + pat(65, 0xa2)
    v["prodis_all"] = u16(1) + pat(32, 0xa1) + u16(0) + u8(3) + b"".join(pat(65, 0xa3 + i) for i in range(3))
    # (g) type 11 ProUpShareTx
    v["proupshare"] = u16(1) + pat(32, 0xb1) + u16(2) + vec(p2pkh(pat(20, 0xb2))) + pat(32, 0xb3) + vec(pat(65, 0xb4))
    # (h) type 12 ProUpSharedRegTx: sig count + sigs ride after inputsHash
    v["proupsharedreg"] = (u16(1) + pat(32, 0xc1) + pat(48, 0xc2) + pat(20, 0xc3) + pat(32, 0xc4)
                           + u8(3) + b"".join(pat(65, 0xc5 + i) for i in range(3)))
    return v


# ── SML entries and an mnlistdiff (simplifiedmns.h, smldiff.h) ──────────────
def sml_entry(ver, pro, conf, netinfo, opkey, voting, valid, mntype, http_port, nodeid):
    """Returns (wire bytes, SER_GETHASH preimage)."""
    body = pro + conf + netinfo + opkey + voting + u8(1 if valid else 0)
    if ver >= 2:
        body += u16(mntype)
        if mntype == 1:
            if ver < 3:
                body += u16(http_port)
            body += nodeid
    return u16(ver) + body, body


def merkle(leaves):
    if not leaves:
        return bytes(32)
    while len(leaves) > 1:
        if len(leaves) & 1:
            leaves.append(leaves[-1])
        leaves = [dsha(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
    return leaves[0]


def sml_vectors():
    v = {}
    evo_ext = extnetinfo([(0, [entry_service("ipv4", ipv4("7.7.7.7"), 9999)]),
                          (1, [entry_service("ipv4", ipv4("7.7.7.7"), 26656)]),
                          (2, [entry_service("ipv4", ipv4("7.7.7.7"), 443)])])
    legacy = bytes(10) + b"\xff\xff" + ipv4("7.7.7.7") + be16(9999)
    pro, conf = pat(32, 0xd1), pat(32, 0xd2)
    opkey, voting, nodeid = pat(48, 0xd3), pat(20, 0xd4), pat(20, 0xd5)
    v["sml_evo_v3"] = sml_entry(3, pro, conf, evo_ext, opkey, voting, True, 1, 0, nodeid)
    v["sml_evo_v2"] = sml_entry(2, pro, conf, legacy, opkey, voting, True, 1, 443, nodeid)
    reg_ext = extnetinfo([(0, [entry_service("ipv4", ipv4("6.6.6.6"), 9999)])])
    v["sml_reg_v3"] = sml_entry(3, pat(32, 0xe1), pat(32, 0xe2), reg_ext, pat(48, 0xe3),
                                pat(20, 0xe4), False, 0, 0, b"")
    reg_legacy = bytes(10) + b"\xff\xff" + ipv4("6.6.6.6") + be16(9999)
    v["sml_reg_v2"] = sml_entry(2, pat(32, 0xf1), bytes(32), reg_legacy, pat(48, 0xf3),
                                pat(20, 0xf4), True, 0, 0, b"")
    # An empty v3 netInfo (a revoked masternode after v24 keeps ExtNetInfo{v1, no purposes}).
    v["sml_reg_v3_empty"] = sml_entry(3, pat(32, 0x15), bytes(32), extnetinfo([]), bytes(48),
                                      pat(20, 0x16), False, 0, 0, b"")

    entries = [v["sml_reg_v2"], v["sml_reg_v3"], v["sml_evo_v3"], v["sml_reg_v3_empty"]]
    leaves = sorted(((e[0][2:34], dsha(e[1])) for e in entries), key=lambda t: t[0])
    root = merkle([h for _, h in leaves])
    # Coinbase with a CbTx v3 payload committing that root (the diff's cbTx).
    cbtx = u16(3) + i32(1_600_000) + root + bytes(32) + cs(0) + bytes(96) + i64(0)
    cb = (u32(3 | (5 << 16)) + cs(1) + bytes(32) + u32(0xFFFFFFFF) + vec(bytes.fromhex("0300691800"))
          + u32(0xFFFFFFFF) + cs(1) + i64(50 * COIN) + vec(p2pkh(pat(20, 0x31))) + u32(0) + vec(cbtx))
    cbid = dsha(cb)
    diff = (u16(1) + bytes(32) + pat(32, 0x32)
            + u32(1) + cs(1) + cbid + vec(b"\x01")       # CPartialMerkleTree: 1 tx, its hash, bits
            + cb
            + cs(1) + pat(32, 0x33)                       # deletedMNs
            + cs(len(entries)) + b"".join(e[0] for e in entries)
            + cs(0) + cs(0) + cs(0))                      # deletedQuorums, newQuorums, quorumsCLSigs
    v["diff"] = diff
    v["diff_root"] = root
    return v


def cstr(name, b):
    return 'static const char* %s =\n    "%s";\n' % (name, b.hex())


def main():
    txdir, out = sys.argv[1], sys.argv[2]
    rows = testnet_fixtures(txdir)
    syn = syn_vectors()
    sml = sml_vectors()
    o = ["// SPDX-License-Identifier: AGPL-3.0-or-later\n",
         "// Generated by test/fixtures/dash_v24/gen_s2_vectors.py -- do not edit by hand.\n",
         "// Testnet rows: raw bytes rebuilt from the Insight JSON, SHA256d checked against the txid,\n",
         "// fields cross-checked against the Insight decode. Synthetic rows: Dash Core v24.0.0 layout.\n\n",
         "struct TestnetProTxFixture {\n"
         "    const char* txid; uint32_t height; uint16_t txtype; uint16_t mntype;\n"
         "    const char* raw; const char* payload;\n"
         "    const char* ref;        // collateral hash (type 1) or proTxHash (types 2, 4)\n"
         "    uint32_t index;         // collateral index (type 1) or revocation reason (type 4)\n"
         "    const char* addresses;  // purpose=addr:port,...;... (Insight `addresses`)\n"
         "    const char* owner; const char* voting; const char* opkey;  // raw-byte hex\n"
         "    const char* payouts;    // script:reward,...\n"
         "    const char* inputs; const char* nodeid;  // uint GetHex() form\n"
         "};\n\n",
         "static const TestnetProTxFixture kTestnetProTx[] = {\n"]
    for r in rows:
        o.append('    {"%s", %d, %d, %d,\n     "%s",\n     "%s",\n     "%s", %d, "%s", "%s", "%s", "%s", "%s", "%s", "%s"},\n'
                 % (r["txid"], r["height"], r["txtype"], r["mntype"], r["raw"], r["payload"], r["ref"],
                    r["index"], r["addresses"], r["owner"], r["voting"], r["opkey"], r["payouts"],
                    r["inputs"], r["nodeid"]))
    o.append("};\n\n")
    for k in ("proreg_shared", "proreg_multipayout", "proreg_evo", "proupreg", "proupserv",
              "prodis_uni", "prodis_all", "proupshare", "proupsharedreg"):
        o.append(cstr("kSyn_" + k, syn[k]))
    for k in ("sml_evo_v3", "sml_evo_v2", "sml_reg_v3", "sml_reg_v2", "sml_reg_v3_empty"):
        o.append(cstr("kSml_" + k + "_wire", sml[k][0]))
        o.append(cstr("kSml_" + k + "_hash", dsha(sml[k][1])))
    o.append(cstr("kSml_diff", sml["diff"]))
    o.append(cstr("kSml_diff_root", sml["diff_root"]))
    open(out, "w").write("".join(o))
    print("testnet rows:", len(rows), "synthetic:", len(syn), "sml:", len(sml))


if __name__ == "__main__":
    main()
