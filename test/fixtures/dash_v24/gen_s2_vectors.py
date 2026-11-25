#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate the Dash Core v24 provider-payload vectors used by
test/test_dash_v24_protx_codecs.cpp (written to dash_v24_s2_vectors.inc).

Usage:
  python3 -I gen_s2_vectors.py <dir with tx_*.json captures> <out.inc> \
      --bls-helper "<command running bls_helper>" --dash-cli "<command running dash-cli>"

  --bls-helper  bls_helper.cpp in this directory, built against dashbls (the
                library dashd wraps), possibly behind ssh.
  --dash-cli    dash-cli of a Dash Core 24.0.0 node, possibly behind ssh. Only
                read-only calls: decoderawtransaction and bls fromsecret.

Two kinds of vectors:

1. Testnet captures (v24 has been active on testnet since height 1,578,000):
   the verbose JSON of each tx, from Insight or from dashd's
   `getrawtransaction <txid> true <blockhash>` (the same fields). Each tx is
   rebuilt byte by byte from it (version|type, vin, vout, locktime, extra
   payload) and kept only if SHA256d(raw) equals the txid. The payload is then
   decoded by the independent decoder below and every decoded field is
   cross-checked against the JSON before it is emitted as an expected value.

2. Synthetic payloads for the shapes testnet does not carry yet (shared
   masternodes, multi-entry payout lists, types 10-12, every ADDRv2 network,
   domain entries, v3 SML entries and an mnlistdiff carrying them). They are
   encoded field by field following the SERIALIZE_METHODS of Dash Core
   v24.0.0 (src/evo/providertx.h, netinfo.h, simplifiedmns.h, smldiff.h,
   src/netaddress.h).
   * Operator keys are real BLS public keys of fixed secrets ({i, 0, ..., 0},
     Core's evo_simplifiedmns_tests convention) under the payload's scheme
     (legacy for ProTx v1, else basic; always basic for type 12), each
     cross-checked against dashd's `bls fromsecret`.
   * The type-2 and type-4 signatures are real: the operator secret's
     signature over the payload's sign hash (SHA256d of the payload without
     its signature), so they verify against the matching key.
   * Every synthetic payload is run through dashd's decoderawtransaction.
     The generator fails unless dashd decodes the payload object (a missing
     object is a GetTxPayload failure) and prints the same operator key (an
     invalid key prints as zeros).
   * ECDSA signatures (vchSig, join and dissolution signatures) are 65-byte
     placeholders: Core checks them only against masternode-list state, which
     the payload-only rules do not cover.
   The BLS facts table records, for each key or signature encoding the tests
   use, what Core's decoding makes of it, confirmed by dashd and by dashbls.
   The SML vectors keep placeholder keys: an SML entry hashes the key bytes
   as they are and never decodes them. The regtest harness (slice S9)
   replaces the synthetic payloads with bytes produced by dashd itself.
"""
import hashlib
import json
import os
import shlex
import struct
import subprocess
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
        j = json.load(open(os.path.join(txdir, name)), parse_float=Decimal)
        if j["type"] not in (1, 2, 4):
            continue
        raw = rebuild_raw(j)
        assert dsha(raw)[::-1].hex() == j["txid"], name
        payload = bytes.fromhex(j["extraPayload"])
        assert len(payload) == j["extraPayloadSize"]
        row = {"txid": j["txid"], "height": j.get("blockheight", j.get("height")), "txtype": j["type"],
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


# ── BLS (dashbls via bls_helper) and the dashd oracle ───────────────────────
BLS_P = int("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)


def secret(i):
    return bytes([i]) + bytes(31)


class Bls:
    def __init__(self, cmd):
        self.cmd = shlex.split(cmd)

    def _run(self, *a):
        r = subprocess.run(self.cmd + list(a), capture_output=True, text=True, check=True)
        return r.stdout.strip()

    def pub(self, i, legacy):
        return bytes.fromhex(self._run("pub", secret(i).hex(), "1" if legacy else "0"))

    def sign(self, i, h, legacy):
        return bytes.fromhex(self._run("sign", secret(i).hex(), h.hex(), "1" if legacy else "0"))

    def g1valid(self, b, legacy):
        return self._run("g1valid", b.hex(), "1" if legacy else "0") == "1"

    def g2decodes(self, b, legacy):
        return self._run("g2decodes", b.hex(), "1" if legacy else "0") == "1"


PAYLOAD_KEY = {1: "proRegTx", 2: "proUpServTx", 3: "proUpRegTx", 4: "proUpRevTx",
               10: "proDisTx", 11: "proUpShareTx", 12: "proUpSharedRegTx"}


class Dashd:
    def __init__(self, cmd):
        self.cmd = shlex.split(cmd)

    def _run(self, *a):
        r = subprocess.run(self.cmd + list(a), capture_output=True, text=True, check=True)
        return json.loads(r.stdout)

    def payload_object(self, txtype, payload):
        """decoderawtransaction of a bare tx carrying `payload`: the payload
        object, or None when Core's GetTxPayload failed."""
        tx = u16(3) + u16(txtype) + cs(0) + cs(0) + u32(0) + vec(payload)
        return self._run("decoderawtransaction", tx.hex()).get(PAYLOAD_KEY[txtype])

    def fromsecret(self, i, legacy):
        a = ["bls", "fromsecret", secret(i).hex()] + (["true"] if legacy else [])
        return bytes.fromhex(self._run(*a)["public"])


def operator_key(bls, dashd, i, legacy):
    k = bls.pub(i, legacy)
    assert dashd.fromsecret(i, legacy) == k, ("bls fromsecret disagrees", i, legacy)
    return k


def check_decodes(dashd, txtype, payload, opkey=None):
    o = dashd.payload_object(txtype, payload)
    assert o is not None, ("dashd cannot decode the payload", txtype, payload.hex())
    if opkey is not None:
        assert o["pubKeyOperator"] == opkey.hex(), ("dashd reads another operator key", txtype)
    return o


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


def proreg_legacy(version, mntype, coll_hash, coll_n, service, owner, opkey, voting, op_reward,
                  payout, inputs, nodeid=b"", p2p_port=0, http_port=0, sig=b""):
    """ProRegTx v1/v2: the 18-byte legacy CService, one payout script."""
    out = u16(version) + u16(mntype) + u16(0) + coll_hash + u32(coll_n) + service
    out += owner + opkey + voting + u16(op_reward) + vec(payout) + inputs
    if version >= 2 and mntype == 1:
        out += nodeid + u16(p2p_port) + u16(http_port)
    return out + vec(sig)


# Secret index of each synthetic operator key (bls_helper `pub i`).
KEY_OF = {"proreg_shared": 1, "proreg_multipayout": 2, "proreg_evo": 3, "proupreg": 4,
          "proupsharedreg": 5, "proupserv": 6, "prouprev": 7, "proreg_v1": 8, "proreg_v2_evo": 8}


def syn_vectors(bls, dashd):
    """Returns (payloads, operator keys, signatures)."""
    v, keys, sigs = {}, {}, {}
    for name, i in KEY_OF.items():
        keys[name] = operator_key(bls, dashd, i, legacy=(name == "proreg_v1"))
    zero32 = bytes(32)
    # (a) shared regular registration: 3 shares, internal collateral, early-exit terms
    shares = [
        (400 * COIN, p2pkh(pat(20, 0x11)), b"", pat(20, 0x21)),
        (350 * COIN, p2pkh(pat(20, 0x12)), p2sh(pat(20, 0x32)), pat(20, 0x22)),
        (250 * COIN, p2sh(pat(20, 0x13)), p2pkh(pat(20, 0x33)), pat(20, 0x23)),
    ]
    join = [pat(65, 0x41 + i) for i in range(3)]
    v["proreg_shared"] = proreg_v3(
        0, zero32, 0, extnetinfo([(0, [entry_service("ipv4", ipv4("1.2.3.4"), 9999)])]),
        bytes(20), keys["proreg_shared"], pat(20, 0x06), 500, [], shares, join, 210240, 10 * COIN,
        pat(32, 0x07), b"", b"")
    # (b) multi-payout regular registration, external collateral, IPv4 + IPv6 core entries
    payouts3 = [(p2pkh(pat(20, 0x51)), 5000), (p2sh(pat(20, 0x52)), 3000), (p2pkh(pat(20, 0x53)), 2000)]
    v6 = bytes.fromhex("2a0104f8000000000000000000000001")
    v["proreg_multipayout"] = proreg_v3(
        0, pat(32, 0x61), 1,
        extnetinfo([(0, [entry_service("ipv4", ipv4("5.6.7.8"), 9999),
                         entry_service("ipv6", v6, 9999)])]),
        pat(20, 0x62), keys["proreg_multipayout"], pat(20, 0x64), 0, payouts3, [], [], 0, 0,
        pat(32, 0x65), b"", pat(65, 0x66))
    # (c) EvoNode registration: TORv3 core entry, a domain HTTPS entry
    v["proreg_evo"] = proreg_v3(
        1, pat(32, 0x71), 0,
        extnetinfo([(0, [entry_service("ipv4", ipv4("9.9.9.9"), 9999),
                         entry_service("torv3", pat(32, 0x7a), 9999)]),
                    (1, [entry_service("ipv4", ipv4("9.9.9.9"), 26656)]),
                    (2, [entry_service("ipv4", ipv4("9.9.9.9"), 443),
                         entry_domain("evo.dash.org", 443)])]),
        pat(20, 0x72), keys["proreg_evo"], pat(20, 0x74), 1000, [(p2pkh(pat(20, 0x75)), 10000)],
        [], [], 0, 0, pat(32, 0x76), pat(20, 0x77), pat(65, 0x78))
    # (d) ProUpRegTx v3 with two payouts
    v["proupreg"] = (u16(3) + pat(32, 0x81) + u16(0) + keys["proupreg"] + pat(20, 0x83)
                     + u8(2) + vec(p2pkh(pat(20, 0x84))) + u16(6000)
                     + vec(p2sh(pat(20, 0x85))) + u16(4000)
                     + pat(32, 0x86) + vec(pat(65, 0x87)))
    # (e) ProUpServTx v3 regular: IPv4 + CJDNS + I2P core entries, signed by key 6
    cjdns = bytes([0xfc]) + pat(15, 0x91)
    unsigned = (u16(3) + u16(0) + pat(32, 0x92)
                + extnetinfo([(0, [entry_service("ipv4", ipv4("8.8.4.4"), 9999),
                                   entry_service("cjdns", cjdns, 9999),
                                   entry_service("i2p", pat(32, 0x93), 0)])])
                + vec(p2pkh(pat(20, 0x94))) + pat(32, 0x95))
    sigs["proupserv"] = bls.sign(KEY_OF["proupserv"], dsha(unsigned), legacy=False)
    v["proupserv"] = unsigned + sigs["proupserv"]
    # (e') ProUpRevTx v3, signed by key 7
    unsigned = u16(3) + pat(32, 0x9a) + u16(3) + pat(32, 0x9b)   # REASON_CHANGE_OF_KEYS
    sigs["prouprev"] = bls.sign(KEY_OF["prouprev"], dsha(unsigned), legacy=False)
    v["prouprev"] = unsigned + sigs["prouprev"]
    # (f) type 10 ProDisTx: unilateral (one sig) and unanimous (three sigs)
    v["prodis_uni"] = u16(1) + pat(32, 0xa1) + u16(1) + u8(1) + pat(65, 0xa2)
    v["prodis_all"] = u16(1) + pat(32, 0xa1) + u16(0) + u8(3) + b"".join(pat(65, 0xa3 + i) for i in range(3))
    # (g) type 11 ProUpShareTx
    v["proupshare"] = u16(1) + pat(32, 0xb1) + u16(2) + vec(p2pkh(pat(20, 0xb2))) + pat(32, 0xb3) + vec(pat(65, 0xb4))
    # (h) type 12 ProUpSharedRegTx: sig count + sigs ride after inputsHash
    v["proupsharedreg"] = (u16(1) + pat(32, 0xc1) + keys["proupsharedreg"] + pat(20, 0xc3) + pat(32, 0xc4)
                           + u8(3) + b"".join(pat(65, 0xc5 + i) for i in range(3)))
    # (i) ProRegTx v1 (legacy-scheme key) and v2 EvoNode (basic), legacy CService ::ffff:1.2.3.4:9999
    service = bytes(10) + b"\xff\xff" + ipv4("1.2.3.4") + be16(9999)
    v["proreg_v1"] = proreg_legacy(1, 0, pat(32, 0x01), 0, service, pat(20, 0x02), keys["proreg_v1"],
                                   pat(20, 0x04), 0, p2pkh(pat(20, 0x05)), pat(32, 0x06))
    v["proreg_v2_evo"] = proreg_legacy(2, 1, pat(32, 0x01), 0, service, pat(20, 0x02), keys["proreg_v2_evo"],
                                       pat(20, 0x04), 0, p2pkh(pat(20, 0x05)), pat(32, 0x06),
                                       nodeid=pat(20, 0x07), p2p_port=26656, http_port=443)
    for name, b in v.items():
        t = SYN_TYPE[name]
        check_decodes(dashd, t, b, keys.get(name) if t in (1, 3, 12) else None)
    return v, keys, sigs


SYN_TYPE = {"proreg_shared": 1, "proreg_multipayout": 1, "proreg_evo": 1, "proupreg": 3,
            "proupserv": 2, "prouprev": 4, "prodis_uni": 10, "prodis_all": 10, "proupshare": 11,
            "proupsharedreg": 12, "proreg_v1": 1, "proreg_v2_evo": 1}


def bls_facts(bls, dashd, syn, keys, sigs, rows):
    """What Core's decoding makes of each BLS encoding the tests use:
    (name, bytes, legacy, core_ok). Each is confirmed twice: by dashbls
    (bls_helper) and by dashd, which decodes it inside a payload."""
    key_facts, sig_facts = [], []

    def key_fact(name, k, legacy, want):
        assert bls.g1valid(k, legacy) == want, ("dashbls", name)
        if legacy:   # inside the v1 ProRegTx
            b = syn["proreg_v1"]
            at = b.index(keys["proreg_v1"])
            o = check_decodes(dashd, 1, b[:at] + k + b[at + 48:])
        else:        # inside the v3 ProUpRegTx
            b = syn["proupreg"]
            at = b.index(keys["proupreg"])
            o = check_decodes(dashd, 3, b[:at] + k + b[at + 48:])
        assert (o["pubKeyOperator"] == k.hex()) == want, ("dashd", name, o["pubKeyOperator"])
        assert want or o["pubKeyOperator"] == "00" * 48, ("dashd", name)
        key_facts.append((name, k, legacy, want))

    def sig_fact(name, sg, want):
        assert bls.g2decodes(sg, False) == want, ("dashbls", name)
        b = syn["proupserv"]
        o = dashd.payload_object(2, b[:-96] + sg)
        assert (o is not None) == want, ("dashd", name)
        sig_facts.append((name, sg, False, want))

    for name, k in keys.items():
        key_fact("key:" + name, k, name == "proreg_v1", True)
    for r in rows:
        if r["txtype"] == 1:
            key_fact("key:testnet " + r["txid"][:16], bytes.fromhex(r["opkey"]), False, True)
    # Invalid keys. Basic-scheme flags: 0x80 compressed, 0x40 infinity, 0x20 sign.
    key_fact("key:identity", bytes([0xc0]) + bytes(47), False, False)
    for fill in (0x01, 0x80, 0xff):  # the S2 verify harness's filled keys
        key_fact("key:0x%02x-filled" % fill, bytes([fill]) * 48, False, False)
    key_fact("key:x>=p", bytes([0x9f]) + b"\xff" * 47, False, False)
    for x in range(1, 64):
        k = bytes([0x80]) + x.to_bytes(47, "big")
        if not bls.g1valid(k, False):
            key_fact("key:x=%d not on the curve" % x, k, False, False)
            break
    else:
        raise AssertionError("no small off-curve x")
    for i in range(9, 120):         # x + p still fits the 381 bits of a key: a second encoding
        base = bls.pub(i, False)
        xa = int.from_bytes(bytes([base[0] & 0x1f]) + base[1:], "big") + BLS_P
        if xa < (1 << 381):
            alias = xa.to_bytes(48, "big")
            key_fact("key:x+p alias of the valid key of secret %d" % i,
                     bytes([alias[0] | (base[0] & 0xe0)]) + alias[1:], False, False)
            break
    else:
        raise AssertionError("no key with a small enough x")
    for i in range(9, 64):          # a legacy encoding without the sign bit: no basic flag
        lk = bls.pub(i, True)
        if lk[0] & 0x80 == 0:
            key_fact("key:legacy encoding in a basic payload", lk, False, False)
            break
    else:
        raise AssertionError("no legacy key without the sign bit")
    bk = bls.pub(KEY_OF["proreg_v1"], False)   # the basic encoding read as legacy
    key_fact("key:basic encoding in a legacy payload", bk, True, bls.g1valid(bk, True))
    lk = keys["proreg_v1"]                     # the legacy encoding read as basic
    key_fact("key:proreg_v1 read in a basic payload", lk, False, bls.g1valid(lk, False))
    # Legacy scheme: 0x80 is the sign bit, 0x40 infinity.
    key_fact("key:x>=p (legacy)", bytes([0x1f]) + b"\xff" * 47, True, False)
    key_fact("key:infinity flag (legacy)", bytes([0x40]) + bytes(47), True,
             bls.g1valid(bytes([0x40]) + bytes(47), True))
    # Signatures (in the v3 ProUpServTx; read in the basic scheme).
    for name, sg in sigs.items():
        sig_fact("sig:" + name, sg, True)
    for r in rows:
        if r["txtype"] in (2, 4):
            sig_fact("sig:testnet " + r["txid"][:16], bytes.fromhex(r["payload"])[-96:], True)
    sig_fact("sig:null", bytes(96), True)
    sig_fact("sig:legacy encoding (read, then reset by Core)",
             bls.sign(KEY_OF["proupserv"], dsha(syn["proupserv"][:-96]), legacy=True), True)
    sig_fact("sig:all ff", b"\xff" * 96, False)
    sig_fact("sig:identity", bytes([0xc0]) + bytes(95), False)
    sig_fact("sig:x>=p", bytes([0x9f]) + b"\xff" * 95, False)
    return key_facts, sig_facts


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


def arg(name):
    if name not in sys.argv:
        sys.exit("missing %s (see the usage)" % name)
    return sys.argv[sys.argv.index(name) + 1]


def main():
    txdir, out = sys.argv[1], sys.argv[2]
    bls, dashd = Bls(arg("--bls-helper")), Dashd(arg("--dash-cli"))
    rows = testnet_fixtures(txdir)
    for r in rows:
        check_decodes(dashd, r["txtype"], bytes.fromhex(r["payload"]),
                      bytes.fromhex(r["opkey"]) if r["txtype"] == 1 else None)
    syn, keys, sigs = syn_vectors(bls, dashd)
    key_facts, sig_facts = bls_facts(bls, dashd, syn, keys, sigs, rows)
    sml = sml_vectors()
    o = ["// SPDX-License-Identifier: AGPL-3.0-or-later\n",
         "// Generated by test/fixtures/dash_v24/gen_s2_vectors.py -- do not edit by hand.\n",
         "// Testnet rows: raw bytes rebuilt from the tx JSON, SHA256d checked against the txid,\n",
         "// fields cross-checked against the JSON decode. Synthetic rows: Dash Core v24.0.0 layout,\n",
         "// real BLS operator keys and signatures (fixed secrets), every payload decoded by\n",
         "// dashd 24.0.0 (decoderawtransaction) with the same operator key.\n\n",
         "struct TestnetProTxFixture {\n"
         "    const char* txid; uint32_t height; uint16_t txtype; uint16_t mntype;\n"
         "    const char* raw; const char* payload;\n"
         "    const char* ref;        // collateral hash (type 1) or proTxHash (types 2, 4)\n"
         "    uint32_t index;         // collateral index (type 1) or revocation reason (type 4)\n"
         "    const char* addresses;  // purpose=addr:port,...;... (the JSON `addresses`)\n"
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
    for k in ("proreg_shared", "proreg_multipayout", "proreg_evo", "proupreg", "proupserv", "prouprev",
              "prodis_uni", "prodis_all", "proupshare", "proupsharedreg", "proreg_v1", "proreg_v2_evo"):
        o.append(cstr("kSyn_" + k, syn[k]))
    o.append("\n// Operator keys of the synthetic payloads: secret {i, 0, ..., 0} (i in the name).\n")
    for k, i in KEY_OF.items():
        o.append(cstr("kOpKey_%s /* secret %d, %s */" % (k, i, "legacy" if k == "proreg_v1" else "basic"), keys[k]))
    for k in ("proupserv", "prouprev"):
        o.append(cstr("kSig_" + k, sigs[k]))
    o.append("\n// What Core's decoding makes of each BLS encoding (dashd- and dashbls-confirmed).\n"
             "// Keys: CBLSLazyPublicKey::Get().IsValid() under `legacy`. Signatures:\n"
             "// CBLSSignature::Unserialize(s, legacy) does not throw.\n"
             "struct BlsFact { const char* what; const char* bytes; bool legacy; bool core_ok; };\n")
    for tname, facts in (("kBlsKeyFacts", key_facts), ("kBlsSigFacts", sig_facts)):
        o.append("static const BlsFact %s[] = {\n" % tname)
        for name, b, legacy, ok in facts:
            o.append('    {"%s", "%s", %s, %s},\n' % (name, b.hex(), "true" if legacy else "false",
                                                    "true" if ok else "false"))
        o.append("};\n")
    o.append("\n")
    for k in ("sml_evo_v3", "sml_evo_v2", "sml_reg_v3", "sml_reg_v2", "sml_reg_v3_empty"):
        o.append(cstr("kSml_" + k + "_wire", sml[k][0]))
        o.append(cstr("kSml_" + k + "_hash", dsha(sml[k][1])))
    o.append(cstr("kSml_diff", sml["diff"]))
    o.append(cstr("kSml_diff_root", sml["diff_root"]))
    open(out, "w").write("".join(o))
    print("testnet rows:", len(rows), "synthetic:", len(syn), "key facts:", len(key_facts),
          "sig facts:", len(sig_facts), "sml:", len(sml))


if __name__ == "__main__":
    main()
