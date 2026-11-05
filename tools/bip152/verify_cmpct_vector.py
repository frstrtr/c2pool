#!/usr/bin/env python3
"""Check a captured cmpctblock vector against BIP 152 with an independent
SipHash-2-4 (pure Python, no c2pool code, no daemon).

    verify_cmpct_vector.py <coin>.json

Verifies, for every capture in the JSON:
  * the payload parses as BIP 152 HeaderAndShortIDs: header(80) | nonce(u64 LE)
    | shortids | prefilled (one entry: index 0 = the coinbase, bytes identical
    to getblock's tx[0].hex, witness serialization);
  * the header equals getblockheader's bytes and SHA256d(header) == block hash;
  * k0,k1 = first two LE64 words of ONE SHA256(header || nonce_le64) and
    SipHash-2-4(k0,k1, wtxid) & 0xffffffffffff reproduces EVERY short id the
    daemon sent (BIP 152 / Core blockencodings.cpp FillShortTxIDSelector);
  * the pre-fix c2pool derivation (SHA256d(header) XOR nonce for both words)
    matches NONE of them (so a KAT built on this vector fails on today's code);
  * every non-coinbase tx has wtxid != txid (short ids are by wtxid, v2).
Exit status 0 only if everything holds.
"""
import hashlib, json, struct, sys

M64 = (1 << 64) - 1


def rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & M64


def siphash24(k0, k1, data):
    v0 = k0 ^ 0x736f6d6570736575
    v1 = k1 ^ 0x646f72616e646f6d
    v2 = k0 ^ 0x6c7967656e657261
    v3 = k1 ^ 0x7465646279746573

    def rounds(n):
        nonlocal v0, v1, v2, v3
        for _ in range(n):
            v0 = (v0 + v1) & M64; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32)
            v2 = (v2 + v3) & M64; v3 = rotl(v3, 16); v3 ^= v2
            v0 = (v0 + v3) & M64; v3 = rotl(v3, 21); v3 ^= v0
            v2 = (v2 + v1) & M64; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32)

    n = len(data)
    full = n - (n % 8)
    for i in range(0, full, 8):
        m = int.from_bytes(data[i:i + 8], 'little')
        v3 ^= m
        rounds(2)
        v0 ^= m
    b = (n & 0xff) << 56
    b |= int.from_bytes(data[full:].ljust(8, b'\0'), 'little') & ((1 << 56) - 1)
    v3 ^= b
    rounds(2)
    v0 ^= b
    v2 ^= 0xff
    rounds(4)
    return (v0 ^ v1 ^ v2 ^ v3) & M64


def sha256(b):
    return hashlib.sha256(b).digest()


def sha256d(b):
    return sha256(sha256(b))


def read_compact_size(b, off):
    c = b[off]
    if c < 253:
        return c, off + 1
    if c == 253:
        return struct.unpack_from('<H', b, off + 1)[0], off + 3
    if c == 254:
        return struct.unpack_from('<I', b, off + 1)[0], off + 5
    return struct.unpack_from('<Q', b, off + 1)[0], off + 9


def bip152_keys(header, nonce):
    h = sha256(header + struct.pack('<Q', nonce))
    return int.from_bytes(h[0:8], 'little'), int.from_bytes(h[8:16], 'little')


def old_c2pool_keys(header, nonce):
    h = sha256d(header)
    return (int.from_bytes(h[0:8], 'little') ^ nonce,
            int.from_bytes(h[8:16], 'little') ^ nonce)


def short_id(k0, k1, hash_hex):
    return siphash24(k0, k1, bytes.fromhex(hash_hex)[::-1]) & 0xffffffffffff


def check(cond, what, fails):
    print(('  ok   ' if cond else '  FAIL ') + what)
    if not cond:
        fails.append(what)


def main():
    v = json.load(open(sys.argv[1]))
    fails = []
    header = bytes.fromhex(v['header_hex'])
    print(f"{v['coin']}: {v['daemon_version']} block {v['height']} {v['block_hash']} ({len(v['txs'])} txs)")
    check(len(header) == 80, 'header is 80 bytes', fails)
    check(sha256d(header)[::-1].hex() == v['block_hash'], 'SHA256d(header) == block hash', fails)
    check(v['block_hex'].startswith(v['header_hex']), 'block hex starts with the header', fails)
    for t in v['txs'][1:]:
        check(t['txid'] != t['wtxid'], f"tx {t['txid'][:12]} has a witness (wtxid != txid)", fails)

    for name, cap in v['captures'].items():
        print(f"capture {name}: {cap['command']} ({len(cap['payload_hex']) // 2} bytes) from {cap['peer_user_agent']}")
        check(cap['command'] == 'cmpctblock', 'daemon answered getdata(MSG_CMPCT_BLOCK) with cmpctblock', fails)
        p = bytes.fromhex(cap['payload_hex'])
        check(p[:80] == header, 'payload header == getblockheader bytes', fails)
        nonce = struct.unpack_from('<Q', p, 80)[0]
        off = 88
        n_short, off = read_compact_size(p, off)
        check(n_short == len(v['txs']) - 1, f'{n_short} short ids == txcount-1', fails)
        sids = [int.from_bytes(p[off + 6 * i: off + 6 * i + 6], 'little') for i in range(n_short)]
        off += 6 * n_short
        n_pre, off = read_compact_size(p, off)
        check(n_pre == 1, 'exactly one prefilled tx', fails)
        idx, off = read_compact_size(p, off)
        check(idx == 0, 'prefilled index 0 (coinbase)', fails)
        check(p[off:] == bytes.fromhex(v['txs'][0]['hex']), 'prefilled bytes == coinbase witness serialization; nothing follows', fails)

        k0, k1 = bip152_keys(header, nonce)
        print(f"  nonce=0x{nonce:016x} k0=0x{k0:016x} k1=0x{k1:016x} (SHA256(header||nonce_le))")
        good = [short_id(k0, k1, t['wtxid']) for t in v['txs'][1:]]
        check(good == sids, 'BIP152 keys reproduce every daemon short id (by wtxid)', fails)
        by_txid = [short_id(k0, k1, t['txid']) for t in v['txs'][1:]]
        check(sum(a == b for a, b in zip(by_txid, sids)) == 0, 'short ids by TXID match none (v2 is wtxid)', fails)
        ok0, ok1 = old_c2pool_keys(header, nonce)
        old = [short_id(ok0, ok1, t['wtxid']) for t in v['txs'][1:]]
        check(sum(a == b for a, b in zip(old, sids)) == 0, 'pre-fix derivation SHA256d(header)^nonce matches none', fails)
        for i, (s, g) in enumerate(zip(sids, good), 1):
            print(f"    tx{i} daemon={s:012x} bip152={g:012x} old={old[i-1]:012x}")
    if fails:
        print(f"\n{len(fails)} FAILURE(S)")
        sys.exit(1)
    print("\nall checks passed")


main()
