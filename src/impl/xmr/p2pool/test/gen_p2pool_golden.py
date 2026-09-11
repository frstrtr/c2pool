#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
#
# ---------------------------------------------------------------------------
# gen_p2pool_golden.py -- turn real captured P2Pool frames into the KAT golden.
#
#   xmr_p2pool_observer --chain mini --capture-golden A.bin --capture-mm B.bin
#   python3 gen_p2pool_golden.py A.bin B.bin > p2pool_golden_frames.hpp
#
# WHY THIS SCRIPT EXISTS AND IS NOT JUST A HEXDUMP. The expected values it
# writes into the header are computed HERE, by an INDEPENDENT implementation of
# the P2Pool block format and of Monero's block identity -- a few hundred lines
# of Python that share no code with the C++ under test. So the KAT is a
# cross-implementation check, not a photograph of whatever the C++ happened to
# produce on the day. Two different readings of the same live bytes have to
# agree on the sidechain id, the embedded Monero block id, the PPLNS share
# count and every field in between.
#
# The frames themselves are copied byte for byte, message-id and length prefix
# included. Nothing is normalised, trimmed or re-serialised.
# ---------------------------------------------------------------------------

import struct
import sys

# --- keccak-256 (legacy padding), pure python --------------------------------
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
       [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
M64 = (1 << 64) - 1


def _rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M64


def _keccak_f(A):
    for rnd in range(24):
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rol(A[x][y], ROT[x][y])
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & M64 & B[(x + 2) % 5][y])
        A[0][0] ^= RC[rnd]
    return A


def keccak256(data):
    rate = 136
    A = [[0] * 5 for _ in range(5)]
    pad = bytearray(data)
    pad.append(0x01)
    while len(pad) % rate != 0:
        pad.append(0x00)
    pad[-1] |= 0x80
    for off in range(0, len(pad), rate):
        blk = pad[off:off + rate]
        for i in range(rate // 8):
            A[i % 5][i // 5] ^= int.from_bytes(blk[i * 8:i * 8 + 8], 'little')
        A = _keccak_f(A)
    return b''.join(A[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))


# --- CryptoNote varint + tree hash -------------------------------------------
def read_varint(b, i):
    r, sh = 0, 0
    while True:
        c = b[i]
        i += 1
        r |= (c & 0x7F) << sh
        if not (c & 0x80):
            return r, i
        sh += 7
        if sh > 63:
            raise ValueError('varint overflow')


def write_varint(v):
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _tree_hash_cnt(count):
    # largest power of two strictly below `count`
    assert 3 <= count
    p = 1
    while p * 2 < count:
        p *= 2
    return p


def tree_hash(hashes):
    n = len(hashes)
    if n == 1:
        return hashes[0]
    if n == 2:
        return keccak256(hashes[0] + hashes[1])
    cnt = _tree_hash_cnt(n)
    ints = list(hashes[:2 * cnt - n])
    i = 2 * cnt - n
    while len(ints) < cnt:
        ints.append(keccak256(hashes[i] + hashes[i + 1]))
        i += 2
    while cnt > 2:
        cnt >>= 1
        ints = [keccak256(ints[2 * j] + ints[2 * j + 1]) for j in range(cnt)]
    return keccak256(ints[0] + ints[1])


# --- the P2Pool block format --------------------------------------------------
MINI = bytes([57, 130, 201, 26, 149, 174, 199, 250, 66, 80, 189, 18, 108, 216, 194, 220,
              136, 23, 63, 24, 64, 113, 221, 44, 219, 86, 39, 163, 53, 24, 126, 196])
MAIN = bytes([34, 175, 126, 231, 181, 11, 104, 146, 227, 153, 218, 107, 44, 108, 68, 39,
              178, 81, 4, 212, 169, 4, 142, 0, 177, 110, 157, 240, 68, 7, 249, 24])


def parse_pool_block(b, consensus):
    i = 0
    o = {}
    o['major'] = b[i]; i += 1
    o['minor'] = b[i]; i += 1
    o['timestamp'], i = read_varint(b, i)
    o['prev_id'] = b[i:i + 32]; i += 32
    nonce_off = i
    o['nonce'] = struct.unpack_from('<I', b, i)[0]; i += 4
    assert b[i] == 2; i += 1
    unlock, i = read_varint(b, i)
    assert b[i] == 1; i += 1
    assert b[i] == 0xFF; i += 1
    o['txin_gen_height'], i = read_varint(b, i)
    assert unlock == o['txin_gen_height'] + 60
    n_out, i = read_varint(b, i)
    total = 0
    for _ in range(n_out):
        rw, i = read_varint(b, i)
        total += rw
        assert b[i] == 3; i += 1
        i += 32
        i += 1
    o['n_outputs'] = n_out
    o['total_reward'] = total
    extra_size, i = read_varint(b, i)
    extra_begin = i
    assert b[i] == 1; i += 1
    o['txkey_pub'] = b[i:i + 32]; i += 32
    assert b[i] == 2; i += 1
    en_size, i = read_varint(b, i)
    extra_nonce_off = i
    o['extra_nonce'] = struct.unpack_from('<I', b, i)[0]; i += 4
    for _ in range(en_size - 4):
        assert b[i] == 0; i += 1
    assert b[i] == 3; i += 1
    mm_size, i = read_varint(b, i)
    mm_begin = i
    mtd, i = read_varint(b, i)
    k = mtd & 0xFFFFFFFF
    n = 1 + (k & 7)
    o['mm_n_aux_chains'] = 1 + ((k >> 3) & ((1 << n) - 1))
    o['mm_nonce'] = mtd >> (3 + n)
    mm_root_off = i
    o['merkle_root'] = b[i:i + 32]; i += 32
    assert i - mm_begin == mm_size
    assert i - extra_begin == extra_size
    assert b[i] == 0; i += 1
    n_tx, i = read_varint(b, i)
    o['tx_hashes'] = [b[i + 32 * t:i + 32 * (t + 1)] for t in range(n_tx)]
    i += 32 * n_tx
    o['sidechain_offset'] = i
    o['miner_spend'] = b[i:i + 32]; i += 32
    o['miner_view'] = b[i:i + 32]; i += 32
    o['txkey_sec_seed'] = b[i:i + 32]; i += 32
    o['parent'] = b[i:i + 32]; i += 32
    n_unc, i = read_varint(b, i)
    o['uncles'] = [b[i + 32 * u:i + 32 * (u + 1)] for u in range(n_unc)]
    i += 32 * n_unc
    o['sidechain_height'], i = read_varint(b, i)
    dlo, i = read_varint(b, i)
    dhi, i = read_varint(b, i)
    o['difficulty'] = (dlo, dhi)
    clo, i = read_varint(b, i)
    chi, i = read_varint(b, i)
    o['cumulative_difficulty'] = (clo, chi)
    mp = b[i]; i += 1
    o['merkle_proof'] = [b[i + 32 * m:i + 32 * (m + 1)] for m in range(mp)]
    i += 32 * mp
    mmx, i = read_varint(b, i)
    mm_extra = []
    for _ in range(mmx):
        cid = b[i:i + 32]; i += 32
        ln, i = read_varint(b, i)
        mm_extra.append((cid, b[i:i + ln])); i += ln
    o['mm_extra'] = mm_extra
    o['sidechain_extra'] = struct.unpack_from('<4I', b, i); i += 16
    assert i == len(b), 'trailing bytes'

    z = bytearray(b)
    for j in range(nonce_off, nonce_off + 4):
        z[j] = 0
    for j in range(extra_nonce_off, extra_nonce_off + 4):
        z[j] = 0
    for j in range(mm_root_off, mm_root_off + 32):
        z[j] = 0
    o['sidechain_id'] = keccak256(bytes(z) + consensus)
    return o


def monero_identity(mblob):
    """Coinbase hash, tree root, hashing blob and block id of an embedded template."""
    i = 0
    _major, i = read_varint(mblob, i)
    _minor, i = read_varint(mblob, i)
    _ts, i = read_varint(mblob, i)
    i += 32 + 4
    header_end = i
    tx_start = i
    ver, i = read_varint(mblob, i)
    _unlock, i = read_varint(mblob, i)
    n_in, i = read_varint(mblob, i)
    assert n_in == 1 and mblob[i] == 0xFF
    i += 1
    _h, i = read_varint(mblob, i)
    n_out, i = read_varint(mblob, i)
    for _ in range(n_out):
        _a, i = read_varint(mblob, i)
        assert mblob[i] == 3
        i += 1 + 32 + 1
    extra_len, i = read_varint(mblob, i)
    i += extra_len
    prefix_end = i
    assert ver >= 2
    assert mblob[i] == 0          # RCTTypeNull
    i += 1
    tx_end = i
    n_tx, i = read_varint(mblob, i)
    tx_hashes = [mblob[i + 32 * t:i + 32 * (t + 1)] for t in range(n_tx)]
    i += 32 * n_tx
    assert i == len(mblob), 'trailing bytes in monero blob'

    prefix_hash = keccak256(mblob[tx_start:prefix_end])
    null32 = b'\x00' * 32
    miner_hash = keccak256(prefix_hash + keccak256(b'\x00') + null32)
    root = tree_hash([miner_hash] + tx_hashes)
    hashing = mblob[:header_end] + root + write_varint(n_tx + 1)
    block_id = keccak256(write_varint(len(hashing)) + hashing)
    return {'miner_tx_hash': miner_hash, 'tree_root': root, 'hashing_blob': hashing,
            'block_id': block_id, 'n_tx': n_tx, 'tx_size': tx_end - tx_start}


def hexstr(b):
    return b.hex()


def emit_frame(name, path, consensus_name, consensus):
    raw = open(path, 'rb').read()
    assert raw[0] == 4, 'not a BLOCK_RESPONSE frame'
    body_len = struct.unpack_from('<I', raw, 1)[0]
    assert body_len + 5 == len(raw), 'frame length mismatch'
    body = raw[5:]
    pb = parse_pool_block(body, consensus)
    mid = monero_identity(body[:pb['sidechain_offset']])

    print('// ---------------------------------------------------------------------------')
    print('// %s -- a real BLOCK_RESPONSE frame from the live P2Pool %s sidechain.'
          % (name, consensus_name))
    print('// Frame: %d bytes (1 id + 4 length + %d body). Nothing stripped.'
          % (len(raw), body_len))
    print('// sidechain height %d, id %s' % (pb['sidechain_height'], hexstr(pb['sidechain_id'])))
    print('// ---------------------------------------------------------------------------')
    print('inline constexpr const char* k%sFrameHex =' % name)
    h = raw.hex()
    for off in range(0, len(h), 128):
        print('    "%s"' % h[off:off + 128])
    print('    ;')
    print()
    print('inline constexpr GoldenExpect k%sExpect = {' % name)
    print('    /* frame_bytes           */ %du,' % len(raw))
    print('    /* body_bytes            */ %du,' % body_len)
    print('    /* sidechain_id          */ "%s",' % hexstr(pb['sidechain_id']))
    print('    /* sidechain_height      */ %dull,' % pb['sidechain_height'])
    print('    /* parent                */ "%s",' % hexstr(pb['parent']))
    print('    /* difficulty_lo         */ %dull,' % pb['difficulty'][0])
    print('    /* difficulty_hi         */ %dull,' % pb['difficulty'][1])
    print('    /* cumulative_lo         */ %dull,' % pb['cumulative_difficulty'][0])
    print('    /* cumulative_hi         */ %dull,' % pb['cumulative_difficulty'][1])
    print('    /* uncle_count           */ %du,' % len(pb['uncles']))
    print('    /* share_outputs         */ %du,' % pb['n_outputs'])
    print('    /* total_reward          */ %dull,' % pb['total_reward'])
    print('    /* tx_count              */ %du,' % len(pb['tx_hashes']))
    print('    /* merkle_proof_len      */ %du,' % len(pb['merkle_proof']))
    print('    /* mm_extra_count        */ %du,' % len(pb['mm_extra']))
    print('    /* mm_n_aux_chains       */ %du,' % pb['mm_n_aux_chains'])
    print('    /* mm_nonce              */ %du,' % pb['mm_nonce'])
    print('    /* major_version         */ %du,' % pb['major'])
    print('    /* minor_version         */ %du,' % pb['minor'])
    print('    /* monero_timestamp      */ %dull,' % pb['timestamp'])
    print('    /* monero_nonce          */ %du,' % pb['nonce'])
    print('    /* monero_height         */ %dull,' % pb['txin_gen_height'])
    print('    /* monero_prev_id        */ "%s",' % hexstr(pb['prev_id']))
    print('    /* sidechain_offset      */ %du,' % pb['sidechain_offset'])
    print('    /* monero_block_id       */ "%s",' % hexstr(mid['block_id']))
    print('    /* monero_miner_tx_hash  */ "%s",' % hexstr(mid['miner_tx_hash']))
    print('    /* monero_tree_root      */ "%s",' % hexstr(mid['tree_root']))
    print('    /* monero_hashing_bytes  */ %du,' % len(mid['hashing_blob']))
    print('    /* merkle_root           */ "%s",' % hexstr(pb['merkle_root']))
    print('    /* txkey_pub             */ "%s",' % hexstr(pb['txkey_pub']))
    print('};')
    print()
    if pb['mm_extra']:
        print('inline constexpr const char* k%sMergeMiningChainIds[] = {' % name)
        for cid, _d in pb['mm_extra']:
            print('    "%s",' % hexstr(cid))
        print('};')
        print()


def main():
    if len(sys.argv) < 3:
        sys.stderr.write('usage: gen_p2pool_golden.py A.bin B.bin\n')
        return 2
    print('// SPDX-License-Identifier: AGPL-3.0-or-later')
    print('// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)')
    print('//')
    print('// GENERATED by gen_p2pool_golden.py from frames captured on the LIVE P2Pool')
    print('// mini sidechain. Do not edit by hand; re-capture and re-run the script.')
    print('#pragma once')
    print()
    print('#include <cstdint>')
    print()
    print('namespace c2pool::xmr::p2pool::golden {')
    print()
    print('struct GoldenExpect {')
    for f in ('frame_bytes', 'body_bytes'):
        print('    std::uint32_t %s;' % f)
    print('    const char*   sidechain_id;')
    print('    std::uint64_t sidechain_height;')
    print('    const char*   parent;')
    print('    std::uint64_t difficulty_lo;')
    print('    std::uint64_t difficulty_hi;')
    print('    std::uint64_t cumulative_lo;')
    print('    std::uint64_t cumulative_hi;')
    print('    std::uint32_t uncle_count;')
    print('    std::uint32_t share_outputs;')
    print('    std::uint64_t total_reward;')
    print('    std::uint32_t tx_count;')
    print('    std::uint32_t merkle_proof_len;')
    print('    std::uint32_t mm_extra_count;')
    print('    std::uint32_t mm_n_aux_chains;')
    print('    std::uint32_t mm_nonce;')
    print('    std::uint32_t major_version;')
    print('    std::uint32_t minor_version;')
    print('    std::uint64_t monero_timestamp;')
    print('    std::uint32_t monero_nonce;')
    print('    std::uint64_t monero_height;')
    print('    const char*   monero_prev_id;')
    print('    std::uint32_t sidechain_offset;')
    print('    const char*   monero_block_id;')
    print('    const char*   monero_miner_tx_hash;')
    print('    const char*   monero_tree_root;')
    print('    std::uint32_t monero_hashing_bytes;')
    print('    const char*   merkle_root;')
    print('    const char*   txkey_pub;')
    print('};')
    print()
    emit_frame('A', sys.argv[1], 'mini', MINI)
    emit_frame('B', sys.argv[2], 'mini', MINI)
    print('} // namespace c2pool::xmr::p2pool::golden')
    return 0


if __name__ == '__main__':
    sys.exit(main())
