#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
#
# Golden vectors of v37_xmr_side_data_v3_kat: side_data_v3 bytes laid out from
# the field table with struct, and mm_root = Keccak-256(domain || bytes) from a
# reference Keccak-f[1600] (original 0x01 padding); the ratchet state S (134 B)
# laid out from its field table, rs_root = sha256d("c2pool-v37-rs1" || S) and
# receipts_root = sha256d("c2pool-v37-carry" || carried_root || rs_root) with
# hashlib. Python 3 standard library.
RC=[0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,0x000000000000808B,0x0000000080000001,
0x8000000080008081,0x8000000000008009,0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,
0x000000000000800A,0x800000008000000A,0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
ROT=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
M=(1<<64)-1
def rol(x,n): return ((x<<n)|(x>>(64-n)))&M if n else x
def f(A):
    for rc in RC:
        C=[A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4] for x in range(5)]
        D=[C[(x-1)%5]^rol(C[(x+1)%5],1) for x in range(5)]
        A=[[A[x][y]^D[x] for y in range(5)] for x in range(5)]
        B=[[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5): B[y][(2*x+3*y)%5]=rol(A[x][y],ROT[x][y])
        A=[[B[x][y]^((~B[(x+1)%5][y])&B[(x+2)%5][y]) for y in range(5)] for x in range(5)]
        A[0][0]^=rc
    return A
def keccak256(data):
    rate=136; p=bytearray(data); p.append(0x01)
    while len(p)%rate: p.append(0)
    p[-1]|=0x80
    A=[[0]*5 for _ in range(5)]
    for off in range(0,len(p),rate):
        blk=p[off:off+rate]
        for i in range(rate//8):
            x,y=i%5,i//5; A[x][y]^=int.from_bytes(blk[8*i:8*i+8],'little')
        A=f(A)
    out=b''.join(A[i%5][i//5].to_bytes(8,'little') for i in range(4))
    return out
assert keccak256(b'').hex()=='c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'


def sha256d(b):
    import hashlib
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def ratchet_state(epoch_cur, rules_cur, all_, y1, y2, levels):
    import struct
    assert len(rules_cur) == 32 and len(levels) == 4
    return (struct.pack('<H', epoch_cur) + rules_cur + all_.to_bytes(32, 'little') + y1.to_bytes(32, 'little')
            + y2.to_bytes(32, 'little') + bytes(levels))


def main():
    import struct

    def seq(b):
        return bytes((b + i) & 0xff for i in range(32))

    sd = (bytes([3]) + seq(0x01) + struct.pack('<H', 0x0201) + struct.pack('<H', 0x0403) + seq(0x40)
          + struct.pack('<Q', 0x0807060504030201) + seq(0x60) + seq(0xA0)
          + seq(0xC0) + seq(0xE0) + struct.pack('<H', 0x0102) + seq(0x21) + struct.pack('<H', 10))
    assert len(sd) == 241
    print('side_bytes', sd.hex())
    print('mm_root', keccak256(b'c2pool-v37-xmr-side-v3' + sd).hex())

    # S after three carriers of d 18,180 on genesis, every ballot 0.
    s3 = ratchet_state(0, seq(0x11), 3 * 18180, 0, 0, [0, 0, 0, 0])
    assert len(s3) == 134
    rs3 = sha256d(b'c2pool-v37-rs1' + s3)
    print('s1_state', s3.hex())
    print('s1_rs_root', rs3.hex())
    print('s1_receipts_root', sha256d(b'c2pool-v37-carry' + bytes(32) + rs3).hex())
    print('s1_receipts_root_carried', sha256d(b'c2pool-v37-carry' + seq(0x30) + rs3).hex())

    # Every field set.
    limbs = lambda a, b, c, d: a | (b << 64) | (c << 128) | (d << 192)
    sx = ratchet_state(0x0102, seq(0x20), limbs(1, 2, 3, 4), limbs(5, 6, 7, 8), limbs(9, 10, 11, 12), [0, 1, 2, 1])
    print('full_state', sx.hex())
    print('full_rs_root', sha256d(b'c2pool-v37-rs1' + sx).hex())


if __name__ == '__main__':
    main()
