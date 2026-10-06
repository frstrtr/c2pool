#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
#
# Golden vector of v37_xmr_side_data_v3_kat: side_data_v3 bytes laid out from
# the field table with struct, and mm_root = Keccak-256(domain || bytes) from a
# reference Keccak-f[1600] (original 0x01 padding). Python 3 standard library.
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


def main():
    import struct

    def seq(b):
        return bytes((b + i) & 0xff for i in range(32))

    sd = (bytes([3]) + seq(0x01) + struct.pack('<I', 0x04030201) + seq(0x40)
          + struct.pack('<Q', 0x0807060504030201) + seq(0x60) + seq(0x80) + seq(0xA0)
          + seq(0xC0) + seq(0xE0) + struct.pack('<H', 0x0102) + seq(0x21) + struct.pack('<H', 10))
    assert len(sd) == 273
    print('side_bytes', sd.hex())
    print('mm_root', keccak256(b'c2pool-v37-xmr-side-v3' + sd).hex())


if __name__ == '__main__':
    main()
