#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# bip110_gpu_miner.py — GPU (CuPy RawKernel BLAKE2b) BIP-110 Stratum-v1 test miner.
#
# Host-side Sv1 plumbing is reused VERBATIM from the proven CPU miner
# (bip110_miner.py, gate wcbszi5xo). ONLY the nonce loop is swapped for a
# CUDA BLAKE2b kernel JIT-compiled by CuPy through the driver-provided nvrtc.
#
# The kernel's BLAKE2b core is self-tested against live fork block 961640's
# canonical display hash BEFORE mining (feeds the block's REAL 80-byte
# profile-0 buffer through the SAME __device__ blake2b core the mining kernel
# uses, and asserts byte-for-byte == canonical == the Python reference fold).
# A wrong core fails the self-test and aborts, so an accepted share proves
# genuine GPU BLAKE2b work.
#
# Usage:
#   python3 bip110_gpu_miner.py --selftest-only
#   python3 bip110_gpu_miner.py --host bip110.voidbind.com --port 9336 \
#       --address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 --worker legion64gpu \
#       --diff 1 --minutes 600 --log /tmp/legion64_gpu_miner.log

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import time

# ─────────────────────────── PoW primitives (CPU reference) ─────────────

def sha256(b):
    return hashlib.sha256(b).digest()

def tagged_hash(tag, msg):
    th = sha256(tag.encode())
    return sha256(th + th + msg)

def blake2b256(b):
    return hashlib.blake2b(b, digest_size=32).digest()

# ─────────────────────────── KAT self-test vector ──────────────────────

KAT_HEADER_HEX = "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc7684dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d0300000000000000000000001e0300000000000000000000000000000000000068ac0e000000000000000000000000000000000000000000000000000000000000000000"
KAT_CANONICAL = "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb"


def parse_header_v2(h):
    assert len(h) == 164, "v2 header must be 164 bytes, got %d" % len(h)
    o = {}
    p = 0
    def take(n):
        nonlocal p
        s = h[p:p+n]; p += n; return s
    o['version']     = take(4)
    o['prev']        = take(32)
    o['merkle']      = take(32)
    o['time']        = take(4)
    o['nbits']       = take(4)
    o['nonce']       = take(4)
    o['nonce2']      = take(4)
    o['nonce3']      = take(4)
    o['extranonce']  = take(16)
    o['time_offset'] = take(4)
    o['txcount']     = take(2)
    o['flags']       = take(1)
    o['clear_bits']  = take(1)
    o['xor_key']     = take(16)
    o['height']      = take(4)
    o['mm_rhs']      = take(32)
    assert p == 164
    return o


def compute_h1_h2_pbh(f):
    assert f['flags'] == b"\x00", "flags must be 0 (profile 0)"
    assert f['clear_bits'] == b"\x00", "clear_bits must be 0"
    assert f['xor_key'] == b"\x00" * 16, "xor_key must be null"
    rev_prev = f['prev'][::-1]
    xkh = tagged_hash("Bitcoin block hash PoW XOR key", f['xor_key'])
    txcount = f['txcount'][0] | (f['txcount'][1] << 8)
    msg1 = b""
    msg1 += f['version']
    msg1 += rev_prev
    msg1 += f['height']
    msg1 += f['merkle']
    msg1 += f['time']
    msg1 += b"\x00"
    msg1 += f['nbits']
    msg1 += bytes([txcount & 0xff, (txcount >> 8) & 0xff, 0x00, 0x00])
    msg1 += f['flags']
    msg1 += f['clear_bits']
    msg1 += xkh
    assert len(msg1) == 119, len(msg1)
    h1 = tagged_hash("Bitcoin block header 1", msg1)
    msg2 = h1 + b"\x00" * 32 + f['mm_rhs']
    assert len(msg2) == 96
    h2 = tagged_hash("Merge-mining hook", msg2)
    pbh = bytearray(tagged_hash("Bitcoin prevblock header, hashed", rev_prev))
    for i in range(6):
        pbh[i] = 0
    return h1, h2, bytes(pbh)


def compute_root(h2, extranonce16):
    msg3 = b"\x00" * 4 + h2 + extranonce16
    assert len(msg3) == 52
    return blake2b256(msg3)


def b2_from(pbh, nonce4, nonce2_4, time_offset4, nonce3_4, root):
    buf = pbh + nonce4 + nonce2_4 + time_offset4 + nonce3_4 + root
    assert len(buf) == 80
    return blake2b256(buf)

# ─────────────────────────── target / diff ─────────────────────────────

DIFF1 = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

def share_target_from_diff(diff):
    if diff <= 0:
        return DIFF1
    return int(DIFF1 // diff)

# ─────────────────────────── CUDA BLAKE2b kernel ────────────────────────

CUDA_SRC = r'''
typedef unsigned long long u64;
typedef unsigned int       u32;
typedef unsigned char      u8;

__device__ __forceinline__ u64 rotr64(u64 x, int n){ return (x >> n) | (x << (64 - n)); }

__device__ __forceinline__ u64 bswap64(u64 x){
    x = ((x & 0x00000000FFFFFFFFULL) << 32) | ((x & 0xFFFFFFFF00000000ULL) >> 32);
    x = ((x & 0x0000FFFF0000FFFFULL) << 16) | ((x & 0xFFFF0000FFFF0000ULL) >> 16);
    x = ((x & 0x00FF00FF00FF00FFULL) <<  8) | ((x & 0xFF00FF00FF00FF00ULL) >>  8);
    return x;
}

__constant__ u64 IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

__constant__ u8 SIGMA[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3}
};

#define G(a,b,c,d,x,y) \
    v[a] = v[a] + v[b] + (x); v[d] = rotr64(v[d] ^ v[a], 32); \
    v[c] = v[c] + v[d];       v[b] = rotr64(v[b] ^ v[c], 24); \
    v[a] = v[a] + v[b] + (y); v[d] = rotr64(v[d] ^ v[a], 16); \
    v[c] = v[c] + v[d];       v[b] = rotr64(v[b] ^ v[c], 63);

// BLAKE2b-256, single 128-byte compression block, message length = 80 bytes,
// no key.  m[0..15] are the 16 little-endian 64-bit words of the 128-byte
// zero-padded block. Writes the first 4 output words (32-byte digest) to h4.
__device__ void blake2b80_core(const u64 m[16], u64 h4[4]){
    u64 h[8];
    h[0] = IV[0] ^ 0x0000000001010020ULL;  // param: digest_length=32, fanout=1, depth=1
    #pragma unroll
    for (int i = 1; i < 8; i++) h[i] = IV[i];

    u64 v[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) { v[i] = h[i]; v[i+8] = IV[i]; }
    v[12] ^= 80ULL;                 // t0 = bytes processed = 80
    // v[13] ^= 0  (t1)
    v[14] ^= 0xFFFFFFFFFFFFFFFFULL; // f0 = last block
    // v[15] ^= 0  (f1)

    #pragma unroll
    for (int r = 0; r < 12; r++){
        const u8* s = SIGMA[r];
        G(0,4, 8,12, m[s[ 0]], m[s[ 1]]);
        G(1,5, 9,13, m[s[ 2]], m[s[ 3]]);
        G(2,6,10,14, m[s[ 4]], m[s[ 5]]);
        G(3,7,11,15, m[s[ 6]], m[s[ 7]]);
        G(0,5,10,15, m[s[ 8]], m[s[ 9]]);
        G(1,6,11,12, m[s[10]], m[s[11]]);
        G(2,7, 8,13, m[s[12]], m[s[13]]);
        G(3,4, 9,14, m[s[14]], m[s[15]]);
    }
    #pragma unroll
    for (int i = 0; i < 4; i++) h4[i] = h[i] ^ v[i] ^ v[i+8];
}

// ---- Self-test kernel: hash one arbitrary 80-byte buffer through the core ----
extern "C" __global__ void hash_one(const u8* buf, u8* out){
    u64 m[16];
    #pragma unroll
    for (int i = 0; i < 16; i++){
        u64 w = 0;
        #pragma unroll
        for (int j = 0; j < 8; j++){
            int bi = i*8 + j;
            u8 c = (bi < 80) ? buf[bi] : 0;
            w |= ((u64)c) << (8*j);
        }
        m[i] = w;
    }
    u64 h4[4];
    blake2b80_core(m, h4);
    #pragma unroll
    for (int i = 0; i < 4; i++)
        #pragma unroll
        for (int j = 0; j < 8; j++)
            out[i*8 + j] = (u8)((h4[i] >> (8*j)) & 0xff);
}

// ---- Mining kernel ----
// pbh_w[0..3] = little-endian 64-bit words of the 32-byte prevblock_hidden.
// root_w[0..3]= little-endian 64-bit words of the 32-byte BLAKE2b root.
// Buffer per nonce = pbh(32) || nonce_le(4) || 0*12 || root(32).  nonce2 =
// time_offset = nonce3 = 0 (the served Sv1 shape). Big-endian digest <= target
// (t0 = most-significant 64 bits) emits the nonce.
extern "C" __global__ void mine(
        const u64* pbh_w, const u64* root_w,
        u32 nonce_base, u32 count,
        u64 t0, u64 t1, u64 t2, u64 t3,
        u32* out_nonces, u32* out_count, u32 out_cap){
    u32 idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    u32 nonce = nonce_base + idx;

    u64 m[16];
    m[0] = pbh_w[0]; m[1] = pbh_w[1]; m[2] = pbh_w[2]; m[3] = pbh_w[3];
    m[4] = (u64)nonce;   // bytes 32..35 = nonce LE, bytes 36..39 = 0
    m[5] = 0ULL;         // bytes 40..47 = time_offset(0) || nonce3(0)
    m[6] = root_w[0]; m[7] = root_w[1]; m[8] = root_w[2]; m[9] = root_w[3];
    m[10]=0ULL; m[11]=0ULL; m[12]=0ULL; m[13]=0ULL; m[14]=0ULL; m[15]=0ULL;

    u64 h4[4];
    blake2b80_core(m, h4);

    u64 be0 = bswap64(h4[0]);
    u64 be1 = bswap64(h4[1]);
    u64 be2 = bswap64(h4[2]);
    u64 be3 = bswap64(h4[3]);

    bool le;
    if      (be0 != t0) le = be0 < t0;
    else if (be1 != t1) le = be1 < t1;
    else if (be2 != t2) le = be2 < t2;
    else                le = be3 <= t3;

    if (le){
        u32 p = atomicAdd(out_count, 1u);
        if (p < out_cap) out_nonces[p] = nonce;
    }
}
'''

# ─────────────────────────── GPU engine ────────────────────────────────

class GpuEngine:
    def __init__(self, threads_per_block=256, blocks=4096, device=0):
        import cupy as cp
        self.cp = cp
        # Bind this engine (and therefore this whole process) to one GPU. With
        # one process per GPU this gives clean multi-GPU: --device 0/1/2, each
        # process owning a distinct board. (CUDA_VISIBLE_DEVICES also works and
        # composes — device is then an index into the visible subset.)
        self.device = int(device)
        cp.cuda.Device(self.device).use()
        self.module = cp.RawModule(code=CUDA_SRC, options=('--std=c++14',))
        self.k_mine = self.module.get_function('mine')
        self.k_hash = self.module.get_function('hash_one')
        self.tpb = threads_per_block
        self.blocks = blocks
        self.batch = threads_per_block * blocks
        # persistent output buffers
        self.d_out_nonces = cp.zeros(4096, dtype=cp.uint32)
        self.d_out_count = cp.zeros(1, dtype=cp.uint32)
        self.out_cap = 4096

    def gpu_hash_one(self, buf80):
        cp = self.cp
        assert len(buf80) == 80
        d_buf = cp.frombuffer(bytes(buf80), dtype=cp.uint8)
        d_out = cp.zeros(32, dtype=cp.uint8)
        self.k_hash((1,), (1,), (d_buf, d_out))
        cp.cuda.Stream.null.synchronize()
        return bytes(d_out.get())

    @staticmethod
    def _words_le(b32):
        # 32 bytes -> 4 little-endian uint64 words
        return struct.unpack('<4Q', b32)

    def mine_batch(self, pbh, root, target, nonce_base, count=None):
        cp = self.cp
        d_pbh = cp.array(self._words_le(pbh), dtype=cp.uint64)
        d_root = cp.array(self._words_le(root), dtype=cp.uint64)
        tb = target.to_bytes(32, 'big')
        t0, t1, t2, t3 = struct.unpack('>4Q', tb)
        self.d_out_count.fill(0)
        if count is None:
            count = self.batch
        grid = (count + self.tpb - 1) // self.tpb
        self.k_mine(
            (grid,), (self.tpb,),
            (d_pbh, d_root,
             cp.uint32(nonce_base & 0xffffffff), cp.uint32(count),
             cp.uint64(t0), cp.uint64(t1), cp.uint64(t2), cp.uint64(t3),
             self.d_out_nonces, self.d_out_count, cp.uint32(self.out_cap)))
        cp.cuda.Stream.null.synchronize()
        n_found = int(self.d_out_count.get()[0])
        if n_found == 0:
            return []
        n_found = min(n_found, self.out_cap)
        return [int(x) for x in self.d_out_nonces[:n_found].get()]

# ─────────────────────────── self-test ─────────────────────────────────

def run_selftest_cpu(verbose=True):
    H = bytes.fromhex(KAT_HEADER_HEX)
    f = parse_header_v2(H)
    _h1, h2, pbh = compute_h1_h2_pbh(f)
    wire_coinb1 = b"\x00" * 4 + h2 + b"\x00" * 8
    assert wire_coinb1[4:36] == h2
    root = compute_root(h2, f['extranonce'])
    b2 = b2_from(pbh, f['nonce'], f['nonce2'], f['time_offset'], f['nonce3'], root)
    got = b2.hex()
    ok = (got == KAT_CANONICAL)
    if verbose:
        print("  [CPU ref] h2               = %s" % h2.hex())
        print("  [CPU ref] root(extranonce) = %s" % root.hex())
        print("  [CPU ref] display          = %s" % got)
        print("  [CPU ref] canonical (KAT)  = %s" % KAT_CANONICAL)
        print("  [CPU ref] SELFTEST %s" % ("PASS" if ok else "FAIL"))
    return ok, f, h2, pbh, root


def run_selftest_gpu(engine, verbose=True):
    ok_cpu, f, h2, pbh, root = run_selftest_cpu(verbose=verbose)
    # Build the EXACT 80-byte profile-0 buffer of block 961640 (real rolled
    # fields) and hash it through the GPU core.
    buf = pbh + f['nonce'] + f['nonce2'] + f['time_offset'] + f['nonce3'] + root
    assert len(buf) == 80
    gpu_hash = engine.gpu_hash_one(buf)
    cpu_hash = blake2b256(buf)
    gpu_hex = gpu_hash.hex()
    ok_gpu_vs_canon = (gpu_hex == KAT_CANONICAL)
    ok_gpu_vs_cpu = (gpu_hash == cpu_hash)
    if verbose:
        print("  [GPU]     display          = %s" % gpu_hex)
        print("  [GPU]     == canonical(KAT) : %s" % ok_gpu_vs_canon)
        print("  [GPU]     == CPU ref fold   : %s" % ok_gpu_vs_cpu)
    # Also exercise the MINING kernel path (nonce2=nonce3=time_offset=0) against
    # a CPU cross-check on a random target so we know the mine-kernel buffer
    # construction + big-endian compare agrees with hashlib.
    import random
    en1 = os.urandom(4); en2 = os.urandom(4)
    coinb1 = b"\x00" * 4 + h2 + b"\x00" * 8
    root2 = blake2b256(coinb1 + en1 + en2)
    test_nonce = random.randint(0, 0xffffffff)
    cpu_b2 = blake2b256(pbh + struct.pack('<I', test_nonce) + b"\x00" * 12 + root2)
    # target = cpu_b2 exactly -> the mine kernel MUST flag test_nonce as <= target
    tgt = int.from_bytes(cpu_b2, 'big')
    base = test_nonce
    # 1-thread launch: only test_nonce is evaluated, so the digest==target check
    # (buffer construction + big-endian compare in the MINE kernel) is exercised
    # deterministically with no output-cap overflow.
    found = engine.mine_batch(pbh, root2, tgt, base, count=1)
    ok_mine = (found == [test_nonce])
    if verbose:
        print("  [GPU mine] nonce=%08x root=%s" % (test_nonce, root2.hex()))
        print("  [GPU mine] cpu_b2          = %s" % cpu_b2.hex())
        print("  [GPU mine] kernel flagged nonce at its own hash-target: %s" % ok_mine)
    return ok_cpu and ok_gpu_vs_canon and ok_gpu_vs_cpu and ok_mine

# ─────────────────────────── Stratum client (reused) ───────────────────

class GpuMiner:
    def __init__(self, args, engine):
        self.args = args
        self.engine = engine
        self.sock = None
        self.buf = b""
        self.msg_id = 1
        self.extranonce1 = None
        self.en2_size = None
        self.job = None
        self.difficulty = args.diff
        self.log_path = args.log
        self.logf = None
        self.job_epoch = 0   # bump on every notify to drop in-flight work

    def log(self, s):
        line = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), s)
        print(line, flush=True)
        if self.logf:
            self.logf.write(line + "\n"); self.logf.flush()

    def log_raw(self, direction, obj):
        line = "[%s] %s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), direction, json.dumps(obj))
        if self.logf:
            self.logf.write(line + "\n"); self.logf.flush()
        print(line, flush=True)

    def connect(self):
        self.log("connecting to %s:%d" % (self.args.host, self.args.port))
        self.sock = socket.create_connection((self.args.host, self.args.port), timeout=30)
        # Non-blocking: the GPU mining loop polls the socket without stalling.
        # (A 0.2s timeout here throttled the loop to ~5 batches/s = ~10 MH/s.)
        self.sock.setblocking(False)

    def send(self, method, params, mid=None):
        if mid is None:
            mid = self.msg_id; self.msg_id += 1
        obj = {"id": mid, "method": method, "params": params}
        data = (json.dumps(obj) + "\n").encode()
        self.sock.sendall(data)
        self.log_raw("SEND", obj)
        return mid

    def recv_lines(self):
        try:
            chunk = self.sock.recv(65536)
        except (socket.timeout, BlockingIOError):
            return []
        if not chunk:
            raise ConnectionError("pool closed connection")
        self.buf += chunk
        lines = []
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            line = line.strip()
            if line:
                try:
                    lines.append(json.loads(line))
                except Exception as e:
                    self.log("bad json: %r (%s)" % (line, e))
        return lines

    def handle_notify(self, params):
        job_id = params[0]
        prevhash_hex = params[1]
        coinb1_hex = params[2]
        merkle_branch = params[4]
        ntime = params[7]
        clean = params[8] if len(params) > 8 else True
        pbh = bytes.fromhex(prevhash_hex)
        coinb1 = bytes.fromhex(coinb1_hex)
        self.job = {
            "job_id": job_id,
            "pbh": pbh,
            "coinb1": coinb1,
            "ntime": ntime,
            "difficulty": self.difficulty,
        }
        self.job_epoch += 1
        self.log("notify job=%s clean=%s coinb1=%dB pbh=%dB ntime=%s branches=%d diff=%s"
                 % (job_id, clean, len(coinb1), len(pbh), ntime, len(merkle_branch), self.difficulty))

    @staticmethod
    def fmt_diff(d):
        if d == int(d):
            return str(int(d))
        return ("%g" % d)

    def build_extranonce16(self, en2_int):
        en1 = bytes.fromhex(self.extranonce1)
        assert len(en1) == 4, "extranonce1 must be 4 bytes, got %d" % len(en1)
        en2 = struct.pack("<I", en2_int & 0xffffffff)
        return en1, en2

    def subscribe_authorize(self):
        self.send("mining.subscribe", ["bip110-gpuminer/0.1"])
        got_sub = False
        deadline = time.time() + 30
        while time.time() < deadline and not got_sub:
            for m in self.recv_lines():
                if m.get("id") == 1 and "result" in m and m["result"]:
                    res = m["result"]
                    self.extranonce1 = res[1]
                    self.en2_size = res[2]
                    self.log("subscribed extranonce1=%s en2_size=%s" % (self.extranonce1, self.en2_size))
                    got_sub = True
                elif m.get("method") == "mining.notify":
                    self.handle_notify(m["params"])
                elif m.get("method") == "mining.set_difficulty":
                    self.difficulty = float(m["params"][0])
                    self.log("set_difficulty=%s" % self.difficulty)
            if not got_sub:
                time.sleep(0.01)
        if not got_sub:
            raise RuntimeError("no subscribe reply")
        user = "%s.%s+%s" % (self.args.address, self.args.worker, self.fmt_diff(self.args.diff))
        self.authorize_user = user
        self.send("mining.authorize", [user, "x"])

    def drain_socket(self, pending):
        for m in self.recv_lines():
            if m.get("method") == "mining.notify":
                self.handle_notify(m["params"])
            elif m.get("method") == "mining.set_difficulty":
                self.difficulty = float(m["params"][0])
                self.log("set_difficulty=%s" % self.difficulty)
            elif "id" in m and ("result" in m or "error" in m):
                mid = m.get("id")
                if mid in pending:
                    jid, nonce, en2hex = pending.pop(mid)
                    res = m.get("result")
                    err = m.get("error")
                    self.log_raw("SUBMIT_RESULT", m)
                    if res is True:
                        self.accepted += 1
                        self.log("SHARE ACCEPTED result=true job=%s nonce=%s en2=%s (accepted=%d)"
                                 % (jid, nonce, en2hex, self.accepted))
                    else:
                        self.rejected += 1
                        self.log("SHARE REJECTED result=%r error=%r job=%s nonce=%s"
                                 % (res, err, jid, nonce))
                elif mid == 2:
                    self.log_raw("AUTHORIZE_RESULT", m)

    def run(self):
        if self.log_path:
            self.logf = open(self.log_path, "a")
        self.connect()
        self.subscribe_authorize()

        end = time.time() + self.args.minutes * 60
        en2_int = (os.getpid() * 2654435761) & 0xffffffff
        self.accepted = 0
        self.rejected = 0
        submitted = 0
        pending = {}
        hashes = 0
        last_report = time.time()
        hr_hashes = 0
        hr_t0 = time.time()

        cur_epoch = -1
        nonce_base = 0
        en1 = en2 = root = None
        en2hex = None

        while time.time() < end:
            self.drain_socket(pending)
            if not self.job:
                time.sleep(0.05)
                continue

            job = self.job
            # New job -> drop in-flight work (avoid DOA), reset nonce sweep + root.
            if self.job_epoch != cur_epoch:
                cur_epoch = self.job_epoch
                nonce_base = 0
                en1, en2 = self.build_extranonce16(en2_int)
                root = blake2b256(job["coinb1"] + en1 + en2)
                en2hex = en2.hex()

            # The pinned +N fixed diff (args.diff) is the pool's REAL acceptance
            # floor; its set_difficulty (observed 0.0005) is a loose vardiff that
            # is BELOW the real gate. Never mine easier than args.diff, or the
            # pool rejects with "Low difficulty share". Honor a HIGHER live diff.
            eff_diff = max(self.args.diff, self.difficulty)
            target = share_target_from_diff(eff_diff * self.args.margin)

            found = self.engine.mine_batch(job["pbh"], root, target, nonce_base)
            batch = self.engine.batch
            hashes += batch
            hr_hashes += batch

            # If a new job arrived DURING the kernel launch, drop these results.
            if self.job_epoch != cur_epoch:
                continue

            for n in found:
                nonce_hex = "%08x" % n
                ntime = job["ntime"]
                mid = self.send("mining.submit",
                                [self.authorize_user, job["job_id"], en2hex, ntime, nonce_hex])
                pending[mid] = (job["job_id"], nonce_hex, en2hex)
                submitted += 1
                self.log("SUBMIT job=%s en2=%s ntime=%s nonce=%s (batch found %d)"
                         % (job["job_id"], en2hex, ntime, nonce_hex, len(found)))

            # advance nonce sweep; roll en2 (new root) when 32-bit space exhausted
            nonce_base = (nonce_base + batch) & 0xffffffff
            if nonce_base < batch:  # wrapped -> exhausted the 2^32 nonce space
                en2_int = (en2_int + 1) & 0xffffffff
                en1, en2 = self.build_extranonce16(en2_int)
                root = blake2b256(job["coinb1"] + en1 + en2)
                en2hex = en2.hex()

            now = time.time()
            if now - last_report > 30:
                dt = now - hr_t0
                hr = hr_hashes / dt if dt > 0 else 0
                self.log("progress: submitted=%d accepted=%d rejected=%d hashes~%d hashrate=%.3f MH/s"
                         % (submitted, self.accepted, self.rejected, hashes, hr / 1e6))
                last_report = now
                hr_hashes = 0
                hr_t0 = now

        self.log("DONE submitted=%d accepted=%d rejected=%d" % (submitted, self.accepted, self.rejected))
        return self.accepted


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="bip110.voidbind.com")
    ap.add_argument("--port", type=int, default=9336)
    ap.add_argument("--address", default="")
    ap.add_argument("--worker", default="legion64gpu")
    ap.add_argument("--diff", type=float, default=1.0)
    ap.add_argument("--minutes", type=float, default=600)
    ap.add_argument("--log", default="")
    ap.add_argument("--margin", type=float, default=1.0,
                    help="submit shares this many x above the required difficulty")
    ap.add_argument("--tpb", type=int, default=256)
    ap.add_argument("--blocks", type=int, default=8192)
    ap.add_argument("--device", type=int, default=0,
                    help="CUDA device ordinal to bind this process to (multi-GPU: "
                         "run one process per GPU with --device 0/1/2 and a "
                         "distinct --address each)")
    ap.add_argument("--selftest-only", action="store_true")
    args = ap.parse_args()

    print("=== bip110_gpu_miner self-test (KAT block 961640, GPU BLAKE2b) ===")
    engine = GpuEngine(threads_per_block=args.tpb, blocks=args.blocks, device=args.device)
    print("bound to CUDA device %d" % engine.device)
    ok = run_selftest_gpu(engine, verbose=True)
    if not ok:
        print("ABORT: GPU PoW self-test FAILED — kernel is not byte-correct.")
        sys.exit(1)
    print("=== GPU self-test PASSED — kernel BLAKE2b == canonical == CPU ref ===")

    if args.selftest_only:
        sys.exit(0)

    if not args.address:
        print("ABORT: --address required to mine")
        sys.exit(2)

    m = GpuMiner(args, engine)
    try:
        m.run()
    except Exception as e:
        m.log("FATAL: %r" % e)
        raise


if __name__ == "__main__":
    main()
