#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# bip110_miner.py — standalone BIP-110 Stratum-v1 test miner.
#
# NEW standalone tool. Does NOT touch the pool or c2pool source. Its PoW is a
# byte-for-byte Python mirror of src/impl/bip110/pow.hpp + pseudoheader.hpp,
# self-tested against live fork block 961640 (the SAME KAT vector the pool pins)
# BEFORE it ever connects. A wrong fold fails the self-test and aborts, so an
# accepted share genuinely exercises the pool's real verification fold.
#
# Usage:
#   python3 bip110_miner.py --selftest-only
#   python3 bip110_miner.py --host bip110.voidbind.com --port 9336 \
#       --address <BIP110-ADDR> --worker legion64test --diff 0.01 \
#       --procs 8 --minutes 45 --log /path/miner.log

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import time
import multiprocessing as mp

# ─────────────────────────── PoW primitives ────────────────────────────

def sha256(b):
    return hashlib.sha256(b).digest()

def tagged_hash(tag, msg):
    # BIP340-style: SHA256( SHA256(tag) || SHA256(tag) || msg )
    th = sha256(tag.encode())
    return sha256(th + th + msg)

def blake2b256(b):
    return hashlib.blake2b(b, digest_size=32).digest()

# ─────────────────────────── KAT self-test ─────────────────────────────

KAT_HEADER_HEX = "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc7684dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d0300000000000000000000001e0300000000000000000000000000000000000068ac0e000000000000000000000000000000000000000000000000000000000000000000"
KAT_CANONICAL = "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb"


def parse_header_v2(h):
    # returns dict of field byte-slices, offsets per pow.hpp parse_header_v2
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
    # f: parsed header dict. Mirrors pseudoheader.hpp compute_h1_h2 exactly.
    assert f['flags'] == b"\x00", "flags must be 0 (profile 0)"
    assert f['clear_bits'] == b"\x00", "clear_bits must be 0"
    assert f['xor_key'] == b"\x00" * 16, "xor_key must be null"

    rev_prev = f['prev'][::-1]
    xkh = tagged_hash("Bitcoin block hash PoW XOR key", f['xor_key'])

    txcount = f['txcount'][0] | (f['txcount'][1] << 8)
    msg1 = b""
    msg1 += f['version']                       # 4
    msg1 += rev_prev                           # 32
    msg1 += f['height']                        # 4  (raw wire LE bytes)
    msg1 += f['merkle']                        # 32
    msg1 += f['time']                          # 4
    msg1 += b"\x00"                            # 1
    msg1 += f['nbits']                         # 4
    msg1 += bytes([txcount & 0xff, (txcount >> 8) & 0xff, 0x00, 0x00])  # 4
    msg1 += f['flags']                         # 1
    msg1 += f['clear_bits']                    # 1
    msg1 += xkh                                # 32
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
    # 80-byte profile-0 buffer, flags=0.
    buf = pbh + nonce4 + nonce2_4 + time_offset4 + nonce3_4 + root
    assert len(buf) == 80
    return blake2b256(buf)


def run_selftest(verbose=True):
    H = bytes.fromhex(KAT_HEADER_HEX)
    if len(H) != 164:
        print("SELFTEST FAIL: header hex is %d bytes not 164" % len(H))
        return False
    f = parse_header_v2(H)
    h1, h2, pbh = compute_h1_h2_pbh(f)

    # (b) coinb1 round-trip: 00000000 || h2 || 0000000000000000  (44 bytes)
    wire_coinb1 = b"\x00" * 4 + h2 + b"\x00" * 8
    assert len(wire_coinb1) == 44
    assert wire_coinb1[4:36] == h2, "h2 does not round-trip through coinb1"

    # (c) root using the block's REAL 16-byte extranonce
    root = compute_root(h2, f['extranonce'])

    # (d) b2 using the block's real rolled fields -> canonical
    b2 = b2_from(pbh, f['nonce'], f['nonce2'], f['time_offset'], f['nonce3'], root)
    got = b2.hex()
    ok = (got == KAT_CANONICAL)
    if verbose:
        print("  h2                = %s" % h2.hex())
        print("  root(b1)          = %s" % root.hex())
        print("  computed display  = %s" % got)
        print("  canonical (KAT)   = %s" % KAT_CANONICAL)
        print("  SELFTEST %s" % ("PASS" if ok else "FAIL"))
    return ok


def selftest_fastpath_equiv():
    # Prove the miner's Sv1 loop fast path is byte-identical to the reference
    # field-parse fold FOR THE POOL'S SERVED SHAPE (extranonce16 = 8*0x00||en1||en2,
    # nonce2 = nonce3 = time_offset = 0 — the constraint the Sv1->BLAKE2b mapping
    # imposes). The KAT block itself was mined with nonzero nonce2/nonce3 and a
    # populated extranonce top (general chain freedom), so it is NOT a witness for
    # this identity; the field-path selftest above is the binding vs-canonical
    # proof. Here we exercise the exact expressions the mining loop uses.
    H = bytes.fromhex(KAT_HEADER_HEX)
    f = parse_header_v2(H)
    _, h2, pbh = compute_h1_h2_pbh(f)

    coinb1 = b"\x00" * 4 + h2 + b"\x00" * 8      # 44-byte wire coinb1 for this h2
    for (en1, en2, n) in [
        (bytes.fromhex("deadbeef"), bytes.fromhex("00000000"), 0),
        (bytes.fromhex("01020304"), bytes.fromhex("aabbccdd"), 123456),
        (bytes.fromhex("ffffffff"), bytes.fromhex("12345678"), 0xfffffffe),
    ]:
        ex16 = b"\x00" * 8 + en1 + en2                       # Sv1 make_extranonce16
        root_fast = blake2b256(coinb1 + en1 + en2)           # loop root
        root_ref = compute_root(h2, ex16)                    # reference root
        if root_fast != root_ref:
            print("  FASTPATH root mismatch (en1=%s en2=%s)" % (en1.hex(), en2.hex()))
            return False
        b2_fast = blake2b256(pbh + struct.pack("<I", n) + b"\x00" * 12 + root_fast)
        b2_ref = b2_from(pbh, struct.pack("<I", n), b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, root_ref)
        if b2_fast != b2_ref:
            print("  FASTPATH b2 mismatch (en1=%s en2=%s n=%d)" % (en1.hex(), en2.hex(), n))
            return False
    print("  FASTPATH loop-math == reference fold (3 vectors, served Sv1 shape) PASS")
    return True

# ─────────────────────────── target / diff ─────────────────────────────

DIFF1 = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

def share_target_from_diff(diff):
    if diff <= 0:
        return DIFF1
    return int(DIFF1 // diff)

# ─────────────────────────── Stratum client ────────────────────────────

class Miner:
    def __init__(self, args):
        self.args = args
        self.sock = None
        self.buf = b""
        self.msg_id = 1
        self.extranonce1 = None
        self.en2_size = None
        self.job = None            # dict: job_id, coinb1(bytes), pbh(bytes), ntime(str)
        self.difficulty = args.diff
        self.log_path = args.log
        self.logf = None

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
        self.sock.settimeout(1.0)

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
        except socket.timeout:
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
        # [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]
        job_id = params[0]
        prevhash_hex = params[1]
        coinb1_hex = params[2]
        merkle_branch = params[4]
        ntime = params[7]
        clean = params[8] if len(params) > 8 else True
        pbh = bytes.fromhex(prevhash_hex)          # use AS-IS (raw wire prevblock_hidden)
        coinb1 = bytes.fromhex(coinb1_hex)
        self.job = {
            "job_id": job_id,
            "pbh": pbh,
            "coinb1": coinb1,
            "ntime": ntime,
            "difficulty": self.difficulty,   # diff in force when job arrived
        }
        self.log("notify job=%s clean=%s coinb1=%dB pbh=%dB ntime=%s branches=%d diff=%s"
                 % (job_id, clean, len(coinb1), len(pbh), ntime, len(merkle_branch), self.difficulty))

    def subscribe_authorize(self):
        self.send("mining.subscribe", ["bip110-testminer/0.1"])
        # wait for subscribe reply
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
            raise RuntimeError("no subscribe reply")
        if self.en2_size != 4:
            self.log("WARNING: en2_size=%s (expected 4) — GAP for standard miners" % self.en2_size)
        user = "%s.%s+%s" % (self.args.address, self.args.worker, self.fmt_diff(self.args.diff))
        self.authorize_user = user
        self.send("mining.authorize", [user, "x"])

    @staticmethod
    def fmt_diff(d):
        # pin suffix; keep it compact
        if d == int(d):
            return str(int(d))
        return ("%g" % d)

    def build_extranonce16(self, en2_int):
        en1 = bytes.fromhex(self.extranonce1)
        assert len(en1) == 4, "extranonce1 must be 4 bytes, got %d" % len(en1)
        en2 = struct.pack("<I", en2_int & 0xffffffff)   # 4 bytes, any encoding (opaque)
        return en1, en2

    def run(self):
        if self.log_path:
            self.logf = open(self.log_path, "a")
        self.connect()
        self.subscribe_authorize()

        end = time.time() + self.args.minutes * 60
        # single-process inline miner (procs handled by outer launcher for simplicity)
        en2_int = (os.getpid() * 2654435761) & 0xffffffff
        accepted = 0
        submitted = 0
        pending = {}   # id -> (job_id, nonce, en2hex)
        hashes = 0
        last_report = time.time()

        while time.time() < end:
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
                            accepted += 1
                            self.log("SHARE ACCEPTED result=true job=%s nonce=%s en2=%s (accepted=%d)"
                                     % (jid, nonce, en2hex, accepted))
                        else:
                            self.log("SHARE REJECTED result=%r error=%r job=%s nonce=%s"
                                     % (res, err, jid, nonce))
                    elif mid == 2:
                        self.log_raw("AUTHORIZE_RESULT", m)

            if not self.job:
                continue

            job = self.job
            # Judge against the STRICTER (harder = smaller target) of the diff issued
            # with the job and the current live vardiff, so a share passes BOTH the
            # core stratum "Low difficulty share" gate (live) AND the work-source
            # gate (min(live, issued)). With a pinned +N fixed diff these coincide.
            eff_diff = max(job["difficulty"], self.difficulty)
            # SUBMIT_MARGIN: only submit shares comfortably (margin x) above the
            # gate, so a vardiff up-creep between set_difficulty messages cannot
            # borderline-reject an in-flight share. Costs margin x time/share.
            target = share_target_from_diff(eff_diff * self.args.margin)
            en1, en2 = self.build_extranonce16(en2_int)
            root = blake2b256(job["coinb1"] + en1 + en2)
            en2hex = en2.hex()
            # grind a batch of nonces
            base = (hashes) & 0xffffffff
            found = None
            for i in range(200000):
                n = (base + i) & 0xffffffff
                b2 = blake2b256(job["pbh"] + struct.pack("<I", n) + b"\x00" * 12 + root)
                if int.from_bytes(b2, "big") <= target:
                    found = (n, b2)
                    break
            hashes += 200000
            if found:
                n, b2 = found
                nonce_hex = "%08x" % n
                ntime = job["ntime"]
                mid = self.send("mining.submit",
                                [self.authorize_user, job["job_id"], en2hex, ntime, nonce_hex])
                pending[mid] = (job["job_id"], nonce_hex, en2hex)
                submitted += 1
                self.log("SUBMIT job=%s en2=%s ntime=%s nonce=%s hash=%s target=%064x"
                         % (job["job_id"], en2hex, ntime, nonce_hex, b2.hex(), target))
                en2_int = (en2_int + 1) & 0xffffffff   # roll extranonce2 after a hit
            else:
                # exhausted this en2 stripe region; roll en2 to continue
                en2_int = (en2_int + 1) & 0xffffffff

            if time.time() - last_report > 30:
                self.log("progress: submitted=%d accepted=%d hashes~%d" % (submitted, accepted, hashes))
                last_report = time.time()

        self.log("DONE submitted=%d accepted=%d" % (submitted, accepted))
        return accepted


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="bip110.voidbind.com")
    ap.add_argument("--port", type=int, default=9336)
    ap.add_argument("--address", default="")
    ap.add_argument("--worker", default="legion64test")
    ap.add_argument("--diff", type=float, default=0.01)
    ap.add_argument("--minutes", type=float, default=45)
    ap.add_argument("--log", default="")
    ap.add_argument("--procs", type=int, default=1)
    ap.add_argument("--margin", type=float, default=2.0,
                    help="submit shares this many x above the required difficulty")
    ap.add_argument("--selftest-only", action="store_true")
    ap.add_argument("--worker-index", type=int, default=-1,
                    help="internal: single child index (set by the launcher)")
    args = ap.parse_args()

    print("=== bip110_miner self-test (KAT block 961640) ===")
    ok = run_selftest(verbose=True)
    ok2 = selftest_fastpath_equiv()
    if not (ok and ok2):
        print("ABORT: PoW self-test FAILED — pipeline is not byte-correct.")
        sys.exit(1)
    print("=== self-test PASSED — pipeline is byte-correct vs the pool's KAT ===")

    if args.selftest_only:
        sys.exit(0)

    if not args.address:
        print("ABORT: --address required to mine")
        sys.exit(2)

    if args.procs > 1 and args.worker_index < 0:
        # Launcher: fork N independent miner processes, each with its own socket
        # connection but the SAME worker name (the pool aggregates by worker id).
        procs = []
        for idx in range(args.procs):
            p = mp.Process(target=_child_entry, args=(args, idx))
            p.start()
            procs.append(p)
            time.sleep(0.3)   # stagger connects
        for p in procs:
            p.join()
        return

    m = Miner(args)
    try:
        m.run()
    except Exception as e:
        m.log("FATAL: %r" % e)
        raise


def _child_entry(args, idx):
    # Give each child its own log file so raw JSON proof is per-connection.
    if args.log:
        base = args.log
        if base.endswith(".log"):
            args.log = base[:-4] + (".p%d.log" % idx)
        else:
            args.log = base + (".p%d" % idx)
    args.worker_index = idx
    m = Miner(args)
    try:
        m.run()
    except Exception as e:
        m.log("FATAL: %r" % e)


if __name__ == "__main__":
    main()
