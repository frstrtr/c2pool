#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Minimal multi-process X11 stratum miner for the DASH v36 regtest block rig.

Connects to a c2pool-dash stratum port, subscribes + authorizes with a payout
address, and grinds the header nonce of every mining.notify job: coinbase =
coinb1 || extranonce1 || extranonce2 || coinb2, merkle root = sha256d(coinbase)
folded through the job's merkle branches (LE bytes as sent), header = version |
prevhash (the stratum per-4-byte-word form, converted back to internal order) |
merkle root | ntime | nbits | nonce, PoW = X11 (the `x11_hash` C extension).

It submits ONLY hashes <= --target (default: the DASH testnet share floor
2**256 // 2**20 - 1 divided by --margin), so on regtest -- where the block
target is far easier than any share target -- every submitted solve is both a
DASH block and a sharechain share. It exits after --shares accepted submits
(or --timeout seconds) and prints one JSON line per accepted submit.

Needs: python3 with `x11_hash` importable (pip install --target DIR x11_hash;
PYTHONPATH=DIR).
"""
import argparse
import binascii
import hashlib
import json
import multiprocessing as mp
import os
import queue
import socket
import struct
import sys
import time

import x11_hash

TESTNET_MAX_TARGET = (1 << 256) // (1 << 20) - 1
IDLE = ("idle",)


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def stratum_prev_to_internal(prev_hex):
    b = binascii.unhexlify(prev_hex)
    return b"".join(b[i:i + 4][::-1] for i in range(0, 32, 4))


def worker(wid, nworkers, jobq, outq, target):
    job = None
    while True:
        try:
            nj = jobq.get(timeout=0.2 if job is None else 0.001)
            if nj is None:
                return
            job = None if nj == IDLE else nj
            if job is None:
                continue
        except queue.Empty:
            if job is None:
                continue
        (job_id, prev_hex, coinb1, coinb2, branches, version_hex, nbits_hex, ntime_hex,
         en1, en2_size, gen) = job
        en2 = struct.pack(">I", (wid << 24) | (gen & 0xffffff))[-en2_size:].hex()
        coinbase = binascii.unhexlify(coinb1 + en1 + en2 + coinb2)
        root = sha256d(coinbase)
        for br in branches:
            root = sha256d(root + binascii.unhexlify(br))
        head = (struct.pack("<I", int(version_hex, 16)) + stratum_prev_to_internal(prev_hex)
                + root + struct.pack("<I", int(ntime_hex, 16)) + struct.pack("<I", int(nbits_hex, 16)))
        hdr = bytearray(head + b"\0\0\0\0")
        nonce = wid
        found = False
        while nonce < 0xffffffff:
            struct.pack_into("<I", hdr, 76, nonce)
            h = x11_hash.getPoWHash(bytes(hdr))
            if int.from_bytes(h, "little") <= target:
                outq.put((job_id, en2, ntime_hex, "%08x" % nonce, h[::-1].hex(), gen))
                found = True
                break
            nonce += nworkers
            if (nonce // nworkers) % 4096 == 0:
                try:
                    nj = jobq.get_nowait()
                    if nj is None:
                        return
                    job = None if nj == IDLE else nj
                    break
                except queue.Empty:
                    pass
        if found:
            job = None   # wait for the next job (the tip moved: every solve is a block)


class Stratum:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(0.2)
        self.buf = b""
        self.next_id = 1

    def send(self, method, params):
        rid = self.next_id
        self.next_id += 1
        self.sock.sendall((json.dumps({"id": rid, "method": method, "params": params}) + "\n").encode())
        return rid

    def lines(self):
        try:
            data = self.sock.recv(65536)
            if not data:
                raise ConnectionError("stratum closed")
            self.buf += data
        except socket.timeout:
            pass
        out = []
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            if line.strip():
                out.append(json.loads(line))
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--user", required=True, help="payout address (P2PKH)")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--margin", type=int, default=32,
                    help="submit only hashes <= testnet share floor / margin")
    ap.add_argument("--shares", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--min-branches", type=int, default=0,
                    help="mine only jobs with at least this many merkle branches "
                         "(i.e. a template that carries transactions)")
    ap.add_argument("--max-branches", type=int, default=99,
                    help="mine only jobs with at most this many merkle branches "
                         "(0 = coinbase-only templates)")
    a = ap.parse_args()
    target = TESTNET_MAX_TARGET // a.margin

    s = Stratum(a.host, a.port)
    sub_id = s.send("mining.subscribe", ["c2pool-dash-v36-rig-miner"])
    auth_id = s.send("mining.authorize", [a.user, "x"])
    en1, en2_size = None, 4
    outq = mp.Queue()
    jobqs = [mp.Queue() for _ in range(a.workers)]
    procs = [mp.Process(target=worker, args=(i, a.workers, jobqs[i], outq, target), daemon=True)
             for i in range(a.workers)]
    for p in procs:
        p.start()
    pending = {}
    accepted = 0
    gen = 0
    t_end = time.time() + a.timeout
    last_job = None
    submitted_gens = set()
    while time.time() < t_end and accepted < a.shares:
        for m in s.lines():
            if m.get("id") == sub_id and m.get("result"):
                en1, en2_size = m["result"][1], int(m["result"][2])
            elif m.get("id") == auth_id:
                print(json.dumps({"event": "authorize", "result": m.get("result")}), flush=True)
            elif m.get("method") == "mining.notify" and en1 is not None:
                p = m["params"]
                print(json.dumps({"event": "notify", "job": p[0], "branches": len(p[4]),
                                  "nbits": p[6]}), flush=True)
                if not (a.min_branches <= len(p[4]) <= a.max_branches):
                    # not the template shape this round wants: stop grinding
                    # the previous job (its tip may be gone) and wait
                    last_job = None
                    for q in jobqs:
                        q.put(IDLE)
                    continue
                gen += 1
                last_job = (p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], en1, en2_size, gen)
                for q in jobqs:
                    q.put(last_job)
            elif m.get("id") in pending:
                sol = pending.pop(m["id"])
                ok = m.get("result") is True
                print(json.dumps({"event": "submit", "job": sol[0], "hash": sol[4],
                                  "accepted": ok, "error": m.get("error")}), flush=True)
                if ok:
                    accepted += 1
        try:
            while True:
                sol = outq.get_nowait()
                if last_job is None or sol[5] != last_job[10] or sol[5] in submitted_gens:
                    continue   # stale (a newer job was dispatched) or already solved
                submitted_gens.add(sol[5])
                rid = s.send("mining.submit", [a.user, sol[0], sol[1], sol[2], sol[3]])
                pending[rid] = sol
        except queue.Empty:
            pass
    for q in jobqs:
        q.put(None)
    for p in procs:
        p.terminate()
    print(json.dumps({"event": "done", "accepted": accepted}), flush=True)
    return 0 if accepted >= a.shares else 1


if __name__ == "__main__":
    sys.exit(main())
