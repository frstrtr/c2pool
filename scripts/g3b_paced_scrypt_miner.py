#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Paced scrypt stratum miner for regtest harnesses.

On LTC regtest the block target (207fffff) and the c2pool pool-share target
(testnet MAX 200ccccc) are trivial, and c2pool clamps stratum difficulty down
to the share difficulty, so a real miner (minerd) submits every few hashes and
every share is also a block: the template changes on each one and nearly all
submits go DOA, so the sharechain never grows. This miner does genuine scrypt
PoW (hashlib.scrypt N=1024 r=1 p=1) on real stratum jobs, but only submits a
solution that meets the share target and then sleeps PERIOD seconds, so the
share rate is set by the harness (e.g. the 4 s share period) instead of the CPU.

The submit target follows mining.set_difficulty, which c2pool pins to the
pool-share difficulty ("pool-share difficulty bound"), so every submit is a
real share. Scrypt stratum wire difficulty: target = (0xffff << 224) / wire.

c2pool sets that difficulty once per connection (max-target bound) and does not
re-send it when the share target retargets harder, so solutions that only meet
it land as pseudoshares. The miner therefore also enforces a fixed work floor of
2^-WORK_LOG2 per solution (default 13, ~3 s at ~2.7 kH/s). With PERIOD pacing
the pool's attempts/s estimate stays low enough that the retargeted share target
settles easier than the floor, so every submit is a share.

usage: g3b_paced_scrypt_miner.py HOST PORT USER PERIOD_S [WORK_LOG2]
"""
import hashlib, json, socket, struct, sys, time, threading

host, port, user, period = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
T_MAX = (1 << 256) - 1
FLOOR = 1 << (256 - (int(sys.argv[5]) if len(sys.argv) > 5 else 13))
def wire_target(d): return min(T_MAX, FLOOR, int((0xffff << 224) / d)) if d > 0 else FLOOR

def d256(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def log(*a): print(time.strftime("%H:%M:%S"), *a, flush=True)

s = socket.create_connection((host, port)); f = s.makefile("r"); lock = threading.Lock()
mid = [0]
def send(method, params):
    with lock:
        mid[0] += 1; s.sendall((json.dumps({"id": mid[0], "method": method, "params": params}) + "\n").encode())
        return mid[0]

state = {"target": FLOOR, "job": None, "en1": None, "en2n": 4, "fresh": threading.Event()}
results = {"ok": 0, "bad": 0}
def reader():
    for line in f:
        m = json.loads(line)
        if m.get("method") == "mining.notify":
            state["job"] = m["params"]; state["fresh"].set()
        elif m.get("method") == "mining.set_difficulty":
            state["target"] = wire_target(float(m["params"][0])); log("set_difficulty", m["params"][0])
        elif m.get("id") == 1 and m.get("result"):
            state["en1"], state["en2n"] = m["result"][1], m["result"][2]
        elif m.get("id", 0) > 2:
            if m.get("result") is True: results["ok"] += 1
            else: results["bad"] += 1; log("submit result", m.get("result"), m.get("error"))
    log("connection closed"); sys.exit(1)

threading.Thread(target=reader, daemon=True).start()
send("mining.subscribe", ["g3b-paced/1.0"]); send("mining.authorize", [user, "x"])
while state["job"] is None or state["en1"] is None: time.sleep(0.1)

en2c = 0; n = 0
while True:
    state["fresh"].clear()
    job = state["job"]
    jid, prevhash, cb1, cb2, branch, ver, nbits, ntime = job[:8]
    en2c += 1; en2 = ("%0" + str(2 * state["en2n"]) + "x") % en2c
    root = d256(bytes.fromhex(cb1 + state["en1"] + en2 + cb2))
    for b in branch: root = d256(root + bytes.fromhex(b))
    ph = b"".join(bytes.fromhex(prevhash[i:i + 8])[::-1] for i in range(0, 64, 8))
    head = struct.pack("<I", int(ver, 16)) + ph + root + struct.pack("<II", int(ntime, 16), int(nbits, 16))
    t0 = time.time()
    for nonce in range(0, 1 << 24):
        hdr = head + struct.pack("<I", nonce)
        h = int.from_bytes(hashlib.scrypt(hdr, salt=hdr, n=1024, r=1, p=1, dklen=32), "little")
        if h <= state["target"]: break
    if state["job"] is not job:
        continue  # job moved while hashing: never submit a known-stale solution
    send("mining.submit", [user, jid, en2, ntime, "%08x" % nonce]); n += 1
    if n % 10 == 0: log(f"submitted={n} ok={results['ok']} bad={results['bad']} last_nonces={nonce+1} {time.time()-t0:.1f}s")
    time.sleep(period)
    state["fresh"].wait(timeout=5)  # next solution on the template that follows our block
