#!/usr/bin/env python3
# Paced stratum client for the REGTEST rig. At network difficulty 1 (regtest, and the native
# index's own difficulty below ~735 blocks) EVERY hash is a block, so a real miner floods the
# chain with same-height competitors. This client logs in like xmrig and submits ONE nonce per
# interval (uniform MIN..MAX s). The node still recomputes RandomX and runs every gate.
#
# dup-verify: optional 5th arg "eager" -- ALSO submit at once, exactly once, whenever a job
# for a NEW (higher) height arrives, EAGER_DELAY s after the job (default 0.3). Every such
# submission is a block built on a template served right after the node connected a new
# tip: the "backlog refresh" window the dup-tx race lives in.
import sys, json, socket, time, random, os
port, login, lo, hi = int(sys.argv[1]), sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
eager = len(sys.argv) > 5 and sys.argv[5] == "eager"
eager_delay = float(os.environ.get("EAGER_DELAY", "0.3"))
def log(*a): print(time.strftime("%H:%M:%S"), *a, flush=True)
last_eager_h = 0
while True:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(0.2)
        buf = b""
        def send(o): s.sendall((json.dumps(o) + "\n").encode())
        send({"id": 1, "jsonrpc": "2.0", "method": "login",
              "params": {"login": login, "pass": "x", "agent": "paced/1.0", "algo": ["rx/0"]}})
        rpcid, job, nid, nonce = None, None, 2, random.randrange(1 << 32)
        due = time.time() + random.uniform(lo, hi)
        eager_due = None
        def submit(tag):
            global nonce, nid
            nonce = (nonce + 1) & 0xffffffff
            nh = nonce.to_bytes(4, "little").hex()
            send({"id": nid, "jsonrpc": "2.0", "method": "submit",
                  "params": {"id": rpcid, "job_id": job["job_id"], "nonce": nh, "result": "00" * 32}})
            log("submit%s job=%s h=%s nonce=%s" % (tag, job["job_id"], job.get("height"), nh))
            nid += 1
        while True:
            try:
                if b"\n" not in buf:
                    chunk = s.recv(65536)
                    if not chunk: raise ConnectionError("closed")
                    buf += chunk
                    continue
                line, buf = buf.split(b"\n", 1)
                if not line.strip(): continue
                m = json.loads(line)
                newjob = None
                if m.get("method") == "job": newjob = m["params"]
                elif isinstance(m.get("result"), dict) and "job" in m["result"]:
                    rpcid = m["result"].get("id"); newjob = m["result"]["job"]
                elif m.get("error"):
                    log("error", m["error"])
                    # A refused login (lane suspended: "No job available") never
                    # yields a session id; reconnect so the resumed lane serves us.
                    if not rpcid: raise ConnectionError("login refused")
                elif m.get("result") is not None and m.get("id", 0) > 1: log("ok", m["result"])
                if newjob is not None:
                    job = newjob
                    log("JOB h=%s seed=%s" % (job.get("height"), job.get("seed_hash")))
                    try: jh = int(job.get("height") or 0)
                    except Exception: jh = 0
                    if eager and jh > last_eager_h:
                        last_eager_h = jh
                        eager_due = time.time() + eager_delay
                        log("eager armed h=%d" % jh)
            except socket.timeout:
                pass
            if job and rpcid and eager_due is not None and time.time() >= eager_due:
                eager_due = None
                submit("(EAGER)")
            if job and rpcid and time.time() >= due:
                # xdw: a BURST of nonces on the SAME job (one height): at regtest difficulty 1 every
                # hash is also a block, so this is the only way one payee draws >= K hashes in one
                # interval. The node classifies each: share (meets share_diff) or raindrop.
                for _b in range(int(os.environ.get("BURST", "1"))):
                    submit("(b%d)" % _b)
                due = time.time() + random.uniform(lo, hi)
    except Exception as e:
        log("reconnect:", e); time.sleep(2)
