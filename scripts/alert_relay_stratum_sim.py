#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""alert_relay_stratum_sim.py -- minimal stratum v1 miner stand-in for the
D-MINER.7 alert-relay end-to-end rig.

Connects, sends mining.subscribe + mining.authorize(USER, PASS), prints the
authorize result, then holds the session open (reading and discarding work
notifications) for --hold seconds or until SIGTERM/SIGINT, and closes. It never
submits a share: presence on the node is the stratum session registry, which
is what the alert detector samples.

    alert_relay_stratum_sim.py --port 19901 --user yADDR.rig1 --hold 30
    alert_relay_stratum_sim.py --testnet-address 7      # print a valid Dash testnet P2PKH

stdlib only.
"""

import argparse
import hashlib
import json
import signal
import socket
import sys
import time

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = len(data) - len(data.lstrip(b"\0"))
    return "1" * pad + out


def testnet_address(seed):
    """Dash testnet P2PKH (version 140 -> 'y...') over a deterministic hash160."""
    h160 = hashlib.new("sha256", ("alert-relay-sim-%d" % seed).encode()).digest()[:20]
    return b58check(bytes([140]) + h160)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int)
    ap.add_argument("--user")
    ap.add_argument("--password", default="x")
    ap.add_argument("--hold", type=float, default=0.0, help="seconds to stay connected (0 = until signalled)")
    ap.add_argument("--testnet-address", type=int, metavar="SEED")
    args = ap.parse_args()

    if args.testnet_address is not None:
        print(testnet_address(args.testnet_address))
        return 0
    if not args.port or not args.user:
        ap.error("--port and --user are required")

    stop = {"flag": False}

    def on_sig(*_):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, on_sig)
    signal.signal(signal.SIGINT, on_sig)

    s = socket.create_connection((args.host, args.port), timeout=10)
    s.settimeout(1.0)
    f = s.makefile("rwb", buffering=0)

    def send(obj):
        f.write((json.dumps(obj) + "\n").encode())

    send({"id": 1, "method": "mining.subscribe", "params": ["alert-relay-sim/1.0"]})
    send({"id": 2, "method": "mining.authorize", "params": [args.user, args.password]})
    authorized = None
    deadline = time.time() + args.hold if args.hold > 0 else None
    buf = b""
    while not stop["flag"] and (deadline is None or time.time() < deadline):
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            print("sim: server closed the connection", flush=True)
            break
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("id") == 2 and authorized is None:
                authorized = msg.get("result")
                print("sim: authorize %s -> %s" % (args.user, authorized), flush=True)
    s.close()
    print("sim: disconnected %s" % args.user, flush=True)
    return 0 if authorized else 3


if __name__ == "__main__":
    sys.exit(main())
