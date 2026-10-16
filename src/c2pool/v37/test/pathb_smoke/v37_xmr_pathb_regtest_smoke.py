#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
# This file is part of c2pool and is distributed under the terms of the GNU
# Affero General Public License, version 3 or (at your option) any later
# version. See COPYING in the repository root.
# ---------------------------------------------------------------------------
# src/c2pool/v37/test/pathb_smoke/v37_xmr_pathb_regtest_smoke.py
#
# The Path B regtest rig of c2pool-v37-xmr (CTest: v37_xmr_pathb_regtest_smoke).
# Loopback only. Two peered regtest monerods (fixed difficulty 1, no update
# check, no DNS checkpoints), a monero-wallet-rpc, and these c2pool nodes:
#   A, B, C  Path B pool nodes on the rig's raw pool genesis (A: --pathb-launch),
#            relay links A-B, A-C, B-C, --mine 1 each, p2p-first, native
#            template source
#   O        the old binary (relay HELLO frame version 0x01), dialled by A and
#            dialling A
#   D        --follow-only, monerod M1 as its levin peer
#   E        --native-solo, no monerod, the default raw genesis at height 0
# Parts (--parts, default all):
#   chain     monerods, wallets, premine (an offline monerod), the stub
#   pool      A, B, C mine; found blocks read from monerod: Sum(vout) ==
#             Monero's reward at its weight + fees, outputs == the window
#             split every node shows at the block's tip
#   old       O refused at HELLO in both directions; no strike, no ban
#   partition C partitioned (SIGUSR1); a switch that re-pends a receipt;
#             the re-pended receipts relayed (a node other than the
#             switching one holds one pending, or the switching node's own
#             carriers unchanged when they are carried); the receipt
#             carried; all nodes on one best tip
#   restart   C's store corrupted while A and B run (they hold the side
#             headers they saw; a restarted server serves only the closure
#             walks of the side branches it has seen since its restart, P-51):
#             load failure (an unreadable store moved aside) -> the joiner
#             path -> C on the peers' best tip; then A, B, C stopped and
#             started twice, each resuming its native snapshot: byte-equal
#             digests
#   fo        D: start line, no listener, no pathb_db, a follow line per
#             monerod block with monerod's id, TOTAL=0; fee-diverse
#             transactions in monerod's pool, D holding a broadcast one,
#             kill -9 + restart: the first record after the restart has
#             n_tx >= 1 (an n_tx=0 record on an empty network block decides
#             nothing: the next one is judged); the stub on the default
#             regtest monerod RPC / ZMQ ports sees 0 connections
#   solo      E: no template without --pathb-launch; with it found blocks
#             landed=own-index paying the tip's window split; nothing
#             booked; a restart reloads the store
#   hold      K (--native-solo, --pathb-launch, --mine): the rig's K30 set
#             (--pathb-regtest-k30 2,4,8: G of its own) and a kind-2
#             deployment file naming epoch 1, which the build lacks: HOLD at
#             fixed - 1; the job counter stops; no strike
# Inputs: --daemon (the c2pool-v37-xmr under test); XMR_REGTEST_MONEROD,
# XMR_REGTEST_WALLET_RPC (default: beside monerod), XMR_PATHB_SMOKE_OLD_BINARY
# (the old binary; the part "old" needs it). A missing monerod, wallet-rpc
# or old binary: exit 77 (SKIPPED). Exit 0: every part run passed; 1: a check
# failed. Evidence: <work>/evidence/<part>.txt, logs: <work>/logs.
# Every process the rig starts is stopped by its pid.
# ---------------------------------------------------------------------------
import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.request

SKIP = 77
PARTS_ALL = ["chain", "pool", "old", "partition", "restart", "fo", "solo", "hold"]

# The default regtest monerod endpoint of c2pool-v37-xmr (RPC, ZMQ).
DEFAULT_RPC_PORT = 18081
DEFAULT_ZMQ_PORT = 18083

# Monero (cryptonote_config.h, cryptonote_basic_impl.cpp get_block_reward).
MONEY_SUPPLY = (1 << 64) - 1
EMISSION_SPEED_FACTOR = 20 - (2 - 1)
FINAL_SUBSIDY = 300000000000 * 2
FULL_REWARD_ZONE_V5 = 300000

# The files of the old path's store (not written by Path B).
BOOKING_NAMES = re.compile(r"^(settle\.img|pfound\.tsv.*|lane\d+\..*|race\.log|v37_settle_db)$")

FOUND_RE = re.compile(r"^found h=(\d+) id=([0-9a-f]{64}) tip=([0-9a-f]{64}) window_root=([0-9a-f]{64}) "
                      r"n_outputs=(\d+) R=(\d+) landed=(\S+)")
STATUS_RE = re.compile(r"^status: up=(\d+)s monero=(\d+) best pos=(\d+) id=([0-9a-f]+) cum_work=(\d+) epoch=(\d+) "
                       r"H_hold=(\d+) window_root=(\S+) mmr_root=(\S+) leaves=(\d+) pending=(\d+) deferred=(\d+) "
                       r"re-pended\(last switch\)=(\d+) lost\(last switch\)=(\d+) switches=(\d+) template=(.*) "
                       r"templates=(\d+)$")
RELAY_RE = re.compile(r"^  relay: peers in=(\d+) out=(\d+) ready=(\d+) \| hello ok=(\d+) rej=(\d+) old=(\d+) "
                      r"closed=(\d+) tmo=(\d+) \| strikes=(\d+) bans=(\d+)")
JOIN_RE = re.compile(r"\| join tickets=(\d+) attempts=(\d+) strikes=(\d+)")
OWN_RE = re.compile(r"own receipts=(\d+) \(carrier (\d+), pending (\d+)")
REPEND_RE = re.compile(r"relay: re-pend offer (\d+) receipt\(s\) to (\d+) peer\(s\):((?: [0-9a-f]{12})*)")
FOLLOW_RE = re.compile(r"^\[follow-only\] follow h=(\d+) id=([0-9a-f]{64}) prev=([0-9a-f]{64}) "
                       r"event=(extend|reorg|orphan) depth=(\d+) tip=(\d+)")
TEMPLATE_RE = re.compile(r"^\[follow-only\] template h=(\d+) (.*)$")
WIRE_RE = re.compile(r"wire RPC to monerod: TOTAL=(\d+)")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
class Fail(Exception):
    pass


def now():
    return time.monotonic()


def log(msg):
    sys.stdout.write("[smoke %s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stdout.flush()


def http_json(url, body=None, timeout=30):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "Connection": "close"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def rpc(port, method, params=None, timeout=60):
    r = http_json("http://127.0.0.1:%d/json_rpc" % port,
                  {"jsonrpc": "2.0", "id": "0", "method": method, "params": params or {}}, timeout)
    if "error" in r:
        raise Fail("%s on :%d: %s" % (method, port, r["error"]))
    return r["result"]


def port_free(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def listening_ports(pid):
    out = subprocess.run(["ss", "-ltnpH"], capture_output=True, text=True).stdout
    ports = []
    for line in out.splitlines():
        if "pid=%d," % pid in line:
            m = re.search(r":(\d+)\s", line.split()[3] + " ")
            if m:
                ports.append(int(m.group(1)))
    return sorted(set(ports))


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_FULL = 11
B58_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11]


def monero_b58decode(s):
    out = b""
    for i in range(0, len(s), B58_FULL):
        blk = s[i:i + B58_FULL]
        n = 0
        for c in blk:
            n = n * 58 + B58.index(c)
        size = B58_SIZES.index(len(blk))
        out += n.to_bytes(size, "big")
    return out


def address_keys(addr):
    raw = monero_b58decode(addr)
    # prefix varint (one or two bytes), spend 32, view 32, checksum 4
    body = raw[:-4]
    return body[-64:-32].hex(), body[-32:].hex()


def monero_reward(agc, weight, median):
    base = (MONEY_SUPPLY - agc) >> EMISSION_SPEED_FACTOR
    if base < FINAL_SUBSIDY:
        base = FINAL_SUBSIDY
    m = max(median, FULL_REWARD_ZONE_V5)
    if weight <= m:
        return base
    if weight > 2 * m:
        return None
    return (base * ((2 * m - weight) * weight)) // m // m


class Results:
    def __init__(self, work):
        self.items = []
        self.dir = os.path.join(work, "evidence")
        os.makedirs(self.dir, exist_ok=True)

    def note(self, part, line):
        with open(os.path.join(self.dir, part + ".txt"), "a") as f:
            f.write(line + "\n")

    def check(self, part, ok, what):
        self.items.append((part, bool(ok), what))
        self.note(part, ("PASS " if ok else "FAIL ") + what)
        log(("PASS " if ok else "FAIL ") + part + ": " + what)
        return ok


# ---------------------------------------------------------------------------
# processes
# ---------------------------------------------------------------------------
class Proc:
    def __init__(self, name, argv, logpath, cwd):
        self.name = name
        self.argv = argv
        self.logpath = logpath
        self.f = open(logpath, "ab")
        self.p = subprocess.Popen(argv, stdout=self.f, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                  cwd=cwd, start_new_session=True)
        self.pid = self.p.pid

    def alive(self):
        return self.p.poll() is None

    def stop(self, sig=signal.SIGINT, wait_s=60):
        if self.alive():
            try:
                os.kill(self.pid, sig)
            except ProcessLookupError:
                pass
            t = now()
            while self.alive() and now() - t < wait_s:
                time.sleep(0.2)
            if self.alive():
                os.kill(self.pid, signal.SIGKILL)
                self.p.wait()
        self.f.close()
        return self.p.returncode

    def kill9(self):
        if self.alive():
            os.kill(self.pid, signal.SIGKILL)
            self.p.wait()
        self.f.close()

    def text(self):
        try:
            with open(self.logpath, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""


class CountingStub:
    """Accepts and counts TCP connections on loopback ports; answers nothing."""

    def __init__(self, ports):
        self.ports = ports
        self.count = {p: 0 for p in ports}
        self.socks = []
        self.stop_ev = threading.Event()
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", p))
            s.listen(16)
            s.settimeout(0.5)
            self.socks.append(s)
        self.threads = [threading.Thread(target=self._run, args=(s, p), daemon=True) for s, p in zip(self.socks, ports)]
        for t in self.threads:
            t.start()

    def _run(self, s, p):
        while not self.stop_ev.is_set():
            try:
                c, _ = s.accept()
                self.count[p] += 1
                c.close()
            except socket.timeout:
                continue
            except OSError:
                return

    def close(self):
        self.stop_ev.set()
        for t in self.threads:
            t.join(2)
        for s in self.socks:
            s.close()


class WebPoller:
    """Polls each pool node's /xmr/pathb and keeps what it saw per best tip."""

    def __init__(self):
        self.ports = {}
        self.seen = {}      # name -> {tip id: set((window_root, R, amounts))}
        self.last = {}      # name -> last answer
        self.pend = {}      # name -> every pending receipt id (12 hex digits) seen since clear_pending
        self.hist = {}      # name -> [(monotonic time, switches, set(pending ids))] since clear_pending
        self.lock = threading.Lock()
        self.stop_ev = threading.Event()
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def watch(self, name, port):
        with self.lock:
            self.ports[name] = port
            self.seen.setdefault(name, {})

    def unwatch(self, name):
        with self.lock:
            self.ports.pop(name, None)
            self.last.pop(name, None)

    def _run(self):
        while not self.stop_ev.is_set():
            with self.lock:
                ports = dict(self.ports)
            for name, port in ports.items():
                try:
                    j = http_json("http://127.0.0.1:%d/xmr/pathb" % port, timeout=3)
                except Exception:
                    continue
                pb = j.get("pathb", {})
                tip = pb.get("best_tip", {}).get("id", "")
                amounts = tuple(sorted(int(e.get("amount_pico", 0)) for e in j.get("window", [])))
                with self.lock:
                    self.last[name] = j
                    self.pend.setdefault(name, set()).update(pb.get("pending_ids", []))
                    self.hist.setdefault(name, []).append(
                        (time.monotonic(), int(pb.get("switches", -1)), set(pb.get("pending_ids", []))))
                    self.seen.setdefault(name, {}).setdefault(tip, set()).add(
                        (pb.get("window_root", ""), sum(amounts), amounts))
            self.stop_ev.wait(0.4)

    def get(self, name):
        with self.lock:
            return self.last.get(name)

    def clear_pending(self):
        with self.lock:
            self.pend = {}
            self.hist = {}

    def history(self, name):
        with self.lock:
            return list(self.hist.get(name, []))

    def pending_seen(self, name):
        with self.lock:
            return set(self.pend.get(name, set()))

    def views_at(self, name, tip):
        with self.lock:
            return set(self.seen.get(name, {}).get(tip, set()))

    def close(self):
        self.stop_ev.set()
        self.t.join(3)


def digest_of(j):
    pb = j["pathb"]
    bt = pb["best_tip"]
    return (bt["pos"], bt["id"], bt["cum_work"], pb["window_root"], pb["mmr_root"], pb["leaf_count"])


def last_status(text):
    st = None
    for line in text.splitlines():
        m = STATUS_RE.match(line)
        if m:
            st = m
    return st


def last_relay(text):
    st = None
    for line in text.splitlines():
        m = RELAY_RE.match(line)
        if m:
            st = m
    return st


def wait_for(pred, timeout, what, step=1.0):
    t = now()
    while now() - t < timeout:
        v = pred()
        if v:
            return v
        time.sleep(step)
    raise Fail("timeout (%ds): %s" % (timeout, what))


def booking_files(root):
    hits = []
    for d, dirs, files in os.walk(root):
        for n in dirs + files:
            if BOOKING_NAMES.match(n):
                hits.append(os.path.join(d, n))
    return hits


# ---------------------------------------------------------------------------
# the rig
# ---------------------------------------------------------------------------
class Rig:
    def __init__(self, a):
        self.a = a
        self.work = os.path.abspath(a.work)
        self.logs = os.path.join(self.work, "logs")
        self.res = Results(self.work)
        self.procs = []
        self.stub = None
        self.web = WebPoller()
        b = a.port_base
        self.p = {
            "m1_p2p": b, "m1_rpc": b + 1, "wallet": b + 3, "m2_p2p": b + 4, "m2_rpc": b + 5,
            "relay_A": b + 10, "relay_B": b + 11, "relay_C": b + 12, "relay_O": b + 13,
            "stratum_A": b + 20, "stratum_B": b + 21, "stratum_C": b + 22, "stratum_E": b + 23, "stratum_O": b + 24,
            "web_A": b + 30, "web_B": b + 31, "web_C": b + 32, "web_E": b + 33,
            "stratum_K": b + 25, "web_K": b + 34,
        }
        self.addr = {}
        self.genesis = None
        self.H = None
        self.nodes = {}
        self.runs = {}
        self.found = []

    # ---- processes ----
    def start(self, name, argv, cwd=None, nice=True):
        run = self.runs.get(name, 0) + 1
        self.runs[name] = run
        lp = os.path.join(self.logs, "%s.run%d.log" % (name, run))
        argv = (["nice", "-n", "15"] if nice else []) + argv
        p = Proc(name, argv, lp, cwd or self.work)
        self.procs.append(p)
        self.res.note("processes", "start %s pid=%d log=%s argv=%s" % (name, p.pid, lp, " ".join(argv)))
        log("start %s pid %d (%s)" % (name, p.pid, os.path.basename(lp)))
        return p

    def stop_all(self):
        for p in reversed(self.procs):
            if p.alive():
                p.stop(signal.SIGINT, 30)
        if self.stub:
            self.stub.close()
        self.web.close()

    # ---- monerod ----
    def monerod_argv(self, ddir, logf, p2p, rpc_port, extra):
        return [self.a.monerod, "--regtest", "--keep-fakechain", "--fixed-difficulty", "1", "--no-igd",
                "--hide-my-port", "--non-interactive", "--allow-local-ip", "--check-updates", "disabled",
                "--no-zmq", "--disable-dns-checkpoints", "--disable-rpc-ban", "--max-connections-per-ip", "32",
                "--in-peers", "32", "--log-level", "0", "--data-dir", ddir, "--log-file", logf,
                "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(rpc_port)] + \
               (["--p2p-bind-ip", "127.0.0.1", "--p2p-bind-port", str(p2p)] if p2p else []) + extra

    def m1(self):
        return self.p["m1_rpc"]

    def chain_tip(self):
        return rpc(self.m1(), "get_info")["height"] - 1

    def hash_at(self, h):
        return rpc(self.m1(), "get_block_header_by_height", {"height": h})["block_header"]["hash"]

    def wallet(self, method, params=None):
        return rpc(self.p["wallet"], method, params, timeout=300)

    # ---- the wallets (the payee addresses; the funding wallet) ----
    def ensure_wallets(self, offline):
        if self.addr:
            return
        os.makedirs(os.path.join(self.work, "wallets"), exist_ok=True)
        argv = [self.a.wallet_rpc, "--daemon-address", "127.0.0.1:%d" % self.m1(), "--trusted-daemon",
                "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(self.p["wallet"]), "--disable-rpc-login",
                "--wallet-dir", os.path.join(self.work, "wallets"), "--log-file",
                os.path.join(self.logs, "wallet-rpc.log"), "--log-level", "0", "--non-interactive",
                "--allow-mismatched-daemon-version"]
        self.wproc = self.start("wallet-rpc", argv + (["--offline"] if offline else []), nice=False)
        wait_for(lambda: self._wallet_ok(), 60, "wallet-rpc")
        for n in ["fund", "A", "B", "C", "E", "O"]:
            try:
                self.wallet("close_wallet")
            except Exception:
                pass
            self.wallet("create_wallet", {"filename": "w" + n, "language": "English"})
            self.addr[n] = self.wallet("get_address")["address"]
            self.res.note("chain", "wallet %s address %s" % (n, self.addr[n]))

    # ---- part chain ----
    def part_chain(self):
        a = self.a
        md1, md2 = os.path.join(self.work, "m1"), os.path.join(self.work, "m2")
        os.makedirs(md1, exist_ok=True)
        os.makedirs(md2, exist_ok=True)
        pre = self.start("monerod-premine", self.monerod_argv(md1, os.path.join(self.logs, "m1-premine.log"), None,
                                                              self.m1(), ["--offline"]), nice=False)
        wait_for(lambda: self._info_ok(self.m1()), 60, "premine monerod RPC")
        self.ensure_wallets(False)
        r = rpc(self.m1(), "generateblocks", {"amount_of_blocks": a.premine, "wallet_address": self.addr["fund"]})
        self.res.note("chain", "premine generateblocks %d -> height %s" % (a.premine, r.get("height")))
        pre.stop(signal.SIGTERM)

        def synced():
            try:
                i1, i2 = rpc(self.m1(), "get_info"), rpc(self.p["m2_rpc"], "get_info")
            except Exception:
                return False
            return i1["synchronized"] and i2["synchronized"] and i1["height"] == i2["height"] == a.premine + 1
        for attempt in (1, 2):   # a monerod pair that does not flag "synchronized" is started once more
            self.m1p = self.start("monerod-m1", self.monerod_argv(md1, os.path.join(self.logs, "m1.log"),
                                                                   self.p["m1_p2p"], self.m1(),
                                                                   ["--out-peers", "8", "--add-exclusive-node",
                                                                    "127.0.0.1:%d" % self.p["m2_p2p"]]), nice=False)
            self.m2p = self.start("monerod-m2", self.monerod_argv(md2, os.path.join(self.logs, "m2.log"),
                                                                   self.p["m2_p2p"], self.p["m2_rpc"],
                                                                   ["--out-peers", "8", "--add-exclusive-node",
                                                                    "127.0.0.1:%d" % self.p["m1_p2p"]]), nice=False)
            try:
                wait_for(synced, 120, "M1 and M2 synchronized")
                break
            except Fail:
                if attempt == 2:
                    raise
                self.res.note("chain", "M1 and M2 not synchronized in 120 s: both started once more")
                self.m1p.stop(signal.SIGTERM)
                self.m2p.stop(signal.SIGTERM)
        self.H = self.chain_tip()
        hh = self.hash_at(self.H)
        self.genesis = hashlib.sha256(b"v37 pathb regtest smoke" + bytes.fromhex(hh)).hexdigest()
        self.res.note("chain", "pool genesis (raw) %s:%d (Monero block %s)" % (self.genesis, self.H, hh))
        self.res.check("chain", True, "monerods M1/M2 synchronized at tip %d; premine %d blocks" % (self.H, a.premine))
        # the counting stub on the default regtest monerod RPC / ZMQ ports
        for p in (DEFAULT_RPC_PORT, DEFAULT_ZMQ_PORT):
            if not port_free(p):
                raise Fail("the default monerod port 127.0.0.1:%d is in use: the stub cannot run" % p)
        self.stub = CountingStub([DEFAULT_RPC_PORT, DEFAULT_ZMQ_PORT])
        self.res.note("fo", "stub listening on 127.0.0.1:%d and :%d" % (DEFAULT_RPC_PORT, DEFAULT_ZMQ_PORT))

    def _info_ok(self, port):
        try:
            rpc(port, "get_info", timeout=5)
            return True
        except Exception:
            return False

    def _wallet_ok(self):
        try:
            self.wallet("get_version")
            return True
        except Exception:
            return False

    # ---- the pool nodes ----
    def pool_argv(self, n, mine, launch, peers, extra=()):
        d = os.path.join(self.work, "node" + n)
        os.makedirs(d, exist_ok=True)
        argv = [self.a.daemon_run, "--network", "regtest", "--arm-order", "p2p-first", "--xmr-template-source",
                "native", "--randomx", "--native-connect", "127.0.0.1:%d" % self.p["m1_p2p"],
                "--native-snapshot-path", os.path.join(d, "chain.snap"), "--rpc-port", str(self.m1()),
                "--pool-genesis", "%s:%d" % (self.genesis, self.H), "--payout-address", self.addr[n],
                "--relay-listen", "127.0.0.1:%d" % self.p["relay_" + n], "--no-relay-bootstrap",
                "--stratum-port", str(self.p["stratum_" + n]), "--web-port", str(self.p["web_" + n]),
                "--data-dir", d, "--status-every", "5", "--poll-ms", "250"]
        for q in peers:
            argv += ["--relay-peer", "127.0.0.1:%d" % self.p["relay_" + q]]
        if launch:
            argv.append("--pathb-launch")
        if mine:
            argv += ["--mine", str(self.a.mine_threads[n]), "--mine-fast", "--mine-no-huge-pages",
                     "--mine-no-affinity"]
        return argv + list(extra), d

    def start_pool_node(self, n, mine):
        peers = {"A": ["O"], "B": ["A"], "C": ["A", "B"]}[n]
        extra = ["--relay-test-partition-seconds", str(self.a.partition_s)] if n == "C" else []
        argv, d = self.pool_argv(n, mine, n == "A", peers, extra)
        p = self.start(n, argv, cwd=d)
        self.nodes[n] = p
        wait_for(lambda: "stratum: listening on" in p.text() or not p.alive(), 180, "node %s stratum" % n)
        if not p.alive():
            raise Fail("node %s exited: see %s" % (n, p.logpath))
        self.web.watch(n, self.p["web_" + n])
        return p

    def relay_ready(self, n):
        m = last_relay(self.nodes[n].text())
        return int(m.group(3)) if m else 0

    def found_lines(self, n):
        out = []
        for line in self.nodes[n].text().splitlines():
            m = FOUND_RE.match(line)
            if m:
                out.append(dict(node=n, h=int(m.group(1)), id=m.group(2), tip=m.group(3), window_root=m.group(4),
                                n_outputs=int(m.group(5)), R=int(m.group(6)), landed=m.group(7)))
        return out

    def check_found_block(self, f):
        """f lands on monerod's main chain: Sum(vout) == Monero's reward + fees; the outputs == the window split
        each pool node shows at f's tip."""
        try:
            if self.hash_at(f["h"]) != f["id"]:
                return None
        except Exception:
            return None
        blk = rpc(self.m1(), "get_block", {"hash": f["id"]})
        hdr = blk["block_header"]
        bj = json.loads(blk["json"])
        vout = [int(o["amount"]) for o in bj["miner_tx"]["vout"]]
        fees = 0
        if blk.get("tx_hashes"):
            txs = http_json("http://127.0.0.1:%d/get_transactions" % self.m1(),
                            {"txs_hashes": blk["tx_hashes"], "decode_as_json": True})
            for t in txs.get("txs", []):
                fees += int(json.loads(t["as_json"])["rct_signatures"]["txnFee"])
        s = rpc(self.m1(), "get_coinbase_tx_sum", {"height": 0, "count": f["h"]})
        agc = int(s["emission_amount"]) + (int(s.get("emission_amount_top64", 0)) << 64)
        lo = max(0, f["h"] - 100)
        hs = rpc(self.m1(), "get_block_headers_range", {"start_height": lo, "end_height": f["h"] - 1})["headers"]
        median = int(statistics.median([int(x["block_weight"]) for x in hs])) if hs else 0
        weight = int(hdr["block_weight"])
        base = monero_reward(agc, weight, median)
        rec = dict(f, vout=vout, sum_vout=sum(vout), fees=fees, agc=agc, weight=weight, median=median, base=base,
                   reward=hdr.get("reward"))
        return rec

    def own_carriers(self, n):
        own = OWN_RE.findall(self.nodes[n].text())
        return int(own[-1][1]) if own else 0

    def judge_found(self, cache):
        """Each found line of A, B, C buried >= 2 on monerod: its block read from monerod (cached)."""
        tip = self.chain_tip()
        for n in "ABC":
            for f in self.found_lines(n):
                if f["id"] in cache or tip - f["h"] < 2:
                    continue
                cache[f["id"]] = (n, f, self.check_found_block(f))
        return cache

    def coinbase_views(self, f, rec):
        vamounts = tuple(sorted(rec["vout"]))
        per = {}
        for m in "ABC":
            views = self.web.views_at(m, f["tip"])
            per[m] = "equal" if any(v[0] == f["window_root"] and v[2] == vamounts for v in views) else \
                ("other" if views else "not-seen")
        return per

    def part_pool(self):
        a = self.a
        self.start_pool_node("A", True)
        self.start_pool_node("B", True)
        self.start_pool_node("C", True)
        wait_for(lambda: all(self.relay_ready(n) >= 2 for n in "ABC"), 180, "relay links A-B, A-C, B-C ready")
        self.res.note("pool", "relay links ready on A, B, C")
        t0 = now()
        cache = {}
        while True:
            time.sleep(10)
            self.judge_found(cache)
            full = [1 for (_, f, rec) in cache.values() if rec is not None and f["n_outputs"] >= 2 and
                    all(v == "equal" for v in self.coinbase_views(f, rec).values())]
            carriers = {n: self.own_carriers(n) for n in "ABC"}
            if (len(full) >= a.min_found and all(c >= 1 for c in carriers.values())) or now() - t0 > a.pool_s:
                break
        self.res.note("pool", "pool phase %.0f s; own carriers %s" % (now() - t0, carriers))
        checked = 0
        cov = 0
        for bid, (n, f, rec) in sorted(cache.items(), key=lambda x: x[1][1]["h"]):
            if rec is None:
                self.res.note("pool", "found %s h=%d by %s: not on monerod's main chain (a same-height sibling)" %
                              (bid, f["h"], n))
                continue
            checked += 1
            exp = None if rec["base"] is None else rec["base"] + rec["fees"]
            ok = exp is not None and rec["sum_vout"] == exp and rec["sum_vout"] == f["R"] and \
                len(rec["vout"]) == f["n_outputs"] and rec["weight"] <= max(rec["median"], FULL_REWARD_ZONE_V5)
            self.res.check("pool", ok, "block h=%d id=%s by %s: Sum(vout)=%d == Monero reward(agc=%d, weight=%d, "
                           "median=%d)=%s + fees %d; found line R=%d n_outputs=%d; vout %d" %
                           (f["h"], bid, n, rec["sum_vout"], rec["agc"], rec["weight"], rec["median"],
                            rec["base"], rec["fees"], f["R"], f["n_outputs"], len(rec["vout"])))
            if f["n_outputs"] >= 2:
                per = self.coinbase_views(f, rec)
                cov += 1 if all(v == "equal" for v in per.values()) else 0
                self.res.note("pool", "  h=%d outputs %s vs the window split at tip %s (window_root %s): %s" %
                              (f["h"], sorted(rec["vout"]), f["tip"], f["window_root"], per))
        self.res.check("pool", checked >= 1, "found blocks on monerod's main chain checked: %d" % checked)
        self.res.check("pool", cov >= 1, "found blocks whose outputs equal the window split A, B and C show at the "
                                         "block's tip: %d" % cov)
        for n in "ABC":
            t = self.nodes[n].text()
            mined = re.findall(r"^cpu-miner: ENABLED threads=\d+", t, re.M)
            self.res.check("pool", bool(mined) and self.own_carriers(n) >= 1,
                           "%s --mine: %s, own carriers %d" % (n, mined[0] if mined else "no miner",
                                                                self.own_carriers(n)))
        self.pool_alarms()
        self.no_booking("pool", ["A", "B", "C"])

    def pool_alarms(self):
        for n in "ABC":
            t = self.nodes[n].text()
            bad = [l for l in t.splitlines() if "coinbase-internal" in l]
            self.res.check("pool", not bad, "%s: no coinbase-internal alarm (%d lines)" % (n, len(bad)))

    def no_booking(self, part, names):
        for n in names:
            d = os.path.join(self.work, "node" + n)
            hits = booking_files(d)
            self.res.check(part, not hits, "%s: no old-path store file under %s %s" % (n, d, hits[:5]))

    # ---- part old ----
    def part_old(self):
        a = self.a
        d = os.path.join(self.work, "nodeO")
        os.makedirs(d, exist_ok=True)
        spend, view = address_keys(self.addr["O"])
        argv = [a.old_binary, "--network", "regtest", "--randomx", "--rpc-port", str(self.m1()), "--coinbase", "v37",
                "--residual-sink-spend-hex", spend, "--residual-sink-view-hex", view, "--share-diff", "18180",
                "--data-dir", d, "--relay-listen", "127.0.0.1:%d" % self.p["relay_O"], "--relay-peer",
                "127.0.0.1:%d" % self.p["relay_A"], "--no-relay-bootstrap", "--stratum-port",
                str(self.p["stratum_O"]), "--status-every", "5", "--poll-ms", "500"]
        o = self.start("O", argv, cwd=d)
        self.nodes["O"] = o
        before = last_relay(self.nodes["A"].text())
        sb = (int(before.group(9)), int(before.group(10))) if before else (0, 0)

        def both():
            if not o.alive():
                raise Fail("O exited: %s" % o.text().strip().splitlines()[-3:])
            ta, to = self.nodes["A"].text(), o.text()
            a_ref = [l for l in ta.splitlines() if "HELLO REFUSED" in l and "K22" in l and "frame version 1" in l]
            o_ref = [l for l in to.splitlines() if "HELLO undecodable (hello: unknown version)" in l]
            return (a_ref, o_ref) if a_ref and o_ref else None
        try:
            a_ref, o_ref = wait_for(both, a.old_s, "the old HELLO refused on A and the Path B HELLO refused on O", 2)
        except Fail as e:
            ta, to = self.nodes["A"].text(), o.text()
            self.res.note("old", "A HELLO lines: %s" % [l for l in ta.splitlines() if "HELLO" in l][-5:])
            self.res.note("old", "O HELLO lines: %s" % [l for l in to.splitlines() if "HELLO" in l.upper()][-5:])
            self.res.check("old", False, str(e))
            return
        self.res.note("old", "A: " + a_ref[0].strip())
        self.res.note("old", "O: " + o_ref[0].strip())
        time.sleep(12)
        ra = last_relay(self.nodes["A"].text())
        to = o.text()
        o_bans = [l for l in to.splitlines() if re.search(r"\bBANNED\b|\bban(ned)? .*127\.0\.0\.1:%d" %
                                                          self.p["relay_A"], l)]
        a_bans = [l for l in self.nodes["A"].text().splitlines() if "BANNED" in l]
        self.res.check("old", ra is not None and int(ra.group(6)) >= 1,
                       "A: the old HELLO refused (hello old=%s), A dialled O: O refused the Path B HELLO" %
                       (ra.group(6) if ra else "?"))
        self.res.check("old", ra is not None and (int(ra.group(9)), int(ra.group(10))) == sb and not a_bans,
                       "A: strikes/bans unchanged %s -> (%s, %s), no BANNED line" %
                       (sb, ra.group(9) if ra else "?", ra.group(10) if ra else "?"))
        self.res.check("old", not o_bans, "O: no ban of A (%d lines)" % len(o_bans))
        self.res.check("old", len(o_ref) >= 1 and len(a_ref) >= 1,
                       "both directions: O->A refused %d times on A, A->O refused %d times on O" %
                       (len(a_ref), len(o_ref)))

    # ---- part partition ----
    def part_partition(self):
        a = self.a
        for attempt in range(1, a.partition_tries + 1):
            st0 = {n: last_status(self.nodes[n].text()) for n in "ABC"}
            sw0 = {n: int(st0[n].group(15)) if st0[n] else 0 for n in "ABC"}
            j0 = {n: JOIN_RE.findall(self.nodes[n].text()) for n in "ABC"}
            j0 = {n: int(v[-1][1]) if v else 0 for n, v in j0.items()}
            own0 = OWN_RE.findall(self.nodes["C"].text())
            c_carriers0 = int(own0[-1][1]) if own0 else 0
            offers0 = {n: len(REPEND_RE.findall(self.nodes[n].text())) for n in "ABC"}
            wsw0 = {n: int((self.web.get(n) or {}).get("pathb", {}).get("switches", -1)) for n in "ABC"}
            self.web.clear_pending()
            os.kill(self.nodes["C"].pid, signal.SIGUSR1)
            t_heal = time.monotonic() + a.partition_s - 2  # the views before it are of the partition
            self.res.note("partition", "attempt %d: SIGUSR1 to C (pid %d), switches before %s" %
                          (attempt, self.nodes["C"].pid, sw0))
            wait_for(lambda: self.nodes["C"].text().count("relay: partition over") >= attempt,
                     a.partition_s + 60, "C's partition over")
            own1 = OWN_RE.findall(self.nodes["C"].text())
            c_carriers1 = int(own1[-1][1]) if own1 else 0
            self.res.note("partition", "attempt %d: C's own carriers %d -> %d during the partition" %
                          (attempt, c_carriers0, c_carriers1))

            def switched():
                for n in "ABC":
                    s = last_status(self.nodes[n].text())
                    if s and int(s.group(15)) > sw0[n] and int(s.group(13)) >= 1:
                        return (n, s)
                return None
            try:
                n, s = wait_for(switched, a.heal_s, "a switch with a re-pended receipt", 2)
            except Fail:
                self.res.note("partition", "attempt %d: no switch with a re-pended receipt" % attempt)
                continue
            self.res.note("partition", "%s: %s" % (n, s.group(0)))
            own_sw = OWN_RE.findall(self.nodes[n].text())
            own_sw = int(own_sw[-1][1]) if own_sw else -1

            # the re-pend offer: the switching node's offer lines since the attempt began (the ids named, up to 16)
            def offered():
                o = REPEND_RE.findall(self.nodes[n].text())[offers0[n]:]
                return o if o else None
            try:
                offers = wait_for(offered, 30, "the switching node's re-pend offer line", 1)
            except Fail:
                offers = []
            ids = set(i for o in offers for i in o[2].split())
            sent = [(int(o[0]), int(o[1])) for o in offers]

            # every view of the switching node published after the switch (its switches count moved); the peers'
            # pending sets during the partition (before the heal) and after the switch
            def switch_time():
                for t, sw, _ in self.web.history(n):
                    if wsw0[n] >= 0 and sw > wsw0[n]:
                        return t
                return None
            try:
                t_sw = wait_for(switch_time, 30, "a web view of %s after the switch" % n, 1)
            except Fail:
                t_sw = None
            seen = {}

            def settled():
                if t_sw is None:
                    return None
                for t, sw, pend in self.web.history(n):
                    if t >= t_sw and sw > wsw0[n] and ids and not (ids & pend) and "carried" not in seen:
                        seen["carried"] = t
                views = {m: self.web.get(m) for m in "ABC"}
                tips = {v["pathb"]["best_tip"]["id"] for v in views.values() if v}
                if len(tips) == 1 and all(views.values()) and "tip" not in seen:
                    seen["tip"] = (list(tips)[0], views[n]["pathb"]["leaf_count"])
                return seen if "carried" in seen and "tip" in seen else None
            try:
                wait_for(settled, a.heal_s, "the re-pended receipts carried, one best tip", 1)
            except Fail as e:
                seen.setdefault("why", str(e))
            before, after = {}, {}
            for m in "ABC":
                if m == n:
                    continue
                h = self.web.history(m)
                before[m] = set().union(*[p for t, _, p in h if t < t_heal]) if h else set()
                after[m] = set().union(*[p for t, _, p in h if t >= t_heal]) if h else set()
            # a receipt counts for a peer only if that peer did not hold it during the partition; every named receipt
            # must be held after the heal by a peer that did not hold it before
            fresh = {m: ids - before[m] for m in after}
            proven = set().union(*[after[m] & fresh[m] for m in after]) if after else set()
            self.res.check("partition", t_sw is not None and bool(ids) and proven == ids and any(k >= 1 for _, k in sent),
                           "%s relayed its re-pended receipts: offers (receipts, peers) %s; %d named; held pending after "
                           "the heal by a peer that did not hold it during the partition: %s; all: %s" %
                           (n, sent, len(ids),
                            ", ".join("%s %d of %d" % (m, len(after[m] & fresh[m]), len(fresh[m])) for m in sorted(after)),
                            "%d of %d" % (len(proven), len(ids))))
            own_n = OWN_RE.findall(self.nodes[n].text())
            self.res.check("partition", "carried" in seen,
                           "%s: none of its re-pended receipts pending in a view published after the switch (carried)"
                           "%s; own receipts %s" % (n, "" if "carried" in seen else " -- " + seen.get("why", "not seen"),
                                                    own_n[-1] if own_n else "-"))
            if "tip" not in seen:
                self.res.check("partition", False, "A, B, C on one best tip: not seen")
                return
            tips = [seen["tip"][0]]
            j = {"pathb": {"leaf_count": seen["tip"][1]}}
            s2 = last_status(self.nodes[n].text())
            j1 = JOIN_RE.findall(self.nodes[n].text())
            j1 = int(j1[-1][1]) if j1 else 0
            self.res.check("partition", j1 == j0[n], "%s switched by the journal: switches %d -> %s, re-pended(last "
                           "switch)=%s lost(last switch)=%s, join attempts %d -> %d" %
                           (n, sw0[n], s.group(15), s.group(13), s.group(14), j0[n], j1))
            self.res.check("partition", int(s.group(14)) < int(s.group(13)),
                           "%s: re-pended %s > lost %s" % (n, s.group(13), s.group(14)))
            self.res.check("partition", True, "A, B, C on one best tip %s (leaves %s)" % (tips[0], j["pathb"]["leaf_count"]))
            self.res.note("partition", "%s status after: %s" % (n, s2.group(0) if s2 else "-"))
            return
        self.res.check("partition", False, "no switch with a re-pended receipt in %d partitions" % a.partition_tries)

    # ---- part restart ----
    def stop_pool(self, names):
        for n in names:
            self.web.unwatch(n)
            rc = self.nodes[n].stop(signal.SIGINT, 90)
            self.res.note("restart", "stop %s rc=%s" % (n, rc))

    def send_transfers(self, plan, part):
        # transfers from the funding wallet: [(destination, priority)]; returns [(tx_hash, priority, fee)]
        self.wallet("close_wallet")
        self.wallet("open_wallet", {"filename": "wfund"})
        self.wallet("refresh")
        sent = []
        for i, (dst, prio) in enumerate(plan):
            try:
                r = self.wallet("transfer", {"destinations": [{"amount": 1000000000000 + i, "address": self.addr[dst]}],
                                             "priority": prio, "ring_size": 16})
                sent.append((r["tx_hash"], prio, r.get("fee")))
            except Fail as e:
                self.res.note(part, "transfer %d failed: %s" % (i, e))
        return sent

    def txpool_count(self, p):
        c = re.findall(r"^  txpool: .*\| count=(\d+)", p.text(), re.M)
        return int(c[-1]) if c else 0

    def digests_now(self, names, settle_s=8):
        def ready():
            out = {}
            for n in names:
                j = self.web.get(n)
                if not j or not j["pathb"]["best_tip"]["id"] or j["pathb"]["template"] != "ok":
                    return None
                out[n] = digest_of(j)
            return out
        wait_for(lambda: ready(), 180, "web digests of %s" % names, 1)
        time.sleep(settle_s)
        return ready()

    def part_restart(self):
        # load failure first: C's store corrupted while A and B keep running (their side headers held in memory).
        # C is stopped and started once (the store's log goes into a table file), then stopped and corrupted.
        self.stop_pool("C")
        self.start_pool_node("C", False)
        self.stop_pool("C")
        dbs = [os.path.join(dp, f) for dp, _, fs in os.walk(os.path.join(self.work, "nodeC", "regtest", "pathb_db"))
               for f in fs if f.endswith(".ldb")]
        if not dbs:
            self.res.check("restart", False, "C: no table file to corrupt")
            return
        victim = max(dbs, key=os.path.getsize)
        sz = os.path.getsize(victim)
        with open(victim, "r+b") as f:
            f.seek(sz // 2)
            blk = bytearray(f.read(64))
            for i in range(len(blk)):
                blk[i] ^= 0xa5
            f.seek(sz // 2)
            f.write(blk)
        self.res.note("restart", "C: corrupted 64 bytes at offset %d of %s (%d bytes)" % (sz // 2, victim, sz))
        try:
            p = self.start_pool_node("C", False)
        except Fail as e:
            refused = [l for l in self.nodes["C"].text().splitlines() if l.startswith("REFUSED")]
            self.res.check("restart", False, "C with the corrupted store: %s (%s)" % (e, refused[:1]))
            return
        lf = re.findall(r"^store: \S+ load failed .*$", p.text(), re.M)
        mv = re.findall(r"^store: \S+ unreadable .* moved aside to .*$", p.text(), re.M)
        self.res.note("restart", "C: %s" % (mv[0] if mv else "store readable: not moved aside"))
        self.res.check("restart", bool(lf), "C: load failure -> the joiner path: %s" % (lf[0] if lf else "no line"))
        if not lf:
            return

        def adopted():
            j = self.web.get("C")
            ja = self.web.get("A")
            if not j or not ja:
                return None
            return j if j["pathb"]["best_tip"]["id"] == ja["pathb"]["best_tip"]["id"] else None
        try:
            j = wait_for(adopted, self.a.join_s, "C adopts the peers' best tip", 2)
            self.res.check("restart", True, "C: on the peers' best tip after the joiner path: %s" % (digest_of(j),))
        except Fail as e:
            rl = last_relay(p.text())
            self.res.note("restart", "C relay: %s" % (rl.group(0) if rl else "-"))
            self.res.note("restart", "C status: %s" % (last_status(p.text()).group(0) if last_status(p.text()) else "-"))
            att = re.findall(r"^  relay: join attempt .*$", p.text(), re.M)
            self.res.note("restart", "C join attempts: %d, last %s" % (len(att), att[-1] if att else "-"))
            self.res.check("restart", False, str(e))
        # then A, B, C stopped and started twice: byte-equal digests. Between the two restarts (no miner runs) transactions
        # go into monerod's pool and A holds a broadcast one before the stop: each node's first template after the
        # second restart carries them. Before the second restart C's native snapshot loses its output-set overlay (a
        # snapshot of a build that wrote none, a crash between the two writes): C does not resume the image, it re-walks;
        # its next two starts resume the image with its overlay, ring resolution intact
        try:
            pre = {}
            for n in "ABC":
                j = self.web.get(n)
                pre[n] = digest_of(j) if j else None
            self.stop_pool("ABC")
            self.res.note("restart", "pre-stop digests (last web answer): %s" % pre)
            rounds = []
            for r in (1, 2):
                for n in "ABC":
                    self.start_pool_node(n, False)
                wait_for(lambda: all(self.relay_ready(n) >= 2 for n in "ABC"), 180, "relay links after restart %d" % r)
                loaded = {}
                for n in "ABC":
                    m = re.findall(r"^store: \S+ loaded: best position (\d+)$", self.nodes[n].text(), re.M)
                    loaded[n] = m[-1] if m else None
                dg = self.digests_now("ABC")
                rounds.append(dg)
                if r == 2:
                    first = {}
                    for n in "ABC":
                        tl = re.findall(r"^template \d+: .* n_tx=(\d+) ", self.nodes[n].text(), re.M)
                        first[n] = int(tl[0]) if tl else None
                    pool = http_json("http://127.0.0.1:%d/get_transaction_pool" % self.m1(), {}).get("transactions", [])
                    self.res.check("restart", all(first[n] is not None and first[n] >= 1 for n in "ABC"),
                                   "restart 2: each node's first template carries the pool's transactions (n_tx %s; "
                                   "monerod's pool %d)" % (first, len(pool)))
                self.res.note("restart", "restart %d: store loaded best position %s; digests %s" % (r, loaded, dg))
                self.res.check("restart", all(loaded[n] is not None for n in "ABC"),
                               "restart %d: A, B, C loaded their stores (best positions %s)" % (r, loaded))
                self.res.check("restart", len(set(dg.values())) == 1,
                               "restart %d: A, B, C byte-equal (pos, id, cum_work, window_root, mmr_root, leaves)" % r)
                if r == 1:
                    for n in "ABC":
                        if pre[n] is not None:
                            self.res.note("restart", "%s: pre-stop pos %s, loaded pos %s" % (n, pre[n][0], dg[n][0]))
                    sent = self.send_transfers([("B", 2), ("C", 3)], "restart")
                    self.res.note("restart", "sent %s" % (sent,))
                    try:
                        wait_for(lambda: self.txpool_count(self.nodes["A"]) >= 1 or None, self.a.fo_bcast_s,
                                 "A holds a broadcast transaction before the stop", 2)
                    except Fail as e:
                        self.res.check("restart", False, str(e))
                    self.stop_pool("ABC")
                    ovl = os.path.join(self.work, "nodeC", "chain.snap.outset")
                    had = os.path.exists(ovl)
                    if had:
                        os.remove(ovl)
                    self.res.note("restart", "C: native output-set overlay %s" % ("removed" if had else "absent"))
            self.res.check("restart", rounds[0] == rounds[1], "restart 1 == restart 2 per node, byte-equal digests")
            rw = re.findall(r"\[snapshot\] no resume: no output-set overlay usable .*$", self.nodes["C"].text(), re.M)
            self.res.check("restart", bool(rw), "restart 2: C without the overlay re-walks: %s" % (rw[0][:100] if rw else "no line"))
            for k in (1, 2):
                self.stop_pool("C")
                self.start_pool_node("C", False)
                wait_for(lambda: self.relay_ready("C") >= 2, 180, "C's relay links after its later start %d" % k)
                res = re.findall(r"\[snapshot\] RESUMED at height \d+ .*ring resolution (\w+).*$", self.nodes["C"].text(), re.M)
                self.res.check("restart", bool(res) and res[-1] == "intact",
                               "C's later start %d resumes the image with its overlay: ring resolution %s"
                               % (k, res[-1] if res else "(no resume line)"))
        except Fail as e:
            self.res.check("restart", False, str(e))

    # ---- part fo ----
    def fo_argv(self):
        d = os.path.join(self.work, "nodeD")
        os.makedirs(d, exist_ok=True)
        return [self.a.daemon_run, "--network", "regtest", "--follow-only", "--native-connect",
                "127.0.0.1:%d" % self.p["m1_p2p"], "--native-snapshot-path", os.path.join(d, "chain.snap"),
                "--native-snapshot-every", "10", "--data-dir", d, "--status-every", "5", "--poll-ms", "250"], d

    def start_fo(self):
        argv, d = self.fo_argv()
        p = self.start("D", argv, cwd=d)
        self.nodes["D"] = p
        wait_for(lambda: "[follow-only] template" in p.text() or not p.alive(), 180, "D's first template line")
        if not p.alive():
            raise Fail("D exited: see %s" % p.logpath)
        return p

    def part_fo_checks_live(self):
        p = self.nodes["D"]
        t = p.text()
        first = t.splitlines()[0] if t else ""
        sl = [l for l in t.splitlines() if l.startswith("c2pool-v37-xmr: FOLLOW-ONLY ")]
        self.res.check("fo", bool(sl) and " monerod=none " in sl[0] + " " and "stratum=off" in sl[0] and
                       "relay=off" in sl[0] and "mine=off" in sl[0] and "pool=none" in sl[0],
                       "start line: %s" % (sl[0] if sl else first))
        lp = listening_ports(p.pid)
        self.res.check("fo", not lp, "D (pid %d) listens on no TCP port: %s" % (p.pid, lp))
        if port_free(3333):
            try:
                c = socket.create_connection(("127.0.0.1", 3333), timeout=2)
                c.close()
                refused = False
            except OSError:
                refused = True
            self.res.check("fo", refused, "the default stratum port 127.0.0.1:3333 refuses a connect")
        pdb = [os.path.join(dp, x) for dp, ds, _ in os.walk(os.path.join(self.work, "nodeD")) for x in ds
               if x == "pathb_db"]
        self.res.check("fo", not pdb, "no pathb_db directory under nodeD: %s" % pdb)

    def fo_restart(self):
        a = self.a
        p = self.nodes["D"]
        # fee-diverse transactions in monerod's pool; D runs until it holds one of them: the network has broadcast it
        # (monerod's complement answer carries broadcast transactions only, not its local or stem ones)
        sent = self.send_transfers([("A", 1), ("B", 2), ("C", 3), ("E", 4), ("O", 1), ("A", 3)], "fo")
        pool = http_json("http://127.0.0.1:%d/get_transaction_pool" % self.m1(), {}).get("transactions", [])
        rates = sorted({round(int(x["fee"]) / max(1, int(x["weight"])), 3) for x in pool})
        self.res.note("fo", "sent %s; monerod pool %d txs, fee/weight rates %s" % (sent, len(pool), rates))
        self.res.check("fo", len(pool) >= 2 and len(rates) >= 2,
                       "monerod's pool holds %d fee-diverse transactions (rates %s)" % (len(pool), rates))

        def d_pool():
            c = re.findall(r"^  txpool: .*\| count=(\d+)", p.text(), re.M)
            return int(c[-1]) if c and int(c[-1]) >= 1 else None
        try:
            n = wait_for(d_pool, a.fo_bcast_s, "D holds a broadcast transaction before the kill", 2)
            self.res.note("fo", "D's pool before the kill: %d transactions" % n)
        except Fail as e:
            self.res.check("fo", False, str(e))
            return
        p.kill9()
        self.res.note("fo", "kill -9 D (pid %d)" % p.pid)
        argv, d = self.fo_argv()
        q = self.start("D", argv, cwd=d)
        self.nodes["D"] = q

        def records():
            out = []
            for line in q.text().splitlines():
                m = TEMPLATE_RE.match(line)
                if m and not m.group(2).startswith("none"):
                    out.append(line)
            return out
        try:
            wait_for(lambda: records() or None, a.fo_restart_s, "D's first record after the restart", 1)
        except Fail as e:
            self.res.check("fo", False, str(e))
            return
        nones = [l for l in q.text().splitlines() if TEMPLATE_RE.match(l) and " none " in l + " "]
        self.res.note("fo", "after the restart: none lines before the first record: %s" % nones[:5])
        rs = [l for l in q.text().splitlines() if "snapshot" in l and ("RESUMED" in l or "no resume" in l)]
        self.res.note("fo", "restart: %s" % (rs[0].strip() if rs else "-"))
        # 5.9's judge: the first record per height from the first one after the restart; n_tx=0 fails when the
        # network's block at its height carries a transaction; an empty network block decides nothing, the next
        # record is judged. The rig mines the network's blocks on M1 and reads D's compare lines.
        judged = set()
        for step in range(3):
            first = {}
            for line in records():
                h = int(re.search(r"template h=(\d+)", line).group(1))
                first.setdefault(h, line)
            hs = sorted(h for h in first if h not in judged)
            if not hs:
                self.res.check("fo", False, "no record to judge after %d empty network blocks" % step)
                return
            h, line = hs[0], first[hs[0]]
            judged.add(h)
            if int(re.search(r"n_tx=(\d+)", line).group(1)) >= 1:
                self.res.check("fo", True, "the first record after kill -9 + restart%s: %s" %
                               (" (after %d empty network blocks)" % step if step else "", line))
                return
            try:
                rpc(self.m1(), "generateblocks", {"amount_of_blocks": 1, "wallet_address": self.addr["fund"]})
            except Fail as e:
                self.res.check("fo", False, "generateblocks for the judge: %s" % e)
                return
            pat = re.compile(r"^\[follow-only\] compare h=%d net_id=\S+ net_n_tx=(\d+) " % h, re.M)
            try:
                m = wait_for(lambda: pat.search(q.text()), 120, "D's compare line at h=%d" % h, 1)
            except Fail as e:
                self.res.check("fo", False, "a record with n_tx=0 at h=%d and %s" % (h, e))
                return
            if int(m.group(1)) >= 1:
                ref = len(http_json("http://127.0.0.1:%d/get_transaction_pool" % self.m1(), {}).get("transactions", []))
                self.res.check("fo", False, "the first record after kill -9 + restart has n_tx=0 and the network's "
                               "block at h=%d carries %s (the reference pool now %d): %s" % (h, m.group(1), ref, line))
                return
            self.res.note("fo", "h=%d: n_tx=0 and an empty network block: the next record is judged" % h)
            wait_for(lambda: any(int(re.search(r"template h=(\d+)", l).group(1)) > h for l in records()) or None,
                     60, "D's next record", 1)
        self.res.check("fo", False, "three records with n_tx=0, each on an empty network block")

    def part_fo_final(self):
        p = self.nodes["D"]
        p.stop(signal.SIGINT, 60)
        text = ""
        for r in range(1, self.runs.get("D", 0) + 1):
            with open(os.path.join(self.logs, "D.run%d.log" % r), errors="replace") as f:
                text += f.read()
        lines = text.splitlines()
        follow = {}
        for l in lines:
            m = FOLLOW_RE.match(l)
            if m and m.group(4) != "orphan":
                follow[int(m.group(1))] = m.group(2)
        tip = self.chain_tip()
        missing, wrong = [], []
        for h in range(1, tip + 1):
            mid = self.hash_at(h)
            if h not in follow:
                missing.append(h)
            elif follow[h] != mid:
                wrong.append(h)
        self.res.check("fo", not missing and not wrong,
                       "a follow line per monerod block 1..%d with monerod's id (missing %s, other id %s)" %
                       (tip, missing[:10], wrong[:10]))
        # a template line per live tip: after a pump's follow lines that end at the tip, a template line for tip + 1
        tl = [l for l in lines if TEMPLATE_RE.match(l)]
        recs = [l for l in tl if " none " not in l + " "]
        self.res.check("fo", len(recs) >= 1, "template records: %d, none lines: %d" % (len(recs), len(tl) - len(recs)))
        gaps = []
        live = 0
        for i, l in enumerate(lines):
            m = FOLLOW_RE.match(l)
            if not m or m.group(4) != "extend" or int(m.group(1)) != int(m.group(6)):
                continue
            live += 1
            tip_h = int(m.group(1))
            for l2 in lines[i + 1:]:
                if FOLLOW_RE.match(l2) or l2.startswith("c2pool-v37-xmr: FOLLOW-ONLY"):
                    break
                m2 = TEMPLATE_RE.match(l2)
                if m2:
                    if int(m2.group(1)) < tip_h + 1:
                        gaps.append((tip_h, int(m2.group(1))))
                    break
            else:
                pass
        self.res.check("fo", not gaps, "%d live tips: each followed by a template line for tip + 1 or by the next "
                                       "follow line of the same pass (mismatches %s)" % (live, gaps[:5]))
        totals = [int(x) for x in WIRE_RE.findall(text)]
        self.res.check("fo", totals and all(x == 0 for x in totals),
                       "witness: %d status lines 'wire RPC to monerod: TOTAL=0' (other values %s)" %
                       (len(totals), sorted({x for x in totals if x != 0})))
        if self.stub:
            self.res.check("fo", all(v == 0 for v in self.stub.count.values()),
                           "the stub on 127.0.0.1:%d / :%d saw %s connections" %
                           (DEFAULT_RPC_PORT, DEFAULT_ZMQ_PORT, self.stub.count))
        pdb = [os.path.join(dp, x) for dp, ds, _ in os.walk(os.path.join(self.work, "nodeD")) for x in ds
               if x == "pathb_db"]
        self.res.check("fo", not pdb, "after both runs: no pathb_db directory under nodeD: %s" % pdb)

    # ---- part solo ----
    def solo_argv(self, launch, mine):
        d = os.path.join(self.work, "nodeE")
        os.makedirs(d, exist_ok=True)
        argv = [self.a.daemon_run, "--network", "regtest", "--native-solo", "--arm-order", "p2p-first",
                "--xmr-template-source", "native", "--randomx", "--pool-genesis-height", "0", "--payout-address",
                self.addr["E"], "--data-dir", d, "--stratum-port", str(self.p["stratum_E"]),
                "--web-port", str(self.p["web_E"]), "--status-every", "5", "--poll-ms", "250",
                "--native-snapshot-path", os.path.join(d, "chain.snap"), "--native-txpool-warm-timeout-ms", "2000"]
        if launch:
            argv.append("--pathb-launch")
        if mine:
            argv += ["--mine", str(self.a.mine_threads["E"]), "--mine-fast", "--mine-no-huge-pages",
                     "--mine-no-affinity"]
        return argv, d

    def part_solo(self):
        a = self.a
        argv, d = self.solo_argv(False, True)
        p = self.start("E", argv, cwd=d)
        wait_for(lambda: "stratum: listening on" in p.text() or not p.alive(), 180, "E stratum")
        time.sleep(a.solo_nolaunch_s)
        p.stop()
        t = p.text()
        tmpl = re.findall(r"^template \d+: .*$", t, re.M)
        none = re.findall(r"^template: none -- no Path B peer.*$", t, re.M)
        found = re.findall(r"^found h=.*$", t, re.M)
        self.res.check("solo", not tmpl and not found and bool(none),
                       "without --pathb-launch: %d template lines, %d found lines, '%s'" %
                       (len(tmpl), len(found), none[0] if none else "no 'no Path B peer' line"))
        argv, d = self.solo_argv(True, True)
        p = self.start("E", argv, cwd=d)
        self.nodes["E"] = p
        wait_for(lambda: "stratum: listening on" in p.text() or not p.alive(), 180, "E stratum (launch)")
        self.web.watch("E", self.p["web_E"])

        def found2():
            fs = [m for m in (FOUND_RE.match(l) for l in p.text().splitlines()) if m]
            ok = [m for m in fs if int(m.group(5)) >= 2 and
                  any(v[0] == m.group(4) and len(v[2]) == int(m.group(5)) and v[1] == int(m.group(6))
                      for v in self.web.views_at("E", m.group(3)))]
            return ok if ok else None
        try:
            ok = wait_for(found2, a.solo_s, "E: a found block whose coinbase is its tip's window split", 2)
        except Fail as e:
            self.res.check("solo", False, str(e))
            ok = []
        fs = [m for m in (FOUND_RE.match(l) for l in p.text().splitlines()) if m]
        self.res.check("solo", fs and all(m.group(7) == "own-index" for m in fs),
                       "with --pathb-launch: %d found lines, landed %s" % (len(fs), sorted({m.group(7) for m in fs})))
        if ok:
            m = ok[0]
            self.res.check("solo", True, "found h=%s tip=%s: window_root %s, n_outputs %s, R %s equal the window split "
                           "E shows at that tip" % (m.group(1), m.group(3), m.group(4), m.group(5), m.group(6)))
        pub = re.findall(r"^  publish: relayed=(\d+) solo_landed=(\d+)", p.text(), re.M)
        self.res.note("solo", "publish counters (last): %s" % ((pub[-1] if pub else "-"),))
        self.web.unwatch("E")
        p.stop()
        # the state at the stop: the last template line before it (its tip and x = best position + 1); the miner
        # keeps placing carriers until the stop, after the last status line and web answer
        tl = re.findall(r"^template \d+: tip=([0-9a-f]+) x=(\d+) ", p.text().split("c2pool-v37-xmr: stopped")[0], re.M)
        last_tip, last_x = (tl[-1][0], int(tl[-1][1])) if tl else (None, None)
        self.no_booking("solo", ["E"])
        argv, d = self.solo_argv(True, False)
        q = self.start("E", argv, cwd=d)
        wait_for(lambda: "stratum: listening on" in q.text() or not q.alive(), 180, "E stratum (restart)")
        lm = re.findall(r"^store: \S+ loaded: best position (\d+)$", q.text(), re.M)
        self.res.check("solo", bool(lm) and last_x is not None and int(lm[0]) == last_x - 1,
                       "restart: store loaded at best position %s (at the stop: x=%s)" %
                       (lm[0] if lm else "-", last_x if last_x is not None else "-"))
        self.web.watch("E", self.p["web_E"])
        try:
            j = wait_for(lambda: self.web.get("E"), 30, "E web after restart")
            self.res.check("solo", last_tip is not None and j["pathb"]["best_tip"]["id"].startswith(last_tip),
                           "restart: best tip %s == the tip at the stop %s" % (j["pathb"]["best_tip"], last_tip))
        except Fail as e:
            self.res.check("solo", False, str(e))
        self.web.unwatch("E")
        q.stop()
        self.no_booking("solo", ["E"])

    # ---- part hold (AC-07) ----
    def part_hold(self):
        d = os.path.join(self.work, "nodeK")
        os.makedirs(d, exist_ok=True)
        dep = os.path.join(d, "deployments.bin")
        k30 = (2, 4, 8)            # L, GRACE, TIMEOUT: W_R = floor((GRACE - 1) / L) + 1 = 2, N_W = 4
        fixed = 0 + k30[1]         # kind 2: fixed = start + GRACE
        rec = (1).to_bytes(2, "little") + bytes([0x11]) * 32 + bytes([2]) + (0).to_bytes(8, "little") + \
              (0).to_bytes(8, "little") + fixed.to_bytes(8, "little")
        assert len(rec) == 59
        with open(dep, "wb") as f:
            f.write(rec)
        argv = [self.a.daemon_run, "--network", "regtest", "--native-solo", "--arm-order", "p2p-first",
                "--xmr-template-source", "native", "--randomx", "--pool-genesis-height", "0", "--payout-address",
                self.addr["E"], "--data-dir", d, "--stratum-port", str(self.p["stratum_K"]),
                "--web-port", str(self.p["web_K"]), "--status-every", "5", "--poll-ms", "250",
                "--native-snapshot-path", os.path.join(d, "chain.snap"), "--native-txpool-warm-timeout-ms", "2000",
                "--pathb-launch", "--pathb-regtest-k30", "%d,%d,%d" % k30, "--pathb-deployments", dep,
                "--mine", str(self.a.mine_threads["E"]), "--mine-fast", "--mine-no-huge-pages", "--mine-no-affinity"]
        p = self.start("K", argv, cwd=d)
        self.nodes["K"] = p
        wait_for(lambda: "stratum: listening on" in p.text() or not p.alive(), 180, "K stratum")
        golden = "f91737946910674cbe8dac71618f5c02ab5c6c7d4a431163c9b4d2222ce67e0e"
        stores = [n for n in os.listdir(os.path.join(d, "regtest", "pathb_db"))] \
            if os.path.isdir(os.path.join(d, "regtest", "pathb_db")) else []
        self.res.check("hold", bool(stores) and all(not n.endswith(golden) for n in stores),
                       "the rig's K30 set gives a G of its own: store %s" % (stores,))
        try:
            wait_for(lambda: re.search(r"^HOLD: epoch \d+, x=\d+", p.text(), re.M), self.a.hold_s, "K: HOLD", 2)
        except Fail as e:
            self.res.check("hold", False, str(e))
            p.stop()
            return
        hl = re.search(r"^HOLD: .*$", p.text(), re.M).group(0)
        self.res.check("hold", True, "K: %s" % hl)
        sus = re.findall(r"^lane SUSPEND: causes=(\S+)", p.text(), re.M)
        self.res.check("hold", bool(sus) and "hold" in sus[-1], "K: lane SUSPEND with cause hold (%s)" % (sus[-1:],))

        def counts():
            jb = re.findall(r"^  stratum: .* jobs=(\d+) ", p.text(), re.M)
            mj = re.findall(r"^  \S.* jobs=(\d+) hits=(\d+) blocks=(\d+)$", p.text(), re.M)
            return (jb[-1] if jb else None, mj[-1] if mj else None)
        time.sleep(10)
        c1 = counts()
        time.sleep(30)
        c2 = counts()
        self.res.check("hold", c1 == c2 and c1[0] is not None,
                       "K: the job counters (stratum, miner) stop under HOLD (%s -> %s)" % (c1, c2))
        rl = last_relay(p.text())
        bans = [l for l in p.text().splitlines() if "BANNED" in l or " strike " in l]
        self.res.check("hold", (rl is None or (int(rl.group(9)) == 0 and int(rl.group(10)) == 0)) and not bans,
                       "K: no strike, no ban (%s; %d lines)" % (rl.group(0)[:120] if rl else "no relay line", len(bans)))
        p.stop()
        self.no_booking("hold", ["K"])

    # ---- the run ----
    def run(self):
        parts = self.a.parts
        need_chain = any(x in parts for x in ["chain", "pool", "old", "partition", "restart", "fo"])
        if need_chain:
            self.part_chain()
        if "fo" in parts:
            self.start_fo()
        if "pool" in parts or "old" in parts or "partition" in parts or "restart" in parts:
            self.part_pool()
        if "fo" in parts:
            self.part_fo_checks_live()
        if "old" in parts:
            self.part_old()
        if "partition" in parts:
            self.part_partition()
        if "restart" in parts:
            if "O" in self.nodes:
                self.nodes["O"].stop()
            self.part_restart()
        if "fo" in parts:
            self.fo_restart()
            self.part_fo_final()
        if "solo" in parts:
            for n in "ABC":
                if n in self.nodes and self.nodes[n].alive():
                    self.web.unwatch(n)
                    self.nodes[n].stop()
            self.ensure_wallets(True)
            self.part_solo()
        if "hold" in parts:
            self.ensure_wallets(True)
            self.part_hold()


def main():
    ap = argparse.ArgumentParser(description="c2pool-v37-xmr Path B regtest rig")
    ap.add_argument("--daemon", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--port-base", type=int, default=48500)
    ap.add_argument("--parts", default=",".join(PARTS_ALL))
    ap.add_argument("--premine", type=int, default=80)
    ap.add_argument("--pool-s", type=int, default=600)
    ap.add_argument("--min-found", type=int, default=2)
    ap.add_argument("--mine-threads", default="A=2,B=2,C=1,E=2")
    ap.add_argument("--old-s", type=int, default=120)
    ap.add_argument("--partition-s", type=int, default=90)
    ap.add_argument("--partition-tries", type=int, default=3)
    ap.add_argument("--heal-s", type=int, default=180)
    ap.add_argument("--join-s", type=int, default=300)
    ap.add_argument("--fo-restart-s", type=int, default=120)
    ap.add_argument("--fo-bcast-s", type=int, default=300)
    ap.add_argument("--solo-nolaunch-s", type=int, default=30)
    ap.add_argument("--solo-s", type=int, default=300)
    ap.add_argument("--hold-s", type=int, default=600)
    a = ap.parse_args()
    a.mine_threads = {k: int(v) for k, v in (x.split("=") for x in a.mine_threads.split(","))}
    a.parts = [x for x in a.parts.split(",") if x]
    for x in a.parts:
        if x not in PARTS_ALL:
            print("unknown part %s" % x)
            return 2
    a.monerod = os.environ.get("XMR_REGTEST_MONEROD", "")
    a.wallet_rpc = os.environ.get("XMR_REGTEST_WALLET_RPC", "")
    if a.monerod and not a.wallet_rpc:
        a.wallet_rpc = os.path.join(os.path.dirname(a.monerod), "monero-wallet-rpc")
    a.old_binary = os.environ.get("XMR_PATHB_SMOKE_OLD_BINARY", "")
    missing = []
    if not a.monerod or not os.access(a.monerod, os.X_OK):
        missing.append("XMR_REGTEST_MONEROD (monerod)")
    if not a.wallet_rpc or not os.access(a.wallet_rpc, os.X_OK):
        missing.append("XMR_REGTEST_WALLET_RPC (monero-wallet-rpc)")
    if "old" in a.parts and (not a.old_binary or not os.access(a.old_binary, os.X_OK)):
        missing.append("XMR_PATHB_SMOKE_OLD_BINARY (the old c2pool-v37-xmr)")
    if missing:
        print("SKIPPED: v37_xmr_pathb_regtest_smoke needs " + ", ".join(missing))
        return SKIP
    if not os.access(a.daemon, os.X_OK):
        print("FAIL: the daemon %s is not executable" % a.daemon)
        return 1
    if os.path.exists(a.work):
        shutil.rmtree(a.work)
    os.makedirs(os.path.join(a.work, "logs"))
    a.daemon_run = os.path.join(a.work, "c2pool-v37-xmr")
    shutil.copy2(a.daemon, a.daemon_run)
    rig = Rig(a)
    with open(a.daemon, "rb") as f:
        rig.res.note("processes", "daemon %s sha256 %s" % (a.daemon, hashlib.sha256(f.read()).hexdigest()))
    busy = [p for p in sorted(set(rig.p.values())) if not port_free(p)]
    if busy:
        print("FAIL: rig ports in use: %s" % busy)
        return 1
    rc = 0
    try:
        rig.run()
    except Fail as e:
        rig.res.check("rig", False, str(e))
    except Exception as e:
        rig.res.check("rig", False, "%s: %s" % (type(e).__name__, e))
    finally:
        rig.stop_all()
    fails = [x for x in rig.res.items if not x[1]]
    print("=" * 72)
    for part in PARTS_ALL + ["rig"]:
        its = [x for x in rig.res.items if x[0] == part]
        if its:
            print("%-10s %s (%d checks)" % (part, "PASS" if all(x[1] for x in its) else "FAIL", len(its)))
    print("SUMMARY: %d checks, %d failed" % (len(rig.res.items), len(fails)))
    for x in fails:
        print("  FAIL %s: %s" % (x[0], x[2]))
    if fails or not rig.res.items:
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
