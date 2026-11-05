#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""dash_v36_peer_standin.py -- a minimal sharechain peer for the private/isolated
DASH v36 sharechain end-to-end rig (scripts/dash_v36_isolated_e2e.sh).

It dials a c2pool-dash node, sends ONE p2pool `version` message advertising the
protocol version given with --proto, and reports what the node does with it:

    EOF after <ms> ms        the node closed the connection (handshake refused)
    still open after <s> s   the node kept the connection (handshake admitted)

A p2pool-dash (python) peer advertises protocol 1700 and a c2pool-dash build
without v36 isolated support advertises 3600; the private/isolated v36
sharechain advertises 3601 and starts with its accept floor at 3601, so
--proto 1700 and --proto 3600 must be refused and --proto 3601 admitted.

Framing (src/core/packet.hpp, src/impl/dash/messages.hpp):
    prefix | command[12] (NUL padded) | length u32 LE | sha256d(payload)[:4] | payload
    version payload = version u32 | services u64 | addr_to | addr_from |
                      nonce u64 | subversion varstr | mode u32 | best_share[32]
    addr = services u64 | IPv6 (IPv4-mapped) 16 bytes | port u16 BIG endian

--self-test prints the frame for the fixed fields the C++ KAT
DashV36E2E.PeerStandInVersionFramingGolden pins, so both sides are compared to
one golden constant.
"""
import argparse
import hashlib
import socket
import struct
import sys
import time

SELFTEST_PREFIX = "0011223344556677"
SELFTEST_NONCE = 0x0123456789ABCDEF
SELFTEST_SUBVER = b"dash-v36-e2e-standin"


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def varstr(b: bytes) -> bytes:
    n = len(b)
    if n < 0xFD:
        return bytes([n]) + b
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n) + b
    return b"\xfe" + struct.pack("<I", n) + b


def addr(services: int, ipv4: str, port: int) -> bytes:
    ip = bytes(10) + b"\xff\xff" + socket.inet_aton(ipv4)
    return struct.pack("<Q", services) + ip + struct.pack(">H", port)


def version_payload(proto: int, to_port: int, from_port: int, nonce: int, subver: bytes) -> bytes:
    return (struct.pack("<I", proto) + struct.pack("<Q", 0)
            + addr(1, "127.0.0.1", to_port) + addr(1, "127.0.0.1", from_port)
            + struct.pack("<Q", nonce) + varstr(subver) + struct.pack("<I", 1)
            + bytes(32))


def frame(prefix_hex: str, command: str, payload: bytes) -> bytes:
    cmd = command.encode().ljust(12, b"\x00")
    return (bytes.fromhex(prefix_hex) + cmd + struct.pack("<I", len(payload))
            + sha256d(payload)[:4] + payload)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--prefix", default="", help="sharechain prefix, hex (16 chars)")
    ap.add_argument("--proto", type=int, default=1700)
    ap.add_argument("--hold", type=float, default=5.0, help="seconds to wait for EOF")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()

    if a.self_test:
        p = version_payload(1700, 19811, 19899, SELFTEST_NONCE, SELFTEST_SUBVER)
        print(frame(SELFTEST_PREFIX, "version", p).hex())
        return 0

    if not a.port or len(a.prefix) != 16:
        ap.error("--port and a 16-hex-char --prefix are required")

    s = socket.create_connection((a.host, a.port), timeout=5)
    local_port = s.getsockname()[1]
    nonce = int.from_bytes(hashlib.sha256(str(time.time()).encode()).digest()[:8], "little")
    s.sendall(frame(a.prefix, "version",
                    version_payload(a.proto, a.port, local_port, nonce,
                                    b"dash-v36-e2e-standin-%d" % a.proto)))
    t0 = time.time()
    s.settimeout(0.25)
    buf = b""
    while time.time() - t0 < a.hold:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            continue
        except ConnectionResetError:
            chunk = b""
        if not chunk:
            print("EOF after %d ms (received %d bytes: %s)"
                  % ((time.time() - t0) * 1000, len(buf), commands(buf, a.prefix)))
            return 0
        buf += chunk
    print("still open after %.0f s (received %d bytes: %s)" % (a.hold, len(buf), commands(buf, a.prefix)))
    s.close()
    return 0


def commands(buf: bytes, prefix_hex: str) -> str:
    """The commands of the complete frames in `buf`, in order."""
    pre = bytes.fromhex(prefix_hex)
    out, o = [], 0
    while o + len(pre) + 20 <= len(buf):
        if buf[o:o + len(pre)] != pre:
            out.append("<bad prefix>")
            break
        cmd = buf[o + len(pre):o + len(pre) + 12].rstrip(b"\x00").decode(errors="replace")
        (n,) = struct.unpack("<I", buf[o + len(pre) + 12:o + len(pre) + 16])
        if o + len(pre) + 20 + n > len(buf):
            break
        out.append(cmd)
        o += len(pre) + 20 + n
    return ",".join(out) if out else "none"


if __name__ == "__main__":
    sys.exit(main())
