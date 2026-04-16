#!/usr/bin/env python3
"""
Minimal Dash p2pool P2P test server.
Speaks the p2pool wire protocol: [prefix(8)][command(12)][length(4LE)][checksum(4)][payload]
Listens on port 18999, logs all incoming data, responds to version handshake.
"""

import socket
import struct
import hashlib
import sys
import time

PREFIX = bytes.fromhex('3b3e1286f446b891')  # Dash p2pool mainnet prefix
PORT = 18999  # Local test port (not 8999 to avoid conflict)

def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def checksum(payload):
    return sha256d(payload)[:4]

def build_message(command, payload=b''):
    cmd = command.encode('ascii').ljust(12, b'\x00')
    length = struct.pack('<I', len(payload))
    cs = checksum(payload)
    return PREFIX + cmd + length + cs + payload

def build_version_payload():
    """Build a version message payload (protocol 1700)."""
    import struct as S
    payload = b''
    payload += S.pack('<I', 1700)           # version
    payload += S.pack('<Q', 0)              # services
    # addr_to: services(8) + ipv6(16) + port(2BE)
    payload += S.pack('<Q', 0)              # addr_to.services
    payload += b'\x00' * 10 + b'\xff\xff' + b'\x7f\x00\x00\x01'  # IPv4 127.0.0.1 mapped
    payload += S.pack('>H', PORT)           # addr_to.port (big-endian)
    # addr_from
    payload += S.pack('<Q', 0)              # addr_from.services
    payload += b'\x00' * 10 + b'\xff\xff' + b'\x7f\x00\x00\x01'
    payload += S.pack('>H', PORT)
    payload += S.pack('<Q', 0xDEADBEEF)     # nonce
    # sub_version (VarStr)
    subver = b'test-p2pool-dash/1.0'
    payload += bytes([len(subver)]) + subver
    payload += S.pack('<I', 1)              # mode
    # best_share_hash (PossiblyNone: 0 = None)
    payload += b'\x00' * 32
    return payload

def parse_message(data, offset=0):
    """Parse one p2pool message from data starting at offset."""
    if len(data) - offset < 28:  # prefix(8) + cmd(12) + len(4) + cs(4)
        return None, offset

    pfx = data[offset:offset+8]
    if pfx != PREFIX:
        print(f'  [WARN] prefix mismatch: {pfx.hex()} != {PREFIX.hex()}')
        return None, offset + 1  # scan forward

    cmd = data[offset+8:offset+20].rstrip(b'\x00').decode('ascii', errors='replace')
    length = struct.unpack('<I', data[offset+20:offset+24])[0]
    cs = data[offset+24:offset+28]

    if len(data) - offset < 28 + length:
        return None, offset  # incomplete

    payload = data[offset+28:offset+28+length]
    expected_cs = checksum(payload)

    ok = '  OK' if cs == expected_cs else ' FAIL'
    print(f'  [MSG] cmd={cmd:12s} len={length:5d} checksum={cs.hex()}{ok}')
    if cs != expected_cs:
        print(f'  [MSG]   expected checksum: {expected_cs.hex()}')
        print(f'  [MSG]   payload[:64]: {payload[:64].hex()}')

    if cmd == 'version' and length >= 4:
        ver = struct.unpack('<I', payload[:4])[0]
        # nonce at offset 52 (after services+addr_to+addr_from)
        if length >= 60:
            nonce = struct.unpack('<Q', payload[52:60])[0]
        else:
            nonce = 0
        print(f'  [VER] version={ver} nonce=0x{nonce:016x}')

    return cmd, offset + 28 + length

def main():
    print(f'Dash p2pool test server on port {PORT}')
    print(f'Prefix: {PREFIX.hex()}')
    print()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', PORT))
    srv.listen(5)
    print(f'Listening on 0.0.0.0:{PORT}...')
    print()

    while True:
        conn, addr = srv.accept()
        print(f'[CONN] {addr[0]}:{addr[1]} connected')

        # Send our version immediately (like real p2pool)
        ver_msg = build_message('version', build_version_payload())
        conn.sendall(ver_msg)
        print(f'[SENT] version ({len(ver_msg)} bytes)')

        # Read incoming data
        buf = b''
        conn.settimeout(30)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    print(f'[DISC] {addr[0]}:{addr[1]} disconnected (EOF)')
                    break
                buf += chunk
                print(f'[RECV] {len(chunk)} bytes (total buf: {len(buf)})')
                print(f'  raw[:64]: {chunk[:64].hex()}')

                # Parse messages
                offset = 0
                while offset < len(buf):
                    cmd, new_offset = parse_message(buf, offset)
                    if cmd is None:
                        if new_offset == offset:
                            break  # incomplete message
                        offset = new_offset
                        continue
                    offset = new_offset

                    if cmd == 'version':
                        # Send ping as response
                        ping_msg = build_message('ping')
                        conn.sendall(ping_msg)
                        print(f'[SENT] ping')

                        # Send a fake shares message with 0 shares
                        # to test share parsing
                        shares_payload = b'\x00'  # VarInt 0 = empty list
                        shares_msg = build_message('shares', shares_payload)
                        conn.sendall(shares_msg)
                        print(f'[SENT] shares (empty)')

                buf = buf[offset:]

        except socket.timeout:
            print(f'[TIMEOUT] {addr[0]}:{addr[1]} — 30s no data')
        except Exception as e:
            print(f'[ERROR] {e}')
        finally:
            conn.close()
            print(f'[CLOSED] {addr[0]}:{addr[1]}')
            print()

if __name__ == '__main__':
    main()
