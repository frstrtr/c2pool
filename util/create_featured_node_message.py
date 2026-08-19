#!/usr/bin/env python3
"""
c2pool / P2Pool V36 — Featured Developer-Node Banner message creator
====================================================================

Standalone utility for AUTHORITY KEY HOLDERS to create the signed+encrypted
MSG_FEATURED_NODE (0x06) authority message that drives the "featured developer
node" banner in the dashboard header.

This is a SERVICE / PRESENTATION message only. It is CONSENSUS-NEUTRAL: it does
not affect share validity, PPLNS, targets, block validity, or payout. Nodes
render it ONLY after verifying the ECDSA signature against a pinned
COMBINED_DONATION_SCRIPT authority key, and keep only the SINGLE FRESHEST valid
message (highest `seq`) — replay-protected and persisted across restarts.

Crypto is byte-identical to create_transition_message.py / share_messages.py:
  ECDSA secp256k1 (DER) over double-SHA256(msg_type|flags|timestamp|payload),
  inside the sign-then-encrypt authority envelope. ZERO new crypto.

USAGE (authority key holder):
  python3 create_featured_node_message.py create --privkey <64-hex> \\
      --seq $(date +%s) --url dash.voidbind.com \\
      --label "Featured developer node" --com "0.5%" --loc "EU/DE" --hl 1

  # retract the banner (higher seq, highlight bit cleared):
  python3 create_featured_node_message.py create --privkey <64-hex> \\
      --seq $(date +%s) --url dash.voidbind.com --hl 0

The emitted hex blob is delivered out-of-band, exactly like transition messages:
  --message-blob-hex <HEX>  |  bootstrap_messages/*.hex  |  POST /msg/load_blob

AUTHORITY KEYS (from COMBINED_DONATION_REDEEM_SCRIPT):
  forrestv:   03ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1
  maintainer: 02fe6578f8021a7d466787827b3f26437aef88279ef380af326f87ec362633293a
"""

import argparse
import hashlib
import hmac as hmac_mod
import json
import os
import struct
import sys
import time

try:
    import coincurve
    HAS_COINCURVE = True
except ImportError:
    HAS_COINCURVE = False
try:
    import ecdsa
    HAS_ECDSA = True
except ImportError:
    HAS_ECDSA = False

DONATION_PUBKEY_FORRESTV = bytes.fromhex(
    '03ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1')
DONATION_PUBKEY_MAINTAINER = bytes.fromhex(
    '02fe6578f8021a7d466787827b3f26437aef88279ef380af326f87ec362633293a')
DONATION_AUTHORITY_PUBKEYS = frozenset(
    [DONATION_PUBKEY_FORRESTV, DONATION_PUBKEY_MAINTAINER])

MSG_FEATURED_NODE = 0x06

FLAG_HAS_SIGNATURE = 0x01
FLAG_BROADCAST = 0x02
FLAG_PERSISTENT = 0x04
FLAG_PROTOCOL_AUTHORITY = 0x08

MAX_MESSAGE_PAYLOAD = 220
PAYLOAD_SCHEMA_VERSION = 1

ENCRYPTED_ENVELOPE_VERSION = 0x01
ENCRYPTION_NONCE_SIZE = 16
ENCRYPTION_MAC_SIZE = 32


# ---- crypto primitives (identical to create_transition_message.py) ----------
def derive_compressed_pubkey(privkey_bytes):
    if HAS_COINCURVE:
        return coincurve.PrivateKey(privkey_bytes).public_key.format(compressed=True)
    sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.to_string()[:32]; y = vk.to_string()[32:]
    return (b'\x02' if y[-1] % 2 == 0 else b'\x03') + x


def ecdsa_sign(privkey_bytes, message_hash):
    if HAS_COINCURVE:
        return coincurve.PrivateKey(privkey_bytes).sign(message_hash, hasher=None)
    sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
    return sk.sign_digest(message_hash, sigencode=ecdsa.util.sigencode_der)


def ecdsa_verify(pubkey_compressed, message_hash, signature):
    try:
        if HAS_COINCURVE:
            return coincurve.PublicKey(pubkey_compressed).verify(
                signature, message_hash, hasher=None)
        vk = ecdsa.VerifyingKey.from_string(pubkey_compressed, curve=ecdsa.SECP256k1)
        return vk.verify_digest(signature, message_hash,
                                sigdecode=ecdsa.util.sigdecode_der)
    except Exception:
        return False


def _derive_encryption_key(authority_pubkey, nonce):
    return hmac_mod.new(authority_pubkey, nonce, hashlib.sha256).digest()


def _generate_stream(enc_key, length):
    out = b''; counter = 0
    while len(out) < length:
        out += hashlib.sha256(enc_key + struct.pack('<I', counter)).digest()
        counter += 1
    return out[:length]


def encrypt_message_data(inner_data, authority_pubkey):
    nonce = os.urandom(ENCRYPTION_NONCE_SIZE)
    enc_key = _derive_encryption_key(authority_pubkey, nonce)
    ciphertext = bytes(a ^ b for a, b in
                       zip(inner_data, _generate_stream(enc_key, len(inner_data))))
    mac = hmac_mod.new(enc_key, ciphertext, hashlib.sha256).digest()
    return bytes([ENCRYPTED_ENVELOPE_VERSION]) + nonce + mac + ciphertext


def message_hash(msg_type, flags, timestamp, payload):
    data = struct.pack('<BBI', msg_type, flags, timestamp) + payload
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def pack_message(msg_type, flags, timestamp, payload, signature, signing_id=b'\x00' * 20):
    return (struct.pack('<BBIH', msg_type, flags, timestamp, len(payload))
            + payload + signing_id
            + struct.pack('<B', len(signature)) + signature)


# ---- featured-node payload ---------------------------------------------------
def build_featured_node_payload(seq, url, label, com, loc, hl, exp):
    payload = {'v': PAYLOAD_SCHEMA_VERSION, 'seq': int(seq)}
    if url:
        payload['url'] = url
    if label:
        payload['label'] = label
    if com:
        payload['com'] = com
    if loc:
        payload['loc'] = loc
    payload['hl'] = int(hl)
    if exp:
        payload['exp'] = int(exp)
    encoded = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    if len(encoded) > MAX_MESSAGE_PAYLOAD:
        raise ValueError('Payload too large: %d > %d bytes'
                         % (len(encoded), MAX_MESSAGE_PAYLOAD))
    return encoded


def create_featured_node_blob(privkey_bytes, seq, url, label, com, loc, hl, exp,
                              allow_test_key=False):
    pub = derive_compressed_pubkey(privkey_bytes)
    if pub not in DONATION_AUTHORITY_PUBKEYS and not allow_test_key:
        raise ValueError(
            'Private key is not a COMBINED_DONATION_SCRIPT authority key.\n'
            '  Derived: %s\n'
            '  Expected forrestv %s or maintainer %s\n'
            '  (use --unsafe-test-key ONLY to generate adversarial test blobs)'
            % (pub.hex(), DONATION_PUBKEY_FORRESTV.hex(),
               DONATION_PUBKEY_MAINTAINER.hex()))
    payload = build_featured_node_payload(seq, url, label, com, loc, hl, exp)
    ts = int(time.time())
    flags = (FLAG_HAS_SIGNATURE | FLAG_BROADCAST
             | FLAG_PERSISTENT | FLAG_PROTOCOL_AUTHORITY)
    mh = message_hash(MSG_FEATURED_NODE, flags, ts, payload)
    sig = ecdsa_sign(privkey_bytes, mh)
    if not ecdsa_verify(pub, mh, sig):
        raise RuntimeError('Self-verification failed')
    packed = pack_message(MSG_FEATURED_NODE, flags, ts, payload, sig)
    inner = struct.pack('<BBBB', 1, 0, 1, 0) + packed
    return encrypt_message_data(inner, pub), pub, ts, payload


def main():
    ap = argparse.ArgumentParser(description='Create a signed featured-node banner blob')
    sub = ap.add_subparsers(dest='command')
    c = sub.add_parser('create', help='create a signed+encrypted 0x06 blob')
    c.add_argument('--privkey', required=True, help='32-byte hex private key')
    c.add_argument('--seq', type=int, default=int(time.time()),
                   help='monotonic sequence (default: now, epoch seconds)')
    c.add_argument('--url', default='', help="node URL, e.g. dash.voidbind.com")
    c.add_argument('--label', default='Featured developer node')
    c.add_argument('--com', default='', help="commission string, e.g. '0.5%%'")
    c.add_argument('--loc', default='', help="location, e.g. 'EU/DE'")
    c.add_argument('--hl', type=int, default=1,
                   help='highlight bitfield: 0x01 header banner, 0x02 announce, 0=retract')
    c.add_argument('--exp', type=int, default=0, help='optional unix expiry (0 = none)')
    c.add_argument('--unsafe-test-key', action='store_true',
                   help='SKIP authority-pin check — TEST ONLY (adversarial blobs)')
    args = ap.parse_args()
    if args.command != 'create':
        ap.print_help(); return 1
    if args.unsafe_test_key:
        sys.stderr.write('WARNING: --unsafe-test-key: NOT an authority key; '
                         'real nodes WILL reject this blob.\n')
    privkey = bytes.fromhex(args.privkey.strip())
    if len(privkey) != 32:
        sys.stderr.write('private key must be 32 bytes\n'); return 1
    blob, pub, ts, payload = create_featured_node_blob(
        privkey, args.seq, args.url, args.label, args.com, args.loc,
        args.hl, args.exp, allow_test_key=args.unsafe_test_key)
    sys.stderr.write('signer pubkey : %s\n' % pub.hex())
    sys.stderr.write('timestamp     : %d\n' % ts)
    sys.stderr.write('payload       : %s\n' % payload.decode('utf-8'))
    sys.stderr.write('blob bytes    : %d\n' % len(blob))
    print(blob.hex())
    return 0


if __name__ == '__main__':
    sys.exit(main())
