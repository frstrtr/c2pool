#!/usr/bin/env python3
"""
c2pool Block Explorer — lightweight web-based block browser (coin-generic).

Bundled with c2pool for use with embedded SPV nodes or standalone daemons.
ONE explorer serves every coin c2pool supports: the coin is auto-detected from
the daemon / c2pool node it is pointed at (mirroring how the dashboard reads the
node's /web/currency_info), then a per-coin PROFILE selects the correct address
versions, algorithm label, explorer links and coinbase/payout decode hooks.

Supported coins (profile completeness):
  - dash : FULL  — X11, DASH X-addresses, DIP3/DIP4 CbTx payload decode,
                   masternode payee outputs, c2pool/p2pool PPLNS + donation +
                   OP_RETURN ref_hash payout trace.
  - ltc  : FULL  — scrypt, LTC addresses (incl. bech32), AuxPoW parent decode.
  - doge : FULL  — scrypt (AuxPoW child), DOGE addresses, merged-mining parent
                   (LTC) coinbase decode.
  - btc  : FULL  — sha256d, BTC addresses (incl. bech32 / taproot).
  - dgb  : BASIC — DigiByte addresses (incl. bech32); multi-algo label shown but
                   per-block algo detection is a TODO.
  - bch  : BASIC — legacy base58 addresses + coinbase browse; cashaddr is a TODO.

Features:
- Navigate blocks (latest, by height, by hash)
- Decode coinbase scriptSig: BIP34 height, pool tags, THE state_root, AuxPoW
- Decode DASH DIP3/DIP4 CbTx coinbase payload (height, MN-list / quorum roots)
- Trace coinbase payouts (PPLNS outputs, donation, OP_RETURN ref_hash)
- Highlight blocks found by p2pool/c2pool (via coinbase structure detection)
- DOGE merged mining: show aux blocks and their parent LTC block
- Auto-refresh dashboard with recent blocks
- REST API + simple HTML UI

Usage:
    # Auto-detect the coin from the daemon:
    python3 explorer.py --rpc-host 127.0.0.1 --rpc-port 9998 \
                        --rpc-user user --rpc-pass pass [--web-port 8888]

    # Or name the coin explicitly:
    python3 explorer.py --coin dash --rpc-host 127.0.0.1 --rpc-port 9998 \
                        --rpc-user user --rpc-pass pass

    # Against a running c2pool node's explorer API:
    python3 explorer.py --coin dash --c2pool http://127.0.0.1:8080/api/explorer

    # Back-compat: legacy LTC + DOGE two-chain mode (unchanged defaults):
    python3 explorer.py [--ltc-host H --ltc-port P] [--doge-host H --doge-port P]

Requires: Python 3.8+, no external dependencies (uses only stdlib).
"""

import argparse
import hashlib
import http.server
import json
import os
import struct
import sys
import threading
import time
import traceback
import urllib.request
import urllib.error
from base64 import b64encode
from collections import OrderedDict
from datetime import datetime, timezone
from functools import lru_cache
from html import escape

# ============================================================================
# COIN PROFILES — data-driven per-coin configuration.
#
# The explorer is coin-generic: it auto-detects which coin a daemon / c2pool
# node speaks and looks the coin up here.  Each profile carries everything the
# decoders and UI need; adding a coin is a matter of adding a table entry.
#
# Fields:
#   name          human-readable coin name
#   unit          ticker used for amount labels
#   algo          PoW algorithm label (display only)
#   networks      per-network address version bytes + bech32 hrp
#                   p2pkh / p2sh : base58 version byte (int)
#                   hrp          : bech32 human-readable part, or None
#   blockchair    per-network external explorer base URL (or None)
#   subversion    lowercase tokens matched against getnetworkinfo.subversion
#   symbols       /web/currency_info "symbol" values that map to this coin
#   genesis       per-network genesis block hash (secondary auto-detect signal)
#   merged_parent parent coin id for AuxPoW merged-mining children (e.g. doge)
#   coinbase      coinbase-decode hook name ("dash" enables DIP4 CbTx decode)
#   completeness  "full" | "basic" | "stub" (reported to operators)
# ============================================================================

COIN_PROFILES = {
    "dash": {
        "name": "Dash", "unit": "DASH", "algo": "X11",
        "networks": {
            "mainnet": {"p2pkh": 0x4c, "p2sh": 0x10, "hrp": None},  # X..., 7...
            "testnet": {"p2pkh": 0x8c, "p2sh": 0x13, "hrp": None},  # y...
            "regtest": {"p2pkh": 0x8c, "p2sh": 0x13, "hrp": None},
            "devnet":  {"p2pkh": 0x8c, "p2sh": 0x13, "hrp": None},
        },
        "blockchair": {"mainnet": "https://blockchair.com/dash", "testnet": None},
        "subversion": ["dash core", "dashcore"],
        "symbols": ["dash"],
        "genesis": {
            "mainnet": "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6",
            "testnet": "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2e",
        },
        "coinbase": "dash",
        "completeness": "full",
    },
    "ltc": {
        "name": "Litecoin", "unit": "LTC", "algo": "scrypt",
        "networks": {
            "mainnet": {"p2pkh": 0x30, "p2sh": 0x32, "hrp": "ltc"},
            "testnet": {"p2pkh": 0x6f, "p2sh": 0x3a, "hrp": "tltc"},
            "regtest": {"p2pkh": 0x6f, "p2sh": 0x3a, "hrp": "rltc"},
        },
        "blockchair": {
            "mainnet": "https://blockchair.com/litecoin",
            "testnet": "https://blockchair.com/litecoin/testnet",
        },
        "subversion": ["litecoin"],
        "symbols": ["ltc"],
        "genesis": {
            "mainnet": "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2",
            "testnet": "4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0",
        },
        "merged_children": ["doge"],
        "coinbase": "generic",
        "completeness": "full",
    },
    "doge": {
        "name": "Dogecoin", "unit": "DOGE", "algo": "scrypt (AuxPoW)",
        "networks": {
            "mainnet": {"p2pkh": 0x1e, "p2sh": 0x16, "hrp": None},
            "testnet": {"p2pkh": 0x71, "p2sh": 0xc4, "hrp": None},
            "regtest": {"p2pkh": 0x6f, "p2sh": 0xc4, "hrp": None},
        },
        "blockchair": {"mainnet": "https://blockchair.com/dogecoin",
                       "testnet": "https://blockchair.com/dogecoin"},
        "subversion": ["shibetoshi", "dogecoin", "luckycoin"],
        "symbols": ["doge"],
        "genesis": {
            "mainnet": "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691",
            "testnet": "bb0a78264637406b6360aad926284d544d7049f45189db5664f3c4d07350559e",
        },
        "merged_parent": "ltc",
        "coinbase": "generic",
        "completeness": "full",
    },
    "btc": {
        "name": "Bitcoin", "unit": "BTC", "algo": "sha256d",
        "networks": {
            "mainnet": {"p2pkh": 0x00, "p2sh": 0x05, "hrp": "bc"},
            "testnet": {"p2pkh": 0x6f, "p2sh": 0xc4, "hrp": "tb"},
            "regtest": {"p2pkh": 0x6f, "p2sh": 0xc4, "hrp": "bcrt"},
        },
        "blockchair": {
            "mainnet": "https://blockchair.com/bitcoin",
            "testnet": "https://blockchair.com/bitcoin/testnet",
        },
        "subversion": ["satoshi"],
        "symbols": ["btc"],
        "genesis": {
            "mainnet": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            "testnet": "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        },
        "coinbase": "generic",
        "completeness": "full",
    },
    "dgb": {
        "name": "DigiByte", "unit": "DGB", "algo": "multi (sha256d/scrypt/skein/qubit/odo)",
        "networks": {
            "mainnet": {"p2pkh": 0x1e, "p2sh": 0x3f, "hrp": "dgb"},   # D..., S...
            "testnet": {"p2pkh": 0x7e, "p2sh": 0x8c, "hrp": "dgbt"},
        },
        "blockchair": {"mainnet": "https://blockchair.com/digibyte", "testnet": None},
        "subversion": ["digibyte"],
        "symbols": ["dgb"],
        "genesis": {
            "mainnet": "7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496",
        },
        "coinbase": "generic",
        "completeness": "basic",  # TODO: per-block multi-algo detection
    },
    "bch": {
        "name": "Bitcoin Cash", "unit": "BCH", "algo": "sha256d",
        "networks": {
            # BCH default addresses are cashaddr; base58 legacy versions match BTC.
            "mainnet": {"p2pkh": 0x00, "p2sh": 0x05, "hrp": None},
            "testnet": {"p2pkh": 0x6f, "p2sh": 0xc4, "hrp": None},
            "regtest": {"p2pkh": 0x6f, "p2sh": 0xc4, "hrp": None},
        },
        "blockchair": {
            "mainnet": "https://blockchair.com/bitcoin-cash",
            "testnet": None,
        },
        "subversion": ["bitcoin cash", "bchn", "bch unlimited", "bitcoin abc"],
        "symbols": ["bch"],
        "genesis": {
            "mainnet": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        },
        "coinbase": "generic",
        "completeness": "basic",  # TODO: cashaddr encoding
    },
}

# Aliases accepted on the --coin CLI flag.
COIN_ALIASES = {
    "litecoin": "ltc", "dogecoin": "doge", "bitcoin": "btc",
    "digibyte": "dgb", "bitcoincash": "bch", "bitcoin-cash": "bch",
    "bcash": "bch",
}


def resolve_coin_id(name):
    """Normalize a user-supplied coin name to a profile key, or None."""
    if not name:
        return None
    key = name.strip().lower()
    if key in COIN_PROFILES:
        return key
    return COIN_ALIASES.get(key)


def network_from_chain(profile, chain_str):
    """Map a getblockchaininfo 'chain' string to a profile network key."""
    nets = profile.get("networks", {})
    c = (chain_str or "").lower()
    if c in ("main", "mainnet", ""):
        return "mainnet"
    if c.startswith("regtest"):
        return "regtest" if "regtest" in nets else "testnet"
    if c.startswith("devnet"):
        return "devnet" if "devnet" in nets else "testnet"
    # test, testnet, testnet4, testnet4alpha, ...
    return "testnet" if "testnet" in nets else "mainnet"


def addr_versions(profile, network):
    """Return the {p2pkh, p2sh, hrp} address-version dict for a network."""
    nets = profile.get("networks", {})
    return nets.get(network) or nets.get("mainnet") or {"p2pkh": 0x00, "p2sh": 0x05, "hrp": None}


# ============================================================================
# Bech32 encoding (BIP173/BIP350) — needed for P2WPKH address display
# when the daemon doesn't decode cross-chain scripts (e.g., DOGE daemon
# can't decode LTC bech32 addresses in parent AuxPoW transactions).
# ============================================================================

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

def _bech32m_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 0x2bc830a3
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, witver, witprog):
    """Encode a segwit address (BIP173 bech32 for v0, BIP350 bech32m for v1+)."""
    data = [witver] + _convertbits(witprog, 8, 5)
    if witver == 0:
        checksum = _bech32_create_checksum(hrp, data)
    else:
        checksum = _bech32m_create_checksum(hrp, data)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)

def _hash160(data):
    """RIPEMD160(SHA256(data)) — standard Bitcoin hash160."""
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()

def _base58check_encode(version, payload):
    """Encode version byte + payload as a Base58Check string."""
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    data = bytes([version]) + payload
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    num = int.from_bytes(data + checksum, "big")
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(ALPHABET[rem])
    # Leading zeros
    for byte in data + checksum:
        if byte == 0:
            result.append(ALPHABET[0])
        else:
            break
    return "".join(reversed(result))


def script_to_address(hex_script, addr):
    """Decode a scriptPubKey hex to a human-readable address.

    `addr` is a per-network version dict {"p2pkh":int, "p2sh":int, "hrp":str|None}.
    Supports P2PKH, P2SH, P2WPKH, P2WSH, P2TR, and P2PK.
    Returns None if the script format is not recognized.
    """
    if not addr:
        return None
    try:
        s = bytes.fromhex(hex_script)
    except ValueError:
        return None
    hrp = addr.get("hrp")

    # P2WPKH: OP_0 PUSH_20 <20 bytes>
    if len(s) == 22 and s[0] == 0x00 and s[1] == 0x14:
        return bech32_encode(hrp, 0, list(s[2:])) if hrp else None

    # P2WSH: OP_0 PUSH_32 <32 bytes>
    if len(s) == 34 and s[0] == 0x00 and s[1] == 0x20:
        return bech32_encode(hrp, 0, list(s[2:])) if hrp else None

    # P2TR: OP_1 PUSH_32 <32 bytes> (BIP341 Taproot)
    if len(s) == 34 and s[0] == 0x51 and s[1] == 0x20:
        return bech32_encode(hrp, 1, list(s[2:])) if hrp else None

    # P2PKH: OP_DUP OP_HASH160 PUSH_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if len(s) == 25 and s[0] == 0x76 and s[1] == 0xa9 and s[2] == 0x14 and s[23] == 0x88 and s[24] == 0xac:
        return _base58check_encode(addr["p2pkh"], s[3:23])

    # P2SH: OP_HASH160 PUSH_20 <20 bytes> OP_EQUAL
    if len(s) == 23 and s[0] == 0xa9 and s[1] == 0x14 and s[22] == 0x87:
        return _base58check_encode(addr["p2sh"], s[2:22])

    # P2PK: PUSH <pubkey> OP_CHECKSIG — uncompressed (65 bytes) or compressed (33 bytes)
    if len(s) in (35, 67) and s[-1] == 0xac and s[0] == len(s) - 2:
        pubkey = s[1:-1]
        return _base58check_encode(addr["p2pkh"], _hash160(pubkey))

    return None


# ============================================================================
# RPC Client
# ============================================================================

class RpcClient:
    """Minimal JSON-RPC client for Bitcoin-derived daemons."""

    def __init__(self, host, port, user, password, label=""):
        self.url = f"http://{host}:{port}/"
        self.auth = b64encode(f"{user}:{password}".encode()).decode()
        self.label = label
        self._id = 0

    def call(self, method, *params, timeout=10):
        self._id += 1
        payload = json.dumps({
            "jsonrpc": "1.0",
            "id": self._id,
            "method": method,
            "params": list(params),
        }).encode()
        req = urllib.request.Request(
            self.url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {self.auth}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
                if data.get("error"):
                    raise RuntimeError(f"RPC {method}: {data['error']}")
                return data["result"]
        except urllib.error.URLError as e:
            raise ConnectionError(f"[{self.label}] RPC {method} failed: {e}")

    def is_alive(self):
        try:
            self.call("getblockchaininfo", timeout=3)
            return True
        except Exception:
            return False

    def detect_profile(self):
        """Auto-detect coin id from getnetworkinfo.subversion, then genesis hash.
        Returns (coin_id, network) or (None, None)."""
        subver = ""
        try:
            subver = (self.call("getnetworkinfo", timeout=5).get("subversion", "") or "").lower()
        except Exception:
            pass
        chain_str = ""
        try:
            chain_str = self.call("getblockchaininfo", timeout=5).get("chain", "")
        except Exception:
            pass

        # 1) subversion token match (e.g. "/Dash Core:20.1.1/")
        if subver:
            for cid, prof in COIN_PROFILES.items():
                for tok in prof.get("subversion", []):
                    if tok in subver:
                        return cid, network_from_chain(prof, chain_str)

        # 2) genesis block hash match (unambiguous per coin/network)
        try:
            genesis = self.call("getblockhash", 0, timeout=5)
        except Exception:
            genesis = None
        if genesis:
            for cid, prof in COIN_PROFILES.items():
                for net, gh in prof.get("genesis", {}).items():
                    if gh == genesis:
                        return cid, net
        return None, None


class C2PoolClient:
    """Client adapter for c2pool's explorer REST API."""

    def __init__(self, base_url, chain):
        self.base_url = base_url.rstrip('/')
        self.chain = chain  # coin id, e.g. "dash", "ltc", "doge"
        self.url = base_url  # for status display
        self.label = f"c2pool-{chain}"

    def call(self, method, *args, timeout=10):
        if method == "getblockchaininfo":
            return self._get(f"/getblockchaininfo?chain={self.chain}", timeout)
        elif method == "getblockhash":
            return self._get(f"/getblockhash?height={args[0]}&chain={self.chain}", timeout)["result"]
        elif method == "getblock":
            return self._get(f"/getblock?hash={args[0]}&chain={self.chain}", timeout)
        elif method == "getmempoolinfo":
            return self._get(f"/getmempoolinfo?chain={self.chain}", timeout)
        elif method == "getrawmempool":
            verbose = args[0] if args else False
            limit = args[1] if len(args) > 1 else 500
            return self._get(f"/getrawmempool?chain={self.chain}&verbose={'true' if verbose else 'false'}&limit={limit}", timeout)
        elif method == "getmempoolentry":
            return self._get(f"/getmempoolentry?txid={args[0]}&chain={self.chain}", timeout)
        else:
            raise ValueError(f"Unknown method: {method}")

    def _get(self, path, timeout=10):
        url = self.base_url + path
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    def is_alive(self):
        try:
            self.call("getblockchaininfo", timeout=3)
            return True
        except Exception:
            return False

    def currency_info(self, timeout=5):
        """Fetch the node's /web/currency_info (authoritative coin symbol)."""
        # The explorer API base usually looks like http://host:port/api/explorer;
        # currency_info lives at http://host:port/web/currency_info.
        root = self.base_url
        for suffix in ("/api/explorer", "/api", "/explorer"):
            if root.endswith(suffix):
                root = root[: -len(suffix)]
                break
        try:
            req = urllib.request.Request(root.rstrip("/") + "/web/currency_info")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            return {}


# ============================================================================
# Coinbase Decoder
# ============================================================================

def decode_varint(data, offset):
    """Decode a Bitcoin varint, return (value, new_offset)."""
    b = data[offset]
    if b < 0xfd:
        return b, offset + 1
    elif b == 0xfd:
        return struct.unpack_from("<H", data, offset + 1)[0], offset + 3
    elif b == 0xfe:
        return struct.unpack_from("<I", data, offset + 1)[0], offset + 5
    else:
        return struct.unpack_from("<Q", data, offset + 1)[0], offset + 9


def decode_scriptsig(raw_hex):
    """Decode coinbase scriptSig into structured components (coin-agnostic)."""
    data = bytes.fromhex(raw_hex)
    result = {
        "raw_hex": raw_hex,
        "length": len(data),
        "components": [],
    }

    pos = 0

    # BIP34 height: first push is the block height
    if pos < len(data):
        push_len = data[pos]
        pos += 1
        if push_len <= 8 and pos + push_len <= len(data):
            height_bytes = data[pos:pos + push_len]
            height = int.from_bytes(height_bytes, "little")
            result["bip34_height"] = height
            result["components"].append({"type": "BIP34 height", "value": height})
            pos += push_len

    # Scan remaining bytes for known patterns
    remaining = data[pos:]
    remaining_hex = remaining.hex()

    # AuxPoW commitment: starts with fabe6d6d (magic bytes)
    auxpow_marker = "fabe6d6d"
    auxpow_idx = remaining_hex.find(auxpow_marker)
    auxpow_end = 0  # byte offset where AuxPoW ends (0 = no AuxPoW)
    if auxpow_idx >= 0:
        byte_offset = auxpow_idx // 2
        # AuxPoW: 4 magic + 32 hash + 4 merkle_size + 4 merkle_nonce = 44 bytes
        if byte_offset + 44 <= len(remaining):
            aux_hash = remaining[byte_offset + 4:byte_offset + 36].hex()
            merkle_size = struct.unpack_from("<I", remaining, byte_offset + 36)[0]
            merkle_nonce = struct.unpack_from("<I", remaining, byte_offset + 40)[0]
            result["components"].append({
                "type": "AuxPoW commitment",
                "aux_hash": aux_hash,
                "merkle_size": merkle_size,
                "merkle_nonce": merkle_nonce,
            })
            result["has_auxpow"] = True
            auxpow_end = byte_offset + 44

    # Pool tags: search AFTER AuxPoW commitment (binary AuxPoW data contains
    # random bytes that produce false-positive ASCII matches like "ZsEvYwy").
    # p2pool V36 scriptSig = [BIP34 height][push mm_data] with NO pool tag,
    # so the tag search area may be empty — structural detection handles that.
    tag_search = remaining[auxpow_end:]
    known_tags = [
        b"/c2pool/",
        b"/P2Pool v36/", b"/P2Pool-Scrypt/", b"/P2Pool/", b"/p2pool/",
        b"c2pool", b"p2pool",
        b"/Stratum/", b"/bfgminer/", b"/cgminer/",
        b"/hashpoolpro.com/", b"hashpoolpro", b"PoolMine",
        b"/ViaBTC/", b"/AntPool/", b"/F2Pool/", b"/Poolin/",
        b"/SlushPool/", b"/BTC.com/", b"/Foundry/",
        b"Miningcore", b"/Miningcore/",
        b"/LitecoinPool/", b"/prohashing/", b"/NiceHash/",
        b"/Mining-Dutch/", b"/zpool/", b"/zergpool/",
        b"/multipool/", b"/CKPool/", b"/Eligius/",
        b"/STARTER/", b"NovaBlock",
    ]
    for tag in known_tags:
        idx = tag_search.find(tag)
        if idx >= 0:
            result["components"].append({
                "type": "pool_tag",
                "value": tag.decode("ascii", errors="replace"),
                "offset": pos + auxpow_end + idx,
            })
            result["pool_tag"] = tag.decode("ascii", errors="replace")
            break  # use first match

    # Fallback: extract any /tag/ pattern or bare CamelCase word from ASCII
    # Only search post-AuxPoW bytes to avoid false positives from binary data.
    if not result.get("pool_tag"):
        import re
        ascii_str = tag_search.decode("ascii", errors="ignore")
        # Try /tag/ pattern first
        m = re.search(r'/([A-Za-z0-9._-]{3,30})/', ascii_str)
        if m:
            tag_val = "/" + m.group(1) + "/"
            result["components"].append({"type": "pool_tag", "value": tag_val, "offset": pos + auxpow_end + m.start()})
            result["pool_tag"] = tag_val
        else:
            # Try bare CamelCase or known-looking words (e.g. "Miningcore", "NovaBlock")
            m = re.search(r'([A-Z][a-z]+(?:[A-Z][a-z]+)+)', ascii_str)
            if m:
                tag_val = m.group(1)
                result["components"].append({"type": "pool_tag", "value": tag_val, "offset": pos + auxpow_end + m.start()})
                result["pool_tag"] = tag_val

    # NOTE: AuxPoW (fabe6d6d) alone does NOT mean p2pool — any merged-mining
    # pool uses it.  Structural p2pool detection is deferred to _process_block
    # where we can check for p2pool-specific outputs (combined donation, ref_hash).

    # If still no tag found, mark as UNKNOWN
    if not result.get("pool_tag"):
        result["pool_tag"] = "UNKNOWN"
        result["components"].append({"type": "pool_tag", "value": "UNKNOWN", "offset": 0})

    # THE state_root: 32 bytes after pool tag (if present)
    # Look for 32 non-zero bytes after known tags
    tag_end = -1
    for tag in [b"/c2pool/", b"/P2Pool/"]:
        idx = remaining.find(tag)
        if idx >= 0:
            tag_end = idx + len(tag)
            break

    if tag_end >= 0 and tag_end + 32 <= len(remaining):
        candidate = remaining[tag_end:tag_end + 32]
        if any(b != 0 for b in candidate):
            result["components"].append({
                "type": "THE state_root",
                "value": candidate.hex(),
                "offset": pos + tag_end,
            })
            result["the_state_root"] = candidate.hex()

    # Extract readable ASCII from post-AuxPoW bytes only (binary AuxPoW data
    # produces misleading ASCII fragments)
    ascii_parts = []
    current = []
    for b in tag_search:
        if 0x20 <= b <= 0x7e:
            current.append(chr(b))
        else:
            if len(current) >= 3:
                ascii_parts.append("".join(current))
            current = []
    if len(current) >= 3:
        ascii_parts.append("".join(current))
    if ascii_parts:
        result["ascii_strings"] = ascii_parts

    return result


def decode_dip4_cbtx(payload_hex):
    """Decode a Dash DIP3/DIP4 coinbase special-transaction (CbTx) payload.

    Layout (little-endian on the wire; 32-byte roots shown big-endian to match
    dashd RPC):
        uint16  version
        uint32  height
        bytes32 merkleRootMNList
        [v>=2]  bytes32 merkleRootQuorums
        [v>=3]  varint  bestCLHeightDiff
                bytes96 bestCLSignature
                int64   creditPoolBalance (in duffs)
    Returns a dict or None.
    """
    try:
        b = bytes.fromhex(payload_hex)
    except (ValueError, TypeError):
        return None
    if len(b) < 38:  # 2 + 4 + 32
        return None
    off = 0
    ver = int.from_bytes(b[off:off + 2], "little"); off += 2
    height = int.from_bytes(b[off:off + 4], "little"); off += 4
    out = {
        "version": ver,
        "height": height,
        "merkleRootMNList": b[off:off + 32][::-1].hex(),
    }
    off += 32
    if ver >= 2 and off + 32 <= len(b):
        out["merkleRootQuorums"] = b[off:off + 32][::-1].hex()
        off += 32
    if ver >= 3:
        try:
            diff, off = decode_varint(b, off)
            out["bestCLHeightDiff"] = diff
            if off + 96 <= len(b):
                out["bestCLSignature"] = b[off:off + 96].hex()
                off += 96
            if off + 8 <= len(b):
                out["creditPoolBalance"] = int.from_bytes(b[off:off + 8], "little", signed=True) / 1e8
        except Exception:
            pass
    return out


# Known cross-coin p2pool/c2pool donation script fingerprints (see
# src/core/donation.hpp — byte-identical across btc/bch/dgb/ltc/dash).
COMBINED_DONATION_H160 = "8c6272621d89e8fa526dd86acff60c7136be8e85"      # v36 P2SH
OLD_DONATION_PUBKEY = "04ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b"


def _decode_multisig(hex_script, addr):
    """Extract addresses from a P2MS (bare multisig) scriptPubKey.
    Returns (m, n, [addresses]) or None."""
    s = bytes.fromhex(hex_script)
    if len(s) < 3 or s[-1] != 0xae:  # OP_CHECKMULTISIG
        return None
    m = s[0] - 0x50  # OP_1..OP_16 → 1..16
    n = s[-2] - 0x50
    if not (1 <= m <= 16 and 1 <= n <= 16 and m <= n):
        return None
    pos = 1
    addrs = []
    for _ in range(n):
        if pos >= len(s) - 2:
            break
        key_len = s[pos]
        pos += 1
        if key_len not in (33, 65) or pos + key_len > len(s) - 2:
            break
        pubkey = s[pos:pos + key_len]
        addr_str = _base58check_encode(addr.get("p2pkh", 0x00), _hash160(pubkey))
        addrs.append(addr_str)
        pos += key_len
    if len(addrs) == n:
        return m, n, addrs
    return None


def _safe_ascii(raw_bytes):
    """Decode bytes to ASCII, replacing non-printable chars with dots."""
    return "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in raw_bytes)


def decode_outputs(vout_list, addr):
    """Decode transaction outputs into structured components.

    `addr` is a per-network version dict {"p2pkh","p2sh","hrp"}.
    """
    outputs = []
    for i, vout in enumerate(vout_list):
        out = {
            "index": i,
            "value_btc": vout.get("value", 0),
            "value_sat": int(vout.get("value", 0) * 1e8 + 0.5),
        }
        spk = vout.get("scriptPubKey", {})
        out["type"] = spk.get("type", "unknown")
        out["asm"] = spk.get("asm", "")
        out["hex"] = spk.get("hex", "")
        addresses = spk.get("addresses", spk.get("address", []))
        if isinstance(addresses, str):
            addresses = [addresses]
        # Fallback: decode address from raw script when daemon doesn't
        # provide it (e.g., DOGE daemon can't decode LTC bech32 in AuxPoW)
        if not addresses and out["hex"]:
            decoded = script_to_address(out["hex"], addr)
            if decoded:
                addresses = [decoded]
        # P2MS (bare multisig): extract all pubkey addresses
        if not addresses and out["hex"]:
            ms = _decode_multisig(out["hex"], addr)
            if ms:
                m, n, ms_addrs = ms
                addresses = ms_addrs
                out["type"] = f"multisig ({m}-of-{n})"
        out["addresses"] = addresses

        # Detect OP_RETURN
        if out["asm"].startswith("OP_RETURN") or (out["hex"] and out["hex"][:2] == "6a"):
            out["is_op_return"] = True
            hex_data = out["hex"]
            if len(hex_data) >= 4 and hex_data[:4] == "6a28":
                # p2pool ref_hash OP_RETURN: 6a28 + ref_hash(32) + nonce(8)
                if len(hex_data) >= 84:
                    out["ref_hash"] = hex_data[4:68]
                    out["last_txout_nonce"] = hex_data[68:84]
                    out["type"] = "p2pool_ref"
            # Decode OP_RETURN payload as ASCII (skip opcode + push bytes)
            if not out.get("ref_hash"):
                try:
                    raw = bytes.fromhex(hex_data)
                    # Skip OP_RETURN (0x6a) + optional push-length byte(s)
                    payload = raw[1:]
                    if payload and payload[0] < 0x4c:
                        payload = payload[1:]  # single-byte push
                    elif payload and payload[0] == 0x4c:
                        payload = payload[2:]  # OP_PUSHDATA1
                    ascii_str = _safe_ascii(payload)
                    # Only store if it has meaningful printable content
                    printable = sum(1 for c in ascii_str if c != '.')
                    if printable >= 3:
                        out["op_return_ascii"] = ascii_str
                except Exception:
                    pass

        # Detect combined donation script (V36 P2SH a914 <h160> 87)
        if out["hex"].startswith("a914") and out["hex"].endswith("87") and len(out["hex"]) == 46:
            if COMBINED_DONATION_H160 in out["hex"]:
                out["is_donation"] = True
                out["donation_type"] = "p2pool_combined"
        # Detect legacy P2PK donation (pre-v36, shared across coins)
        if OLD_DONATION_PUBKEY in out["hex"]:
            out["is_donation"] = True
            out["donation_type"] = "p2pool_old"

        outputs.append(out)
    return outputs


# ============================================================================
# Block Cache
# ============================================================================

class BlockCache:
    """LRU cache for decoded blocks."""

    def __init__(self, maxsize=500):
        self._cache = OrderedDict()
        self._maxsize = maxsize
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
        return None

    def put(self, key, value):
        with self._lock:
            self._cache[key] = value
            self._cache.move_to_end(key)
            while len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)


# ============================================================================
# Explorer Engine
# ============================================================================

class ExplorerEngine:
    """Core explorer logic: fetch, decode, and serve block data (coin-generic).

    Holds an ordered map of active coins (coin_id -> {rpc, profile}); the first
    registered coin is the primary.  The `chain` argument used throughout the
    renderers and the HTTP API is a coin id (e.g. "dash", "ltc", "doge").
    """

    def __init__(self, coins, primary=None):
        # coins: OrderedDict coin_id -> {"rpc": client, "profile": dict}
        self.coins = OrderedDict(coins)
        self.primary = primary or (next(iter(self.coins)) if self.coins else None)
        self.cache = BlockCache()
        self.found_blocks = []  # blocks found by p2pool/c2pool
        self._scan_lock = threading.Lock()
        self._tip = {cid: 0 for cid in self.coins}
        self._tip_lock = threading.Lock()
        self._sse_clients = []  # list of (queue, chain_filter)
        self._sse_lock = threading.Lock()
        self._poller_running = False
        self._network_cache = {}  # coin_id -> network key

    # --- coin/profile helpers ------------------------------------------------

    def has_coin(self, coin_id):
        return coin_id in self.coins

    def coin_or_primary(self, coin_id):
        return coin_id if coin_id in self.coins else self.primary

    def rpc(self, coin_id):
        entry = self.coins.get(coin_id) or self.coins.get(self.primary)
        return entry["rpc"] if entry else None

    def profile(self, coin_id):
        entry = self.coins.get(coin_id)
        if entry:
            return entry["profile"]
        return COIN_PROFILES.get(coin_id, COIN_PROFILES.get(self.primary, {}))

    def network(self, coin_id):
        """Detected network key for a coin (cached), e.g. 'mainnet'/'testnet'."""
        if coin_id in self._network_cache:
            return self._network_cache[coin_id]
        prof = self.profile(coin_id)
        info = self.get_chain_info(coin_id)
        net = network_from_chain(prof, info.get("chain", "")) if "error" not in info else "mainnet"
        self._network_cache[coin_id] = net
        return net

    def addr(self, coin_id):
        """Address-version dict for a coin's detected network."""
        return addr_versions(self.profile(coin_id), self.network(coin_id))

    def is_testnet(self, coin_id):
        return self.network(coin_id) != "mainnet"

    def unit(self, coin_id):
        return self.profile(coin_id).get("unit", coin_id.upper())

    def coin_label(self, coin_id):
        """Human-readable label, e.g. 'Dash' or 'Litecoin Testnet'."""
        prof = self.profile(coin_id)
        name = prof.get("name", coin_id.upper())
        return f"{name} Testnet" if self.is_testnet(coin_id) else name

    def chain_label(self, coin_id):
        """Short label for nav/tables, e.g. 'DASH' or 'LTC Testnet'."""
        unit = self.unit(coin_id)
        return f"{unit} Testnet" if self.is_testnet(coin_id) else unit

    def blockchair_base(self, coin_id):
        prof = self.profile(coin_id)
        return (prof.get("blockchair", {}) or {}).get(self.network(coin_id), "")

    def footer_label(self):
        parts = [f"{self.coin_label(cid)}" for cid in self.coins]
        return " + ".join(parts) + " Explorer"

    # --- SSE (Server-Sent Events) block notification ---

    def start_block_poller(self, interval=2):
        """Background thread that polls for new blocks and pushes SSE events."""
        if self._poller_running:
            return
        self._poller_running = True

        def _poll():
            while self._poller_running:
                for chain_id in list(self.coins):
                    rpc = self.rpc(chain_id)
                    if rpc is None:
                        continue
                    try:
                        info = rpc.call("getblockchaininfo", timeout=3)
                        height = info.get("blocks", 0)
                        with self._tip_lock:
                            prev = self._tip.get(chain_id, 0)
                            if height > prev:
                                self._tip[chain_id] = height
                                if prev > 0:  # skip initial seed
                                    self._broadcast_new_block(chain_id, height, info.get("bestblockhash", ""))
                    except Exception:
                        pass
                time.sleep(interval)

        t = threading.Thread(target=_poll, daemon=True, name="block-poller")
        t.start()

    def _broadcast_new_block(self, chain, height, bhash):
        """Send SSE event to all connected clients for this chain."""
        import queue as _q
        event_data = json.dumps({"chain": chain, "height": height, "hash": bhash})
        msg = f"event: newblock\ndata: {event_data}\n\n"
        with self._sse_lock:
            dead = []
            for i, (q, chain_filter) in enumerate(self._sse_clients):
                if chain_filter and chain_filter != chain:
                    continue
                try:
                    q.put_nowait(msg)
                except _q.Full:
                    dead.append(i)
            for i in reversed(dead):
                self._sse_clients.pop(i)

    def register_sse_client(self, chain_filter=None):
        """Register a new SSE client, returns a queue to read events from."""
        import queue as _q
        q = _q.Queue(maxsize=50)
        with self._sse_lock:
            self._sse_clients.append((q, chain_filter))
        return q

    def unregister_sse_client(self, q):
        with self._sse_lock:
            self._sse_clients = [(qq, cf) for qq, cf in self._sse_clients if qq is not q]

    def get_chain_info(self, chain=None):
        rpc = self.rpc(chain)
        if rpc is None:
            return {"error": "no such coin"}
        try:
            return rpc.call("getblockchaininfo")
        except Exception as e:
            return {"error": str(e)}

    # Back-compat shim: some callers used chain_key() expecting a "coin_net" key.
    def chain_key(self, chain=None):
        cid = self.coin_or_primary(chain)
        return f"{cid}_{self.network(cid)}"

    def get_block(self, height_or_hash, chain=None):
        """Fetch and decode a block by height or hash."""
        chain = self.coin_or_primary(chain)
        rpc = self.rpc(chain)
        cache_key = f"{chain}:{height_or_hash}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        # Fallback: hardcoded seed blocks (LTC/DOGE only; outside embedded depth)
        seed = self.SEED_BLOCK_DETAILS.get(cache_key)
        if seed:
            self.cache.put(cache_key, seed)
            return seed

        try:
            if isinstance(height_or_hash, int) or height_or_hash.isdigit():
                height = int(height_or_hash)
                bhash = rpc.call("getblockhash", height)
            else:
                bhash = height_or_hash

            block = rpc.call("getblock", bhash, 2)  # verbosity=2: include decoded tx
        except Exception as e:
            return {"error": str(e)}

        prof = self.profile(chain)
        addr = self.addr(chain)

        # Decode coinbase
        if block.get("tx"):
            coinbase_tx = block["tx"][0]
            vin = coinbase_tx.get("vin", [{}])
            if vin and "coinbase" in vin[0]:
                block["_coinbase_decoded"] = decode_scriptsig(vin[0]["coinbase"])
                block["_outputs_decoded"] = decode_outputs(coinbase_tx.get("vout", []), addr)
            else:
                block["_coinbase_decoded"] = {"error": "not a coinbase"}
                block["_outputs_decoded"] = []

            # DASH DIP3/DIP4 CbTx: prefer daemon-decoded 'cbTx', else parse raw payload.
            if prof.get("coinbase") == "dash":
                cbtx = coinbase_tx.get("cbTx")
                if not cbtx:
                    payload = coinbase_tx.get("extraPayload") or coinbase_tx.get("payload")
                    if payload:
                        cbtx = decode_dip4_cbtx(payload)
                if cbtx:
                    block["_cbtx"] = cbtx
                    block["_is_special_cb"] = True
                elif coinbase_tx.get("type", 0) == 5:
                    block["_is_special_cb"] = True

        # Structural p2pool/c2pool detection (coin-agnostic; no AuxPoW required).
        cb = block.get("_coinbase_decoded", {})
        tag = cb.get("pool_tag", "")
        outs = block.get("_outputs_decoded", [])
        has_combined = any(o.get("donation_type") == "p2pool_combined" for o in outs)
        has_ref = any(o.get("type") == "p2pool_ref" for o in outs)

        if has_combined or has_ref:
            cb["is_pool_block"] = True
            if cb.get("the_state_root") or tag in ("c2pool", "/c2pool/"):
                cb["pool_tag"] = "/c2pool/"
            elif "v36" in tag.lower():
                cb["pool_tag"] = "/P2Pool v36/"
            elif "p2pool" in tag.lower():
                cb["pool_tag"] = "/P2Pool v36/"  # combined/ref present => v36
            elif not tag or tag == "UNKNOWN":
                cb["pool_tag"] = "/P2Pool v36/"
                cb.setdefault("components", []).append(
                    {"type": "pool_tag", "value": "/P2Pool v36/ (structural)", "offset": 0})
        elif tag and "p2pool" in tag.lower() and tag not in ("c2pool", "/c2pool/"):
            # Tag says p2pool but no combined/ref output → legacy V35.
            if "v36" not in tag.lower():
                cb["pool_tag"] = "P2Pool v35"

        # Merged-mining parent (e.g. DOGE child → LTC parent) coinbase decode.
        parent_id = prof.get("merged_parent")
        auxpow = block.get("auxpow")
        if auxpow and parent_id:
            parent_prof = COIN_PROFILES.get(parent_id, prof)
            parent_addr = addr_versions(parent_prof, self.network(chain))
            parent_tx = auxpow.get("tx", {})
            parent_vin = parent_tx.get("vin", [{}]) if isinstance(parent_tx, dict) else [{}]
            if parent_vin and "coinbase" in parent_vin[0]:
                block["_parent_coinbase_decoded"] = decode_scriptsig(parent_vin[0]["coinbase"])
                parent_vout = parent_tx.get("vout", []) if isinstance(parent_tx, dict) else []
                block["_parent_outputs_decoded"] = decode_outputs(parent_vout, parent_addr)
                # Propagate parent's pool tag / THE state_root to the merged block.
                # c2pool blocks: parent coinbase carries /c2pool/ + THE state_root,
                # but the child coinbase uses canonical /P2Pool v36/ text.
                ptag = block["_parent_coinbase_decoded"].get("pool_tag", "")
                own_tag = block["_coinbase_decoded"].get("pool_tag", "")
                pthe = block["_parent_coinbase_decoded"].get("the_state_root", "")
                if ptag in ("c2pool", "/c2pool/") or pthe:
                    block["_coinbase_decoded"]["pool_tag"] = "/c2pool/"
                    block["_coinbase_decoded"]["has_auxpow"] = True
                    if pthe:
                        block["_coinbase_decoded"]["the_state_root"] = pthe
                elif ptag and ptag != "UNKNOWN" and (not own_tag or own_tag == "UNKNOWN"):
                    parent_outs = block.get("_parent_outputs_decoded", [])
                    parent_has_combined = any(o.get("donation_type") == "p2pool_combined" for o in parent_outs)
                    parent_has_ref = any(o.get("type") == "p2pool_ref" for o in parent_outs)
                    if "p2pool" in ptag.lower():
                        if parent_has_combined or parent_has_ref:
                            ptag = "/P2Pool v36/"
                        elif "v36" not in ptag.lower():
                            ptag = "P2Pool v35"
                    block["_coinbase_decoded"]["pool_tag"] = ptag
                    block["_coinbase_decoded"]["has_auxpow"] = True
                elif pthe:
                    block["_coinbase_decoded"]["the_state_root"] = pthe
            block["_auxpow_info"] = {
                "parent_blockhash": auxpow.get("parentblock", "")[:64] if isinstance(auxpow.get("parentblock"), str) else "",
                "parent_txid": parent_tx.get("txid", "") if isinstance(parent_tx, dict) else "",
                "chain_index": auxpow.get("chainindex", 0),
                "index": auxpow.get("index", 0),
                "parent_coin": parent_id,
            }

        # Don't cache tip (it can change)
        chain_info = self.get_chain_info(chain)
        tip_height = chain_info.get("blocks", 0)
        if block.get("height", 0) < tip_height - 2:
            self.cache.put(cache_key, block)

        return block

    def get_recent_blocks(self, count=20, chain=None):
        """Fetch the N most recent blocks."""
        chain = self.coin_or_primary(chain)
        info = self.get_chain_info(chain)
        if "error" in info:
            return [info]
        tip = info["blocks"]
        blocks = []
        for h in range(tip, max(tip - count, -1), -1):
            b = self.get_block(h, chain)
            if "error" not in b:
                blocks.append({
                    "height": b["height"],
                    "hash": b["hash"],
                    "time": b.get("time", 0),
                    "tx_count": len(b.get("tx", [])),
                    "size": b.get("size", 0),
                    "pool_tag": b.get("_coinbase_decoded", {}).get("pool_tag", ""),
                    "has_auxpow": b.get("_coinbase_decoded", {}).get("has_auxpow", False),
                    "the_state_root": b.get("_coinbase_decoded", {}).get("the_state_root", ""),
                })
        return blocks

    # First V36-era pool blocks — always shown so the "Pool Blocks" page is never
    # empty for LTC/DOGE.  Other coins start with an empty (live-scanned) list.
    SEED_POOL_BLOCKS = {
        "ltc": [{
            "chain": "ltc", "height": 3069917,
            "hash": "806a9214cd63dae4b5091b69c1f8e14652ff95fff2bbcb06de6fcdafa76ec6ea",
            "time": 1773145632, "pool_tag": "/c2pool/", "has_auxpow": True,
            "the_state_root": "", "coinbase_value": 625_00000000,
        }],
        "doge": [{
            "chain": "doge", "height": 6135703,
            "hash": "f84500c25a4cce2a08887f29763726bd5ecec7b66fed65a88b181fb0b0ab2383",
            "time": 1774276655, "pool_tag": "/c2pool/", "has_auxpow": False,
            "the_state_root": "", "coinbase_value": 10000_00000000,
        }],
    }

    # ── Full block details for seed blocks so /block?q=... always works ──
    SEED_BLOCK_DETAILS = {
        # ─────────────── LTC #3069917 ───────────────
        "ltc:3069917": {
            "height": 3069917,
            "hash": "806a9214cd63dae4b5091b69c1f8e14652ff95fff2bbcb06de6fcdafa76ec6ea",
            "previousblockhash": "90fc24dad8ccf4cb521af889a03d32a24db1590ef5ea2f66a2297dce8c4c1489",
            "time": 1773145632,
            "difficulty": 105778188,
            "bits": "19283258",
            "nonce": 59985092,
            "merkleroot": "96f1d4f3a83499eab0bec48370a0b5e44ef054f2c7314609c876646bb0d4cd61",
            "size": 58921,
            "tx_count": 166,
            "tx": [{"txid": "528f890b36514977fce03e38e9843bd2d41791d227e5fe841cdd426de3d6e694"}],
            "_coinbase_decoded": {
                "raw_hex": "03ddd72e2cfabe6d6dfe4152f52456b9890a7bf9128648c0561d5dce7fd47e8e849df6c4315e8781c2010000000000000026202d2d204d696e6564206279204879706572446f6e6b65792e636f6d20285765737420555329",
                "length": 82,
                "bip34_height": 3069917,
                "has_auxpow": True,
                "pool_tag": "/c2pool/",
                "the_state_root": "",
                "ascii_strings": ["-- Mined by HyperDonkey.com (West US)"],
                "components": [
                    {"type": "BIP34 height", "value": 3069917},
                    {"type": "AuxPoW commitment", "aux_hash": "fe4152f52456b9890a7bf9128648c0561d5dce7fd47e8e849df6c4315e878100", "merkle_size": 1, "merkle_nonce": 0},
                    {"type": "pool_tag", "value": "/c2pool/", "offset": 48},
                ],
            },
            "_outputs_decoded": [
                {"index": 0,  "value_btc": 0.0,        "value_sat": 0,         "type": "op_return",  "asm": "OP_RETURN aa21a9ed1683273b0f24739675d6076c37c3f084998c2493e889e1399f913802912c22ea", "hex": "6a24aa21a9ed1683273b0f24739675d6076c37c3f084998c2493e889e1399f913802912c22ea", "addresses": [], "is_op_return": True},
                {"index": 1,  "value_btc": 0.00074150, "value_sat": 74150,     "type": "p2sh",       "asm": "", "hex": "a9146cbbb83db91c3a72b761fc5ce1050f8dd87f3fca87", "addresses": ["MHp6697dpCacmGsDpaPGijZyYggAVRaVjD"]},
                {"index": 2,  "value_btc": 0.00081093, "value_sat": 81093,     "type": "p2pkh",      "asm": "", "hex": "76a914218f1b2f0b5b9b6f7484573bb4d09d2e2c45238088ac", "addresses": ["LNHPzjcjb1HX6zMiAZWngBGr4u5UK7KdC4"]},
                {"index": 29, "value_btc": 0.00000014, "value_sat": 14,        "type": "p2pk",       "asm": "", "hex": "4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac", "addresses": ["LeD2fnnDJYZuyt8zgDsZ2oBGmuVcxGKCLd"], "is_donation": True, "donation_type": "p2pool_old"},
                {"index": 30, "value_btc": 0.0,        "value_sat": 0,         "type": "op_return",  "asm": "OP_RETURN 8bd158eb8a5e928fea18613ac741a8a66c3b4058d7e059921c85a07250e02e6d000000002ecd1000", "hex": "6a288bd158eb8a5e928fea18613ac741a8a66c3b4058d7e059921c85a07250e02e6d000000002ecd1000", "addresses": [], "is_op_return": True, "ref_hash": "8bd158eb8a5e928fea18613ac741a8a66c3b4058d7e059921c85a07250e02e6d", "last_txout_nonce": "000000002ecd1000", "type": "p2pool_ref"},
            ],
        },
        # ─────────────── DOGE #6135703 ───────────────
        "doge:6135703": {
            "height": 6135703,
            "hash": "f84500c25a4cce2a08887f29763726bd5ecec7b66fed65a88b181fb0b0ab2383",
            "previousblockhash": "8a8c522e08da9050bda3f161f5a5ae8d7f3dc38aee6de87c89d8b56deccba586",
            "time": 1774276655,
            "difficulty": 26085177.03517223,
            "bits": "1a00a834",
            "nonce": 0,
            "merkleroot": "1fade1ce517047e3415bf6e2d02130718c33925c611a9b19481b7038771a0cde",
            "size": 60350,
            "tx_count": 187,
            "tx": [{"txid": "42ca7cc895ae00b9f83e7b4fd1a2d2e59232d000d105e743a3e54df71e3a815c"}],
            "_coinbase_decoded": {
                "raw_hex": "03979f5d2f5032506f6f6c207633362f",
                "length": 16,
                "bip34_height": 6135703,
                "has_auxpow": True,
                "pool_tag": "/c2pool/",
                "the_state_root": "",
                "ascii_strings": ["/P2Pool v36/"],
                "components": [
                    {"type": "BIP34 height", "value": 6135703},
                    {"type": "pool_tag", "value": "/c2pool/", "offset": 4},
                ],
            },
            "_outputs_decoded": [
                {"index": 0, "value_btc": 8598.59979535, "value_sat": 859859979535, "type": "p2pkh", "asm": "", "hex": "76a914b8089e39a70cf3dd3bf057bf86bf03dc2ea1889a88ac", "addresses": ["DMvBCMCSJZ26qjZ5pneBdYFaXSjJUk5L4G"]},
                {"index": 4, "value_btc": 0.0,           "value_sat": 0,            "type": "nulldata", "asm": "OP_RETURN 7032702d7370622e78797a", "hex": "6a0b7032702d7370622e78797a", "addresses": [], "is_op_return": True, "op_return_ascii": "p2p-spb.xyz"},
                {"index": 5, "value_btc": 1.00000002,    "value_sat": 100000002,    "type": "p2sh",  "asm": "", "hex": "a9148c6272621d89e8fa526dd86acff60c7136be8e8587", "addresses": ["A5EZCT4tUrtoKuvJaWbtVQADzdUKdtsqpr"], "is_donation": True, "donation_type": "p2pool_combined"},
            ],
        },
    }

    # Also index by hash for hash-based lookups
    SEED_BLOCK_DETAILS["ltc:806a9214cd63dae4b5091b69c1f8e14652ff95fff2bbcb06de6fcdafa76ec6ea"] = SEED_BLOCK_DETAILS["ltc:3069917"]
    SEED_BLOCK_DETAILS["doge:f84500c25a4cce2a08887f29763726bd5ecec7b66fed65a88b181fb0b0ab2383"] = SEED_BLOCK_DETAILS["doge:6135703"]

    def scan_for_pool_blocks(self, chain=None, depth=100):
        """Scan recent blocks for p2pool/c2pool coinbase tags."""
        chain = self.coin_or_primary(chain)
        with self._scan_lock:
            info = self.get_chain_info(chain)
            if "error" in info:
                return self.SEED_POOL_BLOCKS.get(chain, [])
            tip = info["blocks"]
            found = []
            for h in range(tip, max(tip - depth, -1), -1):
                b = self.get_block(h, chain)
                if "error" in b:
                    continue
                cb = b.get("_coinbase_decoded", {})
                tag = cb.get("pool_tag", "")
                if tag and ("p2pool" in tag.lower() or "c2pool" in tag.lower()):
                    entry = {
                        "chain": chain,
                        "height": b["height"],
                        "hash": b["hash"],
                        "time": b.get("time", 0),
                        "pool_tag": tag,
                        "has_auxpow": cb.get("has_auxpow", False),
                        "the_state_root": cb.get("the_state_root", ""),
                        "coinbase_value": sum(
                            o.get("value_sat", 0)
                            for o in b.get("_outputs_decoded", [])
                            if not o.get("is_op_return")
                        ),
                    }
                    found.append(entry)
            # Append seed blocks not already in scan
            found_heights = {b["height"] for b in found}
            for seed in self.SEED_POOL_BLOCKS.get(chain, []):
                if seed["height"] not in found_heights:
                    found.append(seed)
            self.found_blocks = found
            return found

    def get_mempool_info(self, chain=None):
        """Get mempool summary statistics. Normalizes daemon response to c2pool format."""
        chain = self.coin_or_primary(chain)
        rpc = self.rpc(chain)
        try:
            raw = rpc.call("getmempoolinfo")
            if isinstance(rpc, C2PoolClient):
                return raw
            # Normalize daemon response to match c2pool explorer API format
            entries = self.get_mempool_entries(chain, verbose=True, limit=10000)
            total_fees = 0
            total_weight = 0
            feerates = []
            oldest_time = 0
            now = int(time.time())
            if isinstance(entries, list):
                for e in entries:
                    total_fees += e.get("fee", 0)
                    total_weight += e.get("weight", 0)
                    fr = e.get("feerate", 0)
                    if fr > 0:
                        feerates.append(fr)
                    t = e.get("time_added", 0)
                    if t > 0 and (oldest_time == 0 or t < oldest_time):
                        oldest_time = t
            feerates.sort()
            # Feerate histogram: [0-1), [1-5), [5-20), [20-100), [100+)
            buckets = [
                {"min_feerate": 0, "max_feerate": 1, "count": 0, "bytes": 0},
                {"min_feerate": 1, "max_feerate": 5, "count": 0, "bytes": 0},
                {"min_feerate": 5, "max_feerate": 20, "count": 0, "bytes": 0},
                {"min_feerate": 20, "max_feerate": 100, "count": 0, "bytes": 0},
                {"min_feerate": 100, "max_feerate": "inf", "count": 0, "bytes": 0},
            ]
            if isinstance(entries, list):
                for e in entries:
                    fr = e.get("feerate", 0)
                    sz = e.get("size", 0)
                    for b in buckets:
                        hi = b["max_feerate"] if isinstance(b["max_feerate"], (int, float)) else 1e9
                        if fr >= b["min_feerate"] and fr < hi:
                            b["count"] += 1
                            b["bytes"] += sz
                            break
            return {
                "size": raw.get("size", 0),
                "bytes": raw.get("bytes", 0),
                "total_weight": total_weight,
                "total_fees": total_fees,
                "fee_known_count": len(feerates),
                "fee_unknown_count": raw.get("size", 0) - len(feerates),
                "min_feerate": feerates[0] if feerates else 0,
                "max_feerate": feerates[-1] if feerates else 0,
                "median_feerate": feerates[len(feerates) // 2] if feerates else 0,
                "avg_feerate": sum(feerates) / len(feerates) if feerates else 0,
                "oldest_age_sec": (now - oldest_time) if oldest_time else 0,
                "fee_histogram": buckets,
            }
        except Exception as e:
            return {"error": str(e)}

    def get_mempool_entries(self, chain=None, verbose=True, limit=100):
        """Get mempool transaction list.  Returns a list of entry dicts."""
        chain = self.coin_or_primary(chain)
        rpc = self.rpc(chain)
        try:
            if isinstance(rpc, C2PoolClient):
                return rpc.call("getrawmempool", verbose, limit)
            if not verbose:
                return rpc.call("getrawmempool", False)
            raw = rpc.call("getrawmempool", True)
            if isinstance(raw, dict):
                entries = []
                now = int(time.time())
                for txid, v in raw.items():
                    vsize = v.get("vsize", 0)
                    weight = v.get("weight", 0)
                    fee_btc = v.get("fee", 0)
                    fee_sat = int(round(fee_btc * 1e8))
                    feerate = fee_sat / vsize if vsize > 0 else 0
                    t = v.get("time", 0)
                    entries.append({
                        "txid": txid,
                        "size": vsize,
                        "weight": weight,
                        "fee": fee_sat,
                        "fee_known": True,
                        "feerate": feerate,
                        "time_added": t,
                        "age_sec": now - t if t else 0,
                        "n_vin": 0,
                        "n_vout": 0,
                    })
                entries.sort(key=lambda e: e["feerate"], reverse=True)
                return entries[:limit]
            return raw
        except Exception as e:
            return {"error": str(e)}

    def get_mempool_entry(self, txid, chain=None):
        """Get single mempool tx detail."""
        chain = self.coin_or_primary(chain)
        rpc = self.rpc(chain)
        try:
            return rpc.call("getmempoolentry", txid)
        except Exception as e:
            return {"error": str(e)}


# ============================================================================
# HTML Templates
# ============================================================================

CSS = """
body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
h1 { color: #f0f6fc; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
h2 { color: #e6edf3; margin-top: 24px; }
h3 { color: #e6edf3; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #30363d; padding: 6px 10px; text-align: left; font-size: 13px; }
th { background: #161b22; color: #8b949e; }
tr:hover { background: #161b22; }
.tag-p2pool { background: #1f6feb33; color: #58a6ff; padding: 2px 6px; border-radius: 3px; }
.tag-p2pool-v36 { background: #1f6feb55; color: #79c0ff; padding: 2px 6px; border-radius: 3px; font-weight: bold; }
.tag-p2pool-v35 { background: #1f6feb22; color: #4090cc; padding: 2px 6px; border-radius: 3px; font-style: italic; }
.tag-c2pool { background: #238636aa; color: #3fb950; padding: 2px 6px; border-radius: 3px; font-weight: bold; }
.tag-pool { background: #6e401080; color: #f0a040; padding: 2px 6px; border-radius: 3px; }
.tag-unknown { background: #30363d; color: #484f58; padding: 2px 6px; border-radius: 3px; font-style: italic; }
.tag-the { background: #8957e533; color: #d2a8ff; padding: 2px 6px; border-radius: 3px; }
.tag-auxpow { background: #da3633aa; color: #f85149; padding: 2px 6px; border-radius: 3px; }
.tag-mn { background: #bb800022; color: #e3b341; padding: 2px 6px; border-radius: 3px; }
.mono { font-family: 'Courier New', monospace; font-size: 12px; word-break: break-all; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin: 10px 0; }
.nav { background: #161b22; padding: 10px 20px; margin: -20px -20px 20px -20px; border-bottom: 1px solid #30363d; }
.nav a { margin-right: 20px; color: #8b949e; }
.nav a:hover, .nav a.active { color: #f0f6fc; }
.btn { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 4px 12px; border-radius: 6px; cursor: pointer; }
.btn:hover { background: #30363d; }
input[type=text] { background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 12px; border-radius: 6px; width: 500px; }
.green { color: #3fb950; }
.red { color: #f85149; }
.yellow { color: #d29922; }
.dim { color: #484f58; }
.op-return { background: #f8514922; }
.donation { background: #1f6feb22; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
"""


def blockchair_link(engine, coin_id, item_type, value, display=None):
    """Generate a Blockchair link for a tx, address, or block."""
    base = engine.blockchair_base(coin_id) if engine else ""
    if not base:
        return escape(str(display if display is not None else value))
    if display is None:
        display = value
    if item_type == "tx":
        return f'<a href="{base}/transaction/{value}" target="_blank" title="{value}">{escape(str(display))}</a>'
    elif item_type == "address":
        return f'<a href="{base}/address/{value}" target="_blank">{escape(str(display))}</a>'
    elif item_type == "block":
        return f'<a href="{base}/block/{value}" target="_blank">{escape(str(display))}</a>'
    return escape(str(display))


def render_page(title, body, chain, engine):
    chain_nav = ""
    for cid in engine.coins:
        active = "active" if cid == chain else ""
        chain_nav += f'<a href="/?chain={cid}" class="{active}">{escape(engine.chain_label(cid))}</a>\n'
    chain_nav += f"""
    <a href="/found?chain={chain}">Pool Blocks</a>
    <a href="/mempool?chain={chain}">Mempool</a>
    <a href="/api/status">API Status</a>
    <span id="sound-toggle" style="cursor:pointer;margin-left:12px;font-size:18px" title="Toggle block sounds">&#128263;</span>
    """
    footer_label = engine.footer_label()
    return f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><title>{escape(title)}</title>
<style>{CSS}</style>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head><body>
<div class="nav">{chain_nav}
<form style="display:inline" method="get" action="/block">
<input type="text" name="q" placeholder="Block height or hash..." />
<input type="hidden" name="chain" value="{chain}" />
<button class="btn" type="submit">Go</button>
</form>
</div>
<h1>{escape(title)}</h1>
{body}
<div class="dim" style="margin-top:40px;font-size:11px">
<span id="live-status">&#9679; connecting...</span> |
{escape(footer_label)}
| <a href="/api/chain_info?chain={chain}">chain_info</a>
| <a href="/api/recent?chain={chain}&count=50">recent(50)</a>
| <a href="/api/found?chain={chain}&depth=200">found(200)</a>
</div>
<script>
(function() {{
  var chain = "{chain}";
  var statusEl = document.getElementById("live-status");
  var es = new EventSource("/api/stream?chain=all");
  var soundEnabled = localStorage.getItem("blockSound") === "true";
  var soundBtn = document.getElementById("sound-toggle");
  if (soundBtn) {{
    soundBtn.innerHTML = soundEnabled ? "&#128266;" : "&#128263;";
    soundBtn.onclick = function() {{
      soundEnabled = !soundEnabled;
      localStorage.setItem("blockSound", soundEnabled);
      soundBtn.innerHTML = soundEnabled ? "&#128266;" : "&#128263;";
    }};
  }}

  function playCoins() {{
    var ctx = new (window.AudioContext || window.webkitAudioContext)();
    [880,784,698,659,587].forEach(function(f, i) {{
      var o = ctx.createOscillator(), g = ctx.createGain();
      o.type = "sine"; o.frequency.value = f;
      g.gain.setValueAtTime(0.15, ctx.currentTime + i*0.08);
      g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + i*0.08 + 0.2);
      o.connect(g); g.connect(ctx.destination);
      o.start(ctx.currentTime + i*0.08);
      o.stop(ctx.currentTime + i*0.08 + 0.25);
    }});
  }}
  function playBork() {{
    var ctx = new (window.AudioContext || window.webkitAudioContext)();
    [150,180,120].forEach(function(f, i) {{
      var o = ctx.createOscillator(), g = ctx.createGain();
      o.type = "sawtooth"; o.frequency.value = f;
      g.gain.setValueAtTime(0.2, ctx.currentTime + i*0.12);
      g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + i*0.12 + 0.1);
      o.connect(g); g.connect(ctx.destination);
      o.start(ctx.currentTime + i*0.12);
      o.stop(ctx.currentTime + i*0.12 + 0.15);
    }});
  }}

  es.addEventListener("newblock", function(e) {{
    var d = JSON.parse(e.data);
    if (statusEl) statusEl.innerHTML = '<span class="green">&#9679; block ' + d.height + '</span>';
    if (soundEnabled) {{
      try {{
        if (d.chain === "doge") playBork();
        else playCoins();
      }} catch(ex) {{}}
    }}
    var toast = document.createElement("div");
    toast.style.cssText = "position:fixed;top:20px;right:20px;background:#238636;color:#fff;padding:12px 20px;border-radius:8px;z-index:9999;font-size:14px;box-shadow:0 4px 12px rgba(0,0,0,0.4);transition:opacity 0.5s";
    toast.textContent = "New " + d.chain.toUpperCase() + " block #" + d.height;
    document.body.appendChild(toast);
    setTimeout(function(){{ toast.style.opacity = "0"; }}, 3000);
    setTimeout(function(){{ toast.remove(); }}, 3500);
    var path = window.location.pathname;
    if (path === "/" || path === "/index.html" || path === "/found") {{
      setTimeout(function(){{ window.location.reload(); }}, 1500);
    }}
  }});
  es.onopen = function() {{
    if (statusEl) statusEl.innerHTML = '<span class="green">&#9679; live</span>';
  }};
  es.onerror = function() {{
    if (statusEl) statusEl.innerHTML = '<span class="red">&#9679; disconnected</span>';
  }};
}})();
</script>
</body></html>"""


def render_tag(tag):
    if not tag:
        return ""
    tl = tag.lower()
    if "c2pool" in tl:
        cls = "tag-c2pool"
    elif "v36" in tl and "p2pool" in tl:
        cls = "tag-p2pool-v36"
    elif "scrypt" in tl and "p2pool" in tl:
        tag = "P2Pool v35"  # normalize legacy tag
        cls = "tag-p2pool-v35"
    elif "p2pool" in tl:
        cls = "tag-p2pool"
    elif tag == "UNKNOWN":
        cls = "tag-unknown"
    else:
        cls = "tag-pool"
    return f'<span class="{cls}">{escape(tag)}</span>'


def render_dashboard(engine, chain):
    info = engine.get_chain_info(chain)
    if "error" in info:
        return render_page("Explorer", f'<p class="red">Daemon offline: {escape(str(info["error"]))}</p>', chain, engine)

    blocks = engine.get_recent_blocks(30, chain)
    prof = engine.profile(chain)
    chain_name = engine.coin_label(chain)
    algo = prof.get("algo", "")

    # Chain stats card
    stats = f"""<div class="grid"><div class="card">
    <h2>{escape(chain_name)}</h2>
    <table>
    <tr><td>Algorithm</td><td>{escape(algo)}</td></tr>
    <tr><td>Height</td><td class="green">{info.get('blocks', '?')}</td></tr>
    <tr><td>Headers</td><td>{info.get('headers', '?')}</td></tr>
    <tr><td>Chain</td><td>{info.get('chain', '?')}</td></tr>
    <tr><td>Difficulty</td><td>{float(info.get('difficulty', 0)):,.4f}</td></tr>
    <tr><td>Best block</td><td class="mono"><a href="/block?q={info.get('bestblockhash', '')}&chain={chain}">{info.get('bestblockhash', '?')[:32]}...</a></td></tr>
    </table></div>
    <div class="card"><h2>Legend</h2>
    <p style="margin:0;line-height:2">
    {render_tag('/c2pool/')} c2pool V36 &nbsp;
    {render_tag('/P2Pool v36/')} p2pool V36 &nbsp;
    {render_tag('P2Pool v35')} p2pool V35 &nbsp;
    {render_tag('p2pool')} p2pool &nbsp;
    {render_tag('Miningcore')} Third-party &nbsp;
    {render_tag('UNKNOWN')} Unknown &nbsp;
    <span class="tag-the">THE</span> State root &nbsp;
    <span class="tag-auxpow">AuxPoW</span> Merged mining
    </p>
    </div></div>"""

    # Recent blocks table
    rows = ""
    for b in blocks:
        tags = render_tag(b.get("pool_tag", ""))
        if b.get("has_auxpow"):
            tags += ' <span class="tag-auxpow">AuxPoW</span>'
        if b.get("the_state_root"):
            tags += ' <span class="tag-the">THE</span>'
        ts = datetime.fromtimestamp(b["time"], tz=timezone.utc).strftime("%H:%M:%S") if b.get("time") else "?"
        rows += f"""<tr>
        <td><a href="/block?q={b['height']}&chain={chain}">{b['height']}</a></td>
        <td class="mono"><a href="/block?q={b['hash']}&chain={chain}">{b['hash'][:16]}...</a></td>
        <td>{ts}</td>
        <td>{b.get('tx_count', '?')}</td>
        <td>{b.get('size', '?')}</td>
        <td>{tags}</td>
        </tr>"""

    table = f"""<h2>Recent Blocks</h2>
    <table><tr><th>Height</th><th>Hash</th><th>Time</th><th>Txs</th><th>Size</th><th>Tags</th></tr>
    {rows}</table>"""

    return render_page(f"{chain_name} Explorer", stats + table, chain, engine)


def _render_output_rows(engine, chain, outputs):
    """Render coinbase output rows (shared by block + parent tables)."""
    rows = ""
    for o in outputs:
        row_class = ""
        tags = ""
        if o.get("is_op_return"):
            row_class = ' class="op-return"'
            if o.get("ref_hash"):
                tags += f'ref_hash=<span class="mono">{o["ref_hash"][:16]}...</span> '
                tags += f'nonce=<span class="mono">{o.get("last_txout_nonce", "")}</span>'
            elif o.get("op_return_ascii"):
                tags += f'OP_RETURN <span class="dim">{escape(o["op_return_ascii"])}</span>'
            else:
                tags += "OP_RETURN"
        if o.get("is_donation"):
            row_class = ' class="donation"'
            dtype = o.get("donation_type", "")
            tags += f'<span class="tag-p2pool">donation</span> ' + dtype
        addr_list = o.get("addresses", [])
        if addr_list:
            addr_display = ", ".join(blockchair_link(engine, chain, "address", a) for a in addr_list)
        else:
            addr_display = escape(o.get("hex", "")[:40])
        value = f'{o["value_btc"]:.8f}'
        rows += f'<tr{row_class}><td>{o["index"]}</td><td>{value}</td>'
        rows += f'<td>{o["type"]}</td><td class="mono">{addr_display}</td><td>{tags}</td></tr>'
    return rows


def render_block_detail(engine, query, chain):
    block = engine.get_block(query, chain)
    if "error" in block:
        return render_page("Block Not Found", f'<p class="red">{escape(str(block["error"]))}</p>', chain, engine)

    height = block.get("height", "?")
    bhash = block.get("hash", "?")
    cb = block.get("_coinbase_decoded", {})
    outputs = block.get("_outputs_decoded", [])

    # Navigation
    nav = f'<a href="/block?q={height-1}&chain={chain}">&larr; Prev</a> | '
    nav += f'<a href="/block?q={height+1}&chain={chain}">Next &rarr;</a>'

    # Block header
    header = f"""<div class="card">
    <table>
    <tr><td>Height</td><td class="green">{height}</td></tr>
    <tr><td>Hash</td><td class="mono">{blockchair_link(engine, chain, "block", bhash)}</td></tr>
    <tr><td>Previous</td><td class="mono"><a href="/block?q={block.get('previousblockhash','')}&chain={chain}">{block.get('previousblockhash','?')}</a></td></tr>
    <tr><td>Time</td><td>{datetime.fromtimestamp(block.get('time',0), tz=timezone.utc).isoformat()}</td></tr>
    <tr><td>Difficulty</td><td>{block.get('difficulty', '?')}</td></tr>
    <tr><td>nBits</td><td class="mono">{block.get('bits', '?')}</td></tr>
    <tr><td>Nonce</td><td>{block.get('nonce', '?')}</td></tr>
    <tr><td>Merkle Root</td><td class="mono">{block.get('merkleroot', '?')}</td></tr>
    <tr><td>Size</td><td>{block.get('size', '?')} bytes</td></tr>
    <tr><td>Transactions</td><td>{block.get('tx_count', len(block.get('tx', [])))}</td></tr>
    </table>
    <p>{nav}</p></div>"""

    # Coinbase scriptSig
    cb_html = '<div class="card"><h2>Coinbase ScriptSig</h2>'
    if cb.get("bip34_height") is not None:
        cb_html += f'<p>BIP34 Height: <span class="green">{cb["bip34_height"]}</span></p>'

    for comp in cb.get("components", []):
        ctype = comp["type"]
        if ctype == "pool_tag":
            cb_html += f'<p>Pool Tag: {render_tag(comp["value"])}</p>'
        elif ctype == "AuxPoW commitment":
            cb_html += f'<p><span class="tag-auxpow">AuxPoW</span> '
            cb_html += f'hash=<span class="mono">{comp["aux_hash"]}</span> '
            cb_html += f'merkle_size={comp["merkle_size"]} nonce={comp["merkle_nonce"]}</p>'
        elif ctype == "THE state_root":
            cb_html += f'<p><span class="tag-the">THE state_root</span> '
            cb_html += f'<span class="mono">{comp["value"]}</span></p>'

    if cb.get("ascii_strings"):
        cb_html += f'<p class="dim">ASCII: {escape(", ".join(cb["ascii_strings"]))}</p>'
    cb_html += f'<details><summary class="dim">Raw scriptSig ({cb.get("length", "?")} bytes)</summary>'
    cb_html += f'<p class="mono">{escape(cb.get("raw_hex", ""))}</p>'
    raw_hex = cb.get("raw_hex", "")
    if raw_hex:
        raw_bytes = bytes.fromhex(raw_hex)
        ascii_dec = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in raw_bytes)
        cb_html += f'<p class="mono dim">{escape(ascii_dec)}</p>'
    cb_html += '</details>'
    cb_html += '</div>'

    # DASH DIP3/DIP4 CbTx (masternode-enforced special coinbase)
    cbtx_html = ""
    cbtx = block.get("_cbtx")
    if cbtx or block.get("_is_special_cb"):
        cbtx_html = '<div class="card"><h2><span class="tag-mn">DIP3/DIP4</span> Coinbase Special Payload (CbTx)</h2>'
        cbtx_html += '<p class="dim">Dash coinbase is a special transaction (v3, type=5). '
        cbtx_html += 'Consensus requires the coinbase to pay the scheduled masternode/operator payee '
        cbtx_html += '(shown among the coinbase outputs below).</p>'
        if isinstance(cbtx, dict):
            cbtx_html += '<table>'
            cbtx_html += f'<tr><td>CbTx version</td><td>{cbtx.get("version", "?")}</td></tr>'
            cbtx_html += f'<tr><td>Height</td><td class="green">{cbtx.get("height", "?")}</td></tr>'
            if cbtx.get("merkleRootMNList"):
                cbtx_html += f'<tr><td>MN-list root</td><td class="mono">{escape(str(cbtx["merkleRootMNList"]))}</td></tr>'
            if cbtx.get("merkleRootQuorums"):
                cbtx_html += f'<tr><td>Quorum root</td><td class="mono">{escape(str(cbtx["merkleRootQuorums"]))}</td></tr>'
            if cbtx.get("bestCLHeightDiff") is not None:
                cbtx_html += f'<tr><td>bestCLHeightDiff</td><td>{cbtx.get("bestCLHeightDiff")}</td></tr>'
            if cbtx.get("creditPoolBalance") is not None:
                cbtx_html += f'<tr><td>Credit pool</td><td>{cbtx.get("creditPoolBalance")}</td></tr>'
            cbtx_html += '</table>'
        cbtx_html += '</div>'

    # Coinbase outputs
    out_html = '<div class="card"><h2>Coinbase Outputs</h2><table>'
    out_html += '<tr><th>#</th><th>Value</th><th>Type</th><th>Address / Script</th><th>Tags</th></tr>'
    out_html += _render_output_rows(engine, chain, outputs)
    out_html += '</table></div>'

    # AuxPoW (merged mining) — show parent coinbase
    auxpow_html = ""
    if block.get("_parent_coinbase_decoded"):
        pcb = block["_parent_coinbase_decoded"]
        auxinfo = block.get("_auxpow_info", {})
        parent_id = auxinfo.get("parent_coin", engine.profile(chain).get("merged_parent", chain))
        parent_unit = COIN_PROFILES.get(parent_id, {}).get("unit", parent_id.upper())
        auxpow_html = f'<div class="card"><h2><span class="tag-auxpow">AuxPoW</span> Parent ({escape(parent_unit)}) Coinbase</h2>'
        if pcb.get("bip34_height") is not None:
            auxpow_html += f'<p>Parent BIP34 Height: <span class="green">{pcb["bip34_height"]}</span></p>'
        for comp in pcb.get("components", []):
            if comp["type"] == "pool_tag":
                auxpow_html += f'<p>Parent Pool Tag: {render_tag(comp["value"])}</p>'
            elif comp["type"] == "THE state_root":
                auxpow_html += f'<p><span class="tag-the">THE state_root (parent)</span> '
                auxpow_html += f'<span class="mono">{comp["value"]}</span></p>'
        if pcb.get("ascii_strings"):
            auxpow_html += f'<p class="dim">Parent ASCII: {escape(", ".join(pcb["ascii_strings"]))}</p>'
        parent_txid = auxinfo.get("parent_txid", "?")
        auxpow_html += f'<p class="dim">Parent txid: <span class="mono">{blockchair_link(engine, parent_id, "tx", parent_txid)}</span></p>'
        pouts = block.get("_parent_outputs_decoded", [])
        if pouts:
            auxpow_html += '<h3>Parent Coinbase Outputs</h3><table>'
            auxpow_html += '<tr><th>#</th><th>Value</th><th>Type</th><th>Address</th><th>Tags</th></tr>'
            auxpow_html += _render_output_rows(engine, parent_id, pouts)
            auxpow_html += '</table>'
        auxpow_html += '</div>'

    # All transactions summary
    tx_html = '<div class="card"><h2>Transactions</h2><table>'
    tx_html += '<tr><th>#</th><th>TxID</th><th>Inputs</th><th>Outputs</th></tr>'
    for i, tx in enumerate(block.get("tx", [])[:50]):
        txid = tx.get("txid", "?")
        n_in = len(tx.get("vin", []))
        n_out = len(tx.get("vout", []))
        txid_display = blockchair_link(engine, chain, "tx", txid, txid[:32] + "...")
        tx_html += f'<tr><td>{i}</td><td class="mono">{txid_display}</td>'
        tx_html += f'<td>{n_in}</td><td>{n_out}</td></tr>'
    if len(block.get("tx", [])) > 50:
        tx_html += f'<tr><td colspan="4" class="dim">... and {len(block["tx"]) - 50} more</td></tr>'
    tx_count = block.get("tx_count", len(block.get("tx", [])))
    if tx_count > len(block.get("tx", [])):
        tx_html += f'<tr><td colspan="4" class="dim">Only coinbase shown. Block contains {tx_count} transactions total.</td></tr>'
    tx_html += '</table></div>'

    title = f"Block {height}"
    pool_tag = cb.get("pool_tag", "")
    if pool_tag:
        title += f" ({pool_tag})"

    body = header + cb_html + cbtx_html + out_html + auxpow_html + tx_html
    return render_page(title, body, chain, engine)


def render_found_blocks(engine, chain, depth=200):
    found = engine.scan_for_pool_blocks(chain, depth)

    rows = ""
    for b in found:
        tags = render_tag(b.get("pool_tag", ""))
        if b.get("has_auxpow"):
            tags += ' <span class="tag-auxpow">AuxPoW</span>'
        if b.get("the_state_root"):
            tags += ' <span class="tag-the">THE</span>'
        ts = datetime.fromtimestamp(b["time"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if b.get("time") else "?"
        value = f'{b.get("coinbase_value", 0) / 1e8:.8f}'
        rows += f"""<tr>
        <td><a href="/block?q={b['height']}&chain={chain}">{b['height']}</a></td>
        <td class="mono">{blockchair_link(engine, chain, "block", b['hash'], b['hash'][:24] + "...")}</td>
        <td>{ts}</td>
        <td>{value}</td>
        <td>{tags}</td></tr>"""

    if not rows:
        rows = f'<tr><td colspan="5" class="dim">No pool blocks found in last {depth} blocks</td></tr>'

    table = f"""<table>
    <tr><th>Height</th><th>Hash</th><th>Time</th><th>Coinbase Value</th><th>Tags</th></tr>
    {rows}</table>"""

    return render_page(f"Pool Blocks Found ({engine.chain_label(chain)}, last {depth})", table, chain, engine)


def render_mempool_dashboard(engine, chain):
    """Render the live mempool dashboard page with summary, histogram, and top txs."""
    info = engine.get_mempool_info(chain)
    if "error" in info:
        return render_page("Mempool", f'<p class="red">Mempool unavailable: {escape(str(info["error"]))}</p>', chain, engine)

    unit = engine.unit(chain)
    tx_count = info.get("size", 0)
    total_bytes = info.get("bytes", 0)
    total_weight = info.get("total_weight", 0)
    total_fees = info.get("total_fees", 0)
    fee_known = info.get("fee_known_count", 0)
    fee_unknown = info.get("fee_unknown_count", 0)
    min_fr = info.get("min_feerate", 0)
    max_fr = info.get("max_feerate", 0)
    med_fr = info.get("median_feerate", 0)
    avg_fr = info.get("avg_feerate", 0)
    oldest = info.get("oldest_age_sec", 0)

    stats = f"""<div class="grid"><div class="card">
    <h2>{unit} Mempool</h2>
    <table>
    <tr><td>Transactions</td><td class="green">{tx_count}</td></tr>
    <tr><td>Total size</td><td>{total_bytes:,} bytes</td></tr>
    <tr><td>Total weight</td><td>{total_weight:,} WU</td></tr>
    <tr><td>Total fees</td><td>{total_fees:,} sat ({total_fees / 1e8:.8f} {unit})</td></tr>
    <tr><td>Fee known / unknown</td><td>{fee_known} / {fee_unknown}</td></tr>
    <tr><td>Oldest tx age</td><td>{oldest // 3600}h {(oldest % 3600) // 60}m</td></tr>
    </table></div>
    <div class="card"><h2>Feerate (sat/vB)</h2>
    <table>
    <tr><td>Min</td><td>{min_fr:.2f}</td></tr>
    <tr><td>Max</td><td>{max_fr:.2f}</td></tr>
    <tr><td>Median</td><td class="green">{med_fr:.2f}</td></tr>
    <tr><td>Average</td><td>{avg_fr:.2f}</td></tr>
    </table></div></div>"""

    histogram = info.get("fee_histogram", [])
    if histogram:
        max_count = max((b.get("count", 0) for b in histogram), default=1) or 1
        bar_colors = ["#f85149", "#d29922", "#3fb950", "#58a6ff", "#d2a8ff"]
        hist_html = '<div class="card"><h2>Feerate Distribution</h2>'
        for i, bucket in enumerate(histogram):
            label = f'{bucket.get("min_feerate", 0)}-{bucket.get("max_feerate", "∞")} sat/vB'
            count = bucket.get("count", 0)
            bsize = bucket.get("bytes", 0)
            pct = count / max_count * 100 if max_count > 0 else 0
            color = bar_colors[i % len(bar_colors)]
            hist_html += f"""<div style="margin:6px 0">
            <span style="display:inline-block;width:140px;font-size:12px">{label}</span>
            <span style="display:inline-block;width:{max(pct, 2):.0f}%;max-width:60%;
                  background:{color};height:18px;border-radius:3px;vertical-align:middle"></span>
            <span style="font-size:12px;margin-left:8px">{count} txs, {bsize:,} bytes</span>
            </div>"""
        hist_html += '</div>'
    else:
        hist_html = ''

    entries = engine.get_mempool_entries(chain, verbose=True, limit=50)
    if isinstance(entries, list) and entries and not (len(entries) == 1 and "error" in entries[0]):
        rows = ""
        now = int(time.time())
        for e in entries:
            txid = e.get("txid", "?")
            feerate = e.get("feerate", 0)
            fee = e.get("fee", 0)
            size = e.get("size", e.get("weight", 0))
            weight = e.get("weight", 0)
            age = e.get("age_sec", 0)
            if age == 0 and e.get("time_added"):
                age = now - int(e["time_added"])
            n_vin = e.get("n_vin", 0)
            n_vout = e.get("n_vout", 0)
            age_str = f"{age // 60}m" if age < 3600 else f"{age // 3600}h {(age % 3600) // 60}m"
            txid_display = f'<a href="/mempool/tx?txid={txid}&chain={chain}">{txid[:24]}...</a>'
            fr_class = "green" if feerate >= 20 else ("yellow" if feerate >= 5 else "dim")
            rows += f"""<tr>
            <td class="mono">{txid_display}</td>
            <td>{size}</td><td>{weight}</td>
            <td>{fee:,}</td>
            <td class="{fr_class}">{feerate:.2f}</td>
            <td>{n_vin}/{n_vout}</td>
            <td>{age_str}</td></tr>"""

        tx_table = f"""<h2>Top Transactions (by feerate)</h2>
        <table><tr><th>TxID</th><th>Size</th><th>Weight</th><th>Fee (sat)</th>
        <th>Feerate (sat/vB)</th><th>In/Out</th><th>Age</th></tr>
        {rows}</table>"""
    elif isinstance(entries, dict) and "error" in entries:
        tx_table = f'<p class="dim">Could not load mempool entries: {escape(str(entries["error"]))}</p>'
    else:
        tx_table = '<p class="dim">No transactions in mempool</p>'

    refresh = '<meta http-equiv="refresh" content="15">'
    body = stats + hist_html + tx_table
    page = render_page(f"{unit} Mempool ({tx_count} txs)", body, chain, engine)
    page = page.replace('<meta charset="utf-8">', f'<meta charset="utf-8">{refresh}', 1)
    return page


def render_mempool_tx_detail(engine, txid, chain):
    """Render detail page for a single mempool transaction."""
    entry = engine.get_mempool_entry(txid, chain)
    if isinstance(entry, dict) and "error" in entry:
        return render_page("Mempool Tx", f'<p class="red">Transaction not found: {escape(str(entry["error"]))}</p>', chain, engine)

    unit = engine.unit(chain)

    feerate = entry.get("feerate", 0)
    fee = entry.get("fee", 0)
    size = entry.get("size", 0)
    weight = entry.get("weight", 0)
    age = entry.get("age_sec", 0)
    age_str = f"{age // 60}m" if age < 3600 else f"{age // 3600}h {(age % 3600) // 60}m"

    header = f"""<div class="card">
    <h2>Mempool Transaction</h2>
    <table>
    <tr><td>TxID</td><td class="mono">{blockchair_link(engine, chain, "tx", txid)}</td></tr>
    <tr><td>Size</td><td>{size} bytes</td></tr>
    <tr><td>Weight</td><td>{weight} WU</td></tr>
    <tr><td>Fee</td><td>{fee:,} sat ({fee / 1e8:.8f} {unit})</td></tr>
    <tr><td>Feerate</td><td class="green">{feerate:.2f} sat/vB</td></tr>
    <tr><td>Fee known</td><td>{"Yes" if entry.get("fee_known", True) else "No"}</td></tr>
    <tr><td>Age</td><td>{age_str}</td></tr>
    </table></div>"""

    vin = entry.get("vin", [])
    if vin:
        vin_rows = ""
        for i, inp in enumerate(vin):
            prevout = inp.get("prevout_hash", "?")
            prevout_n = inp.get("prevout_n", 0)
            seq = inp.get("sequence", 0)
            prevout_link = blockchair_link(engine, chain, "tx", prevout, f"{prevout[:24]}...") if prevout != "?" else "?"
            vin_rows += f'<tr><td>{i}</td><td class="mono">{prevout_link}:{prevout_n}</td><td>{seq}</td></tr>'
        vin_html = f"""<div class="card"><h2>Inputs ({len(vin)})</h2>
        <table><tr><th>#</th><th>Prevout (hash:n)</th><th>Sequence</th></tr>
        {vin_rows}</table></div>"""
    else:
        vin_html = ''

    vout = entry.get("vout", [])
    if vout:
        vout_rows = ""
        for i, o in enumerate(vout):
            value_sat = o.get("value_sat", 0)
            value_btc = value_sat / 1e8
            script_type = o.get("type", "?")
            addr = o.get("address", "")
            script_hex = o.get("scriptPubKey_hex", "")
            if addr:
                addr_display = blockchair_link(engine, chain, "address", addr)
            elif script_hex:
                addr_display = f'<span class="mono dim">{escape(script_hex[:60])}{"..." if len(script_hex) > 60 else ""}</span>'
            else:
                addr_display = '<span class="dim">-</span>'
            vout_rows += f'<tr><td>{i}</td><td>{value_btc:.8f}</td><td>{script_type}</td><td>{addr_display}</td></tr>'
        vout_html = f"""<div class="card"><h2>Outputs ({len(vout)})</h2>
        <table><tr><th>#</th><th>Value ({unit})</th><th>Type</th><th>Address</th></tr>
        {vout_rows}</table></div>"""
    else:
        vout_html = ''

    back_link = f'<p><a href="/mempool?chain={chain}">&larr; Back to Mempool</a></p>'
    return render_page(f"Mempool Tx {txid[:16]}...", back_link + header + vin_html + vout_html, chain, engine)


# ============================================================================
# HTTP Server
# ============================================================================

class ExplorerHandler(http.server.BaseHTTPRequestHandler):
    engine: ExplorerEngine = None

    def log_message(self, format, *args):
        pass  # suppress default logging

    def _parse_params(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        return parsed.path, {k: v[0] for k, v in params.items()}

    def _respond(self, code, content, content_type="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if isinstance(content, str):
            content = content.encode()
        self.wfile.write(content)

    def do_GET(self):
        path, params = self._parse_params()
        chain = self.engine.coin_or_primary(params.get("chain", self.engine.primary))

        try:
            if path == "/" or path == "/index.html":
                self._respond(200, render_dashboard(self.engine, chain))

            elif path == "/block":
                q = params.get("q", "")
                if not q:
                    self._respond(400, render_page("Error", '<p class="red">Missing block height or hash</p>', chain, self.engine))
                    return
                self._respond(200, render_block_detail(self.engine, q, chain))

            elif path == "/found":
                depth = int(params.get("depth", "200"))
                self._respond(200, render_found_blocks(self.engine, chain, depth))

            elif path == "/mempool":
                self._respond(200, render_mempool_dashboard(self.engine, chain))

            elif path == "/mempool/tx":
                txid = params.get("txid", "")
                if not txid:
                    self._respond(400, render_page("Error", '<p class="red">Missing txid parameter</p>', chain, self.engine))
                    return
                self._respond(200, render_mempool_tx_detail(self.engine, txid, chain))

            # ---- REST API ----
            elif path == "/api/status":
                status = {}
                for cid in self.engine.coins:
                    rpc = self.engine.rpc(cid)
                    status[cid] = {
                        "alive": rpc.is_alive() if rpc else False,
                        "url": getattr(rpc, "url", None),
                        "coin": self.engine.profile(cid).get("name", cid),
                        "network": self.engine.network(cid),
                        "completeness": self.engine.profile(cid).get("completeness", "unknown"),
                    }
                self._respond(200, json.dumps(status, indent=2), "application/json")

            elif path == "/api/chain_info":
                info = self.engine.get_chain_info(chain)
                self._respond(200, json.dumps(info, indent=2, default=str), "application/json")

            elif path == "/api/block":
                q = params.get("q", "")
                block = self.engine.get_block(q, chain)
                self._respond(200, json.dumps(block, indent=2, default=str), "application/json")

            elif path == "/api/recent":
                count = int(params.get("count", "20"))
                blocks = self.engine.get_recent_blocks(min(count, 100), chain)
                self._respond(200, json.dumps(blocks, indent=2, default=str), "application/json")

            elif path == "/api/found":
                depth = int(params.get("depth", "200"))
                found = self.engine.scan_for_pool_blocks(chain, depth)
                self._respond(200, json.dumps(found, indent=2, default=str), "application/json")

            elif path == "/api/mempool":
                info = self.engine.get_mempool_info(chain)
                self._respond(200, json.dumps(info, indent=2, default=str), "application/json")

            elif path == "/api/mempool/entries":
                verbose = params.get("verbose", "true") == "true"
                limit = min(int(params.get("limit", "100")), 5000)
                entries = self.engine.get_mempool_entries(chain, verbose, limit)
                self._respond(200, json.dumps(entries, indent=2, default=str), "application/json")

            elif path == "/api/mempool/tx":
                txid = params.get("txid", "")
                if not txid:
                    self._respond(400, json.dumps({"error": "Missing txid"}), "application/json")
                    return
                entry = self.engine.get_mempool_entry(txid, chain)
                self._respond(200, json.dumps(entry, indent=2, default=str), "application/json")

            elif path == "/api/stream":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                import queue as _q
                raw_chain = params.get("chain", "all")
                q = self.engine.register_sse_client(raw_chain if raw_chain != "all" else None)
                try:
                    self.wfile.write(b": connected\n\n")
                    self.wfile.flush()
                    while True:
                        try:
                            msg = q.get(timeout=15)
                            self.wfile.write(msg.encode())
                            self.wfile.flush()
                        except _q.Empty:
                            self.wfile.write(b": keepalive\n\n")
                            self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    self.engine.unregister_sse_client(q)
                return

            else:
                self._respond(404, render_page("404", '<p class="red">Page not found</p>', chain, self.engine))

        except Exception as e:
            traceback.print_exc()
            self._respond(500, render_page("Error", f'<pre class="red">{escape(traceback.format_exc())}</pre>', chain, self.engine))


# ============================================================================
# Main
# ============================================================================

def _read_cookie(path):
    """Read a bitcoin-style .cookie file → (user, pass), or (None, None)."""
    try:
        with open(path) as f:
            data = f.read().strip()
        if ":" in data:
            u, p = data.split(":", 1)
            return u, p
    except Exception:
        pass
    return None, None


def _build_rpc(host, port, user, password, cookie, label):
    if cookie:
        cu, cp = _read_cookie(cookie)
        if cu is not None:
            user, password = cu, cp
    return RpcClient(host, port, user or "", password or "", label)


def _probe(rpc, label):
    """Print a one-line liveness/summary for an RPC client."""
    print(f"{label} RPC: ", end="")
    try:
        if rpc.is_alive():
            info = rpc.call("getblockchaininfo")
            chain = info.get('chain', info.get('network', 'unknown'))
            height = info.get('blocks', info.get('headers', 0))
            print(f"OK — chain={chain} height={height}")
            return True
        print("OFFLINE")
    except Exception as e:
        print(f"ERROR ({e})")
    return False


def main():
    parser = argparse.ArgumentParser(description="c2pool Block Explorer (coin-generic, auto-detecting)")

    # Generic single-coin mode
    parser.add_argument("--coin", default=None,
                        help="Coin: dash|ltc|doge|dgb|bch|btc (auto-detected from the daemon if omitted)")
    parser.add_argument("--rpc-host", default=None, help="Coin daemon RPC host")
    parser.add_argument("--rpc-port", type=int, default=None, help="Coin daemon RPC port")
    parser.add_argument("--rpc-user", default=None, help="Coin daemon RPC user")
    parser.add_argument("--rpc-pass", default=None, help="Coin daemon RPC password")
    parser.add_argument("--rpc-cookie", default=None, help="Path to a bitcoin-style .cookie file (overrides user/pass)")
    parser.add_argument("--c2pool", default=None, help="c2pool explorer API URL (e.g. http://127.0.0.1:8080/api/explorer)")

    # Back-compat: legacy LTC + DOGE two-chain mode (unchanged defaults)
    parser.add_argument("--ltc-host", default="192.168.86.26", help="[legacy] Litecoin RPC host")
    parser.add_argument("--ltc-port", type=int, default=19332, help="[legacy] Litecoin RPC port")
    parser.add_argument("--ltc-user", default="litecoinrpc", help="[legacy] Litecoin RPC user")
    parser.add_argument("--ltc-pass", default="litecoinrpc_mainnet_2026", help="[legacy] Litecoin RPC password")
    parser.add_argument("--doge-host", default="192.168.86.27", help="[legacy] Dogecoin RPC host")
    parser.add_argument("--doge-port", type=int, default=44555, help="[legacy] Dogecoin RPC port")
    parser.add_argument("--doge-user", default="dogecoinrpc", help="[legacy] Dogecoin RPC user")
    parser.add_argument("--doge-pass", default="testpass", help="[legacy] Dogecoin RPC password")
    parser.add_argument("--no-doge", action="store_true", help="[legacy] Disable DOGE chain")
    parser.add_argument("--ltc-c2pool", default=None, help="[legacy] c2pool explorer API URL for LTC")
    parser.add_argument("--doge-c2pool", default=None, help="[legacy] c2pool explorer API URL for DOGE")

    parser.add_argument("--web-port", type=int, default=8888, help="Explorer web port")
    args = parser.parse_args()

    coins = OrderedDict()
    primary = None

    # Generic mode is selected when any of --coin/--rpc-host/--c2pool is given.
    generic_mode = bool(args.coin or args.rpc_host or args.c2pool)

    if generic_mode:
        coin_id = resolve_coin_id(args.coin)

        if args.c2pool:
            # c2pool explorer API — coin from --coin or /web/currency_info symbol.
            tmp = C2PoolClient(args.c2pool, coin_id or "coin")
            if not coin_id:
                sym = (tmp.currency_info().get("symbol", "") or "").lower()
                for cid, prof in COIN_PROFILES.items():
                    if sym in prof.get("symbols", []):
                        coin_id = cid
                        break
            if not coin_id:
                print("ERROR: could not detect coin from c2pool node; pass --coin explicitly.")
                sys.exit(2)
            rpc = C2PoolClient(args.c2pool, coin_id)
        else:
            host = args.rpc_host or "127.0.0.1"
            user = args.rpc_user
            password = args.rpc_pass
            # Auto-detect coin (and thus default port) from the daemon if needed.
            if not coin_id:
                # A probe client on the given port to read subversion/genesis.
                probe_port = args.rpc_port or 8332
                probe_rpc = _build_rpc(host, probe_port, user, password, args.rpc_cookie, "probe")
                coin_id, _net = probe_rpc.detect_profile()
                if not coin_id:
                    print("ERROR: could not auto-detect the coin. Pass --coin explicitly "
                          "(and --rpc-port if non-standard).")
                    sys.exit(2)
                print(f"Auto-detected coin: {coin_id}")
            port = args.rpc_port or {"dash": 9998, "ltc": 9332, "doge": 22555,
                                     "btc": 8332, "dgb": 14022, "bch": 8332}.get(coin_id, 8332)
            rpc = _build_rpc(host, port, user, password, args.rpc_cookie,
                             COIN_PROFILES[coin_id]["unit"])

        coins[coin_id] = {"rpc": rpc, "profile": COIN_PROFILES[coin_id]}
        primary = coin_id

    else:
        # Legacy LTC + DOGE two-chain mode (regression-preserving defaults).
        if args.ltc_c2pool:
            ltc_rpc = C2PoolClient(args.ltc_c2pool, "ltc")
        else:
            ltc_rpc = RpcClient(args.ltc_host, args.ltc_port, args.ltc_user, args.ltc_pass, "LTC")
        coins["ltc"] = {"rpc": ltc_rpc, "profile": COIN_PROFILES["ltc"]}
        primary = "ltc"

        if not args.no_doge:
            if args.doge_c2pool:
                doge_rpc = C2PoolClient(args.doge_c2pool, "doge")
            else:
                doge_rpc = RpcClient(args.doge_host, args.doge_port, args.doge_user, args.doge_pass, "DOGE")
            coins["doge"] = {"rpc": doge_rpc, "profile": COIN_PROFILES["doge"]}

    engine = ExplorerEngine(coins, primary=primary)

    # Connectivity probe (retry primary a few times for c2pool API warm-up).
    for attempt in range(10):
        rpc = engine.rpc(primary)
        try:
            if rpc.is_alive():
                _probe(rpc, engine.unit(primary))
                break
            print(f"{engine.unit(primary)} RPC: OFFLINE")
            break
        except (KeyError, TypeError):
            print(f"waiting for API (attempt {attempt+1}/10)...")
            time.sleep(5)
    else:
        print("WARNING: primary API not ready — explorer may show incomplete data")

    for cid in engine.coins:
        if cid != primary:
            _probe(engine.rpc(cid), engine.unit(cid))

    # Start web server (ThreadingHTTPServer so SSE streams don't block requests).
    import http.server as _hs
    class ThreadedServer(_hs.ThreadingHTTPServer):
        daemon_threads = True

    ExplorerHandler.engine = engine
    engine.start_block_poller(interval=2)
    server = ThreadedServer(("0.0.0.0", args.web_port), ExplorerHandler)
    print(f"\nExplorer running at http://0.0.0.0:{args.web_port}/")
    for cid in engine.coins:
        prof = engine.profile(cid)
        print(f"  {prof['name']} ({prof.get('completeness','?')}): "
              f"http://localhost:{args.web_port}/?chain={cid}")
    print(f"  Pool blocks: http://localhost:{args.web_port}/found?chain={primary}")
    print(f"  API status:  http://localhost:{args.web_port}/api/status")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
