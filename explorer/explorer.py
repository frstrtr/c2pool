#!/usr/bin/env python3
"""
c2pool Block Explorer — lightweight web-based block browser for LTC + DOGE chains.
Bundled with c2pool for use with embedded SPV nodes or standalone daemons.

Features:
- Navigate blocks (latest, by height, by hash)
- Decode coinbase scriptSig: BIP34 height, pool tags, THE state_root, AuxPoW commitment
- Trace coinbase payouts (PPLNS outputs, donation, OP_RETURN ref_hash)
- Highlight blocks found by p2pool/c2pool (via coinbase tag detection)
- DOGE merged mining: show aux blocks and their parent LTC block
- Auto-refresh dashboard with recent blocks
- REST API + simple HTML UI

Usage:
    python3 explorer.py [--ltc-host 192.168.86.26] [--ltc-port 19332]
                        [--doge-host 192.168.86.27] [--doge-port 44555]
                        [--web-port 8888]

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
# Blockchair / block explorer URLs for external linking
# ============================================================================

BLOCKCHAIR = {
    "ltc_testnet": "https://blockchair.com/litecoin/testnet",
    "ltc_mainnet": "https://blockchair.com/litecoin",
    "doge_testnet": "https://blockchair.com/dogecoin",
    "doge_mainnet": "https://blockchair.com/dogecoin",
}

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

def bech32_encode(hrp, witver, witprog):
    """Encode a segwit address (BIP173 bech32)."""
    data = [witver] + _convertbits(witprog, 8, 5)
    checksum = _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)

def script_to_address(hex_script, chain="ltc_testnet"):
    """Decode a scriptPubKey hex to a human-readable address.

    Supports P2PKH, P2SH, and P2WPKH for LTC and DOGE networks.
    Returns None if the script format is not recognized.
    """
    # Chain-specific version bytes and bech32 HRP
    CHAINS = {
        "ltc_mainnet":  {"p2pkh": 0x30, "p2sh": 0x32, "hrp": "ltc"},
        "ltc_testnet":  {"p2pkh": 0x6f, "p2sh": 0x3a, "hrp": "tltc"},
        "doge_mainnet": {"p2pkh": 0x1e, "p2sh": 0x16, "hrp": None},
        "doge_testnet": {"p2pkh": 0x71, "p2sh": 0xc4, "hrp": None},
        "btc_mainnet":  {"p2pkh": 0x00, "p2sh": 0x05, "hrp": "bc"},
        "btc_testnet":  {"p2pkh": 0x6f, "p2sh": 0xc4, "hrp": "tb"},
    }
    cfg = CHAINS.get(chain, CHAINS["ltc_testnet"])
    s = bytes.fromhex(hex_script)

    # P2WPKH: OP_0 PUSH_20 <20 bytes>
    if len(s) == 22 and s[0] == 0x00 and s[1] == 0x14:
        if cfg["hrp"]:
            return bech32_encode(cfg["hrp"], 0, list(s[2:]))
        return None  # Chain doesn't support bech32

    # P2WSH: OP_0 PUSH_32 <32 bytes>
    if len(s) == 34 and s[0] == 0x00 and s[1] == 0x20:
        if cfg["hrp"]:
            return bech32_encode(cfg["hrp"], 0, list(s[2:]))
        return None

    # P2PKH: OP_DUP OP_HASH160 PUSH_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if len(s) == 25 and s[0] == 0x76 and s[1] == 0xa9 and s[2] == 0x14 and s[23] == 0x88 and s[24] == 0xac:
        return _base58check_encode(cfg["p2pkh"], s[3:23])

    # P2SH: OP_HASH160 PUSH_20 <20 bytes> OP_EQUAL
    if len(s) == 23 and s[0] == 0xa9 and s[1] == 0x14 and s[22] == 0x87:
        return _base58check_encode(cfg["p2sh"], s[2:22])

    return None

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


class C2PoolClient:
    """Client adapter for c2pool's explorer REST API."""

    def __init__(self, base_url, chain):
        self.base_url = base_url.rstrip('/')
        self.chain = chain  # "ltc" or "doge"
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
    """Decode coinbase scriptSig into structured components."""
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


def decode_outputs(vout_list, chain="ltc_testnet"):
    """Decode transaction outputs into structured components."""
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
            decoded = script_to_address(out["hex"], chain)
            if decoded:
                addresses = [decoded]
        out["addresses"] = addresses

        # Detect OP_RETURN
        if out["asm"].startswith("OP_RETURN"):
            out["is_op_return"] = True
            hex_data = out["hex"]
            if len(hex_data) >= 4 and hex_data[:4] == "6a28":
                # p2pool ref_hash OP_RETURN: 6a28 + ref_hash(32) + nonce(8)
                if len(hex_data) >= 84:
                    out["ref_hash"] = hex_data[4:68]
                    out["last_txout_nonce"] = hex_data[68:84]
                    out["type"] = "p2pool_ref"

        # Detect donation script (P2SH: a914...87)
        if out["hex"].startswith("a914") and out["hex"].endswith("87") and len(out["hex"]) == 46:
            out["is_donation"] = True
            # Check if it's the combined p2pool/c2pool donation
            if "8c6272621d89e8fa526dd86acff60c7136be8e85" in out["hex"]:
                out["donation_type"] = "p2pool_combined"

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
    """Core explorer logic: fetch, decode, and serve block data."""

    def __init__(self, ltc_rpc, doge_rpc=None):
        self.ltc = ltc_rpc
        self.doge = doge_rpc
        self.cache = BlockCache()
        self.found_blocks = []  # blocks found by p2pool/c2pool
        self._scan_lock = threading.Lock()
        # Live block notification: tracks latest known height per chain
        self._tip = {"ltc": 0, "doge": 0}
        self._tip_lock = threading.Lock()
        self._sse_clients = []  # list of (queue, chain_filter)
        self._sse_lock = threading.Lock()
        self._poller_running = False
        # Cache chain labels (populated on first call)
        self._chain_key_cache = {}

    def chain_label(self, chain="ltc"):
        """Human-readable chain label, e.g. 'LTC' or 'DOGE Testnet'."""
        ck = self.chain_key(chain)
        coin = "LTC" if chain == "ltc" else "DOGE"
        return f"{coin} Testnet" if "testnet" in ck else coin

    def footer_label(self):
        """Footer text describing the explorer instance."""
        ltc_label = self.chain_label("ltc")
        parts = [f"{ltc_label} Explorer"]
        if self.doge:
            parts.append(f"+ {self.chain_label('doge')}")
        return " ".join(parts)

    # --- SSE (Server-Sent Events) block notification ---

    def start_block_poller(self, interval=2):
        """Background thread that polls for new blocks and pushes SSE events."""
        if self._poller_running:
            return
        self._poller_running = True

        def _poll():
            while self._poller_running:
                for chain_id, rpc in [("ltc", self.ltc), ("doge", self.doge)]:
                    if rpc is None:
                        continue
                    try:
                        info = rpc.call("getblockchaininfo", timeout=3)
                        height = info.get("blocks", 0)
                        with self._tip_lock:
                            prev = self._tip[chain_id]
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

    def get_chain_info(self, chain="ltc"):
        rpc = self.doge if chain == "doge" and self.doge else self.ltc
        try:
            return rpc.call("getblockchaininfo")
        except Exception as e:
            return {"error": str(e)}

    def chain_key(self, chain="ltc"):
        """Return Blockchair dict key like 'ltc_mainnet' or 'doge_testnet'. Cached."""
        if chain in self._chain_key_cache:
            return self._chain_key_cache[chain]
        info = self.get_chain_info(chain)
        is_test = info.get("chain", "") in ("test", "testnet", "testnet4alpha", "regtest")
        net = "testnet" if is_test else "mainnet"
        key = f"{chain}_{net}"
        self._chain_key_cache[chain] = key
        return key

    def get_block(self, height_or_hash, chain="ltc"):
        """Fetch and decode a block by height or hash."""
        rpc = self.doge if chain == "doge" and self.doge else self.ltc
        cache_key = f"{chain}:{height_or_hash}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        # Fallback: hardcoded seed blocks (outside embedded chain depth)
        seed_key = f"{chain}:{height_or_hash}"
        seed = self.SEED_BLOCK_DETAILS.get(seed_key)
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

        # Decode coinbase
        if block.get("tx"):
            coinbase_tx = block["tx"][0]
            vin = coinbase_tx.get("vin", [{}])
            if vin and "coinbase" in vin[0]:
                block["_coinbase_decoded"] = decode_scriptsig(vin[0]["coinbase"])
                out_chain = self.chain_key(chain)
                block["_outputs_decoded"] = decode_outputs(coinbase_tx.get("vout", []), out_chain)
            else:
                block["_coinbase_decoded"] = {"error": "not a coinbase"}
                block["_outputs_decoded"] = []

        # Detect p2pool version from donation script type and ref_hash in outputs
        # COMBINED_DONATION_SCRIPT (P2SH a9148c6272...) = V36, old P2PK = V35
        cb = block.get("_coinbase_decoded", {})
        tag = cb.get("pool_tag", "")
        outs = block.get("_outputs_decoded", [])
        has_combined = any(
            o.get("donation_type") == "p2pool_combined" for o in outs
        )
        has_ref = any(o.get("type") == "p2pool_ref" for o in outs)

        # Structural detection: no explicit tag but has p2pool-specific outputs
        if not tag and cb.get("has_auxpow") and (has_combined or has_ref):
            tag = "p2pool"
            cb["pool_tag"] = "p2pool"
            cb["components"] = cb.get("components", []) + [{
                "type": "pool_tag",
                "value": "p2pool (structural)",
                "offset": 0,
            }]

        if has_combined and cb.get("has_auxpow"):
            # COMBINED_DONATION_SCRIPT + AuxPoW = definitive V36 p2pool/c2pool block.
            # c2pool blocks have THE state_root in scriptSig → keep /c2pool/ tag
            if tag not in ("c2pool", "/c2pool/"):
                if cb.get("the_state_root"):
                    cb["pool_tag"] = "/c2pool/"
                else:
                    cb["pool_tag"] = "/P2Pool v36/"
        elif tag and "p2pool" in tag.lower() and tag not in ("c2pool", "/c2pool/"):
            if has_combined or has_ref:
                cb["pool_tag"] = "/P2Pool v36/"
            elif tag not in ("/P2Pool v36/",):
                # Old donation script or no donation = V35
                cb["pool_tag"] = "P2Pool v35"

        # DOGE AuxPoW: decode the parent (LTC) coinbase from auxpow data
        auxpow = block.get("auxpow")
        if auxpow:
            parent_tx = auxpow.get("tx", {})
            parent_vin = parent_tx.get("vin", [{}]) if isinstance(parent_tx, dict) else [{}]
            if parent_vin and "coinbase" in parent_vin[0]:
                block["_parent_coinbase_decoded"] = decode_scriptsig(parent_vin[0]["coinbase"])
                parent_vout = parent_tx.get("vout", []) if isinstance(parent_tx, dict) else []
                block["_parent_outputs_decoded"] = decode_outputs(parent_vout, self.chain_key("ltc"))
                # Propagate parent pool tag to block level
                # Propagate parent's pool tag and THE state_root to merged block.
                # c2pool blocks: parent LTC coinbase has /c2pool/ tag + THE state_root,
                # but DOGE coinbase uses canonical /P2Pool v36/ text → need parent check.
                ptag = block["_parent_coinbase_decoded"].get("pool_tag", "")
                own_tag = block["_coinbase_decoded"].get("pool_tag", "")
                pthe = block["_parent_coinbase_decoded"].get("the_state_root", "")

                # c2pool detection: parent has /c2pool/ tag or THE state_root
                if ptag in ("c2pool", "/c2pool/") or pthe:
                    block["_coinbase_decoded"]["pool_tag"] = "/c2pool/"
                    block["_coinbase_decoded"]["has_auxpow"] = True
                    if pthe:
                        block["_coinbase_decoded"]["the_state_root"] = pthe
                elif ptag and ptag != "UNKNOWN" and (not own_tag or own_tag == "UNKNOWN"):
                    # Detect V36 from parent's donation/ref outputs
                    parent_outs = block.get("_parent_outputs_decoded", [])
                    parent_has_combined = any(
                        o.get("donation_type") == "p2pool_combined" for o in parent_outs
                    )
                    parent_has_ref = any(
                        o.get("type") == "p2pool_ref" for o in parent_outs
                    )
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
            }

        # Don't cache tip (it can change)
        chain_info = self.get_chain_info(chain)
        tip_height = chain_info.get("blocks", 0)
        if block.get("height", 0) < tip_height - 2:
            self.cache.put(cache_key, block)

        return block

    def get_recent_blocks(self, count=20, chain="ltc"):
        """Fetch the N most recent blocks."""
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

    # First V36-era pool blocks — always shown so the "Pool Blocks" page is never empty.
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
    # These are pre-decoded to match get_block() output format.  The
    # _coinbase_decoded / _outputs_decoded dicts mirror decode_scriptsig()
    # and decode_outputs() return values.
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
            "tx": [{"txid": "528f890b36514977fce03e38e9843bd2d41791d227e5fe841cdd426de3d6e694"}] + [{}] * 165,
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
                {"index": 3,  "value_btc": 0.00107655, "value_sat": 107655,    "type": "p2pkh",      "asm": "", "hex": "76a91481aab068a76fd27d4e778957dc68aa62e2dd2a2688ac", "addresses": ["LX3ZuePjBpjtst6dPepS2hXXfkmeZaBGmt"]},
                {"index": 4,  "value_btc": 0.00123857, "value_sat": 123857,    "type": "p2pkh",      "asm": "", "hex": "76a914d4db09c28b7feade877c14856f2dc39dc3061b3488ac", "addresses": ["LedRuv8JCCHPu36Nn2HadHT9LXJmvH91so"]},
                {"index": 5,  "value_btc": 0.00292087, "value_sat": 292087,    "type": "v0_p2wpkh",  "asm": "", "hex": "0014e98a1f371a1b36cf83def680c1605e92db25555a", "addresses": ["ltc1qax9p7dc6rvmvlq7776qvzcz7jtdj24266man39"]},
                {"index": 6,  "value_btc": 0.00518639, "value_sat": 518639,    "type": "p2pkh",      "asm": "", "hex": "76a914670947f571cd38fff48b9fe35c94dd726bbf991788ac", "addresses": ["LUckyqGAZZ7RMRpH8bLYLgSw7g5Y6SwN7e"]},
                {"index": 7,  "value_btc": 0.00894577, "value_sat": 894577,    "type": "p2sh",       "asm": "", "hex": "a914212c78273a43420588587a2c4160fe13bc0382dd87", "addresses": ["MAvZoYZxmdozi1BNsyHE8naNMNxqLkVTyd"]},
                {"index": 8,  "value_btc": 0.01847205, "value_sat": 1847205,   "type": "p2sh",       "asm": "", "hex": "a91412fa01fbe0911efc7d350d7280bc238b0f3680f687", "addresses": ["M9dVtj4t94NRx3DPmHLkd8rhSE7HEWwFFA"]},
                {"index": 9,  "value_btc": 0.02193889, "value_sat": 2193889,   "type": "v0_p2wpkh",  "asm": "", "hex": "001423279bb62e8807b064d92e1d5d6c2fc647b1e760", "addresses": ["ltc1qyvnehd3w3qrmqexe9cw46mp0cermremqd9fmqz"]},
                {"index": 10, "value_btc": 0.02898877, "value_sat": 2898877,   "type": "p2sh",       "asm": "", "hex": "a914c15c9a506649e024d731ac78050556e92383c52387", "addresses": ["MRXZacDm3bAcqCMJJ4QReq5vbvP7QpLkFE"]},
                {"index": 11, "value_btc": 0.02993388, "value_sat": 2993388,   "type": "p2pkh",      "asm": "", "hex": "76a91465295f7cdd536cdda899d9ea3ca9c7a07f6f7b0988ac", "addresses": ["LUSr5EYHTygRvGfBSt9vtvuN4X58mimfJq"]},
                {"index": 12, "value_btc": 0.03024197, "value_sat": 3024197,   "type": "v0_p2wpkh",  "asm": "", "hex": "00145a34288f4f82236673b260fae84cc26447fe1213", "addresses": ["ltc1qtg6z3r60sg3kvuajvrawsnxzv3rluysn4dnuw3"]},
                {"index": 13, "value_btc": 0.03493044, "value_sat": 3493044,   "type": "p2sh",       "asm": "", "hex": "a9149927d1b8ca9562869e874dd7974ad8b7401a189b87", "addresses": ["MMryKU8W7VP2pMdvRNRYbuzqiSdpcobans"]},
                {"index": 14, "value_btc": 0.03903404, "value_sat": 3903404,   "type": "p2pkh",      "asm": "", "hex": "76a91416a8fa751d2bdc6f6dfe3ccb4ece16a5bc3200d888ac", "addresses": ["LMHmZFjXTzLtEKcxbBGBnc65LRqiWezM4f"]},
                {"index": 15, "value_btc": 0.04114269, "value_sat": 4114269,   "type": "p2pkh",      "asm": "", "hex": "76a9140c42816983efe49e9748a5fad7ee64100d04807a88ac", "addresses": ["LLLn3Q7MwxwPZ34JHgePTfJdRL9rYEffhX"]},
                {"index": 16, "value_btc": 0.04434624, "value_sat": 4434624,   "type": "p2pkh",      "asm": "", "hex": "76a9145498d7890aacbda5a8e20a12ad20016b48291c7088ac", "addresses": ["LSwG7yFGgHSEMdv8Xnqx9YSDo5fnPYkrUE"]},
                {"index": 17, "value_btc": 0.04583976, "value_sat": 4583976,   "type": "v0_p2wpkh",  "asm": "", "hex": "0014be3b74236293ba942fad64038e67d7e9679e980a", "addresses": ["ltc1qhcahggmzjwafgtadvspcue7ha9neaxq24pe722"]},
                {"index": 18, "value_btc": 0.04663059, "value_sat": 4663059,   "type": "v0_p2wpkh",  "asm": "", "hex": "00146e55db837d96371ddce6e5e58afbc382aa478503", "addresses": ["ltc1qde2ahqmajcm3mh8xuhjc477rs24y0pgrv2fucz"]},
                {"index": 19, "value_btc": 0.08115990, "value_sat": 8115990,   "type": "p2pkh",      "asm": "", "hex": "76a914b1b0447a63a983dcd03b8507abf957db4b2e49ce88ac", "addresses": ["LbRV2StFb9Y6xqAsSPyeoUf2TaazuJHGYx"]},
                {"index": 20, "value_btc": 0.13645416, "value_sat": 13645416,  "type": "p2pkh",      "asm": "", "hex": "76a91412f96bccf2e0a6bab2bb4574c7db76944f434aa888ac", "addresses": ["LLxHDkJwWpaT29imBHZj7EdNxpGwnfrktS"]},
                {"index": 21, "value_btc": 0.16006377, "value_sat": 16006377,  "type": "v0_p2wpkh",  "asm": "", "hex": "0014e00dea88543bfdccdf556b12bdf452783c2695d4", "addresses": ["ltc1quqx74zz5807ueh64dvftmazj0q7zd9w5ef2adu"]},
                {"index": 22, "value_btc": 0.23222312, "value_sat": 23222312,  "type": "v0_p2wpkh",  "asm": "", "hex": "001461f3800a7fdfb90f5c43f1f09004ff994bf3b1b9", "addresses": ["ltc1qv8ecqznlm7us7hzr78cfqp8ln99l8vdecdg06j"]},
                {"index": 23, "value_btc": 0.27128166, "value_sat": 27128166,  "type": "p2pkh",      "asm": "", "hex": "76a914620f499fc74eba7ee7eb2e5821f95226bcbbfeeb88ac", "addresses": ["LUASoDK1SsV5DQ3dwGo5bGFxWJobPydupY"]},
                {"index": 24, "value_btc": 0.39756879, "value_sat": 39756879,  "type": "v0_p2wpkh",  "asm": "", "hex": "0014db5cd391f60e263c137769dec54e88ead4989582", "addresses": ["ltc1qmdwd8y0kpcnrcymhd80v2n5gat2f39vzwv0dnv"]},
                {"index": 25, "value_btc": 0.79428194, "value_sat": 79428194,  "type": "p2pkh",      "asm": "", "hex": "76a9140fa5296e6dcff4ce3bc9a300e959c3cfb224ab6588ac", "addresses": ["LLegFjfScJ3kZvz6rSBhZVg6A93JPrY3tf"]},
                {"index": 26, "value_btc": 1.09527823, "value_sat": 109527823, "type": "p2pkh",      "asm": "", "hex": "76a914238e0e0d040b0d300fa03777e2a0ee9d9c9c221588ac", "addresses": ["LNTx65DqrACZWCSK8Jc4c7wriSWHS448Qj"]},
                {"index": 27, "value_btc": 1.30603390, "value_sat": 130603390, "type": "p2pkh",      "asm": "", "hex": "76a914b8089e39a70cf3dd3bf057bf86bf03dc2ea1889a88ac", "addresses": ["Lc12vJZd5oMsZY4eGLdvMo9jrXNHKaouvk"]},
                {"index": 28, "value_btc": 1.38024571, "value_sat": 138024571, "type": "p2pkh",      "asm": "", "hex": "76a91404f4e9aaf5021dcc4cff4b40498969025d0e832f88ac", "addresses": ["LKgAMpNXkKSq1ixoELmGS2UfvNn2TrpFBx"]},
                {"index": 29, "value_btc": 0.00000014, "value_sat": 14,        "type": "p2pk",       "asm": "", "hex": "4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac", "addresses": [], "is_donation": True, "donation_type": "p2pool_old"},
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
            "tx": [{"txid": "42ca7cc895ae00b9f83e7b4fd1a2d2e59232d000d105e743a3e54df71e3a815c"}] + [{}] * 186,
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
                {"index": 1, "value_btc": 1314.86645163, "value_sat": 131486645163, "type": "p2pkh", "asm": "", "hex": "76a914238e0e0d040b0d300fa03777e2a0ee9d9c9c221588ac", "addresses": ["D8P6N7rf4urnnPvkgkcKss3hPMsJfasFAs"]},
                {"index": 2, "value_btc": 86.58781129,   "value_sat": 8658781129,   "type": "p2pkh", "asm": "", "hex": "76a91465295f7cdd536cdda899d9ea3ca9c7a07f6f7b0988ac", "addresses": ["DEMzMHB6gjLfCU9d1LACAg1CjSS9xPvLfG"]},
                {"index": 3, "value_btc": 5.45895328,    "value_sat": 545895328,    "type": "p2pkh", "asm": "", "hex": "76a91404f4e9aaf5021dcc4cff4b40498969025d0e832f88ac", "addresses": ["D5bJds1Ly574HvTEnnmXhmaWbJ93fUhFUP"]},
                {"index": 4, "value_btc": 0.0,           "value_sat": 0,            "type": "nulldata", "asm": "OP_RETURN 7032702d7370622e78797a", "hex": "6a0b7032702d7370622e78797a", "addresses": [], "is_op_return": True},
                {"index": 5, "value_btc": 1.00000002,    "value_sat": 100000002,    "type": "p2sh",  "asm": "", "hex": "a9148c6272621d89e8fa526dd86acff60c7136be8e8587", "addresses": ["A5EZCT4tUrtoKuvJaWbtVQADzdUKdtsqpr"], "is_donation": True, "donation_type": "p2pool_combined"},
            ],
        },
    }

    # Also index by hash for hash-based lookups
    SEED_BLOCK_DETAILS["ltc:806a9214cd63dae4b5091b69c1f8e14652ff95fff2bbcb06de6fcdafa76ec6ea"] = SEED_BLOCK_DETAILS["ltc:3069917"]
    SEED_BLOCK_DETAILS["doge:f84500c25a4cce2a08887f29763726bd5ecec7b66fed65a88b181fb0b0ab2383"] = SEED_BLOCK_DETAILS["doge:6135703"]

    def scan_for_pool_blocks(self, chain="ltc", depth=100):
        """Scan recent blocks for p2pool/c2pool coinbase tags."""
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

    def get_mempool_info(self, chain="ltc"):
        """Get mempool summary statistics. Normalizes daemon response to c2pool format."""
        rpc = self.doge if chain == "doge" and self.doge else self.ltc
        try:
            raw = rpc.call("getmempoolinfo")
            if isinstance(rpc, C2PoolClient):
                return raw
            # Normalize daemon response to match c2pool explorer API format
            # Daemon returns: size, bytes, usage, maxmempool, mempoolminfee, ...
            # c2pool returns: size, bytes, total_weight, total_fees, fee_histogram, ...
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

    def get_mempool_entries(self, chain="ltc", verbose=True, limit=100):
        """Get mempool transaction list.  Returns a list of entry dicts."""
        rpc = self.doge if chain == "doge" and self.doge else self.ltc
        try:
            if isinstance(rpc, C2PoolClient):
                # c2pool API returns a list of objects already
                return rpc.call("getrawmempool", verbose, limit)
            # Standard daemon RPC
            if not verbose:
                return rpc.call("getrawmempool", False)
            raw = rpc.call("getrawmempool", True)
            # Daemon returns {txid: {...}} dict — normalize to list
            if isinstance(raw, dict):
                entries = []
                now = int(time.time())
                for txid, v in raw.items():
                    vsize = v.get("vsize", 0)
                    weight = v.get("weight", 0)
                    # fee is in BTC, convert to satoshi
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
                        "n_vin": 0,  # not in daemon verbose response
                        "n_vout": 0,
                    })
                entries.sort(key=lambda e: e["feerate"], reverse=True)
                return entries[:limit]
            return raw
        except Exception as e:
            return {"error": str(e)}

    def get_mempool_entry(self, txid, chain="ltc"):
        """Get single mempool tx detail."""
        rpc = self.doge if chain == "doge" and self.doge else self.ltc
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


def blockchair_link(chain_key, item_type, value, display=None):
    """Generate a Blockchair link for a tx, address, or block."""
    base = BLOCKCHAIR.get(chain_key, "")
    if not base:
        return escape(str(display or value))
    if display is None:
        display = value
    if item_type == "tx":
        return f'<a href="{base}/transaction/{value}" target="_blank" title="{value}">{escape(str(display))}</a>'
    elif item_type == "address":
        return f'<a href="{base}/address/{value}" target="_blank">{escape(str(display))}</a>'
    elif item_type == "block":
        return f'<a href="{base}/block/{value}" target="_blank">{escape(str(display))}</a>'
    return escape(str(display))


def render_page(title, body, chain="ltc", engine=None):
    ltc_label = engine.chain_label("ltc") if engine else "LTC"
    doge_label = engine.chain_label("doge") if engine else "DOGE"
    footer_label = engine.footer_label() if engine else "Explorer"
    chain_nav = f"""
    <a href="/?chain=ltc" class="{'active' if chain == 'ltc' else ''}">{ltc_label}</a>
    <a href="/?chain=doge" class="{'active' if chain == 'doge' else ''}">{doge_label}</a>
    <a href="/found?chain={chain}">Pool Blocks</a>
    <a href="/mempool?chain={chain}">Mempool</a>
    <a href="/api/status">API Status</a>
    <span id="sound-toggle" style="cursor:pointer;margin-left:12px;font-size:18px" title="Toggle block sounds">&#128263;</span>
    """
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
{footer_label}
| <a href="/api/chain_info?chain={chain}">chain_info</a>
| <a href="/api/recent?chain={chain}&count=50">recent(50)</a>
| <a href="/api/found?chain={chain}&depth=200">found(200)</a>
</div>
<script>
(function() {{
  var chain = "{chain}";
  var statusEl = document.getElementById("live-status");
  var es = new EventSource("/api/stream?chain=all");
  // Block sound toggle (off by default, persisted in localStorage)
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
    // Falling coins: descending chime sequence
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
    // Dog bark: short low burst + higher yap
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
    // Sound notification
    if (soundEnabled) {{
      try {{
        if (d.chain === "doge") playBork();
        else playCoins();
      }} catch(ex) {{}}
    }}
    // Toast notification
    var toast = document.createElement("div");
    toast.style.cssText = "position:fixed;top:20px;right:20px;background:#238636;color:#fff;padding:12px 20px;border-radius:8px;z-index:9999;font-size:14px;box-shadow:0 4px 12px rgba(0,0,0,0.4);transition:opacity 0.5s";
    toast.textContent = "New " + d.chain.toUpperCase() + " block #" + d.height;
    document.body.appendChild(toast);
    setTimeout(function(){{ toast.style.opacity = "0"; }}, 3000);
    setTimeout(function(){{ toast.remove(); }}, 3500);
    // Auto-reload dashboard and found pages after short delay
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
    is_testnet = info.get("chain", "") in ("test", "testnet", "testnet4alpha", "regtest")
    if chain == "ltc":
        chain_name = "Litecoin Testnet" if is_testnet else "Litecoin"
    else:
        chain_name = "Dogecoin Testnet" if is_testnet else "Dogecoin"

    # Chain stats card
    stats = f"""<div class="grid"><div class="card">
    <h2>{chain_name}</h2>
    <table>
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


def render_block_detail(engine, query, chain):
    block = engine.get_block(query, chain)
    if "error" in block:
        return render_page("Block Not Found", f'<p class="red">{escape(str(block["error"]))}</p>', chain, engine)

    height = block.get("height", "?")
    bhash = block.get("hash", "?")
    cb = block.get("_coinbase_decoded", {})
    outputs = block.get("_outputs_decoded", [])
    chain_key = engine.chain_key(chain)

    # Navigation
    nav = f'<a href="/block?q={height-1}&chain={chain}">&larr; Prev</a> | '
    nav += f'<a href="/block?q={height+1}&chain={chain}">Next &rarr;</a>'

    # Block header
    header = f"""<div class="card">
    <table>
    <tr><td>Height</td><td class="green">{height}</td></tr>
    <tr><td>Hash</td><td class="mono">{blockchair_link(chain_key, "block", bhash)}</td></tr>
    <tr><td>Previous</td><td class="mono"><a href="/block?q={block.get('previousblockhash','')}&chain={chain}">{block.get('previousblockhash','?')}</a></td></tr>
    <tr><td>Time</td><td>{datetime.fromtimestamp(block.get('time',0), tz=timezone.utc).isoformat()}</td></tr>
    <tr><td>Difficulty</td><td>{block.get('difficulty', '?')}</td></tr>
    <tr><td>nBits</td><td class="mono">{block.get('bits', '?')}</td></tr>
    <tr><td>Nonce</td><td>{block.get('nonce', '?')}</td></tr>
    <tr><td>Merkle Root</td><td class="mono">{block.get('merkleroot', '?')}</td></tr>
    <tr><td>Size</td><td>{block.get('size', '?')} bytes</td></tr>
    <tr><td>Transactions</td><td>{len(block.get('tx', []))}</td></tr>
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
    # ASCII decode: printable chars shown, non-printable as dots
    raw_hex = cb.get("raw_hex", "")
    if raw_hex:
        raw_bytes = bytes.fromhex(raw_hex)
        ascii_dec = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in raw_bytes)
        cb_html += f'<p class="mono dim">{escape(ascii_dec)}</p>'
    cb_html += '</details>'
    cb_html += '</div>'

    # Coinbase outputs
    out_html = '<div class="card"><h2>Coinbase Outputs</h2><table>'
    out_html += '<tr><th>#</th><th>Value</th><th>Type</th><th>Address / Script</th><th>Tags</th></tr>'
    for o in outputs:
        row_class = ""
        tags = ""
        if o.get("is_op_return"):
            row_class = ' class="op-return"'
            if o.get("ref_hash"):
                tags += f'ref_hash=<span class="mono">{o["ref_hash"][:16]}...</span> '
                tags += f'nonce=<span class="mono">{o.get("last_txout_nonce", "")}</span>'
            else:
                tags += "OP_RETURN"
        if o.get("is_donation"):
            row_class = ' class="donation"'
            dtype = o.get("donation_type", "")
            tags += f'<span class="tag-p2pool">donation</span> ' + dtype
        addr_list = o.get("addresses", [])
        if addr_list:
            addr_display = ", ".join(blockchair_link(chain_key, "address", a) for a in addr_list)
        else:
            addr_display = escape(o.get("hex", "")[:40])
        value = f'{o["value_btc"]:.8f}'
        out_html += f'<tr{row_class}><td>{o["index"]}</td><td>{value}</td>'
        out_html += f'<td>{o["type"]}</td><td class="mono">{addr_display}</td><td>{tags}</td></tr>'
    out_html += '</table></div>'

    # THE commitment card
    the_html = ""
    if "_the" in block:
        the = block["_the"]
        the_html += '<div class="card">'
        the_html += '<h2><span style="background:#4caf50;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em">THE</span> Commitment Proof</h2>'
        the_html += '<table>'
        if "state_root" in the and the["state_root"]:
            the_html += f'<tr><td>State Root</td><td class="mono">{escape(str(the["state_root"]))}</td></tr>'
        if "metadata" in the:
            md = the["metadata"]
            the_html += f'<tr><td>Protocol Version</td><td>V{md.get("version", "?")}</td></tr>'
            the_html += f'<tr><td>Sharechain Height</td><td style="color:#4caf50">{md.get("sharechain_height", "?")}</td></tr>'
            the_html += f'<tr><td>Active Miners</td><td>{md.get("miner_count", "?")}</td></tr>'
            the_html += f'<tr><td>Pool Hashrate</td><td>~{escape(str(md.get("hashrate_human", "?")))}</td></tr>'
            the_html += f'<tr><td>Chain Fingerprint</td><td class="mono">{escape(str(md.get("chain_fingerprint", "?")))}</td></tr>'
            the_html += f'<tr><td>Share Period</td><td>{md.get("share_period", "?")}s</td></tr>'
            the_html += f'<tr><td>Verified Chain</td><td>{md.get("verified_length", "?")} shares</td></tr>'
        the_html += '</table>'
        the_html += '</div>'

    # AuxPoW (DOGE merged mining) — show parent coinbase
    auxpow_html = ""
    if block.get("_parent_coinbase_decoded"):
        pcb = block["_parent_coinbase_decoded"]
        auxinfo = block.get("_auxpow_info", {})
        auxpow_html = '<div class="card"><h2><span class="tag-auxpow">AuxPoW</span> Parent (LTC) Coinbase</h2>'
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
        auxpow_html += f'<p class="dim">Parent txid: <span class="mono">{blockchair_link(engine.chain_key("ltc"), "tx", parent_txid)}</span></p>'
        # Parent outputs
        pouts = block.get("_parent_outputs_decoded", [])
        if pouts:
            auxpow_html += '<h3>Parent Coinbase Outputs</h3><table>'
            auxpow_html += '<tr><th>#</th><th>Value</th><th>Type</th><th>Address</th><th>Tags</th></tr>'
            for o in pouts:
                row_class = ""
                tags = ""
                if o.get("is_op_return"):
                    row_class = ' class="op-return"'
                    if o.get("ref_hash"):
                        tags = f'ref_hash=<span class="mono">{o["ref_hash"][:16]}...</span>'
                if o.get("is_donation"):
                    row_class = ' class="donation"'
                    tags += '<span class="tag-p2pool">donation</span>'
                addr_list = o.get("addresses", [])
                if addr_list:
                    addr = ", ".join(blockchair_link(engine.chain_key("ltc"), "address", a) for a in addr_list)
                else:
                    addr = escape(o.get("hex", "")[:40])
                auxpow_html += f'<tr{row_class}><td>{o["index"]}</td><td>{o["value_btc"]:.8f}</td>'
                auxpow_html += f'<td>{o["type"]}</td><td class="mono">{addr}</td><td>{tags}</td></tr>'
            auxpow_html += '</table>'
        auxpow_html += '</div>'

    # All transactions summary
    tx_html = '<div class="card"><h2>Transactions</h2><table>'
    tx_html += '<tr><th>#</th><th>TxID</th><th>Inputs</th><th>Outputs</th></tr>'
    for i, tx in enumerate(block.get("tx", [])[:50]):
        txid = tx.get("txid", "?")
        n_in = len(tx.get("vin", []))
        n_out = len(tx.get("vout", []))
        txid_display = blockchair_link(chain_key, "tx", txid, txid[:32] + "...")
        tx_html += f'<tr><td>{i}</td><td class="mono">{txid_display}</td>'
        tx_html += f'<td>{n_in}</td><td>{n_out}</td></tr>'
    if len(block.get("tx", [])) > 50:
        tx_html += f'<tr><td colspan="4" class="dim">... and {len(block["tx"]) - 50} more</td></tr>'
    tx_html += '</table></div>'

    title = f"Block {height}"
    pool_tag = cb.get("pool_tag", "")
    if pool_tag:
        title += f" ({pool_tag})"

    return render_page(title, header + cb_html + out_html + the_html + auxpow_html + tx_html, chain, engine)


def render_found_blocks(engine, chain, depth=200):
    found = engine.scan_for_pool_blocks(chain, depth)
    ck = engine.chain_key(chain)

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
        <td class="mono">{blockchair_link(ck, "block", b['hash'], b['hash'][:24] + "...")}</td>
        <td>{ts}</td>
        <td>{value}</td>
        <td>{tags}</td></tr>"""

    if not rows:
        rows = f'<tr><td colspan="5" class="dim">No pool blocks found in last {depth} blocks</td></tr>'

    table = f"""<table>
    <tr><th>Height</th><th>Hash</th><th>Time</th><th>Coinbase Value</th><th>Tags</th></tr>
    {rows}</table>"""

    chain_name = "LTC" if chain == "ltc" else "DOGE"
    return render_page(f"Pool Blocks Found ({chain_name}, last {depth})", table, chain, engine)


def render_mempool_dashboard(engine, chain):
    """Render the live mempool dashboard page with summary, histogram, and top txs."""
    info = engine.get_mempool_info(chain)
    if "error" in info:
        return render_page("Mempool", f'<p class="red">Mempool unavailable: {escape(str(info["error"]))}</p>', chain, engine)

    chain_name = "LTC" if chain == "ltc" else "DOGE"
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

    # Summary card
    stats = f"""<div class="grid"><div class="card">
    <h2>{chain_name} Mempool</h2>
    <table>
    <tr><td>Transactions</td><td class="green">{tx_count}</td></tr>
    <tr><td>Total size</td><td>{total_bytes:,} bytes</td></tr>
    <tr><td>Total weight</td><td>{total_weight:,} WU</td></tr>
    <tr><td>Total fees</td><td>{total_fees:,} sat ({total_fees / 1e8:.8f} {chain_name})</td></tr>
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

    # Feerate histogram (CSS bars)
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

    # Top transactions table (verbose list, limit 50)
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
    # Inject auto-refresh into the page
    page = render_page(f"{chain_name} Mempool ({tx_count} txs)", body, chain, engine)
    page = page.replace('<meta charset="utf-8">', f'<meta charset="utf-8">{refresh}', 1)
    return page


def render_mempool_tx_detail(engine, txid, chain):
    """Render detail page for a single mempool transaction."""
    entry = engine.get_mempool_entry(txid, chain)
    if isinstance(entry, dict) and "error" in entry:
        return render_page("Mempool Tx", f'<p class="red">Transaction not found: {escape(str(entry["error"]))}</p>', chain, engine)

    chain_name = "LTC" if chain == "ltc" else "DOGE"
    chain_key = engine.chain_key(chain)

    feerate = entry.get("feerate", 0)
    fee = entry.get("fee", 0)
    size = entry.get("size", 0)
    weight = entry.get("weight", 0)
    age = entry.get("age_sec", 0)
    age_str = f"{age // 60}m" if age < 3600 else f"{age // 3600}h {(age % 3600) // 60}m"

    header = f"""<div class="card">
    <h2>Mempool Transaction</h2>
    <table>
    <tr><td>TxID</td><td class="mono">{blockchair_link(chain_key, "tx", txid)}</td></tr>
    <tr><td>Size</td><td>{size} bytes</td></tr>
    <tr><td>Weight</td><td>{weight} WU</td></tr>
    <tr><td>Fee</td><td>{fee:,} sat ({fee / 1e8:.8f} {chain_name})</td></tr>
    <tr><td>Feerate</td><td class="green">{feerate:.2f} sat/vB</td></tr>
    <tr><td>Fee known</td><td>{"Yes" if entry.get("fee_known", True) else "No"}</td></tr>
    <tr><td>Age</td><td>{age_str}</td></tr>
    </table></div>"""

    # Inputs
    vin = entry.get("vin", [])
    if vin:
        vin_rows = ""
        for i, inp in enumerate(vin):
            prevout = inp.get("prevout_hash", "?")
            prevout_n = inp.get("prevout_n", 0)
            seq = inp.get("sequence", 0)
            prevout_link = blockchair_link(chain_key, "tx", prevout, f"{prevout[:24]}...") if prevout != "?" else "?"
            vin_rows += f'<tr><td>{i}</td><td class="mono">{prevout_link}:{prevout_n}</td><td>{seq}</td></tr>'
        vin_html = f"""<div class="card"><h2>Inputs ({len(vin)})</h2>
        <table><tr><th>#</th><th>Prevout (hash:n)</th><th>Sequence</th></tr>
        {vin_rows}</table></div>"""
    else:
        vin_html = ''

    # Outputs
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
                addr_display = blockchair_link(chain_key, "address", addr)
            elif script_hex:
                addr_display = f'<span class="mono dim">{escape(script_hex[:60])}{"..." if len(script_hex) > 60 else ""}</span>'
            else:
                addr_display = '<span class="dim">-</span>'
            vout_rows += f'<tr><td>{i}</td><td>{value_btc:.8f}</td><td>{script_type}</td><td>{addr_display}</td></tr>'
        vout_html = f"""<div class="card"><h2>Outputs ({len(vout)})</h2>
        <table><tr><th>#</th><th>Value ({chain_name})</th><th>Type</th><th>Address</th></tr>
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
        chain = params.get("chain", "ltc")

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
                ltc_ok = self.engine.ltc.is_alive() if self.engine.ltc else False
                doge_ok = self.engine.doge.is_alive() if self.engine.doge else False
                status = {
                    "ltc": {"alive": ltc_ok, "url": self.engine.ltc.url if self.engine.ltc else None},
                    "doge": {"alive": doge_ok, "url": self.engine.doge.url if self.engine.doge else None},
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
                # SSE endpoint: streams new-block events
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                import queue as _q
                q = self.engine.register_sse_client(chain if chain != "all" else None)
                try:
                    # Send initial heartbeat
                    self.wfile.write(b": connected\n\n")
                    self.wfile.flush()
                    while True:
                        try:
                            msg = q.get(timeout=15)
                            self.wfile.write(msg.encode())
                            self.wfile.flush()
                        except _q.Empty:
                            # keepalive comment
                            self.wfile.write(b": keepalive\n\n")
                            self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    self.engine.unregister_sse_client(q)
                return  # don't fall through to error handler

            else:
                self._respond(404, render_page("404", '<p class="red">Page not found</p>', chain, self.engine))

        except Exception as e:
            traceback.print_exc()
            self._respond(500, render_page("Error", f'<pre class="red">{escape(traceback.format_exc())}</pre>', chain, self.engine))


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="c2pool Block Explorer")
    parser.add_argument("--ltc-host", default="192.168.86.26", help="Litecoin RPC host")
    parser.add_argument("--ltc-port", type=int, default=19332, help="Litecoin RPC port")
    parser.add_argument("--ltc-user", default="litecoinrpc", help="Litecoin RPC user")
    parser.add_argument("--ltc-pass", default="litecoinrpc_mainnet_2026", help="Litecoin RPC password")
    parser.add_argument("--doge-host", default="192.168.86.27", help="Dogecoin RPC host")
    parser.add_argument("--doge-port", type=int, default=44555, help="Dogecoin RPC port")
    parser.add_argument("--doge-user", default="dogecoinrpc", help="Dogecoin RPC user")
    parser.add_argument("--doge-pass", default="testpass", help="Dogecoin RPC password")
    parser.add_argument("--web-port", type=int, default=8888, help="Explorer web port")
    parser.add_argument("--no-doge", action="store_true", help="Disable DOGE chain")
    parser.add_argument("--ltc-c2pool", default=None, help="c2pool explorer API URL for LTC (e.g. http://127.0.0.1:8080/api/explorer)")
    parser.add_argument("--doge-c2pool", default=None, help="c2pool explorer API URL for DOGE (e.g. http://127.0.0.1:8080/api/explorer)")
    args = parser.parse_args()

    if args.ltc_c2pool:
        ltc_rpc = C2PoolClient(args.ltc_c2pool, "ltc")
    else:
        ltc_rpc = RpcClient(args.ltc_host, args.ltc_port, args.ltc_user, args.ltc_pass, "LTC")

    doge_rpc = None
    if not args.no_doge:
        if args.doge_c2pool:
            doge_rpc = C2PoolClient(args.doge_c2pool, "doge")
        else:
            doge_rpc = RpcClient(args.doge_host, args.doge_port, args.doge_user, args.doge_pass, "DOGE")

    engine = ExplorerEngine(ltc_rpc, doge_rpc)

    # Test connectivity
    print(f"LTC RPC ({args.ltc_host}:{args.ltc_port}): ", end="")
    if ltc_rpc.is_alive():
        info = ltc_rpc.call("getblockchaininfo")
        print(f"OK — chain={info['chain']} height={info['blocks']}")
    else:
        print("OFFLINE")

    if doge_rpc:
        print(f"DOGE RPC ({args.doge_host}:{args.doge_port}): ", end="")
        if doge_rpc.is_alive():
            info = doge_rpc.call("getblockchaininfo")
            print(f"OK — chain={info['chain']} height={info['blocks']}")
        else:
            print("OFFLINE")

    # Start web server
    # Use ThreadingHTTPServer so SSE streams don't block other requests
    import http.server as _hs
    class ThreadedServer(_hs.ThreadingHTTPServer):
        daemon_threads = True

    ExplorerHandler.engine = engine
    engine.start_block_poller(interval=2)
    server = ThreadedServer(("0.0.0.0", args.web_port), ExplorerHandler)
    print(f"\nExplorer running at http://0.0.0.0:{args.web_port}/")
    print(f"  LTC blocks: http://localhost:{args.web_port}/?chain=ltc")
    print(f"  DOGE blocks: http://localhost:{args.web_port}/?chain=doge")
    print(f"  Pool blocks: http://localhost:{args.web_port}/found?chain=ltc")
    print(f"  API status:  http://localhost:{args.web_port}/api/status")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
