#!/usr/bin/env python3
# Copyright (c) 2026 Alec <frstrtr@gmail.com>
# Distributed under the MIT software license.
"""
dash_collateral_tx.py -- offline Dash governance-proposal collateral transaction builder.

Builds, and optionally signs, the 1-DASH proof-of-burn collateral transaction that a
Dash governance proposal (gobject) requires, WITHOUT a wallet and WITHOUT ever
letting the mnemonic touch disk, the network, or the process arguments.

The collateral commitment is derived byte-exactly from the Dash Core sources
(dashpay/dash @ 728f5055836c6d29806412fc7223ac8fe05af991):

  src/governance/common.cpp:23-39  Governance::Object::GetHash()
      CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
      ss << hashParent;                                    // uint256, 32 raw bytes
      ss << revision;                                      // int32,  4 bytes LE
      ss << time;                                          // int64,  8 bytes LE
      ss << HexStr(vchData);                               // compactsize + lowercase hex ASCII
      ss << masternodeOutpoint << uint8_t{} << 0xffffffff; // null outpoint (32x00 + ffffffff)
                                                           //  + dummy 0x00 + ffffffff
                                                           //  ("to match old hashing", i.e. the
                                                           //   legacy CTxIn empty-scriptSig+sequence)
      ss << vchSig;                                        // compactsize(0) for proposals
      return ss.GetHash();                                 // double-SHA256

  src/governance/object.cpp:454-540  CGovernanceObject::IsCollateralValid()
      :460  uint256 nExpectedHash = GetHash();
      :488  CScript findScript;
      :489  findScript << OP_RETURN << ToByteVector(nExpectedHash);
      :505  if (output.scriptPubKey == findScript && output.nValue >= nMinFee) ...

  src/governance/object.h:30   GOVERNANCE_PROPOSAL_FEE_TX = 1 * COIN
  src/governance/object.h:31   GOVERNANCE_FEE_CONFIRMATIONS = 6

ToByteVector(uint256) yields the *internal* byte order, i.e. the reverse of the
displayed hash hex -- the OP_RETURN push in this script honours that.

SECURITY MODEL
  * The mnemonic (and optional BIP39 passphrase) are read via getpass -- never from
    argv, never echoed, never logged, never written anywhere.
  * The signing key is derived in memory (BIP39 -> BIP44 m/44'/5'/0'/{0,1}/i, Dash
    coin type 5'), used, then best-effort zeroized.  CPython cannot guarantee that
    no copy survives (immutable bytes, GC); run on a trusted, offline machine.
  * The tool ABORTS unless one scanned derivation index produces EXACTLY the
    expected funding address (double-checked through an independent base58
    implementation) -- a wrong path or index can never silently sign.
  * Every selected UTXO's scriptPubKey must equal P2PKH(funding address); anything
    else aborts before signing.
  * Signatures are produced deterministically (RFC 6979), DER-encoded, low-S,
    SIGHASH_ALL, and verified against the public key before the tx is emitted.
  * The ONLY output ever printed is public data: the collateral hash, the dry-run
    summary and the signed raw transaction hex.

THIS TRANSACTION SPENDS REAL FUNDS. 1 DASH is provably burned (OP_RETURN).
Always run with --dry-run first and read the summary.
"""

import argparse
import getpass
import hashlib
import json
import struct
import sys
import urllib.request

# ---------------------------------------------------------------------------
# Vetted third-party libs: bip_utils (BIP39/BIP44), coincurve or ecdsa (signing)
# ---------------------------------------------------------------------------
try:
    from bip_utils import Bip39SeedGenerator, Bip44, Bip44Changes, Bip44Coins
except ImportError:  # pragma: no cover
    sys.stderr.write("ERROR: pip install bip_utils\n")
    sys.exit(2)

_HAVE_COINCURVE = False
try:
    import coincurve

    _HAVE_COINCURVE = True
except ImportError:
    try:
        import ecdsa
        from ecdsa.util import sigencode_der_canonize
    except ImportError:  # pragma: no cover
        sys.stderr.write("ERROR: pip install coincurve (preferred) or ecdsa\n")
        sys.exit(2)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
COIN = 100_000_000  # duffs per DASH
GOVERNANCE_PROPOSAL_FEE_TX = 1 * COIN  # governance/object.h:30
DUST_DUFFS = 5460  # conservative P2PKH dust threshold
DEFAULT_FEE_RATE = 1000  # duffs per kB (Dash default min relay fee)
DEFAULT_MIN_CONF = 101  # donation UTXOs are coinbase outputs: 100-block maturity
SIGHASH_ALL = 0x01
OP_RETURN = 0x6A
OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG = 0x76, 0xA9, 0x88, 0xAC

MAINNET_P2PKH_VERSION = 0x4C  # addresses start with 'X'
TESTNET_P2PKH_VERSION = 0x8C  # addresses start with 'y'

MAINNET_INSIGHT = "https://insight.dash.org/insight-api"
TESTNET_INSIGHT = "https://testnet-insight.dashevo.org/insight-api"

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class Abort(Exception):
    """Fatal, operator-facing error. Never carries secret material."""


# ---------------------------------------------------------------------------
# Hashing / base58 primitives (independent of bip_utils, used for cross-checks)
# ---------------------------------------------------------------------------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))


def hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", sha256(b)).digest()


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58_ALPHABET[r] + out
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        idx = _B58_ALPHABET.find(c)
        if idx < 0:
            raise Abort(f"invalid base58 character {c!r}")
        n = n * 58 + idx
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


def b58check_encode(version: int, payload: bytes) -> str:
    raw = bytes([version]) + payload
    return b58encode(raw + sha256d(raw)[:4])


def b58check_decode(s: str) -> tuple:
    raw = b58decode(s)
    if len(raw) < 5:
        raise Abort(f"address too short: {s}")
    body, checksum = raw[:-4], raw[-4:]
    if sha256d(body)[:4] != checksum:
        raise Abort(f"bad base58 checksum in address {s}")
    return body[0], body[1:]


def addr_to_h160(addr: str, testnet: bool) -> bytes:
    version, payload = b58check_decode(addr)
    expected = TESTNET_P2PKH_VERSION if testnet else MAINNET_P2PKH_VERSION
    if version != expected:
        raise Abort(
            f"address {addr} has version byte {version}, expected {expected} "
            f"({'testnet' if testnet else 'mainnet'} P2PKH) -- wrong network or address type"
        )
    if len(payload) != 20:
        raise Abort(f"address {addr} payload is {len(payload)} bytes, expected 20")
    return payload


def h160_to_addr(h160: bytes, testnet: bool) -> str:
    version = TESTNET_P2PKH_VERSION if testnet else MAINNET_P2PKH_VERSION
    return b58check_encode(version, h160)


def p2pkh_script(h160: bytes) -> bytes:
    return bytes([OP_DUP, OP_HASH160, 20]) + h160 + bytes([OP_EQUALVERIFY, OP_CHECKSIG])


# ---------------------------------------------------------------------------
# Bitcoin/Dash serialization primitives
# ---------------------------------------------------------------------------
def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def ser_string(b: bytes) -> bytes:
    return compact_size(len(b)) + b


# ---------------------------------------------------------------------------
# Governance object collateral hash (see module docstring for the source cites)
# ---------------------------------------------------------------------------
def gov_object_hash(parent_hash_hex: str, revision: int, time_: int, data_hex: str) -> bytes:
    """Governance::Object::GetHash() -- governance/common.cpp:23-39.

    Returns the hash in INTERNAL byte order (what ToByteVector(uint256) yields and
    what the OP_RETURN push must contain). Display order = reversed.
    """
    parent = bytes.fromhex(parent_hash_hex)
    if len(parent) != 32:
        raise Abort("parent hash must be 32 bytes of hex")
    data_hex = data_hex.strip().lower()
    try:
        bytes.fromhex(data_hex)
    except ValueError:
        raise Abort("data-hex is not valid hex")
    ss = b""
    ss += parent[::-1]  # uint256 internal order (input given in display order)
    ss += struct.pack("<i", revision)  # int32 LE
    ss += struct.pack("<q", time_)  # int64 LE
    ss += ser_string(data_hex.encode("ascii"))  # HexStr(vchData) as std::string
    # null masternodeOutpoint: uint256() + n=(uint32)-1   (proposals carry none)
    ss += b"\x00" * 32 + b"\xff\xff\xff\xff"
    # dummy uint8_t{} + 0xffffffff -- common.cpp:34 "to match old hashing"
    ss += b"\x00" + b"\xff\xff\xff\xff"
    # empty vchSig (proposals are unsigned)
    ss += b"\x00"
    return sha256d(ss)


def collateral_op_return_script(gov_hash_internal: bytes) -> bytes:
    """CScript() << OP_RETURN << ToByteVector(nExpectedHash) -- object.cpp:488-489."""
    assert len(gov_hash_internal) == 32
    return bytes([OP_RETURN, 32]) + gov_hash_internal


# ---------------------------------------------------------------------------
# Transaction model
# ---------------------------------------------------------------------------
class TxBuilder:
    """Classic (pre-DIP2, type 0) Dash transaction: version 2, no extra payload."""

    def __init__(self):
        self.version = 2  # lower 16 bits version, upper 16 bits type (0 = classic)
        self.inputs = []  # dicts: txid (display hex), vout, script_pubkey (bytes), value
        self.outputs = []  # dicts: value, script (bytes)
        self.locktime = 0
        self.sigs = {}  # input index -> (der_sig_with_hashtype, pubkey_bytes)

    def add_input(self, txid: str, vout: int, script_pubkey: bytes, value: int):
        self.inputs.append(
            {"txid": txid, "vout": vout, "script_pubkey": script_pubkey, "value": value}
        )

    def add_output(self, value: int, script: bytes):
        self.outputs.append({"value": value, "script": script})

    def _ser_input(self, i: int, script_sig: bytes) -> bytes:
        inp = self.inputs[i]
        return (
            bytes.fromhex(inp["txid"])[::-1]
            + struct.pack("<I", inp["vout"])
            + ser_string(script_sig)
            + b"\xff\xff\xff\xff"
        )

    def _ser_outputs(self) -> bytes:
        out = compact_size(len(self.outputs))
        for o in self.outputs:
            out += struct.pack("<q", o["value"]) + ser_string(o["script"])
        return out

    def sighash(self, index: int) -> bytes:
        """Legacy SIGHASH_ALL preimage double-SHA256 for input `index`."""
        pre = struct.pack("<I", self.version)
        pre += compact_size(len(self.inputs))
        for i in range(len(self.inputs)):
            script = self.inputs[i]["script_pubkey"] if i == index else b""
            pre += self._ser_input(i, script)
        pre += self._ser_outputs()
        pre += struct.pack("<I", self.locktime)
        pre += struct.pack("<I", SIGHASH_ALL)
        return sha256d(pre)

    def serialize(self, signed: bool) -> bytes:
        raw = struct.pack("<I", self.version)
        raw += compact_size(len(self.inputs))
        for i in range(len(self.inputs)):
            if signed:
                sig, pub = self.sigs[i]
                script_sig = bytes([len(sig)]) + sig + bytes([len(pub)]) + pub
            else:
                script_sig = b""
            raw += self._ser_input(i, script_sig)
        raw += self._ser_outputs()
        raw += struct.pack("<I", self.locktime)
        return raw

    def txid(self) -> str:
        return sha256d(self.serialize(signed=True))[::-1].hex()

    def estimate_size(self, n_inputs: int, with_change: bool) -> int:
        # 4 version + varint(nin) + nin*148 (P2PKH input worst case)
        # + varint(nout) + 43 (OP_RETURN out: 8+1+34) + 34 (P2PKH change out) + 4 locktime
        n_out = 2 if with_change else 1
        return (
            4
            + len(compact_size(n_inputs))
            + n_inputs * 148
            + len(compact_size(n_out))
            + 43
            + (34 if with_change else 0)
            + 4
        )


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------
def _der_is_low_s(der: bytes) -> bool:
    """Parse DER (r,s), return True if s <= n/2."""
    try:
        if der[0] != 0x30:
            return False
        rlen = der[3]
        s_off = 4 + rlen
        if der[s_off] != 0x02:
            return False
        slen = der[s_off + 1]
        s = int.from_bytes(der[s_off + 2 : s_off + 2 + slen], "big")
        return 1 <= s <= SECP256K1_N // 2
    except IndexError:
        return False


def sign_digest(priv32: bytes, digest: bytes) -> bytes:
    """RFC6979-deterministic ECDSA over secp256k1, DER, low-S enforced."""
    if _HAVE_COINCURVE:
        der = coincurve.PrivateKey(priv32).sign(digest, hasher=None)
    else:
        sk = ecdsa.SigningKey.from_string(priv32, curve=ecdsa.SECP256k1)
        der = sk.sign_digest_deterministic(
            digest, hashfunc=hashlib.sha256, sigencode=sigencode_der_canonize
        )
    if not _der_is_low_s(der):
        raise Abort("signature is not low-S; refusing to emit non-standard signature")
    return der


def verify_digest(pub: bytes, der: bytes, digest: bytes) -> bool:
    if _HAVE_COINCURVE:
        try:
            return coincurve.PublicKey(pub).verify(der, digest, hasher=None)
        except Exception:
            return False
    try:
        vk = ecdsa.VerifyingKey.from_string(pub, curve=ecdsa.SECP256k1)
        return vk.verify_digest(der, digest, sigdecode=ecdsa.util.sigdecode_der)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Key derivation: scan m/44'/{5|1}'/account'/{0[,1]}/i for the funding address
# ---------------------------------------------------------------------------
def find_key_for_address(
    mnemonic: str,
    passphrase: str,
    address: str,
    testnet: bool,
    account: int,
    scan_limit: int,
    scan_internal: bool,
):
    """Returns (priv32, pub33, path_str). ABORTS if no index matches."""
    expected_h160 = addr_to_h160(address, testnet)
    coin = Bip44Coins.DASH_TESTNET if testnet else Bip44Coins.DASH
    coin_type = 1 if testnet else 5
    seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)  # validates checksum
    acct = Bip44.FromSeed(seed, coin).Purpose().Coin().Account(account)
    chains = [(0, Bip44Changes.CHAIN_EXT)] + ([(1, Bip44Changes.CHAIN_INT)] if scan_internal else [])
    try:
        for chain_no, chain in chains:
            node = acct.Change(chain)
            for i in range(scan_limit):
                leaf = node.AddressIndex(i)
                pub = bytes(leaf.PublicKey().RawCompressed().ToBytes())
                if hash160(pub) == expected_h160:
                    # independent cross-checks: our own encoder AND bip_utils agree
                    ours = h160_to_addr(hash160(pub), testnet)
                    lib_addr = leaf.PublicKey().ToAddress()
                    if ours != address or lib_addr != address:
                        raise Abort(
                            "internal cross-check failed: derived address encodings disagree "
                            f"(independent={ours}, bip_utils={lib_addr}, expected={address})"
                        )
                    priv = bytearray(leaf.PrivateKey().Raw().ToBytes())
                    path = f"m/44'/{coin_type}'/{account}'/{chain_no}/{i}"
                    return priv, pub, path
        raise Abort(
            f"no derivation index in m/44'/{coin_type}'/{account}'/{{0"
            + (",1" if scan_internal else "")
            + f"}}/0..{scan_limit - 1} produces {address}. "
            "REFUSING TO SIGN. Check the mnemonic/passphrase, or widen --scan-limit / "
            "--account / --scan-internal."
        )
    finally:
        # best-effort zeroization of the seed copy we control
        if isinstance(seed, (bytes, bytearray)):
            seed = None


# ---------------------------------------------------------------------------
# UTXOs
# ---------------------------------------------------------------------------
def fetch_utxos(address: str, insight_url: str) -> list:
    url = f"{insight_url.rstrip('/')}/addr/{address}/utxo"
    req = urllib.request.Request(url, headers={"User-Agent": "dash-collateral-tx/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read().decode("utf-8"))
    if not isinstance(data, list):
        raise Abort(f"unexpected UTXO response from {url}")
    return data


def normalize_utxos(raw: list, expected_script: bytes, min_conf: int) -> list:
    """Validate + normalize insight-style UTXOs. ABORT on any foreign script."""
    out = []
    skipped_immature = 0
    for u in raw:
        txid = u.get("txid")
        vout = u.get("vout")
        sats = u.get("satoshis")
        if sats is None and "amount" in u:
            sats = round(float(u["amount"]) * COIN)
        conf = u.get("confirmations", 0)
        spk = u.get("scriptPubKey", "")
        if not (isinstance(txid, str) and len(txid) == 64 and isinstance(vout, int) and isinstance(sats, int)):
            raise Abort(f"malformed UTXO entry: {json.dumps(u)[:200]}")
        bytes.fromhex(txid)
        if spk:
            if bytes.fromhex(spk) != expected_script:
                raise Abort(
                    f"UTXO {txid}:{vout} scriptPubKey {spk} does NOT pay the funding "
                    "address -- refusing to touch it"
                )
        if conf < min_conf:
            skipped_immature += 1
            continue
        out.append({"txid": txid, "vout": vout, "satoshis": sats, "confirmations": conf})
    if skipped_immature:
        print(
            f"note: skipped {skipped_immature} UTXO(s) below --min-confirmations {min_conf} "
            "(coinbase outputs need 100-block maturity)"
        )
    return out


def select_coins(utxos: list, feerate_per_kb: int, txb_probe: TxBuilder) -> tuple:
    """Largest-first accumulation until 1 DASH + fee is covered.

    Returns (selected_utxos, fee, change). Dust change is folded into the fee.
    """
    pool = sorted(utxos, key=lambda u: -u["satoshis"])
    selected = []
    total = 0
    for u in pool:
        selected.append(u)
        total += u["satoshis"]
        size = txb_probe.estimate_size(len(selected), with_change=True)
        fee = max((size * feerate_per_kb + 999) // 1000, 1000)
        need = GOVERNANCE_PROPOSAL_FEE_TX + fee
        if total >= need:
            change = total - need
            if change < DUST_DUFFS:
                # drop the change output; the remainder becomes fee
                size_nc = txb_probe.estimate_size(len(selected), with_change=False)
                fee_nc = max((size_nc * feerate_per_kb + 999) // 1000, 1000)
                if total - GOVERNANCE_PROPOSAL_FEE_TX >= fee_nc:
                    return selected, total - GOVERNANCE_PROPOSAL_FEE_TX, 0
                continue  # need one more input
            return selected, fee, change
    raise Abort(
        f"INSUFFICIENT FUNDS: mature UTXOs total {total / COIN:.8f} DASH, "
        f"need 1 DASH collateral + fee. Nothing was signed."
    )


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Offline Dash governance-proposal collateral tx builder (see README)."
    )
    p.add_argument("--address", required=True, help="funding (donation) P2PKH address")
    p.add_argument("--data-hex", required=True, help="gobject data hex (bare JSON object form)")
    p.add_argument("--time", required=True, type=int, help="gobject creation time (unix epoch)")
    p.add_argument("--revision", type=int, default=1, help="gobject revision (default 1)")
    p.add_argument("--parent-hash", default="00" * 32, help="gobject parent hash (default 0)")
    p.add_argument(
        "--expected-hash",
        help="optional cross-check: displayed gobject hash you expect (from `gobject check` "
        "or a prepared object); ABORTS on mismatch",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--fetch-utxos", action="store_true", help="fetch UTXOs from an insight API")
    src.add_argument("--utxos", help="path to a JSON file with insight-style UTXOs (offline mode)")
    p.add_argument("--insight-url", help="override the insight API base URL")
    p.add_argument("--change-address", help="change address (default: the funding address)")
    p.add_argument(
        "--fee-rate", type=int, default=DEFAULT_FEE_RATE, help="duffs per kB (default 1000)"
    )
    p.add_argument(
        "--min-confirmations",
        type=int,
        default=DEFAULT_MIN_CONF,
        help=f"minimum UTXO confirmations (default {DEFAULT_MIN_CONF}: donation UTXOs are "
        "coinbase outputs and need 100-block maturity)",
    )
    p.add_argument("--account", type=int, default=0, help="BIP44 account (default 0)")
    p.add_argument("--scan-limit", type=int, default=200, help="derivation indices to scan")
    p.add_argument("--scan-internal", action="store_true", help="also scan the change chain (m/.../1/i)")
    p.add_argument("--dry-run", action="store_true", help="summarize only; never asks for the mnemonic")
    p.add_argument("--testnet", action="store_true", help="Dash testnet (coin type 1', 'y' addresses)")
    p.add_argument(
        "--yes-i-know-this-spends-real-funds",
        action="store_true",
        help="skip the interactive SPEND confirmation (for scripted testnet use ONLY)",
    )
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        return _run(args)
    except Abort as e:
        print(f"\nABORT: {e}", file=sys.stderr)
        return 1


def _run(args) -> int:
    if args.fee_rate < 100 or args.fee_rate > 100_000:
        raise Abort(f"--fee-rate {args.fee_rate} duffs/kB is outside the sane range [100, 100000]")
    if args.time <= 1_400_000_000:
        raise Abort(f"--time {args.time} does not look like a recent unix epoch")
    if args.revision < 1:
        raise Abort("--revision must be >= 1")

    funding_h160 = addr_to_h160(args.address, args.testnet)
    funding_script = p2pkh_script(funding_h160)
    change_addr = args.change_address or args.address
    change_script = p2pkh_script(addr_to_h160(change_addr, args.testnet))

    # ---- 1. collateral hash -------------------------------------------------
    gov_hash = gov_object_hash(args.parent_hash, args.revision, args.time, args.data_hex)
    gov_hash_display = gov_hash[::-1].hex()
    if args.expected_hash and args.expected_hash.lower() != gov_hash_display:
        raise Abort(
            f"derived collateral hash {gov_hash_display} != --expected-hash "
            f"{args.expected_hash.lower()} -- the OP_RETURN would commit to the WRONG object"
        )
    op_return_script = collateral_op_return_script(gov_hash)

    # friendly echo of the proposal payload, if it parses
    proposal_note = ""
    try:
        pj = json.loads(bytes.fromhex(args.data_hex.strip()).decode("utf-8"))
        proposal_note = (
            f"  name:            {pj.get('name')}\n"
            f"  payment_address: {pj.get('payment_address')}\n"
            f"  payment_amount:  {pj.get('payment_amount')}\n"
            f"  url:             {pj.get('url')}\n"
        )
    except Exception:
        proposal_note = "  (data-hex is not JSON -- check it is the bare-object form)\n"

    # ---- 2. UTXOs -----------------------------------------------------------
    if args.fetch_utxos:
        insight = args.insight_url or (TESTNET_INSIGHT if args.testnet else MAINNET_INSIGHT)
        raw_utxos = fetch_utxos(args.address, insight)
    else:
        with open(args.utxos) as f:
            raw_utxos = json.load(f)
    utxos = normalize_utxos(raw_utxos, funding_script, args.min_confirmations)
    if not utxos:
        raise Abort("no spendable UTXOs after maturity filtering")

    # ---- 3. coin selection + unsigned tx -------------------------------------
    probe = TxBuilder()
    selected, fee, change = select_coins(utxos, args.fee_rate, probe)

    txb = TxBuilder()
    for u in selected:
        txb.add_input(u["txid"], u["vout"], funding_script, u["satoshis"])
    txb.add_output(GOVERNANCE_PROPOSAL_FEE_TX, op_return_script)
    if change > 0:
        txb.add_output(change, change_script)

    total_in = sum(u["satoshis"] for u in selected)
    est_size = txb.estimate_size(len(selected), with_change=change > 0)

    # ---- 4. dry-run summary ---------------------------------------------------
    net = "TESTNET" if args.testnet else "MAINNET"
    print("=" * 74)
    print(f"DASH GOVERNANCE COLLATERAL TX -- DRY-RUN SUMMARY ({net})")
    print("=" * 74)
    print("proposal payload:")
    print(proposal_note, end="")
    print(f"gobject params:    parent={args.parent_hash} revision={args.revision} time={args.time}")
    print(f"collateral hash:   {gov_hash_display}")
    print("                   (use this as the <collateral-hash> argument of `gobject submit`)")
    print(f"OP_RETURN script:  {op_return_script.hex()}")
    print(f"inputs ({len(selected)}):")
    for u in selected:
        print(f"  {u['txid']}:{u['vout']}  {u['satoshis'] / COIN:.8f} DASH  ({u['confirmations']} conf)")
    print(f"total in:          {total_in / COIN:.8f} DASH")
    print(f"output 0 (BURN):   {GOVERNANCE_PROPOSAL_FEE_TX / COIN:.8f} DASH  OP_RETURN <collateral hash>")
    if change > 0:
        print(f"output 1 (change): {change / COIN:.8f} DASH  -> {change_addr}")
    else:
        print("output 1:          (no change output; sub-dust remainder folded into fee)")
    print(f"fee:               {fee / COIN:.8f} DASH ({fee} duffs, ~{est_size} B est, "
          f"{args.fee_rate} duffs/kB requested)")
    print("-" * 74)
    print("WARNING: this transaction SPENDS REAL DONATION FUNDS and irreversibly")
    print("         BURNS 1 DASH as governance collateral once broadcast.")
    print("=" * 74)

    if args.dry_run:
        print("--dry-run: stopping before key derivation. Nothing was signed.")
        return 0

    # ---- 5. key derivation (secure input) -------------------------------------
    if not sys.stdin.isatty() and not args.yes_i_know_this_spends_real_funds:
        raise Abort("stdin is not a TTY; refusing to read a mnemonic non-interactively")
    print("\nEnter the BIP39 mnemonic for the funding address (input is hidden, never stored):")
    mnemonic = getpass.getpass("mnemonic: ").strip()
    passphrase = getpass.getpass("BIP39 passphrase (empty for none): ")
    if not mnemonic:
        raise Abort("empty mnemonic")

    try:
        priv, pub, path = find_key_for_address(
            mnemonic,
            passphrase,
            args.address,
            args.testnet,
            args.account,
            args.scan_limit,
            args.scan_internal,
        )
    finally:
        mnemonic = None
        passphrase = None

    derived_addr = h160_to_addr(hash160(pub), args.testnet)
    if derived_addr != args.address:  # defense in depth; find_key already guarantees this
        raise Abort(f"derived address {derived_addr} != expected {args.address}")
    print(f"\nkey found at {path} -> {derived_addr}  (matches the funding address)")

    # ---- 6. explicit confirmation ---------------------------------------------
    if not args.yes_i_know_this_spends_real_funds:
        answer = input(
            f'Type SPEND to sign a transaction burning 1 DASH + paying {fee} duffs fee: '
        )
        if answer.strip() != "SPEND":
            _zeroize(priv)
            raise Abort("not confirmed; nothing was signed")

    # ---- 7. sign + verify -------------------------------------------------------
    try:
        priv_bytes = bytes(priv)
        for i in range(len(txb.inputs)):
            digest = txb.sighash(i)
            der = sign_digest(priv_bytes, digest)
            if not verify_digest(pub, der, digest):
                raise Abort(f"self-verification of the signature for input {i} FAILED")
            txb.sigs[i] = (der + bytes([SIGHASH_ALL]), pub)
    finally:
        _zeroize(priv)
        priv_bytes = None

    raw = txb.serialize(signed=True)
    print(f"\nsigned tx size:    {len(raw)} B (estimated {est_size} B)")
    print(f"txid:              {txb.txid()}")
    print("\nSIGNED RAW TRANSACTION HEX (the only secret-free artifact; broadcast with")
    print("`dash-cli sendrawtransaction <hex>` or an explorer's broadcast page):\n")
    print(raw.hex())
    return 0


def _zeroize(buf):
    try:
        if isinstance(buf, bytearray):
            for i in range(len(buf)):
                buf[i] = 0
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(main())
