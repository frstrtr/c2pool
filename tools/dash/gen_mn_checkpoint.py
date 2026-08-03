#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""gen_mn_checkpoint.py -- pin / verify the DASH daemonless masternode-set checkpoint.

The daemonless embedded arm cannot obtain the payout-bearing masternode set from
the P2P network (the Simplified MN List omits scriptPayout + nLastPaidHeight, and
neither is committed in merkleRootMNList). It cold-starts instead from a
release-pinned checkpoint compiled into the binary. This tool produces and
re-validates that checkpoint file.

  pin    -- fetch `protx list registered true <height>` from a dashd (or an
            offline capture), convert it to the checkpoint payload, and OVERWRITE
            the target .inc in place. Prints a provenance block for the release
            notes.

            REGISTERED, NOT `valid`. `protx list valid` filters every
            PoSe-banned masternode OUT, which makes "banned at anchor height"
            byte-identical to "does not exist": absence. The bridge's forward
            replay can only ADD (ProRegTx is its sole insertion path), so a
            ProUpServTx that later REVIVES a banned-at-anchor masternode finds
            no entry, is dropped as an unknown MN, and that masternode can never
            re-enter the DIP-3 payment queue -- leaving every later payee
            projection one queue slot ahead of dashd's. The registered set
            carries those masternodes WITH their PoSeBanHeight, so the runtime
            holds them PRESENT but INELIGIBLE (mn_checkpoint.hpp derives
            isValid as poseBanHeight == 0) and the revive path works as written.
  verify -- re-derive the digest of an existing .inc and confirm every structural
            rule the runtime parser enforces (mn_checkpoint.hpp).

Authoritative format spec: src/impl/dash/coin/mn_checkpoint.hpp header comment and
src/impl/dash/coin/checkpoints/README.md. The field conversions here MIRROR
src/impl/dash/coin/mn_seed.hpp::parse_protx_list_seed so a checkpoint seed and an
RPC seed produce byte-identical MNState for the same masternode
(test/test_dash_mn_checkpoint.cpp::CheckpointSetIsFieldIdenticalToRpcSeed).

Standard library only -- no third-party dependencies, so a release machine needs
nothing but python3.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.request

MAGIC = "c2pool-dash-mn-checkpoint/1"

# Coin address version bytes (governance_object.hpp / chainparams):
#   mainnet PUBKEY_ADDRESS=76 ('X'), SCRIPT_ADDRESS=16 ('7')
#   testnet/devnet/regtest PUBKEY_ADDRESS=140 ('y'), SCRIPT_ADDRESS=19 ('8'/'9')
NETWORK_VERSIONS = {
    "mainnet": (0x4C, 0x10),
    "testnet": (0x8C, 0x13),
    "devnet":  (0x8C, 0x13),
    "regtest": (0x8C, 0x13),
}
# dashd getblockchaininfo.chain -> our network label
CHAIN_TO_NETWORK = {"main": "mainnet", "test": "testnet", "devnet": "devnet", "regtest": "regtest"}

# MNState C++ defaults we must reproduce when dashd omits a field (mn_state_db.hpp).
DEFAULT_NVERSION = 2   # vendor::ProTxVersion::BASIC_BLS
MnType_EVO_STRINGS = ("Evo", "HighPerformance")
BLS_PUBKEY_HEXLEN = 96  # BLS_PUBKEY_SIZE (48) * 2

_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")


def die(msg):
    sys.stderr.write("gen_mn_checkpoint: " + msg + "\n")
    sys.exit(1)


def is_hex_n(s, n):
    return isinstance(s, str) and len(s) == n and bool(_HEX_RE.match(s))


# ── base58check (stdlib only) ──────────────────────────────────────────────
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


def _b58decode(s):
    num = 0
    for ch in s:
        if ch not in _B58_INDEX:
            raise ValueError("invalid base58 character %r" % ch)
        num = num * 58 + _B58_INDEX[ch]
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    n_pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * n_pad + body


def base58check_payload(addr):
    """Decode a base58check string to its payload (version byte(s) + hash160)."""
    raw = _b58decode(addr)
    if len(raw) < 5:
        raise ValueError("address too short")
    body, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != checksum:
        raise ValueError("bad base58check checksum")
    return body


def address_to_script(addr, pubkey_ver, p2sh_ver):
    """payoutAddress -> scriptPubKey bytes, byte-exact with mn_seed.hpp
    hash160_to_merged_script. Only P2PKH/P2SH admitted (dashd consensus for
    ProReg/ProUpReg payout scripts). Raises on any decode failure -- the caller
    fail-closes the WHOLE seed, never emits a partial set."""
    body = base58check_payload(addr)
    ver, h160 = body[0], body[1:]
    if len(h160) != 20:
        raise ValueError("address payload is not a 20-byte hash160")
    if ver == pubkey_ver:                       # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        return b"\x76\xa9\x14" + h160 + b"\x88\xac"
    if ver == p2sh_ver:                         # P2SH:  OP_HASH160 <20> OP_EQUAL
        return b"\xa9\x14" + h160 + b"\x87"
    raise ValueError("address version byte %d is not valid for this network" % ver)


def address_to_keyid_hex(addr):
    """owner/voting address -> CKeyID hash160 hex (base58check_to_hash160)."""
    body = base58check_payload(addr)
    h160 = body[1:]
    if len(h160) != 20:
        raise ValueError("address payload is not a 20-byte hash160")
    return h160.hex()


# ── digest (mn_checkpoint.hpp::mn_checkpoint_digest) ───────────────────────
def _rstrip(line):
    return line.rstrip("\r \t")


def _in_digest_domain(line):
    if line == "":
        return False
    if line[0] == "#":
        return False
    if line == "digest" or line.startswith("digest ") or line.startswith("digest\t"):
        return False
    return True


def mn_checkpoint_digest(payload):
    """SHA-256 over every non-blank, non-'#'-comment, non-'digest' line, each
    stripped of trailing whitespace and terminated by a single '\\n', in file
    order. Deliberately trivial so the parser and this tool cannot disagree."""
    domain = []
    for raw in payload.split("\n"):
        line = _rstrip(raw)
        if _in_digest_domain(line):
            domain.append(line + "\n")
    return hashlib.sha256("".join(domain).encode("ascii")).hexdigest()


# ── protx entry -> mn record fields (mirrors mn_seed.hpp) ──────────────────
def _clamp_height(v):
    """dashd -1 'never' sentinel and any negative clamp to 0 (sane_height_json)."""
    return v if isinstance(v, int) and v > 0 else 0


def _operator_reward_bp(v):
    """JSON reports operatorReward as a percentage double; recover the internal
    0..10000 fixed-point (llround(pct * 100), half away from zero)."""
    if not isinstance(v, (int, float)):
        return 0
    x = float(v) * 100.0
    return int(x + 0.5) if x >= 0 else -int(-x + 0.5)


def build_mn_record(e, pubkey_ver, p2sh_ver):
    if not isinstance(e, dict) or not is_hex_n(e.get("proTxHash"), 64):
        raise ValueError("entry missing/invalid proTxHash")
    s = e.get("state")
    if not isinstance(s, dict):
        raise ValueError("entry %s missing 'state' object" % e.get("proTxHash"))

    protx = e["proTxHash"].lower()

    coll = e.get("collateralHash")
    coll = coll.lower() if is_hex_n(coll, 64) else "0" * 64
    coll_index = e["collateralIndex"] if isinstance(e.get("collateralIndex"), int) else 0

    type_str = e.get("type", "Regular")
    mn_type = 1 if type_str in MnType_EVO_STRINGS else 0

    version = s["version"] if isinstance(s.get("version"), int) else DEFAULT_NVERSION
    registered = _clamp_height(s.get("registeredHeight"))
    last_paid = _clamp_height(s.get("lastPaidHeight"))
    revived = _clamp_height(s.get("PoSeRevivedHeight"))
    banned = _clamp_height(s.get("PoSeBanHeight"))
    consecutive = _clamp_height(s.get("consecutivePayments"))
    revocation = s["revocationReason"] if isinstance(s.get("revocationReason"), int) else 0
    operator_reward = _operator_reward_bp(e.get("operatorReward"))

    # THE payee keystone -- required, byte-exact, fail-closed on any bad address.
    payout_addr = s.get("payoutAddress", "")
    if not payout_addr:
        raise ValueError("proTx %s has no payoutAddress" % protx)
    script_payout = address_to_script(payout_addr, pubkey_ver, p2sh_ver).hex()

    op_addr = s.get("operatorPayoutAddress", "")
    script_op = address_to_script(op_addr, pubkey_ver, p2sh_ver).hex() if op_addr else "-"

    owner = s.get("ownerAddress", "")
    key_owner = address_to_keyid_hex(owner) if owner else "-"
    voting = s.get("votingAddress", "")
    key_voting = address_to_keyid_hex(voting) if voting else "-"

    pk = s.get("pubKeyOperator", "")
    pubkey = pk.lower() if is_hex_n(pk, BLS_PUBKEY_HEXLEN) else "-"

    fields = [protx, coll, coll_index, mn_type, version, registered, last_paid,
              revived, banned, consecutive, revocation, operator_reward,
              script_payout, script_op, key_owner, key_voting, pubkey]
    return protx, coll, coll_index, "mn " + " ".join(str(f) for f in fields)


def records_from_protx(protx_list, pubkey_ver, p2sh_ver):
    """Convert a protx list into sorted mn record lines. Fail-closed: any
    malformed entry, duplicate proTxHash, or duplicate collateral outpoint
    aborts the WHOLE checkpoint (a partial set mints a wrong payee)."""
    if not isinstance(protx_list, list):
        die("protx list is not a JSON array")
    seen_protx, seen_coll, records = set(), set(), []
    for i, e in enumerate(protx_list):
        try:
            protx, coll, idx, line = build_mn_record(e, pubkey_ver, p2sh_ver)
        except ValueError as ex:
            die("entry #%d: %s (seed aborted -- fail-closed)" % (i, ex))
        if protx in seen_protx:
            die("duplicate proTxHash %s -- not a real DIP-3 set" % protx)
        if (coll, idx) in seen_coll:
            die("duplicate collateral outpoint %s:%d -- not a real DIP-3 set" % (coll, idx))
        seen_protx.add(protx)
        seen_coll.add((coll, idx))
        records.append((protx, line))
    # Sort by proTxHash so re-pin diffs are readable and two pins of the same
    # set produce identical bytes.
    records.sort(key=lambda r: r[0])
    return [line for _, line in records]


# ── .inc read/write ────────────────────────────────────────────────────────
_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def unwrap_inc(text):
    """Recover the raw payload the C++ compiler sees from an .inc file: the
    concatenation of its adjacent string literals with escapes interpreted.
    C++ `//` comment lines carry no payload and are dropped."""
    parts = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        for m in _LITERAL_RE.finditer(line):
            parts.append(m.group(1).encode("ascii").decode("unicode_escape"))
    return "".join(parts)


def _c_literal(raw_line):
    return '"' + raw_line.replace("\\", "\\\\").replace('"', '\\"') + '\\n"'


INC_HEADER = """// SPDX-License-Identifier: AGPL-3.0-or-later
//
// GENERATED FILE -- DO NOT EDIT BY HAND.
// Produced by tools/dash/gen_mn_checkpoint.py; the trailing `digest` line
// commits every other line, so a hand edit is rejected at load time.
//
// THIS IS A TRUST ANCHOR. See src/impl/dash/coin/checkpoints/README.md and
// the "DASH daemonless masternode-set checkpoint" section of README.md.
//
"""


def write_inc(path, header_lines, digest, mn_lines):
    payload_lines = header_lines[:7] + ["digest " + digest] + mn_lines
    with open(path, "w") as f:
        f.write(INC_HEADER)
        f.write("\n")
        for line in payload_lines:
            f.write(_c_literal(line) + "\n")
        f.write('"\\n"\n')   # trailing blank line in the payload


# ── minimal parser (mirrors mn_checkpoint.hpp fail-closed contract) ────────
def parse_checkpoint(payload, expected_network=None):
    """Return dict on success; raise ValueError on any defect (fail-closed)."""
    if not any(_rstrip(l) and not _rstrip(l).startswith("#") for l in payload.split("\n")):
        raise ValueError("UNPINNED: this build carries no masternode-set anchor")

    have = {}
    entries, seen_protx, seen_coll = [], set(), set()
    magic_seen = False
    for n, raw in enumerate(payload.split("\n"), 1):
        line = _rstrip(raw)
        if line == "" or line[0] == "#":
            continue
        if not magic_seen:
            if line != MAGIC:
                raise ValueError("bad magic on line %d: %r" % (n, line))
            magic_seen = True
            continue
        parts = line.split(None, 1)
        key = parts[0]
        val = parts[1] if len(parts) > 1 else ""
        if key in ("network", "height", "blockhash", "source", "generated", "count", "digest"):
            if key in have and key != "source":
                raise ValueError("duplicate '%s' line %d" % (key, n))
            have[key] = val
        elif key == "mn":
            f = val.split()
            if len(f) != 17:
                raise ValueError("mn line %d has %d fields, want 17" % (n, len(f)))
            if not is_hex_n(f[0], 64):
                raise ValueError("mn line %d: bad proTxHash" % n)
            if f[12] in ("-", "") or not is_hex_n(f[12], len(f[12])) or len(f[12]) % 2:
                raise ValueError("mn line %d: missing/undecodable scriptPayout" % n)
            if f[0] in seen_protx:
                raise ValueError("duplicate proTxHash on line %d" % n)
            ck = (f[1], f[2])
            if ck in seen_coll:
                raise ValueError("duplicate collateral outpoint on line %d" % n)
            seen_protx.add(f[0]); seen_coll.add(ck)
            entries.append(f)
        else:
            raise ValueError("unknown key '%s' on line %d" % (key, n))

    for req in ("network", "height", "blockhash", "count", "digest"):
        if req not in have:
            raise ValueError("missing '%s' line" % req)
    if not is_hex_n(have["blockhash"], 64) or int(have["blockhash"], 16) == 0:
        raise ValueError("bad/zero blockhash")
    if expected_network and have["network"] != expected_network:
        raise ValueError("network mismatch: checkpoint is '%s', expected '%s'"
                         % (have["network"], expected_network))
    if int(have["count"]) != len(entries):
        raise ValueError("count mismatch: header says %s, found %d" % (have["count"], len(entries)))
    if not entries:
        raise ValueError("checkpoint declares 0 masternodes (fail-closed)")
    actual = mn_checkpoint_digest(payload)
    if actual != have["digest"].lower():
        raise ValueError("DIGEST MISMATCH: declares %s, contents hash to %s"
                         % (have["digest"], actual))
    have["_entries"] = entries
    return have


# ── RPC ────────────────────────────────────────────────────────────────────
def rpc_call(url, user, password, method, params):
    body = json.dumps({"jsonrpc": "1.0", "id": "gen", "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body)
    if user is not None:
        token = base64.b64encode(("%s:%s" % (user, password or "")).encode()).decode()
        req.add_header("Authorization", "Basic " + token)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=180) as resp:
        out = json.load(resp)
    if out.get("error"):
        die("RPC %s error: %s" % (method, out["error"]))
    return out["result"]


# ── commands ────────────────────────────────────────────────────────────────
def cmd_pin(args):
    network = args.network
    if network not in NETWORK_VERSIONS:
        die("unknown --network %r" % network)
    pubkey_ver, p2sh_ver = NETWORK_VERSIONS[network]

    if args.protx_json:
        if args.height is None or args.blockhash is None:
            die("--protx-json (offline) requires --height and --blockhash")
        with open(args.protx_json) as f:
            protx_list = json.load(f)
        height, blockhash = args.height, args.blockhash.lower()
        source = args.source or ("offline capture (%s): protx list registered true %d"
                                 % (os.path.basename(args.protx_json), height))
    else:
        if not args.rpc_url:
            die("pin needs either --protx-json or --rpc-url")
        chain = rpc_call(args.rpc_url, args.rpc_user, args.rpc_password, "getblockchaininfo", [])["chain"]
        got = CHAIN_TO_NETWORK.get(chain)
        if got != network:
            die("chain mismatch: dashd is on '%s' (%s) but --network is '%s'" % (chain, got, network))
        # Bracket protx with getblockcount; refetch if the tip moved and the
        # height was auto-selected (a mislabelled height mis-seeds the cursor).
        while True:
            before = rpc_call(args.rpc_url, args.rpc_user, args.rpc_password, "getblockcount", [])
            height = args.height if args.height is not None else before
            protx_list = rpc_call(args.rpc_url, args.rpc_user, args.rpc_password,
                                  "protx", ["list", "registered", True, height])
            after = rpc_call(args.rpc_url, args.rpc_user, args.rpc_password, "getblockcount", [])
            if args.height is not None or after == before:
                break
            sys.stderr.write("gen_mn_checkpoint: tip moved %d->%d during fetch, refetching\n"
                             % (before, after))
        blockhash = rpc_call(args.rpc_url, args.rpc_user, args.rpc_password, "getblockhash", [height]).lower()
        source = args.source or ("dashd %s RPC: protx list registered true %d" % (network, height))

    if not is_hex_n(blockhash, 64):
        die("blockhash %r is not 64 hex" % blockhash)
    if not isinstance(height, int) or height <= 0:
        die("height %r is not a positive integer" % height)

    mn_lines = records_from_protx(protx_list, pubkey_ver, p2sh_ver)
    if not mn_lines:
        die("protx list produced 0 masternodes -- refusing to write an empty anchor")

    # SEED COMPLETENESS, stated out loud. Field 9 of an `mn` record (1-based,
    # after the "mn" keyword) is poseBanHeight; the runtime derives isValid
    # from it. An anchor with ZERO banned entries cannot reinstate anything,
    # because a ProUpServTx revive needs an entry to revive -- so say so here,
    # at the one moment a human is looking, rather than letting the bridge
    # later report "REINSTATED: 0" and be read as "none were needed".
    banned = sum(1 for l in mn_lines if l.split()[9] != "0")
    if banned == 0:
        sys.stderr.write(
            "gen_mn_checkpoint: WARNING -- this anchor carries ZERO PoSe-banned"
            " masternodes.\n  A real DIP-3 set at any mainnet height has banned"
            " members, so this is the fingerprint of a\n  `protx list valid`"
            " capture. A valid-filtered anchor makes 'banned' and 'does not"
            " exist'\n  the same observation, and no ProUpServTx revive inside"
            " the bridge window can be\n  honoured. Re-capture with"
            " `protx list registered true <height>`.\n")

    generated = args.generated or _iso_now()
    header = [MAGIC, "network " + network, "height %d" % height, "blockhash " + blockhash,
              "source " + source, "generated " + generated, "count %d" % len(mn_lines)]
    digest = mn_checkpoint_digest("\n".join(header + mn_lines) + "\n")

    out_path = args.output or _default_inc_path(network)
    write_inc(out_path, header, digest, mn_lines)

    # Re-parse what we just wrote -- never ship a file the runtime would refuse.
    with open(out_path) as f:
        parse_checkpoint(unwrap_inc(f.read()), expected_network=network)

    if not args.quiet:
        _print_provenance(out_path, network, height, blockhash, len(mn_lines), digest,
                          generated, banned)


def cmd_verify(args):
    with open(args.file) as f:
        payload = unwrap_inc(f.read())
    try:
        cp = parse_checkpoint(payload, expected_network=args.network)
    except ValueError as ex:
        die("REFUSED: %s\n  (%s)" % (ex, args.file))
    banned = sum(1 for f in cp["_entries"] if f[8] != "0")
    print("OK  %s" % args.file)
    print("    network=%s height=%s count=%d (%d payee-eligible, %d PoSe-banned)"
          % (cp["network"], cp["height"], len(cp["_entries"]),
             len(cp["_entries"]) - banned, banned))
    print("    blockhash=%s" % cp["blockhash"])
    print("    digest=%s (recomputed, matches)" % cp["digest"])


def _default_inc_path(network):
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(
        here, "..", "..", "src", "impl", "dash", "coin", "checkpoints",
        "dash_mn_checkpoint_%s.inc" % network))


def _iso_now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _print_provenance(path, network, height, blockhash, count, digest, generated,
                      banned=0):
    bar = "=" * 74
    print(bar)
    print("PROVENANCE -- paste into the release notes")
    print(bar)
    print("  file       %s" % path)
    print("  network    %s" % network)
    print("  height     %d" % height)
    print("  blockhash  %s" % blockhash)
    print("  count      %d registered masternodes" % count)
    print("             %d payee-eligible, %d PoSe-banned (present but INELIGIBLE)"
          % (count - banned, banned))
    print("  digest     %s" % digest)
    print("  generated  %s" % generated)
    print(bar)
    print("Next: rebuild c2pool, start with --embedded-%s and NO coin-RPC, and" % network)
    print("confirm the node LEAVES the CHECKPOINT REFUSED state and builds a template.")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("pin", help="fetch protx set and overwrite the checkpoint .inc")
    pp.add_argument("--network", required=True, choices=sorted(NETWORK_VERSIONS))
    pp.add_argument("--rpc-url")
    pp.add_argument("--rpc-user")
    pp.add_argument("--rpc-password")
    pp.add_argument("--protx-json",
                    help="offline: a captured `protx list registered true` JSON array")
    pp.add_argument("--height", type=int, help="anchor height (required with --protx-json)")
    pp.add_argument("--blockhash", help="anchor blockhash (required with --protx-json)")
    pp.add_argument("--source", help="override the provenance 'source' line")
    pp.add_argument("--generated", help="override the 'generated' timestamp (reproducible pins)")
    pp.add_argument("--output", help="output .inc path (default: the in-tree checkpoint for --network)")
    pp.add_argument("--quiet", action="store_true", help="suppress the provenance block (tests/CI)")
    pp.set_defaults(func=cmd_pin)

    vp = sub.add_parser("verify", help="re-derive the digest and re-validate an .inc")
    vp.add_argument("file")
    vp.add_argument("--network", help="assert the checkpoint is for this network")
    vp.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
