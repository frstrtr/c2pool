#!/usr/bin/env python3
# G0/G1 share-format baseline extractor + comparator.
#
# Purpose: extract the canonical BTC share-format constants (network identifier
# / prefix / ports / protocol versions and the gentx layout signature) from an
# *arbitrary* p2pool source tree, and emit them as a JSON fixture. The tree is
# an INPUT (--tree), never a baked assumption: a Forrest-vs-jtoomim fork-pin
# change is a different --tree argument, not a rewrite of this harness.
#
# Guardrails (integrator, 2026-06-23):
#   1. This is extract-and-compare scaffolding + the fixture-emit format ONLY.
#      It does NOT ship fork-specific golden fixtures. Bake those after the pin
#      lands, by running --emit against the pinned tree.
#   2. The share-format source paths are DISCOVERED, not hard-coded. If the
#      canonical constants cannot be located in a given tree, the harness FAILS
#      LOUD ("baseline path not found") rather than silently juxtaposing against
#      the wrong file.
#
# Extraction is purely static (regex over source text). The target tree is
# never imported or executed -- p2pool baselines are Python 2 and executing an
# arbitrary checkout is unsafe and non-portable.

import argparse
import hashlib
import json
import os
import re
import sys

# Ranked candidate locations, relative to the tree root. First hit wins; the
# resolved path is recorded in the fixture provenance. Extend this list (do not
# hard-code a single path) when a new fork lays its modules out differently.
NETWORK_CANDIDATES = [
    "p2pool/networks/{coin}.py",
    "p2pool/bitcoin/networks/{coin}.py",
]
DATA_CANDIDATES = [
    "p2pool/data.py",
    "p2pool/bitcoin/data.py",
]


class BaselineNotFound(Exception):
    """Raised when a required share-format source cannot be located."""


def _resolve(tree, candidates, coin):
    searched = []
    for rel in candidates:
        rel = rel.format(coin=coin)
        path = os.path.join(tree, rel)
        searched.append(rel)
        if os.path.isfile(path):
            return path, searched
    return None, searched


def _read(path):
    with open(path, "r", errors="replace") as fh:
        return fh.read()


# --- network-module constants -------------------------------------------------

def _hex_decode_literal(text, name):
    # IDENTIFIER = 'fc70035c7a81bc6f'.decode('hex')   (py2 baselines)
    # also tolerate bytes.fromhex(...) / "...".decode("hex") spellings
    pat = re.compile(
        r"^\s*%s\s*=\s*['\"]([0-9a-fA-F]+)['\"]\s*\.decode\(\s*['\"]hex['\"]\s*\)" % name,
        re.MULTILINE,
    )
    m = pat.search(text)
    if m:
        return m.group(1).lower()
    pat2 = re.compile(
        r"^\s*%s\s*=\s*bytes\.fromhex\(\s*['\"]([0-9a-fA-F]+)['\"]\s*\)" % name,
        re.MULTILINE,
    )
    m = pat2.search(text)
    return m.group(1).lower() if m else None


def _int_const(text, name):
    m = re.search(r"^\s*%s\s*=\s*([0-9]+)\b" % name, text, re.MULTILINE)
    return int(m.group(1)) if m else None


def extract_network(path):
    text = _read(path)
    return {
        "IDENTIFIER": _hex_decode_literal(text, "IDENTIFIER"),
        "PREFIX": _hex_decode_literal(text, "PREFIX"),
        "P2P_PORT": _int_const(text, "P2P_PORT"),
        "MINIMUM_PROTOCOL_VERSION": _int_const(text, "MINIMUM_PROTOCOL_VERSION"),
        "SEGWIT_ACTIVATION_VERSION": _int_const(text, "SEGWIT_ACTIVATION_VERSION"),
    }


# --- data.py / gentx-layout constants ----------------------------------------

def _layout_signature(text):
    # gentx_before_refhash defines the byte layout the share's hash_link is
    # computed over -- the G0/G1 byte-parity anchor. We capture the RHS
    # expression verbatim and sign a whitespace-normalized form of it, so a
    # layout change between forks surfaces as a signature mismatch.
    m = re.search(r"^\s*gentx_before_refhash\s*=\s*(.+)$", text, re.MULTILINE)
    if not m:
        return None, None
    expr = m.group(1).strip()
    normalized = re.sub(r"\s+", "", expr)
    sig = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return expr, sig


def extract_data(path):
    text = _read(path)
    expr, sig = _layout_signature(text)
    versions = sorted({int(v) for v in re.findall(r"^\s*VERSION\s*=\s*([0-9]+)\b", text, re.MULTILINE)})
    m_don = re.search(r"^\s*DONATION_SCRIPT\s*=\s*['\"]([0-9a-fA-F]+)['\"]", text, re.MULTILINE)
    return {
        "gentx_before_refhash_expr": expr,
        "gentx_layout_sig": sig,
        "share_versions": versions,
        "DONATION_SCRIPT": (m_don.group(1).lower() if m_don else None),
    }


# --- fixture assembly ---------------------------------------------------------

def _git_rev(tree):
    head = os.path.join(tree, ".git", "HEAD")
    try:
        with open(head) as fh:
            ref = fh.read().strip()
        if ref.startswith("ref:"):
            with open(os.path.join(tree, ".git", ref[4:].strip())) as fh:
                return fh.read().strip()[:12]
        return ref[:12]
    except OSError:
        return None


def build_fixture(tree, coin):
    net_path, net_searched = _resolve(tree, NETWORK_CANDIDATES, coin)
    data_path, data_searched = _resolve(tree, DATA_CANDIDATES, coin)
    missing = []
    if net_path is None:
        missing.append("network module (searched: %s)" % ", ".join(net_searched))
    if data_path is None:
        missing.append("data.py (searched: %s)" % ", ".join(data_searched))
    if missing:
        raise BaselineNotFound(
            "baseline path not found in tree '%s' for coin '%s': %s"
            % (tree, coin, "; ".join(missing))
        )

    net = extract_network(net_path)
    data = extract_data(data_path)

    # Fail loud if a located file yields none of the expected anchors -- that
    # means we found the wrong file, which is exactly the silent-juxtapose trap.
    if net["IDENTIFIER"] is None and net["PREFIX"] is None:
        raise BaselineNotFound(
            "located network module '%s' but extracted no IDENTIFIER/PREFIX -- "
            "wrong file or unsupported spelling" % net_path
        )
    if data["gentx_layout_sig"] is None:
        raise BaselineNotFound(
            "located '%s' but extracted no gentx_before_refhash layout" % data_path
        )

    return {
        "schema": "c2pool.g01.share-format/v1",
        "coin": coin,
        "provenance": {
            "tree": os.path.abspath(tree),
            "git_rev": _git_rev(tree),
            "network_source": os.path.relpath(net_path, tree),
            "data_source": os.path.relpath(data_path, tree),
        },
        "constants": {**net, **data},
    }


def cmd_emit(args):
    fx = build_fixture(args.tree, args.coin)
    out = json.dumps(fx, indent=2, sort_keys=True)
    if args.emit and args.emit != "-":
        with open(args.emit, "w") as fh:
            fh.write(out + "\n")
        print("wrote %s (%s @ %s)" % (args.emit, fx["coin"], fx["provenance"]["git_rev"]))
    else:
        print(out)
    return 0


def cmd_compare(args):
    # Generic fixture-vs-fixture comparison. NO baked golden fixture is shipped;
    # both sides are produced by --emit (one from the pinned baseline tree, one
    # from c2pool's exported constants) once the fork pin lands.
    with open(args.left) as fh:
        left = json.load(fh)
    with open(args.right) as fh:
        right = json.load(fh)
    lc, rc = left.get("constants", {}), right.get("constants", {})
    keys = sorted(set(lc) | set(rc))
    diffs = [(k, lc.get(k), rc.get(k)) for k in keys if lc.get(k) != rc.get(k)]
    if not diffs:
        print("MATCH: %d constants identical (%s vs %s)"
              % (len(keys), args.left, args.right))
        return 0
    print("MISMATCH: %d of %d constants differ" % (len(diffs), len(keys)))
    for k, lv, rv in diffs:
        print("  %-28s left=%r  right=%r" % (k, lv, rv))
    return 1


def main(argv=None):
    p = argparse.ArgumentParser(description="G0/G1 share-format baseline harness")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("emit", help="extract constants from a tree and emit a fixture")
    e.add_argument("--tree", required=True, help="path to a p2pool source tree (INPUT, not baked)")
    e.add_argument("--coin", default="bitcoin", help="network module to extract (default: bitcoin)")
    e.add_argument("--emit", default="-", help="output fixture path, or '-' for stdout")
    e.set_defaults(func=cmd_emit)

    c = sub.add_parser("compare", help="compare two emitted fixtures (no baked golden)")
    c.add_argument("left")
    c.add_argument("right")
    c.set_defaults(func=cmd_compare)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except BaselineNotFound as exc:
        sys.stderr.write("FAIL: %s\n" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
