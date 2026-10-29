#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-check the DOGE hash-schedule anchors before they ship.

Reads src/impl/doge/coin/doge_schedule_anchors.inc (or --inc), re-checks the
file itself (heights in steps of 2000 from 0, the checkpoint line, the SHA-256
digest over the 32-byte hashes), then compares a sample of anchors -- the
first, the last, and --samples more picked deterministically from the digest
-- with independent sources:

  blockchair   https://api.blockchair.com/dogecoin/blocks?q=id(<height>)
  dogechain    https://dogechain.info/api/v1/block/<height>
  rpc          a Dogecoin node's getblockhash (--rpc-url http://user:pass@host:port)

Exit 0: every sampled anchor matches every source that answered, and each
sample was answered by at least --min-sources sources. Exit 1: a mismatch (or
the file is inconsistent). Exit 2: not enough sources answered. The log
printed is what goes with the anchor file into review.
"""

import argparse
import base64
import hashlib
import json
import random
import re
import sys
import time
import urllib.request

STEP = 2000


def parse_inc(path):
    lines = re.findall(r'^"(.*)",\s*$', open(path, encoding="utf-8").read(), re.M)
    fields, anchors = {}, []
    for line in lines:
        key, _, rest = line.partition(" ")
        if key in ("format", "step", "checkpoint", "digest"):
            fields[key] = rest
        else:
            height, _, h = line.partition(" ")
            anchors.append((int(height), h.strip().lower()))
    return fields, anchors


def check_file(fields, anchors):
    errors = []
    if fields.get("format") != "1":
        errors.append("format %r" % fields.get("format"))
    if fields.get("step") != str(STEP):
        errors.append("step %r" % fields.get("step"))
    for i, (height, h) in enumerate(anchors):
        if height != STEP * i:
            errors.append("anchor %d at height %d" % (i, height))
            break
        if not re.fullmatch(r"[0-9a-f]{64}", h):
            errors.append("bad hash at %d" % height)
    cp_height, _, cp_hash = fields.get("checkpoint", "").partition(" ")
    if not anchors or int(cp_height or -1) != anchors[-1][0] or cp_hash.lower() != anchors[-1][1]:
        errors.append("the checkpoint line does not match the last anchor")
    digest = hashlib.sha256(b"".join(bytes.fromhex(h)[::-1] for _, h in anchors)).hexdigest()
    if fields.get("digest", "").lower() != digest:
        errors.append("digest %s, computed %s" % (fields.get("digest"), digest))
    return errors, digest


def http_json(url, timeout, headers=None, data=None):
    req = urllib.request.Request(url, data=data, headers=headers or {"User-Agent": "c2pool-anchor-check/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def src_blockchair(height, timeout):
    j = http_json("https://api.blockchair.com/dogecoin/blocks?q=id(%d)" % height, timeout)
    return j["data"][0]["hash"].lower()


def src_dogechain(height, timeout):
    j = http_json("https://dogechain.info/api/v1/block/%d" % height, timeout)
    return j["block"]["hash"].lower()


def make_rpc(url):
    m = re.match(r"^(https?://)(?:([^:@/]+):([^@/]*)@)?(.+)$", url)
    if not m:
        raise SystemExit("bad --rpc-url")
    scheme, user, password, rest = m.groups()
    endpoint = scheme + rest
    auth = None
    if user is not None:
        auth = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()

    def src_rpc(height, timeout):
        body = json.dumps({"jsonrpc": "1.0", "id": "anchor-check", "method": "getblockhash",
                           "params": [height]}).encode()
        headers = {"Content-Type": "text/plain"}
        if auth:
            headers["Authorization"] = auth
        j = http_json(endpoint, timeout, headers=headers, data=body)
        return j["result"].lower()

    return src_rpc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inc", default="src/impl/doge/coin/doge_schedule_anchors.inc")
    ap.add_argument("--samples", type=int, default=32)
    ap.add_argument("--sources", default="blockchair,dogechain",
                    help="comma list of blockchair, dogechain, rpc")
    ap.add_argument("--rpc-url", default="")
    ap.add_argument("--min-sources", type=int, default=2)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--pause", type=float, default=1.5, help="seconds between explorer calls")
    args = ap.parse_args()

    fields, anchors = parse_inc(args.inc)
    errors, digest = check_file(fields, anchors)
    print("anchor file  %s" % args.inc)
    print("anchors      %d (h=0..%d), digest %s" % (len(anchors), anchors[-1][0] if anchors else -1, digest))
    if errors:
        for e in errors:
            print("FILE ERROR   %s" % e)
        return 1

    sources = {}
    for name in [s.strip() for s in args.sources.split(",") if s.strip()]:
        if name == "blockchair":
            sources[name] = src_blockchair
        elif name == "dogechain":
            sources[name] = src_dogechain
        elif name == "rpc":
            if not args.rpc_url:
                raise SystemExit("--sources rpc needs --rpc-url")
            sources[name] = make_rpc(args.rpc_url)
        else:
            raise SystemExit("unknown source %s" % name)

    rng = random.Random(digest)  # the same sample for the same file
    middle = list(range(1, len(anchors) - 1))
    picks = sorted(set([0, len(anchors) - 1] + rng.sample(middle, min(args.samples, len(middle)))))
    mismatches, short = 0, 0
    for i in picks:
        height, ours = anchors[i]
        answered = 0
        for name, fn in sources.items():
            try:
                theirs = fn(height, args.timeout)
            except Exception as e:  # noqa: BLE001 -- any source failure is reported, not fatal
                print("h=%-8d %-10s unavailable (%s)" % (height, name, e.__class__.__name__))
                continue
            finally:
                if name != "rpc":
                    time.sleep(args.pause)
            answered += 1
            ok = theirs == ours
            mismatches += 0 if ok else 1
            print("h=%-8d %-10s %s %s" % (height, name, "ok      " if ok else "MISMATCH", theirs))
        if answered < args.min_sources:
            short += 1
            print("h=%-8d only %d source(s) answered" % (height, answered))
    print("sampled      %d anchors, %d sources, %d mismatches, %d under-sourced" %
          (len(picks), len(sources), mismatches, short))
    if mismatches:
        print("RESULT       FAIL: do not ship this anchor file")
        return 1
    if short:
        print("RESULT       INCOMPLETE: re-run when the sources answer (or add --sources rpc)")
        return 2
    print("RESULT       PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
