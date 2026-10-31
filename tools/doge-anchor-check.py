#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-check the DOGE hash-schedule anchors before they ship.

Reads src/impl/doge/coin/doge_schedule_anchors.inc (or --inc), re-checks the
file itself (heights in steps of 2000 from 0, the checkpoint line, the SHA-256
digest over the 32-byte hashes), then compares a sample of anchors -- the
first, the last, and --samples more picked deterministically from the digest
(--samples 3081 takes them all) -- with independent sources:

  blockchair   https://api.blockchair.com/dogecoin/dashboards/blocks/<h1>,...  (10 heights a call)
  blockcypher  https://api.blockcypher.com/v1/doge/main/blocks/<height>        (rate-limited: small samples)
  dogechain    https://dogechain.info/api/v1/block/<height>                    (gone since 2026-10: kept for when it returns)
  rpc          a Dogecoin node's getblockhash (--rpc-url http://user:pass@host:port)

A source that fails --give-up times in a row is not asked again in this run
(its remaining heights count as unavailable), so a rate limit or an outage
costs seconds, not hours.

What the sample guards: the list is dumped from a schedule that linked every
height into the configured checkpoint, so a wrong list means a wrong database,
which makes every anchor wrong -- a few samples catch that. A single corrupted
line is not what sampling is for: the digest catches a file edited after the
dump, and --samples 3081 checks every line once.

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
BLOCKCHAIR_BATCH = 10


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
    req = urllib.request.Request(url, data=data, headers=headers or {"User-Agent": "c2pool-anchor-check/2"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


class Source:
    """One source: get(heights) -> {height: hash} for the heights it answered."""

    def __init__(self, name, fetch, batch, pause, give_up):
        self.name, self.fetch, self.batch, self.pause, self.give_up = name, fetch, batch, pause, give_up
        self.failures_in_a_row = 0
        self.dead = False
        self.cache = {}

    def get(self, heights, timeout):
        want = [h for h in heights if h not in self.cache]
        for i in range(0, len(want), self.batch):
            if self.dead:
                break
            chunk = want[i:i + self.batch]
            try:
                self.cache.update(self.fetch(chunk, timeout))
                self.failures_in_a_row = 0
            except Exception as e:  # noqa: BLE001 -- a source failure is reported, not fatal
                self.failures_in_a_row += 1
                print("%-11s unavailable for h=%s (%s)" % (self.name, chunk[0] if len(chunk) == 1
                      else "%d..%d" % (chunk[0], chunk[-1]), e.__class__.__name__))
                if self.failures_in_a_row >= self.give_up:
                    self.dead = True
                    print("%-11s given up after %d failures in a row" % (self.name, self.failures_in_a_row))
            time.sleep(self.pause)
        return {h: self.cache[h] for h in heights if h in self.cache}


def fetch_blockchair(heights, timeout):
    url = "https://api.blockchair.com/dogecoin/dashboards/blocks/" + ",".join(str(h) for h in heights)
    j = http_json(url, timeout)
    out = {}
    for k, v in (j.get("data") or {}).items():
        if v and v.get("block"):
            out[int(k)] = v["block"]["hash"].lower()
    if not out:
        raise RuntimeError("empty answer")
    return out


def fetch_blockcypher(heights, timeout):
    (h,) = heights
    return {h: http_json("https://api.blockcypher.com/v1/doge/main/blocks/%d" % h, timeout)["hash"].lower()}


def fetch_dogechain(heights, timeout):
    (h,) = heights
    return {h: http_json("https://dogechain.info/api/v1/block/%d" % h, timeout)["block"]["hash"].lower()}


def make_rpc(url):
    m = re.match(r"^(https?://)(?:([^:@/]+):([^@/]*)@)?(.+)$", url)
    if not m:
        raise SystemExit("bad --rpc-url")
    scheme, user, password, rest = m.groups()
    endpoint = scheme + rest
    auth = None
    if user is not None:
        auth = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()

    def fetch_rpc(heights, timeout):
        (h,) = heights
        body = json.dumps({"jsonrpc": "1.0", "id": "anchor-check", "method": "getblockhash",
                           "params": [h]}).encode()
        headers = {"Content-Type": "text/plain"}
        if auth:
            headers["Authorization"] = auth
        return {h: http_json(endpoint, timeout, headers=headers, data=body)["result"].lower()}

    return fetch_rpc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inc", default="src/impl/doge/coin/doge_schedule_anchors.inc")
    ap.add_argument("--samples", type=int, default=32)
    ap.add_argument("--sources", default="blockchair,blockcypher",
                    help="comma list of blockchair, blockcypher, dogechain, rpc")
    ap.add_argument("--rpc-url", default="")
    ap.add_argument("--min-sources", type=int, default=2)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--pause", type=float, default=1.5, help="seconds between explorer calls")
    ap.add_argument("--give-up", type=int, default=5, help="failures in a row that retire a source")
    args = ap.parse_args()

    fields, anchors = parse_inc(args.inc)
    errors, digest = check_file(fields, anchors)
    print("anchor file  %s" % args.inc)
    print("anchors      %d (h=0..%d), digest %s" % (len(anchors), anchors[-1][0] if anchors else -1, digest))
    if errors:
        for e in errors:
            print("FILE ERROR   %s" % e)
        return 1

    sources = []
    for name in [s.strip() for s in args.sources.split(",") if s.strip()]:
        if name == "blockchair":
            sources.append(Source(name, fetch_blockchair, BLOCKCHAIR_BATCH, args.pause, args.give_up))
        elif name == "blockcypher":
            sources.append(Source(name, fetch_blockcypher, 1, args.pause, args.give_up))
        elif name == "dogechain":
            sources.append(Source(name, fetch_dogechain, 1, args.pause, args.give_up))
        elif name == "rpc":
            if not args.rpc_url:
                raise SystemExit("--sources rpc needs --rpc-url")
            sources.append(Source(name, make_rpc(args.rpc_url), 1, 0.0, args.give_up))
        else:
            raise SystemExit("unknown source %s" % name)

    rng = random.Random(digest)  # the same sample for the same file
    middle = list(range(1, len(anchors) - 1))
    picks = sorted(set([0, len(anchors) - 1] + rng.sample(middle, min(args.samples, len(middle)))))
    heights = [anchors[i][0] for i in picks]
    ours = dict(anchors)
    answers = {s.name: s.get(heights, args.timeout) for s in sources}

    mismatches, short = 0, 0
    per_source = {s.name: [0, 0] for s in sources}  # matched, answered
    for h in heights:
        answered = 0
        for s in sources:
            theirs = answers[s.name].get(h)
            if theirs is None:
                continue
            answered += 1
            per_source[s.name][1] += 1
            if theirs == ours[h]:
                per_source[s.name][0] += 1
            else:
                mismatches += 1
                print("h=%-8d %-11s MISMATCH %s (ours %s)" % (h, s.name, theirs, ours[h]))
        if answered < args.min_sources:
            short += 1
    for s in sources:
        m, a = per_source[s.name]
        print("%-11s %d/%d answered, %d match%s" % (s.name, a, len(heights), m, " (given up)" if s.dead else ""))
    print("sampled      %d anchors, %d sources, %d mismatches, %d answered by fewer than %d sources" %
          (len(heights), len(sources), mismatches, short, args.min_sources))
    if mismatches:
        print("RESULT       FAIL: do not ship this anchor file")
        return 1
    if short:
        print("RESULT       INCOMPLETE: no mismatch, but %d anchors lack %d sources (re-run, or add --sources rpc)"
              % (short, args.min_sources))
        return 2
    print("RESULT       PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
