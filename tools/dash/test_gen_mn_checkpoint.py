#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline KAT for tools/dash/gen_mn_checkpoint.py.

Proves the generator is byte-correct against the SAME committed testnet fixture
(test/dash_mn_checkpoint_testnet_1519543.inc) that
test/test_dash_mn_checkpoint.cpp::CheckpointSetIsFieldIdenticalToRpcSeed certifies
is byte-identical to the RPC (mn_seed.hpp) seed. No network access.

  1. verify   -- the committed fixture re-derives its own digest (eddc3386...).
  2. parity   -- pinning from the payee-relevant protx JSON subset reproduces the
                 fixture's payee-critical columns byte-for-byte (scriptPayout via
                 base58check->script, the -1 'never' height clamps, type/version/
                 collateral). This is the coinbase-correctness contract.
  3. closed   -- every defect class (digest tamper, count/network mismatch,
                 undecodable payee, unpinned) refuses the WHOLE checkpoint.
  4. roundtrip-- pin a synthetic set, verify accepts it, a one-byte edit refuses.

Run from the repo root:  python3 tools/dash/test_gen_mn_checkpoint.py
"""

import json
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import gen_mn_checkpoint as g  # noqa: E402

REPO = os.path.normpath(os.path.join(_HERE, "..", ".."))
FIXTURE = os.path.join(REPO, "test", "dash_mn_checkpoint_testnet_1519543.inc")
FIXTURE_DIGEST = "eddc3386874eedd5f0e7619f198090390be13e9f5c9893512b629462a9953c91"
FIXTURE_HEIGHT = 1519543
FIXTURE_BLOCKHASH = "00000048ba417fd364d4220de99d16d6e17651a565b9b529417905b99b3a541b"

# The SAME six masternodes reduced to the payee-relevant fields the E2c parser
# consumes (test_dash_mn_checkpoint.cpp kJson). owner/voting/pubkey are the full
# capture's and are NOT payee-critical, so this subset omits them.
GOLDEN_JSON = json.loads(r"""[
 {"type":"Regular","proTxHash":"dc2e02ac95ce4ccc9843c38de7bdaf32f2a1d5966c054127a3f4ca4f4bbd5991",
  "collateralHash":"4ee3ff5074723d995f4cb957a954587c6c637a42655ada8f4054037b28d1e7a8","collateralIndex":34,
  "operatorReward":0,"state":{"version":1,"registeredHeight":838365,"lastPaidHeight":1519459,
  "consecutivePayments":0,"PoSeRevivedHeight":1367840,"PoSeBanHeight":-1,"revocationReason":0,
  "payoutAddress":"yVXDAM73Tg6A44Bm3qduXsMCYxzuqBCT48"}},
 {"type":"Evo","proTxHash":"9b653e767b978c10346d938c08dc8c5acd03c495f9d913e6fc652bfcae11a348",
  "collateralHash":"75fe9d8d90619576ef11deb8550d023366bf9d85e686dc6d5afba0aca8827e21","collateralIndex":2,
  "operatorReward":0,"state":{"version":2,"registeredHeight":1427623,"lastPaidHeight":1519460,
  "consecutivePayments":0,"PoSeRevivedHeight":1446613,"PoSeBanHeight":-1,"revocationReason":0,
  "payoutAddress":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A"}},
 {"type":"Evo","proTxHash":"91bbce94c34ebde0d099c0a2cb7635c0c31425ebabcec644f4f1a0854bfa605d",
  "collateralHash":"6ce8545e25d4f03aba1527062d9583ae01827c65b234bd979aca5954c6ae3a59","collateralIndex":30,
  "operatorReward":0,"state":{"version":2,"registeredHeight":850334,"lastPaidHeight":1519461,
  "consecutivePayments":0,"PoSeRevivedHeight":1368973,"PoSeBanHeight":-1,"revocationReason":0,
  "payoutAddress":"yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A"}},
 {"type":"Regular","proTxHash":"72ee70fa75262781a17d1eb69a6c3e97328208be98b59d5530164f31e481d3aa",
  "collateralHash":"4ee3ff5074723d995f4cb957a954587c6c637a42655ada8f4054037b28d1e7a8","collateralIndex":96,
  "operatorReward":0,"state":{"version":1,"registeredHeight":838365,"lastPaidHeight":1519462,
  "consecutivePayments":0,"PoSeRevivedHeight":1367330,"PoSeBanHeight":-1,"revocationReason":0,
  "payoutAddress":"yVXDAM73Tg6A44Bm3qduXsMCYxzuqBCT48"}},
 {"type":"Regular","proTxHash":"c87218fb9d031f4926c22430c69b4edf1f0fb80c331c1a79e3b1b3873407c0ac",
  "collateralHash":"4ee3ff5074723d995f4cb957a954587c6c637a42655ada8f4054037b28d1e7a8","collateralIndex":62,
  "operatorReward":0,"state":{"version":1,"registeredHeight":838365,"lastPaidHeight":1519463,
  "consecutivePayments":0,"PoSeRevivedHeight":1367840,"PoSeBanHeight":-1,"revocationReason":0,
  "payoutAddress":"yVXDAM73Tg6A44Bm3qduXsMCYxzuqBCT48"}},
 {"type":"Regular","proTxHash":"ecebeb952f56a61abaccd7bda7f4df5eccbd5f87a91bc4a8969535df1058158e",
  "collateralHash":"f329c4c9d194159e81597e50144ce41a40e2b40860c7813a85eabb0454700a3d","collateralIndex":1,
  "operatorReward":0,"state":{"version":2,"registeredHeight":1491043,"lastPaidHeight":1519464,
  "consecutivePayments":0,"PoSeRevivedHeight":1507780,"PoSeBanHeight":-1,"revocationReason":0,
  "payoutAddress":"yjTpMw9buZfv4jNkf87AHpDj95YSAFuDiX"}}
]""")

# payee-critical mn columns (0-based index into f = tokens after 'mn'):
#   0 proTxHash 1 collateralHash 2 index 3 type 4 version 5 registeredHeight
#   6 lastPaidHeight 7 poseRevivedHeight 8 poseBanHeight 9 consecutivePayments
#   10 revocationReason 11 operatorReward 12 scriptPayout
CRIT = list(range(0, 13))

_fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        _fails.append(name)


def mn_map(payload):
    return {l.split()[1]: l.split()[1:] for l in payload.split("\n") if l.startswith("mn ")}


def refused(payload_text, network="testnet"):
    try:
        g.parse_checkpoint(g.unwrap_inc(payload_text), expected_network=network)
        return False
    except ValueError:
        return True


def main():
    fixture_text = open(FIXTURE).read()

    print("[1] verify: committed fixture re-derives its own digest")
    cp = g.parse_checkpoint(g.unwrap_inc(fixture_text), expected_network="testnet")
    check("digest == %s" % FIXTURE_DIGEST[:16], cp["digest"] == FIXTURE_DIGEST)
    check("height/count", cp["height"] == str(FIXTURE_HEIGHT) and len(cp["_entries"]) == 6)

    print("[2] parity: pin-from-JSON reproduces payee-critical columns byte-for-byte")
    with tempfile.NamedTemporaryFile("w", suffix=".inc", delete=False) as tf:
        out = tf.name
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as jf:
        json.dump(GOLDEN_JSON, jf)
        jsrc = jf.name
    g.main(["pin", "--network", "testnet", "--protx-json", jsrc,
            "--height", str(FIXTURE_HEIGHT), "--blockhash", FIXTURE_BLOCKHASH,
            "--generated", "2026-07-26T13:23:51Z", "--source", "kat", "--output", out, "--quiet"])
    R, G = mn_map(g.unwrap_inc(fixture_text)), mn_map(g.unwrap_inc(open(out).read()))
    ok = R.keys() == G.keys()
    for h in R:
        for c in CRIT:
            if R[h][c] != G[h][c]:
                ok = False
                print("      MISMATCH %s col %d: %s != %s" % (h[:12], c, R[h][c], G[h][c]))
    check("6 MN x 13 payee-critical columns identical", ok)

    print("[3] fail-closed: every defect class refuses the whole checkpoint")
    sp = mn_map(g.unwrap_inc(fixture_text))[list(R)[0]][12]
    check("scriptPayout hash160 tamper -> digest mismatch",
          refused(fixture_text.replace(sp[6:46], "00" * 20)))
    check("digest byte tamper", refused(fixture_text.replace("eddc3386", "eddc3387")))
    check("count mismatch", refused(fixture_text.replace("count 6", "count 5")))
    check("network mismatch", refused(fixture_text, network="mainnet"))
    check("unpinned payload", refused('// comments only\n"\\n"\n'))
    check("clean control accepted", not refused(fixture_text))

    print("[4] round-trip: pin synthetic -> verify accepts -> one-byte edit refuses")
    synth = [{"type": "Regular",
              "proTxHash": "11" * 32, "collateralHash": "22" * 32, "collateralIndex": 0,
              "operatorReward": 0,
              "state": {"version": 2, "registeredHeight": 100, "lastPaidHeight": 200,
                        "PoSeRevivedHeight": -1, "PoSeBanHeight": -1, "revocationReason": 0,
                        "payoutAddress": "yVXDAM73Tg6A44Bm3qduXsMCYxzuqBCT48"}}]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as jf:
        json.dump(synth, jf)
        sj = jf.name
    with tempfile.NamedTemporaryFile("w", suffix=".inc", delete=False) as tf:
        so = tf.name
    g.main(["pin", "--network", "testnet", "--protx-json", sj, "--height", "12345",
            "--blockhash", "ab" * 32, "--generated", "2026-01-01T00:00:00Z", "--output", so, "--quiet"])
    st = open(so).read()
    check("synthetic pin verifies", not refused(st))
    check("flip one payload byte -> refused", refused(st.replace("height 12345", "height 12346")))

    for p in (out, jsrc, sj, so):
        os.unlink(p)

    print()
    if _fails:
        print("FAILED: " + ", ".join(_fails))
        sys.exit(1)
    print("ALL PASS")


if __name__ == "__main__":
    main()
