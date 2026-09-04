"""V37 P4 perishable-receipt golden harness — deterministic invariant checks.

Run:  python3 run_p4.py            (asserts + prints golden digest)
Emits a stable sha256 over the result vector so it doubles as a golden vector.
"""
import hashlib
import json

from perishable_receipt import (
    TTL, STANDING_WINDOW, mine_receipt, verify_receipt, Standing,
    derive_signing_privkey, signing_id,
)

ALICE = b"master-key-alice-fixed-seed-0001"
MALLORY = b"master-key-mallory-fixed-seed-02"
DOMAIN = b"stratum-market"
RESULTS = []


def check(name, got, want):
    ok = (got == want)
    RESULTS.append({"case": name, "got": got, "want": want, "pass": ok})
    print(f"[{'PASS' if ok else 'FAIL':4}] {name}: got={got!r} want={want!r}")
    return ok


# P4-1 — perishable / current-difficulty: fresh receipt admits; a receipt
#        precomputed in a cheap PAST epoch is rejected once it ages past TTL.
now = 100
r_fresh = mine_receipt(ALICE, 0, epoch=now, domain=DOMAIN, message=b"hi")
check("P4-1a fresh-current-epoch-admits", verify_receipt(r_fresh, now)[0], True)

r_backdated = mine_receipt(ALICE, 0, epoch=now - (TTL + 3), domain=DOMAIN, message=b"cheap-precompute")
check("P4-1b backdated-precompute-rejected", verify_receipt(r_backdated, now)[1], "expired-ttl")

# a receipt from the FUTURE (target not yet live) is also rejected
r_future = mine_receipt(ALICE, 0, epoch=now + 5, domain=DOMAIN, message=b"from-future")
check("P4-1c future-epoch-rejected", verify_receipt(r_future, now)[1], "future-epoch")

# P4-2 — TTL boundary: exactly TTL old = still fresh; TTL+1 old = dead.
r_edge = mine_receipt(ALICE, 0, epoch=now - TTL, domain=DOMAIN, message=b"edge")
check("P4-2a ttl-edge-inclusive-fresh", verify_receipt(r_edge, now)[0], True)
r_over = mine_receipt(ALICE, 0, epoch=now - TTL - 1, domain=DOMAIN, message=b"over")
check("P4-2b ttl-over-edge-dead", verify_receipt(r_over, now)[1], "expired-ttl")

# P4-3 — signed / anti-grief.
# forged signature => ignored
r_forge = dict(r_fresh)
r_forge["sig"] = b"\x00" * 32
check("P4-3a forged-sig-rejected", verify_receipt(r_forge, now)[1], "bad-sig")
# Mallory cannot mint standing under Alice's signing_id: she has no key that derives it.
alice_sid = signing_id(derive_signing_privkey(ALICE, 0))
r_grief = dict(r_fresh)
r_grief["signing_key"] = derive_signing_privkey(MALLORY, 0)  # attacker key, victim id kept
check("P4-3b cannot-mint-under-victim-id", verify_receipt(r_grief, now)[1], "bad-sig")
check("P4-3c victim-id-unchanged", r_fresh["signing_id"] == alice_sid, True)

# P4-4 — standing: ephemeral + domain-scoped + sybil-taxed (linear).
# One honest identity accrues S receipts over S epochs.
S = 5
acc = Standing()
for e in range(now - S + 1, now + 1):
    acc.admit(mine_receipt(ALICE, 0, epoch=e, domain=DOMAIN, message=f"m{e}".encode()), now)
honest = acc.standing(alice_sid, DOMAIN, now)
check("P4-4a honest-standing", honest, S)

# Sybil split: same hashrate spread over N derived ids => sum of standing == honest total
# (linear tax: no superlinear standing gain from splitting).
accs = Standing()
N = 5
total_sybil = 0
per_id = []
for i in range(N):
    e = now - N + 1 + i
    accs.admit(mine_receipt(ALICE, key_index=i, epoch=e, domain=DOMAIN, message=b"s"), now)
for i in range(N):
    sid_i = signing_id(derive_signing_privkey(ALICE, i))
    per_id.append(accs.standing(sid_i, DOMAIN, now))
total_sybil = sum(per_id)
check("P4-4b sybil-split-linear-no-superlinear", total_sybil, N)  # == number of receipts mined, not N^2

# domain scoping: standing in one domain does not leak to another
check("P4-4c domain-scoped", acc.standing(alice_sid, b"other-domain", now), 0)

# ephemeral: advance the clock past the window; standing garbage-collects to 0
check("P4-4d standing-ephemeral-gc", acc.standing(alice_sid, DOMAIN, now + STANDING_WINDOW + 1), 0)

# ---- golden digest --------------------------------------------------------
all_pass = all(r["pass"] for r in RESULTS)
blob = json.dumps([{k: (v.hex() if isinstance(v, bytes) else v) for k, v in r.items()}
                   for r in RESULTS], sort_keys=True).encode()
digest = hashlib.sha256(blob).hexdigest()
print("\n%d/%d invariants PASS" % (sum(r["pass"] for r in RESULTS), len(RESULTS)))
print("golden-digest sha256:", digest)
if not all_pass:
    raise SystemExit(1)
