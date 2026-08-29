#!/usr/bin/env python3
"""M5 T18: delta-tail acceptance — the SIGNATURE / IDENTITY leg of F1.

T17 closed the WORK leg of red-team finding F1 (per-share PoW + cumulative-work fork choice).
T17 explicitly carved out the IDENTITY leg:

    "The signature/identity leg of F1 (info_digest -> committed payout-descriptor key) is
     NOT modeled here ... sig-verification of the carried PayoutDescriptor stays the M5
     testbed item."

This harness closes that leg, mirroring T17's shape: a deterministic golden vector that
proves an honest tail is ACCEPTED and every forged / mismatched-identity tail is REJECTED.

WHERE THE TWO LEGS DIVIDE:
  - T17 (work leg) binds WHAT WORK was done: per-share PoW over the share header; fork
    choice on cumulative work. It stops a sybil injecting un-mined shares.
  - T18 (identity leg) binds WHO GETS PAID: each share carries a PayoutDescriptor
    (the payout key + script type). The validator must be sure the payout in the
    non-final tail belongs to the miner who actually did that share's work — not to a
    sybil who rewrote the payout target while relaying the tail.

THE BINDING (the F1 identity defense, stated -> tested here):
  A share's PoW-committed payload includes `info_digest = H(PayoutDescriptor)`. Acceptance
  of a tail share requires BOTH:
    (S1) COMMITMENT: H(share.payout_descriptor) == share.info_digest, and info_digest is
         part of the payload the share_id (and thus the PoW) commits to. So the descriptor
         cannot be swapped without recomputing share_id -> redoing the per-share PoW.
    (S2) SIGNATURE: share.sig verifies, under the pubkey IN share.payout_descriptor, over
         the canonical signing message (the share_id). Only the descriptor's key-holder
         can produce it; a sybil relaying the tail cannot forge it for a key it lacks.
  The full acceptance rule is T17's (chained + per-share PoW) AND (S1) AND (S2).

FORGED / MISMATCHED-IDENTITY FAMILIES (all from a relay sybil that did NOT do the work):
  A. PAYOUT-REDIRECT, stale commitment — sybil rewrites payout_descriptor to its own key
     to steal the payout, but leaves info_digest (the honest commitment) untouched.
     Rejected at S1 (H(desc') != info_digest). The canonical theft attempt.
  B. FORGED SIGNATURE — descriptor is the honest miner's key, but the sig is invalid /
     re-used / produced by the sybil (which lacks the private key). Rejected at S2.
  C. SELF-CONSISTENT REWRITE (the cross-leg crux) — sybil rewrites the descriptor to its
     OWN key, recomputes info_digest to match, AND self-signs with its own key. The
     identity leg ALONE (S1+S2) now PASSES — it looks internally consistent. But
     info_digest is inside the PoW-committed payload, so recomputing it changes share_id;
     the honest nonce no longer meets target (PoW breaks) and the chain link to the next
     share breaks. Rejected only by the COMPOSED rule (T17 work leg). This is the proof
     that the identity leg is sound ONLY because it is bound into the work commitment:
     redirecting the payout forces the sybil to re-mine at honest difficulty.
  D. UNBOUND-KEY — descriptor's key != the key that signed (signer mismatch). Rejected
     at S2 (verify under the descriptor key fails).
  HONEST — committed descriptor, valid signature, valid PoW, chained -> ACCEPT.

Mirrors T17's crux assertion: an IDENTITY-ONLY rule that checks S1+S2 but does NOT bind
info_digest into the PoW (i.e. treats the descriptor as a free side-field) ACCEPTS the
payout-redirect family C, while the composed rule REJECTS it.

ed25519 (RFC 8032) signatures are DETERMINISTIC: same key + message -> same 64-byte sig.
Keys are derived from fixed seeds via sha256 (no RNG). So the golden vector is
sha256-identical across runs, exactly like T17.

Run: python3 t18_identity_leg_sig_payout.py
"""
from __future__ import annotations
import argparse, hashlib, json, sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.exceptions import InvalidSignature

MAX256 = 1 << 256


def sha(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def target_for_bits(bits: int) -> int:
    return (1 << (256 - bits)) - 1


def work_of(target: int) -> int:
    return MAX256 // (target + 1)


# ----------------------------- identity (deterministic) -----------------------------
def key_from_seed(label: bytes) -> Ed25519PrivateKey:
    """Deterministic ed25519 private key from a fixed label (sha256 -> 32-byte seed)."""
    return Ed25519PrivateKey.from_private_bytes(sha(b"v37-id-seed", label))


def pub_bytes(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes_raw()


def payout_descriptor(pubkey: bytes, script_type: str) -> dict:
    """Who gets paid: a payout key + its script type (byte-denominated, per M2 h_min)."""
    return {"pubkey": pubkey.hex(), "script_type": script_type}


def descriptor_bytes(desc: dict) -> bytes:
    """Canonical serialization of the descriptor for hashing (sorted, deterministic)."""
    return json.dumps(desc, sort_keys=True, separators=(",", ":")).encode()


def info_digest_of(desc: dict) -> bytes:
    return sha(b"v37-info-digest", descriptor_bytes(desc))


# --- a share = PoW-committed payload (info_digest is INSIDE it) + descriptor + sig ---
def payload_commit(info_digest: bytes, k: int) -> bytes:
    """The PoW-committed payload. info_digest (the payout binding) is part of it, so any
    descriptor swap that updates info_digest changes the payload -> changes share_id."""
    return sha(b"v37-payload", info_digest, k.to_bytes(4, "little"))


def share_id(prev: bytes, payload: bytes, nonce: int) -> bytes:
    return sha(b"v37-share", prev, payload, nonce.to_bytes(8, "little"))


def mine_share(prev: bytes, payload: bytes, target: int, start: int = 0):
    nonce = start
    while True:
        sid = share_id(prev, payload, nonce)
        if int.from_bytes(sid, "big") <= target:
            return nonce, sid
        nonce += 1


def build_share(prev: bytes, k: int, bits: int, sk: Ed25519PrivateKey, script_type: str):
    """Honestly build share k: descriptor = sk's payout, commit info_digest into the PoW
    payload, grind nonce, then sign the share_id with sk (identity binding)."""
    target = target_for_bits(bits)
    desc = payout_descriptor(pub_bytes(sk), script_type)
    info = info_digest_of(desc)
    payload = payload_commit(info, k)
    nonce, sid = mine_share(prev, payload, target)
    sig = sk.sign(sid)                       # sign over the share_id (canonical msg)
    return {"prev": prev, "k": k, "info_digest": info, "payout_descriptor": desc,
            "payload": payload, "nonce": nonce, "target": target, "id": sid,
            "sig": sig.hex()}


def build_tail(boundary: bytes, n: int, bits: int, sk: Ed25519PrivateKey,
               script_type: str = "p2wpkh"):
    tail, prev = [], boundary
    for k in range(n):
        s = build_share(prev, k, bits, sk, script_type)
        tail.append(s)
        prev = s["id"]
    return tail


# --------------------- the work leg (T17, reused) + identity leg ---------------------
def chained(tail, boundary: bytes) -> bool:
    prev = boundary
    for s in tail:
        if s["prev"] != prev:
            return False
        if s["id"] != share_id(s["prev"], s["payload"], s["nonce"]):
            return False
        prev = s["id"]
    return True


def every_share_pow(tail) -> bool:
    return all(int.from_bytes(s["id"], "big") <= s["target"] for s in tail)


def commitment_binds(tail) -> bool:
    """S1: the carried descriptor hashes to info_digest, AND info_digest is the one the
    PoW-committed payload commits to (payload == payload_commit(info_digest, k))."""
    for s in tail:
        if info_digest_of(s["payout_descriptor"]) != s["info_digest"]:
            return False
        if s["payload"] != payload_commit(s["info_digest"], s["k"]):
            return False
    return True


def signatures_valid(tail) -> bool:
    """S2: each sig verifies under the pubkey IN that share's descriptor, over share_id."""
    for s in tail:
        try:
            pk = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(s["payout_descriptor"]["pubkey"]))
            pk.verify(bytes.fromhex(s["sig"]), s["id"])
        except (InvalidSignature, ValueError):
            return False
    return True


def accept_tail_composed(tail, boundary: bytes):
    """FULL rule = T17 work leg (chain + per-share PoW) AND identity leg (S1 commitment +
    S2 signature). Returns (valid, why)."""
    if not chained(tail, boundary):
        return (False, "unchained/spliced")
    if not every_share_pow(tail):
        return (False, "per-share-PoW-fail")
    if not commitment_binds(tail):
        return (False, "descriptor-commitment-mismatch")
    if not signatures_valid(tail):
        return (False, "bad-signature")
    return (True, "ok")


def accept_tail_identity_only(tail, boundary: bytes):
    """The WEAK rule the identity-leg crux faults: verify S1+S2 (descriptor self-consistent
    + signed) but treat the descriptor as a FREE side-field NOT bound into PoW — i.e. skip
    the work leg's commitment that info_digest lives inside the mined payload. Models a node
    that trusts a 'self-consistent, signed' payout without re-checking it was the mined one.
    Here: chained-by-prev only + S1 + S2, NO per-share-PoW re-grind requirement."""
    # accept if descriptor hashes to its own info_digest and the sig verifies — even if the
    # payload/PoW no longer matches (descriptor was swapped post-mining).
    for s in tail:
        if info_digest_of(s["payout_descriptor"]) != s["info_digest"]:
            return (False, "id-only-commit-fail")
    return (signatures_valid(tail), "identity-only")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--df", type=int, default=12, help="tail length D_f (shares)")
    ap.add_argument("--bits", type=int, default=16, help="per-share PoW bits")
    args = ap.parse_args()

    boundary = sha(b"finalized-boundary-roots@tip-Df")
    honest_sk = key_from_seed(b"honest-miner")
    sybil_sk = key_from_seed(b"relay-sybil")

    # HONEST tail.
    honest = build_tail(boundary, args.df, args.bits, honest_sk)

    # Family A: PAYOUT-REDIRECT, stale commitment. Take honest, rewrite each descriptor's
    # pubkey to the sybil's (steal payout) but DO NOT touch info_digest/payload/sig.
    forgedA = [dict(s) for s in honest]
    for s in forgedA:
        d = dict(s["payout_descriptor"]); d["pubkey"] = pub_bytes(sybil_sk).hex()
        s["payout_descriptor"] = d              # info_digest now stale -> S1 fails

    # Family B: FORGED SIGNATURE. Honest descriptor, but replace each sig with the sybil's
    # signature over the same share_id (sybil lacks the honest private key).
    forgedB = [dict(s) for s in honest]
    for s in forgedB:
        s["sig"] = sybil_sk.sign(s["id"]).hex()  # verifies under sybil key, not honest -> S2 fails

    # Family C: SELF-CONSISTENT REWRITE (cross-leg crux). Sybil swaps descriptor to its own
    # key, recomputes info_digest, recomputes payload, self-signs — identity leg consistent.
    # But it does NOT re-grind PoW (re-mining at honest difficulty is the whole cost it
    # avoids), so the kept honest nonce no longer meets target and the chain link breaks.
    forgedC, prev = [], boundary
    for s in honest:
        d = payout_descriptor(pub_bytes(sybil_sk), s["payout_descriptor"]["script_type"])
        info = info_digest_of(d)
        payload = payload_commit(info, s["k"])
        nonce = s["nonce"]                       # KEEP honest nonce (no re-grind)
        sid = share_id(prev, payload, nonce)     # id changes -> PoW almost surely fails
        sig = sybil_sk.sign(sid).hex()           # self-signed: S1+S2 hold
        forgedC.append({"prev": prev, "k": s["k"], "info_digest": info,
                        "payout_descriptor": d, "payload": payload, "nonce": nonce,
                        "target": s["target"], "id": sid, "sig": sig})
        prev = sid                               # chain forgedC internally consistently

    # Family D: UNBOUND-KEY. Descriptor advertises honest key, signer is the sybil, and
    # info_digest matches the (honest-key) descriptor -> S1 passes, S2 fails on key mismatch.
    forgedD = [dict(s) for s in honest]
    for s in forgedD:
        s["sig"] = sybil_sk.sign(s["id"]).hex()  # signer != descriptor.pubkey

    candidates = [("honest", honest), ("forgedA_redirect", forgedA),
                  ("forgedB_forgedsig", forgedB), ("forgedC_selfconsistent", forgedC),
                  ("forgedD_unboundkey", forgedD)]

    print("=== M5 T18: delta-tail identity leg — payout-descriptor commitment + signature ===")
    print(f"D_f={args.df} shares, bits={args.bits}\n")
    print("candidate                  chain  pow   S1-commit  S2-sig   COMPOSED   id-only")
    res = {}
    for name, tail in candidates:
        ch = chained(tail, boundary)
        pw = every_share_pow(tail)
        s1 = commitment_binds(tail)
        s2 = signatures_valid(tail)
        comp_ok, why = accept_tail_composed(tail, boundary)
        id_only_ok, _ = accept_tail_identity_only(tail, boundary)
        res[name] = {"valid": comp_ok, "why": why, "id_only": id_only_ok}
        print(f"{name:25s}  {str(ch):5s} {str(pw):5s} {str(s1):9s} {str(s2):6s} "
              f"{'ACCEPT' if comp_ok else 'reject':9s} "
              f"{'ACCEPT' if id_only_ok else 'reject'}")

    checks = {
        "honest_accepted":             res["honest"]["valid"] is True,
        "redirect_rejected_commit":    res["forgedA_redirect"]["valid"] is False
                                        and res["forgedA_redirect"]["why"] == "descriptor-commitment-mismatch",
        "forgedsig_rejected_S2":       res["forgedB_forgedsig"]["valid"] is False
                                        and res["forgedB_forgedsig"]["why"] == "bad-signature",
        "selfconsistent_rejected_pow": res["forgedC_selfconsistent"]["valid"] is False
                                        and res["forgedC_selfconsistent"]["why"] in
                                            ("per-share-PoW-fail", "unchained/spliced"),
        "unboundkey_rejected_S2":      res["forgedD_unboundkey"]["valid"] is False
                                        and res["forgedD_unboundkey"]["why"] == "bad-signature",
        # the crux: an identity-only rule (descriptor as free signed side-field, NOT bound
        # into PoW) ACCEPTS the payout-redirect family C, while the composed rule REJECTS it.
        "idonly_accepts_selfconsistent": res["forgedC_selfconsistent"]["id_only"] is True,
        "composed_rejects_selfconsistent": res["forgedC_selfconsistent"]["valid"] is False,
    }
    print("\n--- golden invariants ---")
    allok = True
    for k, v in checks.items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
        allok = allok and v

    golden = {
        "boundary": boundary.hex(),
        "honest_tip": honest[-1]["id"].hex(),
        "honest_payout_pubkey": honest[0]["payout_descriptor"]["pubkey"],
        "honest_info_digest_0": honest[0]["info_digest"].hex(),
        "honest_sig_0": honest[0]["sig"],
        "sybil_pubkey": pub_bytes(sybil_sk).hex(),
        "forgedC_tip": forgedC[-1]["id"].hex(),
        "verdicts": {k: res[k]["why"] for k in res},
    }
    print("\n--- golden vector ---")
    print(json.dumps(golden, indent=2))

    print(f"\nRESULT: {'ALL PASS' if allok else 'FAIL'} — "
          f"F1 identity leg (payout-descriptor commitment + signature, bound into PoW) "
          f"{'TESTED & HOLDS' if allok else 'BROKEN'}.")
    sys.exit(0 if allok else 1)


if __name__ == "__main__":
    main()
