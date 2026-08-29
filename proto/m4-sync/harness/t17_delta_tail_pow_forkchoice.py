#!/usr/bin/env python3
"""M4 T17: delta-tail acceptance — per-share PoW + highest-cumulative-work fork choice.

Closes the ONE real red-team finding (F1) for the superlight cold-start model by
converting its *stated* defense into a *tested* one with a deterministic golden vector.

F1 (adversarial cold-start red-team finding): the PoW-anchored delta tail
(`tip-D_f`..`tip`) was applied to the trustless snapshot on block-HEADER PoW +
committed-root only, with NO per-share work check. A sybil serving the tail can inject
forged shares under valid block headers; the validator accepts a non-canonical
(non-final) live-set view. The red-team's stated defense:

    "delta-tail acceptance must do per-share PoW + pick the highest-cumulative-work
     fork, not header-PoW + committed-root only."

This harness builds the smallest faithful model of that defense and proves it rejects
the forged-tail families the red-team named:

  V (validator) holds a trustless FINALIZED boundary hash B = roots @ tip-D_f (root-
  checked, safe). It must extend its view across the NON-final tail to `tip`. A peer
  serves a candidate tail = an ordered list of shares, each carrying its own block
  header with its own PoW (hashPrevBlock => the prior share's id; share PoW <= target).

  accept_tail(tail, B, target):
    1. CHAIN: share[0].prev == B; share[k].prev == id(share[k-1]).  (no splicing)
    2. PER-SHARE PoW: id(share) = sha256(header) <= target for EVERY share.
    3. cumulative work = sum over shares of work(target_k), work = (2^256 // (target+1)).
    fork_choice(candidates) := the VALID (chained + every-share-PoW) tail of MAX
    cumulative work. Ties broken by lexicographically-smallest tip id (deterministic).

  The header-PoW+root-only rule the red-team faulted = step 1 + a root check only,
  WITHOUT step 2/3. T17 shows that rule accepts forged tails that the full rule rejects.

Forged-tail families tested (all from a minority-hashrate sybil):
  A. NO per-share PoW  — shares with nonces that do NOT satisfy target. Rejected at
     step 2. (The exact case the old header-only rule MISSED.)
  B. spliced/unchained — a real honest prefix + a forged suffix whose prev link is
     rewritten. Rejected at step 1.
  C. valid-PoW minority fork — the sybil really mines a competing tail, but at its
     minority hashrate to an EASIER target / fewer shares. Passes steps 1+2 but loses
     fork choice on cumulative work (step 3). This is the only family that survives
     verification; cumulative-work choice is what defeats it.

PoW is modeled by real nonce-grinding to a leading-zero-bits target (sha256, no RNG;
nonce counts up from 0 -> fully deterministic). "Hashrate" = grind budget; the honest
chain is given strictly more cumulative work than the minority sybil, as in the threat
model's >50%-honest-share-work assumption (same floor M1's finality overlay stands on).

Run: python3 t17_delta_tail_pow_forkchoice.py
Deterministic: sha256 only, no randomness, no wall-clock in the accept/fork-choice path.
"""
from __future__ import annotations
import argparse, hashlib, json, sys

MAX256 = 1 << 256


def sha(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def target_for_bits(bits: int) -> int:
    """A PoW target of `bits` leading zero bits: id <= target iff top `bits` bits zero."""
    return (1 << (256 - bits)) - 1


def work_of(target: int) -> int:
    """Expected hashes to beat `target` = 2^256 / (target+1); the share's work weight."""
    return MAX256 // (target + 1)


# --- a share = its block header (prev link, payload commitment, nonce) + claimed target ---
def share_id(prev: bytes, payload: bytes, nonce: int) -> bytes:
    return sha(b"v37-share", prev, payload, nonce.to_bytes(8, "little"))


def mine_share(prev: bytes, payload: bytes, target: int, start: int = 0):
    """Grind nonce up from `start` until share_id <= target. Deterministic. Returns the
    valid share dict and the grind cost (hashes tried) so we can model hashrate budget."""
    nonce = start
    while True:
        sid = share_id(prev, payload, nonce)
        if int.from_bytes(sid, "big") <= target:
            return {"prev": prev, "payload": payload, "nonce": nonce,
                    "target": target, "id": sid}, (nonce - start + 1)
        nonce += 1


def build_tail(boundary: bytes, n: int, bits: int, tag: bytes):
    """Honestly mine a chained tail of n shares from `boundary` at `bits` difficulty."""
    target = target_for_bits(bits)
    tail, prev = [], boundary
    for k in range(n):
        payload = sha(tag, k.to_bytes(4, "little"))   # deterministic per-share payload
        s, _cost = mine_share(prev, payload, target)
        tail.append(s)
        prev = s["id"]
    return tail


# ------------------------------ the defense under test ------------------------------
def chained(tail, boundary: bytes) -> bool:
    """Step 1: tail[0] extends the finalized boundary and every link is intact."""
    prev = boundary
    for s in tail:
        if s["prev"] != prev:
            return False
        # the id must be the actual hash of the claimed header (no asserted ids)
        if s["id"] != share_id(s["prev"], s["payload"], s["nonce"]):
            return False
        prev = s["id"]
    return True


def every_share_pow(tail) -> bool:
    """Step 2: EVERY share's id satisfies its own claimed target (per-share PoW)."""
    return all(int.from_bytes(s["id"], "big") <= s["target"] for s in tail)


def cumulative_work(tail) -> int:
    """Step 3: total work = sum of per-share work weights."""
    return sum(work_of(s["target"]) for s in tail)


def accept_tail_full(tail, boundary: bytes):
    """FULL rule (F1 defense): chain + per-share PoW gate, then return work for fork
    choice. Returns (valid, work). A tail failing chain or per-share PoW is invalid."""
    if not chained(tail, boundary):
        return (False, 0, "unchained/spliced")
    if not every_share_pow(tail):
        return (False, 0, "per-share-PoW-fail")
    return (True, cumulative_work(tail), "ok")


def accept_tail_header_only(tail, boundary: bytes):
    """OLD rule the red-team faulted: chain + root, NO per-share PoW, NO work choice.
    Models 'header-PoW + committed-root only' — accepts anything that merely chains."""
    return (chained(tail, boundary), 0, "header-only")


def fork_choice(candidates, boundary: bytes):
    """Pick the VALID tail of max cumulative work; tie-break on smallest tip id."""
    scored = []
    for name, tail in candidates:
        valid, work, why = accept_tail_full(tail, boundary)
        scored.append((name, tail, valid, work, why))
    valids = [c for c in scored if c[2]]
    if not valids:
        return None, scored
    best = max(valids, key=lambda c: (c[3], [-b for b in c[1][-1]["id"]]))
    return best, scored


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--df", type=int, default=12, help="tail length D_f (shares)")
    ap.add_argument("--bits", type=int, default=16, help="honest per-share PoW bits")
    args = ap.parse_args()

    # Trustless finalized boundary roots @ tip-D_f (root-checked upstream; safe anchor).
    boundary = sha(b"finalized-boundary-roots@tip-Df")

    # HONEST tail: D_f shares, full difficulty (majority-work chain).
    honest = build_tail(boundary, args.df, args.bits, b"honest")

    # Family A: forged tail, NO valid per-share PoW (nonces=0, ids won't meet target).
    forgedA, prev = [], boundary
    tgt = target_for_bits(args.bits)
    for k in range(args.df):
        payload = sha(b"sybilA", k.to_bytes(4, "little"))
        nonce = 0  # no grind => overwhelmingly fails the leading-zero target
        forgedA.append({"prev": prev, "payload": payload, "nonce": nonce,
                        "target": tgt, "id": share_id(prev, payload, nonce)})
        prev = forgedA[-1]["id"]

    # Family B: honest prefix + spliced forged suffix (prev link rewritten to skip).
    forgedB = [dict(s) for s in honest[: args.df // 2]]
    spliced = build_tail(boundary, args.df - args.df // 2, args.bits, b"sybilB")
    # rewrite the splice point's prev to a WRONG (non-matching) ancestor
    spliced[0]["prev"] = sha(b"wrong-ancestor")
    spliced[0]["id"] = share_id(spliced[0]["prev"], spliced[0]["payload"], spliced[0]["nonce"])
    # the spliced[0] was mined against `boundary`, so its id no longer meets target either,
    # but family B is about the CHAIN break — re-mine so PoW holds, isolating the splice.
    spliced[0], _ = mine_share(spliced[0]["prev"], spliced[0]["payload"], target_for_bits(args.bits))
    # relink the rest of the spliced suffix onto the (wrong-ancestor) re-mined head
    relinked, p = [spliced[0]], spliced[0]["id"]
    for s in spliced[1:]:
        ns, _ = mine_share(p, s["payload"], target_for_bits(args.bits))
        relinked.append(ns)
        p = ns["id"]
    forgedB = forgedB + relinked  # prefix tip id != relinked[0].prev => chain break

    # Family C: sybil REALLY mines a competing valid tail, but minority hashrate =>
    # easier target (fewer bits) and/or fewer shares => less cumulative work.
    sybil_bits = args.bits - 4            # 16x easier per share (minority hashrate)
    sybil_len = max(1, args.df - 4)       # and a shorter tail
    forgedC = build_tail(boundary, sybil_len, sybil_bits, b"sybilC")

    candidates = [("honest", honest), ("forgedA_nopow", forgedA),
                  ("forgedB_spliced", forgedB), ("forgedC_minoritywork", forgedC)]

    print("=== M4 T17: delta-tail per-share PoW + cumulative-work fork choice ===")
    print(f"D_f={args.df} shares, honest bits={args.bits}, "
          f"sybilC bits={sybil_bits} len={sybil_len}\n")

    # 1) Per-candidate verdict under the OLD header-only rule vs the FULL F1 defense.
    print("candidate                 chained  per-share-PoW  cum-work        full-rule  header-only")
    for name, tail in candidates:
        ch = chained(tail, boundary)
        pw = every_share_pow(tail)
        cw = cumulative_work(tail) if (ch and pw) else 0
        full_ok = ch and pw
        hdr_ok = accept_tail_header_only(tail, boundary)[0]
        print(f"{name:24s}  {str(ch):5s}    {str(pw):5s}          "
              f"{cw:<14d}  {'ACCEPT' if full_ok else 'reject':9s}  "
              f"{'ACCEPT' if hdr_ok else 'reject'}")

    # 2) Fork choice across all candidates under the FULL rule.
    best, scored = fork_choice(candidates, boundary)
    print()
    winner = best[0] if best else None
    print(f"fork_choice winner (max valid cumulative work): {winner}")

    # 3) Assertions — the golden invariants T17 pins.
    res = {c[0]: {"valid": c[2], "work": c[3], "why": c[4]} for c in scored}
    checks = {
        "honest_accepted":          res["honest"]["valid"] is True,
        "forgedA_rejected_nopow":   res["forgedA_nopow"]["valid"] is False
                                     and res["forgedA_nopow"]["why"] == "per-share-PoW-fail",
        "forgedB_rejected_splice":  res["forgedB_spliced"]["valid"] is False
                                     and res["forgedB_spliced"]["why"] == "unchained/spliced",
        "forgedC_valid_but_loses":  res["forgedC_minoritywork"]["valid"] is True
                                     and res["forgedC_minoritywork"]["work"] < res["honest"]["work"],
        "forkchoice_picks_honest":  winner == "honest",
        # the crux: the OLD header-only rule WOULD have accepted forgedA (the F1 bug)
        "headeronly_accepts_forgedA": accept_tail_header_only(forgedA, boundary)[0] is True,
        "fullrule_rejects_forgedA":   res["forgedA_nopow"]["valid"] is False,
    }
    print("\n--- golden invariants ---")
    allok = True
    for k, v in checks.items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
        allok = allok and v

    # Golden vector: deterministic ids + work, stable across runs (no RNG/clock).
    golden = {
        "boundary": boundary.hex(),
        "honest_tip": honest[-1]["id"].hex(),
        "honest_cum_work": res["honest"]["work"],
        "sybilC_cum_work": res["forgedC_minoritywork"]["work"],
        "work_ratio_honest_over_sybilC": round(
            res["honest"]["work"] / max(1, res["forgedC_minoritywork"]["work"]), 3),
        "winner": winner,
    }
    print("\n--- golden vector ---")
    print(json.dumps(golden, indent=2))

    print(f"\nRESULT: {'ALL PASS' if allok else 'FAIL'} — "
          f"F1 defense (per-share PoW + cumulative-work fork choice) "
          f"{'TESTED & HOLDS' if allok else 'BROKEN'}.")
    sys.exit(0 if allok else 1)


if __name__ == "__main__":
    main()
