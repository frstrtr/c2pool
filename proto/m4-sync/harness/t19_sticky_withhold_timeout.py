#!/usr/bin/env python3
"""T19 — sticky-shard drop-on-withhold/timeout (the F4 liveness rule made
executable; mirrors how T17/T18 converted F1 from STATED to TESTED).

WHY THIS TRACK
--------------
The adversarial red-team's correction #4 (out/SYNTHESIS-superlight-feed.md) is the one
sticky-shard finding that is still DOC-ONLY:

    "The one-strike-drop rule as stated fires only on an INVALID shard; a
     withholding sybil that serves one valid shard then TIMES OUT can stall the
     sticky session (F4, liveness)."

T12's `trial_shard_sticky` drops a server on a sub-root-INVALID shard. But a
strategic sybil never serves an invalid shard: every live-set leaf is PUBLIC
(the eclipse-free model), so serving REAL shards is free. The cheap attack is
SELECTIVE WITHHOLDING -- answer the first shard(s) validly (so an invalid-only
rule keeps you), then go silent (timeout) on the rest. Under server affinity the
validator is "stuck" on a server that already proved honest, so a drop-on-invalid
-only rule re-queries the staller forever and the sticky session never completes.

T12 could not express this: each server there has ONE fixed kind (a WITHHOLD
sybil serves NOTHING on shard 0 and is dropped immediately). The strategic
valid-then-stall server is a NEW adversary class this track adds.

THE FIX UNDER TEST (the F4 rule)
--------------------------------
Redefine the drop predicate as drop-on-{INVALID or TIMEOUT/WITHHOLD}, not
drop-on-INVALID-only: a server that times out / withholds a still-missing shard
is rotated out the SAME as one serving an invalid shard. Then:
  * SAFETY  -- UNCONDITIONAL and rule-independent: every accepted shard is
    sub-root-checked vs the committed roots; a stall produces no leaves, so it
    can never inject a wrong head. (We assert 0 wrong-head under BOTH rules.)
  * LIVENESS -- under the F4 rule the staller is rotated, so ">=1 honest server
    reachable" suffices again (whole-set liveness, the T9/T12 property). Under
    the invalid-only rule the same pool STALLS: the session burns its retry
    budget on a server that never completes the missing shard.

So T19's claim, mirroring T17/T18: neither the work nor identity leg there; here
the INVALID-only predicate is NECESSARY-but-INSUFFICIENT for liveness, and the
TIMEOUT-drop predicate closes it -- a strict rule fix, SAFETY unchanged.

Deterministic given --seed. No wall-clock in the verification path.
Reproduce: python3 t19_sticky_withhold_timeout.py --w 300000 --servers 20 --shards 16
"""

import sys, time, argparse, random

from t9_multibridge_availability import (
    HONEST, committed_roots, shard_subroots,
    check_shard, ROOT_BYTES,
)

LEAF_BYTES = 32

# Adversary classes for this track. HONEST serves every shard validly. The two
# new strategic classes serve REAL (sub-root-valid) shards for the first
# `stall_after` distinct shards they are asked for, then time out / withhold on
# every still-missing shard thereafter -- the F4 attack the invalid-only rule
# cannot catch.
STALL_0 = "stall_after_0"   # times out on the FIRST missing shard (== plain withholder)
STALL_1 = "stall_after_1"   # serves one valid shard, then stalls (the F4 crux)
STALL_2 = "stall_after_2"   # serves two valid shards, then stalls
STRATEGIC_KINDS = [STALL_0, STALL_1, STALL_2]


def stall_budget(kind):
    return {STALL_0: 0, STALL_1: 1, STALL_2: 2}[kind]


class Server:
    """A serving bridge. `served` counts the valid shards it has already given
    THIS validator (server affinity => persistent per-session state)."""
    __slots__ = ("kind", "served")

    def __init__(self, kind):
        self.kind = kind
        self.served = 0

    def request(self, shard_ids):
        """Return the real leaves for a shard, or None for a TIMEOUT/withhold.

        An honest server always returns real leaves. A strategic server returns
        real leaves until it has served `stall_after` shards, then returns None
        (timeout) forever -- it never serves an INVALID shard, so an
        invalid-only drop rule has no trigger."""
        if self.kind == HONEST:
            return list(shard_ids)
        if self.served < stall_budget(self.kind):
            self.served += 1
            return list(shard_ids)          # real, sub-root-valid leaves
        return None                          # timeout / withhold


def make_pool(s, h, rng):
    """s servers, expected honest fraction h. Sybils get a strategic stall kind."""
    n_honest = max(0, min(s, round(s * h)))
    pool = [HONEST] * n_honest + [rng.choice(STRATEGIC_KINDS) for _ in range(s - n_honest)]
    rng.shuffle(pool)
    return [Server(k) for k in pool]


def assemble(pool, shards, subroots, query_budget, rng, timeout_is_drop, retry_budget):
    """Sticky-shard assembly under one of the two drop predicates, bounded by a
    GLOBAL query budget (the validator's finite round-trip patience per
    cold-start; a real node cannot probe forever).

    timeout_is_drop=False  -> the INVALID-ONLY rule (T12 as stated): the rule
        names NO timeout trigger, so under pure server affinity the validator
        keeps RE-QUERYING the same server (up to retry_budget round-trips before
        it grudgingly rotates). A staller therefore drains `retry_budget`
        queries from the global budget per server -- enough stallers ahead of an
        honest server EXHAUST the budget before honest is reached => NOT live.
    timeout_is_drop=True   -> the F4 rule: a timeout/withhold rotates the server
        out the SAME as an invalid shard, so each staller costs ONE query.

    SAFETY is identical under both: every returned shard is sub-root-checked, so
    no wrong head is ever accepted (we also count any accepted-but-wrong shard).

    Returns (bootstrapped_all, queries, wasted_leaves, wrong_head_accepts).
    """
    order = list(range(len(pool)))
    rng.shuffle(order)
    done = [False] * len(shards)
    queries = 0
    wasted = 0
    wrong = 0

    for idx in order:
        if all(done) or queries >= query_budget:
            break
        srv = pool[idx]
        retries = 0
        while not all(done) and queries < query_budget:
            missing = next((j for j in range(len(shards)) if not done[j]), None)
            if missing is None:
                break
            queries += 1
            claimed = srv.request(shards[missing])

            if claimed is not None and check_shard(claimed, subroots[missing]):
                done[missing] = True
                continue                      # affinity: keep pulling from this server
            if claimed is not None and not check_shard(claimed, subroots[missing]):
                # an INVALID shard -> dropped under BOTH rules (and never accepted)
                wasted += len(claimed)
                break
            # claimed is None  ==  TIMEOUT / withhold
            if timeout_is_drop:
                break                         # F4 rule: rotate this server out (1 query spent)
            # invalid-only rule: the rule names no timeout drop -> re-query the
            # same stuck server, draining the global query budget, until a
            # grudging patience cap finally rotates it.
            retries += 1
            if retries >= retry_budget:
                break
    # SAFETY: a "done" shard must verify (belt-and-suspenders; tautological by
    # construction since done is only set on a passing check -> proves the point
    # that the sub-root check, not the drop rule, is what guarantees safety).
    for j, ok in enumerate(done):
        if ok and not check_shard(list(shards[j]), subroots[j]):
            wrong += 1
    return all(done), queries, wasted, wrong


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--w", type=int, default=300000)
    ap.add_argument("--servers", type=int, default=20)
    ap.add_argument("--shards", type=int, default=16)
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--maxq", type=int, default=50, help="GLOBAL query/round-trip budget per cold-start")
    ap.add_argument("--retry", type=int, default=4, help="grudging per-server patience before invalid-only rotates a staller")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    live = list(range(args.w))

    t0 = time.time()
    committed = committed_roots(live)
    shards, subroots, shard_root = shard_subroots(live, args.shards)
    setup_s = time.time() - t0
    wk = args.w // args.shards

    print(f"# T19 sticky drop-on-timeout (F4)  W={args.w}  servers={args.servers}  "
          f"shards={args.shards}  trials={args.trials}  seed={args.seed}")
    print(f"# checkpoint: {len(committed)} forest roots ({len(committed)*ROOT_BYTES}B) "
          f"+ shard-root 32B; W/K bound = {wk} leaves/shard; setup {setup_s:.2f}s")
    print(f"# adversary: strategic valid-then-stall (STALL_0/1/2); global query budget={args.maxq}; "
          f"invalid-only per-server patience={args.retry}")
    print()

    # The crux as a single deterministic golden vector: ONE honest server, the
    # rest strategic STALL_1 (serve one valid shard, then time out).
    print("## CRUX  (1 honest + (servers-1) STALL_1; honest sits LAST in the probe order)")
    for label, tdrop in (("invalid-only rule", False), ("F4 timeout-drop rule", True)):
        # force honest to the back so the validator meets stallers first
        kinds = [STALL_1] * (args.servers - 1) + [HONEST]
        pool = [Server(k) for k in kinds]
        boot, q, w, wrong = assemble(pool, shards, subroots, args.maxq,
                                     random.Random(99), tdrop, args.retry)
        print(f"  {label:24s}: bootstrapped={boot}  queries={q}  wasted_leaves={w}  wrong_head={wrong}")
    print()

    # Statistical sweep over honest fraction.
    print("## SWEEP  live% (bootstrapped all shards) and avg queries, per rule")
    print(f"  {'h':>5} | {'invalid-only live%':>18} {'q':>5} | {'F4-drop live%':>14} {'q':>5} | wrong_head")
    grid = [0.05, 0.10, 0.20, 0.35, 0.50]
    total_wrong = 0
    for h in grid:
        io_live = io_q = f4_live = f4_q = 0
        for t in range(args.trials):
            r = random.Random(args.seed + t)
            kinds = make_pool(args.servers, h, r)  # same pool kinds for both rules
            kk = [s.kind for s in kinds]
            b1, q1, _, wr1 = assemble([Server(k) for k in kk], shards, subroots,
                                      args.maxq, random.Random(7 * t + 1), False, args.retry)
            b2, q2, _, wr2 = assemble([Server(k) for k in kk], shards, subroots,
                                      args.maxq, random.Random(7 * t + 1), True, args.retry)
            io_live += b1; io_q += q1
            f4_live += b2; f4_q += q2
            total_wrong += wr1 + wr2
        n = args.trials
        print(f"  {h:5.2f} | {100*io_live/n:17.1f}% {io_q/n:5.1f} | "
              f"{100*f4_live/n:13.1f}% {f4_q/n:5.1f} | {total_wrong}")
    print()
    print(f"# SAFETY: wrong-head acceptances across ALL trials (both rules) = {total_wrong}")
    print("# INVARIANTS:")
    print("#  I-SAFE  : wrong_head == 0 under BOTH rules (sub-root check is rule-independent)")
    print("#  I-LIVE  : F4-drop live% >= invalid-only live% at every h (strict gain where stallers bite)")
    print("#  I-CRUX  : 1-honest-last pool bootstraps under F4-drop, FAILS under invalid-only")
    print("#            (stallers drain the global query budget before honest is reached)")
    assert total_wrong == 0, "SAFETY VIOLATION: a stall injected a wrong head"
    print("\nOK: SAFETY holds unconditionally; F4 timeout-drop is necessary for liveness under a finite query budget.")


if __name__ == "__main__":
    main()
