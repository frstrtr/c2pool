"""CONS -- the cross-invariant: conservation across arbitrary seeded reorg schedules.

Property-tested over N_SCHEDULES seeded random schedules mixing spine growth, spine reorgs
(at and beyond the D_spine gate), block finds on two coin chains, and coin-chain reorgs.

Checked after EVERY event (model.World.check_invariants):
  CONS-0  no non-positive payout
  CONS-1  no value creation: funds actually moved <= that miner's high-water entitlement,
          and per chain, total moved <= (canonical blocks) x BLOCK_REWARD
  CONS-2  ledger fidelity: what the ledger believes it paid == what actually moved
  CONS-3  exact accounting: ledger_paid + owed_signed == payable
Checked after quiescence:
  CONS-4  every positive owed drains to zero for every non-departed miner

SCHEDULE BOUND (declared, not accidental): coin-chain reorgs are drawn shallower than D_conf.
A reorg at or beyond D_conf orphans a SETTLED payout, which under §4's acceptance reading is
a priced residual, not a conservation failure -- it is exercised separately by AT-BROADCAST/B5.
Spine reorgs ARE drawn beyond D_spine (that residual is repaired forward, so it must conserve).
"""

from __future__ import annotations

import random

from model import Config, Guards, World

N_SCHEDULES = 100
EVENTS_PER_SCHEDULE = 30
QUIESCE_WINDOWS = 14
MINER_POOL = ("m0", "m1", "m2", "m3")


def run_schedule(seed: int, cfg: Config, guards: Guards) -> dict:
    rng = random.Random(seed)
    w = World(cfg, guards)
    # warm-up so the first blocks have a window to pay
    for i in range(cfg.W_pplns + cfg.D_spine):
        w.add_share(MINER_POOL[i % len(MINER_POOL)])

    deep_spine = 0
    coin_reorgs = 0
    for _ in range(EVENTS_PER_SCHEDULE):
        roll = rng.random()
        if roll < 0.40:
            w.add_share(rng.choice(MINER_POOL))
        elif roll < 0.70:
            w.find_block(rng.choice(("A", "B")))
        elif roll < 0.88:
            # spine reorg; height is non-decreasing (a sharechain reorg switches to a
            # longer branch), so successive reorgs do not compose into a deeper rewrite.
            if rng.random() < 0.80:
                d = rng.randint(1, cfg.D_spine)
            else:
                d = rng.randint(cfg.D_spine + 1, cfg.D_spine + 3)
                deep_spine += 1
            d = min(d, w.spine.height)
            n_new = d + rng.randint(1, 2)
            w.spine_reorg(d, [rng.choice(MINER_POOL) for _ in range(n_new)])
        else:
            cname = rng.choice(("A", "B"))
            if w.chains[cname].height >= 1 and cfg.D_conf > 1:
                d = rng.randint(1, cfg.D_conf - 1)      # strictly shallower than D_conf
                # a coin-chain reorg switches to a STRICTLY LONGER branch, so chain height is
                # non-decreasing and confirmations never fall. This is no longer merely the
                # schedule's own discipline: MD-3 is spec-fixed (integrator ruling 2026-08-30,
                # reply to the MD decision mail, reading A) and Guards.monotone_height now
                # enforces it, so any shortening candidate would be refused outright
                # (AT-BROADCAST/B6). The schedule stays as written, which makes the guard
                # inert here -- CONS conserves for the same reason it always did.
                w.coin_reorg(cname, depth=d, replace=d + rng.randint(1, 2))
                coin_reorgs += 1

    # ---- quiescence: miners stop submitting, chains keep finding blocks ------------------
    for cname in ("A", "B"):
        w.quiesce(cname, QUIESCE_WINDOWS)

    residual = {}
    for cname in ("A", "B"):
        left = {m: v for m, v in w.owed(cname).items() if m not in w.departed}
        if left:
            residual[cname] = left
    return {
        "seed": seed,
        "violations": len(w.violations),
        "first_violation": w.violations[0] if w.violations else None,
        "undrained": residual,
        "deep_spine_reorgs": deep_spine,
        "coin_reorgs": coin_reorgs,
        "payouts": len(w.payouts),
        "moved_A": sum(w.moved("A").values()),
        "moved_B": sum(w.moved("B").values()),
        "blocks_A": len(w.chains["A"].ours_blocks),
        "blocks_B": len(w.chains["B"].ours_blocks),
    }


def conservation(cfg: Config, guards: Guards):
    from acceptance import Case
    c = Case("CONS", "cross-invariant",
             ("canonical_history", "remint_on_orphan", "conf_depth",
              "forward_repair", "spine_burial"))
    results = [run_schedule(s, cfg, guards) for s in range(N_SCHEDULES)]

    bad = [r for r in results if r["violations"]]
    undrained = [r for r in results if r["undrained"]]
    ceiling_ok = all(r["moved_A"] <= r["blocks_A"] * cfg.BLOCK_REWARD
                     and r["moved_B"] <= r["blocks_B"] * cfg.BLOCK_REWARD for r in results)

    c.check(f"CONS-1/2/3 hold at every step of all {N_SCHEDULES} schedules", not bad)
    c.check("CONS-1 per-chain value ceiling never exceeded", ceiling_ok)
    c.check("CONS-4 every positive owed drains at quiescence", not undrained)
    c.check("non-vacuous: schedules exercised deep spine reorgs",
            sum(r["deep_spine_reorgs"] for r in results) > 0)
    c.check("non-vacuous: schedules exercised coin-chain reorgs",
            sum(r["coin_reorgs"] for r in results) > 0)
    c.check("non-vacuous: schedules broadcast payouts",
            sum(r["payouts"] for r in results) > 0)

    c.note("schedules", N_SCHEDULES)
    c.note("events_per_schedule", EVENTS_PER_SCHEDULE)
    c.note("total_payouts", sum(r["payouts"] for r in results))
    c.note("total_deep_spine_reorgs", sum(r["deep_spine_reorgs"] for r in results))
    c.note("total_coin_reorgs", sum(r["coin_reorgs"] for r in results))
    c.note("schedules_with_violation", len(bad))
    c.note("schedules_undrained", len(undrained))
    c.note("first_violation", bad[0]["first_violation"] if bad else None)
    c.note("moved_total", sum(r["moved_A"] + r["moved_B"] for r in results))
    return c
