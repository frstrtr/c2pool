"""Executable acceptance tests for the three rev3 falsifiers (roundabout-rev3.md §9).

AT-REPAIR    <- F-REPAIR    (§1 leg 1, the operative weak clause of R(atomic))
AT-SPINE     <- F-SPINE     (§1 third bullet, §4 spine-reorg-after-broadcast)
AT-BROADCAST <- F-BROADCAST (§4 coin-chain orphan, D_conf gate)

Every test carries a RED BASELINE: the named guard in model.Guards whose disabling makes it
fail. `run_all.py --red-matrix` proves the baseline the way a KAT does.
"""

from __future__ import annotations

from model import Config, Guards, World

MINERS = ("m0", "m1", "m2")

# Harness RUN LENGTH for the N-free monotone-progress property (AT-SPINE/S3). This is how many
# settled windows we watch, NOT an acceptance deadline: no verdict is derived from reaching it.
RUN_WINDOWS = 12


class Case:
    """One acceptance test: a list of (check-id, passed, note) plus a numeric record."""

    def __init__(self, tid: str, falsifier: str, red_guards: tuple[str, ...]):
        self.tid = tid
        self.falsifier = falsifier
        self.red_guards = red_guards
        self.checks: list[tuple[str, bool]] = []
        self.record: dict = {}

    def check(self, cid: str, cond) -> bool:
        ok = bool(cond)
        self.checks.append((cid, ok))
        return ok

    def note(self, k, v):
        self.record[k] = v

    @property
    def passed(self) -> bool:
        return all(ok for _, ok in self.checks)

    def as_log(self) -> dict:
        return {"test": self.tid, "falsifier": self.falsifier,
                "checks": [{"id": c, "pass": ok} for c, ok in self.checks],
                "record": self.record}


# ============================================================================================
# AT-REPAIR  --  F-REPAIR
# ============================================================================================


def at_repair(cfg: Config, guards: Guards) -> Case:
    c = Case("AT-REPAIR", "F-REPAIR", ("forward_repair", "remint_on_orphan"))

    # ---- R1: burial-deferred slice on a lagging chain is repaired within N_repair windows --
    w = World(cfg, guards)
    for i in range(11):
        w.add_share(MINERS[i % 3])
    late_idx = w.add_share("late")           # the freshest share: entitled, not yet payable
    w.find_block("B")                        # chain B's first (lagging) window settles
    earned_late = w.earned("B").get("late", 0)
    c.check("R1a in-window share is entitled on the lagging chain", earned_late > 0)
    c.check("R1b D_spine gate defers it (payable == 0)", w.payable("B").get("late", 0) == 0)
    c.check("R1c nothing broadcast to it yet", w.moved("B").get("late", 0) == 0)

    repaired_at = w.repair_windows(
        "B",
        lambda: w.owed_signed("B").get("late", 0) == 0 and w.moved("B").get("late", 0) > 0,
        cfg.N_repair, filler="f")
    c.check("R1d repaired within N_repair windows",
            repaired_at != -1 and repaired_at <= cfg.N_repair)
    c.check("R1e verdict REPAIRED",
            w.f_repair_verdict("B", "late", late_idx,
                               repaired_at if repaired_at != -1 else cfg.N_repair + 1)
            == "REPAIRED")
    c.check("R1f no invariant violation", not w.violations)
    c.note("R1_repaired_at_window", repaired_at)
    c.note("R1_earned_late", earned_late)
    c.note("R1_moved_late", w.moved("B").get("late", 0))

    # ---- R2: an orphaned coinbase's slice is re-owed and re-minted by a later window -------
    w2 = World(cfg, guards)
    for i in range(14):
        w2.add_share(MINERS[i % 3])
    w2.find_block("B")
    w2.add_share("m0")
    w2.add_share("m1")
    b2 = w2.find_block("B")
    mv_pre = dict(w2.moved("B"))
    # b2 is orphaned by a COMPETING miner's block at the same height: the chain never shortens
    # (MD-3 ruling A, Guards.monotone_height), and the replacement pays this pool nothing, so
    # the orphaned slice is genuinely outstanding -- nothing re-minted yet.
    dropped = w2.coin_reorg("B", depth=1, replace=1, foreign=True)
    mv_post = dict(w2.moved("B"))
    owed_post = dict(w2.owed("B"))
    hurt = {m: v for m, v in mv_pre.items() if mv_post.get(m, 0) < v}
    # what the ledger must now deliver: what is still standing, plus what was re-owed
    target = {m: mv_post.get(m, 0) + v for m, v in owed_post.items()}
    c.check("R2a the orphaned block is off the canonical history",
            b2 in dropped and not w2.chains["B"].is_live(b2))
    c.check("R2b its payouts are orphaned and still PENDING",
            any(p.block is b2 and not p.settled for p in w2.orphaned_pending()))
    c.check("R2b2 non-vacuous: miners actually lost broadcast value", bool(hurt))
    c.check("R2b3 the orphaned slice RETURNED TO OWED", sum(owed_post.values()) > 0)
    c.check("R2c nothing silently vanished", w2.vanished() == 0)
    repaired = w2.repair_windows(
        "B", lambda: all(w2.moved("B").get(m, 0) >= t for m, t in target.items()),
        cfg.N_repair)
    # N_repair here is a bounded SEARCH BUDGET for §4's coin-orphan re-mint, not the spine
    # bound (MD-5 de-alias): the spine mechanism is N-free, see AT-SPINE/S3c.
    c.check("R2d the re-owed slice is re-minted within N_repair windows",
            repaired != -1 and repaired <= cfg.N_repair)
    w2.quiesce("B")
    pay, mv = w2.payable("B"), w2.moved("B")
    c.check("R2e at quiescence every in-window miner is made exactly whole",
            all(mv.get(m, 0) == pay.get(m, 0) for m in pay))
    c.check("R2f no miner ends FALSIFIES:F-REPAIR",
            not any(w2.f_repair_falsified("B", m, None, cfg.N_repair + 1) for m in pay))
    c.check("R2g no invariant violation", not w2.violations)
    c.note("R2_repaired_at_window", repaired)
    c.note("R2_hurt_miners", sorted(hurt))
    c.note("R2_reorg_dropped", len(dropped))

    # ---- R3: EXCLUSION -- window expiry. Constructed, and asserted NOT a falsification. ----
    w3 = World(cfg, guards)
    exp_idx = w3.add_share("expire")
    for i in range(cfg.W_pplns + 4):
        w3.add_share(MINERS[i % 3])
    w3.find_block("A")                        # A pays; the 'expire' share is inside A's window?
    for i in range(4):
        w3.add_share(MINERS[i % 3])
    w3.find_block("B")                        # B finally settles: the share has aged out
    c.check("R3a the share is outside the lagging chain's PPLNS window",
            not w3.in_pplns_window(exp_idx))
    c.check("R3b so it is never credited on the lagging chain",
            w3.earned("B").get("expire", 0) == 0)
    c.check("R3c verdict is the declared exclusion, not a falsifier",
            w3.f_repair_verdict("B", "expire", exp_idx, cfg.N_repair + 99)
            == "EXCLUDED:window-expiry")
    c.check("R3d NOT counted as F-REPAIR falsification",
            not w3.f_repair_falsified("B", "expire", exp_idx, cfg.N_repair + 99))
    c.note("R3_expire_earned_B", w3.earned("B").get("expire", 0))

    # ---- R4: EXCLUSION -- miner departure after being paid (the §1 over-credit residual) ---
    w4 = World(cfg, guards)
    for _ in range(6):
        w4.add_share("m0")
    dep_first = w4.spine.height
    for _ in range(6):
        w4.add_share("dep")
    w4.add_share("m1")
    w4.add_share("m1")
    w4.find_block("B")
    moved_dep = w4.moved("B").get("dep", 0)
    c.check("R4a the departing miner was paid before departure", moved_dep > 0)
    depth = w4.spine.height - dep_first       # deep enough to rewrite records already paid for
    w4.spine_reorg(depth, ["m3"] * (depth + 1))
    d_after = w4.owed_signed("B").get("dep", 0)
    c.check("R4b the re-derivation leaves it over-credited", d_after < 0)
    w4.depart("dep")
    c.check("R4c verdict is the declared exclusion",
            w4.f_repair_verdict("B", "dep", None, cfg.N_repair + 99)
            == "EXCLUDED:miner-departure")
    c.check("R4d NOT counted as F-REPAIR falsification",
            not w4.f_repair_falsified("B", "dep", None, cfg.N_repair + 99))
    c.check("R4e funds already broadcast were not clawed back",
            w4.moved("B").get("dep", 0) == moved_dep)
    c.note("R4_overcredit_residual", -d_after)
    return c


# ============================================================================================
# AT-SPINE  --  F-SPINE
# ============================================================================================


def at_spine(cfg: Config, guards: Guards) -> Case:
    c = Case("AT-SPINE", "F-SPINE", ("spine_burial", "forward_repair"))

    # ---- S1: the D_spine gate holds over a schedule of reorgs at depth <= D_spine ----------
    w = World(cfg, guards)
    for i in range(10):
        w.add_share(MINERS[i % 3])
    w.find_block("A")
    for step in range(8):
        w.add_share("m0")
        w.add_share("m1")
        w.find_block("B" if step % 2 else "A")
        d = 1 + (step % cfg.D_spine)                  # depths 1..D_spine
        w.spine_reorg(d, [f"r{step}"] * (d + 1))      # height strictly grows
    c.check("S1a no broadcast was made against a prefix a later reorg rewrote",
            w.broadcast_prefix_rewritten() == [])
    c.check("S1b nothing vanished", w.vanished() == 0)
    c.check("S1c no invariant violation", not w.violations)
    c.check("S1d non-vacuous: payouts and reorgs both happened",
            len(w.payouts) > 0 and len(w.spine.rewrite_events) == 8)
    c.note("S1_payouts", len(w.payouts))
    c.note("S1_reorgs", len(w.spine.rewrite_events))

    # ---- S2: a reorg shallower than the gate re-derives SILENTLY (no external effect) ------
    w2 = World(cfg, guards)
    for i in range(12):
        w2.add_share(MINERS[i % 3])
    w2.find_block("A")
    before = [(p.pid, p.miner, p.amount) for p in w2.payouts]
    tail_before = [r.sid for r in w2.spine.records[-cfg.D_spine:]]
    w2.spine_reorg(cfg.D_spine, [f"q{i}" for i in range(cfg.D_spine + 1)])
    after = [(p.pid, p.miner, p.amount) for p in w2.payouts]
    tail_after = [r.sid for r in w2.spine.records[-(cfg.D_spine + 1):]]
    pay2, mv2 = w2.payable("A"), w2.moved("A")
    c.check("S2a the reorg really rewrote the tail (non-vacuous)",
            tail_before != tail_after[:len(tail_before)])
    c.check("S2b silent: no payout emitted, none unwound", before == after)
    c.check("S2c no broadcast prefix touched", w2.broadcast_prefix_rewritten() == [])
    c.check("S2d re-derivation created no over-credit",
            all(mv2.get(m, 0) <= pay2.get(m, 0) for m in set(mv2) | set(pay2)))
    c.check("S2e nothing vanished", w2.vanished() == 0)
    c.check("S2f no invariant violation", not w2.violations)

    # ---- S3: a reorg DEEPER than the gate -- §1's priced residual, repaired forward --------
    w3 = World(cfg, guards)
    for _ in range(4):
        w3.add_share("m0")
    for _ in range(4):
        w3.add_share("m1")
    for _ in range(6):
        w3.add_share("m2")
    w3.find_block("B")
    mv_before = dict(w3.moved("B"))
    deep = cfg.D_spine + 2
    w3.spine_reorg(deep, ["m3"] * (deep + 1))
    c.check("S3a the exhibit exists: a broadcast prefix WAS re-derived away",
            w3.broadcast_prefix_rewritten() != [])
    osig = w3.owed_signed("B")
    over = sorted(m for m, v in osig.items() if v < 0)
    under = sorted(m for m, v in osig.items() if v > 0)
    c.check("S3b divergence appears in both directions", bool(over) and bool(under))
    # MD-5 ruling C (integrator ruling 2026-08-30, reply to the MD decision mail): the
    # post-broadcast spine-repair leg is N-FREE. It is no longer asserted as "repaired within
    # N_repair windows" (that deadline was shown unfalsifiable -- see the S3 probe below);
    # it is asserted as MONOTONE PROGRESS: at every settled window until the aggregate
    # under-credit reaches zero, that aggregate strictly decreases.
    prog = w3.repair_monotone("B", under, RUN_WINDOWS)
    c.check("S3c under-credit strictly decreases at every settled window until it is zero "
            "(monotone progress; NO deadline, N_repair not consulted)",
            prog["strictly_decreasing"])
    c.check("S3c2 non-vacuous: the aggregate started positive over a non-empty active set",
            prog["series"][0] > 0 and prog["actives"][0] > 0)
    c.check("S3c3 monotone progress therefore drives the aggregate to zero",
            prog["cleared_at_window"] != -1)
    mv_after = w3.moved("B")
    c.check("S3d over-credit is NOT clawed back (effect boundary honoured)",
            all(mv_after.get(m, 0) >= mv_before.get(m, 0) for m in over))
    c.check("S3e no payout is ever issued while owed is negative",
            all(w3.owed("B").get(m, 0) == 0 for m in over))
    c.check("S3f the residual is surfaced, not silent",
            sum(-v for v in w3.owed_signed("B").values() if v < 0) > 0)
    c.check("S3g not an F-SPINE falsification: the divergence was corrected forward "
            "(no under-credit left on the active set) -- stated without any N",
            w3.under_credit("B", under) == 0)
    c.note("S3_reorg_depth", deep)
    c.note("S3_over_credited", over)
    c.note("S3_under_credited", under)
    c.note("S3_undercredit_series", prog["series"])
    c.note("S3_drained_at_window", prog["cleared_at_window"])
    c.note("S3_residual_units",
           sum(-v for v in w3.owed_signed("B").values() if v < 0))
    # ---- B SIZING -- INFORMATIONAL, not a pass/fail check (MD-5 ruling C, second leg) ------
    # "does steady-state payable creation per settled window stay below one block reward?"
    # This is the quantity that decides whether the one-reward coinbase budget can drain the
    # backlog at all. Reported, never asserted.
    c.note("INFO_B_sizing_payable_created_per_window", prog["payable_created"])
    c.note("INFO_B_sizing_max_payable_created", prog["max_payable_created"])
    c.note("INFO_B_sizing_one_block_reward", cfg.BLOCK_REWARD)
    c.note("INFO_B_sizing_stayed_below_one_block_reward",
           bool(prog["max_payable_created"] < cfg.BLOCK_REWARD))

    # ---- S4: PROBES (no pass/fail) --------------------------------------------------------
    # Kept as RECORDED OBSERVATIONS per MD-5 ruling C. The first probe is the original one --
    # the first reorg depth whose divergence does not clear within N_repair windows. It is the
    # evidence that the DEADLINE reading was unfalsifiable, and it survives the ruling as an
    # observation only: it is not asserted, and N_repair no longer governs this mechanism.
    # The second probe is its N-free counterpart: the first depth at which MONOTONE PROGRESS
    # itself stalls (a settled window that fails to strictly decrease the aggregate). That is
    # where the newly-ruled property would bite, and the spec should know the number.
    boundary = None
    mono_stall = None
    for d in range(cfg.D_spine + 1, cfg.D_spine + 8):
        p = World(cfg, guards)
        for _ in range(4):
            p.add_share("m0")
        for _ in range(4):
            p.add_share("m1")
        for _ in range(6):
            p.add_share("m2")
        p.find_block("B")
        p.spine_reorg(d, ["m3"] * (d + 1))
        u = [m for m, v in p.owed_signed("B").items() if v > 0]
        k = p.repair_windows("B",
                             lambda: all(p.owed_signed("B").get(m, 0) <= 0 for m in u),
                             cfg.N_repair)
        if k == -1 and boundary is None:
            boundary = d

        q = World(cfg, guards)
        for _ in range(4):
            q.add_share("m0")
        for _ in range(4):
            q.add_share("m1")
        for _ in range(6):
            q.add_share("m2")
        q.find_block("B")
        q.spine_reorg(d, ["m3"] * (d + 1))
        uq = [m for m, v in q.owed_signed("B").items() if v > 0]
        mp = q.repair_monotone("B", uq, RUN_WINDOWS)
        if not mp["strictly_decreasing"] and mono_stall is None:
            mono_stall = d
        if boundary is not None and mono_stall is not None:
            break
    c.note("S3_probe_first_depth_not_clearing_in_N_repair", boundary)
    c.note("S3_probe_first_depth_monotone_progress_stalls", mono_stall)
    return c


# ============================================================================================
# AT-BROADCAST  --  F-BROADCAST
# ============================================================================================


def at_broadcast(cfg: Config, guards: Guards) -> Case:
    c = Case("AT-BROADCAST", "F-BROADCAST",
             ("remint_on_orphan", "conf_depth", "canonical_history", "monotone_height"))

    # ---- B1: a coin-chain reorg orphans a payout -> re-owed, re-minted, funds never vanish -
    w = World(cfg, guards)
    for i in range(14):
        w.add_share(MINERS[i % 3])
    w.find_block("A")
    w.add_share("m0")
    w.add_share("m1")
    b = w.find_block("A")
    orphan_amt = sum(p.amount for p in w.payouts if p.block is b)
    mv_pre = dict(w.moved("A"))
    c.check("B1a the block being orphaned did broadcast a payout", orphan_amt > 0)
    # orphaned by a competing miner's block at the same height (chain never shortens -- MD-3
    # ruling A); the replacement pays this pool nothing, so nothing is re-minted yet
    w.coin_reorg("A", depth=1, replace=1, foreign=True)
    mv_post = dict(w.moved("A"))
    owed_post = dict(w.owed("A"))
    hurt = {m: v for m, v in mv_pre.items() if mv_post.get(m, 0) < v}
    target = {m: mv_post.get(m, 0) + v for m, v in owed_post.items()}
    c.check("B1b the orphaned coinbase moved no funds",
            all(not w.funds_moved(p) for p in w.payouts if p.block is b) and bool(hurt))
    c.check("B1b2 the orphaned amount RETURNED TO OWED", sum(owed_post.values()) > 0)
    c.check("B1c nothing vanished (ledger belief == funds actually moved)", w.vanished() == 0)
    remint = w.repair_windows(
        "A", lambda: all(w.moved("A").get(m, 0) >= t for m, t in target.items()), cfg.N_repair)
    # as in R2d: N_repair as a bounded search budget for the coin-orphan re-mint (MD-5 de-alias)
    c.check("B1d it is re-minted by a later settlement",
            remint != -1 and remint <= cfg.N_repair)
    w.quiesce("A")
    pay, mv = w.payable("A"), w.moved("A")
    c.check("B1e every miner exactly whole after re-mint",
            all(mv.get(m, 0) == pay.get(m, 0) for m in pay))
    c.check("B1f no invariant violation", not w.violations)
    c.note("B1_orphaned_amount", orphan_amt)
    c.note("B1_remint_window", remint)

    # ---- B2: SETTLED marking respects D_conf ----------------------------------------------
    w2 = World(cfg, guards)
    for i in range(12):
        w2.add_share(MINERS[i % 3])
    for k in range(6):
        w2.add_share(MINERS[k % 3])
        w2.find_block("A")
    settled = [p for p in w2.payouts if p.settled]
    c.check("B2a some payouts reached SETTLED", len(settled) > 0)
    c.check("B2b none marked SETTLED below D_conf confirmations",
            w2.settled_below_conf() == [])
    c.check("B2c every SETTLED payout held >= D_conf confirmations when marked",
            all(p.settled_at_conf >= cfg.D_conf for p in settled))
    c.check("B2d payouts younger than D_conf are still PENDING",
            all(p.settled is False for p in w2.payouts
                if w2.chains["A"].is_live(p.block)
                and w2.chains["A"].confirmations(p.block) < cfg.D_conf))
    c.note("B2_settled", len(settled))
    c.note("B2_pending", sum(1 for p in w2.payouts if not p.settled))

    # ---- B3: the loss sub-case is unreachable for reorgs shallower than D_conf -------------
    w3 = World(cfg, guards)
    for i in range(12):
        w3.add_share(MINERS[i % 3])
    for k in range(8):
        w3.add_share(MINERS[k % 3])
        w3.find_block("A")
        if k % 3 == 2:
            w3.coin_reorg("A", depth=cfg.D_conf - 1, replace=cfg.D_conf - 1)
    c.check("B3a no SETTLED payout was ever orphaned", w3.orphaned_settled() == [])
    c.check("B3b nothing vanished under sub-D_conf reorgs", w3.vanished() == 0)
    c.check("B3c no invariant violation", not w3.violations)
    w3.quiesce("A")
    pay3, mv3 = w3.payable("A"), w3.moved("A")
    c.check("B3d at quiescence the ledger drains to exact payable",
            all(mv3.get(m, 0) == pay3.get(m, 0) for m in pay3))
    c.note("B3_reorgs", 3)
    c.note("B3_payouts", len(w3.payouts))

    # ---- B4: orphan-then-deeper-reorg never double-pays -----------------------------------
    w4 = World(cfg, guards)
    for i in range(12):
        w4.add_share(MINERS[i % 3])
    for k in range(5):
        w4.add_share(MINERS[k % 3])
        w4.find_block("B")
    w4.coin_reorg("B", depth=2, replace=2)     # equal-height competing branch, our blocks
    w4.add_share("m2")
    w4.coin_reorg("B", depth=1, replace=3)     # strictly longer branch
    ceiling = len(w4.chains["B"].blocks) * cfg.BLOCK_REWARD
    c.check("B4a total broadcast <= total minted by the canonical chain",
            sum(w4.moved("B").values()) <= ceiling)
    c.check("B4b no miner received more than its high-water entitlement",
            all(v <= w4.earned_hw[("B", m)] for m, v in w4.moved("B").items()))
    c.check("B4c no invariant violation", not w4.violations)
    c.note("B4_moved", sum(w4.moved("B").values()))
    c.note("B4_ceiling", ceiling)

    # ---- B5: the ACCEPTED residual -- a reorg at/over D_conf orphans a SETTLED payout ------
    # Reading (a) of MD-2 is now SPEC-FIXED (integrator ruling 2026-08-30, reply to the MD
    # decision mail): SETTLED is terminal and D_conf is a genuine acceptance parameter,
    # symmetric with D_spine, so a reorg beyond it is a priced probabilistic residual and not
    # a falsification. The harness asserts the residual is exactly bounded and surfaced rather
    # than silent. The competing branch is STRICTLY LONGER (MD-3 ruling A), which is what a
    # real beyond-acceptance reorg is; its blocks are a competing miner's, so no re-mint
    # muddies the residual arithmetic.
    w5 = World(cfg, guards)
    for i in range(12):
        w5.add_share(MINERS[i % 3])
    for k in range(6):
        w5.add_share(MINERS[k % 3])
        w5.find_block("B")
    settled_before = [p for p in w5.payouts if p.settled]
    w5.coin_reorg("B", depth=cfg.D_conf + 1, replace=cfg.D_conf + 2, foreign=True)
    os = w5.orphaned_settled()
    c.check("B5a a beyond-acceptance reorg does orphan a SETTLED payout",
            len(settled_before) > 0 and len(os) > 0)
    c.check("B5b the residual is exactly bounded by the orphaned SETTLED amount",
            w5.vanished() == sum(p.amount for p in os))
    c.check("B5c the residual is surfaced by the model, not silent",
            w5.vanished() > 0 and len(w5.violations) > 0)
    c.note("B5_orphaned_settled_units", sum(p.amount for p in os))
    c.note("B5_reorg_depth", cfg.D_conf + 1)

    # ---- B6: the MD-3 clause PREVENTS the composition hazard ------------------------------
    # MD-3 is now SPEC-FIXED (integrator ruling 2026-08-30, reply to the MD decision mail),
    # reading A: "settlement state is only advanced or re-evaluated against a monotonically
    # non-decreasing best-chain height."  The hazard it closes: if a node could observe a
    # SHORTER new tip, confirmations would fall and two reorgs each shallower than D_conf
    # would compose into a rewrite deeper than D_conf, orphaning a payout already marked
    # SETTLED (CONS found this at 11/100 schedules before the schedule bound was declared).
    # Under the clause each shortening candidate is simply not adopted, so the composition
    # never reaches the settled blocks. B6 now asserts the PREVENTION.
    # RED ARM: `--red monotone_height` disables the clause and the 11/100-style violation
    # returns -- B6a/b/c/d go red. That arm is the red-matrix row for this guard.
    w6 = World(cfg, guards)
    for i in range(12):
        w6.add_share(MINERS[i % 3])
    for k in range(6):
        w6.add_share(MINERS[k % 3])
        w6.find_block("B")
    settled_ids = {p.pid for p in w6.payouts if p.settled}
    shallow = cfg.D_conf - 1
    hw_before = w6.chains["B"].height_hw
    # two candidate branches, each a sub-D_conf rewrite that LEAVES THE CHAIN SHORTER
    w6.coin_reorg("B", depth=shallow, replace=0)
    w6.coin_reorg("B", depth=shallow, replace=0)
    orphaned_settled_ids = {p.pid for p in w6.orphaned_settled()}
    c.check("B6a non-vacuous: SETTLED payouts exist and the composed rewrite would be deeper "
            "than D_conf", bool(settled_ids) and shallow < cfg.D_conf
            and 2 * shallow > cfg.D_conf)
    c.check("B6b the clause refuses both shortening candidates (settlement is not "
            "re-evaluated against a lower height)", len(w6.rejected_reorgs) == 2)
    c.check("B6c best-chain height never fell below its persisted high-water",
            w6.chains["B"].height >= hw_before
            and w6.chains["B"].height_hw == hw_before)
    c.check("B6d NO SETTLED payout is orphaned -- the composition hazard cannot arise",
            not (settled_ids & orphaned_settled_ids) and w6.orphaned_settled() == [])
    c.check("B6e nothing vanished and no invariant violation",
            w6.vanished() == 0 and not w6.violations)
    c.note("B6_shallow_depth", shallow)
    c.note("B6_composed_depth", 2 * shallow)
    c.note("B6_rejected_candidates", len(w6.rejected_reorgs))
    c.note("B6_height_high_water", w6.chains["B"].height_hw)
    c.note("B6_lost_units", w6.vanished())
    return c


ALL_CASES = (at_repair, at_spine, at_broadcast)
