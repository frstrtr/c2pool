"""rev3 falsifier acceptance model — executable model of the adopted construction.

Source of truth: ../../../../v37-work/roundabout-rev3.md
  §1  per-chain settlement as a pure function of a shared accounting spine, next-window repair,
      spine burial share-depth acceptance parameter
  §4  the two post-broadcast cases (coin-chain reorg -> orphaned coinbase, funds never moved,
      re-mint from unchanged spine, SETTLED gated by coin-chain confirmation depth;
      spine reorg after broadcast -> funds-gone case under burial acceptance)
  §9  F-REPAIR / F-SPINE / F-BROADCAST and their exclusion clauses

Design-track prototype. No c2pool code, no consensus logic, LOCAL/HELD.

--------------------------------------------------------------------------------------------
MODEL IN ONE PARAGRAPH
--------------------------------------------------------------------------------------------
The SPINE is an append-only log of share records, reorg-prone (tail rewrite up to depth d).
Two coin chains A and B each keep a single canonical block list (reorg = truncate + extend).
Per-chain settlement is a PURE FOLD: for each canonical block b of chain c, b generates
BLOCK_REWARD of entitlement distributed over the PPLNS window `spine[b.prefix-W : b.prefix]`
read from the CURRENT spine (nothing is cached, so a spine reorg re-derives by construction).
That per-record entitlement is EARNED. The subset of it attributable to records buried at
least D_spine deep in the current spine is PAYABLE -- the broadcast gate. A block's coinbase
broadcasts `payable - ledger_paid` (forward repair; unclamped, so over-credit is netted
against future entitlement rather than clawed back), capped at BLOCK_REWARD, largest-first.
A broadcast payout is PENDING until it has D_conf confirmations on its own chain, then SETTLED.
An orphaned PENDING payout returns to owed (funds never moved); a later block re-mints it.

INTEGRATOR RULINGS FOLDED IN (ruling of 2026-08-30, reply to the MD decision mail):
  MD-2 = (a) HARDENED. SETTLED is terminal and D_conf is a genuine acceptance parameter
         symmetric with D_spine; `Config.SETTLED_TERMINAL` is spec-fixed, not a knob.
  MD-3 = A.  Settlement state is only advanced or re-evaluated against a monotonically
         non-decreasing best-chain height -- `Guards.monotone_height`, backed by the
         persisted per-chain high-water `Chain.height_hw`. A candidate branch that would
         leave the chain shorter than its high-water is not adopted (World.coin_reorg), so
         the two-sub-D_conf-reorg composition hazard cannot arise (AT-BROADCAST/B6).
         Consequence for the model: an orphan is exhibited by a COMPETING MINER'S block at
         equal or greater height (`Block.ours = False`) -- it occupies chain height, pays this
         pool nothing, and generates no entitlement -- rather than by shortening the chain.
  MD-5 = C.  The post-broadcast SPINE-repair leg is N-free: MONOTONE PROGRESS
         (`World.repair_monotone`), not a deadline. `Config.N_repair` now governs only the
         leg-1 lagging-chain repair (AT-REPAIR/R1).
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field, replace

# ============================================================================================
# CONFIG BLOCK -- the spec addendum references these names verbatim.
# ============================================================================================


@dataclass(frozen=True)
class Config:
    # --- the three rev3 acceptance parameters -------------------------------------------
    N_repair: int = 3      # §1/§9 F-REPAIR: repair-window parameter, counted in PPLNS windows
                           #        (a window settles when the chain finds the block paying it).
                           #        MD-5 DE-ALIAS (integrator ruling 2026-08-30, reply to the MD
                           #        decision mail, reading C): N_repair governs ONLY the leg-1
                           #        lagging-chain repair -- AT-REPAIR/R1. The post-broadcast
                           #        SPINE-repair mechanism (AT-SPINE/S3) is now N-FREE: it is
                           #        stated as monotone progress, not as a deadline. The name is
                           #        deliberately NOT renamed (spec addendum cites it verbatim).
                           #        AT-REPAIR/R2 and AT-BROADCAST/B1 still pass N_repair to
                           #        repair_windows(), but only as a bounded SEARCH BUDGET for the
                           #        coin-orphan re-mint of §4, not as the spine bound.
    D_spine: int = 4       # §1     spine burial share-depth acceptance parameter, in share
                           #        records; a payout may only be broadcast against records
                           #        buried >= D_spine deep in the current spine
    D_conf: int = 3        # §4     coin-chain confirmation-depth acceptance parameter; a
                           #        payout is SETTLED only at this depth on its own chain.
                           #        TOY VALUE: the normative floor is the chain's own coinbase
                           #        maturity; 3 sits deliberately below it so the beyond-
                           #        acceptance residual (B5) is cheap to exercise. See README.
    # --- model geometry (not rev3 parameters; harness scale knobs) -----------------------
    W_pplns: int = 8            # PPLNS window length, in share records
    BLOCK_REWARD: int = 1_000_000   # integer units; exact arithmetic, largest-remainder split
    SETTLED_TERMINAL: bool = True   # MD-2: FIXED by integrator ruling 2026-08-30 (reply to the
                                    # MD decision mail), reading (a) -- SETTLED is terminal and
                                    # D_conf is a genuine acceptance parameter symmetric with
                                    # D_spine. Spec-fixed, no longer an open knob.


# ============================================================================================
# GUARDS -- each is a mechanism rev3 requires. Disabling exactly one is the red baseline.
# ============================================================================================


@dataclass(frozen=True)
class Guards:
    # §1 "the next window's settlement is derived from the corrected spine, so over- and
    #     under-credits are corrected in subsequent payouts"
    forward_repair: bool = True
    # §1 "A payout broadcast is accepted against a spine prefix whose window is buried to the
    #     spec's share-depth parameter"
    spine_burial: bool = True
    # §4 "a payout is SETTLED only at that depth on its own chain"
    conf_depth: bool = True
    # §4 "an orphaned payout below it returns to owed"
    remint_on_orphan: bool = True
    # §1 "settlement is a per-chain pure function of that spine [and] the chain's own history"
    #    -- 'own history' means the CANONICAL history; orphaned blocks generate no entitlement.
    canonical_history: bool = True
    # §4 addendum -- MD-3, FIXED by integrator ruling 2026-08-30 (reply to the MD decision
    #    mail), reading A: "settlement state is only advanced or re-evaluated against a
    #    monotonically non-decreasing best-chain height." Modelled as a persisted per-chain
    #    height high-water (Chain.height_hw): while this guard is on, a candidate branch that
    #    would leave the chain shorter than its high-water is NOT ADOPTED, so settlement is
    #    never re-evaluated against it. Without the clause, two sub-D_conf reorgs compose into
    #    a rewrite deeper than D_conf and orphan a payout already marked SETTLED
    #    (AT-BROADCAST/B6; found by CONS at 11/100 schedules before the schedule bound).
    monotone_height: bool = True

    def disabled(self) -> str | None:
        for name in GUARD_NAMES:
            if not getattr(self, name):
                return name
        return None


GUARD_NAMES = ("forward_repair", "spine_burial", "conf_depth",
               "remint_on_orphan", "canonical_history", "monotone_height")


# ============================================================================================
# Deterministic exact split
# ============================================================================================


def largest_remainder(total: int, weights: list[int]) -> list[int]:
    """Split `total` over `weights` exactly. Deterministic tie-break: lower index first."""
    tw = sum(weights)
    if tw <= 0:
        return [0] * len(weights)
    base = [total * w // tw for w in weights]
    rem = total - sum(base)
    # fractional parts, scaled to integers to avoid float
    fracs = [(total * w) % tw for w in weights]
    order = sorted(range(len(weights)), key=lambda i: (-fracs[i], i))
    for i in order[:rem]:
        base[i] += 1
    return base


# ============================================================================================
# Spine
# ============================================================================================


@dataclass(frozen=True)
class Share:
    sid: str
    miner: str
    work: int


class Spine:
    """Append-only log of share records, subject to tail rewrite (reorg) up to depth d."""

    def __init__(self) -> None:
        self.records: list[Share] = []
        self._counter = 0
        self.ver = 0        # bumped on every mutation; keys the pure-fold memo
        self.rewrite_events: list[tuple[int, int]] = []   # (height_before, depth)

    @property
    def height(self) -> int:
        return len(self.records)

    def _mk(self, miner: str, work: int) -> Share:
        self._counter += 1
        sid = hashlib.sha256(f"share:{self._counter}:{miner}:{work}".encode()).hexdigest()[:12]
        return Share(sid=sid, miner=miner, work=work)

    def append(self, miner: str, work: int = 1) -> int:
        self.records.append(self._mk(miner, work))
        self.ver += 1
        return self.height - 1

    def reorg(self, depth: int, new_miners: list[str], work: int = 1) -> None:
        """Rewrite the last `depth` records, replacing them with `new_miners`."""
        depth = min(depth, self.height)
        self.rewrite_events.append((self.height, depth))
        if depth:
            del self.records[self.height - depth:]
        self.ver += 1
        for m in new_miners:
            self.append(m, work)


# ============================================================================================
# Coin chain
# ============================================================================================


@dataclass
class Block:
    bid: str
    height: int          # index in the canonical list
    spine_prefix: int    # spine height at find time (the tip prefix; NOT the burial-gated one)
    ours: bool = True    # False = a competing miner's block. It occupies chain height but
                         # generates no entitlement for this pool and broadcasts no coinbase
                         # payout, so a reorg can replace one of our blocks with a foreign one
                         # WITHOUT the chain ever shortening (see Guards.monotone_height).


class Chain:
    """One coin chain. Canonical history is a single list; a reorg truncates then extends,
    so a block and its descendants orphan together (no independently surviving branch).

    `height_hw` is the persisted best-chain height high-water: it never decreases, by
    construction. It is the state the MD-3 clause (Guards.monotone_height) is evaluated
    against -- see World.coin_reorg."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.blocks: list[Block] = []
        self.seen: list[Block] = []      # every block ever canonical (for the guard-off fold)
        self.height_hw = 0               # persisted high-water; never decreases
        self._counter = 0

    @property
    def height(self) -> int:
        return len(self.blocks)

    @property
    def ours_blocks(self) -> list[Block]:
        return [b for b in self.blocks if b.ours]

    def find(self, spine_prefix: int, ours: bool = True) -> Block:
        self._counter += 1
        bid = hashlib.sha256(f"blk:{self.name}:{self._counter}".encode()).hexdigest()[:12]
        b = Block(bid=bid, height=len(self.blocks), spine_prefix=spine_prefix, ours=ours)
        self.blocks.append(b)
        self.seen.append(b)
        if self.height > self.height_hw:
            self.height_hw = self.height
        return b

    def truncate(self, depth: int) -> list[Block]:
        depth = min(depth, self.height)
        dropped = self.blocks[self.height - depth:]
        if depth:
            del self.blocks[self.height - depth:]
        return dropped

    def confirmations(self, b: Block) -> int:
        """Tip block has 1 confirmation."""
        return self.height - b.height

    def is_live(self, b: Block) -> bool:
        return b.height < self.height and self.blocks[b.height] is b


# ============================================================================================
# Payouts -- the irreversible external effect (§4 effect boundary)
# ============================================================================================


@dataclass
class Payout:
    pid: str
    chain: str
    miner: str
    amount: int
    block: Block
    # the spine records this payout was broadcast against (index -> sid), frozen at broadcast.
    paid_records: dict[int, str]
    settled: bool = False        # sticky marking; see counted_as_paid()
    settled_at_conf: int | None = None


# ============================================================================================
# World
# ============================================================================================


class World:
    def __init__(self, cfg: Config | None = None, guards: Guards | None = None,
                 chains: tuple[str, ...] = ("A", "B")) -> None:
        self.cfg = cfg or Config()
        self.guards = guards or Guards()
        self.spine = Spine()
        self.chains: dict[str, Chain] = {c: Chain(c) for c in chains}
        self.payouts: list[Payout] = []
        self.departed: set[str] = set()
        self._pid = 0
        # running high-water of reference payable entitlement, per (chain, miner)
        self.earned_hw: dict[tuple[str, str], int] = defaultdict(int)
        self.violations: list[str] = []
        self.rejected_reorgs: list[tuple[str, int, int, int, int]] = []
        self.trace: list[dict] = []
        self._credit_memo: dict[tuple[int, int], dict[int, tuple[str, int]]] = {}

    # ------------------------------------------------------------------ spine / chain events

    def add_share(self, miner: str, work: int = 1) -> int:
        i = self.spine.append(miner, work)
        self._post_event(f"share:{miner}")
        return i

    def spine_reorg(self, depth: int, new_miners: list[str]) -> None:
        self.spine.reorg(depth, new_miners)
        self._post_event(f"spine_reorg:d={depth}")

    def find_block(self, cname: str) -> Block:
        ch = self.chains[cname]
        b = ch.find(self.spine.height)
        self._assemble_and_broadcast(cname, b)
        self._update_settled()
        self._post_event(f"block:{cname}")
        return b

    def coin_reorg(self, cname: str, depth: int, replace: int = 0,
                   foreign: bool = False) -> list[Block]:
        """Orphan the last `depth` blocks of `cname` and extend with `replace` new blocks.

        `foreign=True` makes the replacement blocks another miner's: they occupy chain height
        but generate no entitlement and broadcast no coinbase, which is how an orphan is
        exhibited without the chain shortening.

        MD-3 ruling A (Guards.monotone_height): a candidate branch that would leave the chain
        SHORTER than its persisted high-water is not adopted at all -- settlement state is only
        advanced or re-evaluated against a monotonically non-decreasing best-chain height. The
        rejection is recorded in `self.rejected_reorgs`, never silently swallowed.
        """
        ch = self.chains[cname]
        eff_depth = min(depth, ch.height)
        candidate_height = ch.height - eff_depth + replace
        if self.guards.monotone_height and candidate_height < ch.height_hw:
            self.rejected_reorgs.append((cname, depth, replace,
                                         candidate_height, ch.height_hw))
            self._post_event(f"coin_reorg_rejected:{cname}:d={depth}:r={replace}")
            return []
        dropped = ch.truncate(depth)
        self._update_settled()
        for _ in range(replace):
            b = ch.find(self.spine.height, ours=not foreign)
            if b.ours:
                self._assemble_and_broadcast(cname, b)
            self._update_settled()
        self._post_event(f"coin_reorg:{cname}:d={depth}:r={replace}")
        return dropped

    def depart(self, miner: str) -> None:
        self.departed.add(miner)

    # ------------------------------------------------------------------ the settlement fold

    def _block_credit(self, b: Block) -> dict[int, tuple[str, int]]:
        """PURE fold: (spine record index -> (miner, amount)) for block b, read from the
        CURRENT spine at b's frozen prefix length. The memo is keyed by the spine version,
        so it is an optimisation only -- a spine reorg invalidates it and the fold re-derives."""
        key = (b.spine_prefix, self.spine.ver)
        hit = self._credit_memo.get(key)
        if hit is not None:
            return hit
        val = self._block_credit_uncached(b)
        self._credit_memo[key] = val
        return val

    def _block_credit_uncached(self, b: Block) -> dict[int, tuple[str, int]]:
        p = min(b.spine_prefix, self.spine.height)
        lo = max(0, p - self.cfg.W_pplns)
        recs = self.spine.records[lo:p]
        if not recs:
            return {}
        amounts = largest_remainder(self.cfg.BLOCK_REWARD, [r.work for r in recs])
        return {lo + i: (recs[i].miner, amounts[i]) for i in range(len(recs))}

    def _blocks_for_fold(self, cname: str) -> list[Block]:
        """Only OUR blocks generate entitlement; a competing miner's block occupies chain
        height but pays this pool nothing."""
        ch = self.chains[cname]
        if self.guards.canonical_history:
            return [b for b in ch.blocks if b.ours]
        return [b for b in ch.seen if b.ours]     # RED: credits orphaned blocks too

    def _burial_cutoff(self) -> int:
        """Records with index <= cutoff are buried >= D_spine deep and therefore payable."""
        if not self.guards.spine_burial:
            return self.spine.height - 1        # RED: no gate, tip is payable
        return self.spine.height - self.cfg.D_spine - 1

    def earned(self, cname: str) -> dict[str, int]:
        """Total entitlement generated by the chain's history over the current spine."""
        out: dict[str, int] = defaultdict(int)
        for b in self._blocks_for_fold(cname):
            for _, (m, amt) in self._block_credit(b).items():
                out[m] += amt
        return dict(out)

    def payable(self, cname: str) -> dict[str, int]:
        """Entitlement attributable to records buried >= D_spine -- broadcastable now."""
        cutoff = self._burial_cutoff()
        out: dict[str, int] = defaultdict(int)
        for b in self._blocks_for_fold(cname):
            for idx, (m, amt) in self._block_credit(b).items():
                if idx <= cutoff:
                    out[m] += amt
        return dict(out)

    def reference_payable(self, cname: str) -> dict[str, int]:
        """Guard-independent reference: canonical fold + burial gate. Used for earned_hw so
        the conservation bound cannot be moved by the very guard under test."""
        cutoff = self.spine.height - self.cfg.D_spine - 1
        out: dict[str, int] = defaultdict(int)
        for b in self.chains[cname].ours_blocks:
            for idx, (m, amt) in self._block_credit(b).items():
                if idx <= cutoff:
                    out[m] += amt
        return dict(out)

    # ------------------------------------------------------------------ paid views

    def counted_as_paid(self, p: Payout) -> bool:
        """What the LEDGER believes was paid (drives owed)."""
        if self.chains[p.chain].is_live(p.block):
            return True
        if not self.guards.remint_on_orphan:
            return True                      # RED: orphan never returns to owed -> vanishes
        if p.settled and self.cfg.SETTLED_TERMINAL:
            return True                      # SETTLED is terminal (§4 acceptance; MD-2)
        return False

    def funds_moved(self, p: Payout) -> bool:
        """What actually moved in the world: only a canonical coinbase pays."""
        return self.chains[p.chain].is_live(p.block)

    def _agg(self, cname: str, pred) -> dict[str, int]:
        out: dict[str, int] = defaultdict(int)
        for p in self.payouts:
            if p.chain == cname and pred(p):
                out[p.miner] += p.amount
        return dict(out)

    def ledger_paid(self, cname: str) -> dict[str, int]:
        return self._agg(cname, self.counted_as_paid)

    def moved(self, cname: str) -> dict[str, int]:
        return self._agg(cname, self.funds_moved)

    def owed_signed(self, cname: str) -> dict[str, int]:
        """payable - ledger_paid, UNCLAMPED: over-credit is netted against future entitlement
        (§1 'corrected in subsequent payouts, not clawed back')."""
        pay = self.payable(cname)
        paid = self.ledger_paid(cname)
        out: dict[str, int] = {}
        for m in set(pay) | set(paid):
            out[m] = pay.get(m, 0) - paid.get(m, 0)
        return out

    def owed(self, cname: str) -> dict[str, int]:
        return {m: v for m, v in self.owed_signed(cname).items() if v > 0}

    # ------------------------------------------------------------------ broadcast

    def _assemble_and_broadcast(self, cname: str, b: Block) -> list[Payout]:
        if self.guards.forward_repair:
            candidates = self.owed(cname)
        else:
            # RED: pay only this block's own payable window credit; anything not payable in
            # its own window (burial deferral, an orphaned slice) is never revisited.
            cutoff = self._burial_cutoff()
            own: dict[str, int] = defaultdict(int)
            for idx, (m, amt) in self._block_credit(b).items():
                if idx <= cutoff:
                    own[m] += amt
            candidates = {m: v for m, v in own.items() if v > 0}

        budget = self.cfg.BLOCK_REWARD
        # deterministic: largest owed first, tie-break by miner name
        order = sorted(candidates.items(), key=lambda kv: (-kv[1], kv[0]))
        cutoff = self._burial_cutoff()
        paid_records = {i: self.spine.records[i].sid
                        for i in range(0, min(cutoff + 1, self.spine.height))}
        made: list[Payout] = []
        for miner, amt in order:
            if budget <= 0:
                break
            take = min(amt, budget)
            if take <= 0:
                continue
            budget -= take
            self._pid += 1
            p = Payout(pid=f"p{self._pid}", chain=cname, miner=miner, amount=take,
                       block=b, paid_records=dict(paid_records))
            self.payouts.append(p)
            made.append(p)
        return made

    def _update_settled(self) -> None:
        for p in self.payouts:
            if p.settled:
                continue
            ch = self.chains[p.chain]
            if not ch.is_live(p.block):
                continue
            c = ch.confirmations(p.block)
            need = self.cfg.D_conf if self.guards.conf_depth else 1  # RED: settled at broadcast
            if c >= need:
                p.settled = True
                p.settled_at_conf = c

    # ------------------------------------------------------------------ invariants

    def _post_event(self, tag: str) -> None:
        for cname in self.chains:
            ref = self.reference_payable(cname)
            for m, v in ref.items():
                k = (cname, m)
                if v > self.earned_hw[k]:
                    self.earned_hw[k] = v
        self.check_invariants(tag)

    def check_invariants(self, tag: str = "") -> list[str]:
        """CONS-1 no value creation; CONS-2 ledger fidelity; CONS-3 exact accounting."""
        bad: list[str] = []
        for cname in self.chains:
            moved = self.moved(cname)
            ledger = self.ledger_paid(cname)
            pay = self.payable(cname)
            osig = self.owed_signed(cname)
            miners = set(moved) | set(ledger) | set(pay) | set(osig)
            for m in miners:
                mv, lg, pv = moved.get(m, 0), ledger.get(m, 0), pay.get(m, 0)
                hw = self.earned_hw[(cname, m)]
                if mv > hw:
                    bad.append(f"CONS-1 value-creation {cname}/{m}: moved={mv} > earned_hw={hw} @{tag}")
                if lg != mv:
                    bad.append(f"CONS-2 ledger-fidelity {cname}/{m}: ledger_paid={lg} != moved={mv} @{tag}")
                if lg + osig.get(m, 0) != pv:
                    bad.append(f"CONS-3 accounting {cname}/{m}: paid+owed != payable @{tag}")
            # per-chain value ceiling: a chain cannot pay out more than it minted
            tot_moved = sum(moved.values())
            ceiling = len(self.chains[cname].ours_blocks) * self.cfg.BLOCK_REWARD
            if tot_moved > ceiling:
                bad.append(f"CONS-1 chain-ceiling {cname}: moved={tot_moved} > {ceiling} @{tag}")
        for p in self.payouts:
            if p.amount <= 0:
                bad.append(f"CONS-0 non-positive payout {p.pid}")
        self.violations.extend(bad)
        return bad

    # ------------------------------------------------------------------ F-SPINE probe

    def broadcast_prefix_rewritten(self) -> list[str]:
        """Every payout was broadcast against records buried >= D_spine. If any of those
        records no longer holds the same sid at the same index, the gate was crossed."""
        out = []
        for p in self.payouts:
            for idx, sid in p.paid_records.items():
                if idx >= self.spine.height or self.spine.records[idx].sid != sid:
                    out.append(p.pid)
                    break
        return out

    # ------------------------------------------------------------------ F-BROADCAST probe

    def orphaned_settled(self) -> list[Payout]:
        return [p for p in self.payouts
                if p.settled and not self.chains[p.chain].is_live(p.block)]

    def orphaned_pending(self) -> list[Payout]:
        return [p for p in self.payouts
                if not p.settled and not self.chains[p.chain].is_live(p.block)]

    def settled_below_conf(self) -> list[Payout]:
        """Payouts marked SETTLED while holding fewer than D_conf confirmations."""
        out = []
        for p in self.payouts:
            if p.settled and p.settled_at_conf is not None and p.settled_at_conf < self.cfg.D_conf:
                out.append(p)
        return out

    # ------------------------------------------------------------------ exclusion classifier

    def in_pplns_window(self, share_index: int) -> bool:
        """Would a block found right now still credit this share record?"""
        return share_index >= self.spine.height - self.cfg.W_pplns

    def f_repair_verdict(self, cname: str, miner: str, share_index: int | None,
                         windows_elapsed: int) -> str:
        """§9 verdict for one (chain, miner) divergence. Window-expiry and miner departure
        are outside the bound BY DECLARATION and do not count as falsification."""
        if miner in self.departed:
            return "EXCLUDED:miner-departure"
        if share_index is not None and not self.in_pplns_window(share_index):
            return "EXCLUDED:window-expiry"
        d = self.owed_signed(cname).get(miner, 0)
        if d == 0:
            return "REPAIRED"
        if d < 0:
            return "RESIDUAL:over-credit"          # §1 named residual, corrected forward
        if windows_elapsed > self.cfg.N_repair:
            return "FALSIFIES:F-REPAIR"
        return "IN-FLIGHT"

    def f_repair_falsified(self, cname: str, miner: str, share_index: int | None,
                           windows_elapsed: int) -> bool:
        return self.f_repair_verdict(cname, miner, share_index,
                                     windows_elapsed) == "FALSIFIES:F-REPAIR"

    # ------------------------------------------------------------------ drain to quiescence

    def repair_windows(self, cname: str, predicate, max_windows: int,
                       shares_per_window: int = 2, filler: str = "z") -> int:
        """Settle up to `max_windows` further PPLNS windows on `cname`, no reorgs. Returns the
        window index at which `predicate()` first held, or -1. This is F-REPAIR's own unit:
        'a window settles when the chain finds the block that pays it' (§9)."""
        for w in range(1, max_windows + 1):
            for _ in range(shares_per_window):
                self.add_share(filler)
            self.find_block(cname)
            if predicate():
                return w
        return -1

    # ---------------------------------------------- MD-5 ruling C: monotone progress (N-free)

    def _has_window_record(self, miner: str) -> bool:
        """Is this miner still present in the CURRENT PPLNS window of the spine?"""
        lo = max(0, self.spine.height - self.cfg.W_pplns)
        return any(r.miner == miner for r in self.spine.records[lo:])

    def under_credit(self, cname: str, miners) -> int:
        """Aggregate under-credit on `cname` across the divergence set, restricted to miners
        STILL PRESENT (not departed) and STILL IN-WINDOW -- the same two exclusion clauses §9
        already grants F-REPAIR (miner-departure, window-expiry)."""
        osig = self.owed_signed(cname)
        return sum(max(0, osig.get(m, 0)) for m in miners
                   if m not in self.departed and self._has_window_record(m))

    def repair_monotone(self, cname: str, miners, run_windows: int,
                        shares_per_window: int = 2, filler: str = "z") -> dict:
        """MD-5 ruling C (integrator ruling 2026-08-30, reply to the MD decision mail): the
        post-broadcast SPINE-repair leg is stated as MONOTONE PROGRESS, not as a deadline.

        The property: after the divergence, at every settled window until the aggregate
        under-credit reaches zero, that aggregate MUST STRICTLY DECREASE.

        `run_windows` is a harness RUN LENGTH, not an acceptance deadline: it bounds how long
        we watch, and no verdict is derived from reaching it. (A strictly decreasing sequence
        of non-negative integers reaches zero on its own; that is the whole point of the
        N-free statement.)

        Also instruments the B SIZING observation: how much NEW payable each settled window
        creates, against the one-block-reward coinbase budget. INFORMATIONAL only.
        """
        series = [self.under_credit(cname, miners)]
        actives = [sum(1 for m in miners
                       if m not in self.departed and self._has_window_record(m))]
        payable_created: list[int] = []
        prev_payable = sum(self.payable(cname).values())
        cleared_at = 0 if series[0] == 0 else -1
        for w in range(1, run_windows + 1):
            if cleared_at != -1:
                break
            for _ in range(shares_per_window):
                self.add_share(filler)
            self.find_block(cname)
            now_payable = sum(self.payable(cname).values())
            payable_created.append(now_payable - prev_payable)
            prev_payable = now_payable
            agg = self.under_credit(cname, miners)
            series.append(agg)
            actives.append(sum(1 for m in miners
                               if m not in self.departed and self._has_window_record(m)))
            if agg == 0:
                cleared_at = w
        strictly_decreasing = all(series[i + 1] < series[i]
                                  for i in range(len(series) - 1) if series[i] > 0)
        return {
            "series": series,
            "actives": actives,
            "strictly_decreasing": strictly_decreasing,
            "cleared_at_window": cleared_at,
            "payable_created": payable_created,
            "max_payable_created": max(payable_created) if payable_created else 0,
        }

    def quiesce(self, cname: str, windows: int = 6) -> None:
        """Miners stop submitting; the chain keeps finding blocks. The spine stops growing, so
        burial stops advancing and the whole payable backlog can be broadcast. This is the
        state in which 'paid == payable' is a meaningful closing assertion: while the spine
        grows, the D_spine gate keeps a standing in-flight lag by construction."""
        for _ in range(windows):
            self.find_block(cname)

    # ------------------------------------------------------------------ ledger-vs-world gap

    def vanished(self) -> int:
        """Total value the ledger believes it paid that never actually moved. Must be 0 under
        the guards for any coin reorg shallower than D_conf (§4)."""
        tot = 0
        for cname in self.chains:
            lg, mv = self.ledger_paid(cname), self.moved(cname)
            for m in set(lg) | set(mv):
                tot += max(0, lg.get(m, 0) - mv.get(m, 0))
        return tot


def canon_digest(obj) -> str:
    import json
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
