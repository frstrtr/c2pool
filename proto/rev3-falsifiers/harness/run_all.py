"""rev3 falsifier acceptance harness -- run-all entry point.

    python3 harness/run_all.py                 # green baseline: table + golden stamp
    python3 harness/run_all.py --red-matrix    # red baseline: guard x test failure matrix
    python3 harness/run_all.py --red <guard>   # one guard disabled, show which checks fail

Deterministic: fixed seeds, no wall-clock, no unseeded RNG. The golden stamp is a sha256 over
the canonical JSON of the config block + every check outcome + every recorded quantity; a
changed stamp is a regression signal.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from acceptance import at_broadcast, at_repair, at_spine          # noqa: E402
from conservation import conservation                             # noqa: E402
from model import GUARD_NAMES, Config, Guards, canon_digest       # noqa: E402

CASES = (at_repair, at_spine, at_broadcast, conservation)
GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "..", "golden", "rev3_falsifiers_v1.json")


def run(cfg: Config, guards: Guards):
    return [fn(cfg, guards) for fn in CASES]


def green(cfg: Config, write_golden: bool = True) -> int:
    cases = run(cfg, Guards())
    payload = {"config": asdict(cfg),
               "cases": [c.as_log() for c in cases]}
    stamp = canon_digest(payload)

    print("rev3 falsifier acceptance harness -- roundabout-rev3.md §9")
    print(f"  config: N_repair={cfg.N_repair}  D_spine={cfg.D_spine}  D_conf={cfg.D_conf}"
          f"  (W_pplns={cfg.W_pplns}, BLOCK_REWARD={cfg.BLOCK_REWARD})")
    print()
    print(f"  {'TEST':<14} {'FALSIFIER':<16} {'CHECKS':>8}  {'RESULT':<6}  RED BASELINE (guards)")
    print(f"  {'-'*14} {'-'*16} {'-'*8}  {'-'*6}  {'-'*40}")
    for c in cases:
        n_ok = sum(1 for _, ok in c.checks if ok)
        res = "PASS" if c.passed else "FAIL"
        print(f"  {c.tid:<14} {c.falsifier:<16} {n_ok:>4}/{len(c.checks):<3}  {res:<6}  "
              f"{', '.join(c.red_guards)}")
    print()
    for c in cases:
        for cid, ok in c.checks:
            if not ok:
                print(f"    [FAIL] {c.tid} :: {cid}")

    print("  recorded quantities")
    for c in cases:
        for k, v in c.record.items():
            if not k.startswith("INFO_"):
                print(f"    {c.tid:<14} {k:<28} {v}")

    info = [(c.tid, k, v) for c in cases for k, v in c.record.items()
            if k.startswith("INFO_")]
    if info:
        print()
        print("  INFORMATIONAL -- reported, NOT asserted (no pass/fail attaches to these)")
        for tid, k, v in info:
            print(f"    {tid:<14} {k:<44} {v}")
        for c in cases:
            if "INFO_B_sizing_stayed_below_one_block_reward" in c.record:
                below = c.record["INFO_B_sizing_stayed_below_one_block_reward"]
                mx = c.record["INFO_B_sizing_max_payable_created"]
                rw = c.record["INFO_B_sizing_one_block_reward"]
                print(f"    -> B SIZING ({c.tid}): steady-state payable creation per settled "
                      f"window {'STAYED BELOW' if below else 'DID NOT STAY BELOW'} one block "
                      f"reward over the run (max {mx} vs {rw}).")

    total = sum(len(c.checks) for c in cases)
    ok = sum(1 for c in cases for _, p in c.checks if p)
    print()
    print(f"  {ok}/{total} checks GREEN across {len(cases)} tests")
    print(f"  golden sha256 {stamp}")

    if write_golden and ok == total:
        os.makedirs(os.path.dirname(GOLDEN), exist_ok=True)
        with open(GOLDEN, "w") as fh:
            json.dump({"stamp": stamp, **payload}, fh, sort_keys=True, indent=1)
            fh.write("\n")
    return 0 if ok == total else 1


def red_one(cfg: Config, guard: str) -> int:
    if guard not in GUARD_NAMES:
        print(f"unknown guard {guard!r}; known: {', '.join(GUARD_NAMES)}")
        return 2
    cases = run(cfg, Guards(**{guard: False}))
    print(f"RED BASELINE -- guard disabled: {guard}")
    for c in cases:
        fails = [cid for cid, ok in c.checks if not ok]
        print(f"  {c.tid:<14} {'FAIL' if fails else 'pass'}")
        for cid in fails:
            print(f"      [RED] {cid}")
    return 0


def red_matrix(cfg: Config) -> int:
    base = run(cfg, Guards())
    names = [c.tid for c in base]
    print("RED BASELINE MATRIX -- 'X' = test fails with that guard disabled")
    print(f"  {'guard disabled':<20} " + "  ".join(f"{n:<13}" for n in names))
    print(f"  {'-'*20} " + "  ".join("-" * 13 for _ in names))
    print(f"  {'(none) GREEN':<20} " +
          "  ".join(f"{('X' if not c.passed else '.'):<13}" for c in base))
    rc = 0
    for g in GUARD_NAMES:
        cases = run(cfg, Guards(**{g: False}))
        cells = []
        for c in cases:
            nf = sum(1 for _, ok in c.checks if not ok)
            cells.append(f"{('X (%d)' % nf) if nf else '.':<13}")
        print(f"  {g:<20} " + "  ".join(cells))
        if not any(not c.passed for c in cases):
            print(f"      !! guard {g} reddens nothing -- the guard is not load-bearing")
            rc = 1
    print()
    print("  every guard must redden at least one test, and every test must be reddened by")
    print("  at least one guard, or the acceptance test is not proving what it claims.")
    for i, n in enumerate(names):
        reddened = any(not run(cfg, Guards(**{g: False}))[i].passed for g in GUARD_NAMES)
        if not reddened:
            print(f"      !! test {n} is reddened by no guard")
            rc = 1
    return rc


def main(argv: list[str]) -> int:
    cfg = Config()
    if len(argv) > 1 and argv[1] == "--red-matrix":
        return red_matrix(cfg)
    if len(argv) > 2 and argv[1] == "--red":
        return red_one(cfg, argv[2])
    if len(argv) > 1:
        print(__doc__)
        return 2
    return green(cfg)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
