#!/usr/bin/env python3
"""
conformance-pplns.py — contract test for c2pool's /pplns/current
and /pplns/miner/<address> REST endpoints.

Spec: frstrtr/the/docs/c2pool-pplns-view-module-task.md §5.1 + §5.2.

Locks the HTTP surface that the PPLNS View JS bundle consumes so
the C++ server doesn't drift away from the TS type contract. Runs
against a live daemon; stdlib only (urllib + json).

Usage:
  tools/conformance-pplns.py [--base URL] [--miner ADDR] [--verbose]

Exits 0 on pass, 1 on any violation. Output is a concise report:
one line per check, tagged PASS / FAIL, with the §-reference the
check derives from.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


# ── Result collector ──────────────────────────────────────────────

@dataclass
class Report:
    checks: list[tuple[str, bool, str]] = field(default_factory=list)

    def check(self, ok: bool, label: str, detail: str = "") -> None:
        self.checks.append((label, ok, detail))

    def ok(self, label: str) -> None:
        self.check(True, label)

    def fail(self, label: str, detail: str) -> None:
        self.check(False, label, detail)

    @property
    def passed(self) -> bool:
        return all(ok for (_, ok, _) in self.checks)

    def print(self, verbose: bool = False) -> None:
        for label, ok, detail in self.checks:
            tag = "PASS" if ok else "FAIL"
            line = f"[{tag}] {label}"
            if detail and (verbose or not ok):
                line += f"\n       {detail}"
            print(line)
        passed = sum(1 for (_, ok, _) in self.checks if ok)
        total = len(self.checks)
        print(f"\n{passed}/{total} checks passed")


# ── HTTP ──────────────────────────────────────────────────────────

def fetch_json(url: str, timeout: float = 10.0) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    return json.loads(body)


# ── /pplns/current validators (§5.1) ──────────────────────────────

REQUIRED_CURRENT_KEYS = {
    "tip": str,
    "window_size": int,
    "total_primary": (int, float),
    "merged_chains": list,
    "merged_totals": dict,
    "computed_at": int,
    "schema_version": str,
    "miners": list,
}

# coin label is always present but type is string.
OPTIONAL_CURRENT_KEYS = {"coin": str}

REQUIRED_MINER_ENTRY_KEYS = {
    "address": str,
    "amount": (int, float),
    "pct": (int, float),
}

OPTIONAL_MINER_ENTRY_KEYS = {
    "shares_in_window": int,
    "hashrate_hps": (int, float),
    "version": int,
    "desired_version": int,
    "last_share_at": int,
    "merged": list,
}


def _is_instance(value: Any, expected: Any) -> bool:
    if isinstance(expected, tuple):
        return any(isinstance(value, t) for t in expected)
    return isinstance(value, expected)


def validate_current(snap: Any, report: Report) -> list[str]:
    """Validate /pplns/current. Returns miner addresses for follow-up."""
    if not isinstance(snap, dict):
        report.fail("/pplns/current is a JSON object",
                    f"got {type(snap).__name__}")
        return []
    report.ok("/pplns/current is a JSON object")

    for key, expected in REQUIRED_CURRENT_KEYS.items():
        if key not in snap:
            report.fail(f"[§5.1] required key '{key}' present",
                        "missing from response")
            continue
        if not _is_instance(snap[key], expected):
            report.fail(f"[§5.1] '{key}' has expected type",
                        f"got {type(snap[key]).__name__}, expected "
                        f"{expected}")
        else:
            report.ok(f"[§5.1] '{key}' present and well-typed")

    for key, expected in OPTIONAL_CURRENT_KEYS.items():
        if key in snap and not _is_instance(snap[key], expected):
            report.fail(f"[§5.1] optional '{key}' well-typed",
                        f"got {type(snap[key]).__name__}")

    # schema_version should be "1.0" during current contract.
    sv = snap.get("schema_version")
    if sv is not None and sv != "1.0":
        report.fail("[§5.1] schema_version == '1.0'",
                    f"got {sv!r}")
    elif sv == "1.0":
        report.ok("[§5.1] schema_version == '1.0'")

    # merged_chains[] strings, merged_totals keys match
    mchains = snap.get("merged_chains", [])
    mtotals = snap.get("merged_totals", {})
    if isinstance(mchains, list):
        bad = [c for c in mchains if not isinstance(c, str)]
        if bad:
            report.fail("[§5.1] merged_chains[] are all strings",
                        f"non-string entries: {bad!r}")
        else:
            report.ok("[§5.1] merged_chains[] are all strings")
    if isinstance(mtotals, dict) and isinstance(mchains, list):
        unknown = set(mtotals.keys()) - set(mchains)
        if unknown:
            report.fail(
                "[§5.1] merged_totals keys subset of merged_chains",
                f"unknown symbols: {sorted(unknown)!r}")
        else:
            report.ok(
                "[§5.1] merged_totals keys subset of merged_chains")

    # miners[] — shape + sort + pct sum
    miners = snap.get("miners", [])
    addrs: list[str] = []
    if not isinstance(miners, list):
        return addrs
    for i, m in enumerate(miners):
        if not isinstance(m, dict):
            report.fail(f"[§5.1] miners[{i}] is an object",
                        f"got {type(m).__name__}")
            continue
        for k, expected in REQUIRED_MINER_ENTRY_KEYS.items():
            if k not in m:
                report.fail(
                    f"[§5.1] miners[{i}].{k} present",
                    f"missing in entry {m!r}")
            elif not _is_instance(m[k], expected):
                report.fail(
                    f"[§5.1] miners[{i}].{k} well-typed",
                    f"got {type(m[k]).__name__}")
        for k, expected in OPTIONAL_MINER_ENTRY_KEYS.items():
            if k in m and not _is_instance(m[k], expected):
                report.fail(
                    f"[§5.1] miners[{i}].{k} well-typed (optional)",
                    f"got {type(m[k]).__name__}")
        if "merged" in m and isinstance(m["merged"], list):
            for j, mm in enumerate(m["merged"]):
                if not isinstance(mm, dict):
                    report.fail(
                        f"[§5.1] miners[{i}].merged[{j}] is an object",
                        f"got {type(mm).__name__}")
                    continue
                for k, expected in (("symbol", str), ("address", str),
                                     ("amount", (int, float))):
                    if k not in mm:
                        report.fail(
                            f"[§5.1] miners[{i}].merged[{j}].{k} present",
                            f"entry: {mm!r}")
                    elif not _is_instance(mm[k], expected):
                        report.fail(
                            f"[§5.1] miners[{i}].merged[{j}].{k} "
                            "well-typed",
                            f"got {type(mm[k]).__name__}")
        addr = m.get("address")
        if isinstance(addr, str):
            addrs.append(addr)

    if len(miners) > 1:
        amounts = [m.get("amount", 0) for m in miners if isinstance(m, dict)]
        if amounts == sorted(amounts, reverse=True):
            report.ok("[§5.1] miners[] sorted by amount desc")
        else:
            report.fail("[§5.1] miners[] sorted by amount desc",
                        "found out-of-order entries")

    # pct sum ≈ 1.0 (tolerates 1e-4)
    pct_sum = sum(m.get("pct", 0) for m in miners if isinstance(m, dict))
    if miners and abs(pct_sum - 1.0) > 1e-4:
        # It's common for servers to leave pct unfilled (all zero) — only
        # fail when at least one pct is non-zero so we know it's meant to
        # add up.
        nonzero = any(m.get("pct", 0) > 0 for m in miners
                      if isinstance(m, dict))
        if nonzero:
            report.fail("[§5.1] miners[].pct sums to 1.0",
                        f"got {pct_sum:.6f}")
        else:
            report.ok("[§5.1] miners[].pct unfilled (0) — tolerated")
    elif miners:
        report.ok("[§5.1] miners[].pct sums to 1.0")

    return addrs


# ── /pplns/miner/<addr> validators (§5.2) ─────────────────────────

REQUIRED_DETAIL_KEYS = {
    "address": str,
    "in_window": bool,
}

OPTIONAL_DETAIL_KEYS = {
    "amount": (int, float),
    "pct": (int, float),
    "shares_in_window": int,
    "shares_total": int,
    "first_seen_at": int,
    "last_share_at": int,
    "hashrate_hps": (int, float),
    "hashrate_series": list,
    "version": int,
    "desired_version": int,
    "version_history": list,
    "merged": list,
    "recent_shares": list,
}


def validate_detail(detail: Any, expected_addr: str,
                     report: Report) -> None:
    if not isinstance(detail, dict):
        report.fail(
            f"/pplns/miner/{expected_addr} is a JSON object",
            f"got {type(detail).__name__}")
        return
    report.ok(f"/pplns/miner/{expected_addr} is a JSON object")

    for k, expected in REQUIRED_DETAIL_KEYS.items():
        if k not in detail:
            report.fail(f"[§5.2] required key '{k}' present",
                        f"missing in {detail!r}")
        elif not _is_instance(detail[k], expected):
            report.fail(f"[§5.2] '{k}' well-typed",
                        f"got {type(detail[k]).__name__}")
        else:
            report.ok(f"[§5.2] '{k}' present and well-typed")

    if detail.get("address") == expected_addr:
        report.ok("[§5.2] address matches requested")
    else:
        report.fail("[§5.2] address matches requested",
                    f"got {detail.get('address')!r}")

    for k, expected in OPTIONAL_DETAIL_KEYS.items():
        if k in detail and not _is_instance(detail[k], expected):
            report.fail(f"[§5.2] optional '{k}' well-typed",
                        f"got {type(detail[k]).__name__}")

    # recent_shares[] shape
    rs = detail.get("recent_shares", [])
    if isinstance(rs, list):
        for i, s in enumerate(rs):
            if not isinstance(s, dict):
                report.fail(f"[§5.2] recent_shares[{i}] is an object",
                            f"got {type(s).__name__}")
                continue
            if "h" not in s or not isinstance(s["h"], str):
                report.fail(
                    f"[§5.2] recent_shares[{i}].h present + string",
                    f"entry: {s!r}")
            if "t" not in s or not isinstance(s["t"], (int, float)):
                report.fail(
                    f"[§5.2] recent_shares[{i}].t present + numeric",
                    f"entry: {s!r}")


def validate_not_found(detail: Any, report: Report) -> None:
    if not isinstance(detail, dict):
        report.fail("[§5.2] bogus address returns an object",
                    f"got {type(detail).__name__}")
        return
    if detail.get("error") == "miner_not_found":
        report.ok("[§5.2] bogus address returns "
                  "{error: 'miner_not_found'}")
    else:
        report.fail("[§5.2] bogus address returns "
                    "{error: 'miner_not_found'}",
                    f"got {detail!r}")


# ── Entry point ───────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="c2pool PPLNS REST contract test.")
    parser.add_argument("--base", default="http://127.0.0.1:8080",
                        help="Base URL of the c2pool HTTP server "
                             "(default: %(default)s)")
    parser.add_argument("--miner",
                        help="Miner address to exercise /pplns/miner "
                             "against (default: first from /pplns/current)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print all checks, including passes.")
    args = parser.parse_args()

    base = args.base.rstrip("/")
    report = Report()

    # 1. Fetch /pplns/current.
    try:
        snap = fetch_json(f"{base}/pplns/current")
    except Exception as exc:
        report.fail("GET /pplns/current succeeds", str(exc))
        report.print(args.verbose)
        return 1
    report.ok("GET /pplns/current succeeds")

    addrs = validate_current(snap, report)

    # 2. Pick a target address.
    target = args.miner
    if target is None and addrs:
        target = addrs[0]
    if target is not None:
        enc = urllib.parse.quote(target, safe="")
        url = f"{base}/pplns/miner/{enc}"
        try:
            detail = fetch_json(url)
        except Exception as exc:
            report.fail(f"GET /pplns/miner/{target} succeeds", str(exc))
        else:
            report.ok(f"GET /pplns/miner/{target} succeeds")
            validate_detail(detail, target, report)
    else:
        report.check(True, "/pplns/miner check skipped — no miners in "
                           "current snapshot")

    # 3. Negative case — bogus address should return miner_not_found.
    bogus = "zzzzconformanceprobeADDRESSzzzzzzzzzzzzzzzz"
    try:
        detail = fetch_json(f"{base}/pplns/miner/{bogus}")
    except Exception as exc:
        report.fail(f"GET /pplns/miner/{bogus} reachable", str(exc))
    else:
        validate_not_found(detail, report)

    report.print(args.verbose)
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
