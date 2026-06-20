#!/usr/bin/env python3
# CI drift-guard: every per-coin test executable declared in
# src/impl/<coin>/test/CMakeLists.txt MUST appear as a `--target` argument in
# .github/workflows/build.yml. A test target added to CMake but missing from the
# build.yml allowlist is never compiled, so CTest reports it as a NOT_BUILT
# sentinel that *silently passes* -- this is the exact failure mode that red'd
# master in the DGB #137 / test_dgb_subsidy regression. This guard fails closed
# on that drift so it is caught at PR time, not after merge.
#
# Scope: per-coin test trees only (the integrator-scoped surface). Core/shared
# test targets are out of scope.
#
# Escape hatch: a target intentionally NOT built in CI (e.g. a compile-only TU
# or a live-only harness) must be declared explicitly with a comment line:
#     # ci-allowlist-exempt: <target_name>  -- <reason>
# anywhere in that coin's test CMakeLists.txt. Fail-closed: silence is a failure.

import os
import re
import sys
import glob

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD_YML = os.path.join(REPO, ".github", "workflows", "build.yml")
COIN_GLOB = os.path.join(REPO, "src", "impl", "*", "test", "CMakeLists.txt")


def strip_comment(line):
    # CMake line comments start at '#'. The test CMakeLists do not use bracket
    # comments or '#' inside target names, so a plain cut is sufficient.
    return line.split("#", 1)[0]


def build_yml_targets(path):
    """Collect every token passed as a `cmake --build ... --target <tokens>`
    argument. Target names may contain '-' (e.g. c2pool-bch); option flags
    (-j$(nproc), --config) start with '-' and terminate a target run."""
    with open(path) as f:
        raw = f.read()
    # Fold YAML/shell line continuations so a --target block is one stream.
    raw = raw.replace("\\\n", " ")
    targets = set()
    for m in re.finditer(r"--target\b(.*?)(?:--config\b|-j|\n\s*\n|$)", raw, re.S):
        for tok in m.group(1).split():
            if tok in ("\\",):
                continue
            if tok.startswith("-"):
                break
            targets.add(tok)
    return targets


def parse_exemptions(text):
    return set(
        m.group(1)
        for m in re.finditer(r"ci-allowlist-exempt:\s*([A-Za-z0-9_-]+)", text)
    )


def parse_coin_targets(path):
    """Return the set of concrete test-executable target names declared in a
    coin test CMakeLists.txt, expanding `foreach(t IN LISTS VAR)` +
    `add_executable(prefix_${t} ...)` generator patterns."""
    with open(path) as f:
        raw = f.read()
    clean = "\n".join(strip_comment(l) for l in raw.splitlines())

    lists = {}
    targets = set()
    foreach_stack = []  # list of (loopvar, [items])

    # Commands of interest; their args never contain nested parens here.
    cmd_re = re.compile(
        r"\b(set|foreach|endforeach|add_executable)\s*\(([^()]*)\)", re.S
    )
    for m in cmd_re.finditer(clean):
        cmd, args = m.group(1), m.group(2).split()
        if cmd == "set" and args:
            lists[args[0]] = [a for a in args[1:] if "$" not in a and '"' not in a]
        elif cmd == "foreach":
            loopvar = args[0] if args else None
            items = []
            if "LISTS" in args:
                for lv in args[args.index("LISTS") + 1:]:
                    items.extend(lists.get(lv, []))
            foreach_stack.append((loopvar, items))
        elif cmd == "endforeach":
            if foreach_stack:
                foreach_stack.pop()
        elif cmd == "add_executable" and args:
            name = args[0]
            names = [name]
            if "$" in name:
                # Expand against every enclosing foreach loop variable.
                for loopvar, items in reversed(foreach_stack):
                    if loopvar and ("${%s}" % loopvar) in name:
                        names = [n.replace("${%s}" % loopvar, it)
                                 for n in names for it in items]
            for n in names:
                if "$" not in n:  # only fully-resolved targets
                    targets.add(n)
    return targets


def main():
    allowlist = build_yml_targets(BUILD_YML)
    violations = []
    audited = 0
    for cml in sorted(glob.glob(COIN_GLOB)):
        coin = cml.split(os.sep)[-3]
        with open(cml) as f:
            exempt = parse_exemptions(f.read())
        for tgt in sorted(parse_coin_targets(cml)):
            audited += 1
            if tgt in allowlist or tgt in exempt:
                continue
            violations.append((coin, tgt, cml))

    if violations:
        print("CI drift-guard FAILED: coin test target(s) missing from "
              ".github/workflows/build.yml --target allowlist (NOT_BUILT risk):\n")
        for coin, tgt, cml in violations:
            print("  [%s] %s  (declared in %s)"
                  % (coin, tgt, os.path.relpath(cml, REPO)))
        print("\nFix: add the target to the relevant build.yml --target list, "
              "or declare it '# ci-allowlist-exempt: <target>  -- <reason>' in "
              "the coin test CMakeLists.txt.")
        return 1

    print("CI drift-guard OK: %d per-coin test target(s) across %d coin lane(s) "
          "all present in build.yml --target allowlist."
          % (audited, len(glob.glob(COIN_GLOB))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
