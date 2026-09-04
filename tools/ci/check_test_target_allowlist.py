#!/usr/bin/env python3
# CI drift-guard: every per-coin test executable declared in
# src/impl/<coin>/test/CMakeLists.txt MUST appear as a `--target` argument in
# .github/workflows/build.yml. A test target added to CMake but missing from the
# build.yml allowlist is never compiled, so CTest reports it as a NOT_BUILT
# sentinel that *silently passes* -- this is the exact failure mode that red'd
# master in the DGB #137 / test_dgb_subsidy regression. This guard fails closed
# on that drift so it is caught at PR time, not after merge.
#
# Scope: per-coin test trees (src/impl/<coin>/test/), the sharechain engine
# trees (src/sharechain/**/test/ -- both src/sharechain/test/ and
# src/sharechain/<module>/test/), the c2pool consumer-side trees
# (src/c2pool/**/test/ -- e.g. src/c2pool/v37/test/, where the v37 node
# scaffold lands its unit test), the shared core test tree (src/core/test/)
# and the top-level test/ tree. The sharechain + core trees were previously
# unaudited, so a standalone add_executable there could land NOT_BUILT-silent
# (the coverage gap that let PR #1467's src/sharechain/v37/test/ go unguarded).
# The c2pool tree is the same surface: PR #1477 (W0 node scaffold) adds
# src/c2pool/v37/test/v37_scaffold_test, which this glob now audits so a future
# add_test there missing from build.yml fails closed instead of hollow-greening.
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
# The sharechain engine trees and the shared core test tree are the same
# NOT_BUILT surface as the coin trees, and the v37 engine work lands its test
# code there. Recursive on sharechain so src/sharechain/test/ (no module
# directory) and src/sharechain/<module>/test/ are both audited.
SHARECHAIN_GLOB = os.path.join(REPO, "src", "sharechain", "**", "test", "CMakeLists.txt")
# The c2pool consumer-side trees are the same NOT_BUILT surface: the v37 node
# scaffold (PR #1477) lands its unit test under src/c2pool/v37/test/. Recursive
# so src/c2pool/test/ (no module directory) and src/c2pool/<module>/test/ are
# both audited.
C2POOL_GLOB = os.path.join(REPO, "src", "c2pool", "**", "test", "CMakeLists.txt")
CORE_TEST = os.path.join(REPO, "src", "core", "test", "CMakeLists.txt")
# The top-level shared test tree is ALSO a NOT_BUILT surface: a standalone
# add_executable here that is missing from build.yml is silently "Not Run"
# too (this is why targets get hand-folded into allowlisted executables to
# dodge the trap). Audit it with the same fail-closed rule.
TOP_LEVEL_TEST = os.path.join(REPO, "test", "CMakeLists.txt")


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


def audited_roots():
    """Every test CMakeLists.txt the guard polices, deduplicated, in a stable
    order: per-coin trees, sharechain engine trees, c2pool consumer trees,
    core, then top-level."""
    roots = sorted(glob.glob(COIN_GLOB))
    roots += sorted(glob.glob(SHARECHAIN_GLOB, recursive=True))
    roots += sorted(glob.glob(C2POOL_GLOB, recursive=True))
    if os.path.exists(CORE_TEST):
        roots.append(CORE_TEST)
    if os.path.exists(TOP_LEVEL_TEST):
        roots.append(TOP_LEVEL_TEST)
    seen = set()
    return [r for r in roots if not (r in seen or seen.add(r))]


def main():
    allowlist = build_yml_targets(BUILD_YML)
    violations = []
    audited = 0
    roots = audited_roots()
    for cml in roots:
        # Label: coin/module name for a src/ tree (src/impl/<coin>/test/,
        # src/sharechain/<module>/test/, src/core/test/), "test/" for the
        # shared top-level tree.
        rel = os.path.relpath(cml, REPO)
        coin = cml.split(os.sep)[-3] if rel.startswith("src" + os.sep) else "test/"
        with open(cml) as f:
            exempt = parse_exemptions(f.read())
        for tgt in sorted(parse_coin_targets(cml)):
            audited += 1
            if tgt in allowlist or tgt in exempt:
                continue
            violations.append((coin, tgt, cml))

    if violations:
        print("CI drift-guard FAILED: test target(s) missing from "
              ".github/workflows/build.yml --target allowlist (NOT_BUILT risk):\n")
        for coin, tgt, cml in violations:
            print("  [%s] %s  (declared in %s)"
                  % (coin, tgt, os.path.relpath(cml, REPO)))
        print("\nFix: add the target to the relevant build.yml --target list, "
              "or declare it '# ci-allowlist-exempt: <target>  -- <reason>' in "
              "that test CMakeLists.txt.")
        return 1

    print("CI drift-guard OK: %d test target(s) across %d test tree(s) "
          "all present in build.yml --target allowlist."
          % (audited, len(roots)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
