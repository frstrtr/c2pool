#!/usr/bin/env python3
"""Catalog-completeness tripwire (M0).

Prevents the CLI-flag drift disease: every flag spelling accepted by any of the
five node mains must have a matching alias row in src/core/param_catalog.inc, and
every catalog alias must correspond to a real flag in its main. Runs in seconds
(no build), so it is wired both as a GitHub Actions step (immune to the
master-push-skips-heavy-Linux hole) and as a ctest for the offline full suite.

stdlib only.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src", "c2pool")
CATALOG = os.path.join(ROOT, "src", "core", "param_catalog.inc")

# main file -> catalog BIN_ symbol
MAINS = {
    "main_dash.cpp": "BIN_DASH",
    "main_ltc.cpp": "BIN_LTC",
    "main_btc.cpp": "BIN_BTC",
    "main_dgb.cpp": "BIN_DGB",
    "main_bch.cpp": "BIN_BCH",
    "main_bip110.cpp": "BIN_BIP110",
}

# Flags that are intentionally NOT catalog rows. Keep this list SHORT and each
# entry commented with WHY it is exempt.
ALLOWLIST = {
    # (BIN, spelling)
    ("BIN_LTC", "--no-console"),   # accepted-and-ignored p2pool compat, no effect
    ("BIN_BCH", "--leg-c-capture"),      # dev-harness capture lane, not operator config
    ("BIN_BCH", "--leg-c-capture-p2p"),  # dev-harness capture lane
    # c2pool-bip110 EMBEDDED-lane infra flags (M1/M2 SPV follower control surface,
    # not operator money/config catalog params): the money-class flags
    # (--give-author/--dev-donation/--fee/-f/--node-owner-address/--donation) and
    # meta (--version/--help/-h) ARE catalog rows; these run-mode/network flags are
    # lane-local and carry no [bip110] settings-file key.
    ("BIN_BIP110", "--selftest"),          # selftest vs run mode toggle
    ("BIN_BIP110", "--run"),               # embedded run mode toggle
    ("BIN_BIP110", "--coin-p2p-discover"), # fork-peer discovery toggle
    ("BIN_BIP110", "--fork-checkpoint"),   # BLAKE2b fork checkpoint seed toggle
    ("BIN_BIP110", "--peer"),              # explicit fork peer host:port
    ("BIN_BIP110", "--http"),              # dashboard/http bind host:port
    ("BIN_BIP110", "--stratum"),           # stratum bind port
    ("BIN_BIP110", "--no-stratum"),        # disable stratum
}

# A flag literal looks like -x or --long-flag (letters/digits/dashes, not a bare '-').
FLAG_RE = re.compile(r'^--?[A-Za-z0-9][A-Za-z0-9-]*$')

# Two comparison styles are in use across the mains:
#   strcmp(argv[i], "--flag")             (dash/dgb/bch)
#   arg == "--flag"  /  arg == "-h"       (ltc/btc)
# Extract the string literal from either.
STRCMP_RE = re.compile(r'strcmp\(\s*argv\[\s*\w+\s*\]\s*,\s*"([^"]+)"')
ARGEQ_RE = re.compile(r'\barg\s*==\s*"([^"]+)"')


def extract_main_flags(path):
    flags = set()
    saw_any = False
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            for m in STRCMP_RE.finditer(line):
                lit = m.group(1)
                if FLAG_RE.match(lit):
                    flags.add(lit)
                    saw_any = True
            for m in ARGEQ_RE.finditer(line):
                lit = m.group(1)
                if FLAG_RE.match(lit):
                    flags.add(lit)
                    saw_any = True
    return flags, saw_any


# C2P_ALIAS(canon, BIN_x, "spelling", style). Binary token may carry digits
# (e.g. BIN_BIP110), so match [A-Z0-9]+ not just [A-Z]+.
ALIAS_RE = re.compile(
    r'C2P_ALIAS\(\s*[^,]+,\s*(BIN_[A-Z0-9]+)\s*,\s*"([^"]+)"'
)


def extract_catalog_aliases(path):
    aliases = set()  # (BIN, spelling)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    for m in ALIAS_RE.finditer(text):
        aliases.add((m.group(1), m.group(2)))
    return aliases


def main():
    errors = []

    if not os.path.isfile(CATALOG):
        print("FATAL: catalog not found at %s" % CATALOG, file=sys.stderr)
        return 2

    catalog_aliases = extract_catalog_aliases(CATALOG)
    if not catalog_aliases:
        print("FATAL: zero catalog aliases extracted -- instrument invalid",
              file=sys.stderr)
        return 2

    main_flags = {}  # BIN -> set(spelling)
    for fname, binsym in MAINS.items():
        path = os.path.join(SRC, fname)
        if not os.path.isfile(path):
            errors.append("main missing: %s" % path)
            continue
        flags, saw_any = extract_main_flags(path)
        # Instrument-validity floor (the zero-test-run lesson): a main that
        # yields zero flags means the regex stopped matching -> hard fail.
        if not saw_any:
            errors.append(
                "%s: zero flag literals extracted -- parser regex is broken "
                "(instrument-validity floor)" % fname)
        main_flags[binsym] = flags

    # FORWARD: every main flag must have a catalog alias for that binary.
    for binsym, flags in main_flags.items():
        for spelling in sorted(flags):
            if (binsym, spelling) in ALLOWLIST:
                continue
            if (binsym, spelling) not in catalog_aliases:
                fname = [k for k, v in MAINS.items() if v == binsym][0]
                errors.append(
                    "%s: %s has no catalog row (add a C2P_ALIAS for %s)"
                    % (fname, spelling, binsym))

    # REVERSE: every catalog alias must appear in its main (catches renames /
    # typo'd catalog rows -> keeps the catalog honest).
    for (binsym, spelling) in sorted(catalog_aliases):
        if binsym not in main_flags:
            errors.append("catalog references unknown binary %s" % binsym)
            continue
        if spelling not in main_flags[binsym]:
            errors.append(
                "param_catalog.inc: C2P_ALIAS(%s, \"%s\") not found in the "
                "corresponding main -- stale/typo'd catalog row" % (binsym, spelling))

    if errors:
        print("catalog-completeness tripwire FAILED (%d issue(s)):" % len(errors))
        for e in errors:
            print("  - %s" % e)
        return 1

    total = sum(len(v) for v in main_flags.values())
    print("catalog-completeness tripwire PASSED: %d main flag spellings, "
          "%d catalog aliases, forward+reverse consistent."
          % (total, len(catalog_aliases)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
