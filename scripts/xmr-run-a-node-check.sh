#!/usr/bin/env bash
# xmr-run-a-node-check.sh -- doc-lint KAT for docs/xmr-lane/RUN-A-NODE.md.
#
# 1. RUN: every ```sh block preceded by `<!-- check -->` runs, in order, in ONE
#    bash (set -euo pipefail) with HOME set to a scratch dir. Blocks marked
#    `<!-- check build -->` (packages, clone, conan/cmake build) run too, unless
#    XMR_RUNNODE_SKIP_BUILD=1: then ~/c2pool in the scratch HOME is a link farm
#    of this checkout plus build -> $C2POOL_BUILD_DIR (the tree that holds
#    src/c2pool/c2pool-v37-xmr), so the later blocks run against this build.
# 2. FLAGS: every --flag on a c2pool-v37-xmr command line in the guide, and
#    every `--flag` in its flag table, must appear in `c2pool-v37-xmr --help`;
#    every flag on an xmr_anchor_gen.py command line must appear in that
#    tool's --help.
# 3. PATHS: every repo path the guide names (src/ doc/ docs/ tools/ scripts/
#    ci/ and relative markdown links) must exist in the tree.
# 4. PINS: every 64-hex value in the guide must appear in
#    docs/xmr-lane/PINNED-SNAPSHOTS.md (the pins are stated once, there).
#
# usage: scripts/xmr-run-a-node-check.sh
#   env: XMR_RUNNODE_SKIP_BUILD=1   skip `<!-- check build -->` blocks
#        C2POOL_BUILD_DIR=<dir>     build tree (default <repo>/build)
#        XMR_RUNNODE_GUIDE=<file>   guide to check (default docs/xmr-lane/RUN-A-NODE.md)
# exit: 0 = all checks pass; 1 = a check failed; 2 = usage/setup error.
set -uo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
GUIDE=${XMR_RUNNODE_GUIDE:-$REPO/docs/xmr-lane/RUN-A-NODE.md}
BD=${C2POOL_BUILD_DIR:-$REPO/build}
SKIP_BUILD=${XMR_RUNNODE_SKIP_BUILD:-0}
T0=$(date +%s)
fail=0
say() { printf '%s\n' "$*"; }
bad() { say "FAIL: $*"; fail=1; }

[ -f "$GUIDE" ] || { say "FAIL: guide not found: $GUIDE"; exit 1; }
command -v python3 >/dev/null || { say "FAIL: python3 is required"; exit 2; }

SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/xmr-run-a-node-check.XXXXXX") || exit 2
trap 'rm -rf "$SCRATCH"' EXIT

# ---- extract the marked blocks ------------------------------------------------
python3 - "$GUIDE" "$SCRATCH" "$SKIP_BUILD" <<'PY' || exit 2
import re, sys, os
guide, out, skip = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
lines = open(guide).read().split("\n")
n = 0; skipped = 0; i = 0; mark = None
while i < len(lines):
    m = re.match(r"^\s*<!--\s*check(\s+build)?\s*-->\s*$", lines[i])
    if m:
        mark = "build" if m.group(1) else "check"; i += 1; continue
    if lines[i].startswith("```"):
        j = i + 1
        while j < len(lines) and not lines[j].startswith("```"): j += 1
        if mark:
            if not lines[i].strip() in ("```sh", "```bash"):
                sys.exit("marked block at line %d is not ```sh" % (i + 1))
            if mark == "build" and skip:
                skipped += 1
            else:
                n += 1
                with open(os.path.join(out, "block%02d.sh" % n), "w") as f:
                    f.write("# %s block from %s:%d\n" % (mark, os.path.basename(guide), i + 1))
                    f.write("\n".join(lines[i + 1:j]) + "\n")
        mark = None; i = j + 1; continue
    if lines[i].strip(): mark = None if not lines[i].lstrip().startswith("<!--") else mark
    i += 1
open(os.path.join(out, "counts"), "w").write("%d %d\n" % (n, skipped))
PY
read -r NRUN NSKIP < "$SCRATCH/counts"
say "guide: $GUIDE"
say "blocks: $NRUN to run, $NSKIP build block(s) skipped (XMR_RUNNODE_SKIP_BUILD=$SKIP_BUILD)"
[ "$NRUN" -gt 0 ] || bad "no <!-- check --> block found"

# ---- 1. run them ---------------------------------------------------------------
H=$SCRATCH/home; mkdir -p "$H"
if [ "$SKIP_BUILD" = 1 ]; then
    [ -x "$BD/src/c2pool/c2pool-v37-xmr" ] || { say "FAIL: no binary at $BD/src/c2pool/c2pool-v37-xmr (set C2POOL_BUILD_DIR)"; exit 1; }
    mkdir -p "$H/c2pool"
    for e in "$REPO"/* "$REPO"/.[!.]*; do
        [ -e "$e" ] || continue
        b=$(basename "$e"); [ "$b" = build ] && continue; [ "$b" = .git ] && continue
        ln -s "$e" "$H/c2pool/$b"
    done
    ln -s "$BD" "$H/c2pool/build"
fi
{
    echo 'set -euo pipefail'
    for f in "$SCRATCH"/block*.sh; do
        [ -e "$f" ] || continue
        echo "echo \"--- \$(head -1 '$f' | cut -c3-)\""
        echo "cd \"\$HOME\""
        tail -n +2 "$f"
    done
} > "$SCRATCH/run.sh"
if (cd "$H" && HOME="$H" bash "$SCRATCH/run.sh") > "$SCRATCH/run.log" 2>&1; then
    say "run: OK ($NRUN block(s))"
else
    sed 's/^/  | /' "$SCRATCH/run.log" | tail -40
    bad "a <!-- check --> block failed"
fi

# ---- 2-4. flags, paths, pins ---------------------------------------------------
BIN=$BD/src/c2pool/c2pool-v37-xmr
[ "$SKIP_BUILD" = 1 ] || BIN=$H/c2pool/build/src/c2pool/c2pool-v37-xmr
if [ -x "$BIN" ]; then "$BIN" --help > "$SCRATCH/node-help.txt" 2>&1 || true
else bad "no binary to read --help from: $BIN"; : > "$SCRATCH/node-help.txt"; fi
python3 "$REPO/tools/xmr-anchor-gen/xmr_anchor_gen.py" --help > "$SCRATCH/gen-help.txt" 2>&1 || bad "xmr_anchor_gen.py --help failed"

python3 - "$GUIDE" "$REPO" "$SCRATCH/node-help.txt" "$SCRATCH/gen-help.txt" <<'PY' || fail=1
import re, sys, os
guide, repo, nh, gh = sys.argv[1:5]
text = open(guide).read()
node_help = set(re.findall(r"--[a-z0-9][a-z0-9-]*", open(nh).read())) | {"--help"}
gen_help = set(re.findall(r"--[a-z0-9][a-z0-9-]*", open(gh).read()))
rc = 0
# code blocks -> logical command lines (backslash continuations folded)
blocks = re.findall(r"^[ \t]*```[a-z]*\n(.*?)^[ \t]*```", text, re.S | re.M)
node_flags, gen_flags = set(), set()
for b in blocks:
    for cmd in b.replace("\\\n", " ").split("\n"):
        cmd = cmd.split(" #")[0]
        if re.search(r"(^|[\s/])c2pool-v37-xmr\s", cmd) and "cmake" not in cmd:
            node_flags |= set(re.findall(r"(?<![\w-])--[a-z0-9][a-z0-9-]*", cmd))
        if "xmr_anchor_gen.py" in cmd:
            gen_flags |= set(re.findall(r"(?<![\w-])--[a-z0-9][a-z0-9-]*", cmd))
# prose: every `--flag ...` in inline code outside code blocks is a node flag,
# except inline code that starts with another command (`git clone --x`), the
# anchor tool's flags the prose names, and the monerod flags the prose names.
prose = re.sub(r"^[ \t]*```.*?^[ \t]*```", "", text, flags=re.S | re.M)
gen_prose = {"--height", "--resume", "--net"}
monerod_prose = {"--restricted-rpc", "--max-connections-per-ip"}
other_cmds = ("git", "conan", "cmake", "curl", "pip", "monerod", "xmrig", "rsync", "sha256sum", "python3")
for code in re.findall(r"`([^`\n]+)`", prose):
    if code.split()[0] in other_cmds: continue
    for f in re.findall(r"(?<![\w-])--[a-z0-9][a-z0-9-]*", code):
        if f in monerod_prose: continue
        (gen_flags if f in gen_prose else node_flags).add(f)
nm = sorted(f for f in node_flags if f not in node_help)
gm = sorted(f for f in gen_flags if f not in gen_help)
print("flags: c2pool-v37-xmr %d checked, %d mismatch%s" % (len(node_flags), len(nm), (" " + " ".join(nm)) if nm else ""))
print("flags: xmr_anchor_gen.py %d checked, %d mismatch%s" % (len(gen_flags), len(gm), (" " + " ".join(gm)) if gm else ""))
if nm or gm or not node_flags: rc = 1
# paths
gdir = os.path.dirname(os.path.abspath(guide))
paths = set(re.findall(r"(?<![\w./~-])((?:src|doc|docs|tools|scripts|ci)/[A-Za-z0-9_./-]*[A-Za-z0-9_])", text))
missing = sorted(p for p in paths if not os.path.exists(os.path.join(repo, p)))
links = set(l.split("#")[0] for l in re.findall(r"\]\(([^)#][^)]*)\)", text) if "://" not in l)
lmissing = sorted(l for l in links if l and not os.path.exists(os.path.normpath(os.path.join(gdir, l))))
print("paths: %d repo path(s) + %d link(s) checked, %d missing%s" % (len(paths), len(links), len(missing) + len(lmissing),
      (" " + " ".join(missing + lmissing)) if missing or lmissing else ""))
if missing or lmissing: rc = 1
# pins
pins = open(os.path.join(repo, "docs/xmr-lane/PINNED-SNAPSHOTS.md")).read()
hexes = set(re.findall(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", text))
hm = sorted(h for h in hexes if h not in pins)
print("pins: %d sha256/id value(s) checked against PINNED-SNAPSHOTS.md, %d mismatch%s" % (len(hexes), len(hm), (" " + " ".join(hm)) if hm else ""))
if hm: rc = 1
sys.exit(rc)
PY

say "runtime: $(( $(date +%s) - T0 )) s"
if [ $fail -ne 0 ]; then say "RESULT: FAIL"; exit 1; fi
say "RESULT: PASS"
exit 0
