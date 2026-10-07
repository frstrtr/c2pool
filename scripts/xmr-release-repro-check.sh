#!/usr/bin/env bash
# xmr-release-repro-check.sh — is the c2pool-v37-xmr Release binary byte-reproducible?
#
# Builds ONE commit twice, from scratch, with ccache disabled, in two throw-away
# checkouts that differ in everything an honest rebuild may differ in:
#
#   build A : <work>/a/src                      build dir <work>/a/build
#   build B : <work>/b/some/deeper/path/src     build dir <work>/b/out/other-build
#   plus: a wall-clock gap between the two builds, different TZ, LC_ALL and umask,
#   and a DIFFERENT Conan home for build B (<work>/b/conan-home), restored from
#   exactly the packages build A resolved (conan cache save/restore) — the same
#   binaries at a different absolute path, which is what an outsider with another
#   $HOME/user name has.
#
# Both builds use the canonical release recipe (docs/xmr-lane/REPRODUCIBLE-BUILD.md):
#   conan install . -pr:a=ci/conan/linux-gcc13.profile --lockfile=conan.lock
#   cmake -DCMAKE_BUILD_TYPE=Release -DXMR_BUILD_RANDOMX=ON
#   cmake --build --target c2pool-v37-xmr
# The script injects NO reproducibility flags of its own: whatever makes the
# binary reproducible must live in the build system, so an outsider running the
# plain recipe gets the same bytes.
#
# It then compares sha256 of the unstripped binary and of a stripped copy
# (strip --strip-all). On a mismatch it prints a per-class breakdown of the
# difference (which ELF sections differ, how many bytes, and which strings
# carry a build path) so the cause is visible without diffoscope.
#
# Usage:   scripts/xmr-release-repro-check.sh [<commit-ish>]      (default HEAD)
# Env:     REPRO_WORKDIR=<dir>   work dir (default: mktemp -d under $TMPDIR)
#          REPRO_JOBS=<n>        parallel jobs (default: nproc)
#          REPRO_GAP_SECONDS=<n> wall-clock gap between build A and B (default 65)
#          REPRO_CONAN_BUILD=<policy>  conan --build policy (default: missing)
#          REPRO_KEEP=1          keep the checkouts + build trees afterwards
#          REPRO_NICE=<n>        run the builds under nice -n <n> (default 0)
#          REPRO_SAME_CONAN_HOME=1  build B reuses build A's Conan home
# Exit:    0 = identical (unstripped AND stripped), 1 = differ, 2 = setup/build error.
# Scope:   ONE host (same OS image, compiler, conan cache). Cross-host
#          reproducibility needs a pinned container image — see the doc.
set -euo pipefail

say() { printf '[repro] %s\n' "$*"; }
die() { printf '[repro] ERROR: %s\n' "$*" >&2; exit 2; }

REPO=$(git -C "$(dirname "$(readlink -f "$0")")/.." rev-parse --show-toplevel) \
    || die "not inside a git checkout"
COMMIT=$(git -C "$REPO" rev-parse --verify "${1:-HEAD}^{commit}") \
    || die "unknown commit ${1:-HEAD}"
JOBS=${REPRO_JOBS:-$(nproc)}
GAP=${REPRO_GAP_SECONDS:-65}
CONAN_BUILD=${REPRO_CONAN_BUILD:-missing}
NICE=${REPRO_NICE:-0}
TARGET=c2pool-v37-xmr
PROFILE=ci/conan/linux-gcc13.profile

WORK=${REPRO_WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/xmr-repro.XXXXXX")}
mkdir -p "$WORK"
WORK=$(readlink -f "$WORK")
SRC_A=$WORK/a/src
BLD_A=$WORK/a/build
SRC_B=$WORK/b/some/deeper/path/src
BLD_B=$WORK/b/out/other-build
OUT=$WORK/out
mkdir -p "$OUT"

cleanup() {
    local rc=$?
    if [ "${REPRO_KEEP:-0}" != 1 ]; then
        for s in "$SRC_A" "$SRC_B"; do
            [ -e "$s" ] && git -C "$REPO" worktree remove --force "$s" >/dev/null 2>&1 || true
        done
        rm -rf "$WORK/a" "$WORK/b" "$WORK/deps.tgz"
    fi
    exit $rc
}
trap cleanup EXIT

T0=$(date +%s)
say "commit  $COMMIT ($(git -C "$REPO" log -1 --format=%cI "$COMMIT"))"
say "work    $WORK"

# build <label> <src> <build> <TZ> <LC_ALL> <umask> <conan-home>
build() {
    local label=$1 src=$2 bld=$3 tz=$4 lc=$5 um=$6 ch=$7 log=$OUT/build-$1.log
    mkdir -p "$(dirname "$src")"
    git -C "$REPO" worktree add --detach "$src" "$COMMIT" >/dev/null 2>&1 \
        || die "git worktree add $src failed"
    local lock=()
    [ -f "$src/conan.lock" ] && lock=(--lockfile="$src/conan.lock")
    say "build $label: src=$src build=$bld TZ=$tz LC_ALL=$lc umask=$um conan-home=$ch started $(date -u +%H:%M:%S)"
    (
        umask "$um"
        cd "$src"
        export TZ=$tz LC_ALL=$lc CCACHE_DISABLE=1 CONAN_HOME=$ch
        unset SOURCE_DATE_EPOCH CMAKE_C_COMPILER_LAUNCHER CMAKE_CXX_COMPILER_LAUNCHER
        nice -n "$NICE" conan install . -pr:a="$PROFILE" "${lock[@]}" \
            --build="$CONAN_BUILD" --output-folder="$bld" -nr --format=json \
            >"$OUT/graph-$label.json"
        nice -n "$NICE" cmake -S . -B "$bld" \
            -DCMAKE_TOOLCHAIN_FILE="$bld/conan_toolchain.cmake" \
            -DCMAKE_BUILD_TYPE=Release -DXMR_BUILD_RANDOMX=ON
        nice -n "$NICE" cmake --build "$bld" -j"$JOBS" --target "$TARGET"
    ) >"$log" 2>&1 || { tail -30 "$log" >&2; die "build $label failed (log: $log)"; }
    local exe
    exe=$(find "$bld" -type f -name "$TARGET" -perm -u+x | head -1)
    [ -n "$exe" ] || die "build $label produced no $TARGET"
    cp "$exe" "$OUT/$TARGET.$label"
    strip --strip-all -o "$OUT/$TARGET.$label.stripped" "$OUT/$TARGET.$label"
    say "build $label: done $(date -u +%H:%M:%S)"
}

CH_A=$(conan config home) || die "conan not on PATH"
build A "$SRC_A" "$BLD_A" UTC C 022 "$CH_A"

CH_B=$CH_A
if [ "${REPRO_SAME_CONAN_HOME:-0}" != 1 ]; then
    # Second Conan home = the same package binaries (recipe + package revisions)
    # at another absolute path. Save exactly what build A resolved, restore it.
    CH_B=$WORK/b/conan-home
    say "copying build A's resolved Conan packages into $CH_B"
    conan list --graph="$OUT/graph-A.json" --graph-recipes='*' --graph-binaries=cache \
        --format=json >"$OUT/pkglist.json" 2>"$OUT/conan-list.log" || die "conan list failed"
    conan cache save --list="$OUT/pkglist.json" --file="$WORK/deps.tgz" \
        >"$OUT/conan-save.log" 2>&1 || die "conan cache save failed"
    CONAN_HOME=$CH_B conan cache restore "$WORK/deps.tgz" \
        >"$OUT/conan-restore.log" 2>&1 || die "conan cache restore failed"
    rm -f "$WORK/deps.tgz"
fi
say "waiting ${GAP}s so build B starts at a different wall-clock time"
sleep "$GAP"
build B "$SRC_B" "$BLD_B" Asia/Tokyo C.UTF-8 002 "$CH_B"

h() { sha256sum "$1" | cut -d' ' -f1; }
UA=$(h "$OUT/$TARGET.A");          UB=$(h "$OUT/$TARGET.B")
SA=$(h "$OUT/$TARGET.A.stripped"); SB=$(h "$OUT/$TARGET.B.stripped")
say "unstripped  A $UA"
say "unstripped  B $UB"
say "stripped    A $SA"
say "stripped    B $SB"

# ── difference report (only on a mismatch) ───────────────────────────────────
report() {
    local a=$OUT/$TARGET.A b=$OUT/$TARGET.B
    say "size A=$(stat -c%s "$a") B=$(stat -c%s "$b"); differing bytes (cmp -l): $(cmp -l "$a" "$b" 2>/dev/null | wc -l)"
    say "per-section differences (section: size A / size B, differing bytes):"
    local s t fa=$OUT/sec.A fb=$OUT/sec.B
    readelf -SW "$a" | sed -n 's/^ *\[ *[0-9]*\] *//p' | awk '$1 != "NULL" {print $1, $2}' \
    | while read -r s t; do
        [ "$t" = NOBITS ] && continue
        rm -f "$fa" "$fb"
        objcopy --dump-section "$s=$fa" "$a" "$OUT/junk" 2>/dev/null || continue
        [ -f "$fa" ] || continue    # .symtab/.strtab/.shstrtab: compared via nm below
        objcopy --dump-section "$s=$fb" "$b" "$OUT/junk" 2>/dev/null || : >"$fb"
        [ -f "$fb" ] || : >"$fb"
        if ! cmp -s "$fa" "$fb"; then
            printf '  %-28s %9s / %-9s %s\n' "$s" "$(stat -c%s "$fa")" "$(stat -c%s "$fb")" \
                "$(cmp -l "$fa" "$fb" 2>/dev/null | wc -l)"
        fi
    done
    rm -f "$fa" "$fb" "$OUT/junk"
    say "symbol table: $(nm -a "$a" 2>/dev/null | wc -l) entries, $(diff <(nm -a "$a" 2>/dev/null) <(nm -a "$b" 2>/dev/null) | grep -c '^<' || true) differ (value/order)"
    # Path-carrying strings, per class. grep -c exits 1 on zero matches: || true.
    local n1 n2
    n1=$(strings -a "$a" | grep -c -F -e "$SRC_A" -e "$BLD_A" || true)
    n2=$(strings -a "$b" | grep -c -F -e "$SRC_B" -e "$BLD_B" || true)
    say "class source/build dir: strings A=$n1 B=$n2"
    { strings -a "$a" | grep -F -e "$SRC_A" -e "$BLD_A" | sort -u | head -5 | sed 's/^/    /'; } || true
    n1=$(strings -a "$a" | grep -c -F "$CH_A/" || true)
    n2=$(strings -a "$b" | grep -c -F "$CH_B/" || true)
    say "class Conan home: strings A=$n1 ($CH_A) B=$n2 ($CH_B)"
    { strings -a "$a" | grep -F "$CH_A/" | sort -u | head -5 | sed 's/^/    /'; } || true
    say "class RUNPATH: A=[$(readelf -d "$a" | sed -n 's/.*R[UN]*PATH.*: \[\(.*\)\]/\1/p')] B=[$(readelf -d "$b" | sed -n 's/.*R[UN]*PATH.*: \[\(.*\)\]/\1/p')]"
    n1=$(strings -a "$a" | grep -c -E '[0-9]{2}:[0-9]{2}:[0-9]{2}|(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-9][0-9] 20[0-9]{2}' || true)
    n2=$(strings -a "$b" | grep -c -E '[0-9]{2}:[0-9]{2}:[0-9]{2}|(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-9][0-9] 20[0-9]{2}' || true)
    say "class __DATE__/__TIME__-like strings: A=$n1 B=$n2"
    say "build-id A: $(readelf -n "$a" | awk '/Build ID/{print $3}')  B: $(readelf -n "$b" | awk '/Build ID/{print $3}')"
}

T1=$(date +%s)
if [ "$UA" = "$UB" ] && [ "$SA" = "$SB" ]; then
    say "RESULT: REPRODUCIBLE (unstripped and stripped identical) in $(( (T1 - T0) / 60 ))m$(( (T1 - T0) % 60 ))s"
    exit 0
fi
report
say "RESULT: NOT REPRODUCIBLE in $(( (T1 - T0) / 60 ))m$(( (T1 - T0) % 60 ))s (binaries kept in $OUT)"
exit 1
