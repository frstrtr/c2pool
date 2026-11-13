#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Checks every slice of the Mach-O files a macOS package ships.
#
#   usage: scripts/ci/macos_macho_check.sh --min <macos-version> --archs "<arch...>" <file>...
#
# For each file and each listed arch it requires:
#   1. the slice exists;
#   2. its minimum macOS (LC_BUILD_VERSION minos) equals --min, the pinned
#      deployment target; a slice built for a newer macOS would not start on
#      older Macs, and Intel Macs stop at the last macOS that supports them;
#   3. every LC_RPATH is relative to the package (@executable_path or
#      @loader_path), so nothing is looked up on the build host;
#   4. no load command points outside the package or the system;
#   5. no printable string anywhere in the slice (sections, load commands,
#      symbol tables) names the build host: "/Users/", ".c2pool-deps",
#      "actions-runner", the runner name or the host name.
# Exits non-zero, after listing every failure, when any check fails.
set -uo pipefail

MIN=""
ARCHS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --min)   MIN="$2"; shift 2 ;;
        --archs) ARCHS="$2"; shift 2 ;;
        --)      shift; break ;;
        -*)      echo "::error::macos_macho_check: unknown option $1"; exit 2 ;;
        *)       break ;;
    esac
done
[ -n "$MIN" ] && [ -n "$ARCHS" ] && [ $# -gt 0 ] || {
    echo "usage: macos_macho_check.sh --min <macos-version> --archs \"<arch...>\" <file>..."
    exit 2
}

# Fixed markers, plus this host's runner and host names (read at run time so
# they never have to be written down anywhere).
markers=("/Users/" ".c2pool-deps" "actions-runner")
runner="${RUNNER_NAME:-}"
[ "${#runner}" -ge 3 ] && markers+=("$runner")
host="$(hostname -s 2>/dev/null || true)"
[ "${#host}" -ge 3 ] && markers+=("$host")
grep_args=()
for m in "${markers[@]}"; do grep_args+=(-e "$m"); done

tmp="$(mktemp -d "${TMPDIR:-/tmp}/macho-check.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "::error::$*"; fail=1; }

for f in "$@"; do
    [ -f "$f" ] || { bad "$f: not a file"; continue; }
    name="$(basename "$f")"
    for a in $ARCHS; do
        if ! lipo "$f" -verify_arch "$a" 2>/dev/null; then
            bad "$name: no $a slice (lipo -archs: $(lipo -archs "$f" 2>&1))"
            continue
        fi
        minos="$(otool -arch "$a" -l "$f" | awk '$1=="minos"{print $2; exit}')"
        rpaths="$(otool -arch "$a" -l "$f" | awk '$2=="LC_RPATH"{r=1; next} r&&$1=="path"{print $2; r=0}')"
        bad_rpaths="$(printf '%s\n' "$rpaths" | grep -v -E '^(@executable_path|@loader_path)(/|$)' | grep -v '^$' || true)"
        bad_loads="$(otool -arch "$a" -L "$f" | tail -n +2 | awk '{print $1}' | grep -v -E '^(/usr/lib/|/System/|@executable_path/|@loader_path/)' || true)"
        if [ "$(lipo -archs "$f")" = "$a" ]; then
            slice="$f"
        else
            slice="$tmp/$name.$a"
            lipo -thin "$a" "$f" -output "$slice"
        fi
        # Every printable run in the whole slice (sections, load commands,
        # symbol and string tables), not only what strings(1) looks at.
        hits="$(LC_ALL=C tr -c '[:print:]' '\n' < "$slice" | grep -F "${grep_args[@]}" || true)"
        nhits=0
        [ -n "$hits" ] && nhits="$(printf '%s\n' "$hits" | wc -l | tr -d ' ')"
        nrp=0
        [ -n "$rpaths" ] && nrp="$(printf '%s\n' "$rpaths" | wc -l | tr -d ' ')"
        echo "$name [$a]: minos ${minos:-none}, LC_RPATH $nrp (outside the package: $(printf '%s' "$bad_rpaths" | grep -c . || true)), host-path strings $nhits"
        [ "$minos" = "$MIN" ] || bad "$name [$a]: minimum macOS is '${minos:-none}', pinned target is $MIN"
        [ -z "$bad_rpaths" ] || bad "$name [$a]: LC_RPATH outside the package: $(echo $bad_rpaths)"
        [ -z "$bad_loads" ] || bad "$name [$a]: load command outside the package/system: $(echo $bad_loads)"
        if [ "$nhits" -gt 0 ]; then
            bad "$name [$a]: $nhits string(s) name the build host, e.g.:"
            printf '%s\n' "$hits" | head -n 5 | sed 's/^/    /'
        fi
    done
done
[ "$fail" -eq 0 ] && echo "  ok   $# file(s), slices [$ARCHS]: minimum macOS $MIN, no rpath or string pointing at the build host"
exit "$fail"
