#!/usr/bin/env bash
# smoke-linux-package.sh — prove a Linux release package runs from where it is
# unpacked, with nothing from the caller's environment.
#
# Usage: scripts/ci/smoke-linux-package.sh [--strict] PACKAGE...
#   PACKAGE   c2pool-<coin>-<ver>-linux-x86_64.tar.gz, or an already unpacked
#             package directory (the one holding c2pool-<coin> and lib/).
#   --strict  also fail when a packaged ELF keeps a RUNPATH/RPATH entry that is
#             not $ORIGIN-relative (the build runner's Conan cache and build
#             tree). release.yml normalises those away before tar
#             (scripts/ci/linux_pkg_normalize_runpath.cmake) and runs this
#             with --strict.
#
# Each package is checked as an operator would run it from a systemd unit or
# their own script, i.e. without start.sh and its LD_LIBRARY_PATH:
#   1. readelf -d: the c2pool-<coin> RUNPATH contains $ORIGIN/lib, and every
#      lib/*.so* that needs a non-system library carries $ORIGIN;
#   2. ldd under `env -i PATH=/usr/bin:/bin`: every dependency of the binary
#      and of every lib/*.so* outside the base system set (glibc, libstdc++,
#      libgcc_s) resolves to a file inside the package's lib/ — not to a host
#      copy, and not "not found";
#   3. `env -i PATH=/usr/bin:/bin ./c2pool-<coin> --help` exits 0.
# Exit status: 0 when every package passes, 1 otherwise, 2 on usage errors.
set -uo pipefail

STRICT=0
PKGS=()
for a in "$@"; do
    case "$a" in
        --strict) STRICT=1 ;;
        -h|--help) sed -n '2,/^set -uo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        -*) echo "smoke-linux-package: unknown option $a" >&2; exit 2 ;;
        *) PKGS+=("$a") ;;
    esac
done
if [ ${#PKGS[@]} -eq 0 ]; then
    echo "usage: $0 [--strict] c2pool-<coin>-<ver>-linux-x86_64.tar.gz|DIR..." >&2
    exit 2
fi
for tool in readelf ldd tar timeout; do
    command -v "$tool" >/dev/null 2>&1 || { echo "smoke-linux-package: $tool not found" >&2; exit 2; }
done

# Not bundled by release.yml (its ldd loop skips the same set): the host's
# glibc, libstdc++ and libgcc_s. Everything else must come from lib/.
is_base_lib() {
    case "$1" in
        linux-vdso.so*|ld-linux*|libc.so*|libm.so*|libdl.so*|librt.so*|libpthread.so*|libresolv.so*|libstdc++.so*|libgcc_s.so*) return 0 ;;
    esac
    return 1
}

# readelf -d | the RUNPATH (or legacy RPATH) string, ':'-separated; empty if none.
elf_runpath() {
    readelf -d "$1" 2>/dev/null | sed -n 's/.*(\(RUNPATH\|RPATH\)).*\[\(.*\)\]$/\2/p' | head -1
}
# A RUNPATH for a log line: as is when short, else its head and entry count.
show_rp() {
    if [ -z "$1" ]; then echo "none"
    elif [ ${#1} -le 96 ]; then echo "$1"
    else echo "${1:0:80}... ($(printf '%s' "$1" | tr ':' '\n' | grep -c .) entries)"
    fi
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/c2pool-pkg-smoke.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

overall=0
n=0
for src in "${PKGS[@]}"; do
    n=$((n + 1))
    fails=0
    fail() { echo "  FAIL $*"; fails=$((fails + 1)); }
    ok()   { echo "  ok   $*"; }
    echo "== $src"

    if [ -d "$src" ]; then
        root="$src"
    elif [ -f "$src" ]; then
        root="$WORK/$n"
        mkdir -p "$root"
        if ! tar -xzf "$src" -C "$root"; then
            fail "cannot unpack $src"; overall=1; continue
        fi
    else
        echo "  FAIL no such file or directory"; overall=1; continue
    fi
    # The package dir is the one holding c2pool-<coin>: the given directory
    # itself, or the c2pool-<coin>-<ver>-linux-x86_64/ a tarball wraps it in.
    find_bins() { find "$1" -mindepth "$2" -maxdepth "$2" -type f -name 'c2pool-*' ! -name '*.*' -perm -u+x | sort; }
    mapfile -t bins < <(find_bins "$root" 1)
    [ ${#bins[@]} -eq 0 ] && mapfile -t bins < <(find_bins "$root" 2)
    if [ ${#bins[@]} -ne 1 ]; then
        fail "expected exactly one c2pool-<coin> executable, found ${#bins[@]}: ${bins[*]:-none}"
        overall=1; continue
    fi
    bin="${bins[0]}"
    pkg="$(cd "$(dirname "$bin")" && pwd -P)"
    name="$(basename "$bin")"
    bin="$pkg/$name"
    [ -d "$pkg/lib" ] || fail "no lib/ directory next to $name"

    # 1. RUNPATH
    rp="$(elf_runpath "$bin")"
    if printf '%s\n' "$rp" | tr ':' '\n' | grep -qxF '$ORIGIN/lib'; then
        ok "$name RUNPATH has \$ORIGIN/lib  [$(show_rp "$rp")]"
    else
        fail "$name RUNPATH lacks \$ORIGIN/lib  [$(show_rp "$rp")]: the loader never looks in lib/ (start.sh's LD_LIBRARY_PATH only)"
    fi
    elves=("$bin")
    for so in "$pkg"/lib/*.so*; do
        [ -f "$so" ] && elves+=("$so")
    done
    for f in "${elves[@]}"; do
        frp="$(elf_runpath "$f")"
        rel="${f#"$pkg"/}"
        if [ "$f" != "$bin" ]; then
            # A bundled library that itself needs a non-base library must find
            # it beside itself; DT_RUNPATH is not inherited from the executable.
            needs_bundled=0
            while read -r need; do
                is_base_lib "$need" || needs_bundled=1
            done < <(readelf -d "$f" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]$/\1/p')
            if [ "$needs_bundled" = 1 ]; then
                if printf '%s\n' "$frp" | tr ':' '\n' | grep -qxF '$ORIGIN'; then
                    ok "$rel RUNPATH has \$ORIGIN"
                else
                    fail "$rel needs a bundled library but its RUNPATH lacks \$ORIGIN  [$(show_rp "$frp")]"
                fi
            fi
        fi
        abs="$(printf '%s\n' "$frp" | tr ':' '\n' | grep -v -e '^$' -e '^\$ORIGIN' -e '^\${ORIGIN}' || true)"
        if [ -n "$abs" ]; then
            msg="$rel RUNPATH keeps $(printf '%s\n' "$abs" | grep -c .) build-host entr(y/ies), e.g. $(printf '%s\n' "$abs" | head -1)"
            if [ "$STRICT" = 1 ]; then fail "$msg"; else echo "  warn $msg"; fi
        fi
    done

    # 2. ldd in a clean environment: every non-base dependency from lib/.
    for f in "${elves[@]}"; do
        rel="${f#"$pkg"/}"
        if ! out="$(env -i PATH=/usr/bin:/bin ldd "$f" 2>&1)"; then
            fail "ldd $rel failed: $out"; continue
        fi
        bad=0
        while read -r line; do
            case "$line" in *"=>"*) ;; *) continue ;; esac
            lib="${line%% =>*}"; lib="${lib//[[:space:]]/}"
            is_base_lib "$lib" && continue
            path="$(printf '%s\n' "$line" | sed -n 's/.*=> \(\/[^ ]*\).*/\1/p')"
            if [ -z "$path" ]; then
                fail "$rel: $lib not found (clean env, no LD_LIBRARY_PATH)"; bad=1; continue
            fi
            real="$(readlink -f "$path")"
            case "$real" in
                "$pkg"/lib/*) ;;
                *) fail "$rel: $lib resolves OUTSIDE the package -> $path"; bad=1 ;;
            esac
        done <<<"$out"
        [ "$bad" = 0 ] && ok "$rel: no non-system dependency resolves outside lib/"
    done

    # 3. The bare binary starts.
    log="$WORK/$n.help.log"
    ( cd "$pkg" && env -i PATH=/usr/bin:/bin timeout 60 "./$name" --help ) >"$log" 2>&1
    rc=$?
    if [ "$rc" = 0 ]; then
        ok "env -i ./$name --help exits 0 ($(wc -l <"$log") lines)"
    else
        fail "env -i ./$name --help exited $rc:"
        head -5 "$log" | sed 's/^/         /'
    fi

    # Info: the glibc / libstdc++ floor the host must meet (not bundled).
    floor="$(readelf -V "$bin" 2>/dev/null | grep -o -E 'GLIBC_[0-9.]+|GLIBCXX_[0-9.]+' | sort -u -V \
             | awk -F_ '{m[$1]=$0} END{for (k in m) printf "%s ", m[k]}')"
    echo "  info host floor: ${floor:-unknown}; bundled: $(cd "$pkg/lib" 2>/dev/null && ls | tr '\n' ' ')"

    if [ "$fails" = 0 ]; then
        echo "  PASS $name"
    else
        echo "  FAIL $name ($fails check(s))"
        overall=1
    fi
done
exit "$overall"
