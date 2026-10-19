#!/usr/bin/env bash
# build-release.sh - build c2pool-v37-xmr (Release, RandomX on) and pack it as
#   c2pool-xmr-<version>-linux-x86_64.tar.gz
# with the stripped binary, web-static/, the docs, install.sh, the systemd
# unit, memguard.sh, run-node.sh, node.env.example and SHA256SUMS.
#
# Usage: scripts/xmr-node/build-release.sh [--build-dir DIR] [--out-dir DIR] [--jobs N]
# Env:   CMAKE_EXTRA   extra cmake configure args (e.g. -DCMAKE_PREFIX_PATH=...)
#        CONAN_EXTRA   extra conan install args (e.g. -nr to stay offline)
#        STATIC_RUNTIME=0   link libgcc dynamically (default 1 = -static-libgcc)
#        NICE=15       niceness of the build steps
#
# glibc floor: the binary needs the glibc of the build host or newer. To get a
# lower floor, run this script on an older distribution (e.g. Ubuntu 22.04,
# glibc 2.35). The floor actually required is computed from the binary's
# symbol versions and written to BUILDINFO.txt.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/../.." && pwd)"
BD="$SRC/build-release"
OUT="$SRC/dist"
JOBS="${JOBS:-4}"
NICE="${NICE:-15}"
STATIC_RUNTIME="${STATIC_RUNTIME:-1}"

while [ $# -gt 0 ]; do
    case "$1" in
        --build-dir) BD="$2"; shift 2 ;;
        --out-dir)   OUT="$2"; shift 2 ;;
        --jobs)      JOBS="$2"; shift 2 ;;
        -h|--help)   sed -n 2,17p "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

for t in conan cmake git strip objdump sha256sum tar; do
    command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }
done

VERSION="$(git -C "$SRC" describe --tags --always --dirty 2>/dev/null || echo unknown)"
COMMIT="$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
NAME="c2pool-xmr-${VERSION}-linux-x86_64"
echo "== building $NAME (commit $COMMIT)"

LDFLAGS_RT=""
if [ "$STATIC_RUNTIME" = "1" ]; then
    # libgcc only. libstdc++ stays shared: Conan's Boost links
    # libboost_stacktrace_from_exception, which interposes
    # __cxa_allocate_exception of the SHARED libstdc++; -static-libstdc++
    # then fails to link (multiple definition). So the target needs the
    # libstdc++ of GCC 13 or newer (GLIBCXX floor in BUILDINFO.txt).
    LDFLAGS_RT="-static-libgcc"
fi

cd "$SRC"
nice -n "$NICE" conan install . -pr:a=ci/conan/linux-gcc13.profile --build=missing \
    --output-folder="$BD" -c tools.build:jobs="$JOBS" ${CONAN_EXTRA:-}
# shellcheck disable=SC2086
nice -n "$NICE" cmake -S . -B "$BD" -DCMAKE_TOOLCHAIN_FILE="$BD/conan_toolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release -DXMR_BUILD_RANDOMX=ON \
    -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS_RT" ${CMAKE_EXTRA:-}
nice -n "$NICE" cmake --build "$BD" --target c2pool-v37-xmr -j"$JOBS"

BIN="$BD/src/c2pool/c2pool-v37-xmr"
[ -x "$BIN" ] || { echo "binary not found: $BIN" >&2; exit 1; }
if [ "$STATIC_RUNTIME" = "1" ] && objdump -p "$BIN" | grep -E 'NEEDED +libgcc_s' >/dev/null; then
    echo "libgcc_s is still dynamic in $BIN" >&2; exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
P="$STAGE/$NAME"
mkdir -p "$P/bin" "$P/share/web-static" "$P/share/doc" "$P/share/systemd"

cp "$BIN" "$P/bin/c2pool-v37-xmr"
strip --strip-all "$P/bin/c2pool-v37-xmr"
cp "$HERE/memguard.sh" "$HERE/run-node.sh" "$P/bin/"
cp -r "$SRC/web-static/." "$P/share/web-static/"
cp "$HERE/c2pool-xmr.service" "$P/share/systemd/"
cp "$HERE/install.sh" "$HERE/node.env.example" "$P/"
for d in RUN-A-NODE.md PINNED-SNAPSHOTS.md REPRODUCIBLE-BUILD.md LICENSING.md; do
    cp "$SRC/docs/xmr-lane/$d" "$P/share/doc/"
done
cp "$SRC/LICENSE" "$P/share/doc/LICENSE"
chmod 0755 "$P/install.sh" "$P/bin/"*

# glibc floor = highest GLIBC_x.y symbol version the binary references.
FLOOR="$(objdump -T "$P/bin/c2pool-v37-xmr" | grep -o 'GLIBC_[0-9.]*' \
         | sed 's/GLIBC_//' | sort -uV | tail -1)"
CXXFLOOR="$(objdump -T "$P/bin/c2pool-v37-xmr" | grep -o 'GLIBCXX_[0-9.]*' \
            | sed 's/GLIBCXX_//' | sort -uV | tail -1)"
BUILD_GLIBC="$(getconf GNU_LIBC_VERSION | awk '{print $2}')"
{
    echo "name:          $NAME"
    echo "version:       $VERSION"
    echo "commit:        $COMMIT"
    echo "built_on:      $(. /etc/os-release && echo "$PRETTY_NAME"), glibc $BUILD_GLIBC"
    echo "compiler:      ${CXX:-g++-13} $(${CXX:-g++-13} -dumpfullversion 2>/dev/null || echo unknown)"
    echo "glibc_floor:   $FLOOR"
    echo "glibcxx_floor: $CXXFLOOR (libstdc++.so.6 from GCC 13 or newer)"
    echo "static_libgcc: $STATIC_RUNTIME"
    echo "randomx:       ON"
    echo "needed_libs:   $(objdump -p "$P/bin/c2pool-v37-xmr" | awk '/NEEDED/{print $2}' | xargs)"
} > "$P/BUILDINFO.txt"
echo "$FLOOR" > "$P/GLIBC_FLOOR"

(cd "$P" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
    | xargs -0 sha256sum > SHA256SUMS)

mkdir -p "$OUT"
tar -C "$STAGE" --owner=0 --group=0 --numeric-owner -czf "$OUT/$NAME.tar.gz" "$NAME"
(cd "$OUT" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
echo "== done"
cat "$P/BUILDINFO.txt"
ls -l "$OUT/$NAME.tar.gz"
cat "$OUT/$NAME.tar.gz.sha256"
