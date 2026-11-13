#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build the macOS release dependencies that do not come from Conan, as STATIC
# libraries for ONE target architecture, into <prefix>:
#
#   secp256k1  bitcoin-core/secp256k1 at a pinned tag + commit (not on
#              ConanCenter; Linux takes it from the distro, Windows builds it
#              from source the same way)
#   gmp        GNU MP at a pinned version + sha256 (relic's ARITH=GMP backend
#              inside dashbls; only the DASH build links it)
#
# Everything else (boost, leveldb, yaml-cpp, nlohmann_json, zeromq, gtest) comes
# from conanfile.txt + conan.lock, the same pins as the Linux and Windows lanes.
#
# All macOS packages are built on an Apple Silicon host. The arm64 slice is a
# native build; the x86_64 slice is a cross build (clang -arch x86_64, autotools
# --host=x86_64-apple-darwin). No Homebrew library is used for either slice, so
# both slices of the universal binary link the same pinned sources.
#
#   usage: scripts/ci/build_macos_deps.sh <arm64|x86_64> <prefix>
#          scripts/ci/build_macos_deps.sh --key <arm64|x86_64>
#
# The prefix gets a .deps-key marker holding DEPS_KEY (below); callers reuse a
# prefix whose marker matches and rebuild otherwise. --key prints that string.
set -euo pipefail

KEY_ONLY=0
if [ "${1:-}" = "--key" ]; then
    KEY_ONLY=1
    shift
fi
ARCH="${1:?usage: build_macos_deps.sh <arm64|x86_64> <prefix>}"
PREFIX="${2:-}"

SECP256K1_REPO="https://github.com/bitcoin-core/secp256k1.git"
SECP256K1_REF="v0.8.0"
SECP256K1_COMMIT="6e2c8bc4ecdc6e71dbe7a368f360d8d453ce435d"
GMP_VERSION="6.3.0"
GMP_SHA256="a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898"
GMP_URLS="https://ftp.gnu.org/gnu/gmp/gmp-${GMP_VERSION}.tar.xz https://gmplib.org/download/gmp/gmp-${GMP_VERSION}.tar.xz"

# The provisioning action keys its prefix on this string, so a re-pin here
# rebuilds every runner's prefix.
DEPS_KEY="secp256k1-${SECP256K1_REF}-${SECP256K1_COMMIT:0:12}+gmp-${GMP_VERSION}+${ARCH}"
if [ "$KEY_ONLY" -eq 1 ]; then
    echo "$DEPS_KEY"
    exit 0
fi
[ -n "$PREFIX" ] || { echo "usage: build_macos_deps.sh <arm64|x86_64> <prefix>" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || { echo "[build_macos_deps] macOS only" >&2; exit 1; }
case "$ARCH" in
    arm64)  HOST_TRIPLE="aarch64-apple-darwin" ;;
    x86_64) HOST_TRIPLE="x86_64-apple-darwin" ;;
    *) echo "[build_macos_deps] unknown arch '$ARCH' (want arm64 or x86_64)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    arm64)  BUILD_TRIPLE="aarch64-apple-darwin" ;;
    x86_64) BUILD_TRIPLE="x86_64-apple-darwin" ;;
    *) echo "[build_macos_deps] unsupported build host $(uname -m)" >&2; exit 1 ;;
esac
JOBS="${JOBS:-4}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/c2pool-macos-deps.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

echo "[build_macos_deps] arch=$ARCH host=$HOST_TRIPLE build=$BUILD_TRIPLE prefix=$PREFIX key=$DEPS_KEY"
mkdir -p "$PREFIX"

# ── secp256k1 ────────────────────────────────────────────────────────────────
# Same module set as the Windows lane: upstream defaults plus the recovery
# module (secp256k1_recovery.h is used by the share-message and wallet code).
git clone --quiet --depth 1 --branch "$SECP256K1_REF" "$SECP256K1_REPO" "$WORK/secp256k1"
got="$(git -C "$WORK/secp256k1" rev-parse HEAD)"
if [ "$got" != "$SECP256K1_COMMIT" ]; then
    echo "[build_macos_deps] secp256k1 $SECP256K1_REF resolved to $got, expected $SECP256K1_COMMIT" >&2
    exit 1
fi
cmake -S "$WORK/secp256k1" -B "$WORK/secp256k1/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
    -DSECP256K1_BUILD_TESTS=OFF \
    -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
    -DSECP256K1_BUILD_BENCHMARK=OFF \
    -DSECP256K1_BUILD_EXAMPLES=OFF
cmake --build "$WORK/secp256k1/build" -j "$JOBS"
cmake --install "$WORK/secp256k1/build"

# ── gmp ──────────────────────────────────────────────────────────────────────
# --host names a generic CPU, so the x86_64 build uses baseline x86-64 code
# (no tuning to whatever CPU a build host happens to have) and the arm64 build
# uses the generic aarch64 code. Static + PIC: it is linked into the c2pool-dash
# executable, so there is no libgmp dylib to bundle or lipo.
tarball="$WORK/gmp-${GMP_VERSION}.tar.xz"
for url in $GMP_URLS; do
    if curl -fsSL --retry 3 --max-time 300 -o "$tarball" "$url"; then
        break
    fi
    echo "[build_macos_deps] gmp download failed from $url"
    rm -f "$tarball"
done
[ -f "$tarball" ] || { echo "[build_macos_deps] could not download gmp ${GMP_VERSION}" >&2; exit 1; }
echo "${GMP_SHA256}  ${tarball}" | shasum -a 256 -c -
tar -xJf "$tarball" -C "$WORK"
(
    cd "$WORK/gmp-${GMP_VERSION}"
    ./configure \
        --build="$BUILD_TRIPLE" --host="$HOST_TRIPLE" \
        --prefix="$PREFIX" \
        --enable-static --disable-shared --with-pic \
        CC="clang -arch $ARCH" CC_FOR_BUILD="clang"
    make -j "$JOBS"
    make install
)

# ── verify ───────────────────────────────────────────────────────────────────
fail=0
for f in "$PREFIX/lib/libsecp256k1.a" "$PREFIX/include/secp256k1.h" \
         "$PREFIX/include/secp256k1_recovery.h" \
         "$PREFIX/lib/libgmp.a" "$PREFIX/include/gmp.h"; do
    if [ -f "$f" ]; then echo "  ok   $f"; else echo "  MISS $f"; fail=1; fi
done
for lib in "$PREFIX/lib/libsecp256k1.a" "$PREFIX/lib/libgmp.a"; do
    [ -f "$lib" ] || continue
    archs="$(lipo -archs "$lib" 2>/dev/null || true)"
    echo "  $(basename "$lib"): $archs"
    [ "$archs" = "$ARCH" ] || { echo "  WRONG ARCH in $lib (want $ARCH)"; fail=1; }
done
[ "$fail" -eq 0 ] || { echo "[build_macos_deps] verification failed" >&2; exit 1; }
printf '%s\n' "$DEPS_KEY" > "$PREFIX/.deps-key"
echo "[build_macos_deps] done: $PREFIX"
