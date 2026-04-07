#!/bin/bash
set -euo pipefail

SRCDIR="$(cd "$(dirname "$0")" && pwd)"
BUILDDIR="${SRCDIR}/build-release"
JOBS="${JOBS:-$(nproc)}"

mkdir -p "$BUILDDIR"

echo "=== Conan install (Release) ==="
conan install "$SRCDIR" \
    --build=missing \
    --output-folder="$BUILDDIR" \
    --settings=build_type=Release \
    --settings=compiler.cppstd=20

echo "=== CMake configure ==="
cmake -S "$SRCDIR" -B "$BUILDDIR" \
    -DCMAKE_TOOLCHAIN_FILE="${BUILDDIR}/conan_toolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release

echo "=== Build c2pool ==="
cmake --build "$BUILDDIR" --target c2pool -j"$JOBS"

BINARY="${BUILDDIR}/src/c2pool/c2pool"
echo ""
echo "=== Done ==="
ls -lh "$BINARY"
echo "Runtime dependencies:"
ldd "$BINARY" | grep -v linux-vdso | awk '{print "  " $1}'
