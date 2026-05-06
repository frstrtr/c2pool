#!/bin/bash
# c2pool macOS Universal DMG builder (Intel + Apple Silicon in one .dmg)
#
# Combines a x86_64 c2pool binary + an arm64 c2pool binary (built on
# their respective Macs, scp'd here) into a universal Mach-O via
# `lipo -create`, then invokes create-dmg.sh to bundle the universal
# binary + (universal) libsecp256k1 + web-static + config + explorer
# into a distributable .dmg.
#
# Must be run on a macOS host with lipo (any modern Xcode CLI Tools).
#
# Usage:
#   ./create-universal-dmg.sh <x86_64-binary> <arm64-binary> [x86_64-secp-dylib] [arm64-secp-dylib]
#
# Example (run on M4, after `scp user0@intel-mac:c2pool/build-x86_64/src/c2pool/c2pool ./c2pool-x86_64`):
#   ./create-universal-dmg.sh ./c2pool-x86_64 ~/c2pool/build-arm64/src/c2pool/c2pool \
#                             /usr/local/Cellar/secp256k1/0.7.0/lib/libsecp256k1.6.dylib \
#                             /opt/homebrew/Cellar/secp256k1/0.7.0/lib/libsecp256k1.6.dylib
#
# If only the c2pool binaries are passed, the script will lipo them and
# delegate to create-dmg.sh, which will detect the linked libsecp256k1
# from one slice. The resulting .dmg will then be partially-universal
# (universal c2pool, single-arch libsecp256k1) — workable for testing,
# NOT for distribution. Pass both dylibs for a fully-universal package.

set -e

X86_BIN="$1"
ARM_BIN="$2"
X86_SECP="$3"
ARM_SECP="$4"

if [ -z "$X86_BIN" ] || [ ! -f "$X86_BIN" ] || [ -z "$ARM_BIN" ] || [ ! -f "$ARM_BIN" ]; then
    echo "Usage: $0 <x86_64-binary> <arm64-binary> [x86_64-secp-dylib] [arm64-secp-dylib]"
    exit 1
fi

# Verify each input is the expected architecture
if ! file "$X86_BIN" | grep -q 'x86_64'; then
    echo "ERROR: $X86_BIN is not x86_64"; file "$X86_BIN"; exit 1
fi
if ! file "$ARM_BIN" | grep -q 'arm64'; then
    echo "ERROR: $ARM_BIN is not arm64"; file "$ARM_BIN"; exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP=$(mktemp -d)
UNI_BIN="$TMP/c2pool-universal"

echo "Combining $X86_BIN + $ARM_BIN into universal binary"
lipo -create "$X86_BIN" "$ARM_BIN" -output "$UNI_BIN"
echo "  → $UNI_BIN"
echo "  → $(file "$UNI_BIN" | head -1)"
echo "  → SHA256: $(shasum -a 256 "$UNI_BIN" | cut -d' ' -f1)"

# If both secp dylibs were provided, lipo them and stage the universal
# dylib at a stable absolute path that create-dmg.sh's `otool -L` →
# `cp` flow will see and bundle. The universal binary's install_name
# is patched to point at that staged path so `otool -L` reports it.
#
# Note: the per-arch binary's libsecp256k1 install_name was baked in at
# link time on its respective host (e.g. /usr/local/opt/...lib... on
# Intel Homebrew, /opt/homebrew/opt/...lib... on Apple Silicon). It
# does NOT necessarily equal the FILE PATH the user passed (which is
# wherever the dylib lives on THIS host running the wrapper). We
# discover the actual install_names via `otool -L` on each per-arch
# binary before lipo-ing, then use those exact strings as the FROM in
# install_name_tool -change calls.
if [ -n "$X86_SECP" ] && [ -f "$X86_SECP" ] && [ -n "$ARM_SECP" ] && [ -f "$ARM_SECP" ]; then
    X86_INSTALL_NAME=$(otool -L "$X86_BIN" | grep -m1 secp256k1 | awk '{print $1}')
    ARM_INSTALL_NAME=$(otool -L "$ARM_BIN" | grep -m1 secp256k1 | awk '{print $1}')
    if [ -z "$X86_INSTALL_NAME" ] || [ -z "$ARM_INSTALL_NAME" ]; then
        echo "ERROR: couldn't read libsecp256k1 install_name from one of the binaries"
        otool -L "$X86_BIN" | head -10
        otool -L "$ARM_BIN" | head -10
        exit 1
    fi

    UNI_SECP_TMP="$TMP/libsecp256k1.6.dylib"
    UNI_SECP_STAGED="$TMP/staged-libsecp256k1.6.dylib"
    echo
    echo "Combining libsecp256k1 dylibs"
    lipo -create "$X86_SECP" "$ARM_SECP" -output "$UNI_SECP_TMP"
    echo "  → $UNI_SECP_TMP ($(file "$UNI_SECP_TMP" | head -1))"

    cp "$UNI_SECP_TMP" "$UNI_SECP_STAGED"
    echo "  x86_64 install_name was: $X86_INSTALL_NAME"
    echo "  arm64  install_name was: $ARM_INSTALL_NAME"
    install_name_tool -change "$X86_INSTALL_NAME" "$UNI_SECP_STAGED" "$UNI_BIN" 2>/dev/null || true
    install_name_tool -change "$ARM_INSTALL_NAME" "$UNI_SECP_STAGED" "$UNI_BIN" 2>/dev/null || true
    echo "  → both slices' install_name patched to $UNI_SECP_STAGED"
fi

echo
echo "Invoking create-dmg.sh with arch=universal"
exec "$SCRIPT_DIR/create-dmg.sh" "$UNI_BIN" universal
