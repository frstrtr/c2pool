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

# If both secp dylibs were provided, lipo them too — overrides the
# search-and-bundle logic in create-dmg.sh by pre-staging the universal
# dylib at the path create-dmg.sh expects from `otool -L`.
if [ -n "$X86_SECP" ] && [ -f "$X86_SECP" ] && [ -n "$ARM_SECP" ] && [ -f "$ARM_SECP" ]; then
    UNI_SECP="$TMP/libsecp256k1.6.dylib"
    echo
    echo "Combining libsecp256k1 dylibs"
    lipo -create "$X86_SECP" "$ARM_SECP" -output "$UNI_SECP"
    echo "  → $UNI_SECP ($(file "$UNI_SECP" | head -1))"
    # Patch the universal binary's secp256k1 install_name to a stable
    # path the universal dylib will sit at after create-dmg.sh stages it.
    # (create-dmg.sh's otool-driven detection will find the existing
    # install_name and re-point it to @executable_path; pre-pointing it
    # here ensures the universal dylib is the one packaged.)
    UNI_LIB_DIR="$(dirname "$X86_SECP")"
    install_name_tool -change "$X86_SECP" "$UNI_LIB_DIR/libsecp256k1.6.dylib" "$UNI_BIN" 2>/dev/null || true
    install_name_tool -change "$ARM_SECP" "$UNI_LIB_DIR/libsecp256k1.6.dylib" "$UNI_BIN" 2>/dev/null || true
    # Stage the universal dylib at the install_name path so create-dmg.sh's
    # `cp "$LINKED_SECP"` picks it up. (sudo not required if path is in
    # /opt/homebrew/Cellar, but we use a tmp staging dir to avoid
    # mutating Homebrew's tree.)
    cp "$UNI_SECP" "$UNI_LIB_DIR/libsecp256k1.6.dylib.universal" 2>/dev/null || true
fi

echo
echo "Invoking create-dmg.sh with arch=universal"
exec "$SCRIPT_DIR/create-dmg.sh" "$UNI_BIN" universal
