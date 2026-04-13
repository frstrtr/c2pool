#!/bin/bash
# c2pool macOS DMG builder
#
# Usage:
#   ./create-dmg.sh <binary> <arch>
#
# Examples:
#   ./create-dmg.sh ~/c2pool-build/build/src/c2pool/c2pool x86_64
#   ./create-dmg.sh ~/c2pool-build/build-arm64/src/c2pool/c2pool arm64
#
# The script expects web-static/, explorer/, config/, start.sh in the
# repo root (same level as src/).  Output: c2pool-VERSION-macos-ARCH.dmg

set -e

BINARY="$1"
ARCH="${2:-$(uname -m)}"
VERSION="0.1.1-alpha"
VOLNAME="c2pool-${VERSION}"
DMG_NAME="c2pool-${VERSION}-macos-${ARCH}.dmg"

if [ -z "$BINARY" ] || [ ! -f "$BINARY" ]; then
    echo "Usage: $0 <path-to-c2pool-binary> [arch]"
    echo "  arch: x86_64 or arm64 (default: native)"
    exit 1
fi

# Verify binary architecture
ACTUAL_ARCH=$(file "$BINARY" | grep -o 'x86_64\|arm64' | head -1)
if [ "$ACTUAL_ARCH" != "$ARCH" ]; then
    echo "ERROR: binary is $ACTUAL_ARCH but arch=$ARCH specified"
    exit 1
fi

# Find repo root (script is in installer/macos/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Staging directory
STAGE=$(mktemp -d)
APP_DIR="$STAGE/$VOLNAME"
mkdir -p "$APP_DIR/lib"

echo "Building $DMG_NAME from $BINARY"
echo "  Repo: $REPO_ROOT"
echo "  Stage: $STAGE"

# Copy binary
cp "$BINARY" "$APP_DIR/c2pool"
chmod +x "$APP_DIR/c2pool"

# Copy bundled assets
cp -R "$REPO_ROOT/web-static" "$APP_DIR/web-static"
cp -R "$REPO_ROOT/config" "$APP_DIR/config"
if [ -d "$REPO_ROOT/explorer" ]; then
    cp -R "$REPO_ROOT/explorer" "$APP_DIR/explorer"
fi

# Copy start script
if [ -f "$REPO_ROOT/start.sh" ]; then
    cp "$REPO_ROOT/start.sh" "$APP_DIR/start.sh"
    chmod +x "$APP_DIR/start.sh"
else
    # Generate a start script
    cat > "$APP_DIR/start.sh" << 'STARTEOF'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${1:-$DIR/config/c2pool_mainnet.yaml}"
export DYLD_LIBRARY_PATH="$DIR/lib:${DYLD_LIBRARY_PATH:-}"
echo "=== c2pool ==="
echo "Config: $CONFIG"
exec "$DIR/c2pool" --integrated --net litecoin \
    --embedded-ltc --embedded-doge \
    --dashboard-dir "$DIR/web-static" \
    --config "$CONFIG"
STARTEOF
    chmod +x "$APP_DIR/start.sh"
fi

# Copy secp256k1 dylib and fix load path
# Detect the actual linked path from the binary (Homebrew may use Cellar paths
# like /usr/local/opt/secp256k1/lib/ instead of /usr/local/lib/)
LINKED_SECP=$(otool -L "$APP_DIR/c2pool" | grep secp256k1 | awk '{print $1}')
if [ -n "$LINKED_SECP" ] && [ -f "$LINKED_SECP" ]; then
    SECP_REAL=$(realpath "$LINKED_SECP")
    cp "$SECP_REAL" "$APP_DIR/lib/libsecp256k1.6.dylib"
    ln -sf libsecp256k1.6.dylib "$APP_DIR/lib/libsecp256k1.dylib"
    install_name_tool -change "$LINKED_SECP" "@executable_path/lib/libsecp256k1.6.dylib" "$APP_DIR/c2pool"
    echo "  secp256k1: $LINKED_SECP -> @executable_path/lib/libsecp256k1.6.dylib"
else
    # Fallback: try known paths
    if [ "$ARCH" = "arm64" ]; then
        SECP_SEARCH="/Users/user0/arm64-deps/lib /opt/homebrew/lib"
    else
        SECP_SEARCH="/usr/local/lib /usr/local/opt/secp256k1/lib"
    fi
    for DIR in $SECP_SEARCH; do
        if [ -f "$DIR/libsecp256k1.6.dylib" ]; then
            cp "$DIR/libsecp256k1.6.dylib" "$APP_DIR/lib/libsecp256k1.6.dylib"
            ln -sf libsecp256k1.6.dylib "$APP_DIR/lib/libsecp256k1.dylib"
            # Try all possible linked names
            for CANDIDATE in "$DIR/libsecp256k1.dylib" "$DIR/libsecp256k1.6.dylib"; do
                install_name_tool -change "$CANDIDATE" "@executable_path/lib/libsecp256k1.6.dylib" "$APP_DIR/c2pool" 2>/dev/null || true
            done
            echo "  secp256k1: $DIR -> @executable_path/lib/libsecp256k1.6.dylib"
            break
        fi
    done
fi

# Add a README
cat > "$APP_DIR/README.txt" << 'README'
c2pool — P2Pool rebirth in C++
https://github.com/frstrtr/c2pool

Quick start:
  1. Open Terminal
  2. cd to this directory
  3. ./start.sh

Or run directly:
  ./c2pool --integrated --net litecoin --embedded-ltc --embedded-doge

Dashboard: http://localhost:8080
Stratum:   stratum+tcp://localhost:9327

Miners connect with their payout address as the stratum username.
README

# Create DMG
OUTPUT="$REPO_ROOT/$DMG_NAME"
rm -f "$OUTPUT"
hdiutil create -volname "$VOLNAME" \
    -srcfolder "$APP_DIR" \
    -ov -format UDZO \
    "$OUTPUT"

# Cleanup
rm -rf "$STAGE"

echo ""
echo "Created: $OUTPUT"
echo "Size: $(du -h "$OUTPUT" | cut -f1)"
echo "SHA256: $(shasum -a 256 "$OUTPUT" | cut -d' ' -f1)"
