#!/bin/bash
# Generate SHA256 checksums for all release artifacts
#
# Usage: ./checksums.sh [directory]
# Default: current directory
#
# Generates SHA256SUMS file compatible with `sha256sum -c`

set -e

DIR="${1:-.}"
OUTPUT="$DIR/SHA256SUMS"

echo "Generating SHA256 checksums for release artifacts in $DIR"
echo ""

cd "$DIR"
rm -f SHA256SUMS

# Find release artifacts
FILES=$(find . -maxdepth 1 \( \
    -name '*.dmg' -o \
    -name '*.exe' -o \
    -name '*.zip' -o \
    -name '*.tar.gz' -o \
    -name '*-setup*' -o \
    -name 'c2pool-*' -type d \
    \) | sort)

if [ -z "$FILES" ]; then
    echo "No release artifacts found. Looking for binaries..."
    FILES=$(find . -maxdepth 2 -name 'c2pool' -o -name 'c2pool.exe' | sort)
fi

for f in $FILES; do
    [ -f "$f" ] || continue
    sha256sum "$f" >> SHA256SUMS 2>/dev/null || shasum -a 256 "$f" >> SHA256SUMS
    echo "  $(tail -1 SHA256SUMS)"
done

echo ""
echo "Written to: $DIR/SHA256SUMS"
cat SHA256SUMS
