#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build c2pool_dashbls.dll: the BLS12-381 backend of the Windows (MSVC)
# c2pool-dash, made from the SAME source and the SAME build recipe as dashd.
#
#     usage (MSYS2 MINGW64 shell):  build_dashbls_win64.sh <prefix>
#
# dashd's Windows release builds src/dashbls with autotools and mingw-w64 GCC
# (posix threads) against a static GMP. This script does the same thing in
# MSYS2's MINGW64 environment by running scripts/build_dashbls.sh unchanged:
# same pinned dash tag, same configure, ARITH=GMP, MULTI=PTHREAD. MSVC cannot
# link that C++ static library, so it is then linked, with static GMP,
# libstdc++, libgcc and winpthreads, into ONE self-contained DLL whose only
# exports are the C functions of
# src/impl/dash/coin/vendor/dashbls_abi/c2pool_dashbls_abi.h. The MSVC build
# reaches dashbls through that ABI (see the header for the full rationale).
#
# Output in <prefix>:
#   bin/c2pool_dashbls.dll   the DLL that ships next to c2pool-dash.exe
#   lib/c2pool_dashbls.def   its export list, by name only; cmake turns it
#                            into an MSVC import library
#   lib/libdashbls.a, include/   the dashbls install from build_dashbls.sh
#
# Before installing, it checks that relic really was configured for GMP, that
# the DLL needs no mingw runtime DLL, that it carries the BLS ciphersuite and
# every ABI export, and that a plain-C self-test verifies a real testnet
# quorum-commitment signature through it.
#
# Environment: C2POOL_SRC = repository root (default: this script's ../);
# DASH_REF and BUILD_DIR pass through to build_dashbls.sh.
set -euo pipefail

PREFIX="${1:?usage: $0 <prefix>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
C2POOL_SRC="${C2POOL_SRC:-$(cd "$HERE/.." && pwd)}"
ABI_DIR="$C2POOL_SRC/src/impl/dash/coin/vendor/dashbls_abi"

case "$(uname -s)" in
    MINGW64*) ;;
    *) echo "[build_dashbls_win64] ERROR: run this in MSYS2's MINGW64 shell (uname: $(uname -s))" >&2
       exit 1 ;;
esac

die() { echo "[build_dashbls_win64] ERROR: $*" >&2; exit 1; }

# The pin lives in build_dashbls.sh; honour a DASH_REF override the same way it does.
PINNED="$(sed -n 's/^DASH_REF="\${DASH_REF:-\(.*\)}"$/\1/p' "$HERE/build_dashbls.sh")"
[ -n "$PINNED" ] || die "could not parse DASH_REF from $HERE/build_dashbls.sh"
DASH_REF="${DASH_REF:-$PINNED}"
export DASH_REF

echo "[build_dashbls_win64] dash ref=$DASH_REF prefix=$PREFIX"
echo "[build_dashbls_win64] toolchain: $(g++ --version | head -1) ($(g++ -dumpmachine))"

# 1. dashbls itself, exactly as on Linux and macOS.
bash "$HERE/build_dashbls.sh" "$PREFIX"

conf="$PREFIX/include/relic_conf.h"
grep -q '^#define ARITH GMP$' "$conf" || die "relic was not configured with ARITH=GMP ($conf)"
grep -q '^#define MULTI PTHREAD$' "$conf" || die "relic was not configured with MULTI=PTHREAD ($conf)"
grep -q '^#define OPSYS WINDOWS$' "$conf" || die "relic was not configured for Windows ($conf)"

# 2. The DLL. -static makes every non-system library static (libstdc++, libgcc,
# winpthreads, gmp), as dashd's own mingw link does; the system import
# libraries are the ones dashbls' configure checks for on mingw.
mkdir -p "$PREFIX/bin" "$PREFIX/lib"
stage="$(mktemp -d)"
g++ -std=c++17 -O2 -DNDEBUG -shared \
    -DC2DBLS_BUILDING_DLL -DC2DBLS_DASH_REF="\"$DASH_REF\"" \
    -I"$PREFIX/include" -I"$ABI_DIR" \
    "$ABI_DIR/c2pool_dashbls_abi.cpp" \
    "$PREFIX/lib/libdashbls.a" -lgmp \
    -static -static-libgcc -static-libstdc++ \
    -lbcrypt -ladvapi32 -lpsapi -luser32 -lshell32 \
    -Wl,--output-def,"$stage/ld-exports.def" \
    -o "$stage/c2pool_dashbls.dll"

# 3. Checks on the artefact.
imports="$(objdump -p "$stage/c2pool_dashbls.dll" | sed -n 's/^[[:space:]]*DLL Name: //p')"
echo "[build_dashbls_win64] DLL imports: $(echo "$imports" | tr '\n' ' ')"
while read -r dll; do
    [ -n "$dll" ] || continue
    case "$(echo "$dll" | tr '[:upper:]' '[:lower:]')" in
        kernel32.dll|msvcrt.dll|advapi32.dll|bcrypt.dll|psapi.dll|user32.dll|shell32.dll|api-ms-win-*) ;;
        *) die "c2pool_dashbls.dll depends on $dll, which would have to ship too" ;;
    esac
done <<< "$imports"

exports="$(sed -n 's/^[[:space:]]*\(c2dbls_[a-z0-9_]*\).*/\1/p' "$stage/ld-exports.def" | sort -u)"
wanted="$(sed -n 's/^C2DBLS_API[^(]*[ *]\(c2dbls_[a-z0-9_]*\)(.*/\1/p' "$ABI_DIR/c2pool_dashbls_abi.h" | sort -u)"
[ -n "$wanted" ] || die "could not read the export list from c2pool_dashbls_abi.h"
missing="$(comm -13 <(echo "$exports") <(echo "$wanted"))"
[ -z "$missing" ] || die "DLL is missing exports: $missing"
echo "[build_dashbls_win64] exports: $(echo "$wanted" | wc -l) C ABI functions"

# The export list cmake turns into the MSVC import library. Names only: ld's
# own --output-def numbers every entry ("name @N"), and an import library made
# from that binds the exe to ORDINALS, so a rebuilt DLL whose numbering moved
# would be called at the wrong functions without any load error. By name, a
# mismatch fails at load instead.
{
    echo "LIBRARY c2pool_dashbls.dll"
    echo "EXPORTS"
    echo "$wanted" | sed 's/^/    /'
} > "$stage/c2pool_dashbls.def"

grep -a -q -E 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_(NUL|AUG|POP)_' "$stage/c2pool_dashbls.dll" \
    || die "no BLS12-381 ciphersuite ID in the DLL"

gcc -std=c11 -O1 -I"$ABI_DIR" "$ABI_DIR/c2pool_dashbls_selftest.c" \
    "$stage/c2pool_dashbls.dll" -o "$stage/c2pool_dashbls_selftest.exe"
( cd "$stage" && ./c2pool_dashbls_selftest.exe ) || die "self-test failed"

# 4. Install.
cp "$stage/c2pool_dashbls.dll" "$PREFIX/bin/"
cp "$stage/c2pool_dashbls.def" "$PREFIX/lib/"
rm -rf "$stage"
echo "[build_dashbls_win64] installed $PREFIX/bin/c2pool_dashbls.dll"
