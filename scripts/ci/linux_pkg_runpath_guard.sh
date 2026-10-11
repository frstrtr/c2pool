#!/usr/bin/env bash
# Fail-closed RUNPATH guard for a staged Linux release package directory.
#
# Usage: linux_pkg_runpath_guard.sh <pkg-dir> <binary-name>
#
# The packaged binary must start on a host that has only glibc and the
# toolchain runtime (libstdc++, libgcc_s), with no LD_LIBRARY_PATH. Checked
# with readelf on the files themselves, not with ldd on the build host (the
# build host has every -dev package installed, so ldd would resolve from
# /usr/lib and hide a missing bundle):
#   1. the binary carries RUNPATH exactly $ORIGIN/lib and no legacy DT_RPATH;
#   2. every bundled lib/*.so* carries RUNPATH exactly $ORIGIN;
#   3. every NEEDED entry of the binary and of each bundled lib is either a
#      glibc/toolchain library or a file present in lib/.
# Any miss prints RUNPATH-ASSERT FAIL and exits 1.
set -euo pipefail

PKG="${1:?pkg dir}"
BIN="${2:?binary name}"
# Same exclusion set as the ldd bundling loop in release.yml: these come from
# the host and are never bundled.
SYSTEM_RE='^(libc|libm|libdl|librt|libpthread|libstdc\+\+|libgcc_s|libresolv)\.so|^ld-linux'

fail=0

runpath_of() { readelf -d "$1" | sed -n 's/.*(RUNPATH).*\[\(.*\)\]/\1/p'; }

check_file() {
  local file="$1" want="$2" rp needed
  rp="$(runpath_of "$file")"
  if [ "$rp" != "$want" ]; then
    echo "RUNPATH-ASSERT FAIL: $file RUNPATH='$rp', want '$want'"
    fail=1
  else
    echo "  ok   $file RUNPATH=$rp"
  fi
  if readelf -d "$file" | grep -q '(RPATH)'; then
    echo "RUNPATH-ASSERT FAIL: $file carries DT_RPATH (must be RUNPATH only)"
    fail=1
  fi
  mapfile -t needed < <(readelf -d "$file" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
  for n in "${needed[@]}"; do
    if [[ "$n" =~ $SYSTEM_RE ]]; then
      continue
    fi
    if [ -e "$PKG/lib/$n" ]; then
      echo "  ok   $(basename "$file") NEEDED $n bundled"
    else
      echo "RUNPATH-ASSERT FAIL: $(basename "$file") NEEDED $n, not in $PKG/lib and not a system lib"
      fail=1
    fi
  done
}

[ -f "$PKG/$BIN" ] || { echo "RUNPATH-ASSERT FAIL: $PKG/$BIN missing"; exit 1; }
check_file "$PKG/$BIN" '$ORIGIN/lib'
shopt -s nullglob
for so in "$PKG"/lib/*.so*; do
  check_file "$so" '$ORIGIN'
done

if [ "$fail" -ne 0 ]; then
  echo "RUNPATH-ASSERT FAIL: $PKG would not bare-start without LD_LIBRARY_PATH"
  exit 1
fi
echo "RUNPATH guard passed for $PKG"
