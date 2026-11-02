#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-appimage.sh — Linux packaging for c2wallet-qt (release.yml
# c2wallet-linux and c2wallet-companion-linux jobs).
#
#   --profile signer     c2wallet-qt-signer: an AppDir built by linuxdeploy +
#                        linuxdeploy-plugin-qt, emitted twice with the same
#                        files: c2wallet-qt-signer-<v>-linux-x86_64.AppImage
#                        and .tar.gz. The packaged binary is re-checked by
#                        ci/check_no_network.sh and the whole tree by
#                        ci/check_package_no_network.sh before anything is
#                        emitted.
#   --profile companion  c2wallet-qt-companion + c2wallet-qt-schedd (+ the
#                        systemd unit): c2wallet-qt-companion-<v>-linux-x86_64
#                        .tar.gz only. The online side MAY link QtNetwork, so
#                        no network scan here; the job runs the key-free and
#                        headless guards instead. The signer and the companion
#                        are never packaged together.
#
# Usage:
#   installer/linux/c2wallet-appimage.sh --profile signer --version 0.2.9 \
#       --binary build/c2wallet-qt-signer --out dist
#   installer/linux/c2wallet-appimage.sh --profile companion --version 0.2.9 \
#       --binary build/c2wallet-qt-companion --binary build/c2wallet-qt-schedd \
#       --extra ui/c2wallet-qt/tools/c2wallet-qt-schedd.service --out dist
#
# Every package carries licenses/, README-SIGNER.txt (signer) and MANIFEST.txt
# (sha256 of every file inside, so the inner binary can be verified even
# though the AppImage container is not bit-reproducible).
#
# Inputs are pinned: the three tools and the AppImage runtime by release tag +
# sha256 (a mismatch aborts), Qt by the distro package (qt6-base-dev, the same
# toolchain as the PR-time link-guard job). QMAKE defaults to Ubuntu's
# /usr/lib/qt6/bin/qmake. Tools are cached in C2W_TOOLS_DIR
# (default ~/.cache/c2wallet-appimage-tools).
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
C2W="$REPO/ui/c2wallet-qt"

# ── pinned tools (release tag + sha256) ─────────────────────────────────────
LD_URL="https://github.com/linuxdeploy/linuxdeploy/releases/download/1-alpha-20251107-1/linuxdeploy-x86_64.AppImage"
LD_SHA="c20cd71e3a4e3b80c3483cef793cda3f4e990aca14014d23c544ca3ce1270b4d"
LDQT_URL="https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/1-alpha-20250213-1/linuxdeploy-plugin-qt-x86_64.AppImage"
LDQT_SHA="15106be885c1c48a021198e7e1e9a48ce9d02a86dd0a1848f00bdbf3c1c92724"
AIT_URL="https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage"
AIT_SHA="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
RT_URL="https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64"
RT_SHA="2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"

PROFILE=""
VERSION=""
OUT=""
BINARIES=()
EXTRAS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) PROFILE="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --binary)  BINARIES+=("$2"); shift 2 ;;
        --extra)   EXTRAS+=("$2"); shift 2 ;;
        --out)     OUT="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ "$PROFILE" == signer || "$PROFILE" == companion ]] || { echo "--profile signer|companion is required" >&2; exit 2; }
[[ -n "$VERSION" ]] || { echo "--version is required" >&2; exit 2; }
[[ -n "$OUT" ]] || { echo "--out is required" >&2; exit 2; }
[[ ${#BINARIES[@]} -gt 0 ]] || { echo "at least one --binary is required" >&2; exit 2; }
for b in "${BINARIES[@]}"; do [[ -f "$b" ]] || { echo "binary not found: $b" >&2; exit 2; }; done
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || echo 0)}"
export APPIMAGE_EXTRACT_AND_RUN=1   # CI runners have no FUSE
export ARCH=x86_64
if [[ -z "${QMAKE:-}" ]]; then
    if [[ -x /usr/lib/qt6/bin/qmake ]]; then QMAKE=/usr/lib/qt6/bin/qmake; else QMAKE="$(command -v qmake6 || command -v qmake)"; fi
fi
export QMAKE
echo "qmake: $QMAKE ($("$QMAKE" -query QT_VERSION))"

# ── fetch + verify the pinned tools ─────────────────────────────────────────
TOOLS="${C2W_TOOLS_DIR:-$HOME/.cache/c2wallet-appimage-tools}"
mkdir -p "$TOOLS"
fetch() { # url sha256 dest-name
    local url="$1" sha="$2" dest="$TOOLS/$3"
    if [[ -f "$dest" ]] && echo "$sha  $dest" | sha256sum -c --status; then return 0; fi
    rm -f "$dest"
    curl -fsSL --retry 3 --retry-delay 5 -o "$dest.part" "$url"
    if ! echo "$sha  $dest.part" | sha256sum -c --status; then
        echo "FAIL: sha256 mismatch for $url" >&2
        sha256sum "$dest.part" >&2
        rm -f "$dest.part"
        exit 1
    fi
    mv "$dest.part" "$dest"
    chmod +x "$dest"
}
fetch "$LD_URL" "$LD_SHA" linuxdeploy-x86_64.AppImage
fetch "$LDQT_URL" "$LDQT_SHA" linuxdeploy-plugin-qt-x86_64.AppImage
fetch "$AIT_URL" "$AIT_SHA" appimagetool-x86_64.AppImage
fetch "$RT_URL" "$RT_SHA" runtime-x86_64
export PATH="$TOOLS:$PATH"   # linuxdeploy finds its qt plugin on PATH

# ── the AppDir ──────────────────────────────────────────────────────────────
if [[ "$PROFILE" == signer ]]; then
    NAME="c2wallet-qt-signer"
    DESKTOP="$C2W/packaging/c2wallet-qt-signer.desktop"
    ICON="$C2W/packaging/c2wallet-qt-signer.png"
else
    NAME="c2wallet-qt-companion"
    DESKTOP="$C2W/packaging/c2wallet-qt-companion.desktop"
    ICON=""
fi
PKG="${NAME}-${VERSION}-linux-x86_64"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/c2w-appdir-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
APPDIR="$WORK/$PKG"
mkdir -p "$APPDIR"
if [[ -z "$ICON" ]]; then
    ICON="$WORK/${NAME}.png"   # linuxdeploy wants the icon file named after Icon=
    cp "$C2W/packaging/c2wallet-qt-signer.png" "$ICON"
fi

LD_ARGS=(--appdir "$APPDIR" --desktop-file "$DESKTOP" --icon-file "$ICON" --plugin qt)
for b in "${BINARIES[@]}"; do LD_ARGS+=(--executable "$b"); done
linuxdeploy-x86_64.AppImage "${LD_ARGS[@]}"

for x in "${EXTRAS[@]}"; do cp "$x" "$APPDIR/"; done
mkdir -p "$APPDIR/licenses"
cp "$REPO/LICENSE" "$APPDIR/licenses/LICENSE-AGPL-3.0.txt"
cp "$C2W/packaging/licenses/"*.txt "$APPDIR/licenses/"
for f in /usr/share/doc/libsecp256k1-*/copyright; do
    [[ -f "$f" ]] && cp "$f" "$APPDIR/licenses/libsecp256k1-copyright.txt" && break
done
if [[ "$PROFILE" == signer ]]; then
    cp "$C2W/packaging/README-SIGNER.txt" "$APPDIR/"
    # The packaged binary must still be the network-incapable one, and the deploy
    # step must have brought a platform plugin (else it starts nowhere).
    "$C2W/ci/check_no_network.sh" "$APPDIR/usr/bin/c2wallet-qt-signer"
    "$C2W/ci/check_package_no_network.sh" "$APPDIR"
    [[ -f "$APPDIR/usr/plugins/platforms/libqxcb.so" ]] || { echo "FAIL: no xcb platform plugin in the AppDir" >&2; exit 1; }
fi

# MANIFEST.txt: sha256 of every regular file, sorted, relative to the root.
( cd "$APPDIR" && find . -type f ! -name MANIFEST.txt -print0 | LC_ALL=C sort -z | xargs -0 sha256sum ) > "$WORK/MANIFEST.txt"
mv "$WORK/MANIFEST.txt" "$APPDIR/MANIFEST.txt"

# Deterministic metadata, then the containers.
find "$APPDIR" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
( cd "$WORK" && tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -cf - "$PKG" ) \
    | gzip -n -9 > "$OUT/${PKG}.tar.gz"
echo "wrote $OUT/${PKG}.tar.gz"
if [[ "$PROFILE" == signer ]]; then
    appimagetool-x86_64.AppImage --no-appstream --runtime-file "$TOOLS/runtime-x86_64" "$APPDIR" "$OUT/${PKG}.AppImage"
    echo "wrote $OUT/${PKG}.AppImage"
fi
sha256sum "$OUT/${PKG}".* | sed 's/^/   /'
