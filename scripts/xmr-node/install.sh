#!/usr/bin/env bash
# install.sh - install the c2pool-v37-xmr package from this unpacked directory.
#
#   ./install.sh --user [--prefix DIR] [--data DIR] [--systemd]
#       no root needed. Defaults: prefix ~/.local/c2pool-xmr, data ~/.c2pool-xmr.
#       --systemd also installs a user unit (~/.config/systemd/user).
#   sudo ./install.sh [--prefix DIR] [--data DIR] [--run-user NAME] [--systemd]
#       system install. Defaults: prefix /opt/c2pool-xmr, data /var/lib/c2pool-xmr,
#       run user c2pool-xmr (created as a system user if missing).
#   Other flags: --force (skip the RAM/disk checks), --no-verify (skip SHA256SUMS).
#
# It copies files into PREFIX and DATA only, writes node.env only when absent,
# and never starts, stops or changes any other service.
set -euo pipefail

PKG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=system; PREFIX=""; DATA=""; RUN_USER=c2pool-xmr; SYSTEMD=0; FORCE=0; VERIFY=1
while [ $# -gt 0 ]; do
    case "$1" in
        --user)      MODE=user; shift ;;
        --prefix)    PREFIX="$2"; shift 2 ;;
        --data)      DATA="$2"; shift 2 ;;
        --run-user)  RUN_USER="$2"; shift 2 ;;
        --systemd)   SYSTEMD=1; shift ;;
        --force)     FORCE=1; shift ;;
        --no-verify) VERIFY=0; shift ;;
        -h|--help)   sed -n 2,14p "$0"; exit 0 ;;
        *) echo "install: unknown argument $1" >&2; exit 2 ;;
    esac
done

die()  { echo "install: ERROR: $*" >&2; exit 1; }
warn() { echo "install: WARNING: $*" >&2; }
say()  { echo "install: $*"; }

if [ "$MODE" = system ] && [ "$(id -u)" -ne 0 ]; then
    die "a system install needs root. Run with --user for a per-user install."
fi
if [ "$MODE" = user ]; then
    PREFIX="${PREFIX:-$HOME/.local/c2pool-xmr}"; DATA="${DATA:-$HOME/.c2pool-xmr}"
else
    PREFIX="${PREFIX:-/opt/c2pool-xmr}"; DATA="${DATA:-/var/lib/c2pool-xmr}"
fi

# ---- checks --------------------------------------------------------------
[ "$(uname -m)" = x86_64 ] || die "this package is for x86_64, not $(uname -m)"
if [ "$VERIFY" = 1 ]; then
    (cd "$PKG" && sha256sum --quiet -c SHA256SUMS) || die "SHA256SUMS check failed"
    say "package files match SHA256SUMS"
fi
NEED="$(cat "$PKG/GLIBC_FLOOR")"
HAVE="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
[ -n "$HAVE" ] || die "cannot read the glibc version (musl is not supported)"
if [ "$(printf '%s\n%s\n' "$NEED" "$HAVE" | sort -V | head -1)" != "$NEED" ]; then
    die "glibc $HAVE is older than the $NEED this binary needs"
fi
say "glibc $HAVE (needs >= $NEED): ok"
if ! VOUT="$("$PKG/bin/c2pool-v37-xmr" --version 2>&1)"; then
    die "the binary does not start on this system: $(echo "$VOUT" | head -2 | tr '\n' ' ')
       (it needs libstdc++ from GCC 13 or newer, e.g. Ubuntu 24.04+)"
fi
say "binary starts: $(echo "$VOUT" | head -1)"
MEM_MB=$(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo)
AVAIL_MB=$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)
mkdir -p "$DATA" 2>/dev/null || die "cannot create $DATA"
DISK_MB=$(df -Pm "$DATA" | awk 'NR==2 {print $4}')
say "RAM total ${MEM_MB} MB, available ${AVAIL_MB} MB; free disk at $DATA ${DISK_MB} MB"
LOW=0
[ "$MEM_MB" -ge 4000 ]  || { warn "less than 4 GB RAM: the node needs about 1.2 GB plus page cache"; LOW=1; }
[ "$AVAIL_MB" -ge 1500 ] || { warn "less than 1.5 GB RAM available now"; LOW=1; }
[ "$DISK_MB" -ge 5000 ] || { warn "less than 5 GB free at $DATA (stagenet output set 1.1 GiB, mainnet 17.1 GiB)"; LOW=1; }
if [ "$LOW" = 1 ] && [ "$FORCE" = 0 ]; then die "resources below the minimum (use --force to install anyway)"; fi

# ---- run user (system mode only) -----------------------------------------
if [ "$MODE" = system ] && ! id "$RUN_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin "$RUN_USER"
    say "created system user $RUN_USER"
fi

# ---- files ---------------------------------------------------------------
mkdir -p "$PREFIX/bin" "$PREFIX/share"
install -m 0755 "$PKG/bin/c2pool-v37-xmr" "$PKG/bin/run-node.sh" "$PKG/bin/memguard.sh" "$PREFIX/bin/"
rm -rf "$PREFIX/share/web-static" "$PREFIX/share/doc"
cp -r "$PKG/share/web-static" "$PKG/share/doc" "$PREFIX/share/"
cp -r "$PKG/share/systemd" "$PREFIX/share/"
cp "$PKG/BUILDINFO.txt" "$PKG/GLIBC_FLOOR" "$PKG/node.env.example" "$PREFIX/share/"
if [ -e "$DATA/node.env" ]; then
    say "keeping existing $DATA/node.env (new example: $PREFIX/share/node.env.example)"
else
    install -m 0640 "$PKG/node.env.example" "$DATA/node.env"
    say "wrote $DATA/node.env: edit it before the first start"
fi
[ "$MODE" = system ] && chown -R "$RUN_USER:" "$DATA"

# ---- systemd unit (opt-in) -----------------------------------------------
UNIT_SRC="$PKG/share/systemd/c2pool-xmr.service"
render() {
    sed -e "s#@PREFIX@#$PREFIX#g" -e "s#@DATA@#$DATA#g" \
        -e "s#@USERLINE@#$1#" -e "s#@WANTEDBY@#$2#" "$UNIT_SRC"
}
put_unit() {   # never overwrite a unit that is already there
    local dst="$1"
    if [ -e "$dst" ]; then
        render "$2" "$3" > "$dst.new"
        say "kept existing $dst; the new unit is $dst.new"
    else
        render "$2" "$3" > "$dst"; say "unit: $dst"
    fi
}
if [ "$SYSTEMD" = 1 ]; then
    if [ "$MODE" = user ]; then
        U="$HOME/.config/systemd/user"; mkdir -p "$U"
        put_unit "$U/c2pool-xmr.service" "" default.target
        say "start: systemctl --user start c2pool-xmr"
    else
        put_unit /etc/systemd/system/c2pool-xmr.service "User=$RUN_USER" multi-user.target
        say "start: systemctl start c2pool-xmr"
    fi
    say "the unit is NOT enabled or started; run 'systemctl [--user] daemon-reload' first"
fi

say "installed $("$PREFIX/bin/c2pool-v37-xmr" --version | head -1)"
say "binary: $PREFIX/bin/c2pool-v37-xmr   data: $DATA"
say "next: put the output-set file in $DATA, edit $DATA/node.env, then"
say "      C2POOL_XMR_WORKDIR=$DATA $PREFIX/bin/run-node.sh $DATA/node.env"
