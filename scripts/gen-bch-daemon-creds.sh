#!/usr/bin/env bash
# gen-bch-daemon-creds.sh -- self-provision BCH daemon RPC creds for the
# co-located regtest leg-C broadcaster harness.
#
# Standing rule (operator 2026-06-19): the fleet generates its own daemon RPC
# creds -- RPCUSER fixed, RPCPASS = openssl rand -- writes a localhost-only conf,
# and wires both the daemon conf and the c2pool config. The password is NEVER
# placed in any coordination card; this is [fyi], not [decision-needed].
#
# PER-COIN ISOLATION: BCH only. Tooling for the leg-C regtest host -- zero
# p2pool-merged-v36 surface (no share / PPLNS / coinbase bytes). Idempotent:
# refuses to clobber an existing conf unless --force is passed.
set -euo pipefail

RPCUSER="c2pool_bch"
DATADIR="${BCH_REGTEST_DATADIR:-$HOME/.c2pool-bch-regtest}"
DAEMON_CONF="$DATADIR/bitcoin.conf"
C2POOL_CONF="${C2POOL_BCH_CONF:-$DATADIR/c2pool-bch.conf}"
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

mkdir -p "$DATADIR"
chmod 700 "$DATADIR"

if [ -f "$DAEMON_CONF" ] && [ "$FORCE" -ne 1 ]; then
  echo "conf exists: $DAEMON_CONF (pass --force to regenerate); leaving creds intact" >&2
  exit 0
fi

RPCPASS="$(openssl rand -hex 32)"

umask 077
cat > "$DAEMON_CONF" <<CONF
# BCH regtest -- localhost-only, leg-C broadcaster harness. Generated; do not commit.
regtest=1
server=1
listen=1
[regtest]
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
bind=127.0.0.1
CONF
chmod 600 "$DAEMON_CONF"

cat > "$C2POOL_CONF" <<CONF
# c2pool-bch regtest -- points the embedded-daemon external-RPC fallback at the
# co-located regtest node. Generated; do not commit.
bch_rpc_address=127.0.0.1
bch_rpc_user=$RPCUSER
bch_rpc_password=$RPCPASS
bch_network=regtest
CONF
chmod 600 "$C2POOL_CONF"

echo "wrote $DAEMON_CONF and $C2POOL_CONF (mode 600, localhost-only)" >&2
echo "RPCUSER=$RPCUSER  RPCPASS=<32-byte openssl rand, in conf only, NOT echoed>" >&2
