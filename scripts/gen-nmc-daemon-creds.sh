#!/usr/bin/env bash
# gen-nmc-daemon-creds.sh -- self-provision NMC (Namecoin) daemon RPC creds for
# the co-located regtest 2e won-block soak harness.
#
# Standing rule (operator 2026-06-19, daemon-cred-selfservice): the fleet
# generates its own daemon RPC creds -- RPCUSER fixed, RPCPASS = openssl rand --
# writes a localhost-only conf, and wires both the daemon conf and the c2pool
# config. The password is NEVER placed in any coordination card; this is [fyi],
# not [decision-needed].
#
# PER-COIN ISOLATION: NMC only. Tooling for the 2e regtest soak host -- the
# NMC aux chain_id (0x0001, nmc::coin::NMC_AUXPOW_CHAIN_ID SSOT) is the only
# coin-specific value here; zero share / PPLNS / coinbase-byte surface.
# Idempotent: refuses to clobber an existing conf unless --force is passed.
set -euo pipefail

RPCUSER="c2pool_nmc"
DATADIR="${NMC_REGTEST_DATADIR:-$HOME/.c2pool-nmc-regtest}"
DAEMON_CONF="$DATADIR/namecoin.conf"
C2POOL_CONF="${C2POOL_NMC_CONF:-$DATADIR/c2pool-nmc.conf}"
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
# NMC regtest -- localhost-only, 2e won-block soak harness. Generated; do not commit.
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
# c2pool-nmc regtest -- points the DEPLOYMENT-mode external-RPC fallback at the
# co-located regtest node (submitauxblock leg; N/A in embedded soak, where the
# won-block path is P2P-only). Generated; do not commit.
nmc_rpc_address=127.0.0.1
nmc_rpc_user=$RPCUSER
nmc_rpc_password=$RPCPASS
nmc_network=regtest
CONF
chmod 600 "$C2POOL_CONF"

echo "wrote $DAEMON_CONF and $C2POOL_CONF (mode 600, localhost-only)" >&2
echo "RPCUSER=$RPCUSER  RPCPASS=<32-byte openssl rand, in conf only, NOT echoed>" >&2
