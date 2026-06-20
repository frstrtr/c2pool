#!/usr/bin/env bash
# nmc_regtest_aux_soak.sh -- NMC PE 2e won-block soak harness (regtest substrate).
#
# Stands up the deterministic, peer-dependency-free substrate the NMC embedded
# merge-mined won-block soak runs against. Per integrator (2026-06-20, UID1601):
# DO NOT soak the merged-aux path against the synced mainnet node (real-block /
# real-funds risk). Two legs, both on regtest:
#
#   LEG 1 (DEFERRED -- EXTERNAL-DAEMON DEPLOYMENT, NOT YET PROVEN ON THE WIRE) -- in
#                            broadcaster relies SOLELY on P2P relay; submit_aux_block()
#                            (aux_chain_embedded.hpp:153) is INTENTIONALLY inert in-process,
#                            mirroring the doge embedded path (integrator design call,
#                            2026-06-20). The createauxblock surface is still probed below
#                            as a namecoind substrate sanity check, but NO submitauxblock
#                            won-block is ever driven from the embedded soak. The dual-path
#                            submitblock fallback stays a DEPLOYMENT-level gate (wired +
#                            verified before NMC runs vs a real EXTERNAL namecoind) -- out
#                            of scope for this embedded PE-2e soak, kept explicit here so
#                            we do not lose it.
#   LEG 2 (P2P PRIMARY)   -- the live embedded won-block route. Stand up a SECOND
#                            namecoind -regtest, addnode the pair, so on_block_found
#                            P2P broadcast has a real peer to land on
#                            (aux_chain_embedded.hpp submit_block ->
#                            CoinBroadcaster::submit_block_raw).
#
# This script provisions + validates the SUBSTRATE (nodes, creds, aux-RPC surface,
# peering). PE-2d has LANDED (#247/#253/#254 on master), so submit_block() is out of
# stub: the P2P won-block path (LEG 2) is the live embedded route -- this soak is
# UN-GATED from 2d. It fires end-to-end once the in-loop c2pool embedded regtest
# process drives node A (process standup = next slice, per integrator design call
# 2026-06-20). LEG 1 (submitauxblock) is DEFERRED to the external-daemon deployment
# soak (the mainnet .140 path), NOT exercised in embedded regtest -- it still requires
# its own on-the-wire verification and must NOT be read as "covered" by this soak.
#
# PER-COIN ISOLATION: NMC only. Localhost-only. Generated creds via
# gen-nmc-daemon-creds.sh; no secret ever touches a coordination card.
set -euo pipefail

# NMC_AUXPOW_CHAIN_ID is DERIVED from the aux_id.hpp SSOT at runtime (see below),
# never a hand-typed literal -- the one place a scripts-only slice can drift from consensus.
CLI_BIN="${NMC_CLI:-namecoin-cli}"
DAEMON_BIN="${NMC_DAEMON:-namecoind}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DATADIR_A="${NMC_REGTEST_DATADIR:-$HOME/.c2pool-nmc-regtest}"
DATADIR_B="${DATADIR_A}-peer"
RPCPORT_A=18443
RPCPORT_B=18453
P2PPORT_A=18444
P2PPORT_B=18454
PAYOUT_LABEL="c2pool-soak"

log()  { echo "[2e-soak $(printf "%(%H:%M:%S)T")] $*" >&2; }
die()  { echo "[2e-soak FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing binary: $1 (set NMC_DAEMON/NMC_CLI or install Namecoin Core)"; }

cli_a() { "$CLI_BIN" -regtest -datadir="$DATADIR_A" -rpcport=$RPCPORT_A "$@"; }
cli_b() { "$CLI_BIN" -regtest -datadir="$DATADIR_B" -rpcport=$RPCPORT_B "$@"; }

cleanup() {
  cli_a stop  >/dev/null 2>&1 || true
  cli_b stop  >/dev/null 2>&1 || true
}
trap cleanup EXIT

need "$DAEMON_BIN"; need "$CLI_BIN"; need openssl

# --- chain_id SSOT bind: derive from src/impl/nmc/coin/aux_id.hpp at runtime so this
#     scripts-only slice can NEVER drift from consensus (integrator UID1607). The header
#     ships with #247; its absence is also a clean "#247 not in-tree yet" pre-flight.
AUX_ID_HDR="$SCRIPT_DIR/../src/impl/nmc/coin/aux_id.hpp"
[ -f "$AUX_ID_HDR" ] || die "aux_id.hpp SSOT not found at $AUX_ID_HDR (#247 must be merged into the tree)"
_RAW_CHAIN_ID="$(grep -E 'NMC_AUXPOW_CHAIN_ID[[:space:]]*=' "$AUX_ID_HDR" | sed -E 's/.*=[[:space:]]*(0x[0-9A-Fa-f]+|[0-9]+).*/\1/' | head -1 || true)"
[ -n "$_RAW_CHAIN_ID" ] || die "could not parse NMC_AUXPOW_CHAIN_ID from $AUX_ID_HDR (SSOT format changed)"
NMC_AUXPOW_CHAIN_ID=$(( _RAW_CHAIN_ID ))   # normalize 0x0001 -> 1 for the decimal RPC compare
log "chain_id SSOT bound from aux_id.hpp: raw=$_RAW_CHAIN_ID normalized=$NMC_AUXPOW_CHAIN_ID"

# --- provision creds (idempotent, self-service) --------------------------------
NMC_REGTEST_DATADIR="$DATADIR_A" bash "$SCRIPT_DIR/gen-nmc-daemon-creds.sh" || true
mkdir -p "$DATADIR_B"; chmod 700 "$DATADIR_B"
cp -n "$DATADIR_A/namecoin.conf" "$DATADIR_B/namecoin.conf" 2>/dev/null || true

wait_rpc() { local n=0; until "$@" getblockcount >/dev/null 2>&1; do n=$((n+1)); [ $n -gt 60 ] && die "rpc never came up: $*"; sleep 0.5; done; }

# --- LEG 1: single-node aux-RPC surface ---------------------------------------
log "LEG 1: starting node A (regtest, RPC $RPCPORT_A)"
"$DAEMON_BIN" -regtest -datadir="$DATADIR_A" -rpcport=$RPCPORT_A -port=$P2PPORT_A -daemon >/dev/null
wait_rpc cli_a

ADDR_A="$(cli_a getnewaddress "$PAYOUT_LABEL")"
log "mining 101 maturity blocks to $ADDR_A"
cli_a generatetoaddress 101 "$ADDR_A" >/dev/null

log "createauxblock -> assert chain_id == NMC SSOT ($NMC_AUXPOW_CHAIN_ID)"
AUX_JSON="$(cli_a createauxblock "$ADDR_A")"
CHAINID="$(echo "$AUX_JSON" | grep -o "\"chainid\"[^,]*" | grep -o "[0-9]*$")"
[ "$CHAINID" = "$NMC_AUXPOW_CHAIN_ID" ] || die "createauxblock chainid=$CHAINID, expected $NMC_AUXPOW_CHAIN_ID (aux_id.hpp SSOT mismatch)"
echo "$AUX_JSON" | grep -q "\"hash\""   || die "createauxblock template missing target hash"
echo "$AUX_JSON" | grep -q "\"target\"" || die "createauxblock template missing target bits"
log "LEG 1 OK: aux-RPC surface live, template well-formed, chain_id conforms to SSOT"

# [DEFERRED -- NOT YET PROVEN] submitauxblock won-block submit is deferred to the
#   Embedded relies SOLELY on P2P relay (LEG 2); submit_aux_block() is intentionally
#   inert in-process (aux_chain_embedded.hpp:153, mirrors doge). This leg is exercised
#   ONLY in external-daemon deployment mode, where the dual-path submitblock fallback
#   is separately wired + verified -- it is NEVER driven from this embedded soak.

# --- LEG 2: paired-node P2P substrate -----------------------------------------
log "LEG 2: starting node B (regtest, RPC $RPCPORT_B) and peering to A"
"$DAEMON_BIN" -regtest -datadir="$DATADIR_B" -rpcport=$RPCPORT_B -port=$P2PPORT_B \
              -connect=127.0.0.1:$P2PPORT_A -daemon >/dev/null
wait_rpc cli_b

PEERS=0
for _ in $(seq 1 40); do
  PEERS="$(cli_a getconnectioncount)"
  [ "${PEERS:-0}" -ge 1 ] && break
  sleep 0.5
done
[ "${PEERS:-0}" -ge 1 ] || die "node A has 0 peers after addnode -- P2P substrate not established"
log "LEG 2 OK: paired-node P2P substrate up (node A peers=$PEERS); broadcast has a peer to land on"

# [PE-2e LIVE PATH -- UN-GATED] real P2P won-block relay via on_block_found:
#   PE-2d has landed (submit_block() out of stub, #247/#253/#254 on master 294fb30e3),
#   so the embedded CoinBroadcaster submit_block() relays the frozen aux block over
#   this peer link; assert node B receives it (getblockcount advances). Fires once the
#   in-loop c2pool embedded regtest process drives node A (next slice: stand up the
#   embedded process per integrator design call 2026-06-20).

log "SUBSTRATE READY: P2P substrate provisioned + validated. LEG 1 (submitauxblock)"
log "is DEFERRED to external-daemon deployment (mainnet .140 path), not yet wire-proven;"
log "landed) and fires once the in-loop c2pool embedded regtest process drives node A."
