#!/usr/bin/env bash
# dgb_g2_ratchet_staged_migration_harness.sh
# -----------------------------------------------------------------------------
# Greenlight gate G2 -- DGB RATCHET STAGED-MIGRATION test harness.
#
# Gate sequence (per integrator 2026-06-24, UID2208): G1 (oracle byte-parity
# KAT) -> G2 (this: ratchet staged-migration) -> G3a/G3b (testnet block prod).
#
# WHAT G2 PROVES
# --------------
# DGB conforms to its OWN oracle frstrtr/p2pool-dgb-scrypt (terminal share
# VERSION=35, SUCCESSOR=None); c2pool-dgb drives the 35 -> 36 ratchet while
# staying backward-compatible with the ver35 oracle during the migration
# window. This is NOT the LTC v35 transition -- do not borrow LTC's script.
#
# DUAL-POOL TESTBED (self-provisioned on the VM115 isolated scrypt net,
# 192.168.86.42 -- NOT vm-fleet, which is disabled). Both pools share the DGB
# sharechain IDENTIFIER 4B62545B1A631AFE so they peer as ONE sharechain; the
# axis under test is the share VERSION (35 vs 36), not the namespace.
#
#   POOL O (oracle-base)  : frstrtr/p2pool-dgb-scrypt (python reference),
#                           mints share ver35 / SUCCESSOR=None,
#                           donation 4104ffd0..., P2P 5024.
#   POOL V (v36 c2pool)   : c2pool-dgb, AutoRatchet VOTING->ACTIVATED->CONFIRMED.
#
# Bucket-1 isolation (operator 2026-06-17 3-bucket rule): PREFIX / IDENTIFIER
# are kept per-coin/per-instance -- this testbed is isolated from prod & other
# coins by them. diff-1 both pools. Self-service RPC creds (no secret on any
# coordination card).
#
# THE 5 CHECKS (see scripts/dgb_g2_evidence_template.md for the evidence form):
#   C1 BASELINE COHABIT   : v36 c2pool-dgb peers the ver35 oracle on one
#                           sharechain; accepts ver35 shares (backward compat).
#   C2 VOTING MINT        : c2pool-dgb in VOTING mints base_version=35 (oracle-
#                           faithful), advertises desired_version=36 (the vote);
#                           NO premature v36-format mint.
#   C3 STAGED ACCEPT GATE : (#288) the 95%-by-FLAT-COUNT desired trigger is
#                           GATED behind the 60%-BY-WORK accept
#                           (get_desired_version_weights idx->work). Mint cannot
#                           outrun accept -- flat 95% does NOT activate until
#                           work>=60%. This is the "staged" property.
#   C4 RATCHET + PERSIST  : on 60%-by-work + 95% sustained 2*CHAIN_LENGTH,
#                           VOTING->ACTIVATED->CONFIRMED; v36-format mint begins;
#                           ver35 oracle still accepts in-window; CONFIRMED
#                           survives c2pool-dgb restart (JSON state).
#   C5 ALGO POSTURE       : Scrypt is the ONLY validated/work-weighted algo;
#                           SHA-256d / Skein / Qubit / Odocrypt legs are
#                           N/A-by-continuity (V36 scope) -- recorded as N/A,
#                           NOT as skipped checks.
#
# RIG DEPENDENCY (GATED): C2/C3/C4 work-weighted evidence needs real hashrate to
# move desired_version_weights. The only valid scrypt set is the 3x R1-LTC rigs,
# currently tied up in the LIVE LTC crossing-soak (owner ltc-doge-production-
# steward). Per integrator: author first, then request the rig window -- do NOT
# pull rigs off a live soak. Until rigs are brokered, this harness:
#   * provisions + validates the dual-pool substrate end-to-end (C1 reachable),
#   * drives C2/C3/C4 in SIMULATED-VOTE mode (--sim-votes) using the AutoRatchet
#     KAT seam so the staged-gate LOGIC is proven now,
#   * and emits the evidence template with the rig-bound rows marked
#     [GATED: rigs] until the live run.
#
# PER-COIN ISOLATION: DGB only. Touches no other coin tree. Localhost/VM115 net.
set -euo pipefail

# ---- binaries (self-provision; no operator install) -------------------------
DGB_DAEMON="${DGB_DAEMON:-digibyted}"        # DigiByte Core (NOT vendored)
DGB_CLI="${DGB_CLI:-digibyte-cli}"
C2POOL_DGB="${C2POOL_DGB:-c2pool-dgb}"        # v36 pool binary
ORACLE_PY="${ORACLE_PY:-$HOME/Github/p2pool-dgb-scrypt/run_p2pool.py}"  # ver35 oracle

# ---- isolated net params (VM115 / 192.168.86.42) ----------------------------
NET="${DGB_NET:-testnet}"                      # isolated scrypt testnet, diff-1
BIND_ADDR="${DGB_BIND:-0.0.0.0}"
SHARECHAIN_ID="4b62545b1a631afe"               # bucket-1 IDENTIFIER (peer both)
DONATION="${DGB_DONATION:-4104ffd0}"           # oracle donation tag (prefix)

# pool O (oracle ver35)
O_P2P=${O_P2P:-5024}                           # oracle sharechain P2P
O_STRATUM=${O_STRATUM:-9327}
# pool V (v36 c2pool-dgb)
V_P2P=${V_P2P:-5025}
V_STRATUM=${V_STRATUM:-9328}

# parent daemon (shared)
RPCPORT=${DGB_RPCPORT:-14022}
P2PPORT=${DGB_P2PPORT:-14023}
DATADIR="${DGB_DATADIR:-$HOME/.digibyte-g2}"
RATCHET_STATE="${DGB_RATCHET_STATE:-$HOME/.c2pool-dgb-g2/ratchet.json}"

SIM_VOTES=0
for a in "$@"; do case "$a" in --sim-votes) SIM_VOTES=1;; esac; done

log()  { echo "[dgb-g2 $(printf "%(%H:%M:%S)T")] $*" >&2; }
die()  { echo "[dgb-g2 FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing binary: $1 (self-provision; sudo is operator-only)"; }
gated(){ echo "[dgb-g2 GATED: rigs] $*" >&2; }

cli() { "$DGB_CLI" -"$NET" -datadir="$DATADIR" -rpcport=$RPCPORT "$@"; }

# ---- self-service RPC creds (never written to a coordination card) ----------
gen_creds() {
  mkdir -p "$DATADIR"
  if [ ! -f "$DATADIR/.rpccreds" ]; then
    local u p
    u="dgbg2_$(printf "%(%s)T" -1 | tail -c 6)"
    p="$(head -c18 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)"
    printf 'rpcuser=%s\nrpcpassword=%s\n' "$u" "$p" > "$DATADIR/.rpccreds"
    chmod 600 "$DATADIR/.rpccreds"
    log "generated isolated RPC creds at $DATADIR/.rpccreds (600)"
  fi
}

# ---- substrate: parent daemon on isolated diff-1 net ------------------------
start_daemon() {
  need "$DGB_DAEMON"; need "$DGB_CLI"
  gen_creds
  cat "$DATADIR/.rpccreds" > "$DATADIR/digibyte.conf"
  cat >> "$DATADIR/digibyte.conf" <<CONF
$NET=1
server=1
listen=1
[${NET}]
rpcbind=127.0.0.1
rpcport=$RPCPORT
port=$P2PPORT
CONF
  "$DGB_DAEMON" -datadir="$DATADIR" -daemon
  for i in $(seq 1 30); do cli getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
  cli getblockchaininfo >/dev/null 2>&1 || die "digibyted did not come up on $NET"
  log "parent digibyted up: $(cli getblockchaininfo | grep -E 'chain|blocks' | tr -d ' ,\"')"
}

# ---- pools -------------------------------------------------------------------
start_pool_oracle() {
  [ -f "$ORACLE_PY" ] || { gated "oracle pool $ORACLE_PY not staged -- C1 cohabit deferred"; return 0; }
  log "starting POOL O (oracle ver35) p2p=$O_P2P stratum=$O_STRATUM id=$SHARECHAIN_ID"
  # oracle is the conformance reference: mints ver35 / SUCCESSOR=None.
  nohup python3 "$ORACLE_PY" --net dgb-scrypt-testnet \
        --p2pool-port $O_P2P --worker-port $O_STRATUM \
        --bitcoind-rpc-port $RPCPORT --give-author 0 \
        >"$HOME/.c2pool-dgb-g2/oracle.log" 2>&1 &
  echo $! > "$HOME/.c2pool-dgb-g2/oracle.pid"
}

start_pool_v36() {
  need "$C2POOL_DGB"
  mkdir -p "$(dirname "$RATCHET_STATE")"
  log "starting POOL V (v36 c2pool-dgb) p2p=$V_P2P stratum=$V_STRATUM ratchet-state=$RATCHET_STATE"
  # v36 c2pool-dgb peers POOL O on the shared sharechain identifier; AutoRatchet
  # base_version=35 (oracle-faithful VOTING mint), target=36.
  nohup "$C2POOL_DGB" --run --"$NET" \
        --coin-rpc 127.0.0.1:$RPCPORT --coin-rpc-auth "$DATADIR/digibyte.conf" \
        --sharechain-port $V_P2P --stratum "$BIND_ADDR:$V_STRATUM" \
        --addnode 127.0.0.1:$O_P2P \
        --ratchet-state "$RATCHET_STATE" \
        >"$HOME/.c2pool-dgb-g2/v36.log" 2>&1 &
  echo $! > "$HOME/.c2pool-dgb-g2/v36.pid"
}

# ---- the 5 checks ------------------------------------------------------------
# SIM mode (--sim-votes) proves the staged-gate LOGIC now via existing AutoRatchet
# KATs (rig-independent). LIVE rows (real work-weighted hashrate) stay GATED until
# the R1-LTC scrypt window is brokered off the LTC soak. Exact ctest names below.
check_c1_cohabit() {
  log "C1 BASELINE COHABIT: v36 peers ver35 oracle on id=$SHARECHAIN_ID, accepts ver35 shares"
  # v36 c2pool-dgb establishes a sharechain peer to POOL O and ingests a ver35
  # share without rejecting it (backward-compat in-window). No sharechain split.
  # Live-peer assertion runs against the v36 stats endpoint once both pools are up
  # on the rig-fed net; substrate provisioning (provision subcmd) is reachable now.
  gated "C1 live-peer assertion needs both pools up on the rig-fed net"
}

check_c2_voting_mint() {
  log "C2 VOTING MINT: base_version=35 minted, desired_version=36 advertised, no premature v36-format"
  if [ "$SIM_VOTES" -eq 1 ]; then
    log "  [sim] VOTING mints ver35 / votes 36 -- DGB_share_test.AutoRatchet* KATs"
    ctest --test-dir build_dgb -R 'AutoRatchetBootstrapMintsBaselineWhileVoting|AutoRatchetWireBootstrapMints35Votes36|AutoRatchetBaseVersionParameterized' \
      --output-on-failure || die "C2 sim (VOTING base35/votes36 KAT) failed"
  else
    gated "C2 live work-weighted vote needs rigs"
  fi
}

check_c3_staged_accept_gate() {
  log "C3 STAGED ACCEPT GATE (#288): flat-95% desired is GATED behind 60%-by-WORK accept"
  if [ "$SIM_VOTES" -eq 1 ]; then
    log "  [sim] tail-guard: flat 95% must NOT activate below 60%-by-work -- AutoRatchetTailGuard.* KATs"
    ctest --test-dir build_dgb -R 'AutoRatchetTailGuard' \
      --output-on-failure || die "C3 sim (#288 tail-guard) failed -- mint outran accept"
  else
    gated "C3 live mint-cannot-outrun-accept needs rigs to move work weights"
  fi
}

check_c4_ratchet_persist() {
  log "C4 RATCHET + PERSIST: VOTING->ACTIVATED->CONFIRMED on 60%-work+95%/2*CL; CONFIRMED survives restart"
  if [ "$SIM_VOTES" -eq 1 ]; then
    log "  [sim] state-machine + restart persistence -- DGB_share_test.AutoRatchet* KATs"
    ctest --test-dir build_dgb -R 'AutoRatchetStatePersistsAcrossRestart|AutoRatchetThresholdsMatchCanonical|AutoRatchetWireBaselineConstantsFromOracle' \
      --output-on-failure || die "C4 sim (state-machine/restart KAT) failed"
  else
    gated "C4 live CONFIRMED requires sustained 2*CHAIN_LENGTH of rig-fed 95%/60% shares"
  fi
}

check_c5_algo_posture() {
  log "C5 ALGO POSTURE: Scrypt-only work-weighting; SHA256d/Skein/Qubit/Odocrypt = N/A-by-continuity"
  # NOT a skipped check: V36 scope validates Scrypt only; the other 4 algos are
  # asserted N/A-by-continuity (DgbAlgoSelect.AllKnownNonScryptAlgosAreContinuity).
  ctest --test-dir build_dgb -R 'DgbAlgoSelect|DgbScryptPowKAT' \
    --output-on-failure || die "C5 (scrypt-only work-weighting) failed"
  log "  Scrypt validated + work-weighted; other 4 algos N/A-by-continuity (V36 design, V37 defers)"
}

# ---- driver ------------------------------------------------------------------
main() {
  mkdir -p "$HOME/.c2pool-dgb-g2"
  case "${1:-run}" in
    provision)  start_daemon; start_pool_oracle; start_pool_v36 ;;
    checks)
      check_c1_cohabit
      check_c2_voting_mint
      check_c3_staged_accept_gate
      check_c4_ratchet_persist
      check_c5_algo_posture
      log "G2 check pass complete (sim=$SIM_VOTES). Fill scripts/dgb_g2_evidence_template.md."
      ;;
    run|*)
      log "G2 harness: provision dual-pool substrate, then run 5 checks."
      log "  rig-bound rows GATED until ltc-doge frees the R1-LTC scrypt window."
      start_daemon || true
      start_pool_oracle || true
      start_pool_v36 || true
      check_c1_cohabit
      check_c2_voting_mint
      check_c3_staged_accept_gate
      check_c4_ratchet_persist
      check_c5_algo_posture
      ;;
  esac
}
main "$@"
