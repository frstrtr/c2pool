#!/usr/bin/env bash
# ltc_g2_crossing_staged_migration_harness.sh
# -----------------------------------------------------------------------------
# Greenlight gate G2 -- LTC (+DOGE aux) V35->V36 CROSSING staged-migration
# harness. This is THE contabo LTC-pool prod-cutover gate (operator 2026-06-17
# re-scope): the staged v35->v36 miner-reappointment soak. DOGE rides LTC as
# merged-mining aux and is validated coupled, not separately.
#
# Gate sequence: G1 (differential byte-parity KAT) -> G2 (this: three-tier
# crossing) -> G3a/G3b (regtest/testnet block production).
#
# WHY "RE-CUT" (integrator 2026-07-12, UID2071): stage the harness with the
# 3301 accept-floor + the PR#95 8-byte sharechain identifier + --fresh-ratchet
# so it LANDS the moment the swarm (VM119/120/121) has a target. The build must
# not be the thing we wait on when the operator start-tap fires.
#
# THREE-TIER WIRE-COMPAT (operator 2026-07-03): the v35-phase swarm runs THREE
# node tiers on ONE sharechain (identifier below), the axis under test being the
# share VERSION and the wire bytes, NOT the namespace:
#
#   T-A  jtoomim v35-only     : OLD raw-tx litecoin p2pool. Accepts OUR v35
#                               shares BYTE-FOR-BYTE and SEES the v36 vote via
#                               legacy desired_version / get_desired_version_
#                               counts -- WITHOUT ever gaining v36 features.
#   T-B  p2pool-merged-v36    : our python reference (frstrtr/p2pool-merged-v36,
#        (python)               the v36 DESTINATION shape); the parity oracle.
#   T-C  c2pool-ltc (C++)     : AutoRatchet VOTING->ACTIVATED->CONFIRMED; embedded
#                               LTC + FULLY-embedded DOGE aux (no external
#                               dogecoind on the crossing path).
#
# HARD invariant: ZERO v36-byte leak into v35 shares. addr-autoconvert and
# merged-rewards are GATED on v36-active; while VOTING, T-C mints a v35-faithful
# share T-A accepts byte-for-byte, and only ADVERTISES desired_version=36.
#
# STAGING (operator 2026-06-18): forward natural-fill -> ratchet cross -> reverse
#   FWD   natural-fill : T-A/T-B mint v35, T-C VOTING+v35-faithful; chain fills.
#   CROSS ratchet      : integrator repoints the R1-LTC cgminers (.37/.38/.39,
#                        ALL 3 on the flip per operator) v35-node -> v36-node one
#                        by one; work-weight crosses 60%, count crosses 95%,
#                        sustained 2*CHAIN_LENGTH -> CONFIRMED.
#   REV   reverse      : pre-CONFIRMED revert posture (drop below 50% =
#                        DEACTIVATION_THRESHOLD -> ACTIVATED->VOTING) is exercised
#                        so a stalled crossing rolls back cleanly, not wedges.
#
# BUCKET-1 ISOLATION (operator 2026-06-17 3-bucket rule): PREFIX / IDENTIFIER are
# the per-coin/per-instance isolation boundary -- KEPT, never "standardized".
# This harness pins the LTC identifier explicitly; a private crossing swarm may
# override it (--identifier) to isolate from live prod while keeping the SAME
# version-axis semantics. Self-service RPC creds; no secret on any card.
#
# NATURAL-VOTE HARD GATE (memory contabo-cutover-natural-vote-hardgate): a GREEN
# crossing here authorises DEPLOY of the v36-capable build to contabo ONLY.
# v36_active stays false/VOTING until the REAL network crosses 95% naturally.
# This harness NEVER force-activates and NEVER puts dev rigs on the prod vote.
#
# PER-COIN ISOLATION: LTC (+DOGE aux) only. Touches no other coin tree.
set -euo pipefail

# ---- binaries (self-provision; sudo is operator-only) -----------------------
LTC_DAEMON="${LTC_DAEMON:-litecoind}"          # Litecoin Core (RPC fallback; embedded is primary)
LTC_CLI="${LTC_CLI:-litecoin-cli}"
C2POOL_LTC="${C2POOL_LTC:-c2pool-ltc}"         # T-C: v36 C++ pool, DOGE aux embedded
ORACLE_MERGED_PY="${ORACLE_MERGED_PY:-$HOME/Github/p2pool-merged-v36/run_p2pool.py}"  # T-B
ORACLE_JT_PY="${ORACLE_JT_PY:-}"               # T-A: LTC jtoomim v35-only p2pool (NOT staged; see gate)

# ---- sharechain identity: PR#95 8-BYTE id (bucket-1 isolation primitive) -----
# LTC mainnet (src/impl/ltc/params.hpp:79-80): id e037d5b8c6923410 / prefix 7208c1a53ef629b0
# LTC testnet (params.hpp:81-82):              id cca5e24ec6408b1e / prefix ad9614f6466a39cf
NET="${LTC_NET:-mainnet}"                       # crossing exercises the real prod-path semantics
SHARECHAIN_ID="${LTC_SHARECHAIN_ID:-e037d5b8c6923410}"   # 8-byte; --identifier overrides for private swarm
SHARECHAIN_PREFIX="${LTC_SHARECHAIN_PREFIX:-7208c1a53ef629b0}"

# ---- protocol floor: 3301 accept-floor (params.hpp:65) ----------------------
# minimum_protocol_version=3301 accepts v35 (3502) peers so T-A/T-B and T-C peer
# across the crossing window; advertised 3600 announces v36 capability (the vote).
MIN_PROTO="${LTC_MIN_PROTO:-3301}"
ADV_PROTO="${LTC_ADV_PROTO:-3600}"

# node/pool ports -- T-A v35-only, T-B merged-v36 python, T-C c2pool-ltc
A_P2P=${A_P2P:-9346};  A_STRATUM=${A_STRATUM:-9327}   # jtoomim v35-only
B_P2P=${B_P2P:-9348};  B_STRATUM=${B_STRATUM:-9328}   # merged-v36 python
C_P2P=${C_P2P:-9350};  C_STRATUM=${C_STRATUM:-19327}  # c2pool-ltc (embedded DOGE aux)

# parent daemon (RPC fallback; embedded primary -- never removed)
RPCPORT=${LTC_RPCPORT:-19332}
P2PPORT=${LTC_P2PPORT:-19333}
DATADIR="${LTC_DATADIR:-$HOME/.litecoin-g2}"
RATCHET_STATE="${LTC_RATCHET_STATE:-$HOME/.c2pool-ltc-g2/ratchet.json}"

# ---- flags ------------------------------------------------------------------
SIM_VOTES=0; FRESH_RATCHET=0
for a in "$@"; do case "$a" in
  --sim-votes)     SIM_VOTES=1;;
  --fresh-ratchet) FRESH_RATCHET=1;;   # wipe ratchet state for a clean crossing run
esac; done

log()  { echo "[ltc-g2 $(printf "%(%H:%M:%S)T")] $*" >&2; }
die()  { echo "[ltc-g2 FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing binary: $1 (self-provision; sudo is operator-only)"; }
gated(){ echo "[ltc-g2 GATED: $1] ${*:2}" >&2; }

cli() { "$LTC_CLI" -datadir="$DATADIR" -rpcport=$RPCPORT "$@"; }

# ---- self-service RPC creds (never written to a coordination card) ----------
gen_creds() {
  mkdir -p "$DATADIR"
  if [ ! -f "$DATADIR/.rpccreds" ]; then
    local u p
    u="ltcg2_$(printf "%(%s)T" -1 | tail -c 6)"
    p="$(head -c18 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)"
    printf 'rpcuser=%s\nrpcpassword=%s\n' "$u" "$p" > "$DATADIR/.rpccreds"
    chmod 600 "$DATADIR/.rpccreds"
    log "generated isolated RPC creds at $DATADIR/.rpccreds (600)"
  fi
}

fresh_ratchet() {
  [ "$FRESH_RATCHET" -eq 1 ] || return 0
  mkdir -p "$(dirname "$RATCHET_STATE")"
  if [ -f "$RATCHET_STATE" ]; then
    mv -f "$RATCHET_STATE" "$RATCHET_STATE.pre-$(printf "%(%s)T" -1)"   # preserve, never destroy history
    log "--fresh-ratchet: archived prior ratchet state; T-C starts VOTING from bootstrap"
  else
    log "--fresh-ratchet: no prior state; T-C starts VOTING from bootstrap"
  fi
}

# ---- substrate: parent litecoind (RPC fallback path) ------------------------
start_daemon() {
  need "$LTC_DAEMON"; need "$LTC_CLI"
  gen_creds
  cat "$DATADIR/.rpccreds" > "$DATADIR/litecoin.conf"
  cat >> "$DATADIR/litecoin.conf" <<CONF
server=1
listen=1
rpcbind=127.0.0.1
rpcport=$RPCPORT
port=$P2PPORT
CONF
  "$LTC_DAEMON" -datadir="$DATADIR" -daemon
  for i in $(seq 1 30); do cli getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
  cli getblockchaininfo >/dev/null 2>&1 || die "litecoind did not come up"
  log "parent litecoind up: $(cli getblockchaininfo | grep -E 'chain|blocks' | tr -d ' ,\"')"
}

# ---- the three tiers ---------------------------------------------------------
start_tier_a_jtoomim() {   # v35-only raw-tx oracle
  if [ -z "$ORACLE_JT_PY" ] || [ ! -f "$ORACLE_JT_PY" ]; then
    gated ltc-jtoomim-checkout "T-A (jtoomim v35-only litecoin p2pool) not staged on workstation \
(only p2pool-btc-jtoomim exists) -- C1 byte-for-byte + C2 vote-visibility against the v35-ONLY tier \
DEFERRED until the LTC jtoomim checkout is provisioned. Set ORACLE_JT_PY to arm."
    return 0
  fi
  log "starting T-A (jtoomim v35-only) p2p=$A_P2P stratum=$A_STRATUM id=$SHARECHAIN_ID"
  nohup python3 "$ORACLE_JT_PY" --net litecoin \
        --p2pool-port $A_P2P --worker-port $A_STRATUM \
        --bitcoind-rpc-port $RPCPORT --give-author 0 \
        >"$HOME/.c2pool-ltc-g2/tierA-jtoomim.log" 2>&1 &
  echo $! > "$HOME/.c2pool-ltc-g2/tierA.pid"
}

start_tier_b_merged() {    # merged-v36 python (the v36 DESTINATION / parity oracle)
  [ -f "$ORACLE_MERGED_PY" ] || { gated merged-oracle "T-B $ORACLE_MERGED_PY not staged"; return 0; }
  log "starting T-B (p2pool-merged-v36 python) p2p=$B_P2P stratum=$B_STRATUM id=$SHARECHAIN_ID"
  nohup python3 "$ORACLE_MERGED_PY" --net litecoin \
        --p2pool-port $B_P2P --worker-port $B_STRATUM \
        --bitcoind-rpc-port $RPCPORT --give-author 0 \
        >"$HOME/.c2pool-ltc-g2/tierB-merged.log" 2>&1 &
  echo $! > "$HOME/.c2pool-ltc-g2/tierB.pid"
}

start_tier_c_c2pool() {    # c2pool-ltc C++ (AutoRatchet; DOGE aux embedded)
  need "$C2POOL_LTC"
  fresh_ratchet
  mkdir -p "$(dirname "$RATCHET_STATE")"
  log "starting T-C (c2pool-ltc) p2p=$C_P2P stratum=$C_STRATUM min-proto=$MIN_PROTO adv=$ADV_PROTO"
  # Peers T-A/T-B on the shared 8-byte identifier; VOTING mints v35-faithful,
  # advertises desired_version=36. DOGE aux is embedded (merged-mining), coupled.
  nohup "$C2POOL_LTC" --run --"$NET" \
        --coin-rpc 127.0.0.1:$RPCPORT --coin-rpc-auth "$DATADIR/litecoin.conf" \
        --identifier "$SHARECHAIN_ID" --prefix "$SHARECHAIN_PREFIX" \
        --sharechain-port $C_P2P --stratum "0.0.0.0:$C_STRATUM" \
        --addnode 127.0.0.1:$A_P2P --addnode 127.0.0.1:$B_P2P \
        --ratchet-state "$RATCHET_STATE" \
        >"$HOME/.c2pool-ltc-g2/tierC-c2pool.log" 2>&1 &
  echo $! > "$HOME/.c2pool-ltc-g2/tierC.pid"
}

# ---- the 5 checks ------------------------------------------------------------
# SIM mode (--sim-votes) proves the staged-gate + vote-visibility LOGIC now,
# rig-independent, via the LTC AutoRatchet KATs. LIVE rows (real work-weighted
# R1-LTC hashrate .37/.38/.39) stay GATED until the crossing start-tap fires and
# the rigs are freed onto the v36 tier.
#
# !! DEPENDENCY GAP (found 2026-07-12): the LTC test target `share_test`
# (src/impl/ltc/test/CMakeLists.txt) has NO AutoRatchet sim KATs, though DGB and
# BTC do (src/impl/{dgb,btc}/test/auto_ratchet_sim_test.cpp,
# auto_ratchet_tail_guard_test.cpp, desired_version_tally_test.cpp) -- and those
# port headers state the state machine is "identical shape to ltc::AutoRatchet".
# LTC being the REFERENCE yet lacking the KATs is a coverage inversion. Until the
# LTC ports land, the C2/C3/C4 sim rows are [GATED: ltc-ratchet-kats]. Authoring
# src/impl/ltc/test/auto_ratchet_{sim,tail_guard,desired_version_tally}_test.cpp
# (mirroring dgb, base_version=target-1 not the DGB explicit-35, single Scrypt
# algo so no multi-algo C5 leg) is the immediate next milestone that arms sim.
LTC_RATCHET_TESTDIR="${LTC_RATCHET_TESTDIR:-build_ltc}"

check_c1_threetier_cohabit() {
  log "C1 THREE-TIER COHABIT: T-A/T-B/T-C peer on ONE sharechain id=$SHARECHAIN_ID; T-C accepts v35 byte-for-byte"
  gated rigs "C1 live-peer + no-split assertion needs all three tiers up on the crossing net"
}

check_c2_vote_visibility() {
  log "C2 VOTE VISIBILITY: T-A(v35-only) SEES desired_version=36 via legacy get_desired_version_counts; ZERO v36-byte leak into v35 shares"
  if [ "$SIM_VOTES" -eq 1 ]; then
    if ctest --test-dir "$LTC_RATCHET_TESTDIR" -N -R 'LTC_AutoRatchetSim|LTC_DesiredVersionTally' 2>/dev/null | grep -q 'Test #'; then
      ctest --test-dir "$LTC_RATCHET_TESTDIR" -R 'LTC_AutoRatchetSim|LTC_DesiredVersionTally' \
        --output-on-failure || die "C2 sim (vote-visibility / VOTING mints v35-faithful) failed"
    else
      gated ltc-ratchet-kats "C2 sim needs LTC_AutoRatchetSim + LTC_DesiredVersionTally KATs (not yet authored; port from dgb)"
    fi
  else
    gated rigs "C2 live vote-visibility needs the v35-only tier fed real work"
  fi
}

check_c3_staged_accept_gate() {
  log "C3 STAGED ACCEPT GATE (#288): flat-95%-count desired GATED behind 60%-by-WORK accept; mint cannot outrun accept"
  if [ "$SIM_VOTES" -eq 1 ]; then
    if ctest --test-dir "$LTC_RATCHET_TESTDIR" -N -R 'LTC_AutoRatchetTailGuard' 2>/dev/null | grep -q 'Test #'; then
      ctest --test-dir "$LTC_RATCHET_TESTDIR" -R 'LTC_AutoRatchetTailGuard' \
        --output-on-failure || die "C3 sim (#288 tail-guard) failed -- mint outran accept"
    else
      gated ltc-ratchet-kats "C3 sim needs LTC_AutoRatchetTailGuard KAT (not yet authored; port from dgb)"
    fi
  else
    gated rigs "C3 live mint-cannot-outrun-accept needs rigs to move work weights"
  fi
}

check_c4_ratchet_persist_reverse() {
  log "C4 RATCHET + PERSIST + REVERSE: VOTING->ACTIVATED->CONFIRMED on 60%-work+95%/2*CL; survives restart; pre-CONFIRMED drop<50% reverts cleanly"
  if [ "$SIM_VOTES" -eq 1 ]; then
    if ctest --test-dir "$LTC_RATCHET_TESTDIR" -N -R 'LTC_AutoRatchetSim' 2>/dev/null | grep -q 'Test #'; then
      ctest --test-dir "$LTC_RATCHET_TESTDIR" -R 'LTC_AutoRatchetSim' \
        --output-on-failure || die "C4 sim (state-machine/restart/reverse KAT) failed"
    else
      gated ltc-ratchet-kats "C4 sim needs LTC_AutoRatchetSim KAT (not yet authored; port from dgb)"
    fi
  else
    gated rigs "C4 live CONFIRMED requires sustained 2*CHAIN_LENGTH of rig-fed 95%/60% shares; reverse leg needs a controlled drop"
  fi
}

check_c5_byte_compat_differential() {
  log "C5 BYTE-COMPAT DIFFERENTIAL: c2pool v35 share serialization == jtoomim/merged-v36 python byte-for-byte (G1 + jtoomim-byte-compat)"
  # The merged wire-compat runtime KAT (PR#665) is the standing byte-parity gate.
  if ctest --test-dir "$LTC_RATCHET_TESTDIR" -N -R 'wirecompat|WireCompat' 2>/dev/null | grep -q 'Test #'; then
    ctest --test-dir "$LTC_RATCHET_TESTDIR" -R 'wirecompat|WireCompat' \
      --output-on-failure || die "C5 (v35 byte-parity differential) failed -- v36 byte leaked into a v35 share"
  else
    gated ltc-ratchet-kats "C5 differential needs the wirecompat runtime KAT built in $LTC_RATCHET_TESTDIR (PR#665)"
  fi
}

# ---- driver ------------------------------------------------------------------
main() {
  mkdir -p "$HOME/.c2pool-ltc-g2"
  case "${1:-run}" in
    provision)  start_daemon; start_tier_a_jtoomim; start_tier_b_merged; start_tier_c_c2pool ;;
    checks)
      check_c1_threetier_cohabit
      check_c2_vote_visibility
      check_c3_staged_accept_gate
      check_c4_ratchet_persist_reverse
      check_c5_byte_compat_differential
      log "G2 crossing check pass complete (sim=$SIM_VOTES fresh-ratchet=$FRESH_RATCHET). Fill scripts/ltc_g2_evidence_template.md."
      ;;
    run|*)
      log "G2 crossing harness: provision three-tier substrate, then run 5 checks."
      log "  staged with 3301 floor + PR#95 8-byte id ($SHARECHAIN_ID) + --fresh-ratchet=$FRESH_RATCHET."
      log "  rig-bound + live rows GATED until the operator start-tap frees R1-LTC .37/.38/.39 onto the v36 tier."
      start_daemon || true
      start_tier_a_jtoomim || true
      start_tier_b_merged || true
      start_tier_c_c2pool || true
      check_c1_threetier_cohabit
      check_c2_vote_visibility
      check_c3_staged_accept_gate
      check_c4_ratchet_persist_reverse
      check_c5_byte_compat_differential
      ;;
  esac
}
main "$@"
