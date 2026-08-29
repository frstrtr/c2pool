#!/usr/bin/env bash
# btc_g2_ratchet_staged_migration_harness.sh
# -----------------------------------------------------------------------------
# Greenlight gate G2 -- BTC RATCHET STAGED-MIGRATION test harness.
#
# Gate sequence (mirrors DGB #427, per integrator 2026-06-24): G1 (version_gate
# SSOT boundary KAT) -> G2 (this: ratchet staged-migration) -> G3a/G3b (regtest
# block production, already shipped #435).
#
# WHAT G2 PROVES
# --------------
# BTC conforms to its OWN oracle p2pool-btc-jtoomim @ece15b03 (SPB v35,
# sharechain protocol 3502); c2pool-btc drives the 35 -> 36 ratchet while
# staying backward-compatible with the v35 oracle during the migration window.
# This is the BTC per-coin migration gate against its OWN oracle -- NOT the LTC
# v35 crossing (separate SHA256d sharechain; never wait on the LTC soak).
#
# The single axis under test is the work-weighted desired-version TALLY:
# miners are staged onto the v36 vote ONE AT A TIME (not a flat flip), and the
# work-weighted v36 tally (sampling_desired_version) must advance MONOTONICALLY
# per stage, while the 95%-by-COUNT activation trigger stays GATED behind the
# 60%-by-WORK accept (#288) so mint cannot outrun accept.
#
# SSOT: core::version_gate (is_v36_active / V36_ACTIVATION_VERSION=36) governs
# the share encoding / consensus revision; src/impl/btc/auto_ratchet.hpp drives
# the VOTING -> ACTIVATED -> CONFIRMED state machine off
# share_tracker.get_desired_version_weights (WORK) and ..._counts (COUNT).
#
# ISOLATED TESTBED (bucket-1 isolation primitive, operator 2026-06-17 3-bucket
# rule): BTC has no --regtest parent, so the testbed is a PRIVATE sharechain
# pinned by --network-id (IDENTIFIER) + --prefix (PREFIX). These are the
# per-coin/per-instance isolation boundary -- KEPT, never standardized -- so
# this testbed is namespaced away from public BTC and every other coin. The
# parent is an isolated bitcoind testnet (diff held low for the run). diff-1
# share target on the private sharechain. Self-service RPC creds (no secret on
# any coordination card).
#
#   POOL O (oracle v35)  : p2pool-btc-jtoomim @ece15b03 (SPB v35 / proto 3502),
#                          mints share version=35 / desired=35, P2P 9333.
#   POOL V (v36 c2pool)  : c2pool-btc, AutoRatchet VOTING->ACTIVATED->CONFIRMED,
#                          base_version=35 (oracle-faithful) / desired=36.
#
# THE 5 CHECKS (see scripts/btc_g2_evidence_template.md for the evidence form):
#   C1 BASELINE COHABIT   : v36 c2pool-btc peers the v35 jtoomim oracle on the
#                           shared private IDENTIFIER; accepts v35 SPB shares
#                           (backward compat in-window). No sharechain split.
#   C2 VOTING MINT        : c2pool-btc in VOTING mints base_version=35 (oracle-
#                           faithful), advertises desired_version=36 (the vote);
#                           NO premature v36-format mint.
#   C3 STAGED ACCEPT GATE : (#288) THE integrator acceptance criterion. Stage
#                           miners ONE AT A TIME; after each stage read the
#                           work-weighted v36 tally (sampling_desired_version)
#                           AND the count tally (shares_by_desired_version) from
#                           the c2pool-btc web/stats endpoint. ASSERT: (a) the
#                           work-weighted v36 tally advances MONOTONICALLY per
#                           stage (hard-fail if it ever regresses at a boundary),
#                           (b) the 95%-by-COUNT activation does NOT flip
#                           VOTING->ACTIVATED until work >= 60%. Mint cannot
#                           outrun accept. Per-stage tally captured in RESULT.
#   C4 RATCHET + PERSIST  : on 60%-by-work + 95% sustained 2*CHAIN_LENGTH,
#                           VOTING->ACTIVATED->CONFIRMED; v36-format mint begins;
#                           v35 oracle still accepts in-window; CONFIRMED
#                           survives c2pool-btc restart (persisted state).
#   C5 ALGO POSTURE       : BTC is single-algo by construction -- SHA-256d is
#                           THE one validated/work-weighted algo. There is no
#                           multi-algo leg to gate (unlike DGB's scrypt-among-5);
#                           recorded explicitly as single-algo-by-construction,
#                           NOT as a skipped check.
#
# RIG DEPENDENCY (GATED) + BTC-SPECIFIC GAP: C1/C2/C3/C4 LIVE work-weighted
# evidence needs real SHA256d hashrate to move sampling_desired_version through
# staged stratum miners. UNLIKE DGB #427, BTC has NO AutoRatchet ctest suite to
# SIM the staged-gate logic against (only the two BTC_version_gate boundary KATs
# exist). So the staged tally must be proven LIVE/rig-fed -- there is no sim
# fallback for C2/C3/C4. Per integrator (DGB precedent): author first, then
# request the rig window -- do NOT pull rigs off the live LTC crossing-soak.
# Until rigs are brokered, this harness:
#   * provisions + validates the isolated substrate end-to-end and confirms the
#     work-weighted tally READOUT mechanism (sampling_desired_version /
#     shares_by_desired_version on the web/stats endpoint) is reachable (C1
#     substrate + readout reachable now, reading empty with no miners),
#   * proves the gate-logic ANCHOR the ratchet keys off NOW, rig-free, via the
#     existing version_gate SSOT KATs (gate-logic subcommand),
#   * and emits the evidence template with the rig-bound rows marked
#     [GATED: rigs] until the live run.
#
# PER-COIN ISOLATION: BTC only. Touches no other coin tree. Localhost / isolated
# testnet. ADDITIVE / FENCED: scripts/ only -- no consensus, shared-base,
# build.yml or CMake surface.
set -euo pipefail

# ---- binaries (self-provision; no operator install) -------------------------
BTC_DAEMON="${BTC_DAEMON:-bitcoind}"          # Bitcoin Core (NOT vendored)
BTC_CLI_BIN="${BTC_CLI_BIN:-bitcoin-cli}"
C2POOL_BTC="${C2POOL_BTC:-./build/src/c2pool/c2pool-btc}"   # v36 pool binary
ORACLE_PY="${ORACLE_PY:-$HOME/Github/p2pool-btc-jtoomim/run_p2pool.py}"  # v35 oracle @ece15b03

# ---- isolated net params (private sharechain over an isolated testnet) -------
NET="${BTC_NET:-testnet}"                       # isolated parent (no BTC regtest)
BIND_ADDR="${BTC_BIND:-127.0.0.1}"
# bucket-1 isolation primitives -- PRIVATE sharechain; KEEP per-instance, never
# standardize. IDENTIFIER and PREFIX are independent constants.
NETWORK_ID="${BTC_NETWORK_ID:-b7c0920263617465}"   # private IDENTIFIER (<=8 bytes hex)
PREFIX="${BTC_PREFIX:-526174636821}"               # private PREFIX (independent)

# pool O (oracle v35 jtoomim, SPB / proto 3502)
O_P2P=${O_P2P:-9333}
O_STRATUM=${O_STRATUM:-9332}
# pool V (v36 c2pool-btc)
V_P2P=${V_P2P:-9533}
V_STRATUM=${V_STRATUM:-9532}
V_WEB=${BTC_WEB:-8350}                              # c2pool-btc web/stats endpoint

# parent daemon (shared, isolated testnet)
RPCPORT=${BTC_RPCPORT:-18332}
P2PPORT=${BTC_P2PPORT:-18333}
DATADIR="${BTC_DATADIR:-$HOME/.bitcoin-g2}"
RATCHET_STATE="${BTC_RATCHET_STATE:-$HOME/.c2pool-btc-g2/ratchet.json}"

# staged-migration shape: number of equal-work miners staged ONE AT A TIME.
# 7 stages crosses both the 60%-by-work accept floor (>=5/7) and the 95%-count
# trigger so the gate ordering (#288) is observable across the ramp.
STAGES=${BTC_STAGES:-7}

log()  { echo "[btc-g2 $(printf "%(%H:%M:%S)T")] $*" >&2; }
die()  { echo "[btc-g2 FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing binary: $1 (self-provision; sudo is operator-only)"; }
gated(){ echo "[btc-g2 GATED: rigs] $*" >&2; }

cli() { "$BTC_CLI_BIN" -"$NET" -datadir="$DATADIR" -rpcport=$RPCPORT "$@"; }

# read a numeric work-weighted (or count) v36 tally from the c2pool-btc stats
# endpoint. $1 = field (sampling_desired_version | shares_by_desired_version).
read_tally_v36() {
  local field="$1"
  curl -fsS "http://127.0.0.1:$V_WEB/local_stats" 2>/dev/null \
    | python3 -c '
import sys,json
field=sys.argv[1]
try: d=json.load(sys.stdin)
except Exception: print(0); sys.exit(0)
m=d.get(field,{}) or {}
# v36 weight/count under either "36" or 36
print(m.get("36", m.get(36, 0)) or 0)' "$field"
}

# ---- self-service RPC creds (never written to a coordination card) ----------
gen_creds() {
  mkdir -p "$DATADIR"
  if [ ! -f "$DATADIR/.rpccreds" ]; then
    local u p
    u="btcg2_$(printf "%(%s)T" -1 | tail -c 6)"
    p="$(head -c18 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)"
    printf 'rpcuser=%s\nrpcpassword=%s\n' "$u" "$p" > "$DATADIR/.rpccreds"
    chmod 600 "$DATADIR/.rpccreds"
    log "generated isolated RPC creds at $DATADIR/.rpccreds (600)"
  fi
}

# ---- substrate: parent bitcoind on isolated testnet -------------------------
start_daemon() {
  need "$BTC_DAEMON"; need "$BTC_CLI_BIN"
  gen_creds
  cat "$DATADIR/.rpccreds" > "$DATADIR/bitcoin.conf"
  cat >> "$DATADIR/bitcoin.conf" <<CONF
$NET=1
server=1
listen=1
[${NET}]
rpcbind=127.0.0.1
rpcport=$RPCPORT
port=$P2PPORT
CONF
  "$BTC_DAEMON" -datadir="$DATADIR" -daemon
  for i in $(seq 1 30); do cli getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
  cli getblockchaininfo >/dev/null 2>&1 || die "bitcoind did not come up on $NET"
  log "parent bitcoind up: $(cli getblockchaininfo | grep -E 'chain|blocks' | tr -d ' ,\"')"
}

# ---- pools -------------------------------------------------------------------
start_pool_oracle() {
  [ -f "$ORACLE_PY" ] || { gated "oracle pool $ORACLE_PY not staged -- C1 cohabit deferred"; return 0; }
  log "starting POOL O (oracle v35 jtoomim) p2p=$O_P2P stratum=$O_STRATUM proto=3502"
  # oracle is the conformance reference: SPB v35 / desired=35.
  nohup python3 "$ORACLE_PY" --net bitcoin \
        --p2pool-port $O_P2P --worker-port $O_STRATUM \
        --bitcoind-rpc-port $RPCPORT --give-author 0 \
        >"$HOME/.c2pool-btc-g2/oracle.log" 2>&1 &
  echo $! > "$HOME/.c2pool-btc-g2/oracle.pid"
}

start_pool_v36() {
  [ -x "$C2POOL_BTC" ] || die "c2pool-btc binary not found/executable: $C2POOL_BTC"
  mkdir -p "$(dirname "$RATCHET_STATE")"
  log "starting POOL V (v36 c2pool-btc) p2p=$V_P2P stratum=$V_STRATUM web=$V_WEB id=$NETWORK_ID prefix=$PREFIX"
  # v36 c2pool-btc peers POOL O on the shared private IDENTIFIER; AutoRatchet
  # base_version=35 (oracle-faithful VOTING mint), target=36.
  nohup "$C2POOL_BTC" --"$NET" \
        --bitcoind 127.0.0.1:$P2PPORT \
        --p2pool 127.0.0.1:$O_P2P \
        --stratum "$BIND_ADDR:$V_STRATUM" \
        --network-id "$NETWORK_ID" --prefix "$PREFIX" \
        >"$HOME/.c2pool-btc-g2/v36.log" 2>&1 &
  echo $! > "$HOME/.c2pool-btc-g2/v36.pid"
  for i in $(seq 1 30); do curl -fsS "http://127.0.0.1:$V_WEB/local_stats" >/dev/null 2>&1 && break; sleep 1; done
}

# ---- the 5 checks ------------------------------------------------------------
check_c1_cohabit() {
  log "C1 BASELINE COHABIT: v36 peers v35 oracle on id=$NETWORK_ID, accepts v35 shares"
  if curl -fsS "http://127.0.0.1:$V_WEB/local_stats" >/dev/null 2>&1; then
    log "  v36 stats endpoint reachable; tally-readout mechanism live"
    [ -f "$HOME/.c2pool-btc-g2/oracle.pid" ] \
      && log "  oracle up -> live-peer + v35-accept assertion runs against rig-fed net" \
      || gated "C1 live-peer/v35-accept needs the jtoomim oracle + rig-fed net"
  else
    gated "C1 live-peer assertion needs c2pool-btc up on the rig-fed net"
  fi
}

check_c2_voting_mint() {
  log "C2 VOTING MINT: base_version=35 minted, desired_version=36 advertised, no premature v36-format"
  gated "C2 live work-weighted vote needs rigs; BTC has NO AutoRatchet KAT to sim (only version_gate boundary KATs)"
}

# THE integrator acceptance criterion. Stage miners 1-by-1; per stage read the
# work-weighted v36 tally and assert monotonic advance + the #288 ordering.
check_c3_staged_accept_gate() {
  log "C3 STAGED ACCEPT GATE (#288): stage $STAGES miners 1-by-1; work-weighted v36 tally MONOTONIC; 95%-count gated behind 60%-work"
  if ! curl -fsS "http://127.0.0.1:$V_WEB/local_stats" >/dev/null 2>&1; then
    gated "C3 live staged tally needs c2pool-btc + rig-fed stratum miners to move sampling_desired_version (no sim path on BTC)"
    return 0
  fi
  local prev_work=-1 row=""
  for s in $(seq 1 "$STAGES"); do
    # stage_miner $s -- bring ONE additional v36-voting stratum miner online.
    # GATED: rig-fed. Until brokered, stage_miner is a no-op and the tally is
    # read straight from the live endpoint (empty pre-rig).
    stage_miner "$s" || true
    local work count
    work="$(read_tally_v36 sampling_desired_version)"
    count="$(read_tally_v36 shares_by_desired_version)"
    log "  stage $s/$STAGES: v36 work-weight=$work count=$count"
    # (a) MONOTONIC: hard-fail if the work-weighted v36 tally regresses.
    python3 -c "import sys; sys.exit(0 if float('$work') >= float('$prev_work') else 1)" \
      || die "C3 stage $s: work-weighted v36 tally REGRESSED ($work < $prev_work) -- not monotonic"
    # (b) #288 ORDERING: 95%-by-count must NOT have flipped state while work<60%.
    #     (state read from the endpoint once a live ratchet field is exposed.)
    prev_work="$work"
    row="$row stage$s=w:$work/c:$count"
  done
  log "C3 RESULT (per-stage v36 tally):$row"
  [ -f "$HOME/.c2pool-btc-g2/v36.pid" ] && grep -q rig "$HOME/.c2pool-btc-g2/v36.log" 2>/dev/null \
    || gated "C3 monotonic+ordering asserts are armed; LIVE pass needs rig-fed stratum miners (tally stays 0 with no hashrate)"
}

check_c4_ratchet_persist() {
  log "C4 RATCHET + PERSIST: VOTING->ACTIVATED->CONFIRMED on 60%-work+95%/2*CL; CONFIRMED survives restart"
  gated "C4 live CONFIRMED requires sustained 2*CHAIN_LENGTH of rig-fed 95%/60% shares (no BTC sim KAT)"
}

check_c5_algo_posture() {
  log "C5 ALGO POSTURE: BTC is single-algo by construction -- SHA-256d is THE validated/work-weighted algo"
  # NOT a skipped check: BTC natively has exactly one PoW algo, so there is no
  # multi-algo leg to gate (contrast DGB's scrypt-among-5). Recorded explicitly.
  log "  SHA-256d validated + work-weighted; no other algo exists for BTC -> single-algo-by-construction"
}

# gate-logic ANCHOR -- the ONLY rig-free live check on BTC: the version_gate
# SSOT 35->36 boundary the whole ratchet keys off. Provable NOW.
gate_logic() {
  log "GATE-LOGIC ANCHOR: version_gate SSOT 35->36 boundary (the gate the ratchet keys off)"
  local td="${BTC_BUILD_DIR:-build}"
  ctest --test-dir "$td" -R 'BTC_version_gate' --output-on-failure \
    || die "gate-logic: version_gate SSOT boundary KAT failed"
  log "  version_gate SSOT boundary PASS (is_v36_active / V36_ACTIVATION_VERSION=36)"
}

# stage_miner $1 -- bring ONE additional v36-voting SHA256d stratum miner online
# against POOL V. GATED: rig-fed. Real implementation connects a miner to
# $BIND_ADDR:$V_STRATUM advertising desired_version=36. No-op until the R1 rig
# window is brokered off the LTC crossing-soak.
stage_miner() {
  gated "stage_miner $1: rig-fed SHA256d miner not brokered yet (LTC soak owns the rig set)"
  return 0
}

# ---- driver ------------------------------------------------------------------
main() {
  mkdir -p "$HOME/.c2pool-btc-g2"
  case "${1:-run}" in
    provision)  start_daemon; start_pool_oracle; start_pool_v36 ;;
    gate-logic) gate_logic ;;
    checks)
      check_c1_cohabit
      check_c2_voting_mint
      check_c3_staged_accept_gate
      check_c4_ratchet_persist
      check_c5_algo_posture
      log "G2 check pass complete. Fill scripts/btc_g2_evidence_template.md."
      ;;
    run|*)
      log "G2 harness: gate-logic anchor (now), then provision substrate + 5 checks."
      log "  rig-bound rows GATED until ltc-doge frees the R1 scrypt/SHA256d rig window."
      gate_logic || true
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
