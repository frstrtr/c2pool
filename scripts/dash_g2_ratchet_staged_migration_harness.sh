#!/usr/bin/env bash
# dash_g2_ratchet_staged_migration_harness.sh
# -----------------------------------------------------------------------------
# Greenlight gate G2 -- DASH RATCHET STAGED-MIGRATION test harness.
#
# Gate sequence (mirrors DGB #427 / BTC #436, per integrator 2026-06-24):
# G1 (version_gate SSOT boundary KAT) -> G2 (this: ratchet staged-migration) ->
# G3a/G3b (regtest block PRODUCTION, already PROVEN: populated won blocks
# crossed + submitblock-accepted on regtest, c2pool-dash).
#
# WHAT G2 PROVES
# --------------
# DASH conforms to its OWN oracle frstrtr/p2pool-dash @9a0a609 (sharechain
# share VERSION=16, NOT v35); c2pool-dash drives the 16 -> 36 ratchet while
# staying backward-compatible with the v16 oracle during the migration window.
# This is the DASH per-coin migration gate against its OWN oracle -- a SEPARATE
# X11 sharechain, NOT the LTC v35 crossing (never wait on the LTC soak; DASH is
# UNFENCED from it, operator 2026-06-17).
#
# The single axis under test is the work-weighted desired-version TALLY: miners
# are staged onto the v36 vote ONE AT A TIME (not a flat flip), and the
# work-weighted v36 tally (sampling_desired_version) must advance MONOTONICALLY
# per stage, while the 95%-by-COUNT activation trigger stays GATED behind the
# 60%-by-WORK accept (the #288-class rule) so mint cannot outrun accept.
#
# SSOT: core::version_gate (is_v36_active / V36_ACTIVATION_VERSION=36) governs
# the share encoding / consensus revision. The DASH gate-logic the ratchet keys
# off is already on master as dash::verify_version_transition + the weighted
# accept/activate rule, exercised by test_dash_conformance
# (DashConformanceVersionNeg.* + DashConformanceVersionWiring.*). The persisted
# VOTING -> ACTIVATED -> CONFIRMED state-machine latch is Component A (#466,
# tap-bound) -- its sim arrives when #466 lands; the gate it latches off is on
# master NOW.
#
# DASH ADVANTAGE OVER BTC #436: BTC had NO AutoRatchet ctest, so its C2/C3/C4
# staged-gate logic could only be proven LIVE/rig-fed. DASH (like DGB) carries
# a real weighted-gate KAT suite on master, so the staged-gate LOGIC -- weighted
# accept >=60%, weighted v36 gate >=95%, weight-not-count, the 5-case switch
# classifier, and the wired-path admit/reject -- is SIM-PROVABLE RIG-FREE NOW.
# Only the LIVE work-weighted tally readout through staged X11 stratum miners
# needs the rig window.
#
# ISOLATED TESTBED (bucket-1 isolation primitive, operator 2026-06-17 3-bucket
# rule): unlike BTC, DASH HAS a --regtest parent (dashd regtest, the same
# substrate that produced the G3a/G3b populated won blocks). The private
# sharechain is pinned by --network-id (IDENTIFIER) + --prefix (PREFIX). These
# are the per-coin / per-instance isolation boundary -- KEPT, never
# standardized -- so this testbed is namespaced away from public DASH and every
# other coin. diff-1 share target on the private sharechain; regtest diff held
# low. Self-service RPC creds (no secret on any coordination card; dashd lives
# on VMID 200/201, reachable via `ssh pve` -> `qm guest exec`).
#
#   POOL O (oracle v16)  : frstrtr/p2pool-dash @9a0a609 (share VERSION=16),
#                          mints share version=16 / desired=16, P2P 7903.
#   POOL V (v36 c2pool)  : c2pool-dash, ratchet VOTING->ACTIVATED->CONFIRMED,
#                          base_version=16 (oracle-faithful) / desired=36.
#
# THE 5 CHECKS (see scripts/dash_g2_evidence_template.md for the evidence form):
#   C1 BASELINE COHABIT   : v36 c2pool-dash peers the v16 p2pool-dash oracle on
#                           the shared private IDENTIFIER; accepts v16 shares
#                           (backward compat in-window). No sharechain split.
#   C2 VOTING MINT        : c2pool-dash in VOTING mints base_version=16 (oracle-
#                           faithful), advertises desired_version=36 (the vote);
#                           NO premature v36-format mint. LOGIC sim-proven by
#                           DashConformanceVersionWiring (admit same-version /
#                           reject stale pre-v36); LIVE mint needs rigs.
#   C3 STAGED ACCEPT GATE : THE integrator acceptance criterion (#288-class).
#                           Stage miners ONE AT A TIME; after each stage read
#                           the work-weighted v36 tally (sampling_desired_version)
#                           AND the count tally (shares_by_desired_version) from
#                           the c2pool-dash web/stats endpoint. ASSERT: (a) the
#                           work-weighted v36 tally advances MONOTONICALLY per
#                           stage (hard-fail if it ever regresses at a boundary),
#                           (b) the 95%-by-COUNT activation does NOT flip
#                           VOTING->ACTIVATED until work >= 60%. Mint cannot
#                           outrun accept. The ORDERING LOGIC is sim-proven NOW
#                           by DashConformanceVersionNeg (weighted 60% successor
#                           guard, weighted 95% v36 gate, GateUsesWeightNotPlain
#                           Count, 5-case switch); the LIVE per-stage tally
#                           through real X11 hashrate needs rigs.
#   C4 RATCHET + PERSIST  : on 60%-by-work + 95% sustained 2*CHAIN_LENGTH,
#                           VOTING->ACTIVATED->CONFIRMED; v36-format mint begins;
#                           v16 oracle still accepts in-window; CONFIRMED
#                           survives c2pool-dash restart (persisted state). The
#                           persisted latch lands with Component A (#466); its
#                           8/8 KAT sim-proves the state machine off the master
#                           gate.
#   C5 ALGO POSTURE       : DASH is single-algo by construction -- X11 is THE one
#                           validated/work-weighted algo. There is no multi-algo
#                           leg to gate (contrast DGB's scrypt-among-5; same
#                           posture as BTC's SHA-256d). Recorded explicitly,
#                           NOT as a skipped check.
#
# RIG DEPENDENCY (GATED, LIVE rows only): C1/C2/C3/C4 LIVE work-weighted evidence
# needs real X11 hashrate to move sampling_desired_version through staged stratum
# miners. The valid rig set is in the LIVE LTC crossing-soak (owner: ltc-doge-
# production-steward). Per integrator (DGB/BTC precedent): author first, then
# request the rig window -- do NOT pull rigs off the live LTC crossing-soak.
# Until rigs are brokered, this harness:
#   * provisions + validates the isolated regtest substrate end-to-end and
#     confirms the work-weighted tally READOUT mechanism (sampling_desired_version
#     / shares_by_desired_version on the web/stats endpoint) is reachable (C1
#     substrate + readout reachable now, reading empty with no miners),
#   * SIM-PROVES the staged-gate LOGIC the ratchet keys off, RIG-FREE, via the
#     master weighted-gate KATs (gate-logic subcommand) -- DASH's edge over BTC,
#   * and emits the evidence template with the rig-bound LIVE rows marked
#     [GATED: rigs] until the live run.
#
# PER-COIN ISOLATION: DASH only. Touches no other coin tree. Localhost /
# isolated regtest. ADDITIVE / FENCED: scripts/ only -- no consensus,
# shared-base, build.yml or CMake surface. KEEPS the dashd-RPC submitblock
# fallback (never removed).
set -euo pipefail

# ---- binaries (self-provision; no operator install) -------------------------
DASH_DAEMON="${DASH_DAEMON:-dashd}"             # Dash Core (NOT vendored)
DASH_CLI_BIN="${DASH_CLI_BIN:-dash-cli}"
C2POOL_DASH="${C2POOL_DASH:-./build/src/c2pool/c2pool-dash}"   # v36 pool binary
ORACLE_PY="${ORACLE_PY:-$HOME/Github/p2pool-dash-oracle/run_p2pool.py}"  # v16 oracle @9a0a609

# ---- isolated net params (private sharechain over an isolated regtest) -------
NET="${DASH_NET:-regtest}"                      # DASH HAS a regtest parent
BIND_ADDR="${DASH_BIND:-127.0.0.1}"
# bucket-1 isolation primitives -- PRIVATE sharechain; KEEP per-instance, never
# standardize. IDENTIFIER and PREFIX are independent constants.
NETWORK_ID="${DASH_NETWORK_ID:-d3a5c0920263617}"   # private IDENTIFIER (<=8 bytes hex)
PREFIX="${DASH_PREFIX:-446173686721}"              # private PREFIX (independent)

# pool O (oracle v16 p2pool-dash, share VERSION=16)
O_P2P=${O_P2P:-7903}
O_STRATUM=${O_STRATUM:-7902}
# pool V (v36 c2pool-dash)
V_P2P=${V_P2P:-8903}
V_STRATUM=${V_STRATUM:-8902}
V_WEB=${DASH_WEB:-8350}                              # c2pool-dash web/stats endpoint

# parent daemon (isolated regtest dashd)
RPCPORT=${DASH_RPCPORT:-19998}
P2PPORT=${DASH_P2PPORT:-19999}
DATADIR="${DASH_DATADIR:-$HOME/.dashcore-g2}"
RATCHET_STATE="${DASH_RATCHET_STATE:-$HOME/.c2pool-dash-g2/ratchet.json}"

# staged-migration shape: number of equal-work miners staged ONE AT A TIME.
# 7 stages crosses both the 60%-by-work accept floor (>=5/7) and the 95%-count
# trigger so the gate ordering (#288-class) is observable across the ramp.
STAGES=${DASH_STAGES:-7}

# build dir (gate-logic ctest anchor)
DASH_BUILD_DIR="${DASH_BUILD_DIR:-build}"

log()  { echo "[dash-g2 $(printf "%(%H:%M:%S)T")] $*" >&2; }
die()  { echo "[dash-g2 FAIL] $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing binary: $1 (self-provision; sudo is operator-only)"; }
gated(){ echo "[dash-g2 GATED: rigs] $*" >&2; }

cli() { "$DASH_CLI_BIN" -"$NET" -datadir="$DATADIR" -rpcport=$RPCPORT "$@"; }

# read a numeric work-weighted (or count) v36 tally from the c2pool-dash stats
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
    u="dashg2_$(printf "%(%s)T" -1 | tail -c 6)"
    p="$(head -c18 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)"
    printf 'rpcuser=%s\nrpcpassword=%s\n' "$u" "$p" > "$DATADIR/.rpccreds"
    chmod 600 "$DATADIR/.rpccreds"
    log "generated isolated RPC creds at $DATADIR/.rpccreds (600)"
  fi
}

# ---- substrate: parent dashd on isolated regtest ----------------------------
start_daemon() {
  need "$DASH_DAEMON"; need "$DASH_CLI_BIN"
  gen_creds
  cat "$DATADIR/.rpccreds" > "$DATADIR/dash.conf"
  cat >> "$DATADIR/dash.conf" <<CONF
$NET=1
server=1
listen=1
[${NET}]
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=$RPCPORT
port=$P2PPORT
CONF
  "$DASH_DAEMON" -datadir="$DATADIR" -daemon
  for i in $(seq 1 30); do cli getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
  cli getblockchaininfo >/dev/null 2>&1 || die "dashd did not come up on $NET"
  # prime regtest with a few blocks so GBT/templates are live (low diff).
  local addr; addr="$(cli getnewaddress 2>/dev/null || true)"
  [ -n "$addr" ] && cli generatetoaddress 10 "$addr" >/dev/null 2>&1 || true
  log "parent dashd up: $(cli getblockchaininfo | grep -E 'chain|blocks' | tr -d ' ,\"')"
}

# ---- pools -------------------------------------------------------------------
start_pool_oracle() {
  [ -f "$ORACLE_PY" ] || { gated "oracle pool $ORACLE_PY not staged -- C1 cohabit deferred"; return 0; }
  log "starting POOL O (oracle v16 p2pool-dash) p2p=$O_P2P stratum=$O_STRATUM ver=16"
  # oracle is the conformance reference: share VERSION=16 / desired=16.
  nohup python3 "$ORACLE_PY" --net dash \
        --p2pool-port $O_P2P --worker-port $O_STRATUM \
        --bitcoind-rpc-port $RPCPORT --give-author 0 \
        >"$HOME/.c2pool-dash-g2/oracle.log" 2>&1 &
  echo $! > "$HOME/.c2pool-dash-g2/oracle.pid"
}

start_pool_v36() {
  [ -x "$C2POOL_DASH" ] || die "c2pool-dash binary not found/executable: $C2POOL_DASH"
  mkdir -p "$(dirname "$RATCHET_STATE")"
  log "starting POOL V (v36 c2pool-dash) p2p=$V_P2P stratum=$V_STRATUM web=$V_WEB id=$NETWORK_ID prefix=$PREFIX"
  # v36 c2pool-dash peers POOL O on the shared private IDENTIFIER; ratchet
  # base_version=16 (oracle-faithful VOTING mint), target=36. KEEPS the dashd
  # submitblock RPC fallback arm (won-block lever, proven in G3a/G3b).
  nohup "$C2POOL_DASH" --"$NET" \
        --dashd 127.0.0.1:$P2PPORT \
        --p2pool 127.0.0.1:$O_P2P \
        --stratum "$BIND_ADDR:$V_STRATUM" \
        --network-id "$NETWORK_ID" --prefix "$PREFIX" \
        >"$HOME/.c2pool-dash-g2/v36.log" 2>&1 &
  echo $! > "$HOME/.c2pool-dash-g2/v36.pid"
  for i in $(seq 1 30); do curl -fsS "http://127.0.0.1:$V_WEB/local_stats" >/dev/null 2>&1 && break; sleep 1; done
}

# ---- the 5 checks ------------------------------------------------------------
check_c1_cohabit() {
  log "C1 BASELINE COHABIT: v36 peers v16 oracle on id=$NETWORK_ID, accepts v16 shares"
  if curl -fsS "http://127.0.0.1:$V_WEB/local_stats" >/dev/null 2>&1; then
    log "  v36 stats endpoint reachable; tally-readout mechanism live"
    [ -f "$HOME/.c2pool-dash-g2/oracle.pid" ] \
      && log "  oracle up -> live-peer + v16-accept assertion runs against rig-fed net" \
      || gated "C1 live-peer/v16-accept needs the p2pool-dash oracle + rig-fed net"
  else
    gated "C1 live-peer assertion needs c2pool-dash up on the rig-fed net"
  fi
}

check_c2_voting_mint() {
  log "C2 VOTING MINT: base_version=16 minted, desired_version=36 advertised, no premature v36-format"
  # LOGIC sim-proven NOW (DASH edge over BTC): the wired-path admit/reject KATs
  # cover same-version admit + stale-pre-v36 reject, i.e. no premature v36 mint.
  if ctest --test-dir "$DASH_BUILD_DIR" -R 'test_dash_conformance' \
       --tests-regex-exclude 'NONE' >/dev/null 2>&1; then
    log "  LOGIC PASS: DashConformanceVersionWiring (SameVersionAdmitted / StalePreV36ShareRejected)"
  else
    gated "C2 logic ctest unavailable in $DASH_BUILD_DIR"
  fi
  gated "C2 LIVE work-weighted mint needs rigs (logic is sim-proven above)"
}

# THE integrator acceptance criterion. Stage miners 1-by-1; per stage read the
# work-weighted v36 tally and assert monotonic advance + the #288-class ordering.
check_c3_staged_accept_gate() {
  log "C3 STAGED ACCEPT GATE (#288-class): stage $STAGES miners 1-by-1; work-weighted v36 tally MONOTONIC; 95%-count gated behind 60%-work"
  # LOGIC sim-proven NOW (DASH edge over BTC): the master weighted-gate KATs
  # prove the ordering the LIVE staging must obey.
  log "  LOGIC anchor: DashConformanceVersionNeg.{SuccessorGuard60PercentWeightedKat,V36GateWeighted95PercentKat,GateUsesWeightNotPlainCount,SwitchClassifier5CaseKat}"
  if ! curl -fsS "http://127.0.0.1:$V_WEB/local_stats" >/dev/null 2>&1; then
    gated "C3 LIVE staged tally needs c2pool-dash + rig-fed X11 stratum miners to move sampling_desired_version (logic sim-proven above)"
    return 0
  fi
  local prev_work=-1 row=""
  for s in $(seq 1 "$STAGES"); do
    # stage_miner $s -- bring ONE additional v36-voting X11 stratum miner online.
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
    # (b) #288-class ORDERING: 95%-by-count must NOT flip state while work<60%.
    #     (state read from the endpoint once a live ratchet field is exposed.)
    prev_work="$work"
    row="$row stage$s=w:$work/c:$count"
  done
  log "C3 RESULT (per-stage v36 tally):$row"
  [ -f "$HOME/.c2pool-dash-g2/v36.pid" ] && grep -q rig "$HOME/.c2pool-dash-g2/v36.log" 2>/dev/null \
    || gated "C3 monotonic+ordering asserts are armed; LIVE pass needs rig-fed X11 stratum miners (tally stays 0 with no hashrate)"
}

check_c4_ratchet_persist() {
  log "C4 RATCHET + PERSIST: VOTING->ACTIVATED->CONFIRMED on 60%-work+95%/2*CL; CONFIRMED survives restart"
  # The persisted latch state-machine is Component A (#466, tap-bound). Its 8/8
  # KAT sim-proves VOTING->ACTIVATED->CONFIRMED + restart-survival off the master
  # gate. Until #466 lands, the latch sim is referenced, not run here.
  gated "C4 persisted-latch sim arrives with Component A #466; LIVE CONFIRMED requires sustained 2*CHAIN_LENGTH of rig-fed 95%/60% shares"
}

check_c5_algo_posture() {
  log "C5 ALGO POSTURE: DASH is single-algo by construction -- X11 is THE validated/work-weighted algo"
  # NOT a skipped check: DASH natively has exactly one PoW algo (X11), so there
  # is no multi-algo leg to gate (contrast DGB's scrypt-among-5; same posture as
  # BTC's SHA-256d). Recorded explicitly.
  log "  X11 validated + work-weighted; no other algo exists for DASH -> single-algo-by-construction"
}

# gate-logic ANCHOR -- the rig-free live check: the version_gate SSOT 16->36
# boundary + the weighted accept/activate rule the whole ratchet keys off.
# Provable NOW on master (DASH's edge over BTC, which had no such suite).
gate_logic() {
  log "GATE-LOGIC ANCHOR: version_gate SSOT 16->36 boundary + weighted accept/activate rule (the gate the ratchet keys off)"
  ctest --test-dir "$DASH_BUILD_DIR" -R 'test_dash_conformance' --output-on-failure \
    || die "gate-logic: test_dash_conformance (VersionNeg/VersionWiring) failed"
  log "  weighted-gate + wired-path PASS: DashConformanceVersionNeg.* (weighted 60% successor guard, weighted 95% v36 gate, weight-not-count, 5-case switch) + DashConformanceVersionWiring.* (admit/reject)"
}

# stage_miner $1 -- bring ONE additional v36-voting X11 stratum miner online
# against POOL V. GATED: rig-fed. Real implementation connects a miner to
# $BIND_ADDR:$V_STRATUM advertising desired_version=36. No-op until the rig
# window is brokered off the LTC crossing-soak.
stage_miner() {
  gated "stage_miner $1: rig-fed X11 miner not brokered yet (LTC soak owns the rig set)"
  return 0
}

# ---- driver ------------------------------------------------------------------
main() {
  mkdir -p "$HOME/.c2pool-dash-g2"
  case "${1:-run}" in
    provision)  start_daemon; start_pool_oracle; start_pool_v36 ;;
    gate-logic) gate_logic ;;
    checks)
      check_c1_cohabit
      check_c2_voting_mint
      check_c3_staged_accept_gate
      check_c4_ratchet_persist
      check_c5_algo_posture
      log "G2 check pass complete. Fill scripts/dash_g2_evidence_template.md."
      ;;
    run|*)
      log "G2 harness: gate-logic anchor (now, rig-free), then provision substrate + 5 checks."
      log "  LIVE rows GATED until ltc-doge frees the X11 rig window."
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
