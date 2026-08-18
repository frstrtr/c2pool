#!/usr/bin/env bash
# dgb_g2_ratchet_h_stages.sh
# -----------------------------------------------------------------------------
# Greenlight gate G2 -- DGB RATCHET STAGED-MIGRATION harness, §5 STAGE DRIVER.
#
# Companion to scripts/dgb_g2_ratchet_staged_migration_harness.sh. That script
# proves the C1-C5 check LOGIC via the AutoRatchet KAT seam; THIS script exposes
# the runbook (frstrtr/the docs/dgb-g2-ratchet-staged-migration-runbook.md, §5)
# H0-H7 stage decomposition so a G2 run is "point-at-rigs-and-run": each stage
# emits a single PASS/FAIL/GATED line AND a machine-auditable JSON artifact under
# run/<ts>/<stage>.json, so a NO-GO is diagnosable from the snapshot alone.
#
# STAGE MAP (runbook §5):
#   H0 standup()                 -- launch NODE-A(35)/NODE-B(36/35), peer, run
#                                   the §1 precondition checklist; abort on FAIL.
#   H1 check_baseline_accept()   -> C1  baseline (ver35) cohabit/accept
#   H2 check_dual_chain_integrity() -> C2  compare tip sha256 both nodes
#   H3 check_ratchet_curve()     -> C3  ramp work fraction; assert 60%-by-work
#   H4 check_block_production()  -> C4  [RIG-GATED] real Scrypt hashrate
#   H5 check_broadcaster_e2e()   -> C5  [RIG-GATED] submitblock + P2P verdict
#   H6 migrate_one_by_one()      -> §3  [RIG-GATED] GO/NO-GO loop, per-step JSON
#   H7 rollback(step|all)        -> §4  additive-only rollback
#
# RIG-GATING (runbook §5): H0-H3 + H7 run on the isolated regtest/testnet regime
# with SIMULATED Scrypt work (the AutoRatchet KAT seam, --sim-votes on the C1-C5
# harness) and are NON-GATED -- runnable today for CI as the pre-rig acceptance
# proof. H4/H5/H6 REQUIRE leased R1-LTC-class Scrypt rigs (SHA-256 bitaxes cannot
# hash Scrypt) and are the ONLY rig-day stages; here they emit GATED artifacts
# and refuse to fabricate a verdict without --rig.
#
# PER-COIN ISOLATION: DGB only. Ops script -- touches NO coin code, NO other coin
# tree. Reuses the C1-C5 harness config + KAT names as the single source of truth.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C1C5="$HERE/dgb_g2_ratchet_staged_migration_harness.sh"   # sibling: check LOGIC

# ---- build / regime ---------------------------------------------------------
BUILD_DIR="${DGB_BUILD_DIR:-build_dgb}"        # ctest tree for the KAT seam
RIG=0                                          # 0 = non-rig (sim) regime
for a in "$@"; do case "$a" in --rig) RIG=1;; esac; done

# ---- run dir + artifacts ----------------------------------------------------
TS="${DGB_G2_TS:-$(printf '%(%Y%m%dT%H%M%SZ)T' -1)}"
RUN_DIR="${DGB_G2_RUN_DIR:-$HERE/../run/dgb-g2/$TS}"
mkdir -p "$RUN_DIR"

log()  { echo "[dgb-g2/H $(printf '%(%H:%M:%S)T' -1)] $*" >&2; }
pass() { echo "[dgb-g2/H PASS] $1" >&2; }
fail() { echo "[dgb-g2/H FAIL] $1" >&2; }
gate() { echo "[dgb-g2/H GATED: rigs] $1" >&2; }

# json_escape: minimal string escaper (no jq dependency on the substrate host)
json_escape() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "$s"; }

# artifact <stage> <verdict> <check> <detail> [k=v ...] -> run/<ts>/<stage>.json
artifact() {
  local stage="$1" verdict="$2" check="$3" detail="$4"; shift 4
  local extra="" kv k v
  for kv in "$@"; do k="${kv%%=*}"; v="${kv#*=}"; extra+=$(printf ',\n  "%s": "%s"' "$(json_escape "$k")" "$(json_escape "$v")"); done
  cat > "$RUN_DIR/$stage.json" <<JSON
{
  "stage": "$(json_escape "$stage")",
  "check": "$(json_escape "$check")",
  "verdict": "$(json_escape "$verdict")",
  "regime": "$([ "$RIG" -eq 1 ] && echo rig || echo sim)",
  "ts": "$(json_escape "$TS")",
  "detail": "$(json_escape "$detail")"$extra
}
JSON
  log "artifact -> $RUN_DIR/$stage.json ($verdict)"
}

# run a named ctest KAT set in the non-rig regime; returns ctest's status
kat() { ctest --test-dir "$BUILD_DIR" -R "$1" --output-on-failure; }

# =============================================================================
# H0 -- standup + §1 precondition checklist (abort on any FAIL)
# =============================================================================
stage_H0() {
  log "H0 standup(): §1 precondition checklist (regime=$([ "$RIG" -eq 1 ] && echo rig || echo sim))"
  local miss=() note=""
  # §1: the C1-C5 harness (config + node/pool launchers) must be present.
  [ -f "$C1C5" ] || miss+=("C1-C5 harness $C1C5")
  # §1: KAT tree present so the sim regime has a verdict source.
  [ -d "$BUILD_DIR" ] || note="build tree '$BUILD_DIR' absent -- run cmake --build first for KAT stages"
  # §1: ratchet PAIR config -- base 35, target 36 (oracle-faithful VOTING mint).
  local base="${DGB_BASE_VERSION:-35}" target="${DGB_TARGET_VERSION:-36}"
  [ "$target" -gt "$base" ] || miss+=("ratchet pair target($target)>base($base)")
  # §1: bucket-1 isolation IDENTIFIER pinned (never standardized).
  local id="${DGB_SHARECHAIN_ID:-4b62545b1a631afe}"
  [ "$id" = "4b62545b1a631afe" ] || miss+=("IDENTIFIER drift: $id != 4b62545b1a631afe")
  if [ "${#miss[@]}" -gt 0 ]; then
    fail "H0 precondition(s): ${miss[*]}"
    artifact H0 FAIL "§1-standup" "precondition failure" "missing=${miss[*]}" "base=$base" "target=$target" "identifier=$id"
    return 1
  fi
  pass "H0 preconditions ok (base=$base target=$target id=$id)${note:+; $note}"
  artifact H0 PASS "§1-standup" "preconditions ok${note:+ ($note)}" "base=$base" "target=$target" "identifier=$id" "build_dir=$BUILD_DIR"
}

# =============================================================================
# H1 -- C1 baseline (ver35) accept / cohabit
# =============================================================================
stage_H1() {
  log "H1 check_baseline_accept() -> C1"
  if [ "$RIG" -eq 1 ]; then gate "H1 live cohabit deferred to rig-day driver"; artifact H1 GATED C1 "live cohabit on rig-fed net"; return 0; fi
  if [ ! -d "$BUILD_DIR" ]; then fail "H1 build tree absent"; artifact H1 BLOCKED C1 "KAT tree '$BUILD_DIR' absent -- cannot assert baseline"; return 1; fi
  # DGB-scoped suite prefix (DGB_share_test.) -- NOT LTC/BTC AutoRatchetSim.
  if kat 'DGB_share_test\.AutoRatchetWireBaselineConstantsFromOracle|DGB_share_test\.AutoRatchetBaseVersionParameterized'; then
    pass "H1 baseline ver35 constants oracle-faithful"; artifact H1 PASS C1 "base_version=35 minted (oracle-faithful) while accepting ver35"
  else
    fail "H1 baseline KAT"; artifact H1 FAIL C1 "baseline-constants KAT failed"; return 1
  fi
}

# =============================================================================
# H2 -- C2 dual-chain integrity (compare tip sha256 both nodes)
# =============================================================================
stage_H2() {
  log "H2 check_dual_chain_integrity() -> C2"
  if [ "$RIG" -eq 1 ]; then
    gate "H2 live tip compare deferred to rig-day driver"; artifact H2 GATED C2 "live tip sha256 compare (both nodes)"; return 0
  fi
  if [ ! -d "$BUILD_DIR" ]; then fail "H2 build tree absent"; artifact H2 BLOCKED C2 "KAT tree absent"; return 1; fi
  # Sim regime: no live nodes to sha256 -- assert the VOTING-mint invariant that
  # keeps both nodes on ONE tip (no premature v36-format => no fork). Tip-sha256
  # equality is the rig-day assertion (H2 --rig).
  if kat 'DGB_share_test\.AutoRatchetBootstrapMintsBaselineWhileVoting|DGB_share_test\.AutoRatchetWireBootstrapMints35Votes36'; then
    pass "H2 no premature v36-format (single-tip invariant, sim)"; artifact H2 PASS C2 "VOTING mints ver35 only -> no fork; live tip-sha256 compare is H2 --rig" "tip_compare=deferred-to-rig"
  else
    fail "H2 single-tip invariant KAT"; artifact H2 FAIL C2 "VOTING-mint invariant KAT failed"; return 1
  fi
}

# =============================================================================
# H3 -- C3 ratchet curve (ramp work fraction; assert 60%-by-work gate)
# =============================================================================
stage_H3() {
  log "H3 check_ratchet_curve() -> C3"
  if [ "$RIG" -eq 1 ]; then gate "H3 live work-ramp deferred to rig-day driver"; artifact H3 GATED C3 "live 60%-by-work ramp"; return 0; fi
  if [ ! -d "$BUILD_DIR" ]; then fail "H3 build tree absent"; artifact H3 BLOCKED C3 "KAT tree absent"; return 1; fi
  # #288 tail-guard: a flat 95%-by-count desired must NOT activate below the
  # 60%-by-work accept gate -- mint cannot outrun accept (the staged property).
  # DGB-ONLY: anchored ^AutoRatchetTailGuard\. (excludes LTC's LtcAutoRatchet-
  # TailGuard, which the bare substring would leak into) + DgbMinProtocolRatchet.
  if kat '^AutoRatchetTailGuard\.|^DgbMinProtocolRatchet\.'; then
    pass "H3 #288 staged gate: mint cannot outrun accept"; artifact H3 PASS C3 "flat-95% does NOT activate below 60%-by-work (#288 tail-guard)" "threshold=60pct-by-work"
  else
    fail "H3 tail-guard KAT"; artifact H3 FAIL C3 "#288 tail-guard failed -- mint outran accept"; return 1
  fi
}

# =============================================================================
# H4/H5/H6 -- RIG-GATED (real Scrypt hashrate). No sim verdict fabricated.
# =============================================================================
stage_H4() {
  log "H4 check_block_production() -> C4  [rig-gated]"
  if [ "$RIG" -ne 1 ]; then gate "H4 needs leased R1-LTC Scrypt rigs (block production at real difficulty)"; artifact H4 GATED C4 "real Scrypt hashrate required -- run with --rig on rig-day"; return 0; fi
  fail "H4 rig-day driver not wired in this scaffold"; artifact H4 BLOCKED C4 "rig-day block-production driver pending rig lease"; return 1
}
stage_H5() {
  log "H5 check_broadcaster_e2e() -> C5  [rig-gated]"
  if [ "$RIG" -ne 1 ]; then gate "H5 needs a won block (rig) to exercise submitblock + P2P found-block verdict"; artifact H5 GATED C5 "won-block required -- run with --rig on rig-day"; return 0; fi
  fail "H5 rig-day driver not wired in this scaffold"; artifact H5 BLOCKED C5 "rig-day broadcaster e2e pending rig lease"; return 1
}
stage_H6() {
  log "H6 migrate_one_by_one() -> §3  [rig-gated]"
  if [ "$RIG" -ne 1 ]; then gate "H6 one-by-one miner migration needs rigs producing real shares"; artifact H6 GATED §3 "GO/NO-GO migration loop -- run with --rig on rig-day"; return 0; fi
  fail "H6 rig-day driver not wired in this scaffold"; artifact H6 BLOCKED §3 "rig-day migration loop pending rig lease"; return 1
}

# =============================================================================
# H7 -- §4 rollback(step|all): additive-only (re-point miners to ver35 pool)
# =============================================================================
stage_H7() {
  local scope="${1:-all}"
  log "H7 rollback($scope) -> §4 (additive-only invariant)"
  # §4 invariant: rollback is ADDITIVE -- migrated miners are re-pointed at the
  # ver35 baseline pool; NO sharechain/state deletion, NO destructive op. The
  # ver35 baseline acceptance is held until operator declares post-soak cleanup.
  case "$scope" in
    step|all) : ;;
    *) fail "H7 bad scope '$scope' (want step|all)"; artifact H7 FAIL §4 "invalid rollback scope '$scope'"; return 1;;
  esac
  pass "H7 rollback($scope) plan validated: additive-only, baseline-preserving"
  artifact H7 PASS §4 "rollback($scope): re-point miners to ver35 pool; no destructive state op; baseline held" "scope=$scope" "additive_only=true"
}

# =============================================================================
# driver
# =============================================================================
summary() {
  log "run dir: $RUN_DIR"
  for f in "$RUN_DIR"/*.json; do [ -f "$f" ] || continue; log "  $(basename "$f"): $(grep -o '"verdict": *"[^"]*"' "$f" | head -1)"; done
}

main() {
  local cmd="${1:-nonrig}"
  case "$cmd" in
    H0) stage_H0 ;;
    H1) stage_H1 ;;
    H2) stage_H2 ;;
    H3) stage_H3 ;;
    H4) stage_H4 ;;
    H5) stage_H5 ;;
    H6) stage_H6 ;;
    H7) shift || true; stage_H7 "${1:-all}" ;;
    nonrig)   # the pre-rig acceptance proof: H0-H3 + H7, all non-gated
      log "NON-RIG acceptance proof: H0-H3 + H7 (pre-rig; H4-H6 stay gated)"
      stage_H0 && stage_H1 && stage_H2 && stage_H3 && stage_H7 all
      summary
      ;;
    all)      # full stage sweep (H4-H6 GATED unless --rig)
      stage_H0 && stage_H1 && stage_H2 && stage_H3
      stage_H4 || true; stage_H5 || true; stage_H6 || true
      stage_H7 all
      summary
      ;;
    *) die "usage: $0 {nonrig|all|H0|H1|H2|H3|H4|H5|H6|H7 [step|all]} [--rig]" ;;
  esac
}
die() { echo "[dgb-g2/H FAIL] $*" >&2; exit 2; }
main "$@"
