#!/usr/bin/env bash
# ci/golden_resolved_config.sh  (M0b)
#
# The HARD GATE for the control-plane mains wiring: with NO settings file, the
# resolved config each binary reports via --dump-resolved-config, over a fixed
# CLI-vector matrix, must be BYTE-IDENTICAL to a committed golden fixture. A diff
# on any binary means its no-file resolution changed => NO-SHIP that binary.
#
# The fixtures are the permanent regression tripwire: any future change to the
# catalog, the compiled defaults, or a main's flag set that alters no-file
# resolution must update these fixtures under review, or CI fails here.
#
# It also runs the negative gates in the same instrument:
#   * unknown-flag rejection (exit 1) on every binary,
#   * the money-gate end-to-end (an unacked money key in a settings file =>
#     exit 78, no dump markers), on dash + btc + dgb.
#
# Usage:
#   ci/golden_resolved_config.sh <build_bin_dir> [--capture]
#     <build_bin_dir>  dir holding c2pool-dash/-ltc/-btc/-dgb/-bch
#     --capture        (re)write fixtures instead of verifying
#
# Normalization: LC_ALL=C; extract strictly between the BEGIN/END markers (so no
# startup banner contaminates); substitute the ephemeral --data-dir with
# <DATADIR>. rc.dump() is already sorted (std::map) and carries no timestamps.
set -u

BINDIR="${1:?usage: golden_resolved_config.sh <build_bin_dir> [--capture]}"
MODE="${2:-verify}"
HERE="$(cd "$(dirname "$0")" && pwd)"
FIXDIR="$(cd "$HERE/.." && pwd)/test/fixtures/resolved"
BEGIN="=== RESOLVED CONFIG BEGIN ==="
END="=== RESOLVED CONFIG END ==="
export LC_ALL=C
mkdir -p "$FIXDIR"

fails=0

# Vector matrix: "coin|vN|<cli args>" (WITHOUT --data-dir / --dump-resolved-config,
# which the harness adds). Money-CLI vectors exercise the ungated CLI money path.
VECTORS=(
  "dash|v1|"
  "dash|v2|--testnet --stratum 0.0.0.0:17903 --web-port 8081 --coin-p2p-discover --embedded-serve-mempool-txs=false --redistribute pplns"
  "dash|v3|-f 0.5 --give-author 0.2 --node-owner-address XyZmoneyDest"
  "ltc|v1|"
  "ltc|v2|--testnet --no-embedded-doge --web-port 8081 --worker-port 9327"
  "btc|v1|"
  "btc|v2|--testnet4 --sharechain-port 9334 --coin-p2p-discover"
  "dgb|v1|"
  "dgb|v2|--run --stratum 7902 --http 8081 --coin-p2p-discover --sharechain-port 5025"
  "bch|v1|"
  "bch|v2|--testnet --p2p-port 9350 --stratum 3333"
)

capture_one() {  # coin vN args -> normalized dump on stdout
  local coin="$1" vN="$2" args="$3"
  local bin="$BINDIR/c2pool-$coin"
  local dd; dd="$(mktemp -d)"
  # shellcheck disable=SC2086
  local out; out="$("$bin" --data-dir "$dd" $args --dump-resolved-config 2>/dev/null)"
  # extract between markers, normalize the datadir path
  printf '%s\n' "$out" | awk -v b="$BEGIN" -v e="$END" '
      $0==b {on=1; next} $0==e {on=0} on {print}' \
    | sed "s#$dd#<DATADIR>#g"
  rm -rf "$dd"
}

# Instrument-validity floor (the zero-test-run lesson): if NOT ONE coin binary
# is present, the gate would pass vacuously. Fail loudly instead.
present=0
for coin in dash ltc btc dgb bch; do [ -x "$BINDIR/c2pool-$coin" ] && present=$((present+1)); done
if [ "$present" -eq 0 ] && [ "$MODE" != "--capture" ]; then
  echo "FAIL: no coin binaries under $BINDIR -- golden gate cannot run (instrument-validity floor)"
  exit 1
fi

echo "== golden resolved-config matrix =="
for v in "${VECTORS[@]}"; do
  IFS='|' read -r coin vN args <<< "$v"
  bin="$BINDIR/c2pool-$coin"
  [ -x "$bin" ] || { echo "SKIP $coin/$vN (no binary $bin)"; continue; }
  fix="$FIXDIR/${coin}_${vN}.golden"
  got="$(capture_one "$coin" "$vN" "$args")"
  if [ -z "$got" ]; then echo "FAIL $coin/$vN: empty dump (markers missing?)"; fails=$((fails+1)); continue; fi
  if [ "$MODE" = "--capture" ]; then
    printf '%s\n' "$got" > "$fix"
    echo "captured $fix ($(wc -l < "$fix") lines)"
  else
    if [ ! -f "$fix" ]; then echo "FAIL $coin/$vN: fixture missing ($fix)"; fails=$((fails+1)); continue; fi
    if diff -u "$fix" <(printf '%s\n' "$got") >/tmp/golden_diff.$$ 2>&1; then
      echo "ok   $coin/$vN byte-identical"
    else
      echo "FAIL $coin/$vN DIFFERS:"; cat /tmp/golden_diff.$$; fails=$((fails+1))
    fi
    rm -f /tmp/golden_diff.$$
  fi
done

if [ "$MODE" = "--capture" ]; then
  echo "capture done."; exit 0
fi

echo "== unknown-flag rejection (expect exit 1) =="
for coin in dash ltc btc dgb bch; do
  bin="$BINDIR/c2pool-$coin"; [ -x "$bin" ] || continue
  "$bin" --this-is-not-a-real-flag >/dev/null 2>&1; rc=$?
  if [ "$rc" -eq 1 ]; then echo "ok   $coin rejects unknown flag (exit 1)"; \
  else echo "FAIL $coin unknown-flag exit=$rc (want 1)"; fails=$((fails+1)); fi
done

echo "== money-gate end-to-end (unacked money key => exit 78, no dump) =="
money_e2e() {  # coin section
  local coin="$1" section="$2"
  local bin="$BINDIR/c2pool-$coin"; [ -x "$bin" ] || return 0
  local dd; dd="$(mktemp -d)"; local f="$dd/c2pool.toml"
  printf '[%s]\nnode_owner_address = "XyZunackedMoney"\n' "$section" > "$f"
  local out; out="$("$bin" --data-dir "$dd" --settings "$f" --dump-resolved-config 2>&1)"; local rc=$?
  if [ "$rc" -eq 78 ] && ! printf '%s' "$out" | grep -q "$BEGIN"; then
    echo "ok   $coin refuses unacked money key (exit 78, no dump)"
  else
    echo "FAIL $coin money-gate exit=$rc (want 78) or dump leaked"; fails=$((fails+1))
  fi
  rm -rf "$dd"
}
money_e2e dash dash.money
money_e2e btc  btc.money
money_e2e dgb  dgb.money

if [ "$fails" -eq 0 ]; then echo; echo "golden_resolved_config: ALL PASS"; exit 0; fi
echo; echo "golden_resolved_config: $fails FAILURE(S)"; exit 1
