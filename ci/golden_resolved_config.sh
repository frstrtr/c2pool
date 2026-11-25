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
#   * --version (exit 0, `c2pool-<coin> <version>[ key=value...]`) on every binary,
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
  "dgb|v3|--run -f 0.5 --give-author 0.2 --node-owner-address DExampleDgbAddress"
  "bch|v1|"
  "bch|v2|--testnet --p2p-port 9350 --stratum 3333"
  "bch|v3|--pool -f 0.5 --give-author 0.2 --node-owner-address bitcoincash:qexample"
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

# Present-check integrity (the zero-test-run lesson, strengthened): this gate is
# REGISTERED only where the coin binaries are built (see the CMake option
# C2POOL_GOLDEN_RESOLVED_CONFIG_GATE); the sanitizer lane, which builds no coin
# binaries, does not register it at all. So when the gate DOES run in verify
# mode, EVERY coin binary must be present -- a missing one is a NO-SHIP FAILURE,
# never a silent per-binary skip that could let the release leg green vacuously
# over a coin whose build was dropped. --capture keeps the lenient behaviour so
# fixtures can be regenerated from whatever subset is built.
if [ "$MODE" != "--capture" ]; then
  missing=""
  for coin in dash ltc btc dgb bch; do
    [ -x "$BINDIR/c2pool-$coin" ] || missing="$missing c2pool-$coin"
  done
  if [ -n "$missing" ]; then
    echo "FAIL: coin binaries missing under $BINDIR -- golden gate is a hard present-check and cannot run:$missing"
    echo "      (registered only where the coin binaries are built; a missing binary is NO-SHIP, not a skip)"
    exit 1
  fi
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

echo "== --version (expect exit 0, 'c2pool-<coin> <version>[ key=value...]') =="
# The version line is the last stdout line; dash prints its [init] lines before
# it, the other binaries print that line only.
for coin in dash ltc btc dgb bch; do
  bin="$BINDIR/c2pool-$coin"; [ -x "$bin" ] || continue
  out="$("$bin" --version 2>/dev/null)"; rc=$?
  last="$(printf '%s\n' "$out" | tail -n 1)"
  nlines="$(printf '%s\n' "$out" | wc -l | tr -d ' ')"
  if [ "$rc" -eq 0 ] && printf '%s\n' "$last" | grep -qE "^c2pool-$coin [^ ]+( [a-z]+=[^ ]+)*\$" \
     && { [ "$coin" = dash ] || [ "$nlines" -eq 1 ]; }; then
    echo "ok   $coin --version: $last"
  else
    echo "FAIL $coin --version exit=$rc lines=$nlines last='$last'"; fails=$((fails+1))
  fi
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

# c2pool-ltc --import-found-blocks FILE: a bad value is refused while the flags
# are parsed (exit 1, no dump), never swallowed. `--import-found-blocks
# --testnet` dropped network.testnet=true (a mainnet node), and a second file
# given without its own flag became the positional RPC user.
echo "== ltc --import-found-blocks values (bad value => exit 1, no dump) =="
if [ -x "$BINDIR/c2pool-ltc" ]; then
  fbi_dd="$(mktemp -d)"
  printf '[]' > "$fbi_dd/a.json"; printf '[]' > "$fbi_dd/b.json"
  fbi_case() {  # want_rc label args...
    local want="$1" label="$2"; shift 2
    local out; out="$("$BINDIR/c2pool-ltc" --data-dir "$fbi_dd" "$@" --dump-resolved-config 2>/dev/null)"
    local rc=$?
    local dumped=0; printf '%s' "$out" | grep -q "$BEGIN" && dumped=1
    local ok=0   # a refusal prints no dump; an accepted value dumps
    if [ "$want" -eq 0 ]; then [ "$dumped" -eq 1 ] && ok=1; else [ "$dumped" -eq 0 ] && ok=1; fi
    if [ "$rc" -eq "$want" ] && [ "$ok" -eq 1 ]; then
      echo "ok   ltc $label (exit $rc)"
    else
      echo "FAIL ltc $label exit=$rc (want $want) dumped=$dumped"; fails=$((fails+1))
    fi
  }
  fbi_case 1 "value is an option (--testnet)" --import-found-blocks --testnet
  fbi_case 1 "missing file" --import-found-blocks "$fbi_dd/none.json"
  fbi_case 1 "a directory" --import-found-blocks "$fbi_dd"
  fbi_case 1 "second file without its own flag" --import-found-blocks "$fbi_dd/a.json" "$fbi_dd/b.json"
  fbi_case 0 "two files, flag twice" --import-found-blocks "$fbi_dd/a.json" --import-found-blocks "$fbi_dd/b.json"
  fbi_case 0 "two files, comma list" --import-found-blocks "$fbi_dd/a.json,$fbi_dd/b.json"
  rm -rf "$fbi_dd"
fi

# c2pool-btc --import-found-blocks FILE: the same refusals, while the flags are
# parsed (src/impl/btc/found_block_ledger.hpp take_import_flags).
echo "== btc --import-found-blocks values (bad value => exit 1, no dump) =="
if [ -x "$BINDIR/c2pool-btc" ]; then
  fbb_dd="$(mktemp -d)"
  printf '[]' > "$fbb_dd/a.json"; printf '[]' > "$fbb_dd/b.json"
  fbb_case() {  # want_rc label args...
    local want="$1" label="$2"; shift 2
    local out; out="$("$BINDIR/c2pool-btc" --data-dir "$fbb_dd" "$@" --dump-resolved-config 2>/dev/null)"
    local rc=$?
    local dumped=0; printf '%s' "$out" | grep -q "$BEGIN" && dumped=1
    local ok=0   # a refusal prints no dump; an accepted value dumps
    if [ "$want" -eq 0 ]; then [ "$dumped" -eq 1 ] && ok=1; else [ "$dumped" -eq 0 ] && ok=1; fi
    if [ "$rc" -eq "$want" ] && [ "$ok" -eq 1 ]; then
      echo "ok   btc $label (exit $rc)"
    else
      echo "FAIL btc $label exit=$rc (want $want) dumped=$dumped"; fails=$((fails+1))
    fi
  }
  fbb_case 1 "value is an option (--testnet)" --import-found-blocks --testnet
  fbb_case 1 "missing file" --import-found-blocks "$fbb_dd/none.json"
  fbb_case 1 "a directory" --import-found-blocks "$fbb_dd"
  fbb_case 1 "second file without its own flag" --import-found-blocks "$fbb_dd/a.json" "$fbb_dd/b.json"
  fbb_case 0 "two files, flag twice" --import-found-blocks "$fbb_dd/a.json" --import-found-blocks "$fbb_dd/b.json"
  fbb_case 0 "two files, comma list" --import-found-blocks "$fbb_dd/a.json,$fbb_dd/b.json"
  rm -rf "$fbb_dd"
fi

if [ "$fails" -eq 0 ]; then echo; echo "golden_resolved_config: ALL PASS"; exit 0; fi
echo; echo "golden_resolved_config: $fails FAILURE(S)"; exit 1
