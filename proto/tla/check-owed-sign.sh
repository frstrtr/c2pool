#!/bin/sh
# Reproduce the owed-sign model checks for Settlement.tla (revision 2, see ERRATA.md).
#
#   proto/tla/check-owed-sign.sh <path/to/tla2tools.jar> [out-dir]
#
# Runs, one after another, and prints one verdict line per run:
#   base-red    the ORIGINAL model (BASE_REV) with owed widened to Int and one added action
#               (a pool block whose credit row may be negative)  -> expect NoNegativeOwed violated
#   fix         Settlement.cfg on the revised model                -> expect no error
#   noC4        Settlement_noC4.cfg (C-4 floor off)                -> expect KeyFloor violated
#   clawback    Settlement_clawback.cfg (clawback on)              -> expect NoClawback violated
#   nomass      Settlement_nomass.cfg (delta mass rule off)        -> expect AggregateNonNeg violated
#   wit-neg     witness: a key does go negative in the fix         -> expect WitNoNegative violated
#   wit-resid   witness: a SETTLED orphan residual is reachable    -> expect WitNoResidual violated
# Env: TLC_WORKERS (default 6), TLC_HEAP (default 8g), BASE_REV (default adc5cb88).
# Exit status 0 only if every run matches its expectation.
set -eu
JAR=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
OUT=${2:-./tlc-owed-sign-out}
WORKERS=${TLC_WORKERS:-6}
HEAP=${TLC_HEAP:-8g}
BASE_REV=${BASE_REV:-adc5cb88}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
FAIL=0

# run <name> <tla-file> <cfg-file> [extra module file]
run() {
    d="$OUT/$1"; rm -rf "$d"; mkdir -p "$d"
    cp "$2" "$d/Settlement.tla"; cp "$3" "$d/run.cfg"
    [ $# -ge 4 ] && cp "$4" "$d/"
    main=Settlement.tla; [ $# -ge 4 ] && main=$(basename "$4")
    ( cd "$d" && java -Xmx"$HEAP" -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
        -workers "$WORKERS" -metadir "$d/states" -config run.cfg "$main" ) \
        > "$OUT/$1.log" 2>&1 < /dev/null || true
    rm -rf "$d/states"
}

# expect <name> <grep pattern>
expect() {
    log="$OUT/$1.log"
    ds=$(grep -o '[0-9,]* distinct states found' "$log" | tail -1 | cut -d' ' -f1)
    dp=$(grep -o 'depth of the complete state graph search is [0-9]*' "$log" | awk '{print $NF}')
    if grep -q "$2" "$log"; then v=PASS; else v=FAIL; FAIL=1; fi
    echo "$v $1 expect='$2' distinct=${ds:-?} depth=${dp:--} log=$log"
}

# base-red: original model + one negative-credit action
git -C "$HERE" show "$BASE_REV:proto/tla/Settlement.tla" > "$OUT/base.tla"
git -C "$HERE" show "$BASE_REV:proto/tla/Settlement.cfg" > "$OUT/base.cfg"
sed -e 's/^EXTENDS Naturals, FiniteSets, Sequences, TLC$/EXTENDS Integers, FiniteSets, Sequences, TLC/' \
    -e 's/owed \\in \[ Miners -> Nat \]/owed \\in [ Miners -> Int ]/' "$OUT/base.tla" |
awk '/^Next ==$/ {
       print "\\* ADDED (base-red only): a DROPS credit row with E_b + Hhat - W_shares < 0."
       print "NegCreditFound(credit, payout) == BlockFound(credit, payout)"; print ""; print
       print "    \\/ \\E c \\in [ Miners -> -MaxReward..0 ], p \\in [ Miners -> 0..MaxReward ] : NegCreditFound(c, p)"
       next }
     { print }' > "$OUT/base-red.tla"
grep -q 'NegCreditFound(c, p)' "$OUT/base-red.tla"
grep -q '^EXTENDS Integers' "$OUT/base-red.tla"
run base-red "$OUT/base-red.tla" "$OUT/base.cfg"
expect base-red 'Invariant NoNegativeOwed is violated'

run fix "$HERE/Settlement.tla" "$HERE/Settlement.cfg"
expect fix 'No error has been found'
run noC4 "$HERE/Settlement.tla" "$HERE/Settlement_noC4.cfg"
expect noC4 'Invariant KeyFloor is violated'
run clawback "$HERE/Settlement.tla" "$HERE/Settlement_clawback.cfg"
expect clawback 'Action property NoClawback is violated'
run nomass "$HERE/Settlement.tla" "$HERE/Settlement_nomass.cfg"
expect nomass 'Invariant AggregateNonNeg is violated'

# witnesses: the negative and residual paths are reachable in the fix config
cat > "$OUT/SettlementWitness.tla" <<'EOF'
---------------------------- MODULE SettlementWitness ----------------------------
EXTENDS Settlement
WitNoNegative == \A m \in Miners : owed[m] >= 0
WitNoResidual == residual = 0
=============================================================================
EOF
for w in NoNegative NoResidual; do
    sed -e '/^INVARIANT /d' -e '/^PROPERTY /d' "$HERE/Settlement.cfg" > "$OUT/wit.cfg"
    echo "INVARIANT Wit$w" >> "$OUT/wit.cfg"
    n=$(echo "$w" | sed 's/NoNegative/wit-neg/; s/NoResidual/wit-resid/')
    run "$n" "$HERE/Settlement.tla" "$OUT/wit.cfg" "$OUT/SettlementWitness.tla"
    expect "$n" "Invariant Wit$w is violated"
done
echo "sha256(tla2tools.jar) $(sha256sum "$JAR" | cut -d' ' -f1)"
exit $FAIL
