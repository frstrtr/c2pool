#!/bin/sh
# Reproduce the model checks for SettlementCanon.tla (the lane coinbase recompute).
#
#   proto/tla/check-settlement-canon.sh <path/to/tla2tools.jar> [out-dir]
#
# Runs, one after another, and prints one verdict line per run:
#   green                 SettlementCanon.cfg                      -> expect no error
#   green-debt            SettlementCanon_debt.cfg                 -> expect no error
#   green-noslot          SettlementCanon_noslot.cfg (no slot)     -> expect no error
#   unreach-main          degenerate_keep_credit on SettlementCanon.cfg      -> expect no error
#   unreach-debt          degenerate_keep_credit on SettlementCanon_debt.cfg -> expect no error
#                         (with a slot, a block always has a payee output: the degenerate
#                         case is unreachable there, so that mutation changes nothing)
# Negative controls (Mutation = ...; each must be caught):
#   mut-foreign-credit    a debit-only block keeps its credit      -> NonCanonicalEarnsNothing
#   mut-authority         no verdict: a mismatch books as canonical -> UnpaidKeyNeverNegative
#                         or LedgerWithinFloat (two 3-state counterexamples; the first found wins)
#   mut-authority-cnn     the same, CanonicalNeverNegative alone   -> CanonicalNeverNegative
#   mut-advance           redistributed cash paid, not credited    -> UnpaidKeyNeverNegative
#   mut-advance-na        the same, NoAdvance alone                -> NoAdvance
#   mut-debt-unbounded    debt pass ignores owed_left (debt cfg)   -> UnpaidKeyNeverNegative
#   mut-redist-nobody     nobody admitted: credit off, cash to nobody -> RedistributionNeutral
#   mut-keep-unbacked     nobody admitted: credit kept, cash to residual -> LedgerWithinFloat
#   mut-degenerate-keep   no payee output: credit kept (noslot cfg) -> LedgerWithinFloat
#   mut-held-debit        an undecidable block booked debit-only   -> HonestIsCanonical
#   mut-nogate            builder without the booking-point gate   -> HonestIsCanonical
# Reachability witnesses (each must be violated, i.e. the path is reached):
#   wit-negative          a debit-only block drives a key negative
#   wit-redistribution    the credit_delta moves credit
#   wit-held              a block is held
#   wit-leftover-to-owed  nobody admitted, the owed-paid payees take the moved cash
#   wit-debt-first        the debt-first step pays a balance (debt cfg)
# Env: TLC_WORKERS (default 6), TLC_HEAP (default 8g).
# Exit status 0 only if every run matches its expectation.
set -eu
JAR=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
OUT=${2:-./tlc-settlement-canon-out}
WORKERS=${TLC_WORKERS:-6}
HEAP=${TLC_HEAP:-8g}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
FAIL=0

# run <name> <base cfg> [<Mutation> [<only line>]]
#   the base cfg, with Mutation set and, if given, every INVARIANT/PROPERTY line
#   replaced by the one line
run() {
    d="$OUT/$1"; rm -rf "$d"; mkdir -p "$d"
    cp "$HERE/SettlementCanon.tla" "$d/"
    sed "s/Mutation = \"none\"/Mutation = \"${3:-none}\"/" "$HERE/$2" > "$d/run.cfg"
    grep -q "Mutation = \"${3:-none}\"" "$d/run.cfg"
    if [ $# -ge 4 ]; then
        sed -e '/^INVARIANT /d' -e '/^PROPERTY /d' "$d/run.cfg" > "$d/only.cfg"
        echo "$4" >> "$d/only.cfg"
        mv "$d/only.cfg" "$d/run.cfg"
    fi
    ( cd "$d" && java -Xmx"$HEAP" -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
        -workers "$WORKERS" -metadir "$d/states" -config run.cfg SettlementCanon.tla ) \
        > "$OUT/$1.log" 2>&1 < /dev/null || true
    rm -rf "$d/states"
}

# expect <name> <grep pattern>
expect() {
    log="$OUT/$1.log"
    ds=$(grep -o '[0-9,]* distinct states found' "$log" | tail -1 | cut -d' ' -f1)
    dp=$(grep -o 'depth of the complete state graph search is [0-9]*' "$log" | awk '{print $NF}')
    tr=$(grep -c '^State [0-9]*:' "$log" || true)
    if grep -q -E "$2" "$log"; then v=PASS; else v=FAIL; FAIL=1; fi
    echo "$v $1 expect='$2' distinct=${ds:-?} depth=${dp:--} trace=${tr} log=$log"
}

run green SettlementCanon.cfg
expect green 'No error has been found'
run green-debt SettlementCanon_debt.cfg
expect green-debt 'No error has been found'
run green-noslot SettlementCanon_noslot.cfg
expect green-noslot 'No error has been found'
run unreach-main SettlementCanon.cfg degenerate_keep_credit
expect unreach-main 'No error has been found'
run unreach-debt SettlementCanon_debt.cfg degenerate_keep_credit
expect unreach-debt 'No error has been found'

run mut-foreign-credit SettlementCanon.cfg foreign_credit
expect mut-foreign-credit 'Invariant NonCanonicalEarnsNothing is violated'
run mut-authority SettlementCanon.cfg authority
expect mut-authority 'Invariant (UnpaidKeyNeverNegative|LedgerWithinFloat) is violated'
run mut-authority-cnn SettlementCanon.cfg authority 'PROPERTY CanonicalNeverNegative'
expect mut-authority-cnn 'Action property CanonicalNeverNegative is violated'
run mut-advance SettlementCanon.cfg advance
expect mut-advance 'Invariant UnpaidKeyNeverNegative is violated'
run mut-advance-na SettlementCanon.cfg advance 'PROPERTY NoAdvance'
expect mut-advance-na 'Action property NoAdvance is violated'
run mut-debt-unbounded SettlementCanon_debt.cfg debt_unbounded
expect mut-debt-unbounded 'Invariant UnpaidKeyNeverNegative is violated'
run mut-redist-nobody SettlementCanon.cfg redistribute_to_nobody
expect mut-redist-nobody 'Invariant RedistributionNeutral is violated'
run mut-keep-unbacked SettlementCanon.cfg keep_credit_unbacked
expect mut-keep-unbacked 'Invariant LedgerWithinFloat is violated'
run mut-degenerate-keep SettlementCanon_noslot.cfg degenerate_keep_credit
expect mut-degenerate-keep 'Invariant LedgerWithinFloat is violated'
run mut-held-debit SettlementCanon.cfg held_debit
expect mut-held-debit 'Invariant HonestIsCanonical is violated'
run mut-nogate SettlementCanon.cfg nogate
expect mut-nogate 'Invariant HonestIsCanonical is violated'

run wit-negative SettlementCanon.cfg none 'INVARIANT WitNoNegative'
expect wit-negative 'Invariant WitNoNegative is violated'
run wit-redistribution SettlementCanon.cfg none 'INVARIANT WitNoRedistribution'
expect wit-redistribution 'Invariant WitNoRedistribution is violated'
run wit-held SettlementCanon.cfg none 'INVARIANT WitNoHeld'
expect wit-held 'Invariant WitNoHeld is violated'
run wit-leftover-to-owed SettlementCanon.cfg none 'PROPERTY WitNoLeftoverToOwed'
expect wit-leftover-to-owed 'Action property WitNoLeftoverToOwed is violated'
run wit-debt-first SettlementCanon_debt.cfg none 'PROPERTY WitNoDebtFirst'
expect wit-debt-first 'Action property WitNoDebtFirst is violated'

echo "sha256(tla2tools.jar) $(sha256sum "$JAR" | cut -d' ' -f1)"
exit $FAIL
