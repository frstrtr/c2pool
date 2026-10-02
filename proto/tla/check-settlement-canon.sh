#!/bin/sh
# Reproduce the model checks for SettlementCanon.tla (the lane coinbase recompute with
# the drain rule of the operator rulings of 2026-10-02).
#
#   proto/tla/check-settlement-canon.sh <path/to/tla2tools.jar> [out-dir]
#
# Configs:
#   SettlementCanon.cfg         the drain rule, one payee slot (Reward 4, DrainQ 4, HCap 2)
#   SettlementCanon_ko.cfg      the drain rule, contested slots (3 keys, 2 slots: K_o)
#   SettlementCanon_noslot.cfg  the drain rule, no slot for any payee (the degenerate case)
#   SettlementCanon_master.cfg  master, DrainQ = 0 (owed pass on the whole block, window
#                               credited at R, DEBT FIRST)
#   SettlementCanon_len3.cfg    the drain rule over three blocks (TLC_LONG=1 only)
#
# Runs, one after another, one verdict line per run:
#   green, green-ko, green-noslot, green-master   every invariant of the cfg -> no error
#   unreach-main, unreach-master  degenerate_keep_credit where a block always has a payee
#                         output: the case is unreachable, the mutation changes nothing
# Negative controls of the drain rule (Mutation = ...; each checked against the named
# property alone, each must be caught):
#   mut-debt-first        DEBT FIRST kept                          -> NoNewOwed
#   mut-debt-first-float  the same                                 -> FloatNonIncreasing
#   mut-credit-at-r       window credited at R while Delta pays    -> NoNewOwed
#   mut-delta-unb         the owed pass draws on the whole block   -> DrainBound
#   mut-no-ko             contested: the owed pass keeps its slots -> SomeoneAdmitted (ko)
#   mut-no-ko-share       the same                                 -> SlotShare (ko)
#   mut-split-at-delta    P = R - the slice before the clamp by F  -> MasterWhenNoFloat
#   mut-hcap-full         no mutation; HCap = DrainQ (Delta up to R) and SeedMax 2 on the
#                         ko cfg: the lane-rules validity condition HCap < DrainQ is
#                         needed                                   -> SomeoneAdmitted
# Negative controls of the recompute (from the model before the rule; each checked
# against its property alone):
#   mut-foreign-credit    a debit-only block keeps its credit      -> NonCanonicalEarnsNothing
#   mut-authority         no verdict: a mismatch books as canonical -> UnpaidKeyNeverNegative
#                         or LedgerWithinFloat (both checked; the first found wins)
#   mut-authority-cnn     the same                                 -> CanonicalNeverNegative
#   mut-advance           redistributed cash paid, not credited    -> UnpaidKeyNeverNegative
#   mut-advance-na        the same                                 -> NoAdvance
#   mut-debt-unbounded    master's debt pass ignores owed_left     -> UnpaidKeyNeverNegative (master)
#   mut-redist-nobody     nobody admitted: credit off, cash to nobody -> RedistributionNeutral
#   mut-keep-unbacked     nobody admitted: credit kept, cash to residual -> LedgerWithinFloat
#   mut-degenerate-keep   no payee output: credit kept (noslot)    -> LedgerWithinFloat
#   mut-held-debit        an undecidable block booked debit-only   -> HonestIsCanonical
#   mut-nogate            builder without the booking-point gate   -> HonestIsCanonical
# Reachability witnesses (each must be violated, i.e. the path is reached):
#   wit-negative          a debit-only block drives a key negative
#   wit-redistribution    the credit_delta moves credit
#   wit-held              a block is held
#   wit-leftover-to-owed  nobody admitted, the owed-paid payees take the moved cash
#   wit-drain             a canonical block pays an old balance out of Delta
#   wit-split-at-p        the window is credited at P < R
#   wit-floor-fallback    a payee admitted, E_b(P) floored to 0, the owed-paid take the cash
#   wit-ko-cut            the K_o cap cuts an owed pass (ko)
#   wit-debt-first        master's debt-first step pays a balance (master)
#   wit-master-new-owed   master breaks NoNewOwed: its short pool leaves a balance (master)
# Optional (TLC_LONG=1): green-len3, SettlementCanon_len3.cfg (three blocks: a block is
# booked on a finalized predecessor; Reward 3, SeedMax 1, DrainQ 3), every invariant ->
# no error; tens of millions of states, minutes to tens of minutes.
# Env: TLC_WORKERS (default 6), TLC_HEAP (default 8g), TLC_LONG (default 0).
# Exit status 0 only if every run matches its expectation.
set -eu
JAR=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
OUT=${2:-./tlc-settlement-canon-out}
WORKERS=${TLC_WORKERS:-6}
HEAP=${TLC_HEAP:-8g}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
FAIL=0
NL='
'

# run <name> <base cfg> [<Mutation> [<only lines> [<sed script>]]]
#   the base cfg with Mutation set; if <only lines> is not empty, every INVARIANT and
#   PROPERTY line is replaced by those lines; if given, <sed script> edits the CONSTANTS
run() {
    d="$OUT/$1"; rm -rf "$d"; mkdir -p "$d"
    cp "$HERE/SettlementCanon.tla" "$d/"
    sed "s/Mutation = \"none\"/Mutation = \"${3:-none}\"/" "$HERE/$2" > "$d/run.cfg"
    grep -q "Mutation = \"${3:-none}\"" "$d/run.cfg"
    if [ -n "${4:-}" ]; then
        sed -e '/^INVARIANT /d' -e '/^PROPERTY /d' "$d/run.cfg" > "$d/only.cfg"
        printf '%s\n' "$4" >> "$d/only.cfg"
        mv "$d/only.cfg" "$d/run.cfg"
    fi
    if [ -n "${5:-}" ]; then
        sed -e "$5" "$d/run.cfg" > "$d/edit.cfg"
        cmp -s "$d/edit.cfg" "$d/run.cfg" && { echo "sed script changed nothing: $5" >&2; exit 2; }
        mv "$d/edit.cfg" "$d/run.cfg"
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

OK='No error has been found'

run green SettlementCanon.cfg
expect green "$OK"
run green-ko SettlementCanon_ko.cfg
expect green-ko "$OK"
run green-noslot SettlementCanon_noslot.cfg
expect green-noslot "$OK"
run green-master SettlementCanon_master.cfg
expect green-master "$OK"
if [ "${TLC_LONG:-0}" = 1 ]; then
    run green-len3 SettlementCanon_len3.cfg
    expect green-len3 "$OK"
fi
run unreach-main SettlementCanon.cfg degenerate_keep_credit
expect unreach-main "$OK"
run unreach-master SettlementCanon_master.cfg degenerate_keep_credit
expect unreach-master "$OK"

run mut-debt-first SettlementCanon.cfg debt_first_on 'INVARIANT NoNewOwed'
expect mut-debt-first 'Invariant NoNewOwed is violated'
run mut-debt-first-float SettlementCanon.cfg debt_first_on 'PROPERTY FloatNonIncreasing'
expect mut-debt-first-float 'Action property FloatNonIncreasing is violated'
run mut-credit-at-r SettlementCanon.cfg credit_at_reward 'INVARIANT NoNewOwed'
expect mut-credit-at-r 'Invariant NoNewOwed is violated'
run mut-delta-unb SettlementCanon.cfg delta_unbounded 'PROPERTY DrainBound'
expect mut-delta-unb 'Action property DrainBound is violated'
run mut-no-ko SettlementCanon_ko.cfg no_ko 'PROPERTY SomeoneAdmitted'
expect mut-no-ko 'Action property SomeoneAdmitted is violated'
run mut-no-ko-share SettlementCanon_ko.cfg no_ko 'PROPERTY SlotShare'
expect mut-no-ko-share 'Action property SlotShare is violated'
run mut-split-at-delta SettlementCanon.cfg split_at_delta 'PROPERTY MasterWhenNoFloat'
expect mut-split-at-delta 'Action property MasterWhenNoFloat is violated'
run mut-hcap-full SettlementCanon_ko.cfg none 'PROPERTY SomeoneAdmitted' \
    's/SeedMax = 1/SeedMax = 2/; s/HCap = 2/HCap = 4/'
expect mut-hcap-full 'Action property SomeoneAdmitted is violated'

run mut-foreign-credit SettlementCanon.cfg foreign_credit 'INVARIANT NonCanonicalEarnsNothing'
expect mut-foreign-credit 'Invariant NonCanonicalEarnsNothing is violated'
run mut-authority SettlementCanon.cfg authority \
    "INVARIANT UnpaidKeyNeverNegative${NL}INVARIANT LedgerWithinFloat"
expect mut-authority 'Invariant (UnpaidKeyNeverNegative|LedgerWithinFloat) is violated'
run mut-authority-cnn SettlementCanon.cfg authority 'PROPERTY CanonicalNeverNegative'
expect mut-authority-cnn 'Action property CanonicalNeverNegative is violated'
run mut-advance SettlementCanon.cfg advance 'INVARIANT UnpaidKeyNeverNegative'
expect mut-advance 'Invariant UnpaidKeyNeverNegative is violated'
run mut-advance-na SettlementCanon.cfg advance 'PROPERTY NoAdvance'
expect mut-advance-na 'Action property NoAdvance is violated'
run mut-debt-unbounded SettlementCanon_master.cfg debt_unbounded 'INVARIANT UnpaidKeyNeverNegative'
expect mut-debt-unbounded 'Invariant UnpaidKeyNeverNegative is violated'
run mut-redist-nobody SettlementCanon.cfg redistribute_to_nobody 'INVARIANT RedistributionNeutral'
expect mut-redist-nobody 'Invariant RedistributionNeutral is violated'
run mut-keep-unbacked SettlementCanon.cfg keep_credit_unbacked 'INVARIANT LedgerWithinFloat'
expect mut-keep-unbacked 'Invariant LedgerWithinFloat is violated'
run mut-degenerate-keep SettlementCanon_noslot.cfg degenerate_keep_credit 'INVARIANT LedgerWithinFloat'
expect mut-degenerate-keep 'Invariant LedgerWithinFloat is violated'
run mut-held-debit SettlementCanon.cfg held_debit 'INVARIANT HonestIsCanonical'
expect mut-held-debit 'Invariant HonestIsCanonical is violated'
run mut-nogate SettlementCanon.cfg nogate 'INVARIANT HonestIsCanonical'
expect mut-nogate 'Invariant HonestIsCanonical is violated'

run wit-negative SettlementCanon.cfg none 'INVARIANT WitNoNegative'
expect wit-negative 'Invariant WitNoNegative is violated'
run wit-redistribution SettlementCanon.cfg none 'INVARIANT WitNoRedistribution'
expect wit-redistribution 'Invariant WitNoRedistribution is violated'
run wit-held SettlementCanon.cfg none 'INVARIANT WitNoHeld'
expect wit-held 'Invariant WitNoHeld is violated'
run wit-leftover-to-owed SettlementCanon.cfg none 'PROPERTY WitNoLeftoverToOwed'
expect wit-leftover-to-owed 'Action property WitNoLeftoverToOwed is violated'
run wit-drain SettlementCanon.cfg none 'PROPERTY WitNoDrain'
expect wit-drain 'Action property WitNoDrain is violated'
run wit-split-at-p SettlementCanon.cfg none 'INVARIANT WitNoSplitAtP'
expect wit-split-at-p 'Invariant WitNoSplitAtP is violated'
run wit-floor-fallback SettlementCanon.cfg none 'PROPERTY WitNoFloorFallback'
expect wit-floor-fallback 'Action property WitNoFloorFallback is violated'
run wit-ko-cut SettlementCanon_ko.cfg none 'PROPERTY WitNoKoCut'
expect wit-ko-cut 'Action property WitNoKoCut is violated'
run wit-debt-first SettlementCanon_master.cfg none 'PROPERTY WitNoDebtFirst'
expect wit-debt-first 'Action property WitNoDebtFirst is violated'
run wit-master-new-owed SettlementCanon_master.cfg none 'INVARIANT NoNewOwed'
expect wit-master-new-owed 'Invariant NoNewOwed is violated'

echo "sha256(tla2tools.jar) $(sha256sum "$JAR" | cut -d' ' -f1)"
exit $FAIL
