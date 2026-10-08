#!/bin/sh
# Model-check PathBRatchet.tla (the Path B rules ratchet) with TLC.
#
#   proto/tla/check-ratchet.sh <path/to/tla2tools.jar> [out-dir]
#
# Model values L 4 / GRACE 6 / TIMEOUT 9 / EPOCH_MAX 3 (small CI bounds; about
# 16 minutes on 4 workers).  Per-PR configs, one verdict line per run:
#   GREEN (no error, the whole space explored, distinct states and depth at
#   or above the floor given on its line):
#                                                G_A_n22 G_S_n22 G_B_n24 G_BS_n24
#                                                P_overlap36_MT
#   controls (the named invariant is violated):  C01 C02 C04b C05 C06 C09 C12a C13
#   finding probes (the encoded text is not the rule, so it stays violated):
#                                                P_strict_A_n22 P_strict_long_T
#                                                P_tipconv_T_adv2 P_overlap28_MS
#   witnesses (the scenario is reachable, so the witness invariant is violated):
#                                                W_rp_A W_rp_MT W_sc1 W_sc5 W_sc10
# Extended (TLC_LONG=1; about 95 minutes in all on 4 workers, GREEN with floors):
#                                                G_T_adv2_n18 G_M_n38 G_MT_n40
# Env: TLC_WORKERS (default 4), TLC_HEAP (default 4g), TLC_LONG (default 0).
# Exit status 0 only if every run matches its expectation.
set -eu
JAR=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
OUT=${2:-./tlc-ratchet-out}
WORKERS=${TLC_WORKERS:-4}
HEAP=${TLC_HEAP:-4g}
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=PathBRatchet
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
FAIL=0

# run <cfg>
run() {
    d="$OUT/$1"; rm -rf "$d"; mkdir -p "$d"
    cp "$HERE/$MOD.tla" "$d/"
    ( cd "$d" && java -Xmx"$HEAP" -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
        -workers "$WORKERS" -metadir "$d/states" -config "$HERE/$1.cfg" "$MOD.tla" ) \
        > "$OUT/$1.log" 2>&1 < /dev/null || true
    rm -rf "$d"
}

# expect <cfg> <grep pattern>
expect() {
    log="$OUT/$1.log"
    ds=$(grep -o '[0-9,]* distinct states found' "$log" | tail -1 | cut -d' ' -f1)
    if grep -qE "$2" "$log"; then v=PASS; else v=FAIL; FAIL=1; fi
    echo "$v $1 expect='$2' distinct=${ds:-?} log=$log"
}

OK='No error has been found'

# green <cfg> <min distinct> <min depth>: no error, an empty queue at the end,
# and at least <min distinct> distinct states at a depth of at least <min depth>.
green() {
    log="$OUT/$1.log"
    ds=$(sed -n 's/.* \([0-9][0-9]*\) distinct states found, 0 states left on queue.*/\1/p' "$log" | tail -1)
    dp=$(sed -n 's/.*depth of the complete state graph search is \([0-9][0-9]*\).*/\1/p' "$log" | tail -1)
    if grep -q "$OK" "$log" && [ "${ds:-0}" -ge "$2" ] && [ "${dp:-0}" -ge "$3" ]; then v=PASS; else v=FAIL; FAIL=1; fi
    echo "$v $1 expect='$OK' distinct=${ds:-?}>=$2 depth=${dp:-?}>=$3 log=$log"
}

run G_A_n22;        green G_A_n22        62429 28
run G_S_n22;        green G_S_n22        62293 28
run G_B_n24;        green G_B_n24        84067 30
run G_BS_n24;       green G_BS_n24       84904 30
run P_overlap36_MT; green P_overlap36_MT 206128 41

run C01_framehold;        expect C01_framehold        'Invariant HoldOnlyOnConfirmedLockIn is violated'
run C02_hellodesc;        expect C02_hellodesc        'Invariant FollowerNeverDiverges is violated'
run C04b_neverreuse_open; expect C04b_neverreuse_open 'Invariant ReProposalOpen is violated'
run C05_tailyes;          expect C05_tailyes          'Invariant NoSpuriousHold is violated'
run C06_r5eimpl;          expect C06_r5eimpl          'Invariant PrefixEImpl is violated'
run C09_norulescur;       expect C09_norulescur       'Invariant JoinerAgreesWithFollower is violated'
run C12a_pendingtally;    expect C12a_pendingtally    'Invariant SameActivation is violated'
run C13_stales;           expect C13_stales           'Invariant RsRootIsFunctionOfChain is violated'

run P_strict_A_n22;       expect P_strict_A_n22       'Invariant NoSpuriousHold is violated'
run P_strict_long_T;      expect P_strict_long_T      'Invariant NoSpuriousHold is violated'
run P_tipconv_T_adv2;     expect P_tipconv_T_adv2     'Invariant NoSpuriousHold is violated'
run P_overlap28_MS;       expect P_overlap28_MS       'Invariant ActiveEqualsHoldTrigger is violated'

run W_rp_A;               expect W_rp_A               'Invariant RPWitness is violated'
run W_rp_MT;              expect W_rp_MT              'Invariant RPWitness is violated'
run W_sc1;                expect W_sc1                'Invariant Sc1 is violated'
run W_sc5;                expect W_sc5                'Invariant Sc5 is violated'
run W_sc10;               expect W_sc10               'Invariant Sc10 is violated'

if [ "${TLC_LONG:-0}" = 1 ]; then
    run G_T_adv2_n18; green G_T_adv2_n18 47389 21
    run G_M_n38;      green G_M_n38      1613127 44
    run G_MT_n40;     green G_MT_n40     1485356 46
fi

echo "sha256(tla2tools.jar) $(sha256sum "$JAR" | cut -d' ' -f1)"
exit $FAIL
