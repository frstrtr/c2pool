#!/bin/sh
# Model-check PathBRatchet.tla (the Path B rules ratchet) with TLC.
#
#   proto/tla/check-ratchet.sh <path/to/tla2tools.jar> [out-dir]
#
# Model values L 4 / GRACE 6 / TIMEOUT 9 / EPOCH_MAX 3 (small CI bounds; a few
# minutes).  Per-PR configs, one verdict line per run:
#   GREEN (all 13 invariants hold):              G_A_n22 G_S_n22 G_B_n24 G_BS_n24
#   controls (the named invariant is violated):  C01 C02 C04b C05 C06 C09 C12a C13
#   finding probes (the encoded text is not the rule, so it stays violated):
#                                                P_strict_A_n22 P_tipconv_T_adv2
#   witnesses (the scenario is reachable, so the witness invariant is violated):
#                                                W_rp_A W_sc1 W_sc5 W_sc10
# Extended (TLC_LONG=1; minutes to ~1 h, GREEN):  G_T_adv2_n18 G_M_n38
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

for t in G_A_n22 G_S_n22 G_B_n24 G_BS_n24; do run "$t"; expect "$t" "$OK"; done

run C01_framehold;        expect C01_framehold        'Invariant HoldOnlyOnConfirmedLockIn is violated'
run C02_hellodesc;        expect C02_hellodesc        'Invariant FollowerNeverDiverges is violated'
run C04b_neverreuse_open; expect C04b_neverreuse_open 'Invariant ReProposalOpen is violated'
run C05_tailyes;          expect C05_tailyes          'Invariant NoSpuriousHold is violated'
run C06_r5eimpl;          expect C06_r5eimpl          'Invariant PrefixEImpl is violated'
run C09_norulescur;       expect C09_norulescur       'Invariant JoinerAgreesWithFollower is violated'
run C12a_pendingtally;    expect C12a_pendingtally    'Invariant SameActivation is violated'
run C13_stales;           expect C13_stales           'Invariant RsRootIsFunctionOfChain is violated'

run P_strict_A_n22;       expect P_strict_A_n22       'Invariant NoSpuriousHold is violated'
run P_tipconv_T_adv2;     expect P_tipconv_T_adv2     'Invariant NoSpuriousHold is violated'

run W_rp_A;               expect W_rp_A               'Invariant RPWitness is violated'
run W_sc1;                expect W_sc1                'Invariant Sc1 is violated'
run W_sc5;                expect W_sc5                'Invariant Sc5 is violated'
run W_sc10;               expect W_sc10               'Invariant Sc10 is violated'

if [ "${TLC_LONG:-0}" = 1 ]; then
    run G_T_adv2_n18; expect G_T_adv2_n18 "$OK"
    run G_M_n38;      expect G_M_n38      "$OK"
fi

echo "sha256(tla2tools.jar) $(sha256sum "$JAR" | cut -d' ' -f1)"
exit $FAIL
