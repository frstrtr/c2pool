#!/bin/sh
# Model-check PathBSealRNP.tla (the Path B settlement / seal state machine) with TLC.
#
#   proto/tla/check-seal-rnp.sh <path/to/tla2tools.jar> [out-dir]
#
# Configs (two nodes, four receipt ids; a few minutes), one verdict line per run:
#   GREEN (every seal invariant + Agreement + HonestAccepted + ChainRuledValid +
#          RecordIsCarrierMax):          V1_rnp_own_n2r4 V1_rnp_carriage_n2r4
#   controls (the named invariant is violated):
#          V1_rnp_neg_openlocal_n2r4   Agreement
#          V1_rnp_neg_omitlocal_n2r4   Agreement
#          V1_rnp_nodead_n2r4          LegallyDead
#          V1_rnp_sharechain_n2r4      OrphanRecovered
#   witnesses under Adv (the single-check case is reachable, so it is violated):
#          V1_rnp_probe_order_n2r4_adv_k2  NoOrderRefusal
#          V1_rnp_probe_closed_n2r4_adv    NoClosedRefusal
# Env: TLC_WORKERS (default 4), TLC_HEAP (default 4g).
# Exit status 0 only if every run matches its expectation.
set -eu
JAR=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
OUT=${2:-./tlc-seal-rnp-out}
WORKERS=${TLC_WORKERS:-4}
HEAP=${TLC_HEAP:-4g}
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=PathBSealRNP
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

run V1_rnp_own_n2r4;      expect V1_rnp_own_n2r4      "$OK"
run V1_rnp_carriage_n2r4; expect V1_rnp_carriage_n2r4 "$OK"

run V1_rnp_neg_openlocal_n2r4;      expect V1_rnp_neg_openlocal_n2r4      'Invariant Agreement is violated'
run V1_rnp_neg_omitlocal_n2r4;      expect V1_rnp_neg_omitlocal_n2r4      'Invariant Agreement is violated'
run V1_rnp_nodead_n2r4;             expect V1_rnp_nodead_n2r4             'Invariant LegallyDead is violated'
run V1_rnp_sharechain_n2r4;         expect V1_rnp_sharechain_n2r4         'Invariant OrphanRecovered is violated'
run V1_rnp_probe_order_n2r4_adv_k2; expect V1_rnp_probe_order_n2r4_adv_k2 'Invariant NoOrderRefusal is violated'
run V1_rnp_probe_closed_n2r4_adv;   expect V1_rnp_probe_closed_n2r4_adv   'Invariant NoClosedRefusal is violated'

echo "sha256(tla2tools.jar) $(sha256sum "$JAR" | cut -d' ' -f1)"
exit $FAIL
