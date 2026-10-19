#!/bin/bash
# runq.sh PREFIX N BIN : N race-heavy runs of BIN labelled PREFIX-1..N, then the table (table.py).
# Extra env (FOUND_WANT, LO, HI, DCONF, ...) passes through to run.sh.
source "$(dirname "$0")/common.sh"; P=$1; NR=${2:-6}; B=$3
[ -x "$B" ] || { echo "usage: runq.sh PREFIX N BIN"; exit 1; }
for i in $(seq 1 $NR); do
  while [ "$(free -g | awk '/Mem:/{print $7}')" -lt 7 ]; do echo "$(date -Is) waiting mem"; sleep 20; done
  echo "$(date -Is) START $P-$i"; BIN=$B LABEL=$P-$i $HERE/run.sh; echo "$(date -Is) END $P-$i rc=$?"
  $HERE/stop.sh > /dev/null 2>&1; sleep 3
done
python3 $HERE/table.py $RIG/runs-$P-* ; echo RUNQ_DONE
