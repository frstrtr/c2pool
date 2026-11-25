#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# G3b L3 scorer (parent lost -> aux dropped). It reads the evidence the
# harness leaves in an evidence dir, so a finished run can be re-scored.
#
# usage: g3b_l3_score.sh <evidence-dir> <P parent hash> <D aux hash> <doge conf of D>
#
# Ground truth is the node logs, not /recent_blocks. With --no-embedded-ltc
# (the G3b mode) main_ltc.cpp only wires set_block_verify_fn on the embedded
# path; the RPC path logs its +30s/+120s getblock check and never writes a
# verdict into the row. So every row stays "pending" (legs1124d: 1213/1213),
# and DOGE rows are not in /recent_blocks at all. The rows are reported for
# information and fail L3 only if one claims P "confirmed".
#
# PASS needs all of:
#   P_ORPH  node logged "Block <P16>... ORPHANED (confirmations=<0)"
#   D_ORPH  node logged the "BLOCK ORPHANED -- DOGE" banner for D's hash
#   RESUB   no "Merged block submitted ... snapshot hash=<D16>" after the orphan step
#   DCONF   dogecoind getblock D confirmations < 0
#   ROWS    no /recent_blocks row for P says "confirmed"
set -u
E=$1 PH=$2 DH=$3 DCONF=${4:-}
P16=${PH:0:16} D16=${DH:0:16}
LOGS=("$E"/node?.log)

p_orph=$(cat "${LOGS[@]}" | grep -c "Block ${P16}\.\.\. ORPHANED (confirmations=-")
d_orph=$(cat "${LOGS[@]}" | grep -A3 "BLOCK ORPHANED — DOGE" | grep -c "Block hash: *${DH}")
# submits of D written after the orphan step. l3.lines holds the nodeA/nodeB log line
# counts at that step, so only later lines are read: no clock, timezone or midnight
# dependence. Evidence from older harness runs has only l3.mark (UTC HH:MM:SS, while
# node logs stamp local time); it is compared as before and tagged clock=legacy-utc.
# Both node logs must exist and l3.lines must hold exactly two integers. Anything else
# gives resub=NA, which is never a PASS: a missing log or a one-field l3.lines would
# otherwise drop a node silently and read as "0 resubmits".
RESUB_RE="Merged block submitted.*snapshot hash=${D16}"
if [ ! -f "$E/nodeA.log" ] || [ ! -f "$E/nodeB.log" ]; then
  resub=NA; clock=missing-log
elif [ -s "$E/l3.lines" ]; then
  LA="" LB="" LX=""
  read -r LA LB LX < "$E/l3.lines"
  if [[ $LA =~ ^[0-9]+$ ]] && [[ $LB =~ ^[0-9]+$ ]] && [ -z "$LX" ]; then
    resub=$( { tail -n +"$((LA+1))" "$E/nodeA.log"; tail -n +"$((LB+1))" "$E/nodeB.log"; } | grep -c "$RESUB_RE")
    clock=lines
  else
    resub=NA; clock=bad-l3.lines
  fi
elif [ -s "$E/l3.mark" ]; then
  MARK=$(cat "$E/l3.mark")
  if [[ $MARK =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]]; then
    resub=$(cat "$E/nodeA.log" "$E/nodeB.log" | grep "$RESUB_RE" \
            | awk -v m="$MARK" '{t=substr($1,2,8); if (t>=m) n++} END{print n+0}')
    clock=legacy-utc
  else
    resub=NA; clock=bad-l3.mark
  fi
else
  resub=NA; clock=none
fi
rows=$(python3 - "$E" "$PH" <<'PY'
import json,sys
E,PH=sys.argv[1:]
try: rows=json.load(open(f"{E}/recent_blocks.after.json"))
except Exception as e: print(f"rows=unreadable"); sys.exit()
rows=rows if isinstance(rows,list) else rows.get("blocks",rows.get("recent_blocks",[]))
p=[r.get("status") for r in rows if r.get("hash")==PH]
print(f"rows_P={p} rows_pending={sum(r.get('status')=='pending' for r in rows)}/{len(rows)}")
PY
)
ok=1
[ "$p_orph" -ge 1 ] || ok=0
[ "$d_orph" -ge 1 ] || ok=0
[ "$resub" = "0" ] || ok=0
[ "${DCONF:-0}" -lt 0 ] 2>/dev/null || ok=0
echo "$rows" | grep -q "confirmed" && ok=0
S="L3SCORE P_ORPH=$p_orph D_ORPH=$d_orph resub_after_orphan=$resub resub_clock=$clock doge_conf_D=${DCONF:-NA} $rows"
if [ $ok = 1 ]; then echo "L3 PASS $S"; else echo "L3 FAIL $S"; fi
