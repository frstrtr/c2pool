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
MARK=$(cat "$E/l3.mark" 2>/dev/null || echo "")   # HH:MM:SS of the orphan step

p_orph=$(cat "${LOGS[@]}" | grep -c "Block ${P16}\.\.\. ORPHANED (confirmations=-")
d_orph=$(cat "${LOGS[@]}" | grep -A3 "BLOCK ORPHANED — DOGE" | grep -c "Block hash: *${DH}")
# submits of D stamped after the orphan step (log lines start "[HH:MM:SS.")
if [ -n "$MARK" ]; then
  resub=$(cat "${LOGS[@]}" | grep "Merged block submitted.*snapshot hash=${D16}" \
          | awk -v m="$MARK" '{t=substr($1,2,8); if (t>=m) n++} END{print n+0}')
else
  resub=NA
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
S="L3SCORE P_ORPH=$p_orph D_ORPH=$d_orph resub_after_orphan=$resub doge_conf_D=${DCONF:-NA} $rows"
if [ $ok = 1 ]; then echo "L3 PASS $S"; else echo "L3 FAIL $S"; fi
